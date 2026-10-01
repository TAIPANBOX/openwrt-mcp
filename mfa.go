package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Optional second factor for the tools that can change or read anything.
//
// The bearer token is something the workstation has. If that workstation is compromised the
// token goes with it, and with a broad grant that is root on the router. A TOTP code is
// something *you* have, on a different device, so a stolen token alone stops being enough.
//
// Deliberately not a code per call. An agent makes bursts of calls, and prompting for six
// digits each time would push people to disable it -- a control that is too annoying to leave
// on protects nothing. Instead one code unlocks a time-boxed window, the way sudo does. The
// window is per client, held in memory only: a daemon restart drops every unlock, which errs
// toward asking again.
//
// Standard RFC 6238: SHA-1, 6 digits, 30-second step. That is what Google Authenticator,
// Aegis, 1Password and the rest implement, so enrolment is a QR scan and nothing bespoke.

const (
	totpStep    = 30 * time.Second
	totpDigits  = 6
	totpSkew    = 1 // accept the adjacent steps: routers drift, phones drift
	mfaFileMode = 0o600
)

const (
	factorTOTP    = "totp"
	factorPIN     = "pin"
	factorPINTOTP = "pin+totp"
)

const (
	defaultMFAMaxFailures = 5
	defaultMFALockout     = 15 * time.Minute
)

// unlockPolicy is the part of a policy that governs one unlock attempt.
type unlockPolicy struct {
	Factor      string
	Window      time.Duration
	MaxFailures int
	Lockout     time.Duration
}

// withDefaults fills anything unset, so a zero Policy (every config written before these
// options existed) unlocks exactly as it always did: TOTP, the default window, five tries.
func (u unlockPolicy) withDefaults() unlockPolicy {
	if u.Factor == "" {
		u.Factor = factorTOTP
	}
	if u.Window <= 0 {
		u.Window = defaultMFAWindow
	}
	if u.MaxFailures <= 0 {
		u.MaxFailures = defaultMFAMaxFailures
	}
	if u.Lockout <= 0 {
		u.Lockout = defaultMFALockout
	}
	return u
}

func (p *Policy) unlockPolicy() unlockPolicy {
	return unlockPolicy{p.MFAFactor, p.MFAWindow, p.MFAMaxFailures, p.MFALockout}.withDefaults()
}

// unlockAttempt is what a client supplies to mfa_unlock. Which fields matter is the
// policy's decision; a field the policy does not ask for is ignored, never checked.
type unlockAttempt struct{ Code, PIN string }

// mfaState is the live, in-memory state of one client, as the daemon holds it.
type mfaState struct {
	UnlockedUntil  time.Time // zero when locked
	LockedOutUntil time.Time // zero when not locked out
	Failures       int       // consecutive failed unlocks
}

// defaultMFAWindow is how long one code keeps the gated tools open.
const defaultMFAWindow = 15 * time.Minute

// MFAStore holds one TOTP secret per client, plus the live unlock state.
//
// The secret is stored raw because TOTP is symmetric -- unlike the bearer tokens, which are
// only ever kept as digests. That is a real difference in blast radius, so the file is 0600
// and lives beside the token store, and `mfa enrol` is the only thing that ever prints it.
type MFAStore struct {
	path string
	pins *PINStore

	mu      sync.Mutex
	mtime   time.Time            // of path, to notice enrolments by the CLI
	secrets map[string]string    // client -> base32 secret
	unlocks map[string]time.Time // client -> unlocked until
	lastCtr map[string]uint64    // client -> last accepted time-step, for replay

	// Throttle on guessing. Runtime state like unlocks: in memory, per client, gone on restart.
	fails       map[string]int       // client -> consecutive failed unlocks
	lockedUntil map[string]time.Time // client -> unlocking refused until
	pinFP       map[string]string    // client -> fingerprint of the PIN record last seen
}

// reloadLocked re-reads the secret file when it has changed on disk. Callers hold m.mu.
//
// `openwrt-mcp mfa enrol` is a separate process writing that file, so without this a running
// daemon keeps the secrets it loaded at startup and rejects every code from a freshly
// enrolled client as "invalid" -- with no hint that a restart is what it wants. `allow`
// already takes effect on a running daemon; enrolment has to behave the same way.
//
// Unlocks and replay counters are runtime state and survive a reload, except for a client
// whose secret actually changed: rotating a secret is what you do when it may be compromised,
// so any window opened under the old one must close.
func (m *MFAStore) reloadLocked() {
	m.reloadSecretsLocked()
	m.reloadPINsLocked()
}

// forgetLocked drops everything a client's earlier credentials earned: the open window, the
// replay counter, and any lockout. Rotating a credential is the owner's recovery path, so it
// must also lift a lockout a guesser caused, without a daemon restart.
func (m *MFAStore) forgetLocked(client string) {
	delete(m.unlocks, client)
	delete(m.lastCtr, client)
	delete(m.fails, client)
	delete(m.lockedUntil, client)
}

// reloadPINsLocked is the PIN-side twin of the above: a PIN set, rotated or cleared by the
// CLI closes any window opened under the old one.
func (m *MFAStore) reloadPINsLocked() {
	fresh := m.pins.Fingerprints()
	for client, fp := range fresh {
		if m.pinFP[client] != fp {
			m.forgetLocked(client)
		}
	}
	for client := range m.pinFP {
		if _, still := fresh[client]; !still {
			m.forgetLocked(client)
		}
	}
	m.pinFP = fresh
}

func (m *MFAStore) reloadSecretsLocked() {
	st, err := os.Stat(m.path)
	if err != nil {
		return // no file yet, or unreadable: keep what we have
	}
	if st.ModTime().Equal(m.mtime) {
		return
	}
	fresh, err := parseMFAFile(m.path)
	if err != nil {
		return // a half-written file must not wipe working secrets
	}
	for client, old := range m.secrets {
		if fresh[client] != old {
			m.forgetLocked(client)
		}
	}
	m.secrets, m.mtime = fresh, st.ModTime()
	m.applySpentStepsLocked()
}

// ---------------------------------------------------------------- steps spent elsewhere
//
// `mfa activate` runs in its own process and spends a code to prove the scan worked. The
// daemon only learns of the new secret by reloading the file, and its replay counter for that
// client starts empty, so without help the very code typed at activation would open the
// window once more for the rest of its 90 seconds. Activate therefore records the step it
// spent in mfa.used, keyed to a fingerprint of the secret, and a reload honours it. The
// fingerprint keeps a step spent on one secret from blocking the next one.

func (m *MFAStore) usedPath() string { return m.path + ".used" }

// secretFingerprint names a secret without revealing it: a truncated SHA-256 is enough to
// tell two secrets apart and useless for producing codes.
func secretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

type spentStep struct {
	ctr uint64
	fp  string
}

func readSpentSteps(path string) map[string]spentStep {
	out := map[string]spentStep{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ctr, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		out[f[0]] = spentStep{ctr: ctr, fp: f[2]}
	}
	return out
}

// applySpentStepsLocked raises a client's replay counter to a step recorded for the secret it
// now has. It never lowers one. Callers hold m.mu.
func (m *MFAStore) applySpentStepsLocked() {
	for client, sp := range readSpentSteps(m.usedPath()) {
		secret := m.secrets[client]
		if secret == "" || secretFingerprint(secret) != sp.fp {
			continue
		}
		if last, seen := m.lastCtr[client]; !seen || last < sp.ctr {
			m.lastCtr[client] = sp.ctr
		}
	}
}

// recordSpentStep writes the step into mfa.used, one line per client, by sidecar and rename.
func (m *MFAStore) recordSpentStep(client, secret string, ctr uint64) error {
	steps := readSpentSteps(m.usedPath())
	steps[client] = spentStep{ctr: ctr, fp: secretFingerprint(secret)}
	var b strings.Builder
	b.WriteString("# openwrt-mcp: TOTP steps already spent by `mfa activate`, so the daemon refuses them.\n")
	clients := make([]string, 0, len(steps))
	for c := range steps {
		clients = append(clients, c)
	}
	sortStrings(clients)
	for _, c := range clients {
		fmt.Fprintf(&b, "%s %d %s\n", c, steps[c].ctr, steps[c].fp)
	}
	tmp := m.usedPath() + ".new"
	if err := os.WriteFile(tmp, []byte(b.String()), mfaFileMode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mfaFileMode); err != nil {
		return err
	}
	return os.Rename(tmp, m.usedPath())
}

func parseMFAFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		client, secret, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		out[client] = strings.TrimSpace(secret)
	}
	return out, nil
}

func LoadMFA(path string) (*MFAStore, error) {
	m := &MFAStore{
		path:    path,
		secrets: map[string]string{},
		unlocks: map[string]time.Time{},
		lastCtr: map[string]uint64{},

		fails:       map[string]int{},
		lockedUntil: map[string]time.Time{},
	}
	pins, err := LoadPINs(filepath.Join(filepath.Dir(path), "pin"))
	if err != nil {
		return nil, err
	}
	m.pins = pins
	m.pinFP = pins.Fingerprints()
	fresh, err := parseMFAFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil // no enrolments == no MFA == every policy unaffected. Valid state.
		}
		return nil, err
	}
	m.secrets = fresh
	if st, err := os.Stat(path); err == nil {
		m.mtime = st.ModTime()
	}
	return m, nil
}

// deviceLabel names the router in the otpauth account, so an authenticator holding secrets
// for several routers can tell them apart.
//
// Without it every enrolment shows up as the same "openwrt-mcp (claude-code)" and you are
// left guessing which entry belongs to which box -- which is exactly what happened with two
// routers: the entries were indistinguishable and the only way to pair them up was trying
// each code against each router.
func deviceLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" && h != "(none)" {
		return h
	}
	if b, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		if h := strings.TrimSpace(string(b)); h != "" {
			return h
		}
	}
	return ""
}

// Enrol mints a new secret for a client, replacing any existing one. Returns the secret and
// an otpauth:// URI for a QR code. Re-enrolling invalidates the old secret, which is the
// recovery path when a phone is lost.
//
// device names the router in the account label; empty falls back to the hostname.
func (m *MFAStore) Enrol(client, issuer, device string) (secret, uri string, err error) {
	secret, err = newTOTPSecret()
	if err != nil {
		return "", "", err
	}

	m.mu.Lock()
	m.secrets[client] = secret
	m.forgetLocked(client) // a new secret must not inherit an old unlock
	snapshot := make(map[string]string, len(m.secrets))
	for k, v := range m.secrets {
		snapshot[k] = v
	}
	m.mu.Unlock()

	if err := m.save(snapshot); err != nil {
		return "", "", err
	}
	return secret, otpauthURI(client, issuer, device, secret), nil
}

func newTOTPSecret() (string, error) {
	buf := make([]byte, 20) // 160 bits, per RFC 4226 section 4
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// otpauthURI is the string an authenticator app takes, as text or as a QR.
func otpauthURI(client, issuer, device, secret string) string {
	// otpauth label is "Issuer:AccountName". The router goes in the account, so apps show
	// e.g. "openwrt-mcp (claude-code@GL-BE14000)" and two routers never collide.
	account := client
	if device == "" {
		device = deviceLabel()
	}
	if device != "" {
		account = client + "@" + device
	}
	label := url.PathEscape(issuer + ":" + account)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		label, secret, url.QueryEscape(issuer), totpDigits, int(totpStep.Seconds()))
}

func (m *MFAStore) save(secrets map[string]string) error {
	return writeMFAFile(m.path, secrets, "# openwrt-mcp TOTP secrets. Treat as credentials: anyone who reads this\n"+
		"# file can generate valid codes. Re-run `openwrt-mcp mfa enrol <client>` to rotate.\n")
}

// writeMFAFile writes "<client> <secret>" lines by sidecar and rename, so a crash mid-write
// cannot leave a half-file that locks you out. Shared by the active and the pending file.
func writeMFAFile(path string, secrets map[string]string, header string) error {
	var b strings.Builder
	b.WriteString(header)
	clients := make([]string, 0, len(secrets))
	for c := range secrets {
		clients = append(clients, c)
	}
	sortStrings(clients)
	for _, c := range clients {
		fmt.Fprintf(&b, "%s %s\n", c, secrets[c])
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(b.String()), mfaFileMode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------- two-step enrolment
//
// A plain `mfa enrol` makes the new secret live at once. If the QR was never scanned, or was
// scanned wrongly, the client is now gated behind codes nobody can produce. Enrolling into
// mfa.pending first, and activating with a code from the authenticator, proves the scan
// worked before anything depends on it -- and lets an existing secret be rotated without a
// window where neither works.

const pendingHeader = "# openwrt-mcp TOTP secrets awaiting activation. Not in force until\n" +
	"# `openwrt-mcp mfa activate <client> <code>` proves the authenticator has the secret.\n"

func (m *MFAStore) pendingPath() string { return m.path + ".pending" }

func readPending(path string) (map[string]string, error) {
	pend, err := parseMFAFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	return pend, nil
}

// EnrolPending mints a secret into mfa.pending, leaving the active file untouched.
func (m *MFAStore) EnrolPending(client, issuer, device string) (secret, uri string, err error) {
	secret, err = newTOTPSecret()
	if err != nil {
		return "", "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pend, err := readPending(m.pendingPath())
	if err != nil {
		return "", "", err
	}
	pend[client] = secret
	if err := writeMFAFile(m.pendingPath(), pend, pendingHeader); err != nil {
		return "", "", err
	}
	return secret, otpauthURI(client, issuer, device, secret), nil
}

// TOTPPending reports whether the client has a secret waiting to be activated.
func (m *MFAStore) TOTPPending(client string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	pend, err := readPending(m.pendingPath())
	return err == nil && pend[client] != ""
}

// Activate moves the client's pending secret into force, but only if code is valid now under
// that secret. Otherwise it refuses and the secret stays pending. Replacing an active secret
// closes any window opened under it, exactly as a rotation does.
func (m *MFAStore) Activate(client, code string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pend, err := readPending(m.pendingPath())
	if err != nil {
		return err
	}
	secret := pend[client]
	if secret == "" {
		return fmt.Errorf("no pending enrolment for %q; start one with: openwrt-mcp mfa enrol %s --pending", client, client)
	}
	ctr, ok := matchTOTP(secret, strings.TrimSpace(code), now)
	if !ok {
		return fmt.Errorf("that code is not valid right now, so the enrolment is still pending " +
			"(scan the QR again if needed, and check the phone's clock)")
	}

	m.reloadSecretsLocked()
	// Recorded before the secret goes live, so a daemon that reloads the moment the active
	// file changes already knows this step is spent.
	if err := m.recordSpentStep(client, secret, ctr); err != nil {
		return err
	}
	m.secrets[client] = secret
	m.forgetLocked(client)
	m.lastCtr[client] = ctr // the code that proved the scan is spent
	snapshot := make(map[string]string, len(m.secrets))
	for k, v := range m.secrets {
		snapshot[k] = v
	}
	if err := m.save(snapshot); err != nil {
		return err
	}
	delete(pend, client)
	if len(pend) == 0 {
		return os.Remove(m.pendingPath())
	}
	return writeMFAFile(m.pendingPath(), pend, pendingHeader)
}

func (m *MFAStore) Enrolled(client string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadLocked()
	return m.secrets[client] != ""
}

func (m *MFAStore) Clients() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.secrets))
	for c := range m.secrets {
		out = append(out, c)
	}
	sortStrings(out)
	return out
}

// Unlock is the TOTP-only way in, kept for callers and tests that predate the other factors.
// It goes through Attempt, so it is subject to the same lockout as every other way in.
func (m *MFAStore) Unlock(client, code string, window time.Duration, now time.Time) (time.Time, error) {
	return m.Attempt(client, unlockAttempt{Code: code}, unlockPolicy{Factor: factorTOTP, Window: window}, now)
}

var (
	errInvalidCode  = fmt.Errorf("invalid code")
	errCodeReplayed = fmt.Errorf("code already used")
	errInvalidCreds = fmt.Errorf("invalid credentials")
)

// Attempt checks the factors the policy names and, if every one passes, opens the window.
//
// What a failure costs is decided here and nowhere else. A failed attempt counts against the
// client; reaching MaxFailures refuses every attempt for Lockout, without looking at any
// factor and without counting, so the lockout neither extends itself nor lets a guesser learn
// anything from it. Success resets the count. The error text never says which factor was
// wrong: it depends only on the policy, so it cannot be used to guess a factor at a time.
//
// The one place that reads differently is a TOTP-only policy, which keeps the messages it
// always had ("invalid code", "code already used"): with a single factor there is nothing to
// give away.
//
// m.mu is held across the PIN derivation. That serialises PIN guesses, which is a feature
// (two parallel attempts cannot both slip under the failure limit), and it is bounded: a
// client past its limit is refused before any derivation happens.
func (m *MFAStore) Attempt(client string, in unlockAttempt, up unlockPolicy, now time.Time) (time.Time, error) {
	up = up.withDefaults()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadLocked()

	if until, locked := m.lockedUntil[client]; locked {
		if now.Before(until) {
			return time.Time{}, fmt.Errorf("too many failed attempts: unlocking is locked out until %s",
				until.Format(time.RFC3339))
		}
		// The lockout has run its course: the next failure is the first of a fresh count.
		delete(m.lockedUntil, client)
		delete(m.fails, client)
	}

	if err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {
		m.fails[client]++
		if m.fails[client] >= up.MaxFailures {
			m.lockedUntil[client] = now.Add(up.Lockout)
		}
		return time.Time{}, err
	}
	delete(m.fails, client)
	until := now.Add(up.Window)
	m.unlocks[client] = until
	return until, nil
}

// checkFactorsLocked verifies every factor the policy names, PIN first. That order is the
// point of pin+totp: a wrong PIN must fail before the TOTP replay counter is touched, or a
// guesser holding only the client's token could burn the owner's codes one at a time.
func (m *MFAStore) checkFactorsLocked(client string, in unlockAttempt, factor string, now time.Time) error {
	needPIN := factor == factorPIN || factor == factorPINTOTP
	needTOTP := factor == factorTOTP || factor == factorPINTOTP
	if !needPIN && !needTOTP {
		return errInvalidCreds // an unknown factor never opens anything
	}
	if needPIN && !m.pins.Verify(client, in.PIN) {
		return errInvalidCreds
	}
	if needTOTP {
		err := m.checkTOTPLocked(client, in.Code, now)
		if err != nil && factor == factorPINTOTP {
			return errInvalidCreds // a replay would confirm that the PIN half was right
		}
		return err
	}
	return nil
}

// matchTOTP reports whether code is valid at now, within the accepted skew, and for which
// time-step.
func matchTOTP(secret, code string, now time.Time) (uint64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	step := uint64(now.Unix()) / uint64(totpStep.Seconds())
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		ctr := step + uint64(skew)
		want, err := totpAt(secret, ctr)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return ctr, true
		}
	}
	return 0, false
}

// checkTOTPLocked validates a code and, only if it is good and fresh, consumes its step.
func (m *MFAStore) checkTOTPLocked(client, code string, now time.Time) error {
	secret := m.secrets[client]
	// "No secret" and "wrong code" read the same: telling them apart tells an attacker
	// which clients are worth attacking.
	if secret == "" {
		return errInvalidCode
	}
	ctr, ok := matchTOTP(secret, strings.TrimSpace(code), now)
	if !ok {
		return errInvalidCode
	}
	// Replay: a code is single-use. Without this, a code shoulder-surfed or captured
	// from a log is good for its whole 90-second acceptance span.
	if last, seen := m.lastCtr[client]; seen && ctr <= last {
		return errCodeReplayed
	}
	m.lastCtr[client] = ctr
	return nil
}

// UnlockedUntil returns when the client's window closes, and whether it is open now.
func (m *MFAStore) UnlockedUntil(client string, now time.Time) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.unlocks[client]
	if !ok || !now.Before(until) {
		return time.Time{}, false
	}
	return until, true
}

// State reports what the daemon currently holds for a client: an open window, a lockout and
// the running failure count. It is read-only and only ever true of the process that holds
// the attempts, which is why `status` run as a separate process cannot show it.
func (m *MFAStore) State(client string, now time.Time) mfaState {
	m.mu.Lock()
	defer m.mu.Unlock()
	var st mfaState
	if until, ok := m.unlocks[client]; ok && now.Before(until) {
		st.UnlockedUntil = until
	}
	until, locked := m.lockedUntil[client]
	if locked && now.Before(until) {
		st.LockedOutUntil = until
	}
	// An expired lockout is spent, and the count it was holding with it.
	if !locked || now.Before(until) {
		st.Failures = m.fails[client]
	}
	return st
}

// PINSet reports whether the client has a PIN on file.
func (m *MFAStore) PINSet(client string) bool { return m.pins.Has(client) }

// Lock closes the window immediately -- the "I am done, re-lock it" path -- and reports
// whether one was open. It deliberately leaves the failure count and any lockout alone: it
// is a convenience for the owner, never a way to reset the throttle.
func (m *MFAStore) Lock(client string) bool { return m.LockAt(client, time.Now()) }

// LockAt is Lock against an injected clock.
func (m *MFAStore) LockAt(client string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, was := m.unlocks[client]
	delete(m.unlocks, client)
	return was && now.Before(until)
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 section 5.4.
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, v%mod), nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// parseMFAWindow accepts the same duration spellings as grant expiry.
func parseMFAWindow(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return defaultMFAWindow, nil
	}
	d, err := parseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("mfa_window must be positive")
	}
	return d, nil
}

// writeMFAStatus prints who has a factor set up and what each policy asks for, warning where
// a policy asks for something the client has not got (a gate nobody can open).
func writeMFAStatus(w io.Writer, ms *MFAStore, cfg *Config) {
	clients := ms.Clients()
	if len(clients) == 0 {
		fmt.Fprintln(w, "(no clients enrolled -- no tool requires a TOTP code)")
	}
	for _, c := range clients {
		fmt.Fprintf(w, "%s: enrolled\n", c)
	}
	for _, p := range cfg.Policies {
		if len(p.MFATools) == 0 {
			continue
		}
		up := p.unlockPolicy()
		fmt.Fprintf(w, "  policy %s requires %s for: %s (window %s, locked out %s after %d failures)\n",
			p.Client, up.Factor, strings.Join(p.MFATools, ", "), up.Window, up.Lockout, up.MaxFailures)
		if (up.Factor == factorTOTP || up.Factor == factorPINTOTP) && !ms.Enrolled(p.Client) {
			fmt.Fprintf(w, "  WARNING: %q has no enrolled secret, so those tools cannot be unlocked.\n"+
				"           Run: openwrt-mcp mfa enrol %s\n", p.Client, p.Client)
		}
		if (up.Factor == factorPIN || up.Factor == factorPINTOTP) && !ms.PINSet(p.Client) {
			fmt.Fprintf(w, "  WARNING: %q has no PIN, so those tools cannot be unlocked.\n"+
				"           Run: openwrt-mcp pin set %s\n", p.Client, p.Client)
		}
	}
}
