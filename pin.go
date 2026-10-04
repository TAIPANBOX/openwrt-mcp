package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// An owner-set PIN, the second kind of unlock factor beside TOTP.
//
// TOTP proves the owner holds a device. A PIN proves the owner knows something, which is
// the right shape for the owner who would rather type four digits at a keyboard than reach
// for a phone, and for a deployment with no authenticator at all. A policy picks one, or
// both (see mfa_factor), and the unlock window and lockout are shared with TOTP.
//
// A PIN is short by design, so it is only as strong as the throttle in front of it. The hash
// is deliberately slow (PBKDF2-HMAC-SHA256, pinIterations) and per-client lockout caps the
// number of guesses (see mfa_max_failures); neither is sufficient alone, and the lockout is
// the one that matters, since an attacker with the file can brute-force 10^4 offline whatever
// the hash costs. So the file is 0600 and root-only, exactly like the TOTP secrets.
//
// The plaintext PIN is never stored, logged or accepted as an argument: `pin set` reads it
// from stdin so it never appears in /proc/<pid>/cmdline or in shell history.

const (
	pinMinDigits = 4
	pinMaxDigits = 8

	// pinIterations is the PBKDF2 cost written into each new record. 200k is what
	// BenchmarkPINVerify is there to price on a real router; the count is stored per record,
	// so raising it later does not invalidate PINs that are already set.
	pinIterations = 200000

	pinScheme   = "pbkdf2-sha256"
	pinSaltLen  = 16
	pinKeyLen   = 32
	pinFileMode = 0o600

	// A corrupted record must not be able to ask for an hour of CPU.
	pinMaxIterations = 10_000_000
	// Longer than any valid PIN; beyond this there is nothing to compare against.
	pinMaxInput = 64
)

type pinRecord struct {
	iter int
	salt []byte
	hash []byte
	raw  string // the file's "pbkdf2-sha256$..." field, kept verbatim for rewriting
}

// PINStore holds one PIN hash per client.
type PINStore struct {
	path string

	mu    sync.Mutex
	mtime time.Time
	recs  map[string]pinRecord
}

func LoadPINs(path string) (*PINStore, error) {
	p := &PINStore{path: path, recs: map[string]pinRecord{}}
	fresh, err := parsePINFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil // no PINs set == the pin factor can never be satisfied. Valid state.
		}
		return nil, err
	}
	p.recs = fresh
	if st, err := os.Stat(path); err == nil {
		p.mtime = st.ModTime()
	}
	return p, nil
}

func parsePINFile(path string) (map[string]pinRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]pinRecord{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		client, raw, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if rec, ok := parsePINRecord(strings.TrimSpace(raw)); ok {
			out[client] = rec
		}
		// A record that does not parse is skipped, never trusted: it counts as no PIN.
	}
	return out, nil
}

func parsePINRecord(raw string) (pinRecord, bool) {
	f := strings.Split(raw, "$")
	if len(f) != 4 || f[0] != pinScheme {
		return pinRecord{}, false
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > pinMaxIterations {
		return pinRecord{}, false
	}
	salt, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil || len(salt) == 0 {
		return pinRecord{}, false
	}
	hash, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil || len(hash) != pinKeyLen {
		return pinRecord{}, false
	}
	return pinRecord{iter: iter, salt: salt, hash: hash, raw: raw}, true
}

// refresh re-reads the file when it has changed on disk. Callers hold p.mu.
//
// `pin set` runs in another process from the daemon; without this a running daemon would
// keep checking against the old PIN, or none, until restarted. A half-written or unreadable
// file keeps what we have rather than wiping working PINs.
func (p *PINStore) refresh() {
	st, err := os.Stat(p.path)
	if err != nil || st.ModTime().Equal(p.mtime) {
		return
	}
	fresh, err := parsePINFile(p.path)
	if err != nil {
		return
	}
	p.recs, p.mtime = fresh, st.ModTime()
}

// Fingerprints names, per client, a digest of that client's current record. It lets the MFA
// store notice that a PIN was rotated or cleared and close any window opened under the old
// one, without the PIN store knowing anything about windows.
func (p *PINStore) Fingerprints() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	out := make(map[string]string, len(p.recs))
	for c, r := range p.recs {
		sum := sha256.Sum256([]byte(r.raw))
		out[c] = hex.EncodeToString(sum[:])
	}
	return out
}

func (p *PINStore) Has(client string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	_, ok := p.recs[client]
	return ok
}

// validatePIN accepts exactly 4 to 8 ASCII digits and nothing else: not whitespace, not a
// sign, not another script's digits (which unicode.IsDigit would let through and which an
// operator typing on another layout would not be able to reproduce). The message never
// contains the input.
func validatePIN(pin string) error {
	if len(pin) >= pinMinDigits && len(pin) <= pinMaxDigits {
		ok := true
		for i := 0; i < len(pin); i++ {
			if pin[i] < '0' || pin[i] > '9' {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("a PIN must be %d to %d digits (0-9) and nothing else", pinMinDigits, pinMaxDigits)
}

// validClientName keeps the one-line-per-client file unambiguous.
func validClientName(c string) error {
	if c == "" || strings.ContainsAny(c, " \t\r\n") {
		return fmt.Errorf("client name %q must be non-empty and contain no whitespace", c)
	}
	return nil
}

func derivePIN(pin string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pin, salt, iter, pinKeyLen)
}

// Set replaces the client's PIN. Nothing is written unless the PIN and the name are valid.
func (p *PINStore) Set(client, pin string) error {
	if err := validClientName(client); err != nil {
		return err
	}
	if err := validatePIN(pin); err != nil {
		return err
	}
	salt := make([]byte, pinSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash, err := derivePIN(pin, salt, pinIterations)
	if err != nil {
		return err
	}
	raw := fmt.Sprintf("%s$%d$%s$%s", pinScheme, pinIterations,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash))
	rec, _ := parsePINRecord(raw)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	p.recs[client] = rec
	return p.saveLocked()
}

// Clear removes the client's PIN and reports whether there was one.
func (p *PINStore) Clear(client string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	if _, ok := p.recs[client]; !ok {
		return false, nil
	}
	delete(p.recs, client)
	return true, p.saveLocked()
}

func (p *PINStore) saveLocked() error {
	var b strings.Builder
	b.WriteString("# openwrt-mcp PIN hashes (PBKDF2-HMAC-SHA256, salted). Not reversible, but a PIN is\n" +
		"# short: keep this file root-only. Change with `openwrt-mcp pin set <client>`.\n")
	clients := make([]string, 0, len(p.recs))
	for c := range p.recs {
		clients = append(clients, c)
	}
	sortStrings(clients)
	for _, c := range clients {
		fmt.Fprintf(&b, "%s %s\n", c, p.recs[c].raw)
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	// Write-and-rename so a crash mid-write cannot leave a half-file that drops every PIN.
	tmp := p.path + ".new"
	if err := os.WriteFile(tmp, []byte(b.String()), pinFileMode); err != nil {
		return err
	}
	// WriteFile keeps the mode of a pre-existing sidecar; make it 0600 whatever was there.
	if err := os.Chmod(tmp, pinFileMode); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		return err
	}
	if st, err := os.Stat(p.path); err == nil {
		p.mtime = st.ModTime()
	}
	return nil
}

// Verify reports whether pin is the client's PIN. The comparison is constant-time, and a
// client with no PIN (or a bad input) still pays for one derivation, so how long the answer
// takes does not say whether the client has a PIN set.
func (p *PINStore) Verify(client, pin string) bool {
	p.mu.Lock()
	p.refresh()
	rec, ok := p.recs[client]
	p.mu.Unlock()

	if !ok {
		// A throwaway record at the standard cost, so the missing-client path is not faster.
		rec = pinRecord{iter: pinIterations, salt: make([]byte, pinSaltLen), hash: make([]byte, pinKeyLen)}
	}
	if len(pin) > pinMaxInput {
		return false
	}
	got, err := derivePIN(pin, rec.salt, rec.iter)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, rec.hash) == 1 && ok
}

// readPINLine reads exactly one line. It reads at most pinMaxInput*2 bytes, so a runaway
// pipe is refused rather than buffered, and it strips only the line terminator: a PIN with
// stray spaces is a wrong PIN, not one to be quietly repaired.
func readPINLine(r io.Reader) (string, error) {
	const limit = pinMaxInput * 2
	buf := make([]byte, 0, 16)
	one := make([]byte, 1)
	for len(buf) <= limit {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimSuffix(string(buf), "\r"), nil
			}
			buf = append(buf, one[0])
		}
		if err == io.EOF {
			if len(buf) == 0 {
				return "", fmt.Errorf("no PIN on stdin: pipe it in, e.g. printf '%%s\\n' \"$PIN\" | openwrt-mcp pin set <client>")
			}
			return strings.TrimSuffix(string(buf), "\r"), nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("the line on stdin is too long to be a PIN")
}

const pinUsage = "usage: openwrt-mcp pin set <client>    (reads one line, the PIN, from stdin)\n" +
	"       openwrt-mcp pin clear <client>"

// runPIN implements the `pin` subcommand. The PIN is only ever read from `in`; an extra
// argument is refused so nobody types one on a command line by habit.
func runPIN(out io.Writer, in io.Reader, statePath string, args []string) error {
	if len(args) != 2 || (args[0] != "set" && args[0] != "clear") {
		return fmt.Errorf("%s", pinUsage)
	}
	client := args[1]
	if err := validClientName(client); err != nil {
		return err
	}
	store, err := LoadPINs(filepath.Join(statePath, "pin"))
	if err != nil {
		return err
	}
	switch args[0] {
	case "set":
		pin, err := readPINLine(in)
		if err != nil {
			return err
		}
		if err := store.Set(client, pin); err != nil {
			return err
		}
		fmt.Fprintf(out, "PIN set for %q. It takes effect on a running daemon without a restart.\n"+
			"Require it with:  option mfa_factor 'pin'  (or 'pin+totp')  in the client's policy.\n", client)
	case "clear":
		was, err := store.Clear(client)
		if err != nil {
			return err
		}
		if was {
			fmt.Fprintf(out, "PIN cleared for %q.\n", client)
		} else {
			fmt.Fprintf(out, "%q has no PIN set; nothing to clear.\n", client)
		}
	}
	return nil
}
