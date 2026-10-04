package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Owner-controlled unlocking: which factors a policy asks for, what a failed attempt costs,
// and when the door closes again. The store is driven with an injected clock throughout, so
// every boundary (the last allowed failure, the instant a lockout ends, the instant a window
// lapses) is pinned exactly rather than approximated with sleeps.

var t0 = time.Unix(1700000000, 0)

func policyFor(factor string) unlockPolicy {
	return unlockPolicy{Factor: factor, Window: 15 * time.Minute, MaxFailures: 5, Lockout: 15 * time.Minute}
}

// enrolled returns a store with both factors set up for the named clients.
func enrolled(t *testing.T, pin string, clients ...string) (*MFAStore, string) {
	t.Helper()
	m, dir := newMFA(t)
	for _, c := range clients {
		if _, _, err := m.Enrol(c, "openwrt-mcp", "testrouter"); err != nil {
			t.Fatal(err)
		}
		if err := m.pins.Set(c, pin); err != nil {
			t.Fatal(err)
		}
	}
	return m, dir
}

// wrongCode is a six-digit code that is not valid at now or its neighbouring steps.
func wrongCode(t *testing.T, m *MFAStore, client string, now time.Time) string {
	t.Helper()
	valid := map[string]bool{}
	for d := -1; d <= 1; d++ {
		valid[codeNow(t, m, client, now.Add(time.Duration(d)*30*time.Second))] = true
	}
	for off := 1; off < 50; off++ {
		if c := codeNow(t, m, client, now.Add(time.Duration(off)*time.Hour)); !valid[c] {
			return c
		}
	}
	t.Fatal("could not find a wrong code")
	return ""
}

func TestAttemptTOTPFactorIsUnchanged(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := policyFor(factorTOTP)

	// The PIN is not a substitute for the code, even when it is right.
	if _, err := m.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0); err == nil {
		t.Fatal("a right PIN unlocked a totp-only client")
	}
	if _, err := m.Attempt("a", unlockAttempt{Code: wrongCode(t, m, "a", t0)}, up, t0); err == nil ||
		err.Error() != "invalid code" {
		t.Errorf("wrong code: got %v, want the historical \"invalid code\"", err)
	}
	code := codeNow(t, m, "a", t0)
	until, err := m.Attempt("a", unlockAttempt{Code: code, PIN: "wrong, and ignored"}, up, t0)
	if err != nil {
		t.Fatalf("a right code was refused: %v", err)
	}
	if !until.Equal(t0.Add(15 * time.Minute)) {
		t.Errorf("window ends %v, want %v", until, t0.Add(15*time.Minute))
	}
	m.Lock("a")
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, up, t0); err == nil || err.Error() != "code already used" {
		t.Errorf("replay: got %v, want \"code already used\"", err)
	}
}

func TestAttemptPINFactor(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := policyFor(factorPIN)
	up.MaxFailures = 100 // this table makes eight wrong attempts; the lockout has its own tests

	for name, in := range map[string]unlockAttempt{
		"wrong PIN":                        {PIN: "4822"},
		"empty":                            {},
		"code only, however valid":         {Code: codeNow(t, m, "a", t0)},
		"right code and wrong PIN":         {PIN: "0000", Code: codeNow(t, m, "a", t0)},
		"PIN with a space":                 {PIN: "4821 "},
		"a different client's right PIN":   {PIN: "1111"},
		"the PIN in the code field":        {Code: "4821"},
		"zero-padded PIN of another value": {PIN: "04821"},
	} {
		if _, err := m.Attempt("a", in, up, t0); err == nil {
			t.Errorf("%s: unlocked", name)
		}
	}
	if _, open := m.UnlockedUntil("a", t0); open {
		t.Fatal("a failed attempt left the window open")
	}
	until, err := m.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0)
	if err != nil {
		t.Fatalf("the right PIN was refused: %v", err)
	}
	if _, open := m.UnlockedUntil("a", t0); !open || !until.Equal(t0.Add(15*time.Minute)) {
		t.Errorf("the right PIN did not open a 15m window (until %v)", until)
	}
}

func TestAttemptPINFactorWithNoPINSetFailsLikeAWrongPIN(t *testing.T) {
	m, _ := newMFA(t)
	m.Enrol("a", "openwrt-mcp", "r")
	m.pins.Set("other", "4821")
	_, errNone := m.Attempt("a", unlockAttempt{PIN: "4821"}, policyFor(factorPIN), t0)
	_, errWrong := m.Attempt("other", unlockAttempt{PIN: "0000"}, policyFor(factorPIN), t0)
	if errNone == nil || errWrong == nil {
		t.Fatal("both must fail")
	}
	if errNone.Error() != errWrong.Error() {
		t.Errorf("having no PIN is distinguishable from a wrong PIN: %q vs %q", errNone, errWrong)
	}
}

func TestAttemptPINPlusTOTPNeedsBothAndSaysNothingAboutWhich(t *testing.T) {
	type tc struct {
		name   string
		pin    string
		code   func(*testing.T, *MFAStore) string
		wantOK bool
	}
	right := func(t *testing.T, m *MFAStore) string { return codeNow(t, m, "a", t0) }
	wrong := func(t *testing.T, m *MFAStore) string { return wrongCode(t, m, "a", t0) }
	none := func(*testing.T, *MFAStore) string { return "" }

	var msgs = map[string]string{}
	for _, c := range []tc{
		{"both right", "4821", right, true},
		{"right PIN, wrong code", "4821", wrong, false},
		{"wrong PIN, right code", "0000", right, false},
		{"both wrong", "0000", wrong, false},
		{"right PIN, code missing", "4821", none, false},
		{"PIN missing, right code", "", right, false},
		{"both missing", "", none, false},
	} {
		m, _ := enrolled(t, "4821", "a")
		_, err := m.Attempt("a", unlockAttempt{PIN: c.pin, Code: c.code(t, m)}, policyFor(factorPINTOTP), t0)
		if c.wantOK != (err == nil) {
			t.Errorf("%s: err = %v, want success = %v", c.name, err, c.wantOK)
			continue
		}
		if err != nil {
			msgs[c.name] = err.Error()
		}
	}
	// Every failure reads the same, so the answer cannot be used to guess one factor at a
	// time.
	first := ""
	for name, m := range msgs {
		if first == "" {
			first = m
		}
		if m != first {
			t.Errorf("%s: %q differs from %q, which tells the caller which factor failed", name, m, first)
		}
		low := strings.ToLower(m)
		if strings.Contains(low, "pin") || strings.Contains(low, "code") || strings.Contains(low, "totp") {
			t.Errorf("%s: %q names a factor", name, m)
		}
	}
}

func TestPINPlusTOTPReplayIsGeneric(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := policyFor(factorPINTOTP)
	code := codeNow(t, m, "a", t0)
	if _, err := m.Attempt("a", unlockAttempt{PIN: "4821", Code: code}, up, t0); err != nil {
		t.Fatal(err)
	}
	m.Lock("a")
	_, err := m.Attempt("a", unlockAttempt{PIN: "4821", Code: code}, up, t0)
	if err == nil {
		t.Fatal("a replayed code unlocked")
	}
	// "code already used" would confirm to a guesser that the PIN half was right.
	if strings.Contains(err.Error(), "already used") {
		t.Errorf("replay reveals that the PIN was right: %q", err)
	}
}

// The reason the PIN is checked first. A guesser who has the client's token but not the
// owner's PIN could otherwise submit codes together with wrong PINs and burn the TOTP replay
// counter, leaving the owner's own code "already used".
func TestAWrongPINDoesNotBurnTheTOTPCounter(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := policyFor(factorPINTOTP)
	code := codeNow(t, m, "a", t0)

	if _, err := m.Attempt("a", unlockAttempt{PIN: "0000", Code: code}, up, t0); err == nil {
		t.Fatal("a wrong PIN unlocked")
	}
	if _, err := m.Attempt("a", unlockAttempt{PIN: "4821", Code: code}, up, t0); err != nil {
		t.Fatalf("the owner's own code was burned by someone else's wrong-PIN guess: %v", err)
	}
}

func TestLockoutBoundaries(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := unlockPolicy{Factor: factorPIN, Window: time.Minute, MaxFailures: 3, Lockout: 10 * time.Minute}
	bad := unlockAttempt{PIN: "0000"}
	good := unlockAttempt{PIN: "4821"}

	// max-1 failures: still open to the right PIN, and success resets the count.
	m.Attempt("a", bad, up, t0)
	m.Attempt("a", bad, up, t0)
	if f := m.State("a", t0).Failures; f != 2 {
		t.Fatalf("failures = %d after two wrong PINs, want 2", f)
	}
	if _, err := m.Attempt("a", good, up, t0); err != nil {
		t.Fatalf("locked out one failure early: %v", err)
	}
	if f := m.State("a", t0).Failures; f != 0 {
		t.Errorf("success left failures at %d, want 0", f)
	}
	// ...so two more failures do not lock it (they would if success had not reset).
	m.Attempt("a", bad, up, t0)
	m.Attempt("a", bad, up, t0)
	if _, err := m.Attempt("a", good, up, t0); err != nil {
		t.Fatalf("failures survived a success: %v", err)
	}

	// max failures: the third locks it.
	for i := 0; i < 3; i++ {
		if st := m.State("a", t0); !st.LockedOutUntil.IsZero() {
			t.Fatalf("locked after only %d failures", i)
		}
		m.Attempt("a", bad, up, t0)
	}
	end := t0.Add(10 * time.Minute)
	if st := m.State("a", t0); !st.LockedOutUntil.Equal(end) || st.Failures != 3 {
		t.Fatalf("state = %+v, want locked until %v with 3 failures", st, end)
	}

	// During the lockout even the right PIN is refused, and the refusal names the end time.
	for _, at := range []time.Duration{0, time.Second, 5 * time.Minute, 10*time.Minute - time.Nanosecond} {
		_, err := m.Attempt("a", good, up, t0.Add(at))
		if err == nil {
			t.Fatalf("unlocked %v into a lockout", at)
		}
		if !strings.Contains(err.Error(), end.Format(time.RFC3339)) {
			t.Errorf("at +%v the refusal does not name when it ends (%s): %q", at, end.Format(time.RFC3339), err)
		}
	}
	// Refused attempts are not counted and do not extend the lockout.
	if st := m.State("a", t0.Add(9*time.Minute)); st.Failures != 3 || !st.LockedOutUntil.Equal(end) {
		t.Errorf("refused attempts changed the state: %+v", st)
	}
	if _, open := m.UnlockedUntil("a", t0.Add(5*time.Minute)); open {
		t.Error("the window opened during a lockout")
	}

	// The instant it ends, the right PIN works.
	if _, err := m.Attempt("a", good, up, end); err != nil {
		t.Fatalf("still locked out at the end instant: %v", err)
	}
	if st := m.State("a", end); st.Failures != 0 || !st.LockedOutUntil.IsZero() {
		t.Errorf("state after the lockout and a success = %+v", st)
	}
}

func TestAfterALockoutTheCountStartsAgain(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := unlockPolicy{Factor: factorPIN, Window: time.Minute, MaxFailures: 2, Lockout: time.Minute}
	bad := unlockAttempt{PIN: "0000"}
	m.Attempt("a", bad, up, t0)
	m.Attempt("a", bad, up, t0) // locked until t0+1m

	later := t0.Add(time.Minute)
	m.Attempt("a", bad, up, later) // the lockout has ended: this is failure 1 of a fresh count
	if st := m.State("a", later); !st.LockedOutUntil.IsZero() || st.Failures != 1 {
		t.Fatalf("one failure after a lockout re-locked at once: %+v", st)
	}
	m.Attempt("a", bad, up, later)
	if st := m.State("a", later); st.LockedOutUntil.IsZero() {
		t.Error("two fresh failures did not lock again")
	}
}

// Refusing during a lockout must not even look at the factors: the point is that a guesser
// learns nothing and that nobody's replay counter moves.
func TestALockoutChecksNoFactor(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := unlockPolicy{Factor: factorTOTP, Window: time.Minute, MaxFailures: 1, Lockout: 20 * time.Second}
	m.Attempt("a", unlockAttempt{Code: wrongCode(t, m, "a", t0)}, up, t0) // locks at once

	code := codeNow(t, m, "a", t0)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, up, t0.Add(5*time.Second)); err == nil {
		t.Fatal("a valid code unlocked during the lockout")
	}
	// The same code, still inside its acceptance span once the lockout is over, is good. If
	// the refused attempt had consumed it, this would say "already used".
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, up, t0.Add(20*time.Second)); err != nil {
		t.Fatalf("the refused attempt consumed the code: %v", err)
	}
}

func TestLockoutIsPerClient(t *testing.T) {
	m, _ := enrolled(t, "4821", "a", "b")
	up := unlockPolicy{Factor: factorPIN, Window: time.Minute, MaxFailures: 2, Lockout: time.Minute}
	m.Attempt("a", unlockAttempt{PIN: "0"}, up, t0)
	m.Attempt("a", unlockAttempt{PIN: "0"}, up, t0)
	if st := m.State("a", t0); st.LockedOutUntil.IsZero() {
		t.Fatal("a was not locked out")
	}
	if st := m.State("b", t0); !st.LockedOutUntil.IsZero() || st.Failures != 0 {
		t.Errorf("a's failures were charged to b: %+v", st)
	}
	if _, err := m.Attempt("b", unlockAttempt{PIN: "4821"}, up, t0); err != nil {
		t.Errorf("b was locked out by a's failures: %v", err)
	}
}

func TestWindowExpiresExactlyAtItsEnd(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := unlockPolicy{Factor: factorPIN, Window: 5 * time.Minute, MaxFailures: 5, Lockout: time.Minute}
	until, err := m.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, open := m.UnlockedUntil("a", until.Add(-time.Nanosecond)); !open {
		t.Error("closed early")
	}
	if _, open := m.UnlockedUntil("a", until); open {
		t.Error("still open at the end instant")
	}
	if st := m.State("a", t0); !st.UnlockedUntil.Equal(until) {
		t.Errorf("State reports %v, want %v", st.UnlockedUntil, until)
	}
	if st := m.State("a", until); !st.UnlockedUntil.IsZero() {
		t.Errorf("State still reports an expired window: %v", st.UnlockedUntil)
	}
}

func TestLockClosesTheWindowAndSaysWhetherItWasOpen(t *testing.T) {
	m, _ := enrolled(t, "4821", "a", "b")
	up := policyFor(factorPIN)
	m.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0)
	m.Attempt("b", unlockAttempt{PIN: "4821"}, up, t0)

	if !m.LockAt("a", t0) {
		t.Error("Lock did not report that a window was open")
	}
	if _, open := m.UnlockedUntil("a", t0); open {
		t.Error("the window is still open after Lock")
	}
	if _, open := m.UnlockedUntil("b", t0); !open {
		t.Error("locking a closed b's window")
	}
	m.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0)
	if m.LockAt("a", t0.Add(16*time.Minute)) {
		t.Error("Lock reported an already-expired window as open")
	}
	if m.LockAt("a", t0) {
		t.Error("Lock reported a window that was already closed")
	}
	if m.LockAt("nobody", t0) {
		t.Error("Lock reported a window for a client that never unlocked")
	}
}

func TestLockDoesNotForgiveFailures(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	up := unlockPolicy{Factor: factorPIN, Window: time.Minute, MaxFailures: 3, Lockout: time.Minute}
	m.Attempt("a", unlockAttempt{PIN: "0"}, up, t0)
	m.Lock("a")
	if f := m.State("a", t0).Failures; f != 1 {
		t.Errorf("Lock cleared the failure count (now %d); it must not be a way to reset the throttle", f)
	}
}

// Rotating a PIN is what the owner does after a scare, and it must take effect on a running
// daemon at once: the old window closes, and a lockout the guesser caused is lifted.
func TestRotatingAPINClosesTheWindowAndLiftsTheLockout(t *testing.T) {
	dir := t.TempDir()
	daemon, _ := LoadMFA(filepath.Join(dir, "mfa"))
	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	daemon.Enrol("a", "openwrt-mcp", "r")
	cli.pins.Set("a", "4821")
	os.Chtimes(filepath.Join(dir, "pin"), t0, t0)
	up := unlockPolicy{Factor: factorPIN, Window: time.Hour, MaxFailures: 2, Lockout: time.Hour}

	if _, err := daemon.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0); err != nil {
		t.Fatalf("the daemon did not see the PIN set by another process: %v", err)
	}
	cli.pins.Set("a", "9999")
	os.Chtimes(filepath.Join(dir, "pin"), t0.Add(time.Minute), t0.Add(time.Minute))
	daemon.Attempt("a", unlockAttempt{PIN: "x"}, up, t0.Add(time.Minute)) // any call reloads
	if _, open := daemon.UnlockedUntil("a", t0.Add(time.Minute)); open {
		t.Error("a window opened under the old PIN survived its rotation")
	}

	// Lock the client out, then rotate: the owner gets back in without waiting or restarting.
	daemon.Attempt("a", unlockAttempt{PIN: "x"}, up, t0.Add(2*time.Minute))
	if st := daemon.State("a", t0.Add(2*time.Minute)); st.LockedOutUntil.IsZero() {
		t.Fatal("setup: not locked out")
	}
	cli.pins.Set("a", "5555")
	os.Chtimes(filepath.Join(dir, "pin"), t0.Add(time.Hour), t0.Add(time.Hour))
	if _, err := daemon.Attempt("a", unlockAttempt{PIN: "5555"}, up, t0.Add(3*time.Minute)); err != nil {
		t.Errorf("setting a new PIN did not lift the lockout: %v", err)
	}
}

func TestClearingAPINClosesTheWindow(t *testing.T) {
	dir := t.TempDir()
	daemon, _ := LoadMFA(filepath.Join(dir, "mfa"))
	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	cli.pins.Set("a", "4821")
	os.Chtimes(filepath.Join(dir, "pin"), t0, t0)
	up := policyFor(factorPIN)
	if _, err := daemon.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0); err != nil {
		t.Fatal(err)
	}
	cli.pins.Clear("a")
	os.Chtimes(filepath.Join(dir, "pin"), t0.Add(time.Minute), t0.Add(time.Minute))
	if _, err := daemon.Attempt("a", unlockAttempt{PIN: "4821"}, up, t0.Add(time.Minute)); err == nil {
		t.Error("a cleared PIN still unlocks")
	}
	if _, open := daemon.UnlockedUntil("a", t0.Add(time.Minute)); open {
		t.Error("clearing the PIN left the window open")
	}
}

func TestRotatingTheTOTPSecretLiftsALockout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa")
	daemon, _ := LoadMFA(path)
	cli, _ := LoadMFA(path)
	cli.Enrol("a", "openwrt-mcp", "r")
	os.Chtimes(path, t0, t0)
	up := unlockPolicy{Factor: factorTOTP, Window: time.Hour, MaxFailures: 1, Lockout: time.Hour}
	daemon.Attempt("a", unlockAttempt{Code: "000000"}, up, t0)
	if st := daemon.State("a", t0); st.LockedOutUntil.IsZero() {
		t.Fatal("setup: not locked out")
	}
	secret, _, _ := cli.Enrol("a", "openwrt-mcp", "r") // rotate
	os.Chtimes(path, t0.Add(time.Hour), t0.Add(time.Hour))
	code, _ := totpAt(secret, uint64(t0.Add(time.Minute).Unix())/30)
	if _, err := daemon.Attempt("a", unlockAttempt{Code: code}, up, t0.Add(time.Minute)); err != nil {
		t.Errorf("re-enrolling did not lift the lockout: %v", err)
	}
}

func TestUnlockStillWorksThroughTheOldEntryPoint(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	code := codeNow(t, m, "a", t0)
	if _, err := m.Unlock("a", code, time.Minute, t0); err != nil {
		t.Fatal(err)
	}
	// And it is subject to the lockout like every other way in.
	for i := 0; i < 5; i++ {
		m.Unlock("a", "000000", time.Minute, t0)
	}
	m.Lock("a")
	if _, err := m.Unlock("a", codeNow(t, m, "a", t0.Add(30*time.Second)), time.Minute, t0.Add(30*time.Second)); err == nil ||
		!strings.Contains(err.Error(), "locked out") {
		t.Errorf("Unlock bypasses the lockout: %v", err)
	}
}

func TestUnknownFactorNeverUnlocks(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	for _, f := range []string{"", "sms", "TOTP", "none"} {
		up := policyFor(f)
		if f == "" {
			// A zero value is the default factor, not an open door.
			if _, err := m.Attempt("a", unlockAttempt{}, up, t0); err == nil {
				t.Error("an empty attempt unlocked under the default factor")
			}
			continue
		}
		if _, err := m.Attempt("a", unlockAttempt{PIN: "4821", Code: codeNow(t, m, "a", t0)}, up, t0); err == nil {
			t.Errorf("factor %q unlocked", f)
		}
	}
}

func TestUnlockPolicyDefaultsFillZeroValues(t *testing.T) {
	got := (&Policy{}).unlockPolicy()
	want := unlockPolicy{Factor: factorTOTP, Window: defaultMFAWindow,
		MaxFailures: defaultMFAMaxFailures, Lockout: defaultMFALockout}
	if got != want {
		t.Errorf("zero policy -> %+v, want %+v", got, want)
	}
	if defaultMFAMaxFailures != 5 || defaultMFALockout != 15*time.Minute {
		t.Errorf("defaults are %d and %v, want 5 and 15m", defaultMFAMaxFailures, defaultMFALockout)
	}
	p := &Policy{MFAFactor: factorPIN, MFAWindow: time.Minute, MFAMaxFailures: 9, MFALockout: time.Hour}
	if got := p.unlockPolicy(); got != (unlockPolicy{factorPIN, time.Minute, 9, time.Hour}) {
		t.Errorf("explicit policy -> %+v", got)
	}
}
