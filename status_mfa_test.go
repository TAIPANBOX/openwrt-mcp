package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What `status --json` says about each client's unlock factors, and -- the point of several
// of these tests -- what it must never say. The report goes to a browser on the router's
// admin panel.

const statusMFAConfig = `
config policy
	option client 'alpha'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'
	option mfa_factor 'pin+totp'

config policy
	option client 'beta'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'

config policy
	option client 'gamma'
	list tools 'exec'
	list scopes '*'
`

// statusRig sets up three paired clients: alpha with a TOTP secret and a PIN, beta with only
// a pending TOTP secret, gamma with nothing. It returns the state dir and the secrets that
// must never surface.
func statusRig(t *testing.T) (dir, cfg string, secrets []string) {
	t.Helper()
	dir = t.TempDir()
	cfg = statusFile(t, dir, "config", "config server\n\toption audit '"+dir+"/audit.jsonl'\n"+statusMFAConfig)
	ts, err := LoadTokens(filepath.Join(dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"alpha", "beta", "gamma"} {
		if _, err := ts.Mint(c); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	alphaSecret, _, _ := ms.Enrol("alpha", "openwrt-mcp", "r")
	betaSecret, _, _ := ms.EnrolPending("beta", "openwrt-mcp", "r")
	if err := ms.pins.Set("alpha", "73918246"); err != nil {
		t.Fatal(err)
	}
	// Everything that is credential material in the pin file: the PIN, salt and hash.
	raw, _ := os.ReadFile(filepath.Join(dir, "pin"))
	rec := strings.Fields(strings.TrimSpace(strings.Split(string(raw), "\n")[2]))[1]
	parts := strings.Split(rec, "$")
	return dir, cfg, []string{alphaSecret, betaSecret, "73918246", parts[2], parts[3], rec}
}

func statusClients(t *testing.T, cfg, dir string) (map[string]mfaReport, string) {
	t.Helper()
	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, true); err != nil {
			t.Fatal(err)
		}
	})
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	m := map[string]mfaReport{}
	for _, c := range rep.Clients {
		m[c.Name] = c.MFA
	}
	return m, out
}

func TestStatusReportsEachClientsUnlockFactors(t *testing.T) {
	dir, cfg, _ := statusRig(t)
	got, _ := statusClients(t, cfg, dir)

	want := map[string]mfaReport{
		"alpha": {Factor: "pin+totp", TOTPEnrolled: true, PINSet: true},
		"beta":  {Factor: "totp", TOTPPending: true},
		"gamma": {Factor: "none"},
	}
	if len(got) != 3 {
		t.Fatalf("clients = %v", got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %+v, want %+v", name, got[name], w)
		}
	}
	// The runtime fields are not knowable from another process, and the report says so
	// rather than claiming "no failures" and "locked".
	for name, r := range got {
		if r.LiveState || r.UnlockedUntil != "" || r.LockedOutUntil != "" || r.Failures != 0 {
			t.Errorf("%s: a separate process claimed live state: %+v", name, r)
		}
	}
}

func TestStatusNeverContainsASecretAHashOrASalt(t *testing.T) {
	dir, cfg, secrets := statusRig(t)
	_, raw := statusClients(t, cfg, dir)
	text := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, false); err != nil {
			t.Fatal(err)
		}
	})
	for _, s := range secrets {
		if s == "" {
			t.Fatal("test setup produced an empty secret")
		}
		if strings.Contains(raw, s) || strings.Contains(text, s) {
			t.Errorf("%q reached the status output", s)
		}
	}
	for _, w := range []string{"pbkdf2", "otpauth", "secret", "salt", "hash"} {
		if strings.Contains(strings.ToLower(raw), w) {
			t.Errorf("the JSON mentions %q", w)
		}
	}
}

func TestStatusTextSaysWhichFactorsAreMissing(t *testing.T) {
	dir, cfg, _ := statusRig(t)
	text := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, false); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"unlock factor pin+totp: totp set, pin set",
		"unlock factor totp: totp pending activation, pin not set",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "gamma (0 policy/policies)\n    unlock") {
		t.Errorf("an ungated client got an unlock line:\n%s", text)
	}
}

// Whoever holds the daemon's own store can see the runtime state, and then it must be right.
func TestMFAReportFromTheDaemonShowsLiveState(t *testing.T) {
	m, _ := enrolled(t, "4821", "a")
	cfg := parse(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n"+
		"\tlist mfa_tools 'exec'\n\toption mfa_factor 'pin'\n\toption mfa_max_failures '2'\n")
	up := cfg.Policies[0].unlockPolicy()

	r := buildMFAReport(m, cfg, "a", t0, true)
	if !r.LiveState || r.UnlockedUntil != "" || r.LockedOutUntil != "" || r.Failures != 0 {
		t.Errorf("fresh: %+v", r)
	}
	if !r.PINSet || !r.TOTPEnrolled || r.Factor != "pin" {
		t.Errorf("facts: %+v", r)
	}

	m.Attempt("a", unlockAttempt{PIN: "0"}, up, t0)
	if r := buildMFAReport(m, cfg, "a", t0, true); r.Failures != 1 || r.LockedOutUntil != "" {
		t.Errorf("one failure: %+v", r)
	}
	m.Attempt("a", unlockAttempt{PIN: "0"}, up, t0)
	r = buildMFAReport(m, cfg, "a", t0, true)
	if r.Failures != 2 || r.LockedOutUntil != t0.Add(15*time.Minute).Format(time.RFC3339) {
		t.Errorf("locked out: %+v", r)
	}

	// After the lockout the owner gets in, and the report shows the window.
	later := t0.Add(16 * time.Minute)
	if _, err := m.Attempt("a", unlockAttempt{PIN: "4821"}, up, later); err != nil {
		t.Fatal(err)
	}
	r = buildMFAReport(m, cfg, "a", later, true)
	if r.UnlockedUntil != later.Add(15*time.Minute).Format(time.RFC3339) || r.Failures != 0 || r.LockedOutUntil != "" {
		t.Errorf("unlocked: %+v", r)
	}
	// The same store seen as a separate process would see it hides all of that.
	if r := buildMFAReport(m, cfg, "a", later, false); r.UnlockedUntil != "" || r.LiveState {
		t.Errorf("a non-live report leaked runtime state: %+v", r)
	}
}

func TestMFAReportWithAnUnreadableStoreFailsSoft(t *testing.T) {
	cfg := parse(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n\tlist mfa_tools 'exec'\n")
	r := buildMFAReport(nil, cfg, "a", t0, false)
	if r.Factor != "totp" || r.TOTPEnrolled || r.PINSet || r.TOTPPending {
		t.Errorf("%+v", r)
	}
}

func TestStatusIgnoresADisabledGatingPolicy(t *testing.T) {
	cfg := parse(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n"+
		"\tlist mfa_tools 'exec'\n\toption mfa_factor 'pin'\n\toption enabled '0'\n")
	if r := buildMFAReport(nil, cfg, "a", t0, false); r.Factor != "none" {
		t.Errorf("a disabled policy still sets the factor: %+v", r)
	}
}
