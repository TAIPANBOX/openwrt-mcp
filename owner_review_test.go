package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The code typed to activate a secret is entered in another process (the CLI, or a web page
// behind it). The daemon learns of the new secret only by reloading the file, so unless the
// spent step travels with it, that code is good once more for the rest of its 90 seconds.
func TestADaemonRefusesTheCodeThatActivatedASecret(t *testing.T) {
	daemon, dir := enrolRig(t)
	cli, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runMFAEnrol(io.Discard, cli, dir, []string{"a", "--pending"}); err != nil {
		t.Fatal(err)
	}
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	step := uint64(t0.Unix()) / 30
	code, _ := totpAt(pend["a"], step)
	if err := runMFAActivate(io.Discard, cli, []string{"a", code}, t0); err != nil {
		t.Fatal(err)
	}

	if _, err := daemon.Attempt("a", unlockAttempt{Code: code}, policyFor(factorTOTP), t0.Add(10*time.Second)); err == nil {
		t.Fatal("the daemon accepted the code that activated the secret")
	}
	next, _ := totpAt(pend["a"], step+1)
	if _, err := daemon.Attempt("a", unlockAttempt{Code: next}, policyFor(factorTOTP), t0.Add(30*time.Second)); err != nil {
		t.Fatalf("a fresh code after activation was refused: %v", err)
	}
}

// A spent step recorded for an older secret must not block the new one.
func TestASpentStepOnlyCountsForTheSecretItWasSpentOn(t *testing.T) {
	daemon, dir := enrolRig(t)
	cli, _ := LoadMFA(filepath.Join(dir, "mfa"))
	runMFAEnrol(io.Discard, cli, dir, []string{"a", "--pending"})
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	step := uint64(t0.Unix()) / 30
	code, _ := totpAt(pend["a"], step)
	if err := runMFAActivate(io.Discard, cli, []string{"a", code}, t0); err != nil {
		t.Fatal(err)
	}
	// Rotated again with a plain enrol, in the CLI: nothing has been spent on this secret.
	fresh, _, err := cli.Enrol("a", "openwrt-mcp", "r")
	if err != nil {
		t.Fatal(err)
	}
	bump(t, filepath.Join(dir, "mfa"))
	c2, _ := totpAt(fresh, step)
	if _, err := daemon.Attempt("a", unlockAttempt{Code: c2}, policyFor(factorTOTP), t0.Add(5*time.Second)); err != nil {
		t.Fatalf("a step spent on the old secret blocked the new one: %v", err)
	}
}

// One client can be named by several policies. Unlocking is per client, so if two of them
// gate tools and disagree on how, the refusal from one would ask for a factor the unlock then
// does not check. Such a config must not load.
func TestAClientsGatingPoliciesMustAgreeOnHowToUnlock(t *testing.T) {
	pol := func(tool, opts string) string {
		return "config policy\n\toption client 'a'\n\tlist tools '" + tool + "'\n\tlist scopes '*'\n" +
			"\tlist mfa_tools '" + tool + "'\n" + opts + "\n"
	}
	for name, c := range map[string]struct{ second, mention string }{
		"factor":       {"\toption mfa_factor 'pin'", "mfa_factor"},
		"window":       {"\toption mfa_window '5m'", "mfa_window"},
		"max failures": {"\toption mfa_max_failures '3'", "mfa_max_failures"},
		"lockout":      {"\toption mfa_lockout '1h'", "mfa_lockout"},
	} {
		p := filepath.Join(t.TempDir(), "config")
		os.WriteFile(p, []byte(pol("exec", "")+pol("uci_apply", c.second)), 0o600)
		_, err := LoadConfig(p)
		if err == nil {
			t.Errorf("%s: two gating policies for one client that disagree loaded", name)
			continue
		}
		if !strings.Contains(err.Error(), c.mention) || !strings.Contains(err.Error(), `"a"`) {
			t.Errorf("%s: the error %q names neither %s nor the client", name, err, c.mention)
		}
	}

	// Agreeing policies load, and a policy that gates nothing may say anything.
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(pol("exec", "\toption mfa_factor 'pin'")+pol("uci_apply", "\toption mfa_factor 'pin'")+
		"config policy\n\toption client 'a'\n\tlist tools 'logread'\n\tlist scopes '*'\n\toption mfa_factor 'totp'\n"), 0o600)
	if _, err := LoadConfig(p); err != nil {
		t.Fatalf("agreeing policies were refused: %v", err)
	}
}

// bump moves a file's mtime forward, so a reload keyed on mtime cannot miss a rewrite that
// landed within the filesystem's timestamp granularity.
func bump(t *testing.T, path string) {
	t.Helper()
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}
