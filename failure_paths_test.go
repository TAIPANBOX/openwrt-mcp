package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What happens when the disk, the state files or the inputs misbehave. Each of these is a
// way a security control can fail silently: a PIN that was "set" but not written, a secret
// that vanished because one read failed, a refusal that was never audited.

// blocked returns the path of a state file that can be read (it does not exist yet) but
// never written: the sidecar it would be written through is occupied by a directory. That
// holds for root too, unlike a read-only directory.
func blocked(t *testing.T, name, sidecar string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, name+sidecar), 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func TestPINWritesReportADiskFailureInsteadOfPretending(t *testing.T) {
	p, err := LoadPINs(blocked(t, "pin", ".new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Set("a", "1234"); err == nil {
		t.Error("Set reported success though nothing could be written")
	}
	// Clear fails the same way.
	p3, _ := LoadPINs(blocked(t, "pin", ".new"))
	p3.recs["a"], _ = parsePINRecord("pbkdf2-sha256$1000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if _, err := p3.Clear("a"); err == nil {
		t.Error("Clear reported success though the file could not be rewritten")
	}
}

func TestRunPINReportsAnUnreadableStore(t *testing.T) {
	state := t.TempDir()
	os.Mkdir(filepath.Join(state, "pin"), 0o700) // a directory where the file should be
	for _, args := range [][]string{{"set", "a"}, {"clear", "a"}} {
		if err := runPIN(io.Discard, strings.NewReader("1234\n"), state, args); err == nil {
			t.Errorf("%v: an unreadable pin store was ignored", args)
		}
	}
}

func TestEnrolReportsADiskFailure(t *testing.T) {
	path := blocked(t, "mfa", ".new")
	os.Mkdir(path+".pending.new", 0o700)
	m, err := LoadMFA(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Enrol("a", "openwrt-mcp", "r"); err == nil {
		t.Error("Enrol reported success though the secret was not saved")
	}
	if _, _, err := m.EnrolPending("a", "openwrt-mcp", "r"); err == nil {
		t.Error("EnrolPending reported success though the secret was not saved")
	}
	if err := runMFAEnrol(io.Discard, m, "x", []string{"a"}); err == nil {
		t.Error("the CLI hid a failed enrolment")
	}
	if err := runMFAEnrol(io.Discard, m, "x", []string{"a", "--json"}); err == nil {
		t.Error("the CLI hid a failed enrolment under --json")
	}
}

func TestActivateReportsAnUnreadablePendingFile(t *testing.T) {
	m, dir := enrolRig(t)
	os.MkdirAll(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "mfa.pending"), 0o700)
	if err := m.Activate("a", "123456", t0); err == nil || strings.Contains(err.Error(), "no pending") {
		t.Errorf("an unreadable pending file was reported as 'none pending': %v", err)
	}
	if m.TOTPPending("a") {
		t.Error("an unreadable pending file counts as pending")
	}
	if _, _, err := m.EnrolPending("a", "openwrt-mcp", "r"); err == nil {
		t.Error("EnrolPending overwrote a pending store it could not read")
	}
}

func TestActivateReportsAFailureToSaveTheActiveFile(t *testing.T) {
	m, dir := enrolRig(t)
	runMFAEnrol(io.Discard, m, dir, []string{"a", "--pending"})
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	code, _ := totpAt(pend["a"], uint64(t0.Unix())/30)
	os.Mkdir(filepath.Join(dir, "mfa"), 0o700) // the active file can no longer be replaced
	m.path = filepath.Join(dir, "mfa")
	if err := m.Activate("a", code, t0); err == nil {
		t.Error("Activate reported success though the active file was not written")
	}
	if !m.TOTPPending("a") {
		t.Error("a failed activation lost the pending secret")
	}
}

func TestLoadMFAErrorsAreNotSilent(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "mfa"), 0o700)
	if _, err := LoadMFA(filepath.Join(dir, "mfa")); err == nil {
		t.Error("an unreadable secrets file loaded as empty, silently dropping every enrolment")
	}
	dir2 := t.TempDir()
	os.Mkdir(filepath.Join(dir2, "pin"), 0o700)
	if _, err := LoadMFA(filepath.Join(dir2, "mfa")); err == nil {
		t.Error("an unreadable pin store loaded as empty")
	}
}

func TestMFAReloadKeepsSecretsWhenTheFileBecomesUnreadable(t *testing.T) {
	m, dir := newMFA(t)
	secret, _, _ := m.Enrol("a", "openwrt-mcp", "r")
	path := filepath.Join(dir, "mfa")
	os.Remove(path)
	os.Mkdir(path, 0o700)
	os.Chtimes(path, t0, t0)
	code, _ := totpAt(secret, uint64(t0.Unix())/30)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, policyFor(factorTOTP), t0); err != nil {
		t.Errorf("a half-written secrets file wiped a working secret: %v", err)
	}
}

func TestMFAFileLinesWithoutASecretAreSkipped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mfa")
	os.WriteFile(p, []byte("# c\n\nlonely\nok SECRET\n"), 0o600)
	got, err := parseMFAFile(p)
	if err != nil || len(got) != 1 || got["ok"] != "SECRET" {
		t.Errorf("%v %v", got, err)
	}
	m, _ := LoadMFA(p)
	if cs := m.Clients(); len(cs) != 1 || cs[0] != "ok" {
		t.Errorf("Clients() = %v", cs)
	}
}

func TestParseMFAWindow(t *testing.T) {
	for in, want := range map[string]time.Duration{"": defaultMFAWindow, "  ": defaultMFAWindow,
		"5m": 5 * time.Minute, "1h": time.Hour, "2d": 48 * time.Hour} {
		if got, err := parseMFAWindow(in); err != nil || got != want {
			t.Errorf("%q -> %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0s", "-5m", "soon", "5"} {
		if _, err := parseMFAWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMatchTOTPRejectsMalformedSecretsAndCodes(t *testing.T) {
	if _, ok := matchTOTP("!!!not base32!!!", "123456", t0); ok {
		t.Error("a malformed secret matched")
	}
	secret, _ := newTOTPSecret()
	code, _ := totpAt(secret, uint64(t0.Unix())/30)
	if ctr, ok := matchTOTP(secret, code, t0); !ok || ctr != uint64(t0.Unix())/30 {
		t.Errorf("a valid code: %d %v", ctr, ok)
	}
	// One step either side is accepted, two is not.
	if _, ok := matchTOTP(secret, code, t0.Add(30*time.Second)); !ok {
		t.Error("the previous step was refused")
	}
	if _, ok := matchTOTP(secret, code, t0.Add(60*time.Second)); ok {
		t.Error("a code two steps old was accepted")
	}
}

func TestAClientWithNoPolicyIsHeldToTheDefaults(t *testing.T) {
	s, _ := newToolRig(t, "")
	s.mfa.Enrol("a", "openwrt-mcp", "r")
	if up := s.unlockPolicyFor("a"); up != (&Policy{}).unlockPolicy() {
		t.Errorf("unlockPolicyFor = %+v", up)
	}
	out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"code": liveCode(t, s, "a", time.Now())})
	if isErr || !strings.Contains(out, "Unlocked until") || !strings.Contains(out, "15m0s") {
		t.Errorf("%q (error=%v)", out, isErr)
	}
}

func TestADisabledPolicyDoesNotSetTheUnlockRules(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin", "option enabled '0'"))
	if up := s.unlockPolicyFor("a"); up.Factor != factorTOTP {
		t.Errorf("a disabled policy still chose the factor: %+v", up)
	}
}

func TestExecErrorKeepsTheCommandsOutput(t *testing.T) {
	s, _ := newToolRig(t, allToolsPolicy)
	out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"sh", "-c", "echo diagnostic; exit 1"}})
	if !isErr || !strings.Contains(out, "diagnostic") {
		t.Errorf("a failing command's output was dropped: %q (error=%v)", out, isErr)
	}
}

func TestUbusCallRefusesArgsItCannotEncode(t *testing.T) {
	_, _, err := ubusCall(context.Background(), ubusCallIn{Object: "a", Method: "b", Args: map[string]any{"f": func() {}}})
	if err == nil || !strings.Contains(err.Error(), "not encodable") {
		t.Errorf("err = %v", err)
	}
}

func TestPruneUbusJSONLeavesWhatItCannotImprove(t *testing.T) {
	big := strings.Repeat("x", pruneMinBytes+10)
	if got := pruneUbusJSON(big); got != big {
		t.Error("non-JSON over the size gate was altered")
	}
	longString := `{"k":"` + big + `"}`
	if got := pruneUbusJSON(longString); got != longString {
		t.Error("JSON with no long array was altered")
	}
}

// -------------------------------------------------------------------- server

func TestNewServerFailsOnAnUnreadableTokenStore(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "tokens"), 0o700)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, nil, 0o600)
	if _, err := NewServer(cfg, dir); err == nil {
		t.Error("an unreadable token store started a server")
	}
}

func TestApplyReportsAnUnwritableSnapshotDirectory(t *testing.T) {
	r := newRollbackRig(t)
	os.MkdirAll(r.stateDir, 0o700)
	os.WriteFile(filepath.Join(r.stateDir, "rollback"), []byte("a file, not a dir"), 0o600)
	s := r.server(t)
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "snapshot failed") {
		t.Errorf("err = %v", err)
	}
	if got := r.read(t); got != "original\n" {
		t.Errorf("config touched despite no snapshot: %q", got)
	}
}

func TestApplyReportsATarFailureAndLeavesNothingBehind(t *testing.T) {
	r := newRollbackRig(t)
	fakeCmd(t, "tar", `echo "tar: forced failure" >&2; exit 2`)
	s := r.server(t)
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "snapshot failed") {
		t.Errorf("err = %v", err)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("left %v", left)
	}
	if got := r.read(t); got != "original\n" {
		t.Errorf("config = %q", got)
	}
}

func TestRecoveryWithACorruptSnapshotKeepsTheConfigAndMovesOn(t *testing.T) {
	r := newRollbackRig(t)
	os.MkdirAll(filepath.Join(r.stateDir, "rollback"), 0o700)
	snap := filepath.Join(r.stateDir, "rollback", "bad.tar.gz")
	os.WriteFile(snap, []byte("this is not a tarball"), 0o600)
	os.WriteFile(r.configPath, []byte("changed by apply\n"), 0o644)
	rec, _ := json.Marshal([]pendingApply{{Token: "bad", Snapshot: snap, Configs: []string{"network"}}})
	os.WriteFile(filepath.Join(r.stateDir, "pending.json"), rec, 0o600)
	r.server(t)
	if got := r.read(t); got != "changed by apply\n" {
		t.Errorf("a corrupt snapshot altered the config: %q", got)
	}
	if _, err := os.Stat(snap); err != nil {
		t.Error("a snapshot that failed to restore was deleted: it is the only copy")
	}
}

// The rollback timer is the whole point of uci_apply: nobody confirms, and it undoes itself.
func TestAnUnconfirmedApplyRollsItselfBackWhenTheTimerFires(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	if _, _, err := s.uciApply(context.Background(), uciApplyIn{Changes: oneChange.Changes, Timeout: 1}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(r.configPath, []byte("changed by apply\n"), 0o644)
	deadline := time.Now().Add(10 * time.Second)
	for r.read(t) != "original\n" {
		if time.Now().After(deadline) {
			t.Fatal("the timer never rolled the change back")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The config is restored first and the snapshot removed after the reload, so wait for that.
	for len(r.snapshots(t)) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the snapshot was never deleted after the timer rollback: %v", r.snapshots(t))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// -------------------------------------------------------------------- status and audit

func TestStatusTextShowsExpiryAndRecentAuditAndState(t *testing.T) {
	var b bytes.Buffer
	writeStatusText(&b, statusReport{
		Version: "9.9", Listen: "127.0.0.1:1", Running: true,
		Clients: []clientReport{{Name: "a", Policies: 2}},
		Policies: []policyReport{{Client: "a", Tools: []string{"exec"}, Scopes: []string{"*"}, MaxPerMin: 5,
			Expires: "2020-01-01T00:00:00Z", Expired: true}, {Client: "a", Tools: []string{"x"}, MaxPerMin: 1}},
		Audit: []auditRow{{Time: "t", Outcome: "OK", Tool: "exec", Scope: "uptime"}},
	})
	out := b.String()
	for _, want := range []string{"running on 127.0.0.1:1", "expires 2020-01-01T00:00:00Z (EXPIRED)", "expires never",
		"OK", "uptime"} {
		if !strings.Contains(out, want) {
			t.Errorf("status text lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	writeStatusText(&b, statusReport{Version: "9.9", Listen: "x"})
	if !strings.Contains(b.String(), "stopped") {
		t.Errorf("a stopped daemon was not shown as stopped: %q", b.String())
	}
}

func TestStatusReportsABrokenConfigAsAnError(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config policy\n\toption client 'a'\n")
	if err := runStatus(cfg, dir, 0, true); err == nil {
		t.Error("status printed a report from a config that does not parse")
	}
}

func TestStatusShowsAnExpiryOnAPolicy(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config server\n\toption audit '"+dir+"/a'\n"+
		"config policy\n\toption client 'a'\n\tlist tools 'exec'\n\toption expires '2020-01-01'\n")
	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, true); err != nil {
			t.Fatal(err)
		}
	})
	var rep statusReport
	json.Unmarshal([]byte(out), &rep)
	if len(rep.Policies) != 1 || !rep.Policies[0].Expired || rep.Policies[0].Expires == "" {
		t.Errorf("%+v", rep.Policies)
	}
}

func TestDaemonRunningFallsBackToTheDefaultAddress(t *testing.T) {
	// Nothing in the test environment answers on the default port as openwrt-mcp.
	if daemonRunning("") && !daemonRunning(defaultListen) {
		t.Error("an empty listen address must mean the default one")
	}
}

func TestAuditRecordSurvivesAnUnwritablePath(t *testing.T) {
	a := NewAuditor(filepath.Join(t.TempDir(), "x", "y", "audit.jsonl"), 1)
	a.Record(AuditEvent{Client: "c", Outcome: OutcomeOK}) // must not panic or block
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "audit.jsonl"), 0o700) // a directory where the log should be
	NewAuditor(filepath.Join(dir, "audit.jsonl"), 1).Record(AuditEvent{Client: "c", Outcome: OutcomeOK})
}

func TestAuditRecordDropsAnUnencodableEvent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	NewAuditor(p, 1).Record(AuditEvent{Client: "c", Outcome: OutcomeOK, Args: map[string]any{"f": func() {}}})
	if _, err := os.Stat(p); err == nil {
		t.Error("an event that could not be encoded still produced a log line")
	}
}

func TestTokenStoreSurfacesAWriteFailure(t *testing.T) {
	ts, err := LoadTokens(blocked(t, "tokens", ".tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Mint("a"); err == nil {
		t.Error("Mint reported success though the digest was not saved")
	}
}
