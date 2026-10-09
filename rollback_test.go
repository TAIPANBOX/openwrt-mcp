package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// uci_apply arms a rollback so a change that strands the router undoes itself. The snapshot
// that makes that possible has to outlive whatever took the router down, and on OpenWrt
// /tmp is RAM: a reboot empties it, leaving a pending record that points at nothing.

// rollbackRig is a scratch /etc/config, a state directory and a PATH holding fake `uci`,
// `ubus`, and a TMPDIR of its own so a test can wipe "the machine's /tmp".
type rollbackRig struct {
	cfgDir, stateDir, tmp, ctl string
	configPath                 string
	extraConfig                string // appended to the daemon's config file, e.g. policies
}

func newRollbackRig(t *testing.T) *rollbackRig {
	t.Helper()
	root := t.TempDir()
	r := &rollbackRig{
		cfgDir:   filepath.Join(root, "etc-config"),
		stateDir: filepath.Join(root, "state"),
		tmp:      filepath.Join(root, "tmp"),
		ctl:      filepath.Join(root, "ctl"),
	}
	for _, d := range []string{r.cfgDir, r.tmp, r.ctl, filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The fakes succeed unless a marker file in ctl/ asks them to misbehave.
	uci := `#!/bin/sh
cmd=$1
if [ -e "` + r.ctl + `/fail-$cmd" ]; then echo "uci: forced $cmd failure" >&2; exit 1; fi
if [ "$cmd" = changes ] && [ -e "` + r.ctl + `/dirty" ]; then echo "network.lan.ipaddr='9.9.9.9'"; fi
exit 0
`
	ubus := `#!/bin/sh
if [ -e "` + r.ctl + `/fail-ubus" ]; then echo "ubus: forced failure" >&2; exit 1; fi
exit 0
`
	for name, body := range map[string]string{"uci": uci, "ubus": ubus} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", r.tmp)
	old := uciConfigDir
	uciConfigDir = r.cfgDir
	t.Cleanup(func() { uciConfigDir = old })

	r.configPath = filepath.Join(r.cfgDir, "network")
	if err := os.WriteFile(r.configPath, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rollbackRig) flag(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.ctl, name), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *rollbackRig) server(t *testing.T) *Server {
	t.Helper()
	cfg := filepath.Join(filepath.Dir(r.stateDir), "config")
	os.WriteFile(cfg, []byte("config server\n\toption audit '"+filepath.Join(r.stateDir, "audit.jsonl")+"'\n"+r.extraConfig), 0o600)
	s, err := NewServer(cfg, r.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // no timer may outlive the test and fire into another one
		s.mu.Lock()
		for _, p := range s.pending {
			if p.timer != nil {
				p.timer.Stop()
			}
		}
		s.mu.Unlock()
	})
	return s
}

func (r *rollbackRig) read(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.configPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// readWhilePresent is read for a loop that waits on a rollback: the restore unpacks the snapshot
// with tar, which unlinks the file and writes it again, so for a moment it does not exist. That is
// "not yet", not a failure (the timer test once failed on exactly that moment in CI).
func (r *rollbackRig) readWhilePresent(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *rollbackRig) snapshots(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{filepath.Join(r.stateDir, "rollback"), r.tmp} {
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

var oneChange = uciApplyIn{
	Changes: []UCIChange{{Config: "network", Section: "lan", Option: "ipaddr", Value: "10.0.0.1"}},
	Timeout: 600,
}

// applyAndEdit runs uci_apply, then does what the real `uci commit` would: change the file.
func (r *rollbackRig) applyAndEdit(t *testing.T, s *Server) string {
	t.Helper()
	out, _, err := s.uciApply(context.Background(), oneChange)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.configPath, []byte("changed by apply\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	i := strings.Index(out, `"token": "`)
	if i < 0 {
		t.Fatalf("no token in %q", out)
	}
	rest := out[i+len(`"token": "`):]
	return rest[:strings.Index(rest, `"`)]
}

// The point of the change. A reboot wipes /tmp; the snapshot must not have been there.
func TestRollbackSurvivesTheMachinesTmpBeingWiped(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.applyAndEdit(t, s)

	// Reboot: the daemon is gone and RAM-backed /tmp comes back empty.
	s.mu.Lock()
	for _, p := range s.pending {
		p.timer.Stop()
	}
	s.mu.Unlock()
	if err := os.RemoveAll(r.tmp); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(r.tmp, 0o755)

	r.server(t) // the daemon starts again and recovers
	if got := r.read(t); got != "original\n" {
		t.Fatalf("after a reboot the config is %q: the unconfirmed change was not rolled back", got)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("recovery left snapshots behind: %v", left)
	}
	if _, err := os.Stat(filepath.Join(r.stateDir, "pending.json")); !os.IsNotExist(err) {
		t.Error("the pending record survived a completed recovery")
	}
}

func TestSnapshotIsKeptUnderTheStateDirNotInTmp(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.applyAndEdit(t, s)

	if es, _ := os.ReadDir(r.tmp); len(es) != 0 {
		t.Errorf("the snapshot is in the machine's tmp: %v", es)
	}
	dir := filepath.Join(r.stateDir, "rollback")
	es, err := os.ReadDir(dir)
	if err != nil || len(es) != 1 || !strings.HasSuffix(es[0].Name(), ".tar.gz") {
		t.Fatalf("want one .tar.gz in %s, got %v (%v)", dir, es, err)
	}
	// The snapshot holds wifi keys and the like: nobody but root may read it.
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("rollback dir mode %v, want 0700", st.Mode().Perm())
	}
	if st, _ := es[0].Info(); st.Mode().Perm() != 0o600 {
		t.Errorf("snapshot mode %v, want 0600", st.Mode().Perm())
	}
	// And the pending record names it, so recovery can find it.
	b, _ := os.ReadFile(filepath.Join(r.stateDir, "pending.json"))
	var list []pendingApply
	if err := json.Unmarshal(b, &list); err != nil || len(list) != 1 ||
		list[0].Snapshot != filepath.Join(dir, es[0].Name()) {
		t.Errorf("pending.json = %s", b)
	}
}

func TestRollbackDirIsTightenedIfItAlreadyExistsLoose(t *testing.T) {
	r := newRollbackRig(t)
	dir := filepath.Join(r.stateDir, "rollback")
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o755)
	s := r.server(t)
	r.applyAndEdit(t, s)
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("an existing loose rollback dir was left at %v", st.Mode().Perm())
	}
}

func TestConfirmDeletesTheSnapshotAndKeepsTheChange(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	token := r.applyAndEdit(t, s)

	out, summary, err := s.uciConfirm(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Confirmed") || !strings.Contains(summary, token) {
		t.Errorf("confirm: %q / %q", out, summary)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a confirmed apply left its snapshot: %v", left)
	}
	if got := r.read(t); got != "changed by apply\n" {
		t.Errorf("confirming undid the change: %q", got)
	}
	// And a restart now has nothing to roll back.
	r.server(t)
	if got := r.read(t); got != "changed by apply\n" {
		t.Errorf("a restart after confirm rolled the change back: %q", got)
	}
}

func TestTimerRollbackRestoresAndDeletesTheSnapshot(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	token := r.applyAndEdit(t, s)

	s.rollback(token, "timeout")
	if got := r.read(t); got != "original\n" {
		t.Fatalf("config after rollback = %q", got)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a rolled-back apply left its snapshot: %v", left)
	}
	b, _ := os.ReadFile(filepath.Join(r.stateDir, "audit.jsonl"))
	if !strings.Contains(string(b), "uci_rollback") || !strings.Contains(string(b), "rolled back network (timeout)") {
		t.Errorf("the rollback was not audited:\n%s", b)
	}
	// Idempotent: a second call for the same token does nothing and does not panic.
	s.rollback(token, "again")
	if _, _, err := s.uciConfirm(context.Background(), token); err == nil {
		t.Error("a rolled-back token could still be confirmed")
	}
}

func TestFailedRollbackKeepsTheSnapshotForManualRecovery(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	token := r.applyAndEdit(t, s)
	r.flag(t, "fail-ubus") // the reload after restoring fails

	s.rollback(token, "timeout")
	if left := r.snapshots(t); len(left) != 1 {
		t.Errorf("a failed rollback must keep its only copy of the old config, left: %v", left)
	}
	b, _ := os.ReadFile(filepath.Join(r.stateDir, "audit.jsonl"))
	if !strings.Contains(string(b), "ROLLBACK FAILED") {
		t.Errorf("the failure was not audited:\n%s", b)
	}
}

func TestStagingFailureRevertsAndLeavesNoSnapshot(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.flag(t, "fail-set")
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "staging network.lan.ipaddr failed") {
		t.Fatalf("err = %v", err)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a failed apply left a snapshot: %v", left)
	}
	if got := r.read(t); got != "original\n" {
		t.Errorf("config = %q", got)
	}
}

func TestCommitFailureRestoresTheSnapshot(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.flag(t, "fail-commit")
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "commit network failed") {
		t.Fatalf("err = %v", err)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a failed commit left a snapshot: %v", left)
	}
}

func TestApplyRefusesWhileAnotherIsPending(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.applyAndEdit(t, s)
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "already pending") {
		t.Errorf("err = %v", err)
	}
	if got := len(r.snapshots(t)); got != 1 {
		t.Errorf("the refused apply made a snapshot of its own (%d on disk)", got)
	}
}

func TestApplyRefusesOverSomebodyElsesUncommittedChanges(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	r.flag(t, "dirty")
	_, _, err := s.uciApply(context.Background(), oneChange)
	if err == nil || !strings.Contains(err.Error(), "uncommitted UCI changes") {
		t.Errorf("err = %v", err)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("snapshot made before the refusal: %v", left)
	}
}

func TestApplyValidatesBeforeTouchingAnything(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	for name, in := range map[string]uciApplyIn{
		"empty":             {},
		"bad change":        {Changes: []UCIChange{{Config: "network"}}},
		"no such config":    {Changes: []UCIChange{{Config: "nonesuch", Section: "x", Option: "y", Value: "z"}}},
		"config with slash": {Changes: []UCIChange{{Config: "../x", Section: "x", Option: "y"}}},
	} {
		if _, _, err := s.uciApply(context.Background(), in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a refused apply left snapshots: %v", left)
	}
}

func TestConfirmWithAnUnknownTokenSaysSo(t *testing.T) {
	r := newRollbackRig(t)
	s := r.server(t)
	if _, _, err := s.uciConfirm(context.Background(), "nope"); err == nil || !strings.Contains(err.Error(), "no pending apply") {
		t.Errorf("err = %v", err)
	}
}

// A pending record left by an older version points into /tmp. It must still be honoured.
func TestRecoveryHonoursARecordPointingAtTheOldTmpLocation(t *testing.T) {
	r := newRollbackRig(t)
	snap := filepath.Join(r.tmp, "openwrt-mcp-rollback-old.tar.gz")
	if out, err := run(context.Background(), 0, "tar", "-czf", snap, "-C", r.cfgDir, "network"); err != nil {
		t.Fatal(err, out)
	}
	os.WriteFile(r.configPath, []byte("changed by apply\n"), 0o644)
	os.MkdirAll(r.stateDir, 0o700)
	rec, _ := json.Marshal([]pendingApply{{Token: "old", Snapshot: snap, Configs: []string{"network"},
		Deadline: time.Now()}})
	os.WriteFile(filepath.Join(r.stateDir, "pending.json"), rec, 0o600)

	r.server(t)
	if got := r.read(t); got != "original\n" {
		t.Errorf("an upgrade stranded an in-flight rollback: config = %q", got)
	}
}

func TestRecoveryWithAMissingSnapshotDoesNotLoopForever(t *testing.T) {
	r := newRollbackRig(t)
	os.MkdirAll(r.stateDir, 0o700)
	rec, _ := json.Marshal([]pendingApply{{Token: "gone", Snapshot: filepath.Join(r.tmp, "wiped.tar.gz"),
		Configs: []string{"network"}}})
	os.WriteFile(filepath.Join(r.stateDir, "pending.json"), rec, 0o600)

	r.server(t)
	if got := r.read(t); got != "original\n" {
		t.Errorf("config touched by a failed recovery: %q", got)
	}
	if _, err := os.Stat(filepath.Join(r.stateDir, "pending.json")); !os.IsNotExist(err) {
		t.Error("an unrecoverable record is retried on every start")
	}
}

func TestRecoveryIgnoresAGarbagePendingFile(t *testing.T) {
	r := newRollbackRig(t)
	os.MkdirAll(r.stateDir, 0o700)
	os.WriteFile(filepath.Join(r.stateDir, "pending.json"), []byte("{not json"), 0o600)
	r.server(t)
	if got := r.read(t); got != "original\n" {
		t.Errorf("config = %q", got)
	}
}
