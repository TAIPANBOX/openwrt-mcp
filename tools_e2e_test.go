package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each tool through the real handler, so what is asserted is what a client receives: the
// text, the error flag, and the audit outcome the wrapper recorded.

const allToolsPolicy = `
config policy
	option client 'a'
	list tools 'ubus_call'
	list tools 'uci_get'
	list tools 'exec'
	list tools 'logread'
	list scopes '*'
`

func TestUbusListIsUngatedAndPassesTheFilter(t *testing.T) {
	fakeCmd(t, "ubus", `echo "ubus $*"`)
	s, _ := newToolRig(t, "")
	out, isErr := callTool(t, s, "nobody", "ubus_list", map[string]any{})
	if isErr || !strings.Contains(out, "ubus -v list") {
		t.Errorf("unfiltered: %q (error=%v)", out, isErr)
	}
	out, _ = callTool(t, s, "nobody", "ubus_list", map[string]any{"filter": "network"})
	if !strings.Contains(out, "ubus -v list network") {
		t.Errorf("filter not passed: %q", out)
	}
}

func TestUbusCallPassesArgsAndScopesByObjectDotMethod(t *testing.T) {
	fakeCmd(t, "ubus", `echo "ubus $*"`)
	s, dir := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist scopes 'system.*'\n")
	out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "system", "method": "board",
		"args": map[string]any{"verbose": true}})
	if isErr || !strings.Contains(out, `ubus call system board {"verbose":true}`) {
		t.Errorf("granted: %q (error=%v)", out, isErr)
	}
	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "network", "method": "reload"}); !isErr ||
		!strings.Contains(out, "network.reload") {
		t.Errorf("an out-of-scope call must name the scope it lacked: %q", out)
	}
	if _, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "system"}); !isErr {
		t.Error("a call with no method was accepted")
	}
	// The call with no method never reaches the wrapper: the tool's input schema refuses it.
	evs := auditEvents(t, dir)
	if len(evs) != 2 || evs[0].Outcome != OutcomeOK || evs[0].Scope != "system.board" ||
		evs[1].Outcome != OutcomeDenied {
		t.Errorf("audit = %+v", evs)
	}
}

func TestUciGetThroughTheTool(t *testing.T) {
	fakeCmd(t, "uci", `echo "uci $*"`)
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'uci_get'\n\tlist scopes 'dhcp.*'\n\tlist scopes 'dhcp'\n")
	for args, want := range map[string]string{
		`{"config":"dhcp"}`:                                  "uci show dhcp",
		`{"config":"dhcp","section":"lan"}`:                  "uci show dhcp.lan",
		`{"config":"dhcp","section":"lan","option":"start"}`: "uci show dhcp.lan.start",
	} {
		var m map[string]any
		_ = jsonUnmarshal(args, &m)
		out, isErr := callTool(t, s, "a", "uci_get", m)
		if isErr || !strings.Contains(out, want) {
			t.Errorf("%s: %q (error=%v), want %q", args, out, isErr, want)
		}
	}
	if _, isErr := callTool(t, s, "a", "uci_get", map[string]any{"config": "network"}); !isErr {
		t.Error("an ungranted config was readable")
	}
	// Validation is the tool's own, behind the grant.
	if _, _, err := uciGet(context.Background(), uciGetIn{Option: "x", Section: ""}); err == nil {
		t.Error("an option with no config was accepted")
	}
	if _, _, err := uciGet(context.Background(), uciGetIn{Config: "dhcp", Option: "x"}); err == nil ||
		!strings.Contains(err.Error(), "section") {
		t.Errorf("an option with no section: %v", err)
	}
}

func TestExecRunsWithoutAShellAndReportsFailure(t *testing.T) {
	s, dir := newToolRig(t, allToolsPolicy)
	out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"echo", "a;b", "$HOME"}})
	if isErr || strings.TrimSpace(out) != "a;b $HOME" {
		t.Errorf("no shell expected, got %q (error=%v)", out, isErr)
	}
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"false"}}); !isErr {
		t.Errorf("a failing command was reported as success: %q", out)
	}
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{}}); !isErr ||
		!strings.Contains(out, "scope") && !strings.Contains(out, "argv") {
		t.Errorf("empty argv: %q (error=%v)", out, isErr)
	}
	evs := auditEvents(t, dir)
	if len(evs) != 3 || evs[0].Outcome != OutcomeOK || evs[1].Outcome != OutcomeError {
		t.Errorf("outcomes = %+v", evs)
	}
	// The scope is argv[0] alone: the arguments never widen or narrow a grant.
	if evs[0].Scope != "echo" {
		t.Errorf("scope = %q, want echo", evs[0].Scope)
	}
}

func TestExecIsDeniedOutsideItsScope(t *testing.T) {
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'cat'\n")
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"sh", "-c", "id"}}); !isErr ||
		!strings.Contains(out, "denied") || !strings.Contains(out, "openwrt-mcp allow a exec 'sh'") {
		t.Errorf("sh was not refused with the remedy line: %q", out)
	}
}

func TestLogreadClampsAndFiltersLines(t *testing.T) {
	fakeCmd(t, "logread", `echo "args: $*"; echo "alpha one"; echo "beta two"; echo "alpha three"`)
	s, _ := newToolRig(t, allToolsPolicy)
	out, _ := callTool(t, s, "a", "logread", map[string]any{})
	if !strings.Contains(out, "args: -l 100") {
		t.Errorf("default is 100 lines: %q", out)
	}
	out, _ = callTool(t, s, "a", "logread", map[string]any{"lines": 999999})
	if !strings.Contains(out, "args: -l 2000") {
		t.Errorf("lines must be capped at 2000: %q", out)
	}
	out, _ = callTool(t, s, "a", "logread", map[string]any{"lines": 5, "pattern": "alpha"})
	if !strings.Contains(out, "alpha one") || !strings.Contains(out, "alpha three") || strings.Contains(out, "beta") {
		t.Errorf("pattern filter: %q", out)
	}
}

func TestRateLimitThroughTheTool(t *testing.T) {
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n\toption max_per_min '1'\n")
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"true"}}); isErr {
		t.Fatalf("first call: %q", out)
	}
	if out, isErr := callTool(t, s, "a", "exec", map[string]any{"argv": []string{"true"}}); !isErr ||
		!strings.Contains(out, "rate limit") {
		t.Errorf("second call: %q (error=%v)", out, isErr)
	}
}

// The tool wrapper must refuse a gated tool before running it, with the second factor
// consulted after authorisation so a caller with no grant learns nothing about MFA.
func TestAnUnauthorisedCallerLearnsNothingAboutWhichToolsAreGated(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin"))
	out, isErr := callTool(t, s, "stranger", "exec", map[string]any{"argv": []string{"true"}})
	if !isErr || strings.Contains(out, "second factor") || strings.Contains(out, "mfa_unlock") {
		t.Errorf("a client with no grant was told about the second factor: %q", out)
	}
}

func TestUciApplyAndConfirmThroughTheTools(t *testing.T) {
	r := newRollbackRig(t)
	r.extraConfig = "config policy\n\toption client 'a'\n\tlist tools 'uci_apply'\n\tlist tools 'uci_confirm'\n" +
		"\tlist scopes 'network.*'\n"
	s := r.server(t)

	out, isErr := callTool(t, s, "a", "uci_apply", map[string]any{
		"changes": []map[string]any{{"config": "network", "section": "lan", "option": "ipaddr", "value": "10.0.0.1"}},
		"timeout": 600})
	if isErr || !strings.Contains(out, "ROLLBACK ARMED") {
		t.Fatalf("uci_apply: %q (error=%v)", out, isErr)
	}
	i := strings.Index(out, `"token": "`)
	rest := out[i+len(`"token": "`):]
	token := rest[:strings.Index(rest, `"`)]

	if out, isErr := callTool(t, s, "a", "uci_apply", map[string]any{
		"changes": []map[string]any{{"config": "network", "section": "lan", "option": "ipaddr", "value": "10.0.0.2"}}}); !isErr ||
		!strings.Contains(out, "already pending") {
		t.Errorf("a second apply while one is pending: %q", out)
	}
	out, isErr = callTool(t, s, "a", "uci_confirm", map[string]any{"token": token})
	if isErr || !strings.Contains(out, "Confirmed") {
		t.Errorf("uci_confirm: %q (error=%v)", out, isErr)
	}
	// An apply outside the granted scope is refused before anything is snapshotted.
	if _, isErr := callTool(t, s, "a", "uci_apply", map[string]any{
		"changes": []map[string]any{{"config": "firewall", "section": "x", "option": "y", "value": "z"}}}); !isErr {
		t.Error("an apply outside the scope was accepted")
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("snapshots left: %v", left)
	}
}

func TestRunStdinFeedsTheCommandAndTimesOut(t *testing.T) {
	out, err := runStdin(context.Background(), 0, "hello", "cat")
	if err != nil || out != "hello" {
		t.Errorf("cat: %q %v", out, err)
	}
	out, err = runStdin(context.Background(), 0, "", "sh", "-c", "echo err >&2; echo out")
	if err != nil || out != "out\n\nerr" {
		t.Errorf("stdout then stderr: %q %v", out, err)
	}
	if _, err := runStdin(context.Background(), 50*time.Millisecond, "", "sleep", "5"); err == nil ||
		!strings.Contains(err.Error(), "timed out") {
		t.Errorf("timeout: %v", err)
	}
	if _, err := runStdin(context.Background(), 0, "", "sh", "-c", "exit 3"); err == nil {
		t.Error("a failing command succeeded")
	}
}

func TestRunMergesStderrAndTimesOut(t *testing.T) {
	out, err := run(context.Background(), 0, "sh", "-c", "echo out; echo err >&2")
	if err != nil || out != "out\n\nerr" && out != "out\nerr" {
		t.Errorf("merged output %q %v", out, err)
	}
	if _, err := run(context.Background(), 50*time.Millisecond, "sleep", "5"); err == nil ||
		!strings.Contains(err.Error(), "timed out") {
		t.Errorf("timeout: %v", err)
	}
}

func TestClampSec(t *testing.T) {
	for _, tc := range []struct {
		v, def, max int
		want        time.Duration
	}{
		{0, 30, 300, 30 * time.Second}, {-5, 30, 300, 30 * time.Second},
		{10, 30, 300, 10 * time.Second}, {300, 30, 300, 300 * time.Second}, {301, 30, 300, 300 * time.Second},
	} {
		if got := clampSec(tc.v, tc.def, tc.max); got != tc.want {
			t.Errorf("clampSec(%d,%d,%d) = %v, want %v", tc.v, tc.def, tc.max, got, tc.want)
		}
	}
}

func TestWgNewClientIsGatedLikeEveryOtherTool(t *testing.T) {
	s, _ := newToolRig(t, "")
	out, isErr := callTool(t, s, "a", "wg_new_client", map[string]any{"name": "laptop"})
	if !isErr || !strings.Contains(out, "denied") || !strings.Contains(out, "wireguard_server") {
		t.Errorf("%q (error=%v)", out, isErr)
	}
}

func TestAuditRotatesOneGeneration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	a := NewAuditor(p, 0) // a cap of 0 MB: every write finds the file already full
	a.Record(AuditEvent{Time: "t1", Client: "c", Outcome: OutcomeOK, Summary: "first"})
	a.Record(AuditEvent{Time: "t2", Client: "c", Outcome: OutcomeOK, Summary: "second"})
	if b, _ := os.ReadFile(p + ".1"); !strings.Contains(string(b), "first") {
		t.Errorf("the rotated generation lacks the first event: %q", b)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "second") || strings.Contains(string(b), "first") {
		t.Errorf("the live log is wrong: %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode %v, want 0600", st.Mode().Perm())
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
