package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A flood of refusals that cost the caller nothing must not rotate the evidence out of audit.jsonl.

func badToken(s *Server, n int) {
	h := s.Handler()
	for i := 0; i < n; i++ {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", fmt.Sprintf("Bearer wrong-%d", i))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func auditLines(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

func TestABadTokenFloodIsOneLineAndASummary(t *testing.T) {
	s, dir := newToolRig(t, "")
	clk := useServerClock(s)
	badToken(s, 500)
	if got := auditLines(t, dir); got != 1 {
		t.Fatalf("%d lines for 500 bad tokens, want the first alone", got)
	}
	first := auditEvents(t, dir)[0]
	if !strings.Contains(first.Error, "bad or missing bearer token from ") {
		t.Errorf("the first line lost the source: %+v", first)
	}

	clk.pass(auditFoldPeriod)
	s.audit.Sweep()
	evs := auditEvents(t, dir)
	if len(evs) != 2 {
		t.Fatalf("%d lines after the period, want a summary", len(evs))
	}
	sum := evs[1]
	if sum.Folded != 499 || sum.Outcome != OutcomeDenied || sum.Client != "<unauthenticated>" ||
		!strings.Contains(sum.Summary, "499 more bad or missing bearer tokens since "+first.Time) {
		t.Errorf("summary %+v", sum)
	}
}

func TestAFloodCannotRotateTheEvidenceOut(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	s.mfa.pins.Set("a", "4821")
	s.audit.maxMB = 0 // the log moves on at every write it gets, so only a write that is not made saves it
	if _, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"}); !isErr {
		t.Fatal("a wrong PIN unlocked")
	}
	badToken(s, 1) // the first of the run: this line rotates, and it is what must stay
	before := readFile(t, filepath.Join(dir, "audit.jsonl"))
	if !strings.Contains(before, "bad or missing bearer token") {
		t.Fatalf("no evidence to keep: %q", before)
	}
	badToken(s, 20000)
	if got := readFile(t, filepath.Join(dir, "audit.jsonl")); got != before {
		t.Errorf("20000 bad tokens moved the log: it now reads %q", got)
	}
}

func TestEachPeriodOfAFloodCostsTwoLines(t *testing.T) {
	s, dir := newToolRig(t, "")
	clk := useServerClock(s)
	for period := 0; period < 4; period++ {
		badToken(s, 100)
		clk.pass(auditFoldPeriod)
	}
	s.audit.Sweep()
	if got := auditLines(t, dir); got != 8 {
		t.Errorf("%d lines for four periods of a flood, want 8", got)
	}
}

func TestOneBadTokenNeedsNoSummary(t *testing.T) {
	s, dir := newToolRig(t, "")
	clk := useServerClock(s)
	badToken(s, 1)
	clk.pass(auditFoldPeriod)
	s.audit.Sweep()
	if got := auditLines(t, dir); got != 1 {
		t.Errorf("%d lines, want no summary for a run of one", got)
	}
}

func TestRefusalsInADelayAreOneLineAndASummary(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	clk := useServerClock(s)
	s.mfa.pins.Set("a", "4821")
	for i := 0; i < 5; i++ {
		callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
	}
	if got := auditLines(t, dir); got != 5 {
		t.Fatalf("%d lines for 5 counted failures, want every one", got)
	}
	for i := 0; i < 40; i++ {
		out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "4821"})
		if !isErr || !strings.Contains(out, "locked out until") {
			t.Fatalf("inside the delay: %q", out)
		}
	}
	if got := auditLines(t, dir); got != 6 {
		t.Fatalf("%d lines, want the first refusal alone on top of the 5", got)
	}
	first := auditEvents(t, dir)[5]
	if !strings.Contains(first.Error, "locked out until") || first.Tool != "mfa_unlock" {
		t.Errorf("first refusal: %+v", first)
	}

	clk.pass(15 * time.Minute)
	s.sweep()
	evs := auditEvents(t, dir)
	if len(evs) != 7 {
		t.Fatalf("%d lines after the delay, want the summary: %+v", len(evs), evs)
	}
	sum := evs[6]
	if sum.Folded != 39 || sum.Client != "a" || sum.Tool != "mfa_unlock" ||
		!strings.Contains(sum.Summary, "39 more tries refused inside the delay of a since") {
		t.Errorf("summary %+v", sum)
	}
}

// The summary comes before the next try's own line, so the log reads in the order it happened.
func TestTheSummaryComesBeforeTheNextTry(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	clk := useServerClock(s)
	s.mfa.pins.Set("a", "4821")
	for i := 0; i < 8; i++ {
		callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
	}
	clk.pass(15 * time.Minute)
	callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
	evs := auditEvents(t, dir)
	if len(evs) != 8 || evs[6].Folded != 2 || evs[7].Folded != 0 || !strings.Contains(evs[7].Error, "invalid credentials") {
		t.Errorf("the log reads %+v", evs)
	}
}

func TestEachDelayHasItsOwnFirstLine(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	clk := useServerClock(s)
	s.mfa.pins.Set("a", "4821")
	try := func(n int) {
		for i := 0; i < n; i++ {
			callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
		}
	}
	try(5 + 3) // five counted, three refused
	clk.pass(15 * time.Minute)
	try(1 + 3) // one counted, three refused inside the longer delay
	var firsts, folded int
	for _, e := range auditEvents(t, dir) {
		if strings.Contains(e.Error, "locked out until") {
			firsts++
		}
		folded += e.Folded
	}
	if firsts != 2 || folded != 2 {
		t.Errorf("%d first lines and %d folded so far, want 2 and 2", firsts, folded)
	}
}

// A reset inside a delay ends it. A delay that follows is another run, even with the first still open.
func TestAResetInsideADelayStartsAnotherRun(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	clk := useServerClock(s)
	s.mfa.pins.Set("a", "4821")
	try := func(n int) {
		for i := 0; i < n; i++ {
			callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
		}
	}
	try(7)
	if _, err := s.mfa.ResetThrottle("a"); err != nil {
		t.Fatal(err)
	}
	clk.pass(time.Minute)
	try(7)
	firsts := 0
	for _, e := range auditEvents(t, dir) {
		if strings.Contains(e.Error, "locked out until") {
			firsts++
		}
	}
	if firsts != 2 {
		t.Errorf("%d first lines, want one for each delay", firsts)
	}
}

func TestAFlushLeavesNothingOnlyInMemory(t *testing.T) {
	s, dir := newToolRig(t, "")
	useServerClock(s)
	badToken(s, 10)
	s.audit.Flush()
	evs := auditEvents(t, dir)
	if len(evs) != 2 || evs[1].Folded != 9 {
		t.Errorf("after a flush: %+v", evs)
	}
	s.audit.Flush()
	if got := auditLines(t, dir); got != 2 {
		t.Errorf("a second flush wrote again: %d lines", got)
	}
}

func TestTheFoldHoldsNoSecret(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin"))
	useServerClock(s)
	s.mfa.pins.Set("a", "4821")
	for i := 0; i < 8; i++ {
		callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "7395"})
	}
	s.audit.Flush()
	if body := readFile(t, filepath.Join(dir, "audit.jsonl")); strings.Contains(body, "7395") {
		t.Errorf("the PIN reached the log: %s", body)
	}
}

// What the caller sends never names a run, so a flood of different tokens is one run, and the
// memory the runs take is bounded by the clients paired.
func TestAFloodOfDifferentTokensIsOneRun(t *testing.T) {
	s, _ := newToolRig(t, "")
	badToken(s, 300)
	if got := len(s.audit.runs); got != 1 {
		t.Errorf("%d runs in memory, want 1", got)
	}
}

// The agent's own token is the one a compromised agent holds. It cannot spend a try, and it must
// not get a line in the log for each one it asks for either.
func TestTheAgentTokenSpendsNoTries(t *testing.T) {
	r := newApRig(t, "")
	clk := useServerClock(r.s)
	for i := 0; i < 50; i++ {
		out, isErr := callTool(t, r.s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
		if !isErr || !strings.Contains(out, "Nothing was tried") {
			t.Fatalf("the agent's own unlock: %q", out)
		}
	}
	if got := r.s.mfa.State("a", clk.wall).Failures; got != 0 {
		t.Errorf("failures = %d, want 0: the agent's token spent the owner's tries", got)
	}
	if _, err := os.Stat(filepath.Join(r.state, "throttle")); !os.IsNotExist(err) {
		t.Errorf("the refusal wrote to the disk: %v", err)
	}
	if got := auditLines(t, r.state); got != 1 {
		t.Errorf("%d lines for 50 refusals of the agent's unlock, want the first", got)
	}
	r.s.audit.Flush()
	evs := auditEvents(t, r.state)
	if len(evs) != 2 || evs[1].Folded != 49 || evs[1].Outcome != OutcomeDenied || evs[1].Client != "a" {
		t.Errorf("after the flush: %+v", evs)
	}
}

func TestAClientNamingAnotherIsFoldedToo(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin")+policyBlock("b", "pin"))
	for i := 0; i < 20; i++ {
		callTool(t, s, "b", "mfa_unlock", map[string]any{"client": "a", "pin": "0000"})
	}
	if got := auditLines(t, dir); got != 1 {
		t.Errorf("%d lines, want the first", got)
	}
	if got := s.mfa.State("a", time.Now()).Failures; got != 0 {
		t.Errorf("failures = %d", got)
	}
}

func TestAnApprovalRefusedInADelayIsFolded(t *testing.T) {
	r := newApRig(t, "")
	useServerClock(r.s)
	id := r.holdPortForward()
	hash := r.action(id).Hash
	for i := 0; i < 5; i++ {
		r.approve("owner", id, hash, "0000", "000000")
	}
	before := auditLines(t, r.state)
	for i := 0; i < 30; i++ {
		out, _ := r.approve("owner", id, hash, apPIN, "000000")
		if !strings.Contains(out, "locked out") {
			t.Fatalf("inside the delay: %q", out)
		}
	}
	if got := auditLines(t, r.state) - before; got != 1 {
		t.Errorf("%d lines for 30 refused approvals, want the first", got)
	}
}

// The daemon's minute writes what has ended, and the stop writes what has not.
func TestTheDaemonsMinuteSweepsAndItsStopFlushes(t *testing.T) {
	s, dir := newToolRig(t, "")
	clk := useServerClock(s)
	stop := make(chan os.Signal)
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		s.housekeep(stop, tick)
		close(done)
	}()
	badToken(s, 3)
	clk.pass(auditFoldPeriod)
	tick <- time.Time{}
	tick <- time.Time{} // the first tick's sweep is over when the second is taken
	if got := auditEvents(t, dir); len(got) != 2 || got[1].Folded != 2 {
		t.Fatalf("after the minute: %+v", got)
	}
	badToken(s, 4)
	stop <- syscall.SIGTERM
	<-done
	if got := auditEvents(t, dir); len(got) != 4 || got[3].Folded != 3 {
		t.Errorf("after the stop: %+v", got)
	}
}

// ---------------------------------------------------------------- what the owner's client is told

func throttleOf(t *testing.T, s *Server, approver string) []throttleView {
	t.Helper()
	out, isErr := callTool(t, s, approver, "action_list", map[string]any{})
	if isErr {
		t.Fatalf("action_list: %s", out)
	}
	var got struct {
		Throttle []throttleView `json:"throttle"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	return got.Throttle
}

func TestActionListTellsTheOwnerOfForeignTries(t *testing.T) {
	r := newApRig(t, "")
	clk := useServerClock(r.s)
	unlock := func(pin string) (string, bool) {
		return callTool(t, r.s, "owner", "mfa_unlock", map[string]any{"client": "a", "pin": pin})
	}
	if got := throttleOf(t, r.s, "owner"); len(got) != 1 || got[0] != (throttleView{Client: "a", Limit: 5, Persisted: true}) {
		t.Fatalf("nothing happened yet: %+v", got)
	}
	for i := 0; i < 5; i++ {
		unlock("0000")
	}
	for i := 0; i < 3; i++ {
		unlock(apPIN)
	}
	got := throttleOf(t, r.s, "owner")
	if len(got) != 1 || got[0].Client != "a" || got[0].Failures != 5 || got[0].Limit != 5 || got[0].Refused != 3 || !got[0].Persisted {
		t.Fatalf("after five wrong tries and three refused: %+v", got)
	}
	until, err := time.Parse(time.RFC3339, got[0].LockedOutUntil)
	if err != nil {
		t.Fatalf("locked_out_until %q: %v", got[0].LockedOutUntil, err)
	}
	if d := time.Until(until); d < 14*time.Minute || d > 15*time.Minute+time.Second {
		t.Errorf("the delay ends in %v, want about 15m", d)
	}
	clk.pass(15 * time.Minute)
	if got := throttleOf(t, r.s, "owner"); got[0].LockedOutUntil != "" || got[0].Failures != 5 {
		t.Errorf("after the delay: %+v", got[0])
	}
}

func TestActionListSaysWhenTheCountIsNotOnTheDisk(t *testing.T) {
	r := newApRig(t, "")
	useServerClock(r.s)
	setThrottleWriter(r.s.mfa, fullDisk)
	callTool(t, r.s, "owner", "mfa_unlock", map[string]any{"client": "a", "pin": "0000"})
	if got := throttleOf(t, r.s, "owner"); got[0].Persisted || got[0].Failures != 1 {
		t.Errorf("%+v", got[0])
	}
}

func TestTheAgentsOwnViewCarriesNoThrottle(t *testing.T) {
	r := newApRig(t, "")
	out, _ := callTool(t, r.s, "a", "action_status", map[string]any{})
	if strings.Contains(out, "throttle") || strings.Contains(out, "failures") {
		t.Errorf("action_status says %q", out)
	}
	if out, isErr := callTool(t, r.s, "a", "action_list", map[string]any{}); !isErr {
		t.Errorf("the agent listed: %q", out)
	}
}

// Nothing an MCP client can call touches the count. The list of tools is the whole surface, so a
// new tool has to be looked at here before this goes green, and the tools a client could hope to
// use are tried for real.
func TestNoMCPToolResetsTheThrottle(t *testing.T) {
	r := newApRig(t, "")
	useServerClock(r.s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.s.newServerForClient("owner").Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if strings.Contains(strings.ToLower(tool.Name), "reset") || strings.Contains(strings.ToLower(tool.Description), "reset") {
			t.Errorf("a tool speaks of a reset: %s: %s", tool.Name, tool.Description)
		}
	}
	sortStrings(names)
	want := "action_approve action_list action_reject action_status action_withdraw apk_add exec logread mfa_lock " +
		"mfa_unlock ubus_call ubus_list uci_apply uci_confirm uci_get wg_new_client"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("the tools are %q; a new one is a new way to reach the count, so look at it and then change this list", got)
	}

	for i := 0; i < 5; i++ {
		callTool(t, r.s, "owner", "mfa_unlock", map[string]any{"client": "a", "pin": "0000"})
	}
	for _, call := range []struct {
		client, tool string
		args         map[string]any
	}{
		{"owner", "mfa_lock", map[string]any{"client": "a"}},
		{"a", "mfa_lock", map[string]any{}},
		{"owner", "action_list", map[string]any{}},
		{"a", "action_status", map[string]any{}},
	} {
		callTool(t, r.s, call.client, call.tool, call.args)
		if got := r.s.mfa.State("a", time.Now()).Failures; got != 5 {
			t.Fatalf("%s by %s: failures = %d, want 5", call.tool, call.client, got)
		}
	}
}

// A client with no approval section opens its own window, spends its own tries, and is held to
// the same delays across a restart.
func TestAClientWithNoApprovalSectionIsThrottledAcrossARestart(t *testing.T) {
	s, dir := newToolRig(t, policyBlock("a", "pin", "option mfa_max_failures '2'", "option mfa_lockout '10m'"))
	s.mfa.pins.Set("a", "4821")
	for i := 0; i < 2; i++ {
		callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
	}
	again, err := NewServer(filepath.Join(dir, "config"), dir)
	if err != nil {
		t.Fatal(err)
	}
	out, isErr := callTool(t, again, "a", "mfa_unlock", map[string]any{"pin": "4821"})
	if !isErr || !strings.Contains(out, "locked out until") {
		t.Fatalf("the right PIN after a restart inside a delay: %q (error=%v)", out, isErr)
	}
	if _, isErr := execTrue(t, again, "a"); !isErr {
		t.Error("the gated tool ran")
	}
}

// ---------------------------------------------------------------- status

func TestStatusShowsTheFailuresOnRecord(t *testing.T) {
	dir, cfg, _ := statusRig(t)
	writeThrottleFixture(t, dir, throttleHeader+"alpha 7 0\nbeta many 0\n")
	got, _ := statusClients(t, cfg, dir)
	if got["alpha"].Failures != 7 || got["alpha"].LiveState || got["alpha"].LockedOutUntil != "" {
		t.Errorf("alpha: %+v", got["alpha"])
	}
	if got["beta"].Failures != 5 {
		t.Errorf("beta, a corrupt record: %+v, want the limit", got["beta"])
	}
	if got["gamma"].Failures != 0 {
		t.Errorf("gamma: %+v", got["gamma"])
	}
	text := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(text, "failed tries on record: 7") {
		t.Errorf("status text:\n%s", text)
	}
}

func TestMFAStatusNamesTheWayOut(t *testing.T) {
	m, dir := enrolled(t, "4821", "a")
	cfg := parse(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n\tlist mfa_tools 'exec'\n")
	writeThrottleFixture(t, dir, throttleHeader+"a 7 0\n")
	var b strings.Builder
	writeMFAStatus(&b, m, cfg)
	if !strings.Contains(b.String(), "7 failed tries") || !strings.Contains(b.String(), "openwrt-mcp mfa reset a") ||
		!strings.Contains(b.String(), "up to 1h0m0s") {
		t.Errorf("mfa status:\n%s", b.String())
	}
}

func statusOf(t *testing.T, cfg, dir string) map[string]any {
	t.Helper()
	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, true); err != nil {
			t.Fatal(err)
		}
	})
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	return rep
}

func TestStatusShowsThrottlePersistedFalseFromTheDaemon(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s, dir := newToolRigListening(t, addr, policyBlock("a", "pin"))
	s.mfa.pins.Set("a", "4821")
	go s.Serve()
	cfg := filepath.Join(dir, "config")
	for i := 0; i < 100 && !daemonRunning(addr); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if rep := statusOf(t, cfg, dir); rep["running"] != true || rep["throttle_persisted"] != true {
		t.Fatalf("before any failure: running %v, throttle_persisted %v", rep["running"], rep["throttle_persisted"])
	}
	setThrottleWriter(s.mfa, fullDisk)
	if _, err := s.mfa.Attempt("a", unlockAttempt{PIN: "0000"}, s.unlockPolicyFor("a"), time.Now()); err == nil {
		t.Fatal("a wrong PIN unlocked")
	}
	if rep := statusOf(t, cfg, dir); rep["throttle_persisted"] != false {
		t.Errorf("throttle_persisted = %v, want false", rep["throttle_persisted"])
	}
	text := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 0, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(text, "not reaching the disk") {
		t.Errorf("status text:\n%s", text)
	}
}

func TestHealthSaysNothingWhileTheThrottleIsSaved(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin"))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	get := func() string {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		b.Write(buf[:n])
		return b.String()
	}
	if body := get(); strings.Contains(body, "throttle") {
		t.Errorf("/health: %q", body)
	}
	setThrottleWriter(s.mfa, fullDisk)
	s.mfa.Attempt("a", unlockAttempt{PIN: "0000"}, s.unlockPolicyFor("a"), time.Now())
	if body := get(); !strings.Contains(body, "throttle_persisted: false") {
		t.Errorf("/health: %q", body)
	}
}

func TestProbeDaemonReportsNothingForAStoppedDaemon(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if running, persisted := probeDaemon(addr); running || !persisted {
		t.Errorf("running %v, persisted %v", running, persisted)
	}
}

func TestCLIStatusJSONSaysTheThrottleIsPersisted(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := c.run("", "status", "--json", "--audit", "0")
	if code != 0 {
		t.Fatalf("status: exit %d, %q %q", code, out, errOut)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	caps, _ := rep["capabilities"].(map[string]any)
	if caps["second_factor_throttle_persisted"] != true {
		t.Errorf("capabilities = %v", rep["capabilities"])
	}
	if rep["throttle_persisted"] != true {
		t.Errorf("throttle_persisted = %v", rep["throttle_persisted"])
	}
}

// ---------------------------------------------------------------- the daemon as an operator meets it

// A stop, as procd sends it, must not take what is counted in memory with it. Against the real
// binary, because the signal handling is in main.
func TestATermWritesTheSummaryOfAnOpenRun(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	writeFile(t, cfg, "config server\n\toption listen '"+addr+"'\n\toption audit '"+dir+"/audit.jsonl'\n")

	cmd := exec.Command(cliBinary(t), "-config", cfg, "-state", dir, "serve")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for i := 0; i < 200 && !daemonRunning(addr); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		resp, err := http.Post("http://"+addr+"/mcp", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if got := auditLines(t, dir); got != 1 {
		t.Fatalf("%d lines before the stop, want the first", got)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("the daemon did not stop cleanly: %v", err)
	}
	evs := auditEvents(t, dir)
	if len(evs) != 2 || evs[1].Folded != 4 {
		t.Errorf("after the stop: %+v", evs)
	}
}
