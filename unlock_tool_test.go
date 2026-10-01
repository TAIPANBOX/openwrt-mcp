package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// End to end through the real MCP tool handlers, over an in-memory transport, so the audit
// wrapper, the policy gate and the unlock tools are exercised as one thing. The store-level
// tests prove the rules; these prove that the rules are what a client actually meets.

func policyBlock(client, factor string, extra ...string) string {
	var b strings.Builder
	b.WriteString("\nconfig policy\n\toption client '" + client + "'\n\tlist tools 'exec'\n\tlist scopes '*'\n" +
		"\tlist mfa_tools 'exec'\n")
	if factor != "" {
		b.WriteString("\toption mfa_factor '" + factor + "'\n")
	}
	for _, e := range extra {
		b.WriteString("\t" + e + "\n")
	}
	return b.String()
}

func newToolRig(t *testing.T, policies string) (*Server, string) {
	t.Helper()
	return newToolRigListening(t, "127.0.0.1:0", policies)
}

// newToolRigListening is newToolRig with a chosen listen address, which has to be in the
// config file: the server re-reads the file on first use and would discard an override made
// on the in-memory copy.
func newToolRigListening(t *testing.T, listen, policies string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	body := "config server\n\toption listen '" + listen + "'\n\toption audit '" + dir + "/audit.jsonl'\n" + policies
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// callTool runs one tool call as the given client and returns the text and whether it was
// an error result.
func callTool(t *testing.T, s *Server, client, tool string, args map[string]any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.newServerForClient(client).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	var out strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			out.WriteString(tc.Text)
		}
	}
	return out.String(), res.IsError
}

func execTrue(t *testing.T, s *Server, client string) (string, bool) {
	t.Helper()
	return callTool(t, s, client, "exec", map[string]any{"argv": []string{"true"}})
}

func liveCode(t *testing.T, s *Server, client string, at time.Time) string {
	t.Helper()
	return codeNow(t, s.mfa, client, at)
}

func TestUnlockAndLockEndToEnd(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin+totp", "option mfa_window '5m'"))
	s.mfa.Enrol("a", "openwrt-mcp", "r")
	s.mfa.pins.Set("a", "4821")

	if out, isErr := execTrue(t, s, "a"); !isErr || !strings.Contains(out, "second factor") {
		t.Fatalf("exec before unlocking: %q (error=%v)", out, isErr)
	}
	// Both factors are required; either alone is refused.
	if _, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "4821"}); !isErr {
		t.Fatal("the PIN alone unlocked a pin+totp client")
	}
	if _, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"code": liveCode(t, s, "a", time.Now())}); !isErr {
		t.Fatal("the code alone unlocked a pin+totp client")
	}
	out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{
		"pin": "4821", "code": liveCode(t, s, "a", time.Now().Add(30*time.Second))})
	if isErr || !strings.Contains(out, "Unlocked until") || !strings.Contains(out, "5m0s") {
		t.Fatalf("unlock: %q (error=%v); want success naming the policy's 5m window", out, isErr)
	}
	if out, isErr := execTrue(t, s, "a"); isErr {
		t.Fatalf("exec after unlocking: %q", out)
	}

	out, isErr = callTool(t, s, "a", "mfa_lock", map[string]any{})
	if isErr || !strings.Contains(strings.ToLower(out), "locked") {
		t.Fatalf("mfa_lock: %q (error=%v); it must say the window is closed", out, isErr)
	}
	if out, isErr := execTrue(t, s, "a"); !isErr || !strings.Contains(out, "second factor") {
		t.Fatalf("exec after mfa_lock still went through: %q", out)
	}
}

// mfa_lock only ever takes permission away, so like mfa_unlock it needs no grant: a client
// with no policy at all can still close its own window, and saying so when nothing was open
// is not an error.
func TestMFALockIsUngatedAndHonestWhenNothingWasOpen(t *testing.T) {
	s, _ := newToolRig(t, "")
	out, isErr := callTool(t, s, "nobody", "mfa_lock", map[string]any{})
	if isErr || strings.Contains(out, "denied") {
		t.Fatalf("mfa_lock was gated: %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "not unlocked") && !strings.Contains(strings.ToLower(out), "already locked") {
		t.Errorf("it should say there was nothing to close: %q", out)
	}
}

func TestMFALockOnlyClosesTheCallersOwnWindow(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin")+policyBlock("b", "pin"))
	s.mfa.pins.Set("a", "4821")
	s.mfa.pins.Set("b", "4821")
	callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "4821"})
	callTool(t, s, "b", "mfa_unlock", map[string]any{"pin": "4821"})
	callTool(t, s, "a", "mfa_lock", map[string]any{})
	if _, isErr := execTrue(t, s, "a"); !isErr {
		t.Error("a is still unlocked after its own mfa_lock")
	}
	if out, isErr := execTrue(t, s, "b"); isErr {
		t.Errorf("a's mfa_lock closed b's window: %q", out)
	}
}

// Item 9: one client's unlock must not open another's, even when they chose the same PIN.
func TestUnlockingOneClientDoesNotUnlockAnother(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin")+policyBlock("b", "pin"))
	s.mfa.pins.Set("a", "4821")
	s.mfa.pins.Set("b", "4821")

	if out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "4821"}); isErr {
		t.Fatalf("a could not unlock: %q", out)
	}
	if _, isErr := execTrue(t, s, "a"); isErr {
		t.Fatal("a is not unlocked after unlocking")
	}
	if out, isErr := execTrue(t, s, "b"); !isErr || !strings.Contains(out, "second factor") {
		t.Fatalf("b was opened by a's unlock: %q (error=%v)", out, isErr)
	}
	st := s.mfa.State("b", time.Now())
	if !st.UnlockedUntil.IsZero() {
		t.Errorf("b's state shows a window: %+v", st)
	}
}

func TestToolUnlockLocksOutAfterTheConfiguredFailures(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin", "option mfa_max_failures '2'", "option mfa_lockout '10m'"))
	s.mfa.pins.Set("a", "4821")

	for i := 0; i < 2; i++ {
		out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "0000"})
		if !isErr || strings.Contains(out, "locked out") {
			t.Fatalf("failure %d: %q (error=%v)", i+1, out, isErr)
		}
	}
	out, isErr := callTool(t, s, "a", "mfa_unlock", map[string]any{"pin": "4821"})
	if !isErr || !strings.Contains(out, "locked out until") {
		t.Fatalf("the right PIN after the limit: %q (error=%v); want a lockout refusal", out, isErr)
	}
	until := s.mfa.State("a", time.Now()).LockedOutUntil
	if until.IsZero() || !strings.Contains(out, until.Format(time.RFC3339)) {
		t.Errorf("the refusal %q does not carry the end time %v", out, until)
	}
	if d := time.Until(until); d < 9*time.Minute || d > 10*time.Minute+time.Second {
		t.Errorf("lockout ends in %v, want about 10m", d)
	}
	if _, isErr := execTrue(t, s, "a"); !isErr {
		t.Error("a locked-out client reached a gated tool")
	}
}

// What a client may learn from a refusal: that it was refused, and nothing about which of
// its factors was close.
func TestToolRefusalsDoNotNameTheWrongFactor(t *testing.T) {
	s, _ := newToolRig(t, policyBlock("a", "pin+totp", "option mfa_max_failures '50'"))
	s.mfa.Enrol("a", "openwrt-mcp", "r")
	s.mfa.pins.Set("a", "4821")

	good := liveCode(t, s, "a", time.Now())
	var texts []string
	for _, args := range []map[string]any{
		{"pin": "0000", "code": good},
		{"pin": "4821", "code": "000000"},
		{"pin": "0000", "code": "000000"},
		{"pin": "4821"},
		{"code": good},
		{},
	} {
		out, isErr := callTool(t, s, "a", "mfa_unlock", args)
		if !isErr {
			t.Fatalf("%v unlocked", args)
		}
		texts = append(texts, out)
	}
	for _, o := range texts[1:] {
		if o != texts[0] {
			t.Errorf("refusals differ and leak which factor failed: %q vs %q", o, texts[0])
		}
	}
}

func TestAuditNeverHoldsAPINOrACode(t *testing.T) {
	const pin, wrongPIN1, wrongPIN2 = "7391842", "2468135", "6600771"
	s, dir := newToolRig(t, policyBlock("a", "pin+totp", "option mfa_max_failures '50'"))
	s.mfa.Enrol("a", "openwrt-mcp", "r")
	s.mfa.pins.Set("a", pin)

	good := liveCode(t, s, "a", time.Now())
	bad := wrongCode(t, s.mfa, "a", time.Now())
	secrets := []string{pin, wrongPIN1, wrongPIN2, good, bad}
	for _, args := range []map[string]any{
		{"pin": wrongPIN1, "code": bad},
		{"pin": wrongPIN2, "code": good},
		{"pin": pin, "code": bad},
		{"pin": pin, "code": good}, // the one that succeeds
	} {
		callTool(t, s, "a", "mfa_unlock", args)
	}

	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(b), secret) {
			t.Errorf("%q is in the audit log:\n%s", secret, b)
		}
	}
	// The scan above is only worth something if the events are there. Four attempts, each
	// recorded with both arguments present but redacted.
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev AuditEvent
		if json.Unmarshal([]byte(line), &ev) != nil || ev.Tool != "mfa_unlock" {
			continue
		}
		n++
		args, _ := ev.Args.(map[string]any)
		for _, k := range []string{"code", "pin"} {
			if args[k] != redacted {
				t.Errorf("event %d: args[%s] = %v, want %s", n, k, args[k], redacted)
			}
		}
	}
	if n != 4 {
		t.Errorf("found %d mfa_unlock events in the audit log, want 4", n)
	}
}

func TestRedactionCoversCodeAndPinByExactKeyOnly(t *testing.T) {
	in := map[string]any{
		"code": "123456", "pin": "4821", "PIN": "4821", "Code": "1",
		"nested": map[string]any{"pin": "1111", "list": []any{map[string]any{"code": "2"}}},
		// Names that merely contain the letters must stay readable in the log.
		"ping": "8.8.8.8", "mapping": "x", "zipcode": "z", "country_code": "UA", "encoded": "e",
	}
	got := redact(in).(map[string]any)
	for _, k := range []string{"code", "pin", "PIN", "Code"} {
		if got[k] != redacted {
			t.Errorf("%s was not redacted: %v", k, got[k])
		}
	}
	n := got["nested"].(map[string]any)
	if n["pin"] != redacted || n["list"].([]any)[0].(map[string]any)["code"] != redacted {
		t.Errorf("nested secrets leaked: %v", n)
	}
	for _, k := range []string{"ping", "mapping", "zipcode", "country_code", "encoded"} {
		if got[k] == redacted {
			t.Errorf("%s was redacted although it is not a secret key", k)
		}
	}
}

func TestMFAGateNamesTheFactorsThePolicyNeeds(t *testing.T) {
	m, dir := newMFA(t)
	s := &Server{statePath: dir, mfa: m}
	for _, tc := range []struct {
		factor      string
		must, never []string
	}{
		{factorTOTP, []string{"6-digit code", "mfa_unlock"}, []string{"PIN"}},
		{"", []string{"6-digit code", "mfa_unlock"}, []string{"PIN"}},
		{factorPIN, []string{"PIN", "mfa_unlock"}, []string{"6-digit"}},
		{factorPINTOTP, []string{"PIN", "6-digit code", "mfa_unlock"}, nil},
	} {
		p := &Policy{Client: "a", Tools: []string{"exec"}, MFATools: []string{"exec"},
			MFAWindow: time.Minute, MFAFactor: tc.factor, Enabled: true}
		r := s.mfaGate(p, "a", "exec", t0)
		for _, w := range tc.must {
			if !strings.Contains(r, w) {
				t.Errorf("factor %q: refusal %q lacks %q", tc.factor, r, w)
			}
		}
		for _, w := range tc.never {
			if strings.Contains(r, w) {
				t.Errorf("factor %q: refusal %q mentions %q", tc.factor, r, w)
			}
		}
	}
}

func TestPolicyFactorOptionsParse(t *testing.T) {
	cfg := parse(t, `
config policy
	option client 'a'
	list tools 'exec'
	list scopes '*'

config policy
	option client 'b'
	list tools 'exec'
	list scopes '*'
	option mfa_factor 'pin'
	option mfa_max_failures '3'
	option mfa_lockout '2h'

config policy
	option client 'c'
	list tools 'exec'
	list scopes '*'
	option mfa_factor 'pin+totp'
	option mfa_lockout '90s'
`)
	a, b, c := cfg.Policies[0], cfg.Policies[1], cfg.Policies[2]
	if a.MFAFactor != factorTOTP || a.MFAMaxFailures != 5 || a.MFALockout != 15*time.Minute {
		t.Errorf("defaults: %q %d %v, want totp 5 15m: an existing config must behave as before",
			a.MFAFactor, a.MFAMaxFailures, a.MFALockout)
	}
	if b.MFAFactor != factorPIN || b.MFAMaxFailures != 3 || b.MFALockout != 2*time.Hour {
		t.Errorf("b: %q %d %v", b.MFAFactor, b.MFAMaxFailures, b.MFALockout)
	}
	if c.MFAFactor != factorPINTOTP || c.MFAMaxFailures != 5 || c.MFALockout != 90*time.Second {
		t.Errorf("c: %q %d %v", c.MFAFactor, c.MFAMaxFailures, c.MFALockout)
	}
	if got := b.unlockPolicy(); got.Factor != factorPIN || got.MaxFailures != 3 || got.Lockout != 2*time.Hour {
		t.Errorf("unlockPolicy() = %+v", got)
	}
}

func TestPolicyRejectsBadFactorOptions(t *testing.T) {
	base := "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n"
	for name, c := range map[string]struct{ opt, mention string }{
		"unknown factor":   {"option mfa_factor 'sms'", "mfa_factor"},
		"upper case":       {"option mfa_factor 'PIN'", "mfa_factor"},
		"comma not plus":   {"option mfa_factor 'pin,totp'", "mfa_factor"},
		"reversed":         {"option mfa_factor 'totp+pin'", "mfa_factor"},
		"max failures 0":   {"option mfa_max_failures '0'", "mfa_max_failures"},
		"max failures neg": {"option mfa_max_failures '-1'", "mfa_max_failures"},
		"max failures abc": {"option mfa_max_failures 'abc'", "mfa_max_failures"},
		"lockout abc":      {"option mfa_lockout 'soon'", "mfa_lockout"},
		"lockout zero":     {"option mfa_lockout '0s'", "mfa_lockout"},
		"lockout negative": {"option mfa_lockout '-5m'", "mfa_lockout"},
	} {
		p := filepath.Join(t.TempDir(), "config")
		os.WriteFile(p, []byte(base+"\t"+c.opt+"\n"), 0o600)
		_, err := LoadConfig(p)
		if err == nil {
			t.Errorf("%s: the config loaded", name)
			continue
		}
		if !strings.Contains(err.Error(), c.mention) {
			t.Errorf("%s: the error %q does not name %s", name, err, c.mention)
		}
	}
}

func TestMFAStatusWarnsWhereAGateCannotBeOpened(t *testing.T) {
	cfg := parse(t, `
config policy
	option client 'totp-client'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'

config policy
	option client 'pin-client'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'
	option mfa_factor 'pin'
	option mfa_lockout '5m'
	option mfa_max_failures '4'

config policy
	option client 'both-client'
	list tools 'exec'
	list scopes '*'
	list mfa_tools 'exec'
	option mfa_factor 'pin+totp'

config policy
	option client 'ungated'
	list tools 'exec'
	list scopes '*'
`)
	m, _ := newMFA(t)
	var b strings.Builder
	writeMFAStatus(&b, m, cfg)
	out := b.String()
	for _, want := range []string{
		"no clients enrolled",
		"policy totp-client requires totp",
		"policy pin-client requires pin for: exec (window 15m0s, locked out 5m0s after 4 failures)",
		"policy both-client requires pin+totp",
		"mfa enrol totp-client", "mfa enrol both-client",
		"pin set pin-client", "pin set both-client",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ungated") {
		t.Errorf("a policy that gates nothing is listed:\n%s", out)
	}
	if strings.Contains(out, "mfa enrol pin-client") {
		t.Errorf("a pin-only policy was told to enrol TOTP:\n%s", out)
	}

	// Once the factors exist the warnings go away.
	for _, c := range []string{"totp-client", "pin-client", "both-client"} {
		m.Enrol(c, "openwrt-mcp", "r")
		m.pins.Set(c, "4821")
	}
	b.Reset()
	writeMFAStatus(&b, m, cfg)
	if strings.Contains(b.String(), "WARNING") {
		t.Errorf("warnings remain although everything is set up:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "totp-client: enrolled") {
		t.Errorf("enrolled clients are not listed:\n%s", b.String())
	}
}
