package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The daemon as a client meets it: an HTTP listener, a bearer token, and the tools behind
// the policy and audit gate. Where the unit tests prove the parts, these prove the joins.

// fakeCmd puts a stub executable on PATH. The body is a shell script; it sees its own argv.
func fakeCmd(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func auditEvents(t *testing.T, dir string) []AuditEvent {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("no audit log: %v", err)
	}
	var out []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

type bearerRT struct{ token string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHandlerHealthNeedsNoTokenAndNamesItself(t *testing.T) {
	s, _ := newToolRig(t, "")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	b.Write(buf[:n])
	if resp.StatusCode != 200 || !strings.Contains(b.String(), "openwrt-mcp "+version+" ok") ||
		!strings.Contains(b.String(), sourceURL) {
		t.Errorf("health = %d %q", resp.StatusCode, b.String())
	}
}

func TestHandlerRefusesWithoutAValidTokenAndAuditsIt(t *testing.T) {
	s, dir := newToolRig(t, "")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for name, hdr := range map[string]string{"no header": "", "wrong token": "Bearer nope", "empty bearer": "Bearer "} {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader("{}"))
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: status %d, challenge %q", name, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
	evs := auditEvents(t, dir)
	if len(evs) != 3 {
		t.Fatalf("want 3 audit events, got %d", len(evs))
	}
	for _, e := range evs {
		if e.Client != "<unauthenticated>" || e.Outcome != OutcomeDenied || !strings.Contains(e.Error, "bearer token") {
			t.Errorf("event %+v", e)
		}
	}
}

// A page in a local browser must not be able to drive the router, token or not.
func TestHandlerRefusesAForeignOrigin(t *testing.T) {
	s, _ := newToolRig(t, "")
	tok, _ := s.tokens.Mint("a")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for origin, want := range map[string]int{
		"https://evil.example":   http.StatusForbidden,
		"http://evil.example:80": http.StatusForbidden,
		"http://localhost:3000":  http.StatusBadRequest, // passes the origin check; the body is junk
		"http://127.0.0.1:8730":  http.StatusBadRequest,
		"http://[::1]:8730":      http.StatusBadRequest,
		"https://localhost.evil": http.StatusForbidden,
	} {
		req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader("junk"))
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if (want == http.StatusForbidden) != (resp.StatusCode == http.StatusForbidden) {
			t.Errorf("origin %s: status %d, want forbidden=%v", origin, resp.StatusCode, want == http.StatusForbidden)
		}
	}
}

func TestIsLoopbackOrigin(t *testing.T) {
	for o, want := range map[string]bool{
		"http://localhost": true, "https://localhost:8443": true, "http://127.0.0.1:1": true,
		"http://[::1]:9": true, "localhost": true, "127.0.0.1": true,
		"https://example.com": false, "http://10.0.0.1:80": false, "http://localhost.evil.com": false,
		"": false, "null": false,
	} {
		if got := isLoopbackOrigin(o); got != want {
			t.Errorf("isLoopbackOrigin(%q) = %v, want %v", o, got, want)
		}
	}
}

func TestToolsOverHTTPWithABearerTokenAreGatedPerClient(t *testing.T) {
	fakeCmd(t, "ubus", `echo '{"board":"fake"}'`)
	s, dir := newToolRig(t, `
config policy
	option client 'alice'
	list tools 'ubus_call'
	list scopes 'system.*'
`)
	alice, _ := s.tokens.Mint("alice")
	bob, _ := s.tokens.Mint("bob")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	call := func(token, tool string, args map[string]any) (string, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tr := &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp",
			HTTPClient: &http.Client{Transport: bearerRT{token}}, DisableStandaloneSSE: true}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, tr, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text)
			}
		}
		return b.String(), res.IsError
	}

	out, isErr := call(alice, "ubus_call", map[string]any{"object": "system", "method": "board"})
	if isErr || !strings.Contains(out, "fake") {
		t.Fatalf("alice's granted call: %q (error=%v)", out, isErr)
	}
	if out, isErr := call(alice, "ubus_call", map[string]any{"object": "network", "method": "reload"}); !isErr ||
		!strings.Contains(out, "denied") {
		t.Errorf("alice outside her scope: %q (error=%v)", out, isErr)
	}
	// bob has a token but no policy: identity is not authority.
	if out, isErr := call(bob, "ubus_call", map[string]any{"object": "system", "method": "board"}); !isErr ||
		!strings.Contains(out, "denied") {
		t.Errorf("bob with no grant: %q (error=%v)", out, isErr)
	}

	var clients []string
	for _, e := range auditEvents(t, dir) {
		clients = append(clients, fmt.Sprintf("%s:%s:%s", e.Client, e.Tool, e.Outcome))
	}
	want := []string{"alice:ubus_call:OK", "alice:ubus_call:DENIED", "bob:ubus_call:DENIED"}
	if strings.Join(clients, " ") != strings.Join(want, " ") {
		t.Errorf("audit trail = %v, want %v", clients, want)
	}
}

func TestConfigReloadsWhenTheFileChangesAndKeepsTheLastGoodOne(t *testing.T) {
	s, dir := newToolRig(t, "")
	cfgPath := filepath.Join(dir, "config")
	if n := len(s.cfg().Policies); n != 0 {
		t.Fatalf("starts with %d policies", n)
	}
	later := time.Now().Add(time.Hour)
	write := func(body string) {
		os.WriteFile(cfgPath, []byte(body), 0o600)
		later = later.Add(time.Hour)
		os.Chtimes(cfgPath, later, later)
	}
	good := "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes '*'\n"

	write(good)
	if n := len(s.cfg().Policies); n != 1 {
		t.Fatalf("an added policy was not picked up: %d", n)
	}
	write("config policy\n\toption client 'a'\n") // grants no tools: does not parse
	if n := len(s.cfg().Policies); n != 1 {
		t.Errorf("a broken edit wiped the policies: %d", n)
	}
	write(good + good)
	if n := len(s.cfg().Policies); n != 2 {
		t.Errorf("a fixed file was not reloaded: %d", n)
	}
}

func TestServeRefusesAnythingButLoopback(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8730", "192.168.1.1:8730", "[::]:8730", "example.com:8730"} {
		s, _ := newToolRigListening(t, listen, "")
		err := s.Serve()
		if err == nil || !strings.Contains(err.Error(), "not loopback") {
			t.Errorf("%s: err = %v", listen, err)
		}
	}
	s, _ := newToolRigListening(t, "no-port", "")
	if err := s.Serve(); err == nil || !strings.Contains(err.Error(), "bad listen address") {
		t.Errorf("a listen address with no port: %v", err)
	}
}

func TestServeAnswersOnLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	s, _ := newToolRigListening(t, addr, "")
	go s.Serve() // runs until the test binary exits
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("health = %d", resp.StatusCode)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Serve never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServeReportsAnAddressThatIsTaken(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	s, _ := newToolRigListening(t, l.Addr().String(), "")
	if err := s.Serve(); err == nil {
		t.Error("Serve on a taken port returned nil")
	}
}

func TestNewServerFailsOnABrokenConfigOrStateFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("config policy\n\toption client 'a'\n"), 0o600)
	if _, err := NewServer(bad, dir); err == nil {
		t.Error("a config that does not parse started a server")
	}
	// A pin path that cannot be read must stop the daemon: a silently absent PIN store would
	// turn a pin policy into a door nobody can open, or worse one that never checks.
	state := filepath.Join(dir, "state")
	os.MkdirAll(filepath.Join(state, "pin"), 0o700)
	ok := filepath.Join(dir, "ok")
	os.WriteFile(ok, nil, 0o600)
	if _, err := NewServer(ok, state); err == nil {
		t.Error("an unreadable pin file did not stop the server")
	}
}
