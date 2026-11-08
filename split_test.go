package main

// The split of the daemon into the listener and the helper (helper.go, frontend.go,
// docs/privilege-split.md): the helper serves only the listener's uid, takes four operations and the
// tools of toolSpecs and nothing else, decodes every frame strictly, resolves the bearer token itself
// on every call, and the listener refuses to run as root or holding a capability.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
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

// shortSocketPath is a socket path under the 108 bytes a Unix address holds, which a test's own
// temporary directory can exceed.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "omh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "run", "helper.sock")
}

// startHelper serves s on a fresh socket for the listener uid given, and returns the socket's path.
func startHelper(t *testing.T, s *Server, parserUID int) string {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := listenHelper(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newHelperServer(s, parserUID).serve(ln)
	return path
}

// rawExchange sends one frame of b and returns the answer frame, or the error that ended the read.
func rawExchange(t *testing.T, path string, b []byte) (helperResponse, error) {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	c.Write(append(n[:], b...))
	rb, err := readFrame(c, maxResponseFrame)
	if err != nil {
		return helperResponse{}, err
	}
	var resp helperResponse
	if err := json.Unmarshal(rb, &resp); err != nil {
		t.Fatalf("an answer that is not JSON: %q", rb)
	}
	return resp, nil
}

func mustRefuse(t *testing.T, path, what string, b []byte) helperResponse {
	t.Helper()
	resp, err := rawExchange(t, path, b)
	if err != nil {
		t.Fatalf("%s: no answer: %v", what, err)
	}
	if resp.OK || resp.Refusal == "" {
		t.Fatalf("%s: taken: %+v", what, resp)
	}
	return resp
}

const splitPolicies = `
config policy
	option client 'alice'
	list tools 'ubus_call'
	list scopes 'system.*'

config policy
	option client 'admin'
	list tools 'exec'
	list scopes 'id'
`

func TestHelperServesOnlyTheListenersUID(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	other := startHelper(t, s, os.Getuid()+1)
	if _, err := rawExchange(t, other, []byte(`{"v":1,"op":"health"}`)); err == nil {
		t.Fatal("a peer that is not the listener's uid got an answer")
	}
	ours := startHelper(t, s, os.Getuid())
	resp, err := rawExchange(t, ours, []byte(`{"v":1,"op":"health"}`))
	if err != nil || !resp.OK {
		t.Fatalf("the listener's uid was not served: %+v %v", resp, err)
	}
}

// The uid is the kernel's, not anything the peer says, and a peer whose uid cannot be read is refused.
func TestHelperRefusesAPeerWhoseUIDCannotBeRead(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	path := shortSocketPath(t)
	ln, err := listenHelper(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := newHelperServer(s, os.Getuid())
	h.peer = func(*net.UnixConn) (int, error) { return os.Getuid(), errors.New("no credentials") }
	go h.serve(ln)
	if _, err := rawExchange(t, path, []byte(`{"v":1,"op":"health"}`)); err == nil {
		t.Fatal("a peer whose credentials could not be read got an answer")
	}
}

func TestHelperTakesOnlyItsFourOperations(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	path := startHelper(t, s, os.Getuid())
	for _, op := range []string{"exec", "run", "shell", "ubus", "uci", "write", "spawn", "Auth", "CALL", ""} {
		mustRefuse(t, path, "op "+op, []byte(fmt.Sprintf(`{"v":1,"op":%q}`, op)))
	}
	if resp, err := rawExchange(t, path, []byte(`{"v":1,"op":"config"}`)); err != nil || !resp.OK || resp.Listen != "127.0.0.1:0" {
		t.Errorf("config: %+v %v", resp, err)
	}
	if resp, err := rawExchange(t, path, []byte(`{"v":1,"op":"health"}`)); err != nil || !resp.OK || !resp.Persisted {
		t.Errorf("health: %+v %v", resp, err)
	}
}

// A tool that is not on the list is refused before its input is read, and so is anything that is not
// the tool's shape: no "run this string" reaches a program.
func TestHelperRefusesAnActionOffTheList(t *testing.T) {
	fakeCmd(t, "ubus", `echo ran >> "$OMH_RAN"; echo '{}'`)
	ran := filepath.Join(t.TempDir(), "ran")
	t.Setenv("OMH_RAN", ran)
	s, dir := newToolRig(t, splitPolicies)
	alice, _ := s.tokens.Mint("alice")
	path := startHelper(t, s, os.Getuid())
	for _, tool := range []string{"sh", "service_set", "file_write", "uci_commit", "exec ", "Exec", "../exec", "pair", "allow", "mfa_reset"} {
		mustRefuse(t, path, "tool "+tool, []byte(fmt.Sprintf(`{"v":1,"op":"call","token":%q,"tool":%q,"input":{}}`, alice, tool)))
	}
	// The tool's own shape: a field ubus_call does not have is refused, and nothing runs.
	resp, err := rawExchange(t, path, []byte(fmt.Sprintf(
		`{"v":1,"op":"call","token":%q,"tool":"ubus_call","input":{"object":"system","method":"board","argv":["sh","-c","id"]}}`, alice)))
	if err != nil || !resp.OK || !resp.IsError || !strings.Contains(resp.Text, "not its shape") {
		t.Fatalf("an input with a field the tool lacks: %+v %v", resp, err)
	}
	for _, in := range []string{`[]`, `"system.board"`, `{"object":"system","method":"board"} {"x":1}`, `{"object":1,"method":"board"}`} {
		resp, err := rawExchange(t, path, []byte(fmt.Sprintf(`{"v":1,"op":"call","token":%q,"tool":"ubus_call","input":%s}`, alice, in)))
		if err == nil && resp.OK && !resp.IsError {
			t.Errorf("input %s was run: %+v", in, resp)
		}
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("a program ran for a request that was refused")
	}
	for _, e := range auditEvents(t, dir) {
		if e.Outcome == OutcomeOK {
			t.Errorf("an OK line for a refused request: %+v", e)
		}
	}
}

func TestHelperDecodesEveryFrameStrictly(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	path := startHelper(t, s, os.Getuid())
	for what, b := range map[string]string{
		"no version":           `{"op":"health"}`,
		"another version":      `{"v":2,"op":"health"}`,
		"an unknown field":     `{"v":1,"op":"health","client":"admin"}`,
		"a client named":       `{"v":1,"op":"call","client":"admin","tool":"exec","input":{"argv":["id"]}}`,
		"a granted flag":       `{"v":1,"op":"call","token":"x","tool":"exec","input":{"argv":["id"]},"approved":true}`,
		"data after":           `{"v":1,"op":"health"}{"v":1,"op":"health"}`,
		"not an object":        `[1,2]`,
		"a field of no op":     `{"v":1,"op":"health","token":"x"}`,
		"input to auth":        `{"v":1,"op":"auth","token":"x","input":{}}`,
		"a tool to config":     `{"v":1,"op":"config","tool":"exec"}`,
		"input not an object":  `{"v":1,"op":"call","token":"x","tool":"exec","input":["id"]}`,
		"no input":             `{"v":1,"op":"call","token":"x","tool":"exec"}`,
		"a token over bound":   `{"v":1,"op":"auth","token":"` + strings.Repeat("a", maxTokenLen+1) + `"}`,
		"a remote over bound":  `{"v":1,"op":"auth","token":"x","remote":"` + strings.Repeat("a", maxRemoteLen+1) + `"}`,
		"a tool name too long": `{"v":1,"op":"call","token":"x","tool":"` + strings.Repeat("e", maxToolNameLen+1) + `","input":{}}`,
		"version as a string":  `{"v":"1","op":"health"}`,
		"invalid json":         `{"v":1,"op":"health"`,
	} {
		mustRefuse(t, path, what, []byte(b))
	}
}

func TestHelperBoundsItsFrames(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	path := startHelper(t, s, os.Getuid())
	// Over the bound by one byte, and the whole of it sent: a request the helper would otherwise take.
	over := append([]byte(`{"v":1,"op":"health"}`), bytes.Repeat([]byte(" "), maxRequestFrame+1-21)...)
	for what, body := range map[string][]byte{"an empty frame": nil, "a frame over the bound": over} {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(body)))
		go c.Write(append(n[:], body...))
		rb, err := readFrame(c, maxResponseFrame)
		c.Close()
		var resp helperResponse
		if err != nil || json.Unmarshal(rb, &resp) != nil || resp.OK {
			t.Errorf("%s: %v %q", what, err, rb)
		}
	}
	// A peer that sends half a frame and stops is cut off by the read deadline, not waited for.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0, 0, 0, 50, '{'})
	c.SetReadDeadline(time.Now().Add(helperReadTimeout + 5*time.Second))
	start := time.Now()
	io.ReadAll(c)
	if time.Since(start) > helperReadTimeout+4*time.Second {
		t.Errorf("a half frame held the connection for %s", time.Since(start))
	}
}

func TestHelperIsBusyRatherThanUnbounded(t *testing.T) {
	s, _ := newToolRig(t, splitPolicies)
	path := shortSocketPath(t)
	ln, err := listenHelper(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := newHelperServer(s, os.Getuid())
	h.slots = make(chan struct{}) // every slot taken
	go h.serve(ln)
	resp, err := rawExchange(t, path, []byte(`{"v":1,"op":"health"}`))
	if err != nil || resp.OK || !strings.Contains(resp.Refusal, "busy") {
		t.Fatalf("with every slot taken: %+v %v", resp, err)
	}
}

// The client of a call is the one its token resolves to in the helper, every time: a request names
// no client, a revoked token is refused on its next call, and a missing one is audited.
func TestHelperResolvesTheTokenItselfOnEveryCall(t *testing.T) {
	fakeCmd(t, "id", `echo uid=0`)
	s, dir := newToolRig(t, splitPolicies)
	alice, _ := s.tokens.Mint("alice")
	admin, _ := s.tokens.Mint("admin")
	path := startHelper(t, s, os.Getuid())
	exec := func(token string) helperResponse {
		resp, err := rawExchange(t, path, []byte(fmt.Sprintf(`{"v":1,"op":"call","token":%q,"tool":"exec","input":{"argv":["id"]}}`, token)))
		if err != nil || !resp.OK {
			t.Fatalf("call: %+v %v", resp, err)
		}
		return resp
	}
	if r := exec(alice); !r.IsError || !strings.Contains(r.Text, "denied") {
		t.Errorf("alice ran admin's exec: %+v", r)
	}
	if r := exec(admin); r.IsError || !strings.Contains(r.Text, "uid=0") {
		t.Errorf("admin's own exec: %+v", r)
	}
	if r := exec(""); !r.IsError || !strings.Contains(r.Text, "unauthorized") {
		t.Errorf("no token: %+v", r)
	}
	s.tokens.Revoke("admin")
	if r := exec(admin); !r.IsError || !strings.Contains(r.Text, "unauthorized") {
		t.Errorf("a revoked token ran: %+v", r)
	}
	resp, err := rawExchange(t, path, []byte(fmt.Sprintf(`{"v":1,"op":"auth","token":%q,"remote":"127.0.0.1:5"}`, alice)))
	if err != nil || !resp.OK || !resp.Known || resp.Client != "alice" {
		t.Errorf("auth of alice: %+v %v", resp, err)
	}
	resp, err = rawExchange(t, path, []byte(`{"v":1,"op":"auth","token":"nope","remote":"127.0.0.1:6"}`))
	if err != nil || !resp.OK || resp.Known || resp.Client != "" {
		t.Errorf("auth of a bad token: %+v %v", resp, err)
	}
	var tools []string
	for _, e := range auditEvents(t, dir) {
		tools = append(tools, e.Client+":"+e.Tool+":"+string(e.Outcome))
	}
	want := "alice:exec:DENIED admin:exec:OK <unauthenticated>::DENIED"
	if got := strings.Join(tools, " "); got != want {
		t.Errorf("audit trail %q, want %q (the rest folded)", got, want)
	}
}

// The listener over the socket, as the daemon runs it: an HTTP request with a bearer token reaches the
// helper's gate, which grants and refuses per client, and the audit log is the helper's.
func TestTheListenerRunsToolsOnlyThroughTheHelper(t *testing.T) {
	fakeCmd(t, "ubus", `echo '{"board":"fake"}'`)
	s, dir := newToolRig(t, splitPolicies)
	alice, _ := s.tokens.Mint("alice")
	bob, _ := s.tokens.Mint("bob")
	path := startHelper(t, s, os.Getuid())
	ts := httptest.NewServer(newFrontend(&helperClient{path: path}).Handler())
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
	if out, isErr := call(alice, "ubus_call", map[string]any{"object": "system", "method": "board"}); isErr || !strings.Contains(out, "fake") {
		t.Fatalf("alice's granted call: %q (error=%v)", out, isErr)
	}
	if out, isErr := call(alice, "ubus_call", map[string]any{"object": "service", "method": "set"}); !isErr || !strings.Contains(out, "denied") {
		t.Errorf("alice outside her scope: %q (error=%v)", out, isErr)
	}
	if out, isErr := call(bob, "exec", map[string]any{"argv": []string{"id"}}); !isErr || !strings.Contains(out, "denied") {
		t.Errorf("bob with no grant: %q (error=%v)", out, isErr)
	}
	// A bad token never opens a session, and the helper writes its line.
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer nope")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a bad token: %d", resp.StatusCode)
	}
	var got []string
	for _, e := range auditEvents(t, dir) {
		got = append(got, e.Client+":"+e.Tool+":"+string(e.Outcome))
	}
	want := "alice:ubus_call:OK alice:ubus_call:DENIED bob:exec:DENIED <unauthenticated>::DENIED"
	if strings.Join(got, " ") != want {
		t.Errorf("audit trail %q, want %q", strings.Join(got, " "), want)
	}
	// /health is the helper's answer.
	hr, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.StatusCode != 200 {
		t.Errorf("health %d", hr.StatusCode)
	}
}

// Without its helper the listener runs nothing and says so, rather than answering for it.
func TestTheListenerWithoutItsHelperRunsNothing(t *testing.T) {
	ts := httptest.NewServer(newFrontend(&helperClient{path: shortSocketPath(t)}).Handler())
	defer ts.Close()
	for _, p := range []string{"/health", "/mcp"} {
		req, _ := http.NewRequest("POST", ts.URL+p, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s with no helper: %d", p, resp.StatusCode)
		}
	}
}

// A token longer than any token is no token: the listener sends none, and the helper counts a bad one.
func TestTheListenerSendsNoOversizeToken(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+strings.Repeat("t", maxTokenLen+1))
	if got := bearerOf(h); got != "" {
		t.Errorf("an oversize token was passed on: %d bytes", len(got))
	}
	h.Set("Authorization", "Bearer abc")
	if got := bearerOf(h); got != "abc" {
		t.Errorf("a token was lost: %q", got)
	}
}

func TestListenerSocketIsItsOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the socket is root:openwrt-mcp 0660, shown on a router by scripts/e2e-vlab.sh")
	}
	path := shortSocketPath(t)
	ln, err := listenHelper(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for p, want := range map[string]os.FileMode{filepath.Dir(path): 0o700, path: 0o600} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s is %o, want %o", p, st.Mode().Perm(), want)
		}
	}
	// A stale socket from a crash is replaced, not a reason not to start.
	ln.Close()
	os.WriteFile(path, nil, 0o600)
	ln2, err := listenHelper(path, os.Getgid())
	if err != nil {
		t.Fatalf("a stale socket file stopped the helper: %v", err)
	}
	ln2.Close()
}

func TestServeIDsAreTheCallersOwnWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the ids are the openwrt-mcp account's")
	}
	uid, gid, err := serveIDs()
	if err != nil || uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("serveIDs = %d %d %v", uid, gid, err)
	}
}

const noCaps = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"

func TestTheListenerRefusesRootAndAnyCapability(t *testing.T) {
	const account = 32768
	full := strings.Replace(noCaps, "CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff", 1)
	for name, tc := range map[string]struct {
		status   string
		uid, eid int
		ok       bool
	}{
		"its account, nothing held":         {noCaps, account, account, true},
		"root":                              {noCaps, 0, 0, false},
		"effective root":                    {noCaps, account, 0, false},
		"real root":                         {noCaps, 0, account, false},
		"its account, a bounding set":       {full, account, account, false},
		"its account, no_new_privs 0":       {strings.Replace(noCaps, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), account, account, false},
		"its account, an effective cap":     {strings.Replace(noCaps, "CapEff:\t0000000000000000", "CapEff:\t0000000000000400", 1), account, account, false},
		"its account, a permitted cap":      {strings.Replace(noCaps, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001", 1), account, account, false},
		"its account, an ambient cap":       {strings.Replace(noCaps, "CapAmb:\t0000000000000000", "CapAmb:\t0000000000001000", 1), account, account, false},
		"its account, sets not shown":       {"NoNewPrivs:\t1\n", account, account, false},
		"another account, a bounding set":   {full, 1000, 1000, true},
		"another account, an effective cap": {strings.Replace(full, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1), 1000, 1000, false},
	} {
		_, err := serveVerdict(42, nil, []byte(tc.status), nil, tc.uid, tc.eid, account)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
	if _, err := serveVerdict(42, errors.New("seccomp: invalid argument"), []byte(noCaps), nil, account, account, account); err == nil {
		t.Error("a filter that failed to go on was allowed to listen")
	}
	if _, err := serveVerdict(0, nil, nil, errors.New("no /proc"), account, account, account); err == nil {
		t.Error("an unreadable /proc/self/status was allowed to listen")
	}
	if _, err := serveVerdict(0, errNoSeccomp, []byte(noCaps), nil, account, account, account); err != nil {
		t.Errorf("a platform with no filter, nothing held: %v", err)
	}
}

// ---------------------------------------------------------------- hostile input

// validFrames are well-formed requests of every kind, the seeds the sweep and the fuzzer mutate.
var validFrames = []string{
	`{"v":1,"op":"auth","token":"abc","remote":"127.0.0.1:1"}`,
	`{"v":1,"op":"call","token":"abc","tool":"exec","input":{"argv":["id"],"timeout":5}}`,
	`{"v":1,"op":"call","token":"abc","tool":"uci_apply","input":{"changes":[{"config":"system","section":"@system[0]","option":"hostname","value":"x"}]}}`,
	`{"v":1,"op":"call","token":"abc","tool":"ubus_call","input":{"object":"system","method":"board","args":{"a":[1,2,{"b":null}]}}}`,
	`{"v":1,"op":"call","token":"abc","tool":"action_approve","input":{"id":"KQWPT","hash":"00","pin":"1","code":"2"}}`,
	`{"v":1,"op":"config"}`,
	`{"v":1,"op":"health"}`,
}

// acceptedIsWellFormed is what a request the decoder takes must be: one of the four operations, a
// call naming a tool on the list with an object for input, fields within their bounds.
func acceptedIsWellFormed(r helperRequest) error {
	switch r.Op {
	case "auth", "config", "health":
		if r.Tool != "" || len(r.Input) != 0 {
			return fmt.Errorf("%s with a tool or an input", r.Op)
		}
	case "call":
		if _, ok := toolByName(r.Tool); !ok {
			return fmt.Errorf("a call to %q", r.Tool)
		}
		if !json.Valid(r.Input) || bytes.TrimLeft(r.Input, " \t\r\n")[0] != '{' {
			return fmt.Errorf("an input that is not an object: %q", r.Input)
		}
	default:
		return fmt.Errorf("op %q", r.Op)
	}
	if r.V != helperProtoVersion || len(r.Token) > maxTokenLen || len(r.Remote) > maxRemoteLen {
		return fmt.Errorf("out of bounds: %+v", r)
	}
	return nil
}

// mutate changes b the ways a hostile or broken peer would: bytes flipped, cut, repeated, spliced.
func mutate(rng *rand.Rand, b []byte) []byte {
	out := append([]byte(nil), b...)
	for k := rng.Intn(4) + 1; k > 0 && len(out) > 0; k-- {
		i := rng.Intn(len(out))
		switch rng.Intn(6) {
		case 0:
			out[i] = byte(rng.Intn(256))
		case 1:
			out = out[:i]
		case 2:
			out = append(out[:i], append([]byte(validFrames[rng.Intn(len(validFrames))]), out[i:]...)...)
		case 3:
			out = append(out[:i], out[i+1:]...)
		case 4:
			for _, w := range []string{`"op":"exec"`, `"client":"admin"`, `"tool":"sh"`, `"v":2`, `\u0000`, `"input":"id"`} {
				if rng.Intn(3) == 0 {
					out = append(out[:i], append([]byte(w), out[i:]...)...)
					break
				}
			}
		case 5:
			out = append(out, out[rng.Intn(len(out)):]...)
		}
	}
	return out
}

// Every seed of the sweep: the decoder never panics, and whatever it takes is well formed.
func TestHelperDecoderSurvivesASweepOfHostileFrames(t *testing.T) {
	const seeds = 200
	taken, refused := 0, 0
	for seed := int64(1); seed <= seeds; seed++ {
		rng := rand.New(rand.NewSource(seed))
		for i := 0; i < 100; i++ {
			b := mutate(rng, []byte(validFrames[rng.Intn(len(validFrames))]))
			r, err := decodeHelperRequest(b)
			if err != nil {
				if !errors.Is(err, errNotARequest) {
					t.Fatalf("seed %d: a refusal that is not the protocol's: %v", seed, err)
				}
				refused++
				continue
			}
			if err := acceptedIsWellFormed(r); err != nil {
				t.Fatalf("seed %d: took %q: %v", seed, b, err)
			}
			taken++
		}
	}
	t.Logf("%d seeds, %d frames: %d taken, every one well formed; %d refused", seeds, taken+refused, taken, refused)
	if refused == 0 || taken == 0 {
		t.Errorf("the sweep measured nothing: %d taken, %d refused", taken, refused)
	}
}

// The same sweep through a running helper: it answers every frame or closes, keeps serving, and
// nothing it was sent runs a program.
func TestHelperSurvivesHostileFramesOnItsSocket(t *testing.T) {
	fakeCmd(t, "id", `echo ran >> "$OMH_RAN"`)
	ran := filepath.Join(t.TempDir(), "ran")
	t.Setenv("OMH_RAN", ran)
	s, _ := newToolRig(t, splitPolicies)
	path := startHelper(t, s, os.Getuid())
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		b := mutate(rng, []byte(validFrames[rng.Intn(len(validFrames))]))
		if len(b) == 0 {
			continue
		}
		rawExchange(t, path, b)
	}
	if resp, err := rawExchange(t, path, []byte(`{"v":1,"op":"health"}`)); err != nil || !resp.OK {
		t.Fatalf("the helper stopped serving after the sweep: %+v %v", resp, err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("a hostile frame ran a program with no token")
	}
}

func FuzzHelperRequest(f *testing.F) {
	for _, v := range validFrames {
		f.Add([]byte(v))
	}
	f.Add([]byte(`{"v":1,"op":"call","token":"","tool":"exec","input":{"argv":["sh","-c","id"]},"x":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeHelperRequest(b)
		if err != nil {
			if !errors.Is(err, errNotARequest) {
				t.Fatalf("a refusal that is not the protocol's: %v", err)
			}
			return
		}
		if err := acceptedIsWellFormed(r); err != nil {
			t.Fatalf("took %q: %v", b, err)
		}
	})
}

// A package that depends on the split asks the binary, the way it asks about the other guarantees:
// status --json, read as plain JSON.
func TestCLIStatusJSONSaysTheListenerHoldsNoRoot(t *testing.T) {
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
	if caps["listener_holds_no_root"] != true {
		t.Errorf("capabilities = %v; a caller cannot tell that the listener holds no root", rep["capabilities"])
	}
}
