package main

// The helper: the part of the daemon that holds root (G3.14, step two; docs/privilege-split.md).
// It does not listen on the network. It takes requests on one Unix socket, from one peer, the
// listener (frontend.go), whose uid it checks on every connection, and it takes four of them:
//
//	auth    who a bearer token is (and the folded audit line of a bad one)
//	call    one tool of toolSpecs, by name, with that tool's own input type, under a bearer token
//	config  the listen address, so the listener reads no file of the daemon's
//	health  whether the last throttle write reached the disk
//
// A request is one frame: a four-byte big-endian length and that many bytes of one JSON object,
// decoded strictly: an unknown field, another type, data after the object, an operation or a tool
// not on the list, or a frame over its bound is refused before anything is looked up. The answer is
// one frame back, and the connection closes. Nothing in a request names a client, a policy, a window
// or an approval: the helper finds each of them itself, from the token and from its own state.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

const (
	helperProtoVersion = 1
	maxRequestFrame    = 1 << 20 // the largest input is a uci batch or a package list
	maxResponseFrame   = 4 << 20 // an answer is cut at maxResultBytes; the frame leaves room
	helperReadTimeout  = 10 * time.Second
	helperCallTimeout  = 6 * time.Minute // exec stops at 300 s, apk_add at its own bounds
	maxHelperConns     = 32
	maxRemoteLen       = 128
	maxToolNameLen     = 64

	defaultHelperSocket = "/var/run/openwrt-mcp/helper.sock"
	// serveUser is the account the listener runs as; the init script makes it.
	serveUser = "openwrt-mcp"
)

type helperRequest struct {
	V      int             `json:"v"`
	Op     string          `json:"op"`
	Token  string          `json:"token,omitempty"`
	Remote string          `json:"remote,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
}

type helperResponse struct {
	OK        bool   `json:"ok"` // false: refused at the protocol, Refusal says why
	Refusal   string `json:"refusal,omitempty"`
	Client    string `json:"client,omitempty"`
	Known     bool   `json:"known,omitempty"` // auth: the token is a client's
	Text      string `json:"text,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
	Listen    string `json:"listen,omitempty"`
	Persisted bool   `json:"persisted,omitempty"`
}

// errOutcomeUnknown is a call that was sent whole and got no answer: the helper may have run it. The
// listener says so to the agent, and never that nothing was run.
var errOutcomeUnknown = errors.New("the outcome is unknown")

// answerTooLarge replaces the answer to a call that cannot be sent back whole.
const answerTooLarge = "the call ran, but its answer was too large to send back; check the router's state before you call it again"

// errNotARequest wraps every reason a frame is refused before it is acted on.
var errNotARequest = errors.New("not a request the helper takes")

// decodeHelperRequest reads one request and refuses anything the protocol does not name.
func decodeHelperRequest(b []byte) (helperRequest, error) {
	var r helperRequest
	if err := strictUnmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%w: %v", errNotARequest, err)
	}
	if r.V != helperProtoVersion {
		return r, fmt.Errorf("%w: protocol version %d, not %d", errNotARequest, r.V, helperProtoVersion)
	}
	if len(r.Token) > maxTokenLen || len(r.Remote) > maxRemoteLen || len(r.Tool) > maxToolNameLen {
		return r, fmt.Errorf("%w: a field is longer than its bound", errNotARequest)
	}
	only := func(token, remote, tool, input bool) error {
		if (!token && r.Token != "") || (!remote && r.Remote != "") || (!tool && r.Tool != "") || (!input && len(r.Input) != 0) {
			return fmt.Errorf("%w: %s takes no such field", errNotARequest, r.Op)
		}
		return nil
	}
	switch r.Op {
	case "auth":
		return r, only(true, true, false, false)
	case "call":
		if err := only(true, false, true, true); err != nil {
			return r, err
		}
		if _, ok := toolByName(r.Tool); !ok {
			return r, fmt.Errorf("%w: %q is not a tool", errNotARequest, r.Tool)
		}
		if t := bytes.TrimLeft(r.Input, " \t\r\n"); len(t) == 0 || t[0] != '{' {
			return r, fmt.Errorf("%w: the input of %s is not a JSON object", errNotARequest, r.Tool)
		}
		return r, nil
	case "config", "health":
		return r, only(false, false, false, false)
	}
	return r, fmt.Errorf("%w: %q is not an operation", errNotARequest, r.Op)
}

// readFrame reads one length-prefixed frame of at most max bytes.
func readFrame(r io.Reader, max int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > uint32(max) {
		return nil, fmt.Errorf("%w: a frame of %d bytes, bounds 1 to %d", errNotARequest, size, max)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxResponseFrame {
		return fmt.Errorf("a frame of %d bytes", len(b))
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, err := w.Write(append(n[:], b...))
	return err
}

// helperServer serves the socket: one request per connection, from the listener's uid only.
type helperServer struct {
	s         *Server
	parserUID int
	slots     chan struct{}
	// peer reads the uid of a connection's other end (SO_PEERCRED); a variable only so a test can
	// stand in another uid.
	peer func(*net.UnixConn) (int, error)
}

func newHelperServer(s *Server, parserUID int) *helperServer {
	return &helperServer{s: s, parserUID: parserUID, slots: make(chan struct{}, maxHelperConns), peer: peerUID}
}

func (h *helperServer) serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go h.handle(c)
	}
}

// handle answers one connection. A peer that is not the listener gets nothing and is logged; it
// never reaches the decoder.
func (h *helperServer) handle(c *net.UnixConn) {
	defer c.Close()
	uid, err := h.peer(c)
	if err != nil || uid != h.parserUID {
		log.Printf("openwrt-mcp: helper: refused a connection from uid %d (%v): only uid %d, the listener, is served", uid, err, h.parserUID)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		h.reply(c, "", helperResponse{Refusal: "busy: too many requests at once"})
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(helperReadTimeout))
	b, err := readFrame(c, maxRequestFrame)
	if err != nil {
		h.reply(c, "", helperResponse{Refusal: err.Error()})
		return
	}
	req, err := decodeHelperRequest(b)
	if err != nil {
		h.reply(c, "", helperResponse{Refusal: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperCallTimeout)
	defer cancel()
	if err := h.reply(c, req.Op, h.dispatch(ctx, req)); err != nil && req.Op == "call" {
		// The call ran and its own line is in the log; this one says the listener never heard how.
		client, ok := h.s.tokens.Resolve(req.Token)
		if !ok {
			client = "<unauthenticated>"
		}
		h.s.audit.Record(AuditEvent{Time: nowISO(), Client: client, Tool: req.Tool, Outcome: OutcomeError,
			Error: "the answer did not reach the listener: " + err.Error() + "; the call itself ran, and its own line says how it ended"})
	}
}

func (h *helperServer) dispatch(ctx context.Context, req helperRequest) helperResponse {
	switch req.Op {
	case "auth":
		client, ok, _ := h.s.auth(req.Token, req.Remote)
		return helperResponse{OK: true, Client: client, Known: ok}
	case "call":
		text, isErr, _ := h.s.call(ctx, req.Token, req.Tool, req.Input)
		return helperResponse{OK: true, Text: text, IsError: isErr}
	case "config":
		return helperResponse{OK: true, Listen: h.s.cfg().Listen}
	case "health":
		p, _ := h.s.health()
		return helperResponse{OK: true, Persisted: p}
	}
	return helperResponse{Refusal: "not an operation"} // unreachable: decodeHelperRequest refused it
}

// reply sends one answer. An answer that cannot be encoded or is over the frame's bound is replaced by
// a short one: for a call, that it ran and its answer was too large, so the agent checks the router
// rather than calling again.
func (h *helperServer) reply(c *net.UnixConn, op string, resp helperResponse) error {
	b, err := json.Marshal(resp)
	if err == nil && len(b) > maxResponseFrame {
		err = fmt.Errorf("an answer of %d bytes", len(b))
	}
	if err != nil {
		short := helperResponse{Refusal: "the answer could not be sent: " + err.Error()}
		if op == "call" {
			short = helperResponse{OK: true, IsError: true, Text: answerTooLarge}
		}
		b, _ = json.Marshal(short)
	}
	_ = c.SetWriteDeadline(time.Now().Add(helperReadTimeout))
	return writeFrame(c, b)
}

// listenHelper makes the socket: a directory the listener's group may enter and nobody else, and a
// socket only that group may connect to. As root the directory is root:<group> 0750 and the socket
// root:<group> 0660; not as root (the tests) both are the caller's own, 0700 and 0600.
func listenHelper(path string, gid int) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o700)
	if os.Geteuid() == 0 {
		mode = 0o750
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, gid); err != nil {
			return nil, err
		}
	}
	// MkdirAll leaves an existing directory as it found it.
	if err := os.Chmod(dir, mode); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	sock := os.FileMode(0o600)
	if os.Geteuid() == 0 {
		sock = 0o660
		if err := os.Chown(path, 0, gid); err != nil {
			ln.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, sock); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// serveIDs is whom the helper serves: as root, the uid and gid of serveUser, and the helper does
// not start without that account; not as root (the tests), its own.
func serveIDs() (uid, gid int, err error) {
	if os.Geteuid() != 0 {
		return os.Getuid(), os.Getgid(), nil
	}
	u, err := user.Lookup(serveUser)
	if err != nil {
		return 0, 0, fmt.Errorf("the account %s does not exist, and the listener runs as it (the init script makes it): %w", serveUser, err)
	}
	g, err := user.LookupGroup(serveUser)
	if err != nil {
		return 0, 0, fmt.Errorf("the group %s does not exist: %w", serveUser, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, fmt.Errorf("the account %s is root's uid or gid, which would make the split nothing", serveUser)
	}
	return uid, gid, nil
}

// runHelper is `openwrt-mcp helper` once the server is up: the socket, then requests until it fails.
func runHelper(s *Server, path string) error {
	uid, gid, err := serveIDs()
	if err != nil {
		return err
	}
	ln, err := listenHelper(path, gid)
	if err != nil {
		return fmt.Errorf("helper socket %s: %w", path, err)
	}
	log.Printf("openwrt-mcp %s helper on %s, serving uid %d only (%d policies, %d paired clients)",
		version, path, uid, len(s.cfg().Policies), len(s.tokens.Clients()))
	return newHelperServer(s, uid).serve(ln)
}

// ---------------------------------------------------------------- the listener's side

// helperClient is the listener's backend: one connection per request to the helper's socket.
type helperClient struct{ path string }

func (h *helperClient) do(ctx context.Context, req helperRequest) (helperResponse, error) {
	req.V = helperProtoVersion
	b, err := json.Marshal(req)
	if err != nil {
		return helperResponse{}, err
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := d.DialContext(dctx, "unix", h.path)
	if err != nil {
		return helperResponse{}, err
	}
	defer c.Close()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > helperCallTimeout+30*time.Second {
		deadline = time.Now().Add(helperCallTimeout + 30*time.Second)
	}
	_ = c.SetDeadline(deadline)
	// The helper acts only on a whole frame, so a frame that was not sent whole was not acted on. Once
	// it was, a missing or broken answer says nothing about whether the call ran.
	if err := writeFrame(c, b); err != nil {
		return helperResponse{}, err
	}
	rb, err := readFrame(c, maxResponseFrame)
	if err != nil {
		return helperResponse{}, fmt.Errorf("%w: the request was sent and no answer came (%v)", errOutcomeUnknown, err)
	}
	var resp helperResponse
	if err := strictUnmarshal(rb, &resp); err != nil {
		return helperResponse{}, fmt.Errorf("%w: the request was sent and the answer does not read (%v)", errOutcomeUnknown, err)
	}
	if !resp.OK {
		return resp, fmt.Errorf("the helper refused the request: %s", resp.Refusal)
	}
	return resp, nil
}

// helperQuickTimeout bounds every request but a tool call: a helper that does not answer a token's
// lookup in that time is not answering.
const helperQuickTimeout = 10 * time.Second

func (h *helperClient) quick(req helperRequest) (helperResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), helperQuickTimeout)
	defer cancel()
	return h.do(ctx, req)
}

func (h *helperClient) auth(token, remote string) (string, bool, error) {
	resp, err := h.quick(helperRequest{Op: "auth", Token: token, Remote: truncateBytes(remote, maxRemoteLen)})
	return resp.Client, resp.Known, err
}

func (h *helperClient) call(ctx context.Context, token, tool string, input json.RawMessage) (string, bool, error) {
	resp, err := h.do(ctx, helperRequest{Op: "call", Token: token, Tool: tool, Input: input})
	return resp.Text, resp.IsError, err
}

func (h *helperClient) health() (bool, error) {
	resp, err := h.quick(helperRequest{Op: "health"})
	return resp.Persisted, err
}

// listen asks the helper for the listen address, waiting for it to come up: procd starts the two
// parts at once.
func (h *helperClient) listen(wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		resp, err := h.quick(helperRequest{Op: "config"})
		if err == nil {
			return resp.Listen, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the helper at %s did not answer in %s: %w", h.path, wait, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// truncateBytes cuts s to at most n bytes.
func truncateBytes(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
