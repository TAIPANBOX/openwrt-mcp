package main

// The listener: the part of the daemon that meets the network (G3.14, step two;
// docs/privilege-split.md). It runs as its own user, holds no capability, may start no program and
// reads no file of the daemon's state. It parses HTTP and MCP's JSON-RPC, checks the Origin, and
// hands every bearer token and every tool call to a backend: the helper over its socket in the
// daemon (helper.go), or a Server in the same process in the tests. It decides nothing about a
// grant, a second factor or a held change; the backend does, on every call.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// backend is what the listener asks: who a bearer token is, to run one call, and whether the last
// throttle write reached the disk. An error means the backend did not answer, not that it refused.
type backend interface {
	auth(token, remote string) (client string, ok bool, err error)
	call(ctx context.Context, token, tool string, input json.RawMessage) (text string, isError bool, err error)
	health() (persisted bool, err error)
}

type frontend struct {
	b backend

	mu      sync.Mutex
	servers map[[32]byte]*mcp.Server // by the digest of the bearer token that opened them
}

func newFrontend(b backend) *frontend {
	return &frontend{b: b, servers: map[[32]byte]*mcp.Server{}}
}

// bearer is the token of a request, bounded: anything longer than a token could be is no token.
func bearer(r *http.Request) string { return bearerOf(r.Header) }

func bearerOf(h http.Header) string {
	raw := strings.TrimSpace(strings.TrimPrefix(h.Get("Authorization"), "Bearer "))
	if len(raw) > maxTokenLen {
		return ""
	}
	return raw
}

func (f *frontend) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", f.authenticate(mcp.NewStreamableHTTPHandler(f.getServer, nil)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		persisted, err := f.b.health()
		if err != nil {
			// The listener without its helper can run nothing, so it is not healthy.
			http.Error(w, "openwrt-mcp "+version+": the helper is not answering", http.StatusServiceUnavailable)
			return
		}
		// Points at its own source. Under the AGPL this was a §13 obligation; under MIT
		// it is only good manners, but a service that will tell you what it is and where
		// it came from is worth keeping either way.
		fmt.Fprintf(w, "openwrt-mcp %s ok\nsource: %s\n", version, sourceURL)
		// The one thing `status`, a separate process, cannot read from a file: whether the daemon's
		// last throttle write reached the disk. Said only when it did not.
		if !persisted {
			fmt.Fprintln(w, "throttle_persisted: false")
		}
	})
	return mux
}

// authenticate enforces the bearer token on every request. There is deliberately no
// loopback auto-trust: any process on the router can reach 127.0.0.1, and an `ssh -R`
// can make remote traffic arrive there too, so reachability is never treated as proof
// of identity. Origin is recorded for audit attribution only.
func (f *frontend) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser defence: a page in a local browser must not be able to drive the router.
		if o := r.Header.Get("Origin"); o != "" && !isLoopbackOrigin(o) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		_, ok, err := f.b.auth(bearer(r), r.RemoteAddr)
		if err != nil {
			log.Printf("openwrt-mcp: the helper did not answer: %v", err)
			http.Error(w, "the helper is not answering", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="openwrt-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getServer gives a session the MCP server of its bearer token. Each call still carries the token of
// the request it arrived in, when the transport has one, and the backend resolves that token again.
func (f *frontend) getServer(r *http.Request) *mcp.Server {
	token := bearer(r)
	key := sha256.Sum256([]byte(token))
	f.mu.Lock()
	defer f.mu.Unlock()
	if srv, ok := f.servers[key]; ok {
		return srv
	}
	srv := buildMCPServer(func(ctx context.Context, req *mcp.CallToolRequest, tool string, input json.RawMessage) (string, bool) {
		tok := token
		if req != nil && req.Extra != nil && req.Extra.Header != nil {
			tok = bearerOf(req.Extra.Header)
		}
		text, isErr, err := f.b.call(ctx, tok, tool, input)
		if errors.Is(err, errOutcomeUnknown) {
			// The helper took the call and its answer was lost: it may have run. The helper's audit
			// log has the call's own line, and a line that its answer did not arrive.
			log.Printf("openwrt-mcp: %s: %v", tool, err)
			return "the result is unknown: the helper took the call and its answer did not arrive, so it may have " +
				"run; check the router's state before you call it again (" + err.Error() + ")", true
		}
		if err != nil {
			return "the helper did not answer, so nothing was run: " + err.Error(), true
		}
		return text, isErr
	})
	f.servers[key] = srv
	return srv
}

func isLoopbackOrigin(o string) bool {
	o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
	if h, _, err := net.SplitHostPort(o); err == nil {
		o = h
	}
	return o == "localhost" || net.ParseIP(o).IsLoopback()
}

// Serve listens on listen, which must be a loopback address, and answers until it fails.
func (f *frontend) Serve(listen string) error {
	// Refuse to bind anything but loopback. This is a deliberate hard stop rather than a
	// default: reaching the router is SSH's job, and a mis-edited config must not silently
	// expose a root-equivalent RPC surface to the LAN.
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("bad listen address %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; openwrt-mcp refuses to bind a routable address (reach it with: ssh -L %s:%s root@router)", listen, listen, listen)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("openwrt-mcp %s listening on %s", version, listen)
	srv := &http.Server{
		Handler:           f.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.Serve(ln)
}
