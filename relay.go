package main

// The listener's pipe to Telegram (docs/approval-path.md, A2). The helper holds the router's own bot
// and opens no IP socket (CLAUDE.md, invariant 12), so its TLS to api.telegram.org runs over this
// pipe: the listener serves one more Unix socket, and for each connection to it from root (the
// helper) it dials api.telegram.org:443 and copies bytes both ways. It takes no request, so there is
// no host or port to name, and it has no key for what it copies: the TLS is the helper's.

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxRelayConns = 4
	relayIdle     = 2 * time.Minute // a long poll waits 25 s; a pipe silent this long is dead
	relayDialWait = 15 * time.Second
)

type telegramRelay struct {
	// allowUID is the uid served: root, the helper. In the tests, the caller's own.
	allowUID int
	peer     func(*net.UnixConn) (int, error)
	// dial reaches api.telegram.org:443. A variable only so a test can stand a server in for it.
	dial  func(ctx context.Context) (net.Conn, error)
	slots chan struct{}
	idle  time.Duration
}

func newTelegramRelay(allowUID int) *telegramRelay {
	return &telegramRelay{allowUID: allowUID, peer: peerUID, dial: dialTelegram,
		slots: make(chan struct{}, maxRelayConns), idle: relayIdle}
}

// dialTelegram is the one place the listener dials for the pipe, and it names one address.
func dialTelegram(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: relayDialWait}
	return d.DialContext(ctx, "tcp", telegramAddr)
}

// listenRelay makes the pipe's socket in a directory the init script made for the listener's
// account (0700). The socket is the listener's own, 0600: root reaches it, and no other account.
func listenRelay(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (r *telegramRelay) serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

// handle copies one connection. A peer that is not root gets nothing, and no connection is made.
func (r *telegramRelay) handle(c *net.UnixConn) {
	defer c.Close()
	uid, err := r.peer(c)
	if err != nil || uid != r.allowUID {
		log.Printf("openwrt-mcp: telegram pipe: refused a connection from uid %d (%v): only uid %d, the helper, is served", uid, err, r.allowUID)
		return
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		log.Printf("openwrt-mcp: telegram pipe: %d connections already, refused one more", maxRelayConns)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayDialWait)
	up, err := r.dial(ctx)
	cancel()
	if err != nil {
		log.Printf("openwrt-mcp: telegram pipe: %s: %v", telegramAddr, err)
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.copy(up, c) }()
	go func() { defer wg.Done(); r.copy(c, up) }()
	wg.Wait()
}

// copy moves bytes from src to dst until either side ends or nothing passes for r.idle, then ends
// both, so the other direction does not linger.
func (r *telegramRelay) copy(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	buf := make([]byte, 16<<10)
	for {
		_ = src.SetReadDeadline(time.Now().Add(r.idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(r.idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// startRelay serves the pipe for the router's own bot, as the listener. A pipe that cannot be made is
// said in the log, and the listener serves MCP all the same: the bot then cannot reach Telegram, its
// status says so, and a held change waits for nobody until it expires.
func startRelay(path string) {
	ln, err := listenRelay(path)
	if err != nil {
		log.Printf("openwrt-mcp: the router's bot has no way to Telegram: the pipe %s: %v", path, err)
		return
	}
	log.Printf("openwrt-mcp: the pipe to %s for the router's bot on %s, serving uid 0 only", telegramAddr, path)
	go func() {
		if err := newTelegramRelay(0).serve(ln); err != nil {
			log.Printf("openwrt-mcp: the pipe for the router's bot stopped: %v", err)
		}
	}()
}
