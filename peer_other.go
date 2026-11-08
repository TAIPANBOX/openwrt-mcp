//go:build !linux

package main

import (
	"errors"
	"net"
)

// peerUID has no kernel answer here, so the helper serves no one: it runs on Linux only.
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("the peer's uid cannot be read on this system")
}
