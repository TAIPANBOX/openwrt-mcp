//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID is the uid of the process at the other end of a Unix socket, from the kernel
// (SO_PEERCRED): what it was when it connected, not anything it says.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			gerr = err
			return
		}
		uid = int(cred.Uid)
	}); err != nil {
		return -1, err
	}
	return uid, gerr
}
