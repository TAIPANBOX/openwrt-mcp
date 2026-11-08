//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kernel's values, from linux/prctl.h and linux/seccomp.h.
const (
	prSetNoNewPrivs        = 38
	seccompSetModeFilter   = 1
	seccompFilterFlagTSYNC = 1
	bpfMaxInsns            = 4096
)

// sockFprog is struct sock_fprog; Insn has the layout of struct sock_filter.
type sockFprog struct {
	Len    uint16
	Filter *Insn
}

// confineSeccomp installs the filter of this architecture on every thread of the process and
// returns how many system calls it denies. A filter, once installed, stays for the life of the
// process and of every program it starts. procd cannot do this for the daemon: it applies a profile
// through LD_PRELOAD=/lib/libpreload-seccomp.so, which a statically linked binary never loads (the
// two sibling daemons measured Seccomp 0 under it), and which would hand the profile to every
// dynamic program it starts as well.
func confineSeccomp() (int, error) {
	names, err := DeniedNames()
	if err != nil {
		return 0, err
	}
	denied, err := numbersOf(names, deniedTable)
	if err != nil {
		return 0, err
	}
	prog, err := buildFilter(auditArch, unix.SYS_CLONE, unix.SYS_CLONE3, denied)
	if err != nil {
		return 0, err
	}
	if err := installFilter(prog); err != nil {
		return 0, err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("the filter went on but /proc/self/status cannot show it: %w", err)
	}
	if err := checkSeccompStatus(status); err != nil {
		return 0, err
	}
	return len(denied), nil
}

// installFilter sets no_new_privs and installs prog with SECCOMP_FILTER_FLAG_TSYNC, so the kernel
// puts the filter on every thread at once: the Go runtime runs several threads before main starts.
func installFilter(prog []Insn) error {
	if len(prog) == 0 || len(prog) > bpfMaxInsns {
		return fmt.Errorf("seccomp: a program of %d instructions", len(prog))
	}
	fprog := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// no_new_privs is per thread and the kernel checks it on the thread that installs the filter.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}
	r, _, errno := syscall.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter,
		seccompFilterFlagTSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	switch {
	case errno != 0:
		return fmt.Errorf("seccomp: %w", errno)
	case r != 0:
		return fmt.Errorf("seccomp: thread %d could not be given the filter, so it would run unfiltered", r)
	}
	return nil
}
