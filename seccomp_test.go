package main

import (
	"slices"
	"testing"
)

// run is a classic BPF interpreter for the four instruction forms the filter uses. It returns the
// action the program gives a call.
func runFilter(t *testing.T, prog []Insn, arch, nr, arg0 uint32) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			switch in.K {
			case offArch:
				a = arch
			case offNr:
				a = nr
			case offArg0:
				a = arg0
			default:
				t.Fatalf("pc %d: load of offset %d", pc, in.K)
			}
		case bpfALU | bpfAND | bpfK:
			a &= in.K
		case bpfJMP | bpfJA:
			pc += int(in.K)
		case bpfJMP | bpfJEQ | bpfK:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			t.Fatalf("pc %d: instruction %#x", pc, in.Code)
		}
	}
	t.Fatal("the program ran off its end")
	return 0
}

const (
	tArch   = 0xc000003e
	tClone  = 56
	tClone3 = 435
)

var tDenied = []uint32{101, 165, 175, 313} // ptrace, mount, init_module, finit_module on amd64

func TestFilterDeniesEveryListedCallAndAllowsTheRest(t *testing.T) {
	prog, err := buildFilter(tArch, tClone, tClone3, tDenied)
	if err != nil {
		t.Fatal(err)
	}
	for _, nr := range tDenied {
		if got := runFilter(t, prog, tArch, nr, 0); got != retKillProcess {
			t.Errorf("call %d: %#x, want kill", nr, got)
		}
	}
	for _, nr := range []uint32{0, 1, 2, 3, 41, 42, 59, 257, 231, 202} { // read write open close socket connect execve openat exit_group futex
		// The first argument is the one the clone rule reads: openat's is a directory descriptor,
		// AT_FDCWD (-100), whose bits overlap the namespace flags. It must still be allowed.
		for _, arg0 := range []uint32{0, 0xffffff9c, 0xffffffff} {
			if got := runFilter(t, prog, tArch, nr, arg0); got != retAllow {
				t.Errorf("call %d (first argument %#x): %#x, want allow", nr, arg0, got)
			}
		}
	}
}

func TestFilterKillsAnotherArchitecturesCalls(t *testing.T) {
	prog, _ := buildFilter(tArch, tClone, tClone3, tDenied)
	// 0xc000003e is x86_64; 0x40000003 is i386. Call 1 is write on the first and exit on the second.
	if got := runFilter(t, prog, 0x40000003, 1, 0); got != retKillProcess {
		t.Errorf("a 32-bit call: %#x, want kill", got)
	}
	// The x32 bit on an allowed number is a different number, and no test of the program matches it
	// as a deny: the arch word is what stops it, and it is the same word. Documented, not claimed.
}

func TestFilterRefusesClone3AndNamespaceClones(t *testing.T) {
	prog, _ := buildFilter(tArch, tClone, tClone3, tDenied)
	if got := runFilter(t, prog, tArch, tClone3, 0); got != retErrnoBase|enosys {
		t.Errorf("clone3: %#x, want ENOSYS", got)
	}
	const (
		sigchld    = 17
		threadFlag = 0x003d0f00 // what the Go runtime and libc pass for a thread
		newUser    = 0x10000000
		newNS      = 0x00020000
		newNet     = 0x40000000
		newPID     = 0x20000000
		newIPC     = 0x08000000
		newUTS     = 0x04000000
		newCgroup  = 0x02000000
		newTime    = 0x00000080
	)
	for _, ok := range []uint32{sigchld, threadFlag, 0x01200011} { // fork, thread, vfork-like
		if got := runFilter(t, prog, tArch, tClone, ok); got != retAllow {
			t.Errorf("clone flags %#x: %#x, want allow", ok, got)
		}
	}
	for name, f := range map[string]uint32{"user": newUser, "mount": newNS, "net": newNet, "pid": newPID,
		"ipc": newIPC, "uts": newUTS, "cgroup": newCgroup, "time": newTime} {
		if got := runFilter(t, prog, tArch, tClone, sigchld|f); got != retKillProcess {
			t.Errorf("clone into a new %s namespace: %#x, want kill", name, got)
		}
		if got := runFilter(t, prog, tArch, tClone, threadFlag|f); got != retKillProcess {
			t.Errorf("thread clone into a new %s namespace: %#x, want kill", name, got)
		}
	}
}

func TestFilterRefusesAListThatNamesCloneOrIsEmpty(t *testing.T) {
	if _, err := buildFilter(tArch, tClone, tClone3, nil); err == nil {
		t.Error("an empty list built a filter")
	}
	if _, err := buildFilter(tArch, tClone, tClone3, []uint32{101, tClone}); err == nil {
		t.Error("a list naming clone built a filter: its rule would be shadowed")
	}
	if _, err := buildFilter(tArch, tClone, tClone3, make([]uint32, maxDenied+1)); err == nil {
		t.Error("a list over the bound built a filter")
	}
}

func TestDeniedListIsWellFormedAndKeepsTheDaemonsOwnCallsOut(t *testing.T) {
	names, err := DeniedNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 30 {
		t.Fatalf("only %d names: the list was cut", len(names))
	}
	// A call a program needs to run at all, and every call the daemon and apk's scripts make: the
	// deny-list must never reach them, whatever else changes.
	for _, never := range []string{"execve", "execveat", "clone", "clone3", "fork", "vfork", "read", "write", "openat",
		"socket", "connect", "bind", "listen", "accept4", "futex", "mmap", "chown", "fchownat", "chmod", "rename",
		"renameat", "renameat2", "fsync", "kill", "setuid", "setgid", "setgroups", "chroot", "ioctl", "prctl",
		"sendto", "recvfrom", "epoll_wait", "epoll_pwait", "flock", "fcntl", "symlinkat", "linkat", "unlinkat",
		"utimensat", "mkdirat", "mknodat", "capget", "capset", "wait4", "pipe2", "dup3", "getrandom", "nanosleep"} {
		if slices.Contains(names, never) {
			t.Errorf("%q is on the deny list", never)
		}
	}
	for _, must := range []string{"ptrace", "mount", "unshare", "setns", "init_module", "finit_module", "bpf", "reboot", "kexec_load"} {
		if !slices.Contains(names, must) {
			t.Errorf("%q is not on the deny list", must)
		}
	}
}

func TestSeccompStatusMustShowTheFilterInForce(t *testing.T) {
	for name, tc := range map[string]struct {
		status string
		ok     bool
	}{
		"in force":       {"Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n", true},
		"no filter":      {"NoNewPrivs:\t1\nSeccomp:\t0\n", false},
		"strict mode":    {"NoNewPrivs:\t1\nSeccomp:\t1\n", false},
		"no new privs":   {"NoNewPrivs:\t0\nSeccomp:\t2\n", false},
		"neither shown":  {"Name:\tx\n", false},
		"unreadable":     {"", false},
		"fields reorder": {"Seccomp:\t2\nNoNewPrivs:\t1\n", true},
	} {
		if err := checkSeccompStatus([]byte(tc.status)); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, tc.ok)
		}
	}
}
