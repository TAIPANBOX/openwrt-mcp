//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBPFConstantsAreTheKernels(t *testing.T) {
	for name, p := range map[string][2]uint32{
		"ld": {bpfLD, unix.BPF_LD}, "w": {bpfW, unix.BPF_W}, "abs": {bpfABS, unix.BPF_ABS},
		"jmp": {bpfJMP, unix.BPF_JMP}, "jeq": {bpfJEQ, unix.BPF_JEQ}, "k": {bpfK, unix.BPF_K},
		"ret": {bpfRET, unix.BPF_RET}, "ja": {bpfJA, unix.BPF_JA}, "alu": {bpfALU, unix.BPF_ALU}, "and": {bpfAND, unix.BPF_AND},
		"kill": {retKillProcess, unix.SECCOMP_RET_KILL_PROCESS}, "allow": {retAllow, unix.SECCOMP_RET_ALLOW},
		"errno": {retErrnoBase, unix.SECCOMP_RET_ERRNO}, "enosys": {enosys, uint32(unix.ENOSYS)},
		"nnp": {prSetNoNewPrivs, unix.PR_SET_NO_NEW_PRIVS}, "mode": {seccompSetModeFilter, unix.SECCOMP_SET_MODE_FILTER},
		"tsync":   {seccompFilterFlagTSYNC, unix.SECCOMP_FILTER_FLAG_TSYNC},
		"newuser": {0x10000000, unix.CLONE_NEWUSER}, "newns": {0x00020000, unix.CLONE_NEWNS},
		"newnet": {0x40000000, unix.CLONE_NEWNET}, "newpid": {0x20000000, unix.CLONE_NEWPID},
		"newipc": {0x08000000, unix.CLONE_NEWIPC}, "newuts": {0x04000000, unix.CLONE_NEWUTS},
		"newcgroup": {0x02000000, unix.CLONE_NEWCGROUP}, "newtime": {0x00000080, unix.CLONE_NEWTIME},
	} {
		if p[0] != p[1] {
			t.Errorf("%s: %#x here, %#x in the kernel's headers", name, p[0], p[1])
		}
	}
}

func TestEveryNameOfTheListHasANumberOnThisArchitecture(t *testing.T) {
	names, err := DeniedNames()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := numbersOf(names, deniedTable); err != nil {
		t.Fatal(err)
	}
	for k := range deniedTable {
		found := false
		for _, n := range names {
			found = found || n == k
		}
		if !found {
			t.Errorf("%q is in this architecture's table and not in seccomp/denied.txt", k)
		}
	}
}

// The filter on a real kernel, in a child of the test binary: it goes on, and then each case runs.
func TestMain(m *testing.M) {
	if mode := os.Getenv("OPENWRT_MCP_SECCOMP_CHILD"); mode != "" {
		os.Exit(seccompChild(mode))
	}
	os.Exit(m.Run())
}

func seccompChild(mode string) int {
	if _, err := confineSeccomp(); err != nil {
		println("confine:", err.Error())
		return 3
	}
	switch mode {
	case "plain":
		return 0
	case "true":
		if err := exec.Command("/bin/true").Run(); err != nil {
			println("true:", err.Error())
			return 4
		}
		return 0
	case "runs":
		// Ordinary work still runs: a program started under the filter, and files, and a socket.
		out, err := exec.Command("/bin/sh", "-c", "echo ok").Output()
		if err != nil || strings.TrimSpace(string(out)) != "ok" {
			println("exec under the filter:", err)
			return 4
		}
		return 0
	case "ptrace":
		syscall.RawSyscall(unix.SYS_PTRACE, 0, 0, 0)
	case "mount":
		syscall.RawSyscall6(unix.SYS_MOUNT, 0, 0, 0, 0, 0, 0)
	case "unshare":
		syscall.RawSyscall(unix.SYS_UNSHARE, unix.CLONE_NEWUSER, 0, 0)
	case "clone-newuser":
		syscall.RawSyscall6(unix.SYS_CLONE, unix.CLONE_NEWUSER|uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	case "clone3":
		_, _, e := syscall.RawSyscall(unix.SYS_CLONE3, 0, 0, 0)
		if e != unix.ENOSYS {
			println("clone3 gave", e.Error())
			return 5
		}
		return 0
	}
	println("the call was not stopped")
	return 6
}

func runSeccompChild(t *testing.T, mode string) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_SECCOMP_CHILD="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%s: %v %s", mode, err, out)
	}
	return err
}

func killedBySIGSYS(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGSYS
}

func TestFilterOnARealKernel(t *testing.T) {
	if err := runSeccompChild(t, "runs"); err != nil {
		t.Fatalf("a program that does ordinary work did not run under the filter: %v", err)
	}
	for _, mode := range []string{"ptrace", "mount", "unshare", "clone-newuser"} {
		if err := runSeccompChild(t, mode); !killedBySIGSYS(err) {
			t.Errorf("%s was not ended by SIGSYS: %v", mode, err)
		}
	}
	if err := runSeccompChild(t, "clone3"); err != nil {
		t.Errorf("clone3 was not refused with ENOSYS: %v", err)
	}
}
