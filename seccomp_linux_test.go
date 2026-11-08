//go:build linux && (amd64 || arm64)

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBPFConstantsAreTheKernels(t *testing.T) {
	for name, p := range map[string][2]uint32{
		"ld": {bpfLD, unix.BPF_LD}, "w": {bpfW, unix.BPF_W}, "abs": {bpfABS, unix.BPF_ABS},
		"jmp": {bpfJMP, unix.BPF_JMP}, "jeq": {bpfJEQ, unix.BPF_JEQ}, "k": {bpfK, unix.BPF_K},
		"ret": {bpfRET, unix.BPF_RET}, "jge": {bpfJGE, unix.BPF_JGE}, "ja": {bpfJA, unix.BPF_JA}, "alu": {bpfALU, unix.BPF_ALU}, "and": {bpfAND, unix.BPF_AND},
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
	// "nr:<number>": one call by number, with every argument all ones, which every call on the list
	// refuses harmlessly if the filter lets it through (a bad pointer, a bad descriptor, a bad magic
	// number). The line before it says the child got past the filter's installation, so a child the
	// filter killed earlier, at its own start, is not counted as the call being stopped.
	if nr, ok := strings.CutPrefix(mode, "nr:"); ok {
		n, err := strconv.ParseUint(nr, 10, 32)
		if err != nil {
			println("bad number:", nr)
			return 7
		}
		os.Stderr.WriteString("reached " + nr + "\n")
		all := ^uintptr(0)
		syscall.RawSyscall6(uintptr(n), all, all, all, all, all, all)
		println("the call was not stopped")
		return 6
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
	out, err := seccompChildOutput(mode)
	if err != nil {
		t.Logf("%s: %v %s", mode, err, out)
	}
	return err
}

func seccompChildOutput(mode string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_SECCOMP_CHILD="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
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

// kernelHeaderNumbers reads this architecture's system call numbers from the kernel's own headers
// (linux-libc-dev): an account of the numbers that owes nothing to x/sys/unix or to deniedTable, so
// a name in the table that points at another call's number shows up against it.
func kernelHeaderNumbers() (map[string]uint32, string, error) {
	var candidates []string
	switch runtime.GOARCH {
	case "amd64":
		candidates = []string{"/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "/usr/include/asm/unistd_64.h"}
	case "arm64":
		// From Linux 6.11 arm64's numbers are generated into asm/unistd_64.h; before, asm/unistd.h
		// takes them from the generic table.
		candidates = []string{"/usr/include/aarch64-linux-gnu/asm/unistd_64.h", "/usr/include/asm/unistd_64.h",
			"/usr/include/asm-generic/unistd.h"}
	}
	def := regexp.MustCompile(`(?m)^#define __NR_([a-z0-9_]+)[ \t]+([0-9]+)[ \t]*$`)
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		nrs := map[string]uint32{}
		for _, m := range def.FindAllStringSubmatch(string(b), -1) {
			n, err := strconv.ParseUint(m[2], 10, 32)
			if err != nil {
				return nil, p, err
			}
			nrs[m[1]] = uint32(n)
		}
		if len(nrs) < 200 {
			return nil, p, fmt.Errorf("%s defines only %d system calls", p, len(nrs))
		}
		return nrs, p, nil
	}
	return nil, "", fmt.Errorf("no kernel header with the %s system call numbers in %v", runtime.GOARCH, candidates)
}

// Every call on the list, by the number this kernel's headers give its name, is ended by SIGSYS on
// this kernel. CI runs it natively on amd64 and on an arm64 runner (scripts/gate-seccomp-native.sh),
// so the table and the audit architecture of each are executed by a kernel of that architecture,
// not only compiled. OPENWRT_MCP_KERNEL_HEADERS=required makes a missing header a failure.
func TestEveryDeniedCallIsKilledByThisKernel(t *testing.T) {
	hdr, src, err := kernelHeaderNumbers()
	if err != nil {
		if os.Getenv("OPENWRT_MCP_KERNEL_HEADERS") == "required" {
			t.Fatalf("measured nothing: %v", err)
		}
		t.Skipf("measured nothing: %v", err)
	}
	names, err := DeniedNames()
	if err != nil {
		t.Fatal(err)
	}
	killed := 0
	for _, name := range names {
		want, ok := hdr[name]
		if !ok {
			t.Errorf("%s: %s does not define __NR_%s", name, src, name)
			continue
		}
		if got := deniedTable[name]; got != want {
			t.Errorf("%s: the %s table says %d, %s says %d", name, runtime.GOARCH, got, src, want)
		}
		out, err := seccompChildOutput(fmt.Sprintf("nr:%d", want))
		switch {
		case !strings.Contains(out, fmt.Sprintf("reached %d\n", want)):
			t.Errorf("%s (%d): the child did not get to the call: %v %s", name, want, err, out)
		case !killedBySIGSYS(err):
			t.Errorf("%s (%d): not ended by SIGSYS: %v %s", name, want, err, out)
		default:
			killed++
		}
	}
	t.Logf("%s, kernel numbers from %s: %d of %d calls on the list ended by SIGSYS", runtime.GOARCH, src, killed, len(names))
}

// The mask the daemon insists on is the file procd is given: a change to one without the other
// would make the daemon refuse to start, or accept a set nobody wrote down.
func TestExpectedCapabilityMaskIsTheCapabilityFile(t *testing.T) {
	b, err := os.ReadFile("files/etc/capabilities/openwrt-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var f map[string][]string
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	caps := map[string]uint{"CAP_CHOWN": unix.CAP_CHOWN, "CAP_DAC_OVERRIDE": unix.CAP_DAC_OVERRIDE,
		"CAP_FOWNER": unix.CAP_FOWNER, "CAP_FSETID": unix.CAP_FSETID, "CAP_KILL": unix.CAP_KILL,
		"CAP_SETGID": unix.CAP_SETGID, "CAP_SETUID": unix.CAP_SETUID, "CAP_NET_ADMIN": unix.CAP_NET_ADMIN,
		"CAP_NET_RAW": unix.CAP_NET_RAW}
	for _, set := range []string{"bounding", "effective", "permitted"} {
		var mask uint64
		for _, n := range f[set] {
			bit, ok := caps[n]
			if !ok {
				t.Fatalf("%s names %s, which the test does not know", set, n)
			}
			mask |= 1 << bit
		}
		if mask != expectedCaps {
			t.Errorf("%s of the file is %#x, the daemon insists on %#x", set, mask, expectedCaps)
		}
	}
}
