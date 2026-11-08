package main

// The seccomp filter, as a program. This file builds it on any system, so it is tested everywhere;
// installing it is seccomp_linux.go, and only on the architectures a real run of the daemon stands
// behind (amd64 and arm64).
//
// The mechanism is the one in TAIPANBOX/openwrt-llm-gateway internal/sandbox and in rollcall:
// classic BPF, installed on every thread with no_new_privs, checked afterwards in
// /proc/self/status. The difference is the direction. Those two daemons never start a program, so
// they allow a short list and kill the rest. This one starts uci, ubus, apk and the programs a
// grant names, and the filter is inherited by every one of them, so it kills a short list and
// allows the rest (see seccomp/denied.txt).
//
// The program:
//   - a call made with another audit architecture is killed (SECCOMP_RET_KILL_PROCESS), so the
//     32-bit entry of an x86_64 kernel is no way round the list;
//   - clone3 answers ENOSYS: its flags are in memory the filter cannot read, and libc, Go and
//     busybox all fall back to clone, whose flags it can read;
//   - clone with any namespace flag is killed: a new user namespace needs no capability and would
//     give the process back, inside it, the capabilities the jail dropped;
//   - every listed number is killed; every other call is allowed.

import (
	"embed"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"unicode"
)

//go:embed seccomp/denied.txt
var deniedFS embed.FS

// Classic BPF and seccomp values (linux/bpf_common.h, linux/filter.h, linux/seccomp.h), spelled
// out so the program builds on any system; seccomp_linux_test.go checks them against x/sys/unix.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJA  = 0x00
	bpfALU = 0x04
	bpfAND = 0x50
	bpfK   = 0x00
	bpfRET = 0x06

	retKillProcess = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retAllow       = 0x7fff0000 // SECCOMP_RET_ALLOW
	retErrnoBase   = 0x00050000 // SECCOMP_RET_ERRNO
	enosys         = 38

	offNr   = 0  // offsetof(struct seccomp_data, nr)
	offArch = 4  // offsetof(struct seccomp_data, arch)
	offArg0 = 16 // offsetof(struct seccomp_data, args[0]): the low word, on a little-endian kernel

	// cloneNamespaceFlags is CLONE_NEWTIME | NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER |
	// NEWPID | NEWNET, all in the low 32 bits of clone's flags.
	cloneNamespaceFlags = 0x00000080 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000

	maxDenied = 200
)

// Insn is one classic BPF instruction (struct sock_filter).
type Insn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// errNoSeccomp says there is no filter to install here; serve goes on without one.
var errNoSeccomp = errors.New("no seccomp filter for this platform")

// confine installs the filter first thing in serve. Where there is none to install it says so and
// serve goes on; where it fails, serve does not start: a daemon that cannot show its filter does
// not listen.
func confine() {
	n, err := confineSeccomp()
	switch {
	case errors.Is(err, errNoSeccomp):
		log.Printf("openwrt-mcp: no seccomp filter on this platform")
	case err != nil:
		log.Fatalf("openwrt-mcp: seccomp: %v", err)
	default:
		log.Printf("openwrt-mcp: seccomp filter on: %d system calls denied, clone3 refused, namespace clones killed", n)
	}
}

// DeniedNames reads seccomp/denied.txt: blank lines and lines starting with # drop out, trailing
// white space goes, every other line must be one name of [a-z0-9_]. Sorted, once each.
func DeniedNames() ([]string, error) {
	data, err := deniedFS.ReadFile("seccomp/denied.txt")
	if err != nil {
		return nil, err
	}
	var names []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRightFunc(line, unicode.IsSpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, r := range line {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return nil, fmt.Errorf("seccomp/denied.txt:%d: %q is not a system call name", i+1, line)
			}
		}
		names = append(names, line)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// numbersOf maps names to one architecture's numbers. A name the table lacks is an error: the list
// would protect nothing with it.
func numbersOf(names []string, table map[string]uint32) ([]uint32, error) {
	var unknown []string
	var nrs []uint32
	for _, n := range names {
		nr, ok := table[n]
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		nrs = append(nrs, nr)
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return nil, fmt.Errorf("not system calls of this architecture: %s", strings.Join(unknown, ", "))
	}
	slices.Sort(nrs)
	return slices.Compact(nrs), nil
}

// buildFilter returns the program for one architecture: audit arch, the numbers of clone and
// clone3, and the denied numbers.
func buildFilter(arch, nrClone, nrClone3 uint32, denied []uint32) ([]Insn, error) {
	switch {
	case len(denied) == 0:
		return nil, errors.New("filter: nothing is denied")
	case len(denied) > maxDenied:
		return nil, fmt.Errorf("filter: %d system calls; at most %d", len(denied), maxDenied)
	}
	for _, nr := range denied {
		if nr == nrClone || nr == nrClone3 {
			return nil, errors.New("filter: clone and clone3 have their own rules and are not listed")
		}
	}
	// Layout: 4 header instructions, 2 + len(denied) tests, one jump to the allow, then the tails,
	// every jump forward: the clone check (3), ret ERRNO, ret KILL, ret ALLOW. The jump matters: a
	// call no test matched must not fall into the clone check, which reads the first argument as
	// flags (openat's is a directory descriptor).
	tests := 2 + len(denied)
	cloneChk := 4 + tests + 1
	errno := cloneChk + 3
	kill := errno + 1
	allow := kill + 1
	jump := func(from, to int) uint8 { return uint8(to - from - 1) }
	prog := []Insn{
		{Code: bpfLD | bpfW | bpfABS, K: offArch},
		{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: arch},
		{Code: bpfRET | bpfK, K: retKillProcess},
		{Code: bpfLD | bpfW | bpfABS, K: offNr},
	}
	prog = append(prog, Insn{Code: bpfJMP | bpfJEQ | bpfK, Jt: jump(len(prog), errno), K: nrClone3})
	prog = append(prog, Insn{Code: bpfJMP | bpfJEQ | bpfK, Jt: jump(len(prog), cloneChk), K: nrClone})
	for _, nr := range denied {
		prog = append(prog, Insn{Code: bpfJMP | bpfJEQ | bpfK, Jt: jump(len(prog), kill), K: nr})
	}
	// Every test fell through: the call is not on the list.
	prog = append(prog, Insn{Code: bpfJMP | bpfJA, K: uint32(allow - len(prog) - 1)})
	if len(prog) != cloneChk {
		return nil, fmt.Errorf("filter: layout error, clone check at %d, built %d", cloneChk, len(prog))
	}
	prog = append(prog,
		Insn{Code: bpfLD | bpfW | bpfABS, K: offArg0},
		Insn{Code: bpfALU | bpfAND | bpfK, K: cloneNamespaceFlags},
		Insn{Code: bpfJMP | bpfJEQ | bpfK, Jt: jump(cloneChk+2, allow), Jf: jump(cloneChk+2, kill), K: 0},
		Insn{Code: bpfRET | bpfK, K: retErrnoBase | enosys},
		Insn{Code: bpfRET | bpfK, K: retKillProcess},
		Insn{Code: bpfRET | bpfK, K: retAllow},
	)
	if len(prog)-1 != allow {
		return nil, fmt.Errorf("filter: layout error, allow at %d, built %d", allow, len(prog)-1)
	}
	return prog, nil
}

// checkSeccompStatus reads the text of /proc/self/status and requires what the kernel must show
// once the filter is on: no_new_privs set and seccomp in filter mode.
func checkSeccompStatus(status []byte) error {
	var nnp, mode string
	for _, line := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "NoNewPrivs":
			nnp = strings.TrimSpace(v)
		case "Seccomp":
			mode = strings.TrimSpace(v)
		}
	}
	if nnp != "1" || mode != "2" {
		return fmt.Errorf("the kernel shows NoNewPrivs=%q Seccomp=%q, not 1 and 2: the filter is not in force", nnp, mode)
	}
	return nil
}
