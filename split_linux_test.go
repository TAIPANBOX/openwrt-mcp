//go:build linux && (amd64 || arm64)

package main

// The listener's filter on a real kernel, in a child of the test binary. The child is chosen by its
// own environment variable and runs from init, before TestMain, so this file needs nothing from
// seccomp_linux_test.go.

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func init() {
	mode := os.Getenv("OPENWRT_MCP_SPLIT_CHILD")
	if mode == "" {
		return
	}
	if _, err := confineSeccompServe(); err != nil {
		println("confine:", err.Error())
		os.Exit(3)
	}
	switch mode {
	case "serve-runs":
		// What the listener does all day: files, sockets, threads.
		if _, err := os.ReadFile("/proc/self/status"); err != nil {
			os.Exit(4)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(4)
		}
		l.Close()
		os.Exit(0)
	case "serve-exec":
		// Through os/exec: the new process dies of SIGSYS at its execve, and no program runs.
		err := exec.Command("/bin/true").Run()
		if !killedBySIGSYS(err) {
			println("the program was started:", errString(err))
			os.Exit(6)
		}
		os.Exit(0)
	case "serve-execve":
		// The listener's own execve: the listener itself is ended.
		os.Stderr.WriteString("reached execve\n")
		syscall.Exec("/bin/true", []string{"true"}, nil)
		println("execve returned")
		os.Exit(6)
	}
	os.Exit(7)
}

func splitChild(mode string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_SPLIT_CHILD="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The listener's filter kills execve: the part that parses what the network sends starts no program,
// not ubus, not uci, not a shell. Its ordinary work still runs under it.
func TestTheListenersFilterStartsNoProgram(t *testing.T) {
	if out, err := splitChild("serve-runs"); err != nil {
		t.Fatalf("the listener's ordinary work did not run under its filter: %v %s", err, out)
	}
	if out, err := splitChild("serve-exec"); err != nil {
		t.Errorf("a program started under the listener's filter was not ended by SIGSYS: %v %s", err, out)
	}
	out, err := splitChild("serve-execve")
	if !strings.Contains(out, "reached execve") || !killedBySIGSYS(err) {
		t.Errorf("the listener's own execve was not ended by SIGSYS: %v %s", err, out)
	}
}

func errString(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}
