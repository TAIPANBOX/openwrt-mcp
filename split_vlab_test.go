package main

// The split on a real OpenWrt router: what the listener is, what it holds, and what it cannot do.
// It runs inside TestJailVlab (jail_vlab_test.go), on the router, as root, against the daemon procd
// started (scripts/e2e-vlab.sh). The probes run in a child of the test binary that takes the
// listener's own identity: the account, an empty bounding set, no_new_privs and the listener's filter,
// and the child shows its /proc/self/status beside the listener's, so the stand-in is checked equal.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// procFields are the lines of /proc/PID/status the report shows for each part.
var procFields = []string{"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"}

func procStatus(pid string) map[string]string {
	b, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			m[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	return m
}

// daemonParts finds the two processes by their command line.
func daemonParts(t *testing.T) (helper, serve string) {
	t.Helper()
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(args) < 2 || args[0] != "/usr/bin/openwrt-mcp" {
			continue
		}
		switch args[len(args)-1] {
		case "helper":
			helper = e.Name()
		case "serve":
			serve = e.Name()
		}
	}
	if helper == "" || serve == "" {
		t.Fatalf("the two parts are not both running: helper %q, serve %q", helper, serve)
	}
	return helper, serve
}

func accountIDs(t *testing.T) (int, int) {
	t.Helper()
	u, err := user.Lookup(serveUser)
	if err != nil {
		t.Fatalf("no account %s: %v", serveUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
}

func showProc(name, pid string, st map[string]string) {
	var b strings.Builder
	for _, k := range procFields {
		fmt.Fprintf(&b, " %s=%q", k, st[k])
	}
	fmt.Printf("VALUES %-7s pid %s:%s\n", name, pid, b.String())
}

// socketInodes are the inodes of the sockets a process holds open.
func socketInodes(pid string) map[string]bool {
	out := map[string]bool{}
	ents, _ := os.ReadDir("/proc/" + pid + "/fd")
	for _, e := range ents {
		l, err := os.Readlink("/proc/" + pid + "/fd/" + e.Name())
		if err == nil && strings.HasPrefix(l, "socket:[") {
			out[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	return out
}

// inetInodes maps the inode of every IP socket on the router to its line of /proc/net/{tcp,udp}{,6}.
func inetInodes() map[string]string {
	out := map[string]string{}
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
		b, _ := os.ReadFile("/proc/net/" + f)
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 {
				continue
			}
			out[fs[9]] = f + " " + fs[1] + " st " + fs[3]
		}
	}
	return out
}

// boundaryChild is the probe: run as root from the test, it takes the listener's identity, then tries
// what the listener must not be able to do, one PROBE line each. "base" leaves out the listener's
// execve rule, so the ubus ACL can be shown on its own.
func init() {
	mode := os.Getenv("OPENWRT_MCP_BOUNDARY_CHILD")
	if mode == "" {
		return
	}
	uid, _ := strconv.Atoi(os.Getenv("OPENWRT_MCP_BOUNDARY_UID"))
	gid, _ := strconv.Atoi(os.Getenv("OPENWRT_MCP_BOUNDARY_GID"))
	for c := 0; c <= 63; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			fmt.Println("SETUP capbset", c, err)
			os.Exit(3)
		}
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		fmt.Println("SETUP setgroups", err)
		os.Exit(3)
	}
	if err := syscall.Setgid(gid); err != nil {
		fmt.Println("SETUP setgid", err)
		os.Exit(3)
	}
	if err := syscall.Setuid(uid); err != nil {
		fmt.Println("SETUP setuid", err)
		os.Exit(3)
	}
	var err error
	if mode == "base" {
		_, err = confineSeccomp()
	} else {
		_, err = confineSeccompServe()
	}
	if err != nil {
		fmt.Println("SETUP seccomp", err)
		os.Exit(3)
	}
	st := procStatus("self")
	b, _ := json.Marshal(st)
	fmt.Printf("STATUS %s\n", b)
	probe := func(name string, f func() (string, error)) {
		out, err := f()
		e := "nil"
		if err != nil {
			e = err.Error()
		}
		fmt.Printf("PROBE %s | err=%s | %.160q\n", name, e, out)
	}
	run := func(argv ...string) func() (string, error) {
		return func() (string, error) {
			o, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
			return string(o), err
		}
	}
	write := func(path string, flags int) func() (string, error) {
		return func() (string, error) {
			f, err := os.OpenFile(path, flags, 0o644)
			if err == nil {
				f.Close()
			}
			return "", err
		}
	}
	read := func(path string) func() (string, error) {
		return func() (string, error) {
			b, err := os.ReadFile(path)
			return fmt.Sprintf("%d bytes", len(b)), err
		}
	}
	ask := func(frame string) func() (string, error) {
		return func() (string, error) {
			c, err := net.Dial("unix", defaultHelperSocket)
			if err != nil {
				return "", err
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(frame)))
			c.Write(append(n[:], frame...))
			rb, err := readFrame(c, maxResponseFrame)
			return string(rb), err
		}
	}
	switch mode {
	case "serve":
		probe("exec-ubus-service-set", run("/bin/ubus", "call", "service", "set", `{"name":"mcpprobe","instances":{"i":{"command":["/bin/touch","/tmp/mcpprobe-ran"]}}}`))
		probe("write-etc-config-new", write("/etc/config/mcpprobe", os.O_CREATE|os.O_WRONLY))
		probe("write-etc-config-system", write("/etc/config/system", os.O_WRONLY|os.O_APPEND))
		probe("write-init-script", write("/etc/init.d/openwrt-mcp", os.O_WRONLY|os.O_APPEND))
		probe("write-state-dir", write("/etc/openwrt-mcp/mcpprobe", os.O_CREATE|os.O_WRONLY))
		probe("read-shadow", read("/etc/shadow"))
		probe("read-tokens", read("/etc/openwrt-mcp/tokens"))
		probe("read-mfa", read("/etc/openwrt-mcp/mfa"))
		probe("read-pin", read("/etc/openwrt-mcp/pin"))
		probe("read-network-config", read("/etc/config/network"))
		probe("helper-op-off-the-list", ask(`{"v":1,"op":"exec","tool":"sh","input":{"argv":["id"]}}`))
		probe("helper-tool-off-the-list", ask(`{"v":1,"op":"call","token":"x","tool":"service_set","input":{"name":"mcpprobe"}}`))
		probe("helper-run-a-string", ask(`{"v":1,"op":"call","token":"x","tool":"exec","input":{"argv":["id"]},"cmd":"id"}`))
		probe("helper-exec-without-a-token", ask(`{"v":1,"op":"call","token":"","tool":"exec","input":{"argv":["id"]}}`))
		probe("helper-names-a-client", ask(`{"v":1,"op":"call","client":"admin","tool":"exec","input":{"argv":["id"]}}`))
	case "base":
		probe("ubus-call-service-set", run("/bin/ubus", "call", "service", "set", `{"name":"mcpprobe","instances":{"i":{"command":["/bin/touch","/tmp/mcpprobe-ran"]}}}`))
		probe("ubus-call-system-board", run("/bin/ubus", "call", "system", "board"))
		probe("ubus-call-file-exec", run("/bin/ubus", "call", "file", "exec", `{"command":"/bin/touch","params":["/tmp/mcpprobe-ran"]}`))
		probe("ubus-call-uci-set", run("/bin/ubus", "call", "uci", "set", `{"config":"system","section":"@system[0]","values":{"hostname":"probe"}}`))
	case "other":
		probe("other-account-connects", ask(`{"v":1,"op":"health"}`))
	}
	os.Exit(0)
}

func boundaryProbes(t *testing.T, mode string, uid, gid int) (map[string]string, map[string]string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_BOUNDARY_CHILD="+mode,
		"OPENWRT_MCP_BOUNDARY_UID="+strconv.Itoa(uid), "OPENWRT_MCP_BOUNDARY_GID="+strconv.Itoa(gid))
	out, _ := cmd.CombinedOutput()
	probes := map[string]string{}
	var st map[string]string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "STATUS ") {
			json.Unmarshal([]byte(strings.TrimPrefix(line, "STATUS ")), &st)
		}
		if strings.HasPrefix(line, "PROBE ") {
			fmt.Println(line)
			name, rest, _ := strings.Cut(strings.TrimPrefix(line, "PROBE "), " | ")
			probes[name] = rest
		}
	}
	if len(probes) == 0 {
		t.Fatalf("the %s probe ran nothing:\n%s", mode, out)
	}
	return probes, st
}

// splitVlab is the part of TestJailVlab about the split.
func splitVlab(t *testing.T, r *jailRig) {

	t.Run("the_two_parts_and_what_the_kernel_shows", func(t *testing.T) {
		uid, gid := accountIDs(t)
		helper, serve := daemonParts(t)
		hs, ss := procStatus(helper), procStatus(serve)
		showProc("helper", helper, hs)
		showProc("serve", serve, ss)
		for k, want := range map[string]string{"Uid": "0 0 0 0", "CapBnd": "00000000000030fb", "CapEff": "00000000000030fb", "NoNewPrivs": "1", "Seccomp": "2"} {
			if hs[k] != want {
				t.Errorf("helper %s = %q, want %q", k, hs[k], want)
			}
		}
		id := strconv.Itoa(uid)
		for k, want := range map[string]string{"Uid": strings.Repeat(id+" ", 3) + id, "Gid": strconv.Itoa(gid) + " " + strconv.Itoa(gid) + " " + strconv.Itoa(gid) + " " + strconv.Itoa(gid),
			"CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000", "CapBnd": "0000000000000000",
			"CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2"} {
			if ss[k] != want {
				t.Errorf("serve %s = %q, want %q", k, ss[k], want)
			}
		}
		// No jail around either: the same mount and pid namespaces as init.
		for _, pid := range []string{helper, serve} {
			for _, ns := range []string{"mnt", "pid"} {
				a, _ := os.Readlink("/proc/1/ns/" + ns)
				b, _ := os.Readlink("/proc/" + pid + "/ns/" + ns)
				if a == "" || a != b {
					t.Errorf("pid %s %s namespace %q, init's %q", pid, ns, b, a)
				}
			}
		}
		// The listener holds open no file of the daemon's state and no config.
		ents, _ := os.ReadDir("/proc/" + serve + "/fd")
		for _, e := range ents {
			l, _ := os.Readlink("/proc/" + serve + "/fd/" + e.Name())
			if strings.HasPrefix(l, "/etc/") {
				t.Errorf("the listener holds %s open", l)
			}
		}
	})

	t.Run("only_the_listener_listens_and_only_on_loopback", func(t *testing.T) {
		helper, serve := daemonParts(t)
		inet := inetInodes()
		for ino := range socketInodes(helper) {
			if l, ok := inet[ino]; ok {
				t.Errorf("the helper holds an IP socket: %s", l)
			}
		}
		var listens []string
		for ino := range socketInodes(serve) {
			if l, ok := inet[ino]; ok && strings.HasSuffix(l, "st 0A") {
				listens = append(listens, l)
			}
		}
		// 0100007F:221A is 127.0.0.1:8730, little-endian as the kernel prints it.
		if len(listens) != 1 || !strings.Contains(listens[0], "0100007F:221A") {
			t.Errorf("the listener's listening sockets: %v, want one, on 127.0.0.1:8730", listens)
		}
		fmt.Printf("SOCKETS helper: no IP socket; serve listens: %v\n", listens)
	})

	t.Run("the_helper_socket_is_the_listeners", func(t *testing.T) {
		_, gid := accountIDs(t)
		for p, want := range map[string]string{filepath.Dir(defaultHelperSocket): "drwxr-x---", defaultHelperSocket: "Srw-rw----"} {
			st, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			sys := st.Sys().(*syscall.Stat_t)
			if st.Mode().String() != want || sys.Uid != 0 || int(sys.Gid) != gid {
				t.Errorf("%s: %s %d:%d, want %s 0:%d", p, st.Mode(), sys.Uid, sys.Gid, want, gid)
			}
			fmt.Printf("SOCKET %s %s %d:%d\n", p, st.Mode(), sys.Uid, sys.Gid)
		}
		// Root is not the listener: the helper answers its connection with nothing.
		c, err := net.Dial("unix", defaultHelperSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{0, 0, 0, 21})
		c.Write([]byte(`{"v":1,"op":"health"}`))
		if b, err := readFrame(c, maxResponseFrame); err == nil {
			t.Errorf("the helper answered root, which is not the listener: %s", b)
		}
		// Another account cannot even reach the socket.
		probes, _ := boundaryProbes(t, "other", 65534, 65534)
		if p := probes["other-account-connects"]; !strings.Contains(p, "permission denied") {
			t.Errorf("another account reached the socket: %s", p)
		}
	})

	t.Run("the_listener_cannot", func(t *testing.T) {
		uid, gid := accountIDs(t)
		_, serve := daemonParts(t)
		probes, st := boundaryProbes(t, "serve", uid, gid)
		ss := procStatus(serve)
		for _, k := range []string{"Uid", "Gid", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"} {
			if st[k] != ss[k] {
				t.Errorf("the probe is not the listener: %s %q, the listener %q", k, st[k], ss[k])
			}
		}
		denied := regexp.MustCompile(`permission denied|bad system call`)
		for _, name := range []string{"exec-ubus-service-set", "write-etc-config-new", "write-etc-config-system", "write-init-script",
			"write-state-dir", "read-shadow", "read-tokens", "read-mfa", "read-pin", "read-network-config"} {
			if p := probes[name]; !denied.MatchString(p) {
				t.Errorf("the listener could %s: %s", name, p)
			}
		}
		for _, name := range []string{"helper-op-off-the-list", "helper-tool-off-the-list", "helper-run-a-string", "helper-names-a-client"} {
			if p := probes[name]; !strings.Contains(p, `\"ok\":false`) {
				t.Errorf("the helper took %s: %s", name, p)
			}
		}
		if p := probes["helper-exec-without-a-token"]; !strings.Contains(p, "unauthorized") {
			t.Errorf("exec with no token: %s", p)
		}
		if _, err := os.Stat("/tmp/mcpprobe-ran"); err == nil {
			t.Error("a probe made something run")
		}
		if _, err := os.Stat("/etc/config/mcpprobe"); err == nil {
			t.Error("a probe wrote /etc/config")
		}
	})

	t.Run("the_listener_account_has_no_ubus", func(t *testing.T) {
		uid, gid := accountIDs(t)
		probes, _ := boundaryProbes(t, "base", uid, gid)
		for _, name := range []string{"ubus-call-service-set", "ubus-call-system-board", "ubus-call-file-exec", "ubus-call-uci-set"} {
			if p := probes[name]; !strings.Contains(p, "Not found") && !strings.Contains(p, "Permission denied") {
				t.Errorf("the account reached ubus: %s %s", name, p)
			}
		}
		if _, err := os.Stat("/tmp/mcpprobe-ran"); err == nil {
			t.Error("ubus service set ran a command for the account")
		}
		if out := jailSh(t, "ubus call service list '{\"name\":\"mcpprobe\"}'"); strings.Contains(out, "mcpprobe") {
			t.Errorf("a service was set: %s", out)
		}
	})

	t.Run("the_listener_refuses_to_run_as_root", func(t *testing.T) {
		out, err := exec.Command("/usr/bin/openwrt-mcp", "-socket", "/tmp/mcpprobe.sock", "serve").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "does not run as root") {
			t.Errorf("serve as root: %v %s", err, out)
		}
	})

	t.Run("the_listener_without_its_helper_runs_nothing", func(t *testing.T) {
		jailSh(t, "kill -STOP $(pidof openwrt-mcp | tr ' ' '\\n' | while read p; do grep -q helper /proc/$p/cmdline && echo $p; done)")
		defer jailSh(t, "kill -CONT $(pidof openwrt-mcp | tr ' ' '\\n' | while read p; do grep -q helper /proc/$p/cmdline && echo $p; done)")
		start := time.Now()
		resp, err := (&http.Client{Timeout: 40 * time.Second}).Get("http://127.0.0.1:8730/health")
		if err != nil {
			t.Fatalf("health with the helper stopped: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("health with the helper stopped: %d", resp.StatusCode)
		}
		fmt.Printf("HELPER-STOPPED /health %d after %s\n", resp.StatusCode, time.Since(start).Round(time.Second))
	})
	_ = r
}
