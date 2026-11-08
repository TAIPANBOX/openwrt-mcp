//go:build linux

package main

// The owner's approval past the listener, on a real OpenWrt router (vlab), against the daemon procd
// started: the helper as root, with its bot, and in place of the listener a hostile one, run as the
// listener's own account under the listener's filter, which holds every token it is given and serves
// the pipe to Telegram, recording every byte. Telegram is a stand-in served on the router at
// 127.0.0.1:443, with a certificate from a CA made for this run; for the run, /etc/hosts sends
// api.telegram.org there and the router's trust store holds that CA and nothing else, so nothing here
// can reach Telegram and no real token is used. Everything is put back at the end.
//
// It adapts to the binary as a client of the capability would: with owner_approves_past_the_listener
// the owner answers in the router's chat; without it (origin/main, the red run of scripts/e2e-vlab.sh
// --daemon), the owner's client answers through the listener, and the listener moves the factor.
//
// Without OPENWRT_MCP_OWNBOT_E2E=1 it skips: it rewrites the router's config, trust store and hosts.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const ownVlabConfig = `config server
	option listen '127.0.0.1:8730'

config approval 'vown'
	option client 'vagent'
	option approver 'vowner'
	option max_open '2'
	list hold 'ubus_call:system.board'
	list hold 'ubus_call:system.info'

config policy
	option client 'vagent'
	list tools 'ubus_call'
	list scopes 'system.*'
	list mfa_tools 'ubus_call'
	option mfa_factor 'pin+totp'
	option approval 'vown'
`

const ownVlabSave = "/tmp/ownbot-vlab-save"

// ---------------------------------------------------------------- the hostile listener, a child

// The child takes the listener's identity, serves the pipe with the listener's own code and dial,
// recording what it copies, and answers one helper call per line of its standard input.
func init() {
	if os.Getenv("OPENWRT_MCP_HOSTILE_CHILD") != "1" {
		return
	}
	uid, _ := strconv.Atoi(os.Getenv("OPENWRT_MCP_HOSTILE_UID"))
	gid, _ := strconv.Atoi(os.Getenv("OPENWRT_MCP_HOSTILE_GID"))
	for c := 0; c <= 63; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			fmt.Println(`{"err":"capbset"}`)
			os.Exit(3)
		}
	}
	if syscall.Setgroups([]int{gid}) != nil || syscall.Setgid(gid) != nil || syscall.Setuid(uid) != nil {
		fmt.Println(`{"err":"identity"}`)
		os.Exit(3)
	}
	if _, err := confineSeccompServe(); err != nil {
		fmt.Println(`{"err":"seccomp"}`)
		os.Exit(3)
	}
	var mu sync.Mutex
	var carried bytes.Buffer
	if _, err := os.Stat(filepath.Dir(defaultRelaySocket)); err == nil {
		r := newTelegramRelay(0)
		r.dial = func(ctx context.Context) (net.Conn, error) {
			c, err := dialTelegram(ctx) // the listener's own dial: api.telegram.org:443
			if err != nil {
				return nil, err
			}
			return &tapConn{Conn: c, mu: &mu, up: &carried, down: &carried, tamper: new(atomic.Bool)}, nil
		}
		if ln, err := listenRelay(defaultRelaySocket); err == nil {
			go r.serve(ln)
		}
	}
	hc := &helperClient{path: defaultHelperSocket}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(os.Stdout)
	st := procStatus("self")
	enc.Encode(map[string]any{"ready": true, "uid": st["Uid"], "seccomp": st["Seccomp"], "capeff": st["CapEff"]})
	for in.Scan() {
		var cmd struct {
			Op, Token, Tool string
			Input           json.RawMessage
		}
		if json.Unmarshal(in.Bytes(), &cmd) != nil {
			continue
		}
		switch cmd.Op {
		case "call":
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			text, isErr, err := hc.call(ctx, cmd.Token, cmd.Tool, cmd.Input)
			cancel()
			e := ""
			if err != nil {
				e = err.Error()
			}
			enc.Encode(map[string]any{"text": text, "is_error": isErr, "err": e})
		case "carried":
			mu.Lock()
			enc.Encode(map[string]any{"carried": base64.StdEncoding.EncodeToString(carried.Bytes())})
			mu.Unlock()
		case "quit":
			os.Exit(0)
		}
	}
	os.Exit(0)
}

type hostileChild struct {
	t   *testing.T
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
	mu  sync.Mutex
}

func startHostileChild(t *testing.T) *hostileChild {
	t.Helper()
	u, err := user.Lookup(serveUser)
	if err != nil {
		t.Fatalf("no account %s: %v", serveUser, err)
	}
	g, err := user.LookupGroup(serveUser)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_HOSTILE_CHILD=1", "OPENWRT_MCP_HOSTILE_UID="+u.Uid, "OPENWRT_MCP_HOSTILE_GID="+g.Gid)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &hostileChild{t: t, cmd: cmd, in: in, out: bufio.NewScanner(out)}
	h.out.Buffer(make([]byte, 8<<20), 8<<20)
	var ready map[string]any
	if !h.out.Scan() || json.Unmarshal(h.out.Bytes(), &ready) != nil || ready["ready"] != true {
		t.Fatalf("the hostile listener did not start: %s", h.out.Text())
	}
	fmt.Printf("OWNBOT hostile listener: uid %v, Seccomp %v, CapEff %v\n", ready["uid"], ready["seccomp"], ready["capeff"])
	t.Cleanup(func() {
		h.in.Write([]byte(`{"Op":"quit"}` + "\n"))
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill() // our own child, by its own handle
		}
	})
	return h
}

func (h *hostileChild) send(v any) map[string]any {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	b, _ := json.Marshal(v)
	h.in.Write(append(b, '\n'))
	var out map[string]any
	if !h.out.Scan() || json.Unmarshal(h.out.Bytes(), &out) != nil {
		h.t.Fatalf("the hostile listener did not answer: %s", h.out.Text())
	}
	return out
}

func (h *hostileChild) call(token, tool string, in map[string]any) (string, bool) {
	h.t.Helper()
	b, _ := json.Marshal(in)
	out := h.send(map[string]any{"Op": "call", "Token": token, "Tool": tool, "Input": json.RawMessage(b)})
	if e, _ := out["err"].(string); e != "" {
		return e, true
	}
	text, _ := out["text"].(string)
	isErr, _ := out["is_error"].(bool)
	return text, isErr
}

func (h *hostileChild) carried() []byte {
	out := h.send(map[string]any{"Op": "carried"})
	b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(out["carried"]))
	return b
}

// ---------------------------------------------------------------- the router, for the run

type ownVlab struct {
	t        *testing.T
	ca       testCA
	tg       *tgStandIn
	secret   string
	agentTok string
	ownerTok string
	uhttpd   bool // stopped for the run: it held 443
}

func (v *ownVlab) sh(script string) string { return jailSh(v.t, script) }

func (v *ownVlab) code(at time.Time) string {
	c, err := totpAt(v.secret, uint64(at.Unix())/30)
	if err != nil {
		v.t.Fatal(err)
	}
	return c
}

func (v *ownVlab) restartDaemon() {
	v.sh("/etc/init.d/openwrt-mcp restart")
	for i := 0; i < 60; i++ {
		if resp, err := http.Get("http://127.0.0.1:8730/health"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	v.t.Fatal("the daemon did not come back after a restart")
}

func (v *ownVlab) setup() {
	t := v.t
	v.sh("rm -rf " + ownVlabSave + " && mkdir -p " + ownVlabSave + " && cp -a /etc/config/openwrt-mcp /etc/hosts " + ownVlabSave + "/ && " +
		"if [ -d /etc/ssl/certs ]; then mv /etc/ssl/certs " + ownVlabSave + "/certs; fi && " +
		"if [ -e /etc/ssl/cert.pem ]; then mv /etc/ssl/cert.pem " + ownVlabSave + "/cert.pem; fi && mkdir -p /etc/ssl/certs")
	t.Cleanup(v.restore)
	v.ca = newTestCA(t, "openwrt-mcp vlab stand-in CA")
	if err := os.WriteFile("/etc/ssl/certs/ca-certificates.crt",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.ca.cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	v.sh("printf '127.0.0.1 api.telegram.org\\n' >> /etc/hosts")
	if strings.Contains(v.sh("netstat -ltn 2>/dev/null | grep ':443 ' || true"), ":443") {
		v.sh("/etc/init.d/uhttpd stop")
		v.uhttpd = true
	}
	v.tg = newTGStandInOn(t, v.ca.leaf(t, telegramHost), "127.0.0.1:443")

	v.sh("rm -rf /etc/openwrt-mcp/owner-bot && rm -f /etc/openwrt-mcp/tokens /etc/openwrt-mcp/pin /etc/openwrt-mcp/mfa* " +
		"/etc/openwrt-mcp/pending.json /etc/openwrt-mcp/throttle*")
	if err := os.WriteFile("/etc/config/openwrt-mcp", []byte(ownVlabConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	v.agentTok = v.sh("/usr/bin/openwrt-mcp pair vagent")
	v.ownerTok = v.sh("/usr/bin/openwrt-mcp pair vowner")
	v.sh("printf '4821\\n' | /usr/bin/openwrt-mcp pin set vagent")
	var enrol struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal([]byte(v.sh("/usr/bin/openwrt-mcp mfa enrol vagent --json")), &enrol)
	if enrol.Secret == "" {
		t.Fatal("mfa enrol gave no secret")
	}
	v.secret = enrol.Secret
	// The helper reads the trust store once, so it starts again with the run's CA in it; then the
	// listener procd started is taken away, and the hostile one stands in its place.
	v.restartDaemon()
	v.sh(`ubus call service delete '{"name":"openwrt-mcp","instance":"serve"}'`)
	for i := 0; i < 40 && v.sh("pgrep -f '/usr/bin/openwrt-mcp serve' || true") != ""; i++ {
		time.Sleep(100 * time.Millisecond)
	}
}

func (v *ownVlab) restore() {
	exec.Command("/bin/sh", "-c", "/usr/bin/openwrt-mcp owner-bot clear >/dev/null 2>&1; "+
		"cp -a "+ownVlabSave+"/openwrt-mcp /etc/config/openwrt-mcp; cp -a "+ownVlabSave+"/hosts /etc/hosts; "+
		"rm -rf /etc/ssl/certs; if [ -d "+ownVlabSave+"/certs ]; then mv "+ownVlabSave+"/certs /etc/ssl/certs; fi; "+
		"if [ -e "+ownVlabSave+"/cert.pem ]; then mv "+ownVlabSave+"/cert.pem /etc/ssl/cert.pem; fi").Run()
	if v.uhttpd {
		exec.Command("/etc/init.d/uhttpd", "start").Run()
	}
	exec.Command("/etc/init.d/openwrt-mcp", "restart").Run()
}

func (v *ownVlab) capability() bool {
	var st struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	json.Unmarshal([]byte(v.sh("/usr/bin/openwrt-mcp status --json --audit 0")), &st)
	return st.Capabilities["owner_approves_past_the_listener"]
}

// helperPID is the helper's pid, by its command line: procd's serve instance is gone in this run, so
// daemonParts, which wants both, is not used.
func helperPID() string {
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
		if len(args) >= 2 && args[0] == "/usr/bin/openwrt-mcp" && args[1] == "helper" {
			return e.Name()
		}
	}
	return ""
}

// inetSockets counts a process's IP sockets, by the inodes of its descriptors in /proc/net.
func inetSockets(pid string) (inet, unixSocks int) {
	inodes := map[string]bool{}
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
		b, _ := os.ReadFile("/proc/net/" + f)
		for i, line := range strings.Split(string(b), "\n") {
			if fs := strings.Fields(line); i > 0 && len(fs) > 9 {
				inodes[fs[9]] = true
			}
		}
	}
	fds, _ := os.ReadDir("/proc/" + pid + "/fd")
	for _, fd := range fds {
		l, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		if inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] {
			inet++
		} else {
			unixSocks++
		}
	}
	return inet, unixSocks
}

func TestOwnBotVlab(t *testing.T) {
	if os.Getenv("OPENWRT_MCP_OWNBOT_E2E") != "1" {
		t.Skip("set OPENWRT_MCP_OWNBOT_E2E=1 on a router that runs the installed daemon (scripts/e2e-vlab.sh)")
	}
	v := &ownVlab{t: t}
	v.setup()
	withBot := v.capability()
	fmt.Printf("OWNBOT the binary has owner_approves_past_the_listener: %v\n", withBot)
	h := startHostileChild(t)

	held := func(out string, isErr bool) string {
		m := heldLine.FindStringSubmatch(out)
		if isErr || m == nil {
			t.Fatalf("not held: %q", out)
		}
		return m[1]
	}
	var factorsSeen []string // what of the owner's passed the listener
	if withBot {
		v.sh("printf '%s\\n' '" + testBotToken + "' | /usr/bin/openwrt-mcp owner-bot set")
		var b struct {
			Code string `json:"code"`
		}
		json.Unmarshal([]byte(v.sh("/usr/bin/openwrt-mcp owner-bot bind --json")), &b)
		start := time.Now()
		v.tg.say(testOwner, testOwner, "private", "/start "+b.Code)
		waitFor(t, "the owner's chat to be bound on the router", 60*time.Second, func() bool {
			return strings.Contains(v.sh("/usr/bin/openwrt-mcp owner-bot status --json"), `"bound": true`)
		})
		fmt.Printf("OWNBOT bound the owner's chat in %s; status: %s\n", time.Since(start).Round(time.Millisecond),
			strings.Join(strings.Fields(v.sh("/usr/bin/openwrt-mcp owner-bot status --json")), " "))
	}
	t0 := time.Now()
	a := held(h.call(v.agentTok, "ubus_call", map[string]any{"object": "system", "method": "board"}))
	b := held(h.call(v.agentTok, "ubus_call", map[string]any{"object": "system", "method": "info"}))
	hashOf := func(id string) string {
		out, isErr := h.call(v.ownerTok, "action_list", map[string]any{})
		if isErr {
			return ""
		}
		var l struct{ Actions []apAction }
		json.Unmarshal([]byte(out), &l)
		for _, x := range l.Actions {
			if x.ID == id {
				return x.Hash
			}
		}
		return ""
	}
	bHash := hashOf(b)
	cApprove, cUnlock := v.code(time.Now()), v.code(time.Now().Add(30*time.Second))
	var cards []string
	if withBot {
		card := v.tg.waitCard(t, a)
		fmt.Printf("OWNBOT the card of %s reached the owner's chat %s after the hold\n", a, time.Since(t0).Round(time.Millisecond))
		cards = append(cards, card.Text, v.tg.waitCard(t, b).Text)
		got := v.tg.approve(t, card, apPIN+" "+cApprove)
		fmt.Printf("OWNBOT the owner's approval in the chat answered: %q\n", got)
		n := len(v.tg.sentTo(testOwner))
		v.tg.say(testOwner, testOwner, "private", "/unlock "+apPIN+" "+cUnlock)
		v.tg.waitText(t, n, "Unlocked vagent until")
	} else {
		// The owner's client approves A through the listener, which puts it on B; then it unlocks,
		// and the listener sends that PIN and code as an approval of B as well.
		factorsSeen = append(factorsSeen, apPIN, cApprove)
		h.call(v.ownerTok, "action_approve", map[string]any{"id": b, "hash": bHash, "pin": apPIN, "code": cApprove})
		factorsSeen = append(factorsSeen, cUnlock)
	}
	pin, code := "", ""
	if len(factorsSeen) > 0 {
		pin, code = factorsSeen[0], factorsSeen[len(factorsSeen)-1]
	}
	h.call(v.ownerTok, "action_approve", map[string]any{"id": b, "hash": bHash, "pin": pin, "code": code})

	status := map[string]string{}
	out, _ := h.call(v.agentTok, "action_status", map[string]any{})
	var l struct{ Actions []apAction }
	json.Unmarshal([]byte(out), &l)
	for _, x := range l.Actions {
		status[x.ID] = x.Status
	}
	fmt.Printf("OWNBOT A %s is %s, B %s (the listener's) is %s\n", a, status[a], b, status[b])
	if status[b] == statusApplied {
		t.Errorf("the listener's change ran: the owner's factor was moved to a change the owner was never shown")
	}
	if withBot && status[a] != statusApplied {
		t.Errorf("A, which the owner approved in the router's chat, is %s", status[a])
	}

	carried := h.carried()
	fmt.Printf("OWNBOT the pipe carried %d bytes\n", len(carried))
	if withBot {
		if len(carried) < 2000 {
			t.Errorf("the pipe carried %d bytes: the check below reads nothing", len(carried))
		}
		secrets := map[string]string{"the approval": apPIN + " " + cApprove, "a code": cApprove, "the unlock's code": cUnlock,
			"/unlock": "/unlock ", "the token": testBotToken, "a request in clear": "POST /bot", "getUpdates": "getUpdates",
			"a card's header": "Router change waiting"}
		for i, c := range cards {
			secrets[fmt.Sprintf("card %d", i)] = c
		}
		clear := 0
		for what, s := range secrets {
			if bytes.Contains(carried, []byte(s)) {
				t.Errorf("%s passed the listener in clear", what)
				clear++
			}
		}
		fmt.Printf("OWNBOT of %d secrets looked for in the pipe's bytes, %d were there in clear\n", len(secrets), clear)
	}

	// What the kernel shows: the helper's sockets, and that it is still in its cage.
	if pid := helperPID(); pid != "" {
		inet, us := inetSockets(pid)
		st := procStatus(pid)
		fmt.Printf("OWNBOT helper pid %s: IP sockets %d, Unix sockets %d; Uid %s NoNewPrivs %s Seccomp %s CapEff %s\n",
			pid, inet, us, st["Uid"], st["NoNewPrivs"], st["Seccomp"], st["CapEff"])
		if inet != 0 {
			t.Errorf("the helper holds %d IP socket(s)", inet)
		}
	}
	if withBot {
		inet, _ := inetSockets(strconv.Itoa(h.cmd.Process.Pid))
		fmt.Printf("OWNBOT the hostile listener holds %d IP socket(s): the pipe's connection to 127.0.0.1:443\n", inet)
	}
}

// ---------------------------------------------------------------- the stand-in, on a fixed address

// newTGStandInOn is newTGStandIn listening on addr.
func newTGStandInOn(t *testing.T, cert tls.Certificate, addr string) *tgStandIn {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the stand-in cannot listen on %s: %v", addr, err)
	}
	return newTGStandInListener(t, cert, ln)
}

func (st *tgStandIn) waitCard(t *testing.T, id string) tgSent {
	t.Helper()
	var card tgSent
	waitFor(t, "the card of "+id, 60*time.Second, func() bool {
		for _, m := range st.sentTo(testOwner) {
			if len(m.Keyboard) > 0 && strings.Contains(m.Text, "("+id+",") {
				card = m
				return true
			}
		}
		return false
	})
	return card
}

func (st *tgStandIn) waitText(t *testing.T, from int, want string) string {
	t.Helper()
	var got string
	waitFor(t, fmt.Sprintf("a message with %q", want), 60*time.Second, func() bool {
		ms := st.sentTo(testOwner)
		for i := from; i < len(ms); i++ {
			if strings.Contains(ms[i].Text, want) {
				got = ms[i].Text
				return true
			}
		}
		return false
	})
	return got
}

// approve taps Approve on the card and answers the prompt, and returns the router's answer.
func (st *tgStandIn) approve(t *testing.T, card tgSent, factor string) string {
	t.Helper()
	n := len(st.sentTo(testOwner))
	st.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	st.waitText(t, n, "Approve ")
	n = len(st.sentTo(testOwner))
	st.say(testOwner, testOwner, "private", factor)
	var got string
	waitFor(t, "the router's answer to the factor", 60*time.Second, func() bool {
		ms := st.sentTo(testOwner)
		for i := n; i < len(ms); i++ {
			if strings.HasPrefix(ms[i].Text, "Applied") || strings.HasPrefix(ms[i].Text, "Not approved") ||
				strings.HasPrefix(ms[i].Text, "That was") {
				got = ms[i].Text
				return true
			}
		}
		return false
	})
	return got
}
