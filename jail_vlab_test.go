package main

// The daemon with its narrowed kernel surface, on a real OpenWrt router: every tool, through the
// HTTP listener, a bearer token and the policy gate, as a client meets it. It runs on the router
// itself, as root and as a process of its own, against the installed daemon that procd started:
//
//	scripts/e2e-vlab.sh builds this test binary, copies it to a vlab router and runs it there.
//
// Without OPENWRT_MCP_JAIL_E2E=1 it skips, like the real-uci test: it rewrites the router's
// /etc/config/openwrt-mcp and installs packages.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const jailE2EConfig = `config server
	option listen '127.0.0.1:8730'
	option audit '/etc/openwrt-mcp/audit.jsonl'
	option audit_max_mb '16'

config approval 'appr'
	option client 'agent'
	option approver 'owner'
	option factor 'pin+totp'

config policy
	option client 'agent'
	list tools 'uci_apply'
	list tools 'uci_confirm'
	list tools 'uci_get'
	list tools 'ubus_call'
	list tools 'logread'
	list tools 'apk_add'
	list scopes '*'
	option approval 'appr'

config policy 'admin'
	option client 'admin'
	list tools 'exec'
	list tools 'uci_apply'
	list tools 'uci_confirm'
	list tools 'wg_new_client'
	list tools 'logread'
	list scopes '*'
	list argv 'sh -c *'
	list argv 'cat /proc/self/status'
	list argv '/etc/init.d/dnsmasq enabled'
	list argv '/etc/init.d/dnsmasq restart'
	list argv 'pidof dnsmasq'
	list argv 'ps'
	list argv 'sysupgrade -b /tmp/jail-e2e-backup.tgz'
	list argv 'sysupgrade -h'
	list argv 'mtd'
	list argv 'ls /root'
	list argv 'ls -l /sbin/reboot'
	list argv 'ls /rom'
	list argv 'ls /dev'
	list argv 'mount'
	list argv 'firstboot'
	list argv 'insmod /nonexistent.ko'
	list argv 'mount -t tmpfs none /mnt'
	list mfa_tools 'exec'
	option mfa_factor 'pin'
`

type jailRig struct {
	t           *testing.T
	token       map[string]string
	ownerSecret string
}

func jailSh(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %s\n%v\n%s", script, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *jailRig) call(client, tool string, args map[string]any) (string, bool) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 330*time.Second)
	defer cancel()
	tr := &mcp.StreamableClientTransport{Endpoint: "http://127.0.0.1:8730/mcp",
		HTTPClient: &http.Client{Transport: bearerRT{r.token[client]}}, DisableStandaloneSSE: true}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "jail-e2e", Version: "0"}, nil).Connect(ctx, tr, nil)
	if err != nil {
		r.t.Fatalf("connect as %s: %v", client, err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		r.t.Fatalf("%s %s: %v", client, tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func (r *jailRig) mustOK(client, tool string, args map[string]any) string {
	r.t.Helper()
	out, isErr := r.call(client, tool, args)
	if isErr {
		r.t.Fatalf("%s %s %v: %s", client, tool, args, out)
	}
	return out
}

// sh runs a command through the exec tool: the policy grants "sh -c *" to admin, which is the
// shell the documentation warns an exec grant can be.
func (r *jailRig) sh(script string) (string, bool) {
	return r.call("admin", "exec", map[string]any{"argv": []string{"sh", "-c", script}, "timeout": 120})
}

func (r *jailRig) restart() {
	r.t.Helper()
	jailSh(r.t, "/etc/init.d/openwrt-mcp restart")
	for i := 0; i < 40; i++ {
		if resp, err := http.Get("http://127.0.0.1:8730/health"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	r.t.Fatal("the daemon did not come back after a restart")
}

func (r *jailRig) setup() {
	t := r.t
	jailSh(t, "mkdir -p /etc/openwrt-mcp && rm -f /etc/openwrt-mcp/tokens /etc/openwrt-mcp/pin /etc/openwrt-mcp/mfa* "+
		"/etc/openwrt-mcp/pending.json /etc/openwrt-mcp/throttle* /etc/openwrt-mcp/audit.jsonl*")
	if err := os.WriteFile("/etc/config/openwrt-mcp", []byte(jailE2EConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	jailSh(t, "apk del htop wireguard-tools >/dev/null 2>&1; rm -f /usr/bin/wg /usr/bin/htop")
	r.token = map[string]string{}
	for _, c := range []string{"agent", "owner", "admin"} {
		r.token[c] = jailSh(t, "/usr/bin/openwrt-mcp pair "+c)
	}
	for _, c := range []string{"owner", "admin", "agent"} {
		jailSh(t, "printf '4821\\n' | /usr/bin/openwrt-mcp pin set "+c)
	}
	// The approval is checked against the factors of the client whose change is held (the owner
	// is the person who holds them), as in the unit rig.
	r.ownerSecret = jailSh(t, `/usr/bin/openwrt-mcp mfa enrol agent --json | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p'`)
	r.restart()
}

func TestJailVlab(t *testing.T) {
	if os.Getenv("OPENWRT_MCP_JAIL_E2E") != "1" {
		t.Skip("set OPENWRT_MCP_JAIL_E2E=1 on a router that runs the installed daemon (scripts/e2e-vlab.sh)")
	}
	r := &jailRig{t: t}
	r.setup()

	t.Run("health_and_version", func(t *testing.T) {
		resp, err := http.Get("http://127.0.0.1:8730/health")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("health %d", resp.StatusCode)
		}
	})

	// The split: the two parts, what each holds, and what the listener cannot do (split_vlab_test.go).
	splitVlab(t, r)

	t.Run("ubus_list_and_call", func(t *testing.T) {
		if out := r.mustOK("agent", "ubus_list", map[string]any{"filter": "system"}); !strings.Contains(out, "system") {
			t.Fatalf("ubus_list: %q", out)
		}
		if out := r.mustOK("agent", "ubus_call", map[string]any{"object": "system", "method": "board"}); !strings.Contains(out, "release") {
			t.Fatalf("ubus_call system board: %q", out)
		}
		if out := r.mustOK("agent", "ubus_call", map[string]any{"object": "network.interface.wan", "method": "status"}); !strings.Contains(out, "up") {
			t.Fatalf("ubus_call network.interface.wan status: %q", out)
		}
	})

	t.Run("uci_get_and_logread", func(t *testing.T) {
		if out := r.mustOK("agent", "uci_get", map[string]any{"config": "system"}); !strings.Contains(out, "hostname") {
			t.Fatalf("uci_get: %q", out)
		}
		if out := r.mustOK("agent", "logread", map[string]any{"lines": 20}); !strings.Contains(out, "openwrt-mcp") {
			t.Fatalf("logread does not show the daemon: %q", out)
		}
	})

	t.Run("uci_apply_confirm_writes_etc_config", func(t *testing.T) {
		out := r.mustOK("admin", "uci_apply", map[string]any{"timeout": 60, "changes": []map[string]any{
			{"config": "system", "section": "@system[0]", "option": "description", "value": "jail-e2e"}}})
		tok := regexp.MustCompile(`[A-Za-z0-9_-]{8,}`).FindString(out[strings.Index(out, "confirm"):])
		if got := jailSh(t, "uci -q get system.@system[0].description"); got != "jail-e2e" {
			t.Fatalf("the change did not reach /etc/config: %q (%s)", got, out)
		}
		r.mustOK("admin", "uci_confirm", map[string]any{"token": tok})
		if got := jailSh(t, "uci -q get system.@system[0].description"); got != "jail-e2e" {
			t.Fatalf("the confirmed change is gone: %q", got)
		}
	})

	t.Run("uci_apply_unconfirmed_rolls_back", func(t *testing.T) {
		r.mustOK("admin", "uci_apply", map[string]any{"timeout": 5, "changes": []map[string]any{
			{"config": "system", "section": "@system[0]", "option": "description", "value": "to-be-reverted"}}})
		if got := jailSh(t, "uci -q get system.@system[0].description"); got != "to-be-reverted" {
			t.Fatalf("the change was not staged: %q", got)
		}
		if _, err := os.Stat("/etc/openwrt-mcp/pending.json"); err != nil {
			t.Fatalf("no pending record while an apply waits: %v", err)
		}
		time.Sleep(9 * time.Second)
		if got := jailSh(t, "uci -q get system.@system[0].description"); got != "jail-e2e" {
			t.Fatalf("the rollback did not restore /etc/config: %q", got)
		}
	})

	t.Run("held_change_approved_by_the_owner", func(t *testing.T) {
		out := r.mustOK("agent", "uci_apply", map[string]any{"timeout": 120, "changes": []map[string]any{
			{"config": "firewall", "section": "@zone[1]", "option": "input", "value": "ACCEPT"}}})
		if !strings.HasPrefix(out, "HELD ") {
			t.Fatalf("a firewall weakening was not held: %q", out)
		}
		id := strings.Fields(out)[1]
		list := r.mustOK("owner", "action_list", nil)
		var doc struct {
			Held []struct{ ID, Hash string } `json:"held"`
		}
		_ = json.Unmarshal([]byte(list), &doc)
		hash := ""
		for _, h := range doc.Held {
			if h.ID == id {
				hash = h.Hash
			}
		}
		if hash == "" {
			m := regexp.MustCompile(`"hash":\s*"([0-9a-f]{64})"`).FindStringSubmatch(list)
			if m == nil {
				t.Fatalf("no hash in the owner's list: %s", list)
			}
			hash = m[1]
		}
		code, err := totpAt(r.ownerSecret, uint64(time.Now().Unix())/30)
		if err != nil {
			t.Fatal(err)
		}
		out = r.mustOK("owner", "action_approve", map[string]any{"id": id, "hash": hash, "pin": "4821", "code": code})
		if !strings.Contains(strings.ToLower(out), "appl") {
			t.Fatalf("the approved change did not run: %q", out)
		}
		if got := jailSh(t, "uci -q get firewall.@zone[1].input"); got != "ACCEPT" {
			t.Fatalf("the approved change is not in /etc/config: %q", got)
		}
		// the rollback restores it when nobody confirms: put it back by hand now.
		jailSh(t, "uci -q set firewall.@zone[1].input=REJECT; uci commit firewall")
	})

	t.Run("exec_ordinary_programs", func(t *testing.T) {
		r.mustOK("admin", "mfa_unlock", map[string]any{"pin": "4821"})
		for name, c := range map[string]struct{ script, want string }{
			"ip":     {"ip -o addr show lo", "127.0.0.1"},
			"ping":   {"ping -c 1 -W 2 127.0.0.1", "1 packets received"},
			"date":   {"date +%Y", "20"},
			"uci":    {"uci show system.@system[0].hostname", "hostname"},
			"ubus":   {"ubus list system", "system"},
			"logger": {"logger -t jail-e2e hello && logread -l 5", "hello"},
			"nft":    {"nft list ruleset | head -3", "table"},
		} {
			out, isErr := r.sh(c.script)
			if isErr || !strings.Contains(out, c.want) {
				t.Errorf("exec %s (%q): want %q in %q (error=%v)", name, c.script, c.want, out, isErr)
			}
		}
	})

	t.Run("exec_a_service_restart_through_its_init_script", func(t *testing.T) {
		// The pid is read from outside the jail: inside it the router's processes are not
		// visible (the jail has its own pid namespace), so pidof there would say nothing.
		before := jailSh(t, "pidof dnsmasq")
		if out, isErr := r.call("admin", "exec", map[string]any{"argv": []string{"/etc/init.d/dnsmasq", "restart"}}); isErr {
			t.Fatalf("dnsmasq restart: %q", out)
		}
		time.Sleep(2 * time.Second)
		after := jailSh(t, "pidof dnsmasq")
		if after == "" || after == before {
			t.Fatalf("dnsmasq was not restarted by the exec: pid %q -> %q", before, after)
		}
	})

	t.Run("apk_add_dry_run_and_install", func(t *testing.T) {
		out := r.mustOK("agent", "apk_add", map[string]any{"packages": []string{"wireguard-tools"}, "dry_run": true})
		if !strings.Contains(out, "Dry run") {
			t.Fatalf("dry run: %q", out)
		}
		out = r.mustOK("agent", "apk_add", map[string]any{"packages": []string{"wireguard-tools", "htop"}})
		if !strings.Contains(out, "Done") {
			t.Fatalf("apk_add: %q", out)
		}
		for _, p := range []string{"/usr/bin/wg", "/usr/bin/htop"} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("the package's file is not on the router after apk_add: %v", err)
			}
		}
	})

	t.Run("wg_new_client", func(t *testing.T) {
		jailSh(t, `rm -f /etc/config/wireguard_server; touch /etc/config/wireguard_server
uci -q delete network.wgs; uci -q batch <<'EOF'
set wireguard_server.main_server=servers
set wireguard_server.main_server.address_v4='10.1.0.1/24'
set wireguard_server.main_server.port='51820'
set wireguard_server.main_server.public_key='SERVERPUB='
commit wireguard_server
set network.wgs=interface
set network.wgs.proto='wgserver'
set network.wgs.config='main_server'
commit network
EOF`)
		out := r.mustOK("admin", "wg_new_client", map[string]any{"name": "laptop", "endpoint": "198.51.100.7:51820"})
		if !strings.Contains(out, "PrivateKey") || !strings.Contains(out, "10.1.0.2") {
			t.Fatalf("wg_new_client: %.300q", out)
		}
		if got := jailSh(t, "uci -q get wireguard_server.peer_1001.name"); got != "laptop" {
			t.Logf("peer written: %s", jailSh(t, "uci show wireguard_server | grep -c laptop"))
			t.Fatalf("the peer is not in /etc/config/wireguard_server: %q", got)
		}
	})

	t.Run("state_survives_a_restart_and_a_failed_unlock_counts", func(t *testing.T) {
		if out, isErr := r.call("admin", "mfa_unlock", map[string]any{"pin": "0000"}); !isErr {
			t.Fatalf("a wrong PIN unlocked: %q", out)
		}
		before := jailSh(t, "ls /etc/openwrt-mcp | tr '\\n' ' '")
		r.restart()
		after := jailSh(t, "ls /etc/openwrt-mcp | tr '\\n' ' '")
		if !strings.Contains(after, "tokens") || !strings.Contains(after, "pin") {
			t.Fatalf("state files lost over a restart: %s -> %s", before, after)
		}
		if out := r.mustOK("agent", "ubus_call", map[string]any{"object": "system", "method": "board"}); !strings.Contains(out, "release") {
			t.Fatalf("the token did not survive the restart: %q", out)
		}
		if b, err := os.ReadFile("/etc/openwrt-mcp/audit.jsonl"); err != nil || !strings.Contains(string(b), "uci_apply") {
			t.Fatalf("the audit log lacks the earlier calls: %v", err)
		}
	})

	t.Run("a_program_the_daemon_starts_has_the_same_narrowing", func(t *testing.T) {
		r.mustOK("admin", "mfa_unlock", map[string]any{"pin": "4821"})
		out := r.mustOK("admin", "exec", map[string]any{"argv": []string{"cat", "/proc/self/status"}})
		for _, want := range []string{"Seccomp:\t2", "NoNewPrivs:\t1", "CapBnd:\t00000000000030fb", "CapEff:\t00000000000030fb"} {
			if !strings.Contains(out, want) {
				t.Errorf("a program started by exec lacks %q:\n%s", want, out)
			}
		}
		o, isErr := r.call("admin", "exec", map[string]any{"argv": []string{"mount", "-t", "tmpfs", "none", "/mnt"}})
		if !isErr || !strings.Contains(o, "bad system call") {
			t.Errorf("mount was not ended by the filter: error=%v %q", isErr, o)
		}
	})

	// There is no jail, so a program started by exec sees the router as before: its processes, with
	// procd as pid 1, its /root, and the reboot command.
	t.Run("exec_sees_the_router_as_before", func(t *testing.T) {
		r.mustOK("admin", "mfa_unlock", map[string]any{"pin": "4821"})
		ps := r.mustOK("admin", "exec", map[string]any{"argv": []string{"ps"}})
		if !regexp.MustCompile(`(?m)^\s*1 root .*(procd|init)`).MatchString(ps) || !strings.Contains(ps, "dnsmasq") {
			t.Errorf("ps through exec does not show the router's processes (procd as pid 1, dnsmasq):\n%.600s", ps)
		}
		if o, isErr := r.call("admin", "exec", map[string]any{"argv": []string{"ls", "/root"}}); isErr {
			t.Errorf("/root is not there for a program started by exec: %q", o)
		}
		if o, isErr := r.call("admin", "exec", map[string]any{"argv": []string{"ls", "-l", "/sbin/reboot"}}); isErr || !strings.Contains(o, "reboot") {
			t.Errorf("the reboot command is not there: %q", o)
		}
		if out, isErr := r.call("admin", "exec", map[string]any{"argv": []string{"sysupgrade", "-b", "/tmp/jail-e2e-backup.tgz"}}); isErr {
			t.Errorf("sysupgrade -b through exec: %q", out)
		}
	})

	// What a granted program meets is written down, not asserted: a measurement of this router.
	t.Run("report_what_a_granted_program_meets", func(t *testing.T) {
		r.mustOK("admin", "mfa_unlock", map[string]any{"pin": "4821"})
		for _, argv := range [][]string{{"ps"}, {"sysupgrade", "-b", "/tmp/jail-e2e-backup.tgz"}, {"mtd"},
			{"ls", "/root"}, {"ls", "/dev"}, {"mount"}, {"firstboot"},
			{"insmod", "/nonexistent.ko"}} {
			out, isErr := r.call("admin", "exec", map[string]any{"argv": argv, "timeout": 20})
			fmt.Printf("PROBE %-40s error=%-5v %.110q\n", strings.Join(argv, " "), isErr, out)
		}
	})

	t.Run("no_seccomp_death_anywhere", func(t *testing.T) {
		if out := jailSh(t, "logread | grep -c -i -E 'bad system call|SIGSYS' || true"); out != "0" {
			t.Fatalf("%s log lines mention a seccomp death:\n%s", out, jailSh(t, "logread | grep -i -E 'bad system call|SIGSYS'"))
		}
		fmt.Println("SECCOMP-DEATHS 0")
	})
}
