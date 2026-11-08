//go:build linux

package main

// The router's own bot on a router configured as the Flint 2 was when a held change's card never
// reached the owner (0.5.0.10, 2026-11-08): its approval section names an approver whose token
// binding revoked, both parts run as procd starts them (the real listener carries the pipe), the
// helper runs a while before the bot's token is set, and the change is uci_apply of the time servers.
// Without OPENWRT_MCP_OWNBOT_E2E=1 it skips: it rewrites the router's config, trust store and hosts.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const flint2Config = `
config server
	option listen '127.0.0.1:8730'
	option audit '/tmp/flint2-vlab-audit.jsonl'
	option audit_max_mb '16'

config policy 'hermes_main_read_ubus'
	option client 'hermes-main'
	list tools 'ubus_call'
	list scopes 'system.board'
	list scopes 'system.info'
	list scopes 'network.interface.dump'
	list scopes 'network.interface.*.status'
	list scopes 'network.device.status'
	list scopes 'iwinfo.devices'
	list scopes 'iwinfo.info'
	list scopes 'iwinfo.assoclist'
	list scopes 'dhcp.ipv6leases'
	list scopes 'luci-rpc.getDHCPLeases'
	list scopes 'luci-rpc.getHostHints'
	list scopes 'luci-rpc.getNetworkDevices'
	list scopes 'rc.list'

config policy 'hermes_main_read_uci'
	option client 'hermes-main'
	list tools 'uci_get'
	list scopes '*'

config policy 'hermes_main_read_log'
	option client 'hermes-main'
	list tools 'logread'

config approval 'hermes_main_approval'
	option client 'hermes-main'
	option approver 'hermes-main-owner'
	option factor 'pin+totp'
	option ttl '10m'
	option approvals 'on'
	list hold 'uci_apply:firewall.hermes_*'
	list hold 'uci_apply:firewall.@include*'

config policy 'hermes_main_packages'
	option client 'hermes-main'
	list tools 'apk_add'
	list scopes '*'
	list mfa_tools '*'
	option mfa_factor 'pin'
	option mfa_window '15m'
	option mfa_max_failures '5'
	option mfa_lockout '15m'
	option approval 'hermes_main_approval'

config policy 'hermes_main_change'
	option client 'hermes-main'
	list tools 'uci_apply'
	list tools 'uci_confirm'
	list scopes 'network'
	list scopes 'network.*'
	list scopes 'wireless'
	list scopes 'wireless.*'
	list scopes 'firewall'
	list scopes 'firewall.*'
	list scopes 'dhcp'
	list scopes 'dhcp.*'
	list scopes 'system'
	list scopes 'system.*'
	list mfa_tools '*'
	option mfa_factor 'pin'
	option mfa_window '15m'
	option mfa_max_failures '5'
	option mfa_lockout '15m'
	option approval 'hermes_main_approval'

config policy 'hermes_main_change_ubus'
	option client 'hermes-main'
	list tools 'ubus_call'
	list scopes 'network.reload'
	list scopes 'network.restart'
	list scopes 'network.interface.up'
	list scopes 'network.interface.down'
	list scopes 'network.interface.renew'
	list scopes 'network.interface.*.up'
	list scopes 'network.interface.*.down'
	list scopes 'network.interface.*.renew'
	list scopes 'network.wireless.up'
	list scopes 'network.wireless.down'
	list scopes 'network.wireless.reconf'
	list scopes 'rc.init'
	list mfa_tools '*'
	option mfa_factor 'pin'
	option mfa_window '15m'
	option mfa_max_failures '5'
	option mfa_lockout '15m'
	option approval 'hermes_main_approval'

config policy 'hermes_main_hold'
	option client 'hermes-main'
	list tools 'ubus_call'
	list scopes 'system.reboot'
	option hold '1'
	option approval 'hermes_main_approval'

`

func flint2Call(t *testing.T, token, tool string, args map[string]any) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tr := &mcp.StreamableClientTransport{Endpoint: "http://127.0.0.1:8730/mcp",
		HTTPClient: &http.Client{Transport: bearerRT{token}}, DisableStandaloneSSE: true}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "flint2-e2e", Version: "0"}, nil).Connect(ctx, tr, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func TestOwnBotFlint2Vlab(t *testing.T) {
	if os.Getenv("OPENWRT_MCP_OWNBOT_E2E") != "1" {
		t.Skip("set OPENWRT_MCP_OWNBOT_E2E=1 on a router that runs the installed daemon (scripts/e2e-vlab.sh)")
	}
	v := &ownVlab{t: t}
	v.sh("rm -rf " + ownVlabSave + " && mkdir -p " + ownVlabSave + " && cp -a /etc/config/openwrt-mcp /etc/hosts " + ownVlabSave + "/ && " +
		"if [ -d /etc/ssl/certs ]; then mv /etc/ssl/certs " + ownVlabSave + "/certs; fi && " +
		"if [ -e /etc/ssl/cert.pem ]; then mv /etc/ssl/cert.pem " + ownVlabSave + "/cert.pem; fi && mkdir -p /etc/ssl/certs && " +
		"cp -a /etc/config/system " + ownVlabSave + "/system")
	t.Cleanup(func() { exec.Command("/bin/sh", "-c", "cp -a "+ownVlabSave+"/system /etc/config/system").Run() })
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
		"/etc/openwrt-mcp/pending.json /etc/openwrt-mcp/throttle* /tmp/flint2-vlab-audit.jsonl")
	if err := os.WriteFile("/etc/config/openwrt-mcp", []byte(flint2Config), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := v.sh("/usr/bin/openwrt-mcp pair hermes-main")
	v.sh("/usr/bin/openwrt-mcp pair hermes-main-owner")
	v.sh("printf '4821\\n' | /usr/bin/openwrt-mcp pin set hermes-main")
	var enrol struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal([]byte(v.sh("/usr/bin/openwrt-mcp mfa enrol hermes-main --json")), &enrol)
	if enrol.Secret == "" {
		t.Fatal("mfa enrol gave no secret")
	}
	v.restartDaemon()
	fmt.Printf("FLINT2 both parts run: %s\n", strings.Join(strings.Fields(v.sh("pgrep -af '/usr/bin/openwrt-mcp' | grep -v pgrep || true")), " "))
	// The helper runs with no token for a while, as on the Flint 2 (12 minutes there).
	time.Sleep(6 * time.Second)
	v.sh("printf '%s\\n' '" + testBotToken + "' | /usr/bin/openwrt-mcp owner-bot set")
	var b struct {
		Code string `json:"code"`
	}
	json.Unmarshal([]byte(v.sh("/usr/bin/openwrt-mcp owner-bot bind --json")), &b)
	v.tg.say(testOwner, testOwner, "private", "/start "+b.Code)
	waitFor(t, "the owner's chat to be bound", 60*time.Second, func() bool {
		return strings.Contains(v.sh("/usr/bin/openwrt-mcp owner-bot status --json"), `"bound": true`)
	})
	fmt.Printf("FLINT2 bound; clients now: %s\n", strings.Join(strings.Fields(v.sh("/usr/bin/openwrt-mcp clients")), " "))
	// On the Flint 2 the hold came 12 minutes after the binding: past the pool's idle timeout (90 s)
	// and the pipe's (2 min). FLINT2_GAP sets the wait in seconds.
	gap := 5 * time.Second
	if n, err := strconv.Atoi(os.Getenv("FLINT2_GAP")); err == nil && n > 0 {
		gap = time.Duration(n) * time.Second
	}
	time.Sleep(gap)
	fmt.Printf("FLINT2 waited %s after binding\n", gap)
	out, isErr := flint2Call(t, agent, "uci_apply", map[string]any{"changes": []map[string]any{
		{"config": "system", "section": "ntp", "option": "server", "value": "time.cloudflare.com"}}})
	m := heldLine.FindStringSubmatch(out)
	if isErr || m == nil {
		t.Fatalf("not held: %q", out)
	}
	t0 := time.Now()
	fmt.Printf("FLINT2 held %s\n", m[1])
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range v.tg.sentTo(testOwner) {
			if len(s.Keyboard) > 0 && strings.Contains(s.Text, m[1]) {
				fmt.Printf("FLINT2 the card of %s reached the chat %s after the hold\n", m[1], time.Since(t0).Round(time.Millisecond))
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Printf("FLINT2 helper log: %s\n", v.sh("logread | grep -E 'openwrt-mcp\\[' | tail -15 || true"))
	t.Fatalf("the card of %s never reached the owner's chat; sent there: %d message(s)", m[1], len(v.tg.sentTo(testOwner)))
}
