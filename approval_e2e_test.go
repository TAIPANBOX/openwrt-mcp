package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Held actions, end to end through the real MCP tool handlers. The router is a scratch
// /etc/config, a fake `uci` and a fake `ubus` that log every call. The fake `uci` answers
// `uci -X show <config>` from a fixture of the router as it is now, and the same command run
// against a scratch copy of the configs (`uci -c <dir>/after ...`) from a fixture of the router as
// the change would leave it. The fixtures are what libuci prints with -X: one record a line,
// anonymous sections under their cfgXXXXXX ids.
//
// The property asserted for a held change is "nothing ran": no `uci set`, `uci delete`, `uci
// commit` or `uci revert` against the router, and no ubus call but reads.

const apFirewall = "firewall.cfg01e63d=defaults\n" +
	"firewall.cfg01e63d.syn_flood='1'\n" +
	"firewall.cfg01e63d.input='REJECT'\n" +
	"firewall.cfg01e63d.output='ACCEPT'\n" +
	"firewall.cfg01e63d.forward='REJECT'\n" +
	"firewall.cfg02dc81=zone\n" +
	"firewall.cfg02dc81.name='lan'\n" +
	"firewall.cfg02dc81.network='lan'\n" +
	"firewall.cfg02dc81.input='ACCEPT'\n" +
	"firewall.cfg02dc81.output='ACCEPT'\n" +
	"firewall.cfg02dc81.forward='ACCEPT'\n" +
	"firewall.cfg03dc81=zone\n" +
	"firewall.cfg03dc81.name='wan'\n" +
	"firewall.cfg03dc81.network='wan' 'wan6'\n" +
	"firewall.cfg03dc81.input='REJECT'\n" +
	"firewall.cfg03dc81.output='ACCEPT'\n" +
	"firewall.cfg03dc81.forward='REJECT'\n" +
	"firewall.cfg03dc81.masq='1'\n" +
	"firewall.cfg03dc81.mtu_fix='1'\n" +
	"firewall.cfg04ad58=forwarding\n" +
	"firewall.cfg04ad58.src='lan'\n" +
	"firewall.cfg04ad58.dest='wan'\n" +
	"firewall.cfg0592bd=rule\n" +
	"firewall.cfg0592bd.name='Allow-DHCP-Renew'\n" +
	"firewall.cfg0592bd.src='wan'\n" +
	"firewall.cfg0592bd.proto='udp'\n" +
	"firewall.cfg0592bd.dest_port='68'\n" +
	"firewall.cfg0592bd.target='ACCEPT'\n" +
	"firewall.cfg0592bd.family='ipv4'\n" +
	"firewall.cfg0692bd=rule\n" +
	"firewall.cfg0692bd.name='Allow-Ping'\n" +
	"firewall.cfg0692bd.src='wan'\n" +
	"firewall.cfg0692bd.proto='icmp'\n" +
	"firewall.cfg0692bd.icmp_type='echo-request'\n" +
	"firewall.cfg0692bd.family='ipv4'\n" +
	"firewall.cfg0692bd.target='ACCEPT'\n" +
	"firewall.guest=zone\n" +
	"firewall.guest.name='guest'\n" +
	"firewall.guest.network='guest'\n" +
	"firewall.guest.input='REJECT'\n" +
	"firewall.guest.output='ACCEPT'\n" +
	"firewall.guest.forward='REJECT'\n"

const apNetwork = "network.loopback=interface\n" +
	"network.loopback.device='lo'\n" +
	"network.loopback.proto='static'\n" +
	"network.loopback.ipaddr='127.0.0.1'\n" +
	"network.loopback.netmask='255.0.0.0'\n" +
	"network.globals=globals\n" +
	"network.globals.ula_prefix='fd12:3456:789a::/48'\n" +
	"network.cfg030f15=device\n" +
	"network.cfg030f15.name='br-lan'\n" +
	"network.cfg030f15.type='bridge'\n" +
	"network.cfg030f15.ports='lan1' 'lan2' 'lan3'\n" +
	"network.lan=interface\n" +
	"network.lan.device='br-lan'\n" +
	"network.lan.proto='static'\n" +
	"network.lan.ipaddr='192.168.1.1'\n" +
	"network.lan.netmask='255.255.255.0'\n" +
	"network.wan=interface\n" +
	"network.wan.device='wan'\n" +
	"network.wan.proto='dhcp'\n" +
	"network.wan6=interface\n" +
	"network.wan6.device='wan'\n" +
	"network.wan6.proto='dhcpv6'\n" +
	"network.guest=interface\n" +
	"network.guest.proto='static'\n" +
	"network.guest.device='br-guest'\n" +
	"network.guest.ipaddr='192.168.9.1'\n" +
	"network.guest.netmask='255.255.255.0'\n"

const apDHCP = "dhcp.cfg01411c=dnsmasq\n" +
	"dhcp.cfg01411c.domainneeded='1'\n" +
	"dhcp.cfg01411c.rebind_protection='1'\n" +
	"dhcp.cfg01411c.local='/lan/'\n" +
	"dhcp.cfg01411c.domain='lan'\n" +
	"dhcp.lan=dhcp\n" +
	"dhcp.lan.interface='lan'\n" +
	"dhcp.lan.start='100'\n" +
	"dhcp.lan.limit='150'\n" +
	"dhcp.lan.leasetime='12h'\n" +
	"dhcp.wan=dhcp\n" +
	"dhcp.wan.interface='wan'\n" +
	"dhcp.wan.ignore='1'\n"

const apWireless = "wireless.radio0=wifi-device\n" +
	"wireless.radio0.type='mac80211'\n" +
	"wireless.radio0.band='5g'\n" +
	"wireless.default_radio0=wifi-iface\n" +
	"wireless.default_radio0.device='radio0'\n" +
	"wireless.default_radio0.network='lan'\n" +
	"wireless.default_radio0.mode='ap'\n" +
	"wireless.default_radio0.ssid='Home'\n" +
	"wireless.default_radio0.encryption='sae-mixed'\n" +
	"wireless.default_radio0.key='HOME-WIFI-KEY-CANARY'\n" +
	"wireless.guest_radio0=wifi-iface\n" +
	"wireless.guest_radio0.device='radio0'\n" +
	"wireless.guest_radio0.network='guest'\n" +
	"wireless.guest_radio0.mode='ap'\n" +
	"wireless.guest_radio0.ssid='Guests'\n" +
	"wireless.guest_radio0.encryption='none'\n"

const apSystem = "system.cfg01e48a=system\n" +
	"system.cfg01e48a.hostname='OpenWrt'\n" +
	"system.cfg01e48a.description='baseline'\n" +
	"system.cfg01e48a.timezone='UTC'\n" +
	"system.ntp=timeserver\n" +
	"system.ntp.enabled='1'\n" +
	"system.ntp.enable_server='0'\n" +
	"system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'\n"

const apPBR = "pbr.config=pbr\n" +
	"pbr.config.enabled='0'\n"

var apNow = map[string]string{"firewall": apFirewall, "network": apNetwork, "dhcp": apDHCP,
	"wireless": apWireless, "system": apSystem, "pbr": apPBR}

// The approval section and the policies of the client the tests drive, "a". Its window is opened
// with a PIN; its held changes are approved by "owner" with the PIN and a code.
const apApproval = "\nconfig approval 'appr'\n\toption client 'a'\n\toption approver 'owner'\n"

const apPolicies = "\nconfig policy\n\toption client 'a'\n" +
	"\tlist tools 'uci_apply'\n\tlist tools 'uci_confirm'\n\tlist tools 'ubus_call'\n" +
	"\tlist tools 'exec'\n\tlist tools 'wg_new_client'\n\tlist tools 'uci_get'\n" +
	"\tlist scopes '*'\n\tlist mfa_tools '*'\n\toption mfa_factor 'pin'\n\toption approval 'appr'\n"

const apPIN = "4821"

type apRig struct {
	t                         *testing.T
	s                         *Server
	cfgFile, state, cfgDir    string
	fix, ctl, log, copy, ubus string
}

// newApRig builds the router and the daemon. approval replaces the approval section when it is
// not empty (pass apApproval plus extra options to change one).
func newApRig(t *testing.T, approval string) *apRig {
	t.Helper()
	root := t.TempDir()
	r := &apRig{t: t, state: filepath.Join(root, "state"), cfgDir: filepath.Join(root, "etc-config"),
		fix: filepath.Join(root, "fix"), ctl: filepath.Join(root, "ctl"),
		log: filepath.Join(root, "uci.log"), copy: filepath.Join(root, "uci-copy.log"),
		ubus: filepath.Join(root, "ubus.log"), cfgFile: filepath.Join(root, "config")}
	for _, d := range []string{r.cfgDir, filepath.Join(r.fix, "now"), filepath.Join(r.fix, "after"), r.ctl,
		filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range apNow {
		r.writeConfig(name, name+" as the router has it\n")
		r.setNow(name, body)
	}
	uci := `#!/bin/sh
dir=""
while [ $# -gt 0 ]; do
	case "$1" in
		-c) dir=$2; shift 2 ;;
		-P|-p|-t) shift 2 ;;
		-X|-q|-n|-N) shift ;;
		*) break ;;
	esac
done
case "$1" in
	changes) [ -e "` + r.ctl + `/dirty" ] && echo "network.lan.ipaddr='9.9.9.9'"; exit 0 ;;
	show)
		f="` + r.fix + `/now/$2"
		if [ -n "$dir" ] && [ "$(basename "$dir")" = after ] && [ -f "` + r.fix + `/after/$2" ]; then f="` + r.fix + `/after/$2"; fi
		[ -f "$f" ] && cat "$f"
		exit 0 ;;
esac
if [ -n "$dir" ]; then
	echo "$*" >> "` + r.copy + `"
	[ -e "` + r.ctl + `/fail-copy" ] && { echo "uci: Invalid argument" >&2; exit 1; }
	exit 0
fi
echo "$*" >> "` + r.log + `"
exit 0
`
	ubus := `#!/bin/sh
echo "$*" >> "` + r.ubus + `"
echo '{}'
`
	for name, body := range map[string]string{"uci": uci, "ubus": ubus} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := uciConfigDir
	uciConfigDir = r.cfgDir
	t.Cleanup(func() { uciConfigDir = old })

	if approval == "" {
		approval = apApproval
	}
	body := "config server\n\toption audit '" + filepath.Join(r.state, "audit.jsonl") + "'\n" + approval + apPolicies
	if err := os.WriteFile(r.cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r.s = r.start()
	if err := r.s.mfa.pins.Set("a", apPIN); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.s.mfa.Enrol("a", "openwrt-mcp", "gate"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.tokens.Mint("owner"); err != nil {
		t.Fatal(err)
	}
	return r
}

// start is a daemon over the rig's config and state, as a restart would make one.
func (r *apRig) start() *Server {
	r.t.Helper()
	s, err := NewServer(r.cfgFile, r.state)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() {
		s.mu.Lock()
		for _, p := range s.pending {
			if p.timer != nil {
				p.timer.Stop()
			}
		}
		s.mu.Unlock()
	})
	return s
}

func (r *apRig) writeConfig(name, body string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.cfgDir, name), []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *apRig) setNow(name, show string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.fix, "now", name), []byte(show), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// setAfter is the state the change would leave in one config. Configs not set stay as they are.
func (r *apRig) setAfter(name, show string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.fix, "after", name), []byte(show), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *apRig) clearAfter() {
	r.t.Helper()
	es, _ := os.ReadDir(filepath.Join(r.fix, "after"))
	for _, e := range es {
		os.Remove(filepath.Join(r.fix, "after", e.Name()))
	}
}

// staged is every call that changed the router itself: anything sent to uci without -c, but reads.
func (r *apRig) staged() []string {
	r.t.Helper()
	b, _ := os.ReadFile(r.log)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ubusCalls is every ubus call but the reload uci_apply makes after a commit.
func (r *apRig) ubusCalls() []string {
	r.t.Helper()
	b, _ := os.ReadFile(r.ubus)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (r *apRig) unlock() {
	r.t.Helper()
	if _, err := r.s.mfa.Attempt("a", unlockAttempt{PIN: apPIN}, r.s.unlockPolicyFor("a"), time.Now()); err != nil {
		r.t.Fatalf("could not open a's window: %v", err)
	}
}

func (r *apRig) code(at time.Time) string { return codeNow(r.t, r.s.mfa, "a", at) }

func (r *apRig) apply(changes ...map[string]any) (string, bool) {
	r.t.Helper()
	return callTool(r.t, r.s, "a", "uci_apply", map[string]any{"changes": changes, "timeout": 600})
}

func (r *apRig) ubusCall(object, method string, args map[string]any) (string, bool) {
	r.t.Helper()
	in := map[string]any{"object": object, "method": method}
	if args != nil {
		in["args"] = args
	}
	return callTool(r.t, r.s, "a", "ubus_call", in)
}

var heldLine = regexp.MustCompile(`^HELD ([A-Z]{5}) until (\S+)`)

// mustHold asserts the answer is a hold and nothing ran, and returns the id.
func (r *apRig) mustHold(out string, isErr bool) string {
	r.t.Helper()
	m := heldLine.FindStringSubmatch(out)
	if isErr || m == nil {
		r.t.Fatalf("not held: %q (error=%v)", out, isErr)
	}
	if _, err := time.Parse(time.RFC3339, m[2]); err != nil {
		r.t.Errorf("the hold does not say when it expires as a time: %q", m[2])
	}
	if st := r.staged(); len(st) != 0 {
		r.t.Fatalf("a held change touched the router: %q", st)
	}
	for _, c := range r.ubusCalls() {
		if !strings.HasPrefix(c, "call uci reload_config") {
			r.t.Fatalf("a held change reached ubus: %q", c)
		}
	}
	return m[1]
}

type apAction struct {
	ID       string `json:"id"`
	Client   string `json:"client"`
	Tool     string `json:"tool"`
	Status   string `json:"status"`
	Hash     string `json:"hash"`
	Ref      string `json:"ref"`
	Headline string `json:"headline"`
	Card     string `json:"card"`
	Expires  string `json:"expires"`
	Result   string `json:"result"`
}

func decodeActions(t *testing.T, out string) []apAction {
	t.Helper()
	var v struct {
		Actions []apAction `json:"actions"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not the actions JSON: %v\n%s", err, out)
	}
	return v.Actions
}

// list is what the owner's client sees.
func (r *apRig) list() []apAction {
	r.t.Helper()
	out, isErr := callTool(r.t, r.s, "owner", "action_list", map[string]any{})
	if isErr {
		r.t.Fatalf("action_list: %s", out)
	}
	return decodeActions(r.t, out)
}

func (r *apRig) action(id string) apAction {
	r.t.Helper()
	for _, a := range r.list() {
		if a.ID == id {
			return a
		}
	}
	r.t.Fatalf("%s is not in the owner's list", id)
	return apAction{}
}

// status is what the agent's own client sees.
func (r *apRig) status(id string) apAction {
	r.t.Helper()
	out, isErr := callTool(r.t, r.s, "a", "action_status", map[string]any{})
	if isErr {
		r.t.Fatalf("action_status: %s", out)
	}
	for _, a := range decodeActions(r.t, out) {
		if a.ID == id {
			return a
		}
	}
	r.t.Fatalf("%s is not in the agent's own status: %s", id, out)
	return apAction{}
}

func (r *apRig) approve(as, id, hash, pin, code string) (string, bool) {
	r.t.Helper()
	return callTool(r.t, r.s, as, "action_approve", map[string]any{"id": id, "hash": hash, "pin": pin, "code": code})
}

func (r *apRig) failures() int { return r.s.mfa.State("a", time.Now()).Failures }

// The port forward the design opens with: tcp 2222 from anywhere to a NAS's SSH.
var portForward = []map[string]any{
	{"config": "firewall", "section": "ssh_nas", "type": "redirect"},
	{"config": "firewall", "section": "ssh_nas", "option": "name", "value": "ssh_nas"},
	{"config": "firewall", "section": "ssh_nas", "option": "src", "value": "wan"},
	{"config": "firewall", "section": "ssh_nas", "option": "src_dport", "value": "2222"},
	{"config": "firewall", "section": "ssh_nas", "option": "proto", "value": "tcp"},
	{"config": "firewall", "section": "ssh_nas", "option": "dest", "value": "lan"},
	{"config": "firewall", "section": "ssh_nas", "option": "dest_ip", "value": "192.168.1.20"},
	{"config": "firewall", "section": "ssh_nas", "option": "dest_port", "value": "22"},
}

const portForwardAfter = apFirewall +
	"firewall.ssh_nas=redirect\n" +
	"firewall.ssh_nas.name='ssh_nas'\n" +
	"firewall.ssh_nas.src='wan'\n" +
	"firewall.ssh_nas.src_dport='2222'\n" +
	"firewall.ssh_nas.proto='tcp'\n" +
	"firewall.ssh_nas.dest='lan'\n" +
	"firewall.ssh_nas.dest_ip='192.168.1.20'\n" +
	"firewall.ssh_nas.dest_port='22'\n"

// holdPortForward makes the port forward held and returns its id.
func (r *apRig) holdPortForward() string {
	r.t.Helper()
	r.setAfter("firewall", portForwardAfter)
	out, isErr := r.apply(portForward...)
	return r.mustHold(out, isErr)
}

func replaceLine(show, old, new string) string {
	if !strings.Contains(show, old) {
		panic("fixture has no " + old)
	}
	return strings.Replace(show, old, new, 1)
}

type apCase struct {
	name     string
	after    map[string]string // config -> state after
	changes  []map[string]any  // for uci_apply
	ubus     []any             // object, method, args for ubus_call
	headline string
}

func tier3Cases() []apCase {
	return []apCase{
		{name: "a port forward from the internet", after: map[string]string{"firewall": portForwardAfter},
			changes: portForward, headline: "OPENS THE ROUTER TO THE INTERNET: tcp 2222 from any address to 192.168.1.20:22"},
		{name: "a rule that accepts from the internet", after: map[string]string{"firewall": apFirewall +
			"firewall.web=rule\nfirewall.web.src='wan'\nfirewall.web.proto='tcp'\nfirewall.web.dest_port='8443'\nfirewall.web.target='ACCEPT'\n"},
			changes: []map[string]any{{"config": "firewall", "section": "web", "type": "rule"},
				{"config": "firewall", "section": "web", "option": "src", "value": "wan"},
				{"config": "firewall", "section": "web", "option": "proto", "value": "tcp"},
				{"config": "firewall", "section": "web", "option": "dest_port", "value": "8443"},
				{"config": "firewall", "section": "web", "option": "target", "value": "ACCEPT"}},
			headline: "OPENS THE ROUTER TO THE INTERNET: tcp 8443 from any address to the router"},
		{name: "the internet zone accepts what comes in", after: map[string]string{"firewall": replaceLine(apFirewall,
			"firewall.cfg03dc81.input='REJECT'", "firewall.cfg03dc81.input='ACCEPT'")},
			changes:  []map[string]any{{"config": "firewall", "section": "@zone[1]", "option": "input", "value": "ACCEPT"}},
			headline: "WEAKENS THE FIREWALL: zone 'wan' accepts what comes in from the internet"},
		{name: "forwarding from the internet", after: map[string]string{"firewall": apFirewall +
			"firewall.wan_lan=forwarding\nfirewall.wan_lan.src='wan'\nfirewall.wan_lan.dest='lan'\n"},
			changes: []map[string]any{{"config": "firewall", "section": "wan_lan", "type": "forwarding"},
				{"config": "firewall", "section": "wan_lan", "option": "src", "value": "wan"},
				{"config": "firewall", "section": "wan_lan", "option": "dest", "value": "lan"}},
			headline: "WEAKENS THE FIREWALL: zone 'wan' forwards from the internet to zone 'lan'"},
		{name: "a WireGuard interface", after: map[string]string{"network": apNetwork +
			"network.wg0=interface\nnetwork.wg0.proto='wireguard'\nnetwork.wg0.addresses='10.9.0.1/24'\n"},
			changes: []map[string]any{{"config": "network", "section": "wg0", "type": "interface"},
				{"config": "network", "section": "wg0", "option": "proto", "value": "wireguard"},
				{"config": "network", "section": "wg0", "option": "addresses", "value": "10.9.0.1/24"}},
			headline: "CHANGES VPN OR POLICY ROUTING: network.wg0"},
		{name: "a default route", after: map[string]string{"network": apNetwork +
			"network.r0=route\nnetwork.r0.interface='guest'\nnetwork.r0.target='0.0.0.0/0'\n"},
			changes: []map[string]any{{"config": "network", "section": "r0", "type": "route"},
				{"config": "network", "section": "r0", "option": "interface", "value": "guest"},
				{"config": "network", "section": "r0", "option": "target", "value": "0.0.0.0/0"}},
			headline: "CHANGES VPN OR POLICY ROUTING: every destination through 'guest'"},
		{name: "policy routing", after: map[string]string{"pbr": replaceLine(apPBR, "enabled='0'", "enabled='1'")},
			changes:  []map[string]any{{"config": "pbr", "section": "config", "option": "enabled", "value": "1"}},
			headline: "CHANGES VPN OR POLICY ROUTING: pbr"},
		{name: "an upstream DNS server", after: map[string]string{"dhcp": apDHCP + "dhcp.cfg01411c.server='9.9.9.9'\n"},
			changes:  []map[string]any{{"config": "dhcp", "section": "@dnsmasq[0]", "option": "server", "value": "9.9.9.9"}},
			headline: "CHANGES WHO ANSWERS DNS: dhcp.@dnsmasq[0].server"},
		{name: "rebind protection off", after: map[string]string{"dhcp": replaceLine(apDHCP,
			"rebind_protection='1'", "rebind_protection='0'")},
			changes:  []map[string]any{{"config": "dhcp", "section": "@dnsmasq[0]", "option": "rebind_protection", "value": "0"}},
			headline: "CHANGES WHO ANSWERS DNS: dhcp.@dnsmasq[0].rebind_protection"},
		{name: "a name with a dot answered locally", after: map[string]string{"dhcp": apDHCP +
			"dhcp.bank=domain\ndhcp.bank.name='bank.example.com'\ndhcp.bank.ip='192.168.1.66'\n"},
			changes: []map[string]any{{"config": "dhcp", "section": "bank", "type": "domain"},
				{"config": "dhcp", "section": "bank", "option": "name", "value": "bank.example.com"},
				{"config": "dhcp", "section": "bank", "option": "ip", "value": "192.168.1.66"}},
			headline: "CHANGES WHO ANSWERS DNS: dhcp.bank"},
		{name: "an interface's DNS servers", after: map[string]string{"network": replaceLine(apNetwork,
			"network.wan.proto='dhcp'\n", "network.wan.proto='dhcp'\nnetwork.wan.dns='9.9.9.9'\n")},
			changes:  []map[string]any{{"config": "network", "section": "wan", "option": "dns", "value": "9.9.9.9"}},
			headline: "CHANGES WHO ANSWERS DNS: network.wan.dns"},
		{name: "the time servers", after: map[string]string{"system": replaceLine(apSystem,
			"system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'", "system.ntp.server='time.example.net'")},
			changes:  []map[string]any{{"config": "system", "section": "ntp", "option": "server", "value": "time.example.net"}},
			headline: "CHANGES THE ROUTER'S TIME SERVERS: system.ntp"},
		{name: "the home Wi-Fi without a password", after: map[string]string{"wireless": replaceLine(apWireless,
			"encryption='sae-mixed'", "encryption='none'")},
			changes:  []map[string]any{{"config": "wireless", "section": "default_radio0", "option": "encryption", "value": "none"}},
			headline: "OPENS WI-FI WITHOUT A PASSWORD INTO A TRUSTED NETWORK: 'Home' into zone 'lan'"},
		{name: "the guest zone trusted while its Wi-Fi is open", after: map[string]string{"firewall": replaceLine(apFirewall,
			"firewall.guest.input='REJECT'", "firewall.guest.input='ACCEPT'")},
			changes:  []map[string]any{{"config": "firewall", "section": "guest", "option": "input", "value": "ACCEPT"}},
			headline: "OPENS WI-FI WITHOUT A PASSWORD INTO A TRUSTED NETWORK: 'Guests' into zone 'guest'"},
		{name: "the firewall stopped", ubus: []any{"rc", "init", map[string]any{"name": "firewall", "action": "stop"}},
			headline: "STOPS A SERVICE THAT GUARDS THE ROUTER: firewall (stop)"},
		{name: "dropbear disabled", ubus: []any{"rc", "init", map[string]any{"name": "dropbear", "action": "disable"}},
			headline: "STOPS A SERVICE THAT GUARDS THE ROUTER: dropbear (disable)"},
		{name: "a reboot", ubus: []any{"system", "reboot", nil}, headline: "REBOOTS THE ROUTER"},
	}
}

// The candidates, one by one, with the window open: none runs, every one is held and audited HELD.
func TestTier3HeldWithWindowOpen(t *testing.T) {
	for _, c := range tier3Cases() {
		t.Run(c.name, func(t *testing.T) {
			r := newApRig(t, "")
			r.unlock()
			for name, show := range c.after {
				r.setAfter(name, show)
			}
			var out string
			var isErr bool
			if c.ubus != nil {
				args, _ := c.ubus[2].(map[string]any)
				out, isErr = r.ubusCall(c.ubus[0].(string), c.ubus[1].(string), args)
			} else {
				out, isErr = r.apply(c.changes...)
			}
			id := r.mustHold(out, isErr)
			a := r.action(id)
			if !strings.Contains(a.Headline, c.headline) || !strings.Contains(a.Card, c.headline) {
				t.Errorf("headline %q, card:\n%s\nwant %q", a.Headline, a.Card, c.headline)
			}
			var audited bool
			for _, e := range auditEvents(t, r.state) {
				if e.Client == "a" && (e.Tool == "uci_apply" || e.Tool == "ubus_call") {
					audited = string(e.Outcome) == "HELD"
				}
			}
			if !audited {
				t.Errorf("the held call is not audited as HELD")
			}
		})
	}
}

// What a window is for still runs in one: a description, a static lease, a service restarted.
func TestTier2RunsInTheWindow(t *testing.T) {
	t.Run("the router's description", func(t *testing.T) {
		r := newApRig(t, "")
		r.unlock()
		r.setAfter("system", replaceLine(apSystem, "description='baseline'", "description='attic'"))
		out, isErr := r.apply(map[string]any{"config": "system", "section": "@system[0]", "option": "description", "value": "attic"})
		if isErr || !strings.Contains(out, "ROLLBACK ARMED") {
			t.Fatalf("not applied: %q (error=%v)", out, isErr)
		}
		if st := strings.Join(r.staged(), "\n"); !strings.Contains(st, "set system.@system[0].description=attic") ||
			!strings.Contains(st, "commit system") {
			t.Errorf("staged: %q", st)
		}
	})
	t.Run("a static lease", func(t *testing.T) {
		r := newApRig(t, "")
		r.unlock()
		r.setAfter("dhcp", apDHCP+"dhcp.pi=host\ndhcp.pi.name='pi'\ndhcp.pi.mac='88:a2:9e:8a:e4:15'\ndhcp.pi.ip='192.168.1.141'\n")
		out, isErr := r.apply(
			map[string]any{"config": "dhcp", "section": "pi", "type": "host"},
			map[string]any{"config": "dhcp", "section": "pi", "option": "name", "value": "pi"},
			map[string]any{"config": "dhcp", "section": "pi", "option": "mac", "value": "88:a2:9e:8a:e4:15"},
			map[string]any{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.168.1.141"})
		if isErr || !strings.Contains(out, "ROLLBACK ARMED") {
			t.Fatalf("not applied: %q (error=%v)", out, isErr)
		}
	})
	for _, svc := range []map[string]any{{"name": "dnsmasq", "action": "restart"}, {"name": "transmission", "action": "stop"}} {
		t.Run(fmt.Sprintf("rc.init %v %v", svc["name"], svc["action"]), func(t *testing.T) {
			r := newApRig(t, "")
			r.unlock()
			out, isErr := r.ubusCall("rc", "init", svc)
			if isErr || strings.HasPrefix(out, "HELD") {
				t.Fatalf("not run: %q (error=%v)", out, isErr)
			}
			if calls := strings.Join(r.ubusCalls(), "\n"); !strings.Contains(calls, "call rc init") {
				t.Errorf("ubus was not called: %q", calls)
			}
		})
	}
}

// A port forward made disabled first and switched on next: the second call alone says only
// "enabled=1", and it is the state it leaves that holds it.
func TestSplitRedirectHeldOnSecondCall(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	disabled := portForwardAfter + "firewall.ssh_nas.enabled='0'\n"
	r.setAfter("firewall", disabled)
	out, isErr := r.apply(append(append([]map[string]any(nil), portForward...),
		map[string]any{"config": "firewall", "section": "ssh_nas", "option": "enabled", "value": "0"})...)
	if isErr || !strings.Contains(out, "ROLLBACK ARMED") {
		t.Fatalf("a disabled port forward was not applied: %q (error=%v)", out, isErr)
	}
	token := confirmToken(t, out)
	if out, isErr := callTool(t, r.s, "a", "uci_confirm", map[string]any{"token": token}); isErr {
		t.Fatalf("confirm: %s", out)
	}
	// The router now holds the disabled forward.
	r.setNow("firewall", disabled)
	r.writeConfig("firewall", "firewall with a disabled forward\n")
	r.clearAfter()
	r.setAfter("firewall", portForwardAfter+"firewall.ssh_nas.enabled='1'\n")
	os.Remove(r.log)
	out, isErr = r.apply(map[string]any{"config": "firewall", "section": "ssh_nas", "option": "enabled", "value": "1"})
	id := r.mustHold(out, isErr)
	if a := r.action(id); !strings.Contains(a.Headline, "OPENS THE ROUTER TO THE INTERNET") {
		t.Errorf("headline %q", a.Headline)
	}
}

// The internet port put into the LAN bridge, the bridge's ports written as one string: a change to
// a device's ports, held as rewiring whatever the port is.
func TestWanPortIntoLanBridgeHeld(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("network", replaceLine(apNetwork, "network.cfg030f15.ports='lan1' 'lan2' 'lan3'",
		"network.cfg030f15.ports='lan1 lan2 lan3 wan'"))
	out, isErr := r.apply(map[string]any{"config": "network", "section": "@device[0]", "option": "ports", "value": "lan1 lan2 lan3 wan"})
	id := r.mustHold(out, isErr)
	if a := r.action(id); !strings.Contains(a.Headline, "REWIRES THE NETWORK: device 'br-lan' takes 'lan1', 'lan2', 'lan3' -> 'lan1', 'lan2', 'lan3', 'wan'") {
		t.Errorf("headline %q", a.Headline)
	}
}

// Renaming the internet zone changes which zone faces the internet, whatever the rules say.
func TestZoneRenameHeld(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("firewall", replaceLine(apFirewall, "firewall.cfg03dc81.name='wan'", "firewall.cfg03dc81.name='outside'"))
	out, isErr := r.apply(map[string]any{"config": "firewall", "section": "@zone[1]", "option": "name", "value": "outside"})
	id := r.mustHold(out, isErr)
	if a := r.action(id); !strings.Contains(a.Headline, "WEAKENS THE FIREWALL: the zones that face the internet change") {
		t.Errorf("headline %q", a.Headline)
	}
}

// A state that cannot be read (an option of a section with no type) is not a state to approve
// blind: it waits for the owner, and says why.
func TestUnreadableTypeHeld(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("firewall", apFirewall+"firewall.ghost.src='wan'\n")
	out, isErr := r.apply(map[string]any{"config": "firewall", "section": "@rule[0]", "option": "name", "value": "renamed"})
	id := r.mustHold(out, isErr)
	if a := r.action(id); !strings.Contains(a.Headline, "COULD NOT BE CHECKED") {
		t.Errorf("headline %q", a.Headline)
	}
}

func confirmToken(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, `"token": "`)
	if i < 0 {
		t.Fatalf("no confirm token in %q", out)
	}
	rest := out[i+len(`"token": "`):]
	return rest[:strings.Index(rest, `"`)]
}

// The card is the daemon's, from the record: the headline from parsed values, every changed key
// before and after, secrets redacted, the agent's strings quoted and escaped.
func TestCardIsWhatIsApplied(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("firewall", replaceLine(portForwardAfter, "firewall.ssh_nas.name='ssh_nas'",
		"firewall.ssh_nas.name='nas\u202e'\\''x'"))
	r.setAfter("wireless", replaceLine(apWireless, "key='HOME-WIFI-KEY-CANARY'", "key='NEW-WIFI-KEY-CANARY'"))
	changes := append([]map[string]any(nil), portForward...)
	changes[1] = map[string]any{"config": "firewall", "section": "ssh_nas", "option": "name", "value": "nas\u202e'x"}
	changes = append(changes, map[string]any{"config": "wireless", "section": "default_radio0", "option": "key", "value": "NEW-WIFI-KEY-CANARY"})
	out, isErr := r.apply(changes...)
	id := r.mustHold(out, isErr)
	a := r.action(id)
	for _, want := range []string{
		"OPENS THE ROUTER TO THE INTERNET: tcp 2222 from any address to 192.168.1.20:22",
		"firewall.ssh_nas, new redirect",
		"+ src 'wan'", "+ src_dport '2222'", "+ dest_ip '192.168.1.20'", "+ dest_port '22'",
		`+ name 'nas\u202e\'x'`,
		"wireless.default_radio0", "key <redacted> -> <redacted>",
		id, a.Ref,
	} {
		if !strings.Contains(a.Card, want) {
			t.Errorf("the card lacks %q:\n%s", want, a.Card)
		}
	}
	if strings.Contains(a.Card, "\u202e") {
		t.Errorf("an unprintable character the agent chose reached the card raw:\n%s", a.Card)
	}
	for _, where := range []string{a.Card, out} {
		if strings.Contains(where, "CANARY") {
			t.Errorf("a Wi-Fi key reached the card or the agent:\n%s", where)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(r.state, "audit.jsonl")); strings.Contains(string(b), "CANARY") {
		t.Errorf("a Wi-Fi key reached the audit log")
	}
	if len(a.Hash) != 64 || !strings.HasPrefix(a.Hash, a.Ref) || len(a.Ref) != 8 {
		t.Errorf("hash %q and ref %q: want 64 hex and its first 8", a.Hash, a.Ref)
	}
}

// A card too long for one message is refused, never cut short: what the owner approves is all of it.
func TestCardOverTheLimitIsRefused(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	after := portForwardAfter
	changes := append([]map[string]any(nil), portForward...)
	for i := 0; i < 60; i++ {
		v := strings.Repeat("x", 60)
		after += fmt.Sprintf("firewall.ssh_nas.extra_%02d='%s'\n", i, v)
		changes = append(changes, map[string]any{"config": "firewall", "section": "ssh_nas", "option": fmt.Sprintf("extra_%02d", i), "value": v})
	}
	r.setAfter("firewall", after)
	out, isErr := r.apply(changes...)
	if !isErr || !strings.Contains(out, "too long to show the owner") {
		t.Fatalf("an oversized card was not refused: %q (error=%v)", out, isErr)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if l := r.list(); len(l) != 0 {
		t.Errorf("a record was kept: %+v", l)
	}
}

func TestApproveAppliesExactlyTheHeldBatch(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now()))
	if isErr || !strings.Contains(out, "Applied") {
		t.Fatalf("approve: %q (error=%v)", out, isErr)
	}
	want := []string{"set firewall.ssh_nas=redirect", "set firewall.ssh_nas.name=ssh_nas", "set firewall.ssh_nas.src=wan",
		"set firewall.ssh_nas.src_dport=2222", "set firewall.ssh_nas.proto=tcp", "set firewall.ssh_nas.dest=lan",
		"set firewall.ssh_nas.dest_ip=192.168.1.20", "set firewall.ssh_nas.dest_port=22", "commit firewall"}
	if got := r.staged(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("applied:\n%s\nwant exactly:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	r.s.mu.Lock()
	var deadline time.Time
	for _, p := range r.s.pending {
		deadline = p.Deadline
	}
	r.s.mu.Unlock()
	if d := time.Until(deadline); d < 290*time.Second || d > 300*time.Second {
		t.Errorf("rollback in %v, want 300 s", d)
	}
	st := r.status(id)
	if st.Status != "applied" || !strings.Contains(st.Result, `uci_confirm {"token": "`) {
		t.Fatalf("the agent reads %+v", st)
	}
	// The agent confirms after its check, without an unlock: the owner's approval was the consent.
	if out, isErr := callTool(t, r.s, "a", "uci_confirm", map[string]any{"token": confirmToken(t, st.Result)}); isErr {
		t.Errorf("the agent could not confirm the approved change: %s", out)
	}
}

func TestApproveNeverOpensWindow(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	if out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now())); isErr {
		t.Fatalf("approve: %s", out)
	}
	if st := r.s.mfa.State("a", time.Now()); !st.UnlockedUntil.IsZero() {
		t.Errorf("approving opened the window: %+v", st)
	}
	r.clearAfter()
	out, isErr := r.apply(map[string]any{"config": "system", "section": "@system[0]", "option": "description", "value": "x"})
	if !isErr || !strings.Contains(out, "second factor") {
		t.Errorf("an ordinary change ran without an unlock after an approval: %q", out)
	}
}

func TestApproveRefusesAnotherHash(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	other := strings.Repeat("0", 64)
	if other == a.Hash {
		other = strings.Repeat("1", 64)
	}
	for _, h := range []string{other, a.Hash[:16], ""} {
		out, isErr := r.approve("owner", id, h, apPIN, r.code(time.Now()))
		if !isErr || !strings.Contains(out, "hash") {
			t.Errorf("approved with hash %q: %q (error=%v)", h, out, isErr)
		}
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if n := r.failures(); n != 0 {
		t.Errorf("a refused precondition counted %d tries", n)
	}
	if r.action(id).Status != "held" {
		t.Errorf("the record changed")
	}
}

func TestAgentClientCannotApprove(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	if out, isErr := r.approve("a", id, a.Hash, apPIN, r.code(time.Now())); !isErr || !strings.Contains(out, "only the owner's client") {
		t.Errorf("the agent's client approved its own change: %q (error=%v)", out, isErr)
	}
	for _, tool := range []string{"action_list", "action_reject"} {
		if out, isErr := callTool(t, r.s, "a", tool, map[string]any{"id": id}); !isErr {
			t.Errorf("the agent's client called %s: %q", tool, out)
		}
	}
	if out, isErr := callTool(t, r.s, "stranger", "action_list", map[string]any{}); !isErr {
		t.Errorf("a client that approves nothing listed the cards: %q", out)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if n := r.failures(); n != 0 {
		t.Errorf("the agent spent %d of the owner's tries", n)
	}
}

func TestAgentCannotUnlockItself(t *testing.T) {
	r := newApRig(t, "")
	out, isErr := callTool(t, r.s, "a", "mfa_unlock", map[string]any{"pin": apPIN})
	if !isErr || !strings.Contains(out, "owner") {
		t.Errorf("the agent's client unlocked itself: %q (error=%v)", out, isErr)
	}
	if n := r.failures(); n != 0 {
		t.Errorf("the agent spent %d of the owner's tries", n)
	}
	if st := r.s.mfa.State("a", time.Now()); !st.UnlockedUntil.IsZero() {
		t.Fatalf("the window is open: %+v", st)
	}
	out, isErr = callTool(t, r.s, "owner", "mfa_unlock", map[string]any{"client": "a", "pin": apPIN})
	if isErr || !strings.Contains(out, "Unlocked until") {
		t.Fatalf("the owner's client could not open a's window: %q (error=%v)", out, isErr)
	}
	if st := r.s.mfa.State("a", time.Now()); st.UnlockedUntil.IsZero() {
		t.Errorf("a's window is still closed")
	}
	if st := r.s.mfa.State("owner", time.Now()); !st.UnlockedUntil.IsZero() {
		t.Errorf("the owner's own window was opened instead")
	}
	// A client that approves nothing cannot open another's window.
	if out, isErr := callTool(t, r.s, "stranger", "mfa_unlock", map[string]any{"client": "a", "pin": apPIN}); !isErr {
		t.Errorf("a stranger opened a's window: %q", out)
	}
}

// A code approves once: the TOTP step it belongs to is spent for the client, as an unlock spends it.
func TestApproveStepSpent(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	code := r.code(time.Now())
	out, isErr := r.approve("owner", id, r.action(id).Hash, apPIN, code)
	if isErr {
		t.Fatalf("approve: %s", out)
	}
	if out, isErr := callTool(t, r.s, "a", "uci_confirm", map[string]any{"token": confirmToken(t, r.status(id).Result)}); isErr {
		t.Fatalf("confirm: %s", out)
	}
	os.Remove(r.log)
	r.clearAfter()
	second := r.holdPortForward()
	out, isErr = r.approve("owner", second, r.action(second).Hash, apPIN, code)
	if !isErr {
		t.Fatalf("the same code approved a second change: %q", out)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
}

func TestApproveRefusedAfterDrift(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	r.writeConfig("firewall", "firewall edited in LuCI since\n")
	out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now()))
	if !isErr || !strings.Contains(out, "changed since") {
		t.Errorf("approved over a changed config: %q (error=%v)", out, isErr)
	}
	// Refused before the factors are asked: the change still waits, for the owner to reject.
	if st := r.action(id).Status; st != "held" {
		t.Errorf("after a refusal for drift the change is %q, not still held", st)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if n := r.failures(); n != 0 {
		t.Errorf("a refused precondition counted %d tries", n)
	}
}

func TestApproveRefusedWhileAnApplyAwaitsConfirmation(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("system", replaceLine(apSystem, "description='baseline'", "description='attic'"))
	if out, isErr := r.apply(map[string]any{"config": "system", "section": "@system[0]", "option": "description", "value": "attic"}); isErr {
		t.Fatalf("ordinary apply: %s", out)
	}
	staged := len(r.staged())
	id := func() string {
		r.setAfter("firewall", portForwardAfter)
		out, isErr := r.apply(portForward...)
		m := heldLine.FindStringSubmatch(out)
		if isErr || m == nil {
			t.Fatalf("not held: %q", out)
		}
		return m[1]
	}()
	out, isErr := r.approve("owner", id, r.action(id).Hash, apPIN, r.code(time.Now()))
	if !isErr || !strings.Contains(out, "waits for confirmation") {
		t.Errorf("approved while another apply waits: %q (error=%v)", out, isErr)
	}
	if got := len(r.staged()); got != staged {
		t.Errorf("the held change was staged: %q", r.staged())
	}
	if n := r.failures(); n != 0 {
		t.Errorf("a refused precondition counted %d tries", n)
	}
}

func TestRejectIsOneTapAndCostsNoTry(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	out, isErr := callTool(t, r.s, "owner", "action_reject", map[string]any{"id": id})
	if isErr || !strings.Contains(out, "Rejected") {
		t.Fatalf("reject: %q (error=%v)", out, isErr)
	}
	if st := r.status(id); st.Status != "rejected" {
		t.Errorf("the agent reads %q", st.Status)
	}
	if out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now())); !isErr {
		t.Errorf("a rejected change was approved: %q", out)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if n := r.failures(); n != 0 {
		t.Errorf("rejecting counted %d tries", n)
	}
}

func TestLockRejectsEveryHeld(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	if out, isErr := callTool(t, r.s, "owner", "mfa_lock", map[string]any{"client": "a"}); isErr {
		t.Fatalf("lock: %s", out)
	}
	if st := r.status(id); st.Status != "rejected" {
		t.Errorf("after the owner's lock the agent reads %q", st.Status)
	}
}

func TestHeldExpires(t *testing.T) {
	r := newApRig(t, apApproval+"\toption ttl '2s'\n")
	id := r.holdPortForward()
	a := r.action(id)
	time.Sleep(2500 * time.Millisecond)
	out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now()))
	if !isErr || !strings.Contains(out, "expired") {
		t.Errorf("an expired change: %q (error=%v)", out, isErr)
	}
	if st := r.status(id); st.Status != "expired" {
		t.Errorf("the agent reads %q", st.Status)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
}

func TestRestartDropsHeld(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	r.s = r.start()
	if l := r.list(); len(l) != 0 {
		t.Errorf("a restarted daemon still holds %+v", l)
	}
	if out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now())); !isErr {
		t.Errorf("approved after a restart: %q", out)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
}

func TestOneOpenPerClient(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	out, isErr := r.ubusCall("system", "reboot", nil)
	if !isErr || !strings.Contains(out, id) {
		t.Errorf("a second proposal while %s waits: %q (error=%v)", id, out, isErr)
	}
	if l := r.list(); len(l) != 1 {
		t.Errorf("%d records, want 1", len(l))
	}
	for _, c := range r.ubusCalls() {
		if strings.Contains(c, "reboot") {
			t.Errorf("ubus was called: %q", c)
		}
	}
}

func TestProposalsPerHourAreLimited(t *testing.T) {
	r := newApRig(t, apApproval+"\toption max_per_hour '2'\n")
	for i := 0; i < 2; i++ {
		id := r.holdPortForward()
		if out, isErr := callTool(t, r.s, "a", "action_withdraw", map[string]any{"id": id}); isErr {
			t.Fatalf("withdraw: %s", out)
		}
	}
	r.setAfter("firewall", portForwardAfter)
	out, isErr := r.apply(portForward...)
	if !isErr || !strings.Contains(out, "an hour") {
		t.Errorf("a third proposal in the hour: %q (error=%v)", out, isErr)
	}
}

func TestProposalsPauseAfterRejections(t *testing.T) {
	r := newApRig(t, apApproval+"\toption pause_after_rejects '2'\n")
	for i := 0; i < 2; i++ {
		id := r.holdPortForward()
		if out, isErr := callTool(t, r.s, "owner", "action_reject", map[string]any{"id": id}); isErr {
			t.Fatalf("reject: %s", out)
		}
	}
	r.setAfter("firewall", portForwardAfter)
	out, isErr := r.apply(portForward...)
	if !isErr || !strings.Contains(out, "paused") {
		t.Errorf("a proposal after two rejections: %q (error=%v)", out, isErr)
	}
}

// What only a person may do: refused with the window open and a grant of everything.
func TestHumanOnlyRefusedWhateverTheGrant(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	marker := filepath.Join(t.TempDir(), "ran")
	fakeCmd(t, "touch-marker", "touch "+marker)
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"exec", map[string]any{"argv": []string{"touch-marker"}}},
		{"wg_new_client", map[string]any{"name": "phone"}},
		{"uci_apply", map[string]any{"changes": []map[string]any{{"config": "hermes", "section": "main", "option": "profile", "value": "root"}}}},
		{"uci_apply", map[string]any{"changes": []map[string]any{{"config": "openwrt-mcp", "section": "x", "type": "policy"}}}},
		{"uci_apply", map[string]any{"changes": []map[string]any{{"config": "dropbear", "section": "@dropbear[0]", "option": "PasswordAuth", "value": "on"}}}},
		{"ubus_call", map[string]any{"object": "file", "method": "exec", "args": map[string]any{"command": "/bin/sh"}}},
		{"ubus_call", map[string]any{"object": "system", "method": "sysupgrade", "args": map[string]any{"path": "/tmp/fw.bin"}}},
		{"ubus_call", map[string]any{"object": "system", "method": "signal", "args": map[string]any{"pid": 1, "signum": 9}}},
		{"ubus_call", map[string]any{"object": "service", "method": "set", "args": map[string]any{"name": "x"}}},
		{"ubus_call", map[string]any{"object": "uci", "method": "set", "args": map[string]any{"config": "firewall"}}},
		{"ubus_call", map[string]any{"object": "rpc-sys", "method": "packagelist"}},
	}
	for _, c := range cases {
		for _, name := range []string{"hermes", "openwrt-mcp", "dropbear"} {
			r.writeConfig(name, name+"\n")
		}
		out, isErr := callTool(t, r.s, "a", c.tool, c.args)
		if !isErr || !strings.Contains(out, "only the owner may") {
			t.Errorf("%s %v: %q (error=%v)", c.tool, c.args, out, isErr)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("exec ran a command")
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if calls := r.ubusCalls(); len(calls) != 0 {
		t.Errorf("ubus was called: %q", calls)
	}
}

// A high-impact change with no way to approve it is refused, never run in the window instead.
func TestTier3RefusedUntilApprovalIsSetUp(t *testing.T) {
	for _, c := range []struct {
		name, approval, want string
		setup                func(r *apRig)
	}{
		{"approvals switched off", apApproval + "\toption approvals 'off'\n", "approval is switched off", nil},
		{"no app set up", "", "no authenticator app is set up", func(r *apRig) {
			os.Remove(filepath.Join(r.state, "mfa"))
			r.s = r.start()
		}},
		{"no PIN set", "", "no PIN is set", func(r *apRig) { r.s.mfa.pins.Clear("a") }},
		{"the owner's client not paired", "", "is not paired", func(r *apRig) { r.s.tokens.Revoke("owner") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The window stays closed: a proposal needs none, so what is asserted is the refusal
			// that comes before any hold.
			r := newApRig(t, c.approval)
			if c.setup != nil {
				c.setup(r)
			}
			r.setAfter("firewall", portForwardAfter)
			out, isErr := r.apply(portForward...)
			if !isErr || !strings.Contains(out, "refused") || !strings.Contains(out, c.want) {
				t.Errorf("%q (error=%v), want a refusal naming %q", out, isErr, c.want)
			}
			if st := r.staged(); len(st) != 0 {
				t.Errorf("staged %q", st)
			}
		})
	}
}

func TestApprovalConfigIsChecked(t *testing.T) {
	policy := func(extra string) string {
		return "\nconfig policy\n\toption client 'a'\n\tlist tools 'uci_apply'\n\tlist scopes '*'\n" + extra
	}
	bad := map[string]string{
		"a policy names a missing section": policy("\toption approval 'nope'\n"),
		"a policy names another client's section": "\nconfig approval 'appr'\n\toption client 'b'\n\toption approver 'owner'\n" +
			policy("\toption approval 'appr'\n"),
		"no approver":                                  "\nconfig approval 'appr'\n\toption client 'a'\n",
		"the client approves itself":                   "\nconfig approval 'appr'\n\toption client 'a'\n\toption approver 'a'\n",
		"a PIN alone":                                  apApproval + "\toption factor 'pin'\n",
		"no time to approve":                           apApproval + "\toption ttl '0s'\n",
		"max_open of zero":                             apApproval + "\toption max_open '0'\n",
		"approvals neither on nor off":                 apApproval + "\toption approvals 'maybe'\n",
		"two sections for one client":                  apApproval + "\nconfig approval 'second'\n\toption client 'a'\n\toption approver 'owner'\n",
		"a hold rule for no tool":                      apApproval + "\tlist hold 'nosuchtool:x'\n",
		"a hold policy for no client with an approval": policy("\toption hold '1'\n"),
	}
	for name, body := range bad {
		f := filepath.Join(t.TempDir(), "config")
		os.WriteFile(f, []byte(body), 0o600)
		if _, err := LoadConfig(f); err == nil {
			t.Errorf("%s: the configuration loaded", name)
		}
	}
	good := apApproval + "\toption factor 'pin+totp'\n\toption ttl '10m'\n\tlist hold 'ubus_call:system.reboot'\n" +
		policy("\toption approval 'appr'\n") + policy("\toption hold '1'\n\toption approval 'appr'\n")
	f := filepath.Join(t.TempDir(), "config")
	os.WriteFile(f, []byte(good), 0o600)
	if _, err := LoadConfig(f); err != nil {
		t.Errorf("a good configuration did not load: %v", err)
	}
}

func TestCLIStatusJSONSaysActionsHeldForApproval(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := c.run("", "status", "--json", "--audit", "0")
	if code != 0 {
		t.Fatalf("status: exit %d, %q %q", code, out, errOut)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	caps, _ := rep["capabilities"].(map[string]any)
	if caps["actions_held_for_approval"] != true {
		t.Errorf("capabilities = %v; a caller cannot tell that high-impact changes are held\n%s", rep["capabilities"], out)
	}
}

// An approval takes the PIN and a code, whatever the window's own factor is: the PIN alone opens
// this client's window, and it approves nothing.
func TestApproveNeedsPINAndCode(t *testing.T) {
	r := newApRig(t, "")
	id := r.holdPortForward()
	a := r.action(id)
	for _, c := range []struct{ pin, code string }{{apPIN, ""}, {"", r.code(time.Now())}, {"0000", r.code(time.Now())}} {
		if out, isErr := r.approve("owner", id, a.Hash, c.pin, c.code); !isErr {
			t.Fatalf("approved with pin %q and code %q: %q", c.pin, c.code, out)
		}
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if n := r.failures(); n != 3 {
		t.Errorf("%d tries counted, want 3: a wrong factor counts, as an unlock's does", n)
	}
	if out, isErr := r.approve("owner", id, a.Hash, apPIN, r.code(time.Now())); isErr {
		t.Errorf("the PIN and a code did not approve: %q", out)
	}
}

// Only a change the owner approved is confirmed without an unlock: one made in a window still
// needs the window to be confirmed.
func TestConfirmWithoutUnlockOnlyForApprovedChanges(t *testing.T) {
	r := newApRig(t, "")
	r.unlock()
	r.setAfter("system", replaceLine(apSystem, "description='baseline'", "description='attic'"))
	out, isErr := r.apply(map[string]any{"config": "system", "section": "@system[0]", "option": "description", "value": "attic"})
	if isErr {
		t.Fatalf("apply: %s", out)
	}
	r.s.mfa.Lock("a")
	out, isErr = callTool(t, r.s, "a", "uci_confirm", map[string]any{"token": confirmToken(t, out)})
	if !isErr || !strings.Contains(out, "second factor") {
		t.Errorf("a change made in a window was confirmed after the window closed: %q (error=%v)", out, isErr)
	}
}

// A policy with hold '1' grants calls that always wait, whatever the classifier makes of them.
func TestHoldPolicyHoldsWhatItGrants(t *testing.T) {
	approval := apApproval + "\nconfig policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist scopes 'network.reload'\n" +
		"\toption hold '1'\n\toption approval 'appr'\n"
	r := newApRig(t, approval)
	out, isErr := r.ubusCall("network", "reload", nil)
	id := r.mustHold(out, isErr)
	if a := r.action(id); !strings.Contains(a.Headline, "WAITS FOR YOUR APPROVAL BY POLICY: ubus_call network.reload") {
		t.Errorf("headline %q", a.Headline)
	}
}

// `list hold` and `list refuse` add to the built-in rules and take nothing away.
func TestApprovalRulesAddHoldsAndRefusals(t *testing.T) {
	r := newApRig(t, apApproval+"\tlist hold 'uci_apply:system.*.description'\n\tlist refuse 'ubus_call:network.restart'\n")
	r.unlock()
	r.setAfter("system", replaceLine(apSystem, "description='baseline'", "description='attic'"))
	out, isErr := r.apply(map[string]any{"config": "system", "section": "@system[0]", "option": "description", "value": "attic"})
	r.mustHold(out, isErr)
	if out, isErr := r.ubusCall("network", "restart", nil); !isErr || !strings.Contains(out, "for a person") {
		t.Errorf("a refuse rule did not refuse: %q (error=%v)", out, isErr)
	}
	if calls := r.ubusCalls(); len(calls) != 0 {
		t.Errorf("ubus was called: %q", calls)
	}
}

// A hold policy holds only what can be run once approved: a tool held that no approval can run
// would cost the owner a PIN and a code for nothing.
func TestHoldIsOnlyForWhatAnApprovalCanRun(t *testing.T) {
	for name, body := range map[string]string{
		"a hold policy granting apk_add": apApproval + "\nconfig policy\n\toption client 'a'\n\tlist tools 'apk_add'\n" +
			"\tlist scopes '*'\n\toption hold '1'\n\toption approval 'appr'\n",
		"a hold rule for apk_add": apApproval + "\tlist hold 'apk_add:*'\n",
	} {
		f := filepath.Join(t.TempDir(), "config")
		os.WriteFile(f, []byte(body), 0o600)
		if _, err := LoadConfig(f); err == nil {
			t.Errorf("%s: the configuration loaded", name)
		}
	}
	// A refuse rule for apk_add is fine: refusing needs nothing to run.
	f := filepath.Join(t.TempDir(), "config")
	os.WriteFile(f, []byte(apApproval+"\tlist refuse 'apk_add:*'\n"), 0o600)
	if _, err := LoadConfig(f); err != nil {
		t.Errorf("a refuse rule for apk_add did not load: %v", err)
	}
}

// The approver's client asks for the held changes every few seconds: an answered listing writes no
// audit line, and a refused one does.
func TestApproverListingIsNotAudited(t *testing.T) {
	r := newApRig(t, "")
	r.holdPortForward()
	before := len(auditEvents(t, r.state))
	for i := 0; i < 3; i++ {
		r.list()
	}
	if got := len(auditEvents(t, r.state)); got != before {
		t.Errorf("%d audit lines for three listings", got-before)
	}
	callTool(t, r.s, "stranger", "action_list", map[string]any{})
	events := auditEvents(t, r.state)
	if last := events[len(events)-1]; last.Tool != "action_list" || last.Outcome != OutcomeDenied {
		t.Errorf("a refused listing was not audited: %+v", last)
	}
}

// An edit that lands after the approval's checks and before the apply is caught by the apply
// itself: an approved change is staged only on the configs it was checked against.
func TestApprovedApplyRechecksTheConfigs(t *testing.T) {
	r := newApRig(t, "")
	r.holdPortForward()
	// The edit is made by uci's own `changes` call during the apply, the last step before staging.
	fakeCmd(t, "uci", `if [ "$1" = changes ]; then echo changed > "`+filepath.Join(r.cfgDir, "firewall")+`"; exit 0; fi
dir=""
while [ $# -gt 0 ]; do case "$1" in -c) dir=$2; shift 2 ;; -P) shift 2 ;; -X) shift ;; *) break ;; esac; done
[ "$1" = show ] && { cat "`+filepath.Join(r.fix, "now")+`/$2"; exit 0; }
echo "$*" >> "`+r.log+`"`)
	var id string
	for _, a := range r.list() {
		id = a.ID
	}
	out, isErr := r.approve("owner", id, r.action(id).Hash, apPIN, r.code(time.Now()))
	if !isErr || !strings.Contains(out, "changed since") {
		t.Errorf("an approved change was applied over a config edited during the approval: %q (error=%v)", out, isErr)
	}
	if st := r.staged(); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
}
