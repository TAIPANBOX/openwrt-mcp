package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What uci_apply does with a change that would make the router run a program as root. These go
// through the real tool handler, with a fake `uci` that logs every call it gets and answers
// `uci -X show <config>` from a fixture the way libuci prints it: a section as
// "config.section=type", an anonymous section under its cfgXXXXXX id because of -X.
//
// The property asserted is "nothing was staged": no `uci set`, no `uci delete`, no
// `uci commit`, no snapshot and no reload, because a refusal that stages half a batch and then
// reverts has already written the hook into /tmp/.uci for the next commit to pick up.

const noExecFirewall = "firewall.cfg01e63d=defaults\n" +
	"firewall.cfg01e63d.input='REJECT'\n" +
	"firewall.lan=zone\n" +
	"firewall.lan.name='lan'\n" +
	"firewall.cfg0a92bd=include\n" +
	"firewall.cfg0a92bd.path='/etc/firewall.user'\n" +
	"firewall.user_script=include\n" +
	"firewall.user_script.path='/etc/firewall.extra'\n" +
	"firewall.allow_ssh=rule\n" +
	"firewall.allow_ssh.name='Allow-SSH'\n"

const noExecDHCP = "dhcp.cfg01411c=dnsmasq\n" +
	"dhcp.cfg01411c.domain='lan'\n" +
	"dhcp.lan=dhcp\n" +
	"dhcp.lan.interface='lan'\n"

// noExecRig is the rollback rig with firewall and dhcp configs on disk, a policy that grants
// uci_apply on everything, and a uci that logs. It returns the server and the log's path.
func noExecRig(t *testing.T, failShow bool) (*rollbackRig, *Server, string) {
	t.Helper()
	r := newRollbackRig(t)
	for name, body := range map[string]string{"firewall": "original firewall\n", "dhcp": "original dhcp\n",
		"wireless": "original wireless\n"} {
		if err := os.WriteFile(filepath.Join(r.cfgDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fix := t.TempDir()
	for name, body := range map[string]string{"firewall": noExecFirewall, "dhcp": noExecDHCP} {
		if err := os.WriteFile(filepath.Join(fix, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(t.TempDir(), "uci.log")
	show := `[ -f "` + fix + `/$3" ] && exec cat "` + fix + `/$3"; exit 0`
	if failShow {
		show = `echo "uci: I/O error" >&2; exit 1`
	}
	fakeCmd(t, "uci", `echo "$*" >> "`+log+`"
if [ "$1" = -X ] && [ "$2" = show ]; then `+show+`; fi
exit 0`)
	r.extraConfig = "config policy\n\toption client 'a'\n\tlist tools 'uci_apply'\n\tlist scopes '*'\n"
	return r, r.server(t), log
}

// staged is every call that would have changed the router: anything but a read.
func staged(t *testing.T, log string) []string {
	t.Helper()
	b, _ := os.ReadFile(log)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" || l == "changes" || strings.HasPrefix(l, "-X show ") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func applyChanges(t *testing.T, s *Server, changes ...map[string]any) (string, bool) {
	t.Helper()
	return callTool(t, s, "a", "uci_apply", map[string]any{"changes": changes, "timeout": 600})
}

// assertRefusedUntouched is the whole contract of a refusal: the agent is told plainly which
// key and why, and the router is exactly as it was.
func assertRefusedUntouched(t *testing.T, r *rollbackRig, log, out string, isErr bool, key string) {
	t.Helper()
	want := "refused: " + key + " makes the router run code as root; openwrt-mcp never applies that"
	if !isErr || !strings.Contains(out, want) {
		t.Errorf("not refused as %q:\n%s (error=%v)", want, out, isErr)
	}
	if s := staged(t, log); len(s) != 0 {
		t.Errorf("the refused apply staged or committed something: %q", s)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("a refused apply left a snapshot: %v", left)
	}
}

// The case that started it: a firewall include whose path is a script runs that script as root
// on every firewall reload, which uci_apply triggers itself.
func TestUciApplyRefusesCreatingAFirewallInclude(t *testing.T) {
	r, s, log := noExecRig(t, false)
	out, isErr := applyChanges(t, s,
		map[string]any{"config": "firewall", "section": "evil", "type": "include"},
		map[string]any{"config": "firewall", "section": "evil", "option": "path", "value": "/tmp/script.sh"})
	assertRefusedUntouched(t, r, log, out, isErr, "firewall.evil")
}

// An include that already exists, reached the three ways uci lets a caller name it.
func TestUciApplyRefusesAnOptionOnAnExistingInclude(t *testing.T) {
	for _, sel := range []string{"@include[0]", "@include[-1]", "user_script", "cfg0a92bd"} {
		t.Run(sel, func(t *testing.T) {
			r, s, log := noExecRig(t, false)
			out, isErr := applyChanges(t, s,
				map[string]any{"config": "firewall", "section": sel, "option": "path", "value": "/tmp/script.sh"})
			assertRefusedUntouched(t, r, log, out, isErr, "firewall."+sel+".path")
		})
	}
	// Removing an option from an include is refused too: deleting `enabled` switches a disabled
	// include back on.
	r, s, log := noExecRig(t, false)
	out, isErr := applyChanges(t, s,
		map[string]any{"config": "firewall", "section": "user_script", "option": "enabled", "delete": true})
	assertRefusedUntouched(t, r, log, out, isErr, "firewall.user_script.enabled")
}

func TestUciApplyRefusesDhcpscript(t *testing.T) {
	for _, sel := range []string{"@dnsmasq[0]", "cfg01411c"} {
		r, s, log := noExecRig(t, false)
		out, isErr := applyChanges(t, s,
			map[string]any{"config": "dhcp", "section": sel, "option": "dhcpscript", "value": "/tmp/script.sh"})
		assertRefusedUntouched(t, r, log, out, isErr, "dhcp."+sel+".dhcpscript")
	}
}

// One refused change in a batch refuses the batch, and the ordinary change before it is not
// staged either.
func TestUciApplyRefusesTheWholeBatchWhenOneChangeRunsCode(t *testing.T) {
	r, s, log := noExecRig(t, false)
	out, isErr := applyChanges(t, s,
		map[string]any{"config": "network", "section": "lan", "option": "ipaddr", "value": "10.0.0.1"},
		map[string]any{"config": "firewall", "section": "allow_ssh", "option": "dest_port", "value": "2222"},
		map[string]any{"config": "dhcp", "section": "@dnsmasq[0]", "option": "dhcpscript", "value": "/tmp/x.sh"})
	assertRefusedUntouched(t, r, log, out, isErr, "dhcp.@dnsmasq[0].dhcpscript")
	if got := r.read(t); got != "original\n" {
		t.Errorf("network changed under a refused batch: %q", got)
	}
}

// A value with a line break in it becomes a line of its own in the config file a service writes
// out of uci (dnsmasq.init echoes every option into its conf file), so it can add a
// dhcp-script= line nobody asked for.
func TestUciApplyRefusesALineBreakInAValue(t *testing.T) {
	for _, v := range []string{"lan\ndhcp-script=/tmp/x.sh", "lan\rdhcp-script=/tmp/x.sh"} {
		r, s, log := noExecRig(t, false)
		out, isErr := applyChanges(t, s,
			map[string]any{"config": "dhcp", "section": "@dnsmasq[0]", "option": "domain", "value": v})
		assertRefusedUntouched(t, r, log, out, isErr, "dhcp.@dnsmasq[0].domain")
	}
}

// A section or option name carrying a dot or an "=" would let the key uci sees differ from the
// key this check and the policy read: section "@dnsmasq[0].dhcpscript" with a type would be
// `uci set dhcp.@dnsmasq[0].dhcpscript=<type>`.
func TestUciApplyRefusesASelectorThatHidesAnotherKey(t *testing.T) {
	for _, c := range []map[string]any{
		{"config": "dhcp", "section": "@dnsmasq[0].dhcpscript", "type": "tmpx"},
		{"config": "dhcp", "section": "cfg01411c.dhcpscript", "type": "tmpx"},
		{"config": "dhcp", "section": "lan=x", "option": "domain", "value": "y"},
		{"config": "dhcp", "section": "@dnsmasq[0]", "option": "domain.x", "value": "y"},
		{"config": "dhcp", "section": "lan", "option": "dhcpscript=/tmp/x.sh", "value": "y"},
		{"config": "dhcp", "section": "lan lan", "option": "domain", "value": "y"},
	} {
		r, s, log := noExecRig(t, false)
		out, isErr := applyChanges(t, s, c)
		if !isErr {
			t.Errorf("%v: accepted:\n%s", c, out)
		}
		if st := staged(t, log); len(st) != 0 {
			t.Errorf("%v: staged %q", c, st)
		}
		if left := r.snapshots(t); len(left) != 0 {
			t.Errorf("%v: snapshot left: %v", c, left)
		}
	}
}

// If what kind of section a change lands in cannot be read, the answer is no.
func TestUciApplyRefusesWhenTheSectionTypeCannotBeRead(t *testing.T) {
	r, s, log := noExecRig(t, true)
	out, isErr := applyChanges(t, s,
		map[string]any{"config": "firewall", "section": "user_script", "option": "path", "value": "/tmp/x.sh"})
	if !isErr || !strings.Contains(out, "cannot tell") {
		t.Errorf("applied without knowing the section's type:\n%s (error=%v)", out, isErr)
	}
	if st := staged(t, log); len(st) != 0 {
		t.Errorf("staged %q", st)
	}
	if left := r.snapshots(t); len(left) != 0 {
		t.Errorf("snapshot left: %v", left)
	}
}

// The refusal reaches the audit log as DENIED ("we said no"), with the key, not as an ERROR.
func TestUciApplyCodeExecRefusalIsAudited(t *testing.T) {
	r, s, _ := noExecRig(t, false)
	_, _ = applyChanges(t, s,
		map[string]any{"config": "firewall", "section": "evil", "type": "include"})
	var found bool
	for _, e := range auditEvents(t, r.stateDir) {
		if e.Tool == "uci_apply" {
			found = true
			if e.Outcome != OutcomeDenied || !strings.Contains(e.Error, "refused: firewall.evil makes the router run code as root") {
				t.Errorf("audited as %s %q", e.Outcome, e.Error)
			}
		}
	}
	if !found {
		t.Error("the refused uci_apply was not audited")
	}
}

// What an agent is for still goes through: a firewall rule, a port forward, the Wi-Fi, a
// WireGuard peer, a static lease.
func TestUciApplyStillAppliesOrdinaryChanges(t *testing.T) {
	_, s, log := noExecRig(t, false)
	out, isErr := applyChanges(t, s,
		map[string]any{"config": "firewall", "section": "allow_wg", "type": "rule"},
		map[string]any{"config": "firewall", "section": "allow_wg", "option": "src", "value": "wan"},
		map[string]any{"config": "firewall", "section": "allow_wg", "option": "dest_port", "value": "51820"},
		map[string]any{"config": "firewall", "section": "allow_wg", "option": "target", "value": "ACCEPT"},
		map[string]any{"config": "firewall", "section": "allow_ssh", "option": "enabled", "value": "0"},
		map[string]any{"config": "firewall", "section": "@zone[0]", "option": "masq", "value": "1"},
		map[string]any{"config": "firewall", "section": "fwd_web", "type": "redirect"},
		map[string]any{"config": "firewall", "section": "fwd_web", "option": "dest_ip", "value": "192.168.1.10"},
		map[string]any{"config": "wireless", "section": "@wifi-iface[0]", "option": "ssid", "value": "Home"},
		map[string]any{"config": "wireless", "section": "@wifi-iface[0]", "option": "encryption", "value": "sae"},
		map[string]any{"config": "network", "section": "phone", "type": "wireguard_wg0"},
		map[string]any{"config": "network", "section": "phone", "option": "public_key", "value": "cHViCg=="},
		map[string]any{"config": "network", "section": "phone", "option": "allowed_ips", "value": "10.0.0.2/32"},
		map[string]any{"config": "dhcp", "section": "pi", "type": "host"},
		map[string]any{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.168.1.141"},
		map[string]any{"config": "dhcp", "section": "@dnsmasq[0]", "option": "domain", "value": "home"},
		// Removing a hook is not running one.
		map[string]any{"config": "dhcp", "section": "@dnsmasq[0]", "option": "dhcpscript", "delete": true},
		map[string]any{"config": "firewall", "section": "user_script", "delete": true})
	if isErr || !strings.Contains(out, "ROLLBACK ARMED") {
		t.Fatalf("an ordinary batch was not applied:\n%s (error=%v)", out, isErr)
	}
	st := strings.Join(staged(t, log), "\n")
	for _, want := range []string{"set firewall.allow_wg=rule", "set dhcp.pi.ip=192.168.1.141",
		"delete dhcp.@dnsmasq[0].dhcpscript", "delete firewall.user_script", "commit firewall"} {
		if !strings.Contains(st, want) {
			t.Errorf("%q was not staged; staged:\n%s", want, st)
		}
	}
}
