package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The classifier on the router's own uci. Everywhere else the tests answer `uci -X show` from
// fixtures; this one runs in OpenWrt's published rootfs (scripts/test-real-uci.sh), where uci is
// libuci's, so what it proves is that the state the classifier reads is the state uci builds:
// selectors, lists set as one string, a quote inside a value. It writes /etc/config, so it runs
// only with OPENWRT_MCP_REAL_UCI=1, which the script sets inside a disposable container.

const realFirewall = `config defaults
	option syn_flood	1
	option input		REJECT
	option output		ACCEPT
	option forward		REJECT

config zone
	option name		lan
	list   network		'lan'
	option input		ACCEPT
	option output		ACCEPT
	option forward		ACCEPT

config zone
	option name		wan
	list   network		'wan'
	list   network		'wan6'
	option input		REJECT
	option output		ACCEPT
	option forward		REJECT
	option masq		1
	option mtu_fix		1

config forwarding
	option src		lan
	option dest		wan

config rule
	option name		Allow-DHCP-Renew
	option src		wan
	option proto		udp
	option dest_port	68
	option target		ACCEPT
	option family		ipv4

config rule
	option name		Allow-Ping
	option src		wan
	option proto		icmp
	option icmp_type	echo-request
	option family		ipv4
	option target		ACCEPT
`

const realNetwork = `config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config globals 'globals'
	option ula_prefix 'fd12:3456:789a::/48'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'

config interface 'wan'
	option device 'wan'
	option proto 'dhcp'

config interface 'wan6'
	option device 'wan'
	option proto 'dhcpv6'
`

const realDHCP = `config dnsmasq
	option domainneeded '1'
	option rebind_protection '1'
	option local '/lan/'
	option domain 'lan'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
`

const realWireless = `config wifi-device 'radio0'
	option type 'mac80211'
	option band '5g'

config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'Home'
	option encryption 'sae-mixed'
	option key 'REAL-UCI-WIFI-KEY'
`

const realSystem = `config system
	option hostname 'OpenWrt'
	option description 'baseline'

config timeserver 'ntp'
	option enabled '1'
	list server '0.openwrt.pool.ntp.org'
`

func TestRealUCIClassification(t *testing.T) {
	if os.Getenv("OPENWRT_MCP_REAL_UCI") != "1" {
		t.Skip("needs OpenWrt's uci and a disposable /etc/config: run scripts/test-real-uci.sh")
	}
	if _, err := exec.LookPath("uci"); err != nil {
		t.Fatal("OPENWRT_MCP_REAL_UCI=1, but there is no uci on PATH")
	}
	old := uciConfigDir
	uciConfigDir = "/etc/config"
	t.Cleanup(func() { uciConfigDir = old })
	reset := func() {
		for name, body := range map[string]string{"firewall": realFirewall, "network": realNetwork, "dhcp": realDHCP,
			"wireless": realWireless, "system": realSystem} {
			if err := os.WriteFile(filepath.Join(uciConfigDir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		os.RemoveAll("/tmp/.uci")
	}
	ch := func(config, section, option, value string) UCIChange {
		return UCIChange{Config: config, Section: section, Option: option, Value: value}
	}
	sec := func(config, section, typ string) UCIChange {
		return UCIChange{Config: config, Section: section, Type: typ}
	}
	portForward := []UCIChange{sec("firewall", "ssh_nas", "redirect"), ch("firewall", "ssh_nas", "name", "ssh_nas"),
		ch("firewall", "ssh_nas", "src", "wan"), ch("firewall", "ssh_nas", "src_dport", "2222"),
		ch("firewall", "ssh_nas", "proto", "tcp"), ch("firewall", "ssh_nas", "dest", "lan"),
		ch("firewall", "ssh_nas", "dest_ip", "192.168.1.20"), ch("firewall", "ssh_nas", "dest_port", "22")}
	cases := []struct {
		name    string
		changes []UCIChange
		tier    tier
		want    string
	}{
		{"a port forward from the internet", portForward, tierHeld,
			"OPENS THE ROUTER TO THE INTERNET: tcp 2222 from any address to 192.168.1.20:22"},
		{"the same, disabled", append(append([]UCIChange(nil), portForward...), ch("firewall", "ssh_nas", "enabled", "0")), tierRun, ""},
		{"the internet zone by its selector", []UCIChange{ch("firewall", "@zone[1]", "input", "ACCEPT")}, tierHeld,
			"WEAKENS THE FIREWALL: zone 'wan' accepts what comes in from the internet"},
		{"the internet zone renamed", []UCIChange{ch("firewall", "@zone[-1]", "name", "outside")}, tierHeld,
			"the zones that face the internet change"},
		{"the internet port into the bridge, as one string", []UCIChange{ch("network", "@device[0]", "ports", "lan1 lan2 wan")}, tierHeld,
			"WEAKENS THE FIREWALL: the internet port 'wan' joins 'br-lan'"},
		{"the internet port moved", []UCIChange{ch("network", "wan", "device", "lan3")}, tierHeld,
			"WEAKENS THE FIREWALL: the internet port changes"},
		{"an upstream DNS server", []UCIChange{ch("dhcp", "@dnsmasq[0]", "server", "9.9.9.9")}, tierHeld,
			"CHANGES WHO ANSWERS DNS: dhcp.@dnsmasq[0].server"},
		{"the home Wi-Fi without a password", []UCIChange{ch("wireless", "default_radio0", "encryption", "none")}, tierHeld,
			"OPENS WI-FI WITHOUT A PASSWORD INTO A TRUSTED NETWORK: 'Home' into zone 'lan'"},
		{"the time servers", []UCIChange{ch("system", "ntp", "server", "time.example.net")}, tierHeld,
			"CHANGES THE ROUTER'S TIME SERVERS: system.ntp"},
		{"the description", []UCIChange{ch("system", "@system[0]", "description", "attic")}, tierRun, ""},
		{"a quote in a value", []UCIChange{sec("firewall", "q", "rule"), ch("firewall", "q", "name", "it's"),
			ch("firewall", "q", "src", "lan"), ch("firewall", "q", "target", "ACCEPT")}, tierRun, ""},
		{"an option of a section that does not exist", []UCIChange{ch("firewall", "nosuch", "src", "wan")}, tierRefused,
			"uci refuses firewall.nosuch.src"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset()
			cl := classifyUCI(context.Background(), uciApplyIn{Changes: c.changes})
			got := strings.Join(cl.headlines, "\n")
			if cl.tier != c.tier || !strings.Contains(got+cl.refusal, c.want) {
				t.Errorf("tier %d %q %q, want tier %d and %q", cl.tier, got, cl.refusal, c.tier, c.want)
			}
			if strings.Contains(strings.Join(cl.diff, "\n"), "REAL-UCI-WIFI-KEY") {
				t.Errorf("the Wi-Fi key reached the card")
			}
			if b, _ := os.ReadFile(filepath.Join(uciConfigDir, "firewall")); string(b) != realFirewall {
				t.Errorf("classifying changed the router's own firewall config")
			}
		})
	}
	t.Run("a port forward made disabled, then switched on", func(t *testing.T) {
		reset()
		disabled := append(append([]UCIChange(nil), portForward...), ch("firewall", "ssh_nas", "enabled", "0"))
		for _, c := range disabled {
			if out, err := run(context.Background(), defaultCmdTimeout, uciArgv(c)...); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		}
		if out, err := run(context.Background(), defaultCmdTimeout, "uci", "commit", "firewall"); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		cl := classifyUCI(context.Background(), uciApplyIn{Changes: []UCIChange{ch("firewall", "ssh_nas", "enabled", "1")}})
		if cl.tier != tierHeld || !strings.Contains(strings.Join(cl.headlines, "\n"), "OPENS THE ROUTER TO THE INTERNET") {
			t.Errorf("tier %d %q", cl.tier, cl.headlines)
		}
		if !strings.Contains(strings.Join(cl.diff, "\n"), "~ enabled '0' -> '1'") {
			t.Errorf("the card does not show the switch: %q", cl.diff)
		}
	})
}
