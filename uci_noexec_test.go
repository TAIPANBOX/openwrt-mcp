package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
)

// The cases are written out here rather than read from the tables in uci_noexec.go: a test that
// walked the tables would pass whatever was deleted from them. Each is a hook OpenWrt or a
// common package actually runs, with where it comes from; TestDroppingAnyExecRuleTurnsThisRed
// proves that every table entry is what keeps at least one of them refused.

type execCase struct {
	name  string
	c     UCIChange
	types []string // the section's type on the router, as `uci -X show` gave it
}

func setOpt(config, section, option, value string, types ...string) execCase {
	return execCase{config + "." + section + "." + option + "=" + value,
		UCIChange{Config: config, Section: section, Option: option, Value: value}, types}
}

func newSection(config, section, typ string) execCase {
	return execCase{config + "." + section + "=" + typ, UCIChange{Config: config, Section: section, Type: typ}, nil}
}

func delOpt(config, section, option string, types ...string) execCase {
	return execCase{"delete " + config + "." + section + "." + option,
		UCIChange{Config: config, Section: section, Option: option, Delete: true}, types}
}

func delSection(config, section string, types ...string) execCase {
	return execCase{"delete " + config + "." + section, UCIChange{Config: config, Section: section, Delete: true}, types}
}

var knownExecChanges = []execCase{
	// firewall include: fw4 runs a 'script' include, or loads an 'nftables' one, on every reload
	// (firewall4 fw4.uc parse_include; firewall3 includes.c). Created, or touched, however named.
	newSection("firewall", "evil", "include"),
	newSection("firewall", "evil", "Include"),
	setOpt("firewall", "@include[0]", "path", "/tmp/script.sh"),
	setOpt("firewall", "@include[-1]", "type", "script"),
	setOpt("firewall", "user_script", "path", "/tmp/script.sh", "include"),
	setOpt("firewall", "cfg0a92bd", "path", "/tmp/script.sh", "include"),
	setOpt("firewall", "cfg0a92bd", "reload", "1", "rule", "include"), // every type seen counts
	delOpt("firewall", "user_script", "enabled", "include"),           // re-enables a disabled include
	// pbr include: `. "$path"` (packages net/pbr init.d/pbr)
	newSection("pbr", "mine", "include"),
	// net-snmp exec, extend and pass sections run `prog` (snmpd.init)
	newSection("snmpd", "x", "exec"), newSection("snmpd", "x", "extend"), newSection("snmpd", "x", "pass"),
	setOpt("snmpd", "@extend[0]", "args", "-x"),
	setOpt("snmpd", "x", "prog", "/tmp/x.sh"),
	// luci-app-commands: a command line LuCI runs
	newSection("luci", "x", "command"),
	// rpcd login: an ACL that can reach file.exec over HTTP
	newSection("rpcd", "x", "login"),
	// collectd exec plugin (luci-app-statistics stat-genconfig)
	newSection("luci_statistics", "x", "collectd_exec_input"),
	newSection("luci_statistics", "x", "collectd_exec_notify"),
	setOpt("luci_statistics", "x", "cmdline", "/tmp/x.sh"),
	setOpt("luci_statistics", "collectd", "PluginDir", "/tmp"),
	setOpt("luci_statistics", "collectd", "Include", "/tmp/x.conf"),
	// configs whose every option is raw configuration of something that loads code
	setOpt("nginx", "_lan", "server_name", "x"),
	delSection("nginx", "_lan"),
	setOpt("ucitrack", "network", "init", "../../tmp/x"),
	// dnsmasq (openwrt dnsmasq.init)
	setOpt("dhcp", "@dnsmasq[0]", "dhcpscript", "/tmp/script.sh"),
	setOpt("dhcp", "@dnsmasq[0]", "extraconftext", "dhcp-script=/tmp/x.sh"),
	setOpt("dhcp", "@dnsmasq[0]", "confdir", "/tmp/d"),
	setOpt("dhcp", "@dnsmasq[0]", "conffile", "/tmp/x.conf"),
	setOpt("dhcp", "@dnsmasq[0]", "conf_file", "/tmp/x.conf"),
	setOpt("dhcp", "@dnsmasq[0]", "conf_dir", "/tmp/d"),
	setOpt("dhcp", "@dnsmasq[0]", "domain", "lan\ndhcp-script=/tmp/x.sh"), // a second line is a second directive
	setOpt("dhcp", "@dnsmasq[0]", "domain", "lan\rdhcp-script=/tmp/x.sh"),
	// odhcpd (openwrt/odhcpd config.c)
	setOpt("dhcp", "odhcpd", "leasetrigger", "/tmp/x.sh"),
	// uhttpd (openwrt uhttpd.init)
	setOpt("uhttpd", "main", "interpreter", ".sh=/bin/sh"),
	setOpt("uhttpd", "main", "cgi_prefix", "/x"),
	setOpt("uhttpd", "main", "lua_prefix", "/x=/tmp/x.lua"),
	setOpt("uhttpd", "main", "lua_handler", "/tmp/x.lua"),
	setOpt("uhttpd", "main", "ucode_prefix", "/x=/tmp/x.uc"),
	setOpt("uhttpd", "main", "json_script", "/tmp/x.json"),
	setOpt("uhttpd", "main", "no_ubusauth", "1"),
	setOpt("uhttpd", "main", "home", "/tmp"),
	// network: ppp, sstp, openconnect, nebula (netifd protocol handlers)
	setOpt("network", "wan", "pppd_options", "plugin /tmp/x.so"),
	setOpt("network", "wan", "connect", "/tmp/x.sh"),
	setOpt("network", "wan", "disconnect", "/tmp/x.sh"),
	setOpt("network", "vpn", "sstp_options", "--x"),
	setOpt("network", "vpn", "script", "/tmp/x.sh"),
	setOpt("network", "vpn", "token_script", "/tmp/x.sh"),
	setOpt("network", "vpn", "csd_wrapper", "/tmp/x.sh"),
	setOpt("network", "neb", "config_file", "/tmp/x.yml"),
	// openvpn as a netifd protocol (packages net/openvpn openvpn.uc, openvpn.options)
	setOpt("network", "vpn", "up", "/tmp/x.sh"),
	setOpt("network", "vpn", "down", "/tmp/x.sh"),
	setOpt("network", "vpn", "config", "/tmp/x.ovpn"),
	setOpt("network", "vpn", "route_up", "/tmp/x.sh"),
	setOpt("network", "vpn", "route_pre_down", "/tmp/x.sh"),
	setOpt("network", "vpn", "ipchange", "/tmp/x.sh"),
	setOpt("network", "vpn", "client_connect", "/tmp/x.sh"),
	setOpt("network", "vpn", "client_disconnect", "/tmp/x.sh"),
	setOpt("network", "vpn", "client_crresponse", "/tmp/x.sh"),
	setOpt("network", "vpn", "learn_address", "/tmp/x.sh"),
	setOpt("network", "vpn", "tls_verify", "/tmp/x.sh"),
	setOpt("network", "vpn", "tls_crypt_v2_verify", "/tmp/x.sh"),
	setOpt("network", "vpn", "auth_user_pass_verify", "/tmp/x.sh"),
	setOpt("network", "vpn", "script_security", "2"),
	setOpt("network", "vpn", "plugin", "/tmp/x.so"),
	setOpt("network", "vpn", "providers", "/tmp/x.so"),
	setOpt("network", "vpn", "pkcs11_providers", "/tmp/x.so"),
	setOpt("network", "vpn", "engine", "dynamic"),
	setOpt("network", "vpn", "iproute", "/tmp/x"),
	// openvpn before 25.12, in its own config
	setOpt("openvpn", "x", "up", "/tmp/x.sh"),
	setOpt("openvpn", "x", "down", "/tmp/x.sh"),
	setOpt("openvpn", "x", "config", "/tmp/x.ovpn"),
	// strongswan (swanctl.init), keepalived (keepalived.init)
	setOpt("ipsec", "x", "updown", "/tmp/x.sh"),
	setOpt("keepalived", "x", "script", "/tmp/x.sh"),
	setOpt("keepalived", "x", "misc_path", "/tmp/x.sh"),
	// ddns-scripts (dynamic_dns_functions.sh)
	setOpt("ddns", "x", "update_script", "/tmp/x.sh"),
	setOpt("ddns", "x", "ip_script", "/tmp/x.sh"),
	// adblock, banip, travelmate: the command, the arguments, and the PATH they run with
	setOpt("adblock", "global", "adb_fetchcmd", "/tmp/x.sh"),
	setOpt("adblock", "global", "adb_fetchparm", "-K /tmp/x"),
	setOpt("banip", "global", "ban_fetchcmd", "/tmp/x.sh"),
	setOpt("banip", "global", "ban_rdapparm", "-o /etc/rc.local"),
	setOpt("travelmate", "global", "trm_fetchcmd", "/tmp/x.sh"),
	setOpt("adblock", "global", "PATH", "/tmp"),
	setOpt("banip", "global", "LD_PRELOAD", "/tmp/x.so"),
	setOpt("travelmate", "global", "LD_LIBRARY_PATH", "/tmp"),
	// ttyd (ttyd.init), dropbear ForceCommand (dropbear.init), luci-app-commands, nut, watchcat
	setOpt("ttyd", "x", "command", "/tmp/x.sh"),
	setOpt("dropbear", "x", "ForceCommand", "/tmp/x.sh"),
	setOpt("luci", "x", "command", "/tmp/x.sh"),
	setOpt("nut_monitor", "x", "notifycmd", "/tmp/x.sh"),
	setOpt("watchcat", "x", "script", "/tmp/x.sh"),
	// acme: credentials are eval'd; a dns hook or sqm script with a / reaches any file
	setOpt("acme", "x", "credentials", "CF_Key=x; reboot"),
	setOpt("acme", "x", "dns", "../../../tmp/x"),
	setOpt("acme", "x", "dns", "/tmp/x"),
	setOpt("sqm", "eth1", "script", "../../../tmp/x.sh"),
	setOpt("sqm", "eth1", "script", ".."),
	// a hook's usual names, in a package this list has not met
	setOpt("foo", "x", "on_exec", "/tmp/x"),
	setOpt("foo", "x", "post_hook", "/tmp/x"),
	setOpt("foo", "x", "event_handler", "/tmp/x"),
	setOpt("foo", "x", "reload_cmd", "/tmp/x"),
	setOpt("foo", "x", "start_command", "/tmp/x"),
	setOpt("foo", "x", "Up_Script", "/tmp/x"),
}

// Settings an agent needs to change, several of them close to a hook's name. Refusing these
// would leak nothing, but it would make uci_apply useless for the jobs it exists for.
var knownOrdinaryChanges = []execCase{
	// firewall rule, redirect, zone, forwarding
	newSection("firewall", "allow_wg", "rule"),
	setOpt("firewall", "allow_wg", "dest_port", "51820", "rule"),
	setOpt("firewall", "allow_wg", "target", "ACCEPT", "rule"),
	setOpt("firewall", "@rule[3]", "enabled", "0"),
	newSection("firewall", "fwd", "redirect"),
	setOpt("firewall", "fwd", "dest_ip", "192.168.1.10", "redirect"),
	setOpt("firewall", "fwd", "reflection", "0", "redirect"),
	setOpt("firewall", "@zone[1]", "masq", "1"),
	setOpt("firewall", "lan", "network", "lan", "zone"),
	newSection("firewall", "f", "forwarding"),
	setOpt("firewall", "f", "dest", "wan", "forwarding"),
	setOpt("firewall", "@defaults[0]", "flow_offloading", "1"),
	setOpt("firewall", "set1", "loadfile", "/etc/blocklist.txt", "ipset"),
	// a section NAMED like a hook is only a name
	setOpt("firewall", "include", "name", "x", "rule"),
	setOpt("firewall", "dhcpscript", "proto", "udp", "rule"),
	// removing a hook, or a whole include, runs nothing
	delOpt("dhcp", "@dnsmasq[0]", "dhcpscript"),
	delOpt("uhttpd", "main", "interpreter"),
	delSection("firewall", "user_script", "include"),
	delSection("firewall", "@include[0]"),
	// retyping an include into a rule switches it off
	newSection("firewall", "user_script", "rule"),
	// wireless
	setOpt("wireless", "@wifi-iface[0]", "ssid", "Home"),
	setOpt("wireless", "default_radio0", "encryption", "sae", "wifi-iface"),
	setOpt("wireless", "radio0", "channel", "36", "wifi-device"),
	setOpt("wireless", "radio0", "path", "platform/soc/18000000.wifi", "wifi-device"),
	setOpt("wireless", "guest", "isolate", "1", "wifi-iface"),
	newSection("wireless", "guest", "wifi-iface"),
	// network: static, dhcp, wireguard interface and peer
	setOpt("network", "lan", "ipaddr", "192.168.2.1", "interface"),
	setOpt("network", "lan", "proto", "static", "interface"),
	setOpt("network", "wan", "proto", "dhcp", "interface"),
	setOpt("network", "wan", "peerdns", "0", "interface"),
	newSection("network", "wg0", "interface"),
	setOpt("network", "wg0", "proto", "wireguard", "interface"),
	setOpt("network", "wg0", "listen_port", "51820", "interface"),
	newSection("network", "phone", "wireguard_wg0"),
	setOpt("network", "phone", "public_key", "cHViCg==", "wireguard_wg0"),
	setOpt("network", "phone", "allowed_ips", "10.0.0.2/32", "wireguard_wg0"),
	setOpt("network", "phone", "endpoint_host", "vpn.example.org", "wireguard_wg0"),
	// dhcp host and domain
	newSection("dhcp", "pi", "host"),
	setOpt("dhcp", "pi", "mac", "88:a2:9e:8a:e4:15", "host"),
	setOpt("dhcp", "pi", "ip", "192.168.0.141", "host"),
	setOpt("dhcp", "pi", "name", "pi", "host"),
	newSection("dhcp", "nas", "domain"),
	setOpt("dhcp", "nas", "ip", "192.168.0.5", "domain"),
	setOpt("dhcp", "@dnsmasq[0]", "addnhosts", "/etc/hosts.extra"), // data, not code
	setOpt("dhcp", "lan", "leasetime", "12h", "dhcp"),
	// the exempt names: lists of section names, and booleans that turn an exec off
	setOpt("keepalived", "x", "track_script", "chk_wan"),
	setOpt("network", "vpn", "route_noexec", "1"),
	setOpt("network", "vpn", "ifconfig_noexec", "1"),
	// near misses: a hook only in openvpn, harmless in mwan3; only exact upper-case PATH is a variable
	setOpt("mwan3", "wan", "up", "3", "interface"),
	setOpt("mwan3", "wan", "down", "3", "interface"),
	setOpt("uhttpd", "main", "script_timeout", "60"),
	setOpt("dhcp", "@dnsmasq[0]", "scriptarp", "1"),
	// a plain name picks an installed script from a fixed directory
	setOpt("sqm", "eth1", "script", "piece_of_cake.qos"),
	setOpt("acme", "x", "dns", "dns_cf"),
	// an ordinary multi-word value
	setOpt("system", "@system[0]", "description", "the router in the hall"),
}

func execCaseRefusal(tc execCase) string { return execRefusal(tc.c, tc.types) }

// execTableFailures is what the two tables above say is wrong with the classifier as it stands:
// a hook it lets through, or a setting it refuses.
func execTableFailures() []string {
	var out []string
	for _, tc := range knownExecChanges {
		if execCaseRefusal(tc) == "" {
			out = append(out, "let through: "+strings.ReplaceAll(tc.name, "\n", `\n`))
		}
	}
	for _, tc := range knownOrdinaryChanges {
		if why := execCaseRefusal(tc); why != "" {
			out = append(out, "refused: "+tc.name+" ("+why+")")
		}
	}
	return out
}

func TestExecRefusalKnownChanges(t *testing.T) {
	for _, f := range execTableFailures() {
		t.Error(f)
	}
}

// Every rule is documented with where it comes from, and catches something.
func TestEveryExecRuleSaysWhereItComesFrom(t *testing.T) {
	check := func(table, key, from string) {
		if strings.TrimSpace(from) == "" {
			t.Errorf("%s[%q] has no source", table, key)
		}
	}
	for k, v := range uciExecConfigs {
		check("uciExecConfigs", k, v)
		if execRefusal(UCIChange{Config: k, Section: "x", Option: "y", Value: "z"}, nil) == "" {
			t.Errorf("uciExecConfigs[%q] refuses nothing", k)
		}
	}
	for k, v := range uciExecSectionTypes {
		check("uciExecSectionTypes", k, v)
		cfg, typ, _ := strings.Cut(k, ".")
		if cfg == "*" {
			cfg = "anything"
		}
		if execSectionTypeReason(cfg, typ) == "" {
			t.Errorf("uciExecSectionTypes[%q] refuses nothing", k)
		}
	}
	for k, v := range uciExecOptionNames {
		check("uciExecOptionNames", k, v)
		if execOptionReason("anything", k, "/tmp/x") == "" {
			t.Errorf("uciExecOptionNames[%q] refuses nothing", k)
		}
	}
	for _, s := range uciExecSuffixes {
		check("uciExecSuffixes", s.suffix, s.from)
		if execOptionReason("anything", "x_"+s.suffix, "/tmp/x") == "" {
			t.Errorf("suffix %q catches nothing", s.suffix)
		}
	}
	for k, v := range uciExecExempt {
		check("uciExecExempt", k, v)
	}
	for k, v := range uciExecConfigOptions {
		check("uciExecConfigOptions", k, v)
		cfg, opt, _ := strings.Cut(k, ".")
		if execOptionReason(cfg, opt, "/tmp/x") == "" {
			t.Errorf("uciExecConfigOptions[%q] refuses nothing", k)
		}
	}
	for k, v := range uciExecPlainNameOK {
		check("uciExecPlainNameOK", k, v)
		if _, ok := uciExecConfigOptions[k]; !ok {
			t.Errorf("uciExecPlainNameOK[%q] loosens a rule that does not exist", k)
		}
	}
	for k, v := range uciExecEnvNames {
		check("uciExecEnvNames", k, v)
	}
}

// Mutation, in-process: take any single entry out of any table and the tables above must go
// red. An entry whose removal changes nothing is either dead or covered by nothing a test names,
// and both need looking at.
func TestDroppingAnyExecRuleTurnsThisRed(t *testing.T) {
	if f := execTableFailures(); len(f) != 0 {
		t.Fatalf("the tables are red before anything is dropped: %v", f)
	}
	type mutant struct {
		name string
		drop func() (restore func())
	}
	var ms []mutant
	dropKey := func(table string, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			k := k
			ms = append(ms, mutant{table + "[" + k + "]", func() func() {
				v := m[k]
				delete(m, k)
				return func() { m[k] = v }
			}})
		}
	}
	dropKey("uciExecConfigs", uciExecConfigs)
	dropKey("uciExecSectionTypes", uciExecSectionTypes)
	dropKey("uciExecOptionNames", uciExecOptionNames)
	dropKey("uciExecExempt", uciExecExempt)
	dropKey("uciExecConfigOptions", uciExecConfigOptions)
	dropKey("uciExecPlainNameOK", uciExecPlainNameOK)
	dropKey("uciExecEnvNames", uciExecEnvNames)
	for i := range uciExecSuffixes {
		i := i
		ms = append(ms, mutant{"uciExecSuffixes[" + uciExecSuffixes[i].suffix + "]", func() func() {
			saved := uciExecSuffixes
			uciExecSuffixes = append(append([]struct{ suffix, from string }{}, saved[:i]...), saved[i+1:]...)
			return func() { uciExecSuffixes = saved }
		}})
	}
	for _, m := range ms {
		restore := m.drop()
		caught := execTableFailures()
		restore()
		if len(caught) == 0 {
			t.Errorf("dropping %s turns nothing red", m.name)
		}
	}
	if f := execTableFailures(); len(f) != 0 {
		t.Fatalf("a mutant was not restored: %v", f)
	}
}

// Every option name OpenWrt's own sources define for wireless, firewall, dhcp and network
// (testdata/openwrt-option-names.txt, each block with its source) goes through the check, and
// exactly the hooks are refused. A rule widened by accident shows up here as a setting an agent
// could no longer change.
func TestOpenWrtOptionNamesOnlyTheHooksAreRefused(t *testing.T) {
	b, err := os.ReadFile("testdata/openwrt-option-names.txt")
	if err != nil {
		t.Fatal(err)
	}
	var config string
	n := 0
	refused := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "# ") {
			config = strings.Trim(strings.Fields(line[2:])[0], ":,")
			continue
		}
		for _, opt := range strings.Fields(line) {
			n++
			if execRefusal(UCIChange{Config: config, Section: "x", Option: opt, Value: "/tmp/x"}, nil) != "" {
				refused[config+"."+opt] = true
			}
		}
	}
	if n < 500 {
		t.Fatalf("read only %d names; the list did not parse", n)
	}
	var got []string
	for k := range refused {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"dhcp.confdir", "dhcp.dhcpscript", "dhcp.extraconftext", "dhcp.leasetrigger",
		"network.connect", "network.disconnect", "network.pppd_options"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("of %d OpenWrt option names, refused:\n  %v\nwant exactly:\n  %v", n, got, want)
	}
}

// A seeded sweep of `uci -X show` output: named and anonymous sections of many types, with
// values that imitate section lines (a value may span lines, and the line after a newline can
// read "firewall.x=rule"). For every section the type uci really printed must be among the
// types read back, so an imitation can add a type to check but never hide an include.
func TestParseUCISectionTypesSweep(t *testing.T) {
	types := []string{"include", "rule", "zone", "redirect", "defaults", "forwarding", "ipset"}
	pieces := []string{"'", `\`, "\n", " ", "=", "x", "firewall.", "=rule", "=include", "\nfirewall.s0=rule",
		"\nfirewall.cfg000001=zone", "@include[0]", ".", "''"}
	for seed := int64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		var out strings.Builder
		truth := map[string]string{}
		for i := 0; i < 1+r.Intn(8); i++ {
			name := fmt.Sprintf("s%d", i)
			if r.Intn(2) == 0 {
				name = fmt.Sprintf("cfg%06x", r.Intn(1<<24))
			}
			if _, dup := truth[name]; dup {
				continue
			}
			typ := types[r.Intn(len(types))]
			truth[name] = typ
			fmt.Fprintf(&out, "firewall.%s=%s\n", name, typ)
			for j := r.Intn(3); j > 0; j-- {
				var v strings.Builder
				for k := r.Intn(6); k > 0; k-- {
					v.WriteString(pieces[r.Intn(len(pieces))])
				}
				out.WriteString(uciRecord("firewall."+name+".name", v.String()) + "\n")
			}
		}
		got := parseUCISectionTypes("firewall", out.String())
		for name, typ := range truth {
			found := false
			for _, g := range got[name] {
				found = found || g == typ
			}
			if !found {
				t.Fatalf("seed %d: %s is a %s, read back as %v\n%s", seed, name, typ, got[name], out.String())
			}
			c := UCIChange{Config: "firewall", Section: name, Option: "path", Value: "/tmp/x.sh"}
			if typ == "include" && execRefusal(c, got[name]) == "" {
				t.Fatalf("seed %d: path on include %s was let through", seed, name)
			}
		}
	}
}

func TestSelectorType(t *testing.T) {
	for in, want := range map[string]string{
		"@include[0]": "include", "@include[-1]": "include", "@wifi-iface[12]": "wifi-iface",
		"include": "", "@include": "", "@include[]": "", "@include[x]": "", "x@include[0]": "",
		"@include[0]x": "", "@[0]": "", "": "",
	} {
		if got := selectorType(in); got != want {
			t.Errorf("selectorType(%q) = %q, want %q", in, got, want)
		}
	}
}

// Whatever a value in `uci -X show` holds, the include it sits in is still read as an include,
// and a path set on it is refused. The seeds run on every `go test`; `go test -fuzz
// FuzzSectionTypeResolution` explores. The selector side: whatever string names the section, a
// "@include[n]" form is refused without a lookup, and nothing else is read as an include by the
// selector alone.
func FuzzSectionTypeResolution(f *testing.F) {
	for _, s := range []string{"", "'", "\nfirewall.x=rule", "x'\\''y", "=", "\n\n", "firewall.x", "@include[0]",
		"@include[-1]", "@rule[0]", "x\nfirewall.x=include\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		out := "firewall.x=include\n" + uciRecord("firewall.x.name", v) + "\nfirewall.y=rule\n"
		got := parseUCISectionTypes("firewall", out)
		c := UCIChange{Config: "firewall", Section: "x", Option: "path", Value: "/tmp/x.sh"}
		if execRefusal(c, got["x"]) == "" {
			t.Fatalf("value %q hid the include: %v", v, got)
		}
		sel := UCIChange{Config: "firewall", Section: v, Option: "path", Value: "/tmp/x.sh"}
		byName := execRefusal(sel, nil) != ""
		isInc := typeSelector.MatchString(v) && strings.EqualFold(selectorType(v), "include")
		if isInc && !byName {
			t.Fatalf("selector %q names an include and was let through", v)
		}
		if !isInc && byName && !strings.ContainsAny(v, "\n\r") {
			t.Fatalf("selector %q was refused though it names no include", v)
		}
	})
}
