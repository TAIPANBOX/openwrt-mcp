package main

import (
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// The parser and the predicates on their own, over states written the way `uci -X show` prints
// them. approval_e2e_test.go proves the same rules are what a client meets through the tools.

func mustStates(t *testing.T, shows map[string]string) states {
	t.Helper()
	out := states{}
	for c, show := range shows {
		st, err := parseShow(c, show)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		out[c] = st
	}
	return out
}

func baseShows() map[string]string {
	out := map[string]string{}
	for k, v := range apNow {
		out[k] = v
	}
	return out
}

func with(shows map[string]string, config, show string) map[string]string {
	out := map[string]string{}
	for k, v := range shows {
		out[k] = v
	}
	out[config] = show
	return out
}

// What libuci prints, read back: a list, a quote inside a value, a value that runs over lines,
// an empty value, anonymous sections and their @type[n] names.
func TestParseShowReadsWhatUciPrints(t *testing.T) {
	show := "firewall.cfg01e63d=defaults\n" +
		"firewall.cfg01e63d.input='REJECT'\n" +
		"firewall.z1=zone\n" +
		"firewall.z1.network='wan' 'wan6'\n" +
		"firewall.z1.name='it'\\''s'\n" +
		"firewall.z1.note='two\nlines'\n" +
		"firewall.z1.empty=''\n" +
		"firewall.cfg02dc81=zone\n" +
		"firewall.cfg02dc81.name='lan'\n"
	st, err := parseShow("firewall", show)
	if err != nil {
		t.Fatal(err)
	}
	z1 := st.section("z1")
	if z1 == nil || z1.Type != "zone" || !z1.Lists["network"] || strings.Join(z1.Opts["network"], ",") != "wan,wan6" {
		t.Fatalf("list: %+v", z1)
	}
	if z1.get("name") != "it's" || z1.get("note") != "two\nlines" || z1.Opts["empty"] == nil || z1.get("empty") != "" {
		t.Errorf("values: %q %q %q", z1.get("name"), z1.get("note"), z1.Opts["empty"])
	}
	if l := st.section("cfg02dc81").label(); l != "@zone[1]" {
		t.Errorf("anonymous label %q, want @zone[1]", l)
	}
	if l := st.section("cfg01e63d").label(); l != "@defaults[0]" {
		t.Errorf("anonymous label %q", l)
	}
	for _, bad := range []string{
		"firewall.x.src='wan'\n",                  // an option of a section with no type
		"network.x=interface\n",                   // another config's line
		"firewall.x=zone\nfirewall.x.name=lan\n",  // an unquoted value
		"firewall.x=zone\nfirewall.x.name='lan\n", // a quote that never closes
		"firewall.x=zone\nfirewall.x.name='a'b\n", // text after a value
		"firewall.x=zone\nfirewall.x=zone\n",      // a section twice
		"firewall.x=zo ne\n",                      // a type uci never prints
		"garbage\n",
	} {
		if _, err := parseShow("firewall", bad); err == nil {
			t.Errorf("read %q as a state", bad)
		}
	}
}

// Hostile bytes never crash the parser, and whatever it accepts is a state made only of what
// was in the input.
func FuzzParseShow(f *testing.F) {
	for _, s := range []string{apFirewall, apNetwork, apWireless, "firewall.x=zone\nfirewall.x.a='b'\\''c' 'd'\n",
		"firewall.x=zone\nfirewall.x.a='\n'\n", "", "firewall.", "firewall.x='"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		st, err := parseShow("firewall", in)
		if err != nil {
			return
		}
		for _, s := range st.Sections {
			if !uciName.MatchString(s.Type) || s.Name == "" || strings.Contains(s.Name, ".") {
				t.Fatalf("accepted a section uci does not print: %+v", s)
			}
			for k := range s.Opts {
				if k == "" || strings.Contains(k, ".") {
					t.Fatalf("accepted an option name uci does not print: %q", k)
				}
			}
		}
	})
}

// Whatever a client chose, the card shows it as one quoted, printable string: nothing it holds
// can end the quote, start a line, or reorder the text around it.
func FuzzShowValue(f *testing.F) {
	for _, s := range []string{"plain", "it's", "a\nb", "\u202eevil", "\x00", "back\\slash", "\u2028", "\ufeff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		out := showValue(v)
		if !strings.HasPrefix(out, "'") || !strings.HasSuffix(out, "'") || len(out) < 2 {
			t.Fatalf("not quoted: %q", out)
		}
		inner := out[1 : len(out)-1]
		for i, r := range inner {
			if r == utf8.RuneError && !strings.Contains(v, string(utf8.RuneError)) {
				continue // invalid UTF-8 in, written as \ufffd
			}
			if unicode.Is(unicode.Cf, r) || (!unicode.IsPrint(r) && r != ' ') {
				t.Fatalf("raw %U at %d in %q", r, i, out)
			}
			if r == '\'' && (i == 0 || inner[i-1] != '\\') {
				t.Fatalf("an unescaped quote in %q", out)
			}
		}
	})
}

// Each candidate on its own, and the cases next to it that must not be held: the predicates are
// as narrow as they say.
func TestPredicatesReadTheState(t *testing.T) {
	fw := apFirewall
	cases := []struct {
		name   string
		after  map[string]string
		before map[string]string // when not the base
		want   string            // "" means nothing is held
	}{
		{"a WAN zone's unset input follows a default made ACCEPT",
			with(baseShows(), "firewall", replaceLine(replaceLine(fw, "firewall.cfg03dc81.input='REJECT'\n", ""),
				"firewall.cfg01e63d.input='REJECT'", "firewall.cfg01e63d.input='ACCEPT'")),
			with(baseShows(), "firewall", replaceLine(fw, "firewall.cfg03dc81.input='REJECT'\n", "")),
			"WEAKENS THE FIREWALL: zone 'wan' accepts what comes in from the internet"},
		{"a zone that masquerades faces the internet", with(baseShows(), "firewall", replaceLine(fw,
			"firewall.guest.forward='REJECT'", "firewall.guest.forward='REJECT'\nfirewall.guest.masq='1'")), nil,
			"WEAKENS THE FIREWALL: the zones that face the internet change"},
		{"a zone that holds only wan6 faces the internet", with(baseShows(), "firewall", replaceLine(fw,
			"firewall.guest.network='guest'", "firewall.guest.network='wan6'")), nil,
			"WEAKENS THE FIREWALL: the zones that face the internet change ('wan' -> 'guest', 'wan')"},
		{"a redirect that is SNAT opens nothing", with(baseShows(), "firewall", fw+
			"firewall.s=redirect\nfirewall.s.src='lan'\nfirewall.s.dest='wan'\nfirewall.s.target='SNAT'\n"), nil, ""},
		{"a redirect from the LAN opens nothing", with(baseShows(), "firewall", fw+
			"firewall.s=redirect\nfirewall.s.src='lan'\nfirewall.s.src_dport='80'\nfirewall.s.dest_ip='192.168.1.2'\n"), nil, ""},
		{"a disabled port forward opens nothing", with(baseShows(), "firewall", portForwardAfter+
			"firewall.ssh_nas.enabled='0'\n"), nil, ""},
		{"a port forward from any zone", with(baseShows(), "firewall", replaceLine(portForwardAfter,
			"firewall.ssh_nas.src='wan'", "firewall.ssh_nas.src='*'")), nil, "OPENS THE ROUTER TO THE INTERNET"},
		{"a rule that drops opens nothing", with(baseShows(), "firewall", fw+
			"firewall.d=rule\nfirewall.d.src='wan'\nfirewall.d.dest_port='23'\nfirewall.d.target='DROP'\n"), nil, ""},
		{"a rule with no target counts as open", with(baseShows(), "firewall", fw+
			"firewall.d=rule\nfirewall.d.src='wan'\nfirewall.d.dest_port='23'\n"), nil,
			"OPENS THE ROUTER TO THE INTERNET: tcp and udp 23 from any address to the router"},
		{"renaming an open rule that was there opens nothing new", with(baseShows(), "firewall", replaceLine(fw,
			"name='Allow-Ping'", "name='Ping'")), nil, ""},
		{"an open rule moved to another port is a new opening", with(baseShows(), "firewall", replaceLine(fw,
			"firewall.cfg0592bd.dest_port='68'", "firewall.cfg0592bd.dest_port='22'")), nil,
			"OPENS THE ROUTER TO THE INTERNET: udp 22"},
		{"an unreadable port is shown as unreadable", with(baseShows(), "firewall", fw+
			"firewall.d=rule\nfirewall.d.src='wan'\nfirewall.d.proto='tcp'\nfirewall.d.dest_port='22; evil'\n"), nil,
			"OPENS THE ROUTER TO THE INTERNET: tcp (unreadable '22; evil')"},
		{"a forwarding between LAN zones weakens nothing", with(baseShows(), "firewall", fw+
			"firewall.f=forwarding\nfirewall.f.src='guest'\nfirewall.f.dest='lan'\n"), nil, ""},
		{"a WAN port into a new interface", with(baseShows(), "network", apNetwork+
			"network.x=interface\nnetwork.x.device='wan'\nnetwork.x.proto='static'\n"), nil,
			"WEAKENS THE FIREWALL: the internet port 'wan' joins interface 'x'"},
		{"an anonymous WireGuard peer changed", with(baseShows(), "network", apNetwork+
			"network.cfg0b1234=wireguard_wg0\nnetwork.cfg0b1234.public_key='abc'\nnetwork.cfg0b1234.allowed_ips='0.0.0.0/0'\n"), nil,
			"CHANGES VPN OR POLICY ROUTING: network.@wireguard_wg0[0]"},
		{"a default route removed", with(baseShows(), "network", apNetwork),
			with(baseShows(), "network", apNetwork+"network.r=route\nnetwork.r.interface='wg0'\nnetwork.r.target='0.0.0.0'\nnetwork.r.netmask='0.0.0.0'\n"),
			"CHANGES VPN OR POLICY ROUTING: every destination through 'wg0' is removed"},
		{"a route to one network routes nothing else", with(baseShows(), "network", apNetwork+
			"network.r=route\nnetwork.r.interface='lan'\nnetwork.r.target='10.0.0.0/8'\n"), nil, ""},
		{"a routing rule with no destination", with(baseShows(), "network", apNetwork+
			"network.u=rule6\nnetwork.u.lookup='100'\n"), nil, "CHANGES VPN OR POLICY ROUTING: a routing rule for every destination"},
		{"DHCP option 6 hands out another DNS server", with(baseShows(), "dhcp", apDHCP+"dhcp.lan.dhcp_option='6,9.9.9.9'\n"), nil,
			"CHANGES WHO ANSWERS DNS: dhcp.lan.dhcp_option"},
		{"a host name without a dot is a lease", with(baseShows(), "dhcp", apDHCP+
			"dhcp.pi=host\ndhcp.pi.name='pi'\ndhcp.pi.ip='192.168.1.9'\n"), nil, ""},
		{"a cname for a name with a dot", with(baseShows(), "dhcp", apDHCP+
			"dhcp.c=cname\ndhcp.c.cname='mail.example.com'\ndhcp.c.target='nas'\n"), nil, "CHANGES WHO ANSWERS DNS: dhcp.c"},
		{"peerdns switched off", with(baseShows(), "network", replaceLine(apNetwork,
			"network.wan.proto='dhcp'\n", "network.wan.proto='dhcp'\nnetwork.wan.peerdns='0'\n")), nil,
			"CHANGES WHO ANSWERS DNS: network.wan.peerdns"},
		{"an OWE Wi-Fi has no password either", with(baseShows(), "wireless", replaceLine(apWireless,
			"encryption='sae-mixed'", "encryption='owe'")), nil, "OPENS WI-FI WITHOUT A PASSWORD INTO A TRUSTED NETWORK: 'Home'"},
		{"a disabled open Wi-Fi opens nothing", with(baseShows(), "wireless", replaceLine(apWireless,
			"encryption='sae-mixed'", "encryption='none'\nwireless.default_radio0.disabled='1'")), nil, ""},
		{"an open Wi-Fi in client mode opens nothing", with(baseShows(), "wireless", replaceLine(replaceLine(apWireless,
			"encryption='sae-mixed'", "encryption='none'"), "default_radio0.mode='ap'", "default_radio0.mode='sta'")), nil, ""},
		{"an open Wi-Fi into a zone that is not trusted opens nothing", with(baseShows(), "wireless", replaceLine(apWireless,
			"wireless.guest_radio0.ssid='Guests'", "wireless.guest_radio0.ssid='Cafe'")), nil, ""},
		{"the router's description changes nothing that matters", with(baseShows(), "system", replaceLine(apSystem,
			"description='baseline'", "description='x'")), nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := c.before
			if before == nil {
				before = baseShows()
			}
			got := strings.Join(predicates(mustStates(t, before), mustStates(t, c.after)), "\n")
			if c.want == "" && got != "" {
				t.Errorf("held as %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("headlines %q, want %q", got, c.want)
			}
		})
	}
}

// The hash covers every field the owner's approval is an approval of: change any one and it changes.
func TestHashCoversEveryField(t *testing.T) {
	base := func() *heldAction {
		return &heldAction{ID: "ABCDE", Client: "a", Tool: "uci_apply", Input: []byte(`{"changes":[]}`),
			cardBase: "card", Fingerprint: "fp", Created: time.Unix(1000, 0), Expires: time.Unix(1600, 0)}
	}
	want := base().computeHash()
	for name, mut := range map[string]func(*heldAction){
		"id":          func(h *heldAction) { h.ID = "ABCDF" },
		"client":      func(h *heldAction) { h.Client = "b" },
		"tool":        func(h *heldAction) { h.Tool = "ubus_call" },
		"input":       func(h *heldAction) { h.Input = []byte(`{"changes":[{}]}`) },
		"card":        func(h *heldAction) { h.cardBase = "card " },
		"fingerprint": func(h *heldAction) { h.Fingerprint = "fq" },
		"created":     func(h *heldAction) { h.Created = h.Created.Add(time.Second) },
		"expires":     func(h *heldAction) { h.Expires = h.Expires.Add(time.Second) },
	} {
		h := base()
		mut(h)
		if h.computeHash() == want {
			t.Errorf("the hash does not cover the %s", name)
		}
	}
}

// Review of 2026-10-22: a keyword the classifier reads is read the way a firewall that trims and
// ignores case would read it, and a value it does not know counts as the one that opens. So
// whitespace or a spelling of a boolean cannot make an opening look closed.
func TestKeywordsAreReadTheWayTheyCouldBeApplied(t *testing.T) {
	fw := apFirewall
	for _, c := range []struct{ name, after, want string }{
		{"a DNAT target with spaces", portForwardAfter + "firewall.ssh_nas.target=' dnat '\n", "OPENS THE ROUTER TO THE INTERNET"},
		{"a redirect target nobody knows", portForwardAfter + "firewall.ssh_nas.target='JUMP'\n", "OPENS THE ROUTER TO THE INTERNET"},
		{"an internet zone's input with spaces", replaceLine(fw, "firewall.cfg03dc81.input='REJECT'", "firewall.cfg03dc81.input=' accept '"),
			"WEAKENS THE FIREWALL: zone 'wan' accepts what comes in from the internet"},
		{"an internet zone's input nobody knows", replaceLine(fw, "firewall.cfg03dc81.input='REJECT'", "firewall.cfg03dc81.input='MAYBE'"),
			"WEAKENS THE FIREWALL: zone 'wan' accepts what comes in from the internet"},
		{"a zone that masquerades, spelled on", replaceLine(fw, "firewall.guest.forward='REJECT'",
			"firewall.guest.forward='REJECT'\nfirewall.guest.masq='on'"), "WEAKENS THE FIREWALL: the zones that face the internet change"},
		{"a source zone with spaces", replaceLine(portForwardAfter, "firewall.ssh_nas.src='wan'", "firewall.ssh_nas.src=' wan '"),
			"OPENS THE ROUTER TO THE INTERNET"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(predicates(mustStates(t, baseShows()), mustStates(t, with(baseShows(), "firewall", c.after))), "\n")
			if !strings.Contains(got, c.want) {
				t.Errorf("headlines %q, want %q", got, c.want)
			}
		})
	}
	// And what closes still closes however it is spelled: a SNAT redirect, outbound by definition,
	// and a rule from the internet that drops.
	for _, closed := range []string{
		"firewall.s=redirect\nfirewall.s.src='lan'\nfirewall.s.dest='wan'\nfirewall.s.target=' snat '\n",
		"firewall.d=rule\nfirewall.d.src='wan'\nfirewall.d.dest_port='23'\nfirewall.d.target=' drop '\n",
	} {
		if got := predicates(mustStates(t, baseShows()), mustStates(t, with(baseShows(), "firewall", fw+closed))); len(got) != 0 {
			t.Errorf("held as %q:\n%s", got, closed)
		}
	}
}

// The internet port is what network.wan and wan6 name in the state a call starts from, so moving it
// is held itself: otherwise one call points wan at another port, which no other rule holds, and the
// next puts the old port into the LAN bridge, which is then no longer the internet port. A bridge
// named as the internet port counts by its ports, and its ports moving is held the same way.
func TestInternetPortMovedInTwoStepsHeld(t *testing.T) {
	bridged := replaceLine(replaceLine(apNetwork, "network.wan.device='wan'", "network.wan.device='br-wan'"),
		"network.wan6.device='wan'", "network.wan6.device='br-wan'") +
		"network.bw=device\nnetwork.bw.name='br-wan'\nnetwork.bw.type='bridge'\nnetwork.bw.ports='wan'\n"
	spaced := replaceLine(replaceLine(apNetwork, "network.wan.device='wan'", "network.wan.device=' wan'"),
		"network.wan6.device='wan'", "network.wan6.device='wan '")
	for _, c := range []struct {
		name, before, after, want string
	}{
		{"wan pointed at another port", apNetwork,
			replaceLine(replaceLine(apNetwork, "network.wan.device='wan'", "network.wan.device='lan3'"),
				"network.wan6.device='wan'", "network.wan6.device='lan3'"),
			"WEAKENS THE FIREWALL: the internet port changes"},
		{"wan6 alone pointed elsewhere", apNetwork,
			replaceLine(apNetwork, "network.wan6.device='wan'", "network.wan6.device='lan3'"),
			"WEAKENS THE FIREWALL: the internet port changes"},
		{"wan removed", apNetwork,
			replaceLine(apNetwork, "network.wan.device='wan'\n", ""),
			"WEAKENS THE FIREWALL: the internet port changes"},
		{"the port behind a bridge named as the internet port, into the LAN bridge", bridged,
			replaceLine(bridged, "network.cfg030f15.ports='lan1' 'lan2' 'lan3'", "network.cfg030f15.ports='lan1' 'lan2' 'lan3' 'wan'"),
			"WEAKENS THE FIREWALL: the internet port 'wan' joins 'br-lan'"},
		{"the port taken out of a bridge named as the internet port", bridged,
			replaceLine(bridged, "network.bw.ports='wan'", "network.bw.ports='lan3'"),
			"WEAKENS THE FIREWALL: the internet port changes"},
		{"an internet port written with a space, into the LAN bridge", spaced,
			replaceLine(spaced, "network.cfg030f15.ports='lan1' 'lan2' 'lan3'", "network.cfg030f15.ports='lan1' 'lan2' 'lan3' 'wan'"),
			"WEAKENS THE FIREWALL: the internet port 'wan' joins 'br-lan'"},
		{"a default route written with spaces", apNetwork,
			apNetwork + "network.r=route\nnetwork.r.interface='wg0'\nnetwork.r.target=' 0.0.0.0'\nnetwork.r.netmask='0.0.0.0 '\n",
			"CHANGES VPN OR POLICY ROUTING: every destination through 'wg0'"},
		{"a routing rule whose destination is a space", apNetwork,
			apNetwork + "network.u=rule\nnetwork.u.lookup='100'\nnetwork.u.dest=' '\n",
			"CHANGES VPN OR POLICY ROUTING: a routing rule for every destination"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(predicates(mustStates(t, with(baseShows(), "network", c.before)),
				mustStates(t, with(baseShows(), "network", c.after))), "\n")
			if !strings.Contains(got, c.want) {
				t.Errorf("headlines %q, want %q", got, c.want)
			}
		})
	}
	// What the internet port does not change still runs: wan's protocol, a LAN port added to the
	// LAN bridge, a bridge named as the internet port left as it is.
	for _, c := range []struct{ name, before, after string }{
		{"wan's protocol", apNetwork, replaceLine(apNetwork, "network.wan.proto='dhcp'", "network.wan.proto='pppoe'")},
		{"a LAN port into the LAN bridge", apNetwork + "network.cfg040f15=device\nnetwork.cfg040f15.name='lan4'\n",
			replaceLine(apNetwork, "network.cfg030f15.ports='lan1' 'lan2' 'lan3'", "network.cfg030f15.ports='lan1' 'lan2' 'lan3' 'lan4'") +
				"network.cfg040f15=device\nnetwork.cfg040f15.name='lan4'\n"},
		{"the bridge's own type said again", bridged, replaceLine(bridged, "network.bw.type='bridge'", "network.bw.type='bridge'\nnetwork.bw.mtu='1500'")},
	} {
		if got := predicates(mustStates(t, with(baseShows(), "network", c.before)),
			mustStates(t, with(baseShows(), "network", c.after))); len(got) != 0 {
			t.Errorf("%s: held as %q", c.name, got)
		}
	}
}
