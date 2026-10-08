package main

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// The names are written out here rather than read from uciSecretNames and uciSecretSuffixes:
// a test that walked the list would pass whatever was deleted from it. Each one is an option
// OpenWrt or a common package actually uses; deleting the rule that covers any of them must
// turn this red.
var knownSecretUCIOptions = []string{
	// wireless wifi-iface (hostapd.sh and the wifi-iface schema in wifi-scripts)
	"key", "key1", "key2", "key3", "key4", "sae_password", "password", "auth_secret", "acct_secret",
	"dae_secret", "auth_server_shared_secret", "acct_server_shared_secret", "radius_das_secret",
	"priv_key", "priv_key2", "private_key2", "priv_key_pwd", "priv_key2_pwd", "private_key_passwd",
	"private_key2_passwd", "multi_ap_backhaul_key", "dpp_netaccesskey", "r0kh", "r1kh",
	"wps_pin", "ap_pin",
	// network: wireguard (wireguard.uc), ppp/pppoe, l2tp, 6in4, qmi/mbim/3g, openconnect, vpnc
	"private_key", "preshared_key", "updatekey", "pincode", "password2", "token_secret", "passgroup",
	// uhttpd, dropbear, openvpn
	"keyfile", "rsakeyfile", "cert_password", "secret", "tls_auth", "tls_crypt", "tls_crypt_v2",
	"pkcs12", "askpass", "auth_user_pass", "http_proxy_user_pass", "auth_gen_token_secret",
	// strongswan, snmpd, acme, ttyd, rtty
	"local_key", "pin", "auth_pass", "privacy_pass", "community", "credentials", "credential", "token",
	// the generic families
	"psk", "wpa_psk", "ca_cert_password", "wpa_passphrase", "api_key", "auth_token",
	// case does not save a vendor's option
	"Key", "PASSWORD", "Private_Key",
	// near misses of the exemptions: only "rekey" itself and "*_rekey" are intervals
	"storekey", "wpa_storekey",
}

// Options an agent needs to see, several of them close to a secret's name. Redacting these
// would not leak anything, but it would make the tool useless for the very job it exists for,
// and a rule widened by accident (a bare "contains key") would show up here first.
var knownPublicUCIOptions = []string{
	"ssid", "encryption", "network", "mode", "device", "disabled", "hidden", "isolate",
	"public_key", "endpoint_host", "endpoint_port", "allowed_ips", "persistent_keepalive",
	"r1_key_holder", "mobility_domain", "wpa_group_rekey", "wpa_pair_rekey", "wep_rekey",
	"wpa_disable_eapol_key_retries",
	"key_type", "keepalive", "username", "identity", "auth_server", "auth_port", "proto",
	"ipaddr", "netmask", "PasswordAuth", "RootPasswordAuth", "ping", "mapping", "rekey",
	"keys", "",
}

func TestIsSecretUCIOptionKnownNames(t *testing.T) {
	for _, n := range knownSecretUCIOptions {
		if !isSecretUCIOption(n) {
			t.Errorf("%q is a secret option and was not redacted", n)
		}
	}
	for _, n := range knownPublicUCIOptions {
		if isSecretUCIOption(n) {
			t.Errorf("%q is not a secret and was redacted", n)
		}
	}
}

// Every rule must be documented with where it comes from, and must actually catch something:
// an entry with no source is one nobody can review, and a suffix nothing ends in is dead.
func TestEverySecretRuleSaysWhereItComesFrom(t *testing.T) {
	for n, from := range uciSecretNames {
		if strings.TrimSpace(from) == "" {
			t.Errorf("uciSecretNames[%q] has no source", n)
		}
		if !isSecretUCIOption(n) {
			t.Errorf("uciSecretNames[%q] is not treated as secret", n)
		}
	}
	for _, s := range uciSecretSuffixes {
		if strings.TrimSpace(s.from) == "" {
			t.Errorf("suffix %q has no source", s.suffix)
		}
		if !isSecretUCIOption("x" + s.suffix) {
			t.Errorf("suffix %q catches nothing", s.suffix)
		}
	}
	for n, why := range uciNotSecret {
		if strings.TrimSpace(why) == "" {
			t.Errorf("uciNotSecret[%q] has no reason", n)
		}
	}
}

func TestRedactUCIOutput(t *testing.T) {
	const R = uciRedactedValue
	for _, tc := range []struct {
		name, in, want string
	}{
		{"a Wi-Fi key",
			"wireless.default_radio0.key='hunter22'\n",
			"wireless.default_radio0.key=" + R + "\n"},
		{"everything else byte for byte, section lines included",
			"wireless.radio0=wifi-device\nwireless.radio0.channel='36'\nwireless.default_radio0.ssid='My Net'\n",
			"wireless.radio0=wifi-device\nwireless.radio0.channel='36'\nwireless.default_radio0.ssid='My Net'\n"},
		{"a single-option read has no trailing newline to lean on",
			"wireless.default_radio0.key='hunter22'",
			"wireless.default_radio0.key=" + R},
		{"a quote inside the secret, as uci escapes it, does not end the record early",
			"wireless.g.key='it'\\''s mine'\nwireless.g.ssid='Guest'\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"a secret that is only quotes",
			"wireless.g.key=''\\'''\\'''\nwireless.g.ssid='Guest'\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"a backslash inside quotes is literal and does not hold the quote open",
			"wireless.g.key='ends in \\'\nwireless.g.ssid='Guest'\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"spaces, = and # inside the secret",
			"network.wan.password='a b=c #d'\nnetwork.wan.username='u'\n",
			"network.wan.password=" + R + "\nnetwork.wan.username='u'\n"},
		{"a base64 key ending in = is split at the FIRST =",
			"network.wg0.private_key='aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5MDA='\nnetwork.wg0.proto='wireguard'\n",
			"network.wg0.private_key=" + R + "\nnetwork.wg0.proto='wireguard'\n"},
		{"output that breaks the grammar after a secret: the rest goes with it",
			"network.wg0.private_key='abc=' trailing\nnetwork.wg0.proto='wireguard'\n",
			"network.wg0.private_key=" + R},
		{"output that breaks the grammar after an ordinary value: only that line is in doubt",
			"network.wg0.proto='wireguard' trailing\nnetwork.wg0.private_key='abc='\n",
			"network.wg0.proto='wireguard' trailing\nnetwork.wg0.private_key=" + R + "\n"},
		{"a list option goes whole, every element",
			"wireless.g.r0kh='02:00:00:00:03:00,ap1,0011' '02:00:00:00:04:00,ap2,2233'\nwireless.g.ssid='Guest'\n",
			"wireless.g.r0kh=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"a list element holding a quote and a space",
			"wireless.g.sae_password='a'\\''b c' 'd'\nwireless.g.ssid='Guest'\n",
			"wireless.g.sae_password=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"a multi-line secret goes whole, not just its first line",
			"wireless.g.key='line one\nline two\nline three'\nwireless.g.ssid='Guest'\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"a multi-line secret whose later line looks like a harmless record",
			"wireless.g.key='x\nwireless.g.ssid='\\''Fake'\\''\ny'\nwireless.g.ssid='Real'\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid='Real'\n"},
		{"a multi-line ordinary value is kept, and a secret after it is still found",
			"system.@system[0].notes='first\nsecond'\nwireless.g.key='hunter22'\n",
			"system.@system[0].notes='first\nsecond'\nwireless.g.key=" + R + "\n"},
		{"an ordinary value with a line shaped like a secret's record: that line is hidden too",
			"system.@system[0].notes='hi\nwireless.x.key=nope'\nwireless.g.ssid='Guest'\n",
			"system.@system[0].notes='hi\nwireless.x.key=" + R + "\nwireless.g.ssid='Guest'\n"},
		{"an anonymous section",
			"wireless.@wifi-iface[0].key='hunter22'\nwireless.@wifi-iface[0].ssid='OpenWrt'\n",
			"wireless.@wifi-iface[0].key=" + R + "\nwireless.@wifi-iface[0].ssid='OpenWrt'\n"},
		{"a secret's name in a config that has no business holding one is still a secret",
			"dhcp.lan.key='x'\nopenwrt-mcp.p.password='y'\n",
			"dhcp.lan.key=" + R + "\nopenwrt-mcp.p.password=" + R + "\n"},
		{"a SECTION named like a secret is only a name",
			"wireless.key=wifi-iface\nwireless.key.ssid='Named key'\n",
			"wireless.key=wifi-iface\nwireless.key.ssid='Named key'\n"},
		{"the public key of a WireGuard peer stays readable",
			"network.p1.public_key='cHViCg=='\nnetwork.p1.preshared_key='cHNrCg=='\n",
			"network.p1.public_key='cHViCg=='\nnetwork.p1.preshared_key=" + R + "\n"},
		{"an empty secret is hidden too: whether it is empty is not this tool's to say",
			"wireless.g.key=''\n",
			"wireless.g.key=" + R + "\n"},
		{"an unquoted value, as an old uci printed it",
			"wireless.g.key=plain words\nwireless.g.ssid=Guest\n",
			"wireless.g.key=" + R + "\nwireless.g.ssid=Guest\n"},
		{"uci changes: set, list add, list remove, removal",
			"wireless.g.key='new'\nwireless.g.r0kh+='a,b,c'\nwireless.g.r1kh-='d,e,f'\n-wireless.g.key\nwireless.g.ssid='S'\n",
			"wireless.g.key=" + R + "\nwireless.g.r0kh+=" + R + "\nwireless.g.r1kh-=" + R + "\n-wireless.g.key\nwireless.g.ssid='S'\n"},
		{"uci's error text after the output passes through",
			"wireless.g.key='x'\nuci: Entry not found",
			"wireless.g.key=" + R + "\nuci: Entry not found"},
		{"an ordinary value whose quote never closes does not swallow a secret after it",
			"system.a.notes='oops\nwireless.b.key='hunter22'\nwireless.b.ssid='S'\n",
			"system.a.notes='oops\nwireless.b.key=" + R + "\nwireless.b.ssid='S'\n"},
		{"after an ordinary value whose quote never closes, a MULTI-line secret still goes whole",
			"system.a.notes='oops\nwireless.b.key='line one\nline two'\nwireless.b.ssid='S'\n",
			"system.a.notes='oops\nwireless.b.key=" + R + "\nwireless.b.ssid='S'\n"},
		{"a secret whose quote has no closing quote anywhere after it",
			"wireless.b.key='hunter22\nwireless.b.ssid=S\n",
			"wireless.b.key=" + R},
		{"an ordinary value whose quote has no closing quote anywhere after it",
			"system.a.notes='oops\nwireless.b.key=hunter22\nwireless.b.ssid=S\n",
			"system.a.notes='oops\nwireless.b.key=" + R + "\nwireless.b.ssid=S\n"},
		{"a secret whose quote never closes takes everything after it",
			"wireless.b.key='hunter22\nwireless.b.ssid='S'\n",
			"wireless.b.key=" + R},
		{"text with = and a stray quote that is not a uci record",
			"uci: Invalid argument 'x=y\nwireless.b.key='hunter22'\n",
			"uci: Invalid argument 'x=y\nwireless.b.key=" + R + "\n"},
		{"nothing at all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactUCIOutput(tc.in); got != tc.want {
				t.Errorf("\n in   %q\n got  %q\n want %q", tc.in, got, tc.want)
			}
		})
	}
}

// uciPrint is libuci's uci_print_value (cli.c), so the sweep and the fuzz below feed the
// redaction exactly what a router would.
func uciPrint(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// uciRecord renders one option as `uci show` does: a string, or a list joined by spaces.
func uciRecord(key string, vals ...string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = uciPrint(v)
	}
	return key + "=" + strings.Join(q, " ")
}

// A seeded sweep of hostile values: quotes, backslashes, newlines, spaces, = signs and lines
// that imitate other records, in strings and lists, in secret and ordinary options alike. In
// every one the secrets must vanish and the ordinary values must come back whole.
func TestRedactUCIOutputSweep(t *testing.T) {
	pieces := []string{"'", `\`, "\n", " ", "=", "#", "''", `'\''`, "\t", "x", "é",
		"wireless.s.ssid='fake'", "\nwireless.s.key=", "\nnetwork.p.public_key='pk'", "-", "+=", "@x[0]"}
	public := []string{"ssid", "encryption", "notes", "public_key", "username"}
	secret := []string{"key", "private_key", "preshared_key", "sae_password", "password", "r0kh", "auth_secret"}

	for seed := int64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		value := func(tag string) string {
			var b strings.Builder
			for i := r.Intn(6); i > 0; i-- {
				b.WriteString(pieces[r.Intn(len(pieces))])
			}
			// The tag sits in the middle of the noise, so a leak of any part of the value that
			// carries it is a leak the test sees.
			b.WriteString(tag)
			for i := r.Intn(6); i > 0; i-- {
				b.WriteString(pieces[r.Intn(len(pieces))])
			}
			return b.String()
		}
		var out []string
		var secrets, publics []string
		for i := 0; i < 2+r.Intn(8); i++ {
			sec := fmt.Sprintf("s%d", i)
			if r.Intn(4) == 0 {
				out = append(out, "wireless."+sec+"=wifi-iface")
			}
			n := 1 + r.Intn(3)
			if r.Intn(2) == 0 {
				tag := fmt.Sprintf("SECRET%dZ%dQ", seed, i)
				vals := make([]string, n)
				for j := range vals {
					vals[j] = value(tag)
				}
				secrets = append(secrets, tag)
				out = append(out, uciRecord("wireless."+sec+"."+secret[r.Intn(len(secret))], vals...))
			} else {
				tag := fmt.Sprintf("PUBLIC%dZ%dQ", seed, i)
				publics = append(publics, tag)
				out = append(out, uciRecord("wireless."+sec+"."+public[r.Intn(len(public))], tag+value("")))
			}
		}
		in := strings.Join(out, "\n") + "\n"
		got := redactUCIOutput(in)
		for _, s := range secrets {
			if strings.Contains(got, s) {
				t.Fatalf("seed %d: %s leaked\n in  %q\n got %q", seed, s, in, got)
			}
		}
		for _, p := range publics {
			if !strings.Contains(got, p) {
				t.Fatalf("seed %d: the ordinary value %s was lost\n in  %q\n got %q", seed, p, in, got)
			}
		}
		if strings.Count(got, uciRedactedValue) < len(secrets) {
			t.Fatalf("seed %d: %d secrets, %d markers\n got %q", seed, len(secrets),
				strings.Count(got, uciRedactedValue), got)
		}
	}
}

// Whatever the secret's value, the record collapses to the marker and the record after it is
// untouched. The seeds run on every `go test`; `go test -fuzz FuzzRedactUCIOutput` explores.
func FuzzRedactUCIOutput(f *testing.F) {
	for _, s := range []string{"", "'", `\'`, "a\nb", "x'\\''y", "\nwireless.s.ssid='z'", "a' 'b", "=\n=", "''''"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		const after = "wireless.s.ssid='ok'\n"
		for _, rec := range []string{uciRecord("wireless.s.key", v), uciRecord("wireless.s.r0kh", v, v)} {
			got := redactUCIOutput(rec + "\n" + after)
			if want := "wireless.s." + rec[len("wireless.s."):strings.IndexByte(rec, '=')+1] +
				uciRedactedValue + "\n" + after; got != want {
				t.Fatalf("value %q\n got  %q\n want %q", v, got, want)
			}
		}
	})
}

// There is no way to ask uci_get for the unredacted value: its input is a config, a section and
// an option, and nothing else. A field added here later (a "raw" flag, say) fails this test on
// purpose, so that whoever adds it has to read why it is not there.
func TestUciGetHasNoWayToTurnRedactionOff(t *testing.T) {
	typ := reflect.TypeOf(uciGetIn{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if strings.Join(got, " ") != "Config Section Option" {
		t.Errorf("uci_get takes %v; anything beyond config, section and option needs a reason here", got)
	}
}
