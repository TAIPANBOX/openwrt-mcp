package main

import "strings"

// What a tool answers lands in the agent's context, and from there in its model provider's
// logs. uci_get exists so an agent can read the router's configuration -- the Wi-Fi to set up a
// guest network, the WAN to diagnose a link -- and those configs hold the router's secrets
// beside the settings: Wi-Fi passphrases, WireGuard private and preshared keys, RADIUS
// secrets, the PPPoE password. So every uci_get answer is redacted here, for every client,
// always. There is no argument that turns it off: a switch the agent can reach is a switch the
// agent can flip.
//
// The decision is by OPTION NAME, wherever the option sits. A name on the list below is
// redacted in every config, so `dhcp.lan.key` is hidden as surely as `wireless.wlan0.key`:
// being wrong in that direction costs a value nobody needed, being wrong in the other costs a
// secret. For the same reason a value that is only the path of a key file (uhttpd's
// `option key '/etc/uhttpd.key'`) is redacted too, rather than taught apart from a passphrase.
//
// What this does NOT cover, named so nobody assumes it: a secret inside an option whose name
// gives no sign of it (a token pasted into ddns's update_url, a password inside ppp's
// pppd_options); and every tool other than uci_get. `ubus call network.wireless status`
// returns each interface's config, keys included, and is not redacted here.

// uciSecretNames are option names that are secret as a whole name and are not already caught
// by a suffix below. Each entry says which config it comes from.
var uciSecretNames = map[string]string{
	"key1":         "wireless wifi-iface: WEP key 1 (hostapd.sh)",
	"key2":         "wireless wifi-iface: WEP key 2 (hostapd.sh)",
	"key3":         "wireless wifi-iface: WEP key 3 (hostapd.sh)",
	"key4":         "wireless wifi-iface: WEP key 4 (hostapd.sh)",
	"priv_key2":    "wireless wifi-iface: EAP phase-2 private key file (hostapd.sh); a path",
	"private_key2": "wireless wifi-iface: EAP phase-2 private key file (wifi-iface schema); a path",
	"r0kh":         "wireless wifi-iface: 802.11r R0 key holders, each entry ends in the shared key (hostapd.sh)",
	"r1kh":         "wireless wifi-iface: 802.11r R1 key holders, each entry ends in the shared key (hostapd.sh)",
	"psk":          "generic: a pre-shared key under its bare name",
	"password2":    "network proto openconnect: the second password (openconnect.sh)",
	"passgroup":    "network proto vpnc: the IPsec group password (vpnc.sh)",
	"keyfile":      "dropbear: host private key files (dropbear.init); a path, redacted conservatively",
	"rsakeyfile":   "dropbear: the deprecated RSA host key file (dropbear.init); a path",
	"tls_auth":     "openvpn: the tls-auth static key file (openvpn.options); a path",
	"tls_crypt":    "openvpn: the tls-crypt static key file (openvpn.options); a path",
	"tls_crypt_v2": "openvpn: the tls-crypt-v2 key file (openvpn.options); a path",
	"pkcs12":       "openvpn: a PKCS#12 bundle holding the private key (openvpn.options); a path",
	"community":    "snmpd: an SNMP v1/v2c community string, which is a password (snmpd.conf)",
}

// uciSecretSuffixes catch the families. An option is secret if its name, lower-cased, ends
// with any of these. Each entry lists the OpenWrt options it is there for.
var uciSecretSuffixes = []struct{ suffix, from string }{
	{"key", "wireless wifi-iface key (WPA/SAE passphrase; WEP key index; RADIUS secret on old configs), " +
		"priv_key, priv_key2, multi_ap_backhaul_key, dpp_netaccesskey (hostapd.sh, wifi-iface schema); " +
		"network wireguard private_key and peer preshared_key (wireguard.uc); 6in4 updatekey (6in4.sh); " +
		"uhttpd key; openvpn key; strongswan local_key (swanctl.init)"},
	{"password", "network ppp/pppoe/pptp/l2tp/6in4/qmi/mbim/3g/openconnect/vpnc password; " +
		"wireless password (EAP) and sae_password; openvpn cert_password; ddns password; rpcd login password"},
	{"passwd", "wireless private_key_passwd, private_key2_passwd (wifi-iface schema)"},
	{"pass", "snmpd v3 auth_pass, privacy_pass (snmpd.conf); openvpn askpass, auth_user_pass, " +
		"http_proxy_user_pass (openvpn.options)"},
	{"pwd", "wireless priv_key_pwd, priv_key2_pwd (hostapd.sh)"},
	{"passphrase", "generic: hostapd's own word for the WPA passphrase"},
	{"secret", "wireless auth_secret, acct_secret, dae_secret, auth_server_shared_secret, " +
		"acct_server_shared_secret, radius_das_secret (wifi-iface schema); openvpn secret, " +
		"auth_gen_token_secret; openconnect and vpnc token_secret; strongswan secret"},
	{"_psk", "generic: *_psk, e.g. wpa_psk"},
	{"token", "rtty token (rtty.config); generic auth_token, api_token"},
	{"pin", "wireless wps_pin, ap_pin (wifi-iface schema); strongswan smartcard pin (swanctl.init)"},
	{"pincode", "network proto qmi, mbim, 3g: the SIM PIN (qmi.sh, mbim.sh, 3g.sh)"},
	{"credential", "ttyd credential, user:password (ttyd.init)"},
	{"credentials", "acme credentials, the DNS provider's API keys (acme.config)"},
}

// uciNotSecret are names a suffix would catch but that are public by definition. The list is
// kept as short as it can be: an entry here is the one way a value under a secret-looking
// name gets out. A name is exempt if it is an entry, or ends in "_" and an entry.
var uciNotSecret = map[string]string{
	"public_key": "network wireguard peer: the peer's PUBLIC key, which an agent needs to manage peers",
	"rekey": "wireless wpa_group_rekey, wpa_pair_rekey, wpa_master_rekey, wpa_ptk_rekey, wpa_gmk_rekey, " +
		"wep_rekey: rekeying intervals in seconds, not keys (hostapd.sh)",
}

// isSecretUCIOption reports whether the value of an option with this name must never leave the
// router through uci_get. Option names are compared lower-cased, so a vendor's "Password" is a
// password too.
func isSecretUCIOption(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for exempt := range uciNotSecret {
		if n == exempt || strings.HasSuffix(n, "_"+exempt) {
			return false
		}
	}
	if _, ok := uciSecretNames[n]; ok {
		return true
	}
	for _, s := range uciSecretSuffixes {
		if strings.HasSuffix(n, s.suffix) {
			return true
		}
	}
	return false
}

// uciRedactedValue replaces a secret's value. Quoted, so the line still reads as `uci show`
// syntax to anything parsing it; uci_apply refuses it as a value (see validateChange), so an
// agent copying settings from one network to another cannot set a passphrase of "<redacted>".
const uciRedactedValue = "'" + redacted + "'"

// redactUCIOutput replaces the value of every secret option in `uci show` or `uci changes`
// output with uciRedactedValue, leaving every other byte as uci printed it.
//
// The shape is libuci's (cli.c): one record per option, "config.section.option=" and then the
// value single-quoted, a quote inside it closed, escaped and reopened, list elements each
// quoted and separated by a space:
//
//	wireless.guest.key='it'\''s'
//	wireless.guest.r0kh='02:00:00:00:03:00,ap1,00112233' '02:00:00:00:04:00,ap2,44556677'
//
// Nothing escapes a newline, so a value with one in it runs over several lines, and splitting
// on newlines would redact the first line of such a secret and hand over the rest. So a record
// is read by that grammar, exactly: quoted segments joined by \' , list elements joined by one
// space, then a newline or the end. Whatever a value holds, libuci's printer keeps to it.
// `uci changes` adds "-" before a removal and "+=" / "-=" for list edits; those are read too,
// because uci_apply shows them in a refusal.
//
// Output that breaks the grammar is not uci's, and is read pessimistically: an ordinary record
// shrinks to its first line, so the records after it are still found, and a secret record
// takes everything after it. Then a second, line-by-line pass redacts any physical line that
// starts like a secret option's record. On uci's output it changes nothing, unless a value
// itself contains a line shaped like a secret's record, and then it hides that line too. It is
// there so that a mistake in reading records can only ever hide too much.
//
// The honest limit: on output that is not uci's, a backstop that works by lines finds the
// START of every secret record but cannot promise to find the end of a value it cannot parse.
// uci_get only ever reads `uci show`.
func redactUCIOutput(out string) string {
	var b strings.Builder
	b.Grow(len(out))
	for rest := out; rest != ""; {
		rec, next, nl := nextUCIRecord(rest)
		if eq := strings.IndexByte(rec, '='); eq >= 0 && isSecretUCIKey(rec[:eq]) {
			rec = rec[:eq+1] + uciRedactedValue
		}
		b.WriteString(rec)
		if nl {
			b.WriteByte('\n')
		}
		rest = next
	}
	return redactUCILines(b.String())
}

// nextUCIRecord splits the first record off s. nl reports whether a newline ended it (and was
// consumed). A line with no "=" is a record of its own: uci's error text, or a removal in
// `uci changes`, neither of which carries a value. So is a value that does not open with a
// quote: a section's type ("wireless.guest=wifi-iface"), which uci never quotes.
func nextUCIRecord(s string) (rec, rest string, nl bool) {
	line, lineRest, lineNL := s, "", false
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		line, lineRest, lineNL = s[:i], s[i+1:], true
	}
	eq := strings.IndexByte(line, '=')
	if eq < 0 || eq+1 >= len(line) || line[eq+1] != '\'' {
		return line, lineRest, lineNL
	}
	if end, ok := quotedValueEnd(s, eq+1); ok {
		if end == len(s) {
			return s, "", false
		}
		return s[:end], s[end+1:], true
	}
	if isSecretUCIKey(line[:eq]) {
		return s, "", false // where this secret ends cannot be known, so all of it goes
	}
	return line, lineRest, lineNL
}

// quotedValueEnd reads a value in libuci's grammar from s[i], which is its opening quote, and
// returns the index of the newline that ends it, or len(s). ok is false when s breaks the
// grammar. Inside quotes nothing is escaped: a backslash is a backslash, a newline is a
// newline, and the only way out is the next quote.
func quotedValueEnd(s string, i int) (end int, ok bool) {
	for {
		j := strings.IndexByte(s[i+1:], '\'')
		if j < 0 {
			return 0, false // a quote that never closes
		}
		i += j + 2 // just past the closing quote
		switch {
		case i == len(s) || s[i] == '\n':
			return i, true
		case strings.HasPrefix(s[i:], `\''`):
			i += 2 // the quote that reopens after an escaped one
		case strings.HasPrefix(s[i:], " '"):
			i++ // the next element of a list
		default:
			return 0, false
		}
	}
}

// isSecretUCIKey reports whether the left-hand side of a record, "config.section.option", names
// a secret option. "config.section" (a section and its type) never does.
func isSecretUCIKey(key string) bool {
	k := strings.TrimSpace(key)
	k = strings.TrimPrefix(k, "-") // a removal in `uci changes`
	k = strings.TrimRight(k, "+-") // "+=" and "-=", list edits in `uci changes`
	parts := strings.Split(k, ".")
	if len(parts) < 3 {
		return false
	}
	return isSecretUCIOption(parts[len(parts)-1])
}

// redactUCILines is the line-by-line backstop described at redactUCIOutput.
func redactUCILines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if eq := strings.IndexByte(line, '='); eq >= 0 && isSecretUCIKey(line[:eq]) &&
			line[eq+1:] != uciRedactedValue {
			lines[i] = line[:eq+1] + uciRedactedValue
		}
	}
	return strings.Join(lines, "\n")
}
