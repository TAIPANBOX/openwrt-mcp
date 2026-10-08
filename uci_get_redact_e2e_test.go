package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What a client receives from uci_get when the config holds secrets. A tool's answer goes into
// the agent's context and from there to its model provider, so a secret must not survive any
// shape of read: the whole config, one section, or the option itself.
//
// These go through the real tool handler with a fake `uci` that prints exactly what libuci's
// `uci show` prints (cli.c, uci_print_value): every option value single-quoted, a ' inside a
// value written as '\'', list elements quoted and separated by a space, and a newline inside a
// value printed as a raw newline.

// The secrets in the fixture. Each must be absent from every answer.
var e2eSecrets = []string{
	"Wifi-Passphrase-1",
	"it's a 'quoted' secret",
	"WG+PrivateKey/0123456789abcdefABCDEF0123456789abc=",
	"WG+PresharedKey/0123456789abcdefABCDEF012345678=",
	"pppoe-pw",
	"radius-shared",
	"0011223344556677",
	"second line of a secret",
}

// The fixture, keyed by the argument `uci show` is given. Narrowed reads print only their
// own lines, as uci does.
var e2eUCI = map[string]string{
	"wireless": "wireless.radio0=wifi-device\n" +
		"wireless.radio0.channel='36'\n" +
		"wireless.default_radio0=wifi-iface\n" +
		"wireless.default_radio0.ssid='Home Net'\n" +
		"wireless.default_radio0.encryption='psk2'\n" +
		"wireless.default_radio0.key='Wifi-Passphrase-1'\n" +
		"wireless.guest=wifi-iface\n" +
		"wireless.guest.ssid='Guest'\n" +
		"wireless.guest.key='it'\\''s a '\\''quoted'\\'' secret'\n" +
		"wireless.guest.auth_secret='radius-shared'\n" +
		"wireless.guest.r0kh='02:00:00:00:03:00,ap1,0011223344556677' '02:00:00:00:04:00,ap2,0011223344556677'\n" +
		"wireless.@wifi-iface[2]=wifi-iface\n" +
		"wireless.@wifi-iface[2].sae_password='first line\nsecond line of a secret'\n" +
		"wireless.@wifi-iface[2].ssid='After Multiline'\n",
	"wireless.default_radio0": "wireless.default_radio0=wifi-iface\n" +
		"wireless.default_radio0.ssid='Home Net'\n" +
		"wireless.default_radio0.encryption='psk2'\n" +
		"wireless.default_radio0.key='Wifi-Passphrase-1'\n",
	"wireless.default_radio0.key": "wireless.default_radio0.key='Wifi-Passphrase-1'\n",
	"wireless.guest.r0kh":         "wireless.guest.r0kh='02:00:00:00:03:00,ap1,0011223344556677' '02:00:00:00:04:00,ap2,0011223344556677'\n",
	"network": "network.wg0=interface\n" +
		"network.wg0.proto='wireguard'\n" +
		"network.wg0.private_key='WG+PrivateKey/0123456789abcdefABCDEF0123456789abc='\n" +
		"network.peer1=wireguard_wg0\n" +
		"network.peer1.public_key='WG+PublicKey/stays/visible='\n" +
		"network.peer1.preshared_key='WG+PresharedKey/0123456789abcdefABCDEF012345678='\n" +
		"network.wan=interface\n" +
		"network.wan.proto='pppoe'\n" +
		"network.wan.username='isp-user'\n" +
		"network.wan.password='pppoe-pw'\n",
	"network.wg0.private_key": "network.wg0.private_key='WG+PrivateKey/0123456789abcdefABCDEF0123456789abc='\n",
	"network.peer1":           "network.peer1=wireguard_wg0\nnetwork.peer1.public_key='WG+PublicKey/stays/visible='\nnetwork.peer1.preshared_key='WG+PresharedKey/0123456789abcdefABCDEF012345678='\n",
}

// fakeUCIShow puts a `uci` on PATH that prints the fixture for the argument it is shown, and
// "uci: Entry not found" with exit 1 for anything else, as the real one does.
func fakeUCIShow(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for sel, body := range e2eUCI {
		if err := os.WriteFile(filepath.Join(dir, sel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fakeCmd(t, "uci", `[ "$1" = show ] && [ -f "`+dir+`/$2" ] && exec cat "`+dir+`/$2"
echo "uci: Entry not found" >&2; exit 1`)
}

const uciGetEverywhere = "config policy\n\toption client 'a'\n\tlist tools 'uci_get'\n\tlist scopes '*'\n"

func assertNoSecret(t *testing.T, what, out string) {
	t.Helper()
	for _, s := range e2eSecrets {
		if strings.Contains(out, s) {
			t.Errorf("%s: the secret %q reached the client:\n%s", what, s, out)
		}
	}
	// A fragment of a secret is a leak too: the quoted one could otherwise come back in pieces.
	for _, frag := range []string{"quoted", "Passphrase", "PrivateKey", "PresharedKey", "radius", "pppoe-pw"} {
		if strings.Contains(out, frag) {
			t.Errorf("%s: a fragment of a secret, %q, reached the client:\n%s", what, frag, out)
		}
	}
}

// Widening the read (the whole config) and narrowing it (one section, or the secret option by
// name) must all come back without the secret.
func TestUciGetNeverReturnsASecretWhateverTheReadShape(t *testing.T) {
	fakeUCIShow(t)
	s, _ := newToolRig(t, uciGetEverywhere)
	for _, in := range []map[string]any{
		{"config": "wireless"},
		{"config": "wireless", "section": "default_radio0"},
		{"config": "wireless", "section": "default_radio0", "option": "key"},
		{"config": "wireless", "section": "guest", "option": "r0kh"},
		{"config": "network"},
		{"config": "network", "section": "wg0", "option": "private_key"},
		{"config": "network", "section": "peer1"},
	} {
		out, isErr := callTool(t, s, "a", "uci_get", in)
		if isErr {
			t.Fatalf("%v: %q", in, out)
		}
		assertNoSecret(t, "uci_get "+strings.TrimSpace(strings.Join([]string{
			str(in["config"]), str(in["section"]), str(in["option"])}, " ")), out)
		if !strings.Contains(out, "='<redacted>'") {
			t.Errorf("%v: no redaction marker, so the reader cannot tell a value was hidden:\n%s", in, out)
		}
	}
}

// Redaction must not cost the agent what it legitimately needs: the network's name, how it is
// encrypted, a WireGuard peer's PUBLIC key, the PPPoE user name, and every line after a secret.
func TestUciGetKeepsWhatIsNotSecret(t *testing.T) {
	fakeUCIShow(t)
	s, _ := newToolRig(t, uciGetEverywhere)
	wireless, _ := callTool(t, s, "a", "uci_get", map[string]any{"config": "wireless"})
	for _, want := range []string{
		"wireless.radio0=wifi-device\n",
		"wireless.radio0.channel='36'\n",
		"wireless.default_radio0.ssid='Home Net'\n",
		"wireless.default_radio0.encryption='psk2'\n",
		"wireless.default_radio0.key='<redacted>'\n",
		"wireless.guest.ssid='Guest'\n",
		"wireless.guest.key='<redacted>'\n",
		"wireless.guest.auth_secret='<redacted>'\n",
		"wireless.guest.r0kh='<redacted>'\n",
		"wireless.@wifi-iface[2].sae_password='<redacted>'\n",
		"wireless.@wifi-iface[2].ssid='After Multiline'",
	} {
		if !strings.Contains(wireless, want) {
			t.Errorf("wireless lacks %q:\n%s", want, wireless)
		}
	}
	network, _ := callTool(t, s, "a", "uci_get", map[string]any{"config": "network"})
	for _, want := range []string{
		"network.wg0.proto='wireguard'\n",
		"network.peer1.public_key='WG+PublicKey/stays/visible='\n",
		"network.wan.username='isp-user'\n",
		"network.wan.password='<redacted>'",
	} {
		if !strings.Contains(network, want) {
			t.Errorf("network lacks %q:\n%s", want, network)
		}
	}
}

// When uci exits non-zero the wrapper hands its output to the client inside the error, so the
// redaction has to happen on that path too.
func TestUciGetRedactsEvenWhenUciFails(t *testing.T) {
	fakeCmd(t, "uci", `echo "wireless.default_radio0.key='Wifi-Passphrase-1'"; echo "uci: Parse error" >&2; exit 1`)
	s, _ := newToolRig(t, uciGetEverywhere)
	out, isErr := callTool(t, s, "a", "uci_get", map[string]any{"config": "wireless"})
	if !isErr {
		t.Errorf("a failing uci was reported as success: %q", out)
	}
	assertNoSecret(t, "a failing uci show", out)
	if !strings.Contains(out, "Parse error") {
		t.Errorf("the error itself was lost: %q", out)
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// A selector that begins with "-" is refused before uci runs: some getopt would read it as a
// flag, and `uci -d` changes how lists print, which is the shape the redaction reads.
func TestUciGetRefusesASelectorThatLooksLikeAFlag(t *testing.T) {
	fakeUCIShow(t)
	s, _ := newToolRig(t, uciGetEverywhere)
	for _, in := range []map[string]any{
		{"config": "-d"},
		{"config": "wireless", "section": "-X"},
		{"config": "wireless", "section": "guest", "option": "-q"},
	} {
		out, isErr := callTool(t, s, "a", "uci_get", in)
		if !isErr || !strings.Contains(out, "bad selector") {
			t.Errorf("%v: %q (error=%v)", in, out, isErr)
		}
	}
	// An anonymous section with a negative index is not a flag.
	if out, _ := callTool(t, s, "a", "uci_get", map[string]any{"config": "wireless", "section": "@wifi-iface[-1]"}); strings.Contains(out, "bad selector") {
		t.Errorf("a negative index was taken for a flag: %q", out)
	}
}
