package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordOnce writes one audit event through the real Auditor and returns the line it wrote.
func recordOnce(t *testing.T, e AuditEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	NewAuditor(path, 16).Record(e)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// argsFromJSON decodes tool input the way addTool does before it records it.
func argsFromJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuditRedactsTheValueOfASecretUCIOptionInUciApply(t *testing.T) {
	out := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeOK,
		Args: argsFromJSON(t, `{"changes":[{"config":"wireless","section":"guest","option":"key","value":"hunter2-passphrase"}]}`)})
	if strings.Contains(out, "hunter2-passphrase") {
		t.Fatalf("a Wi-Fi key reached the audit log: %s", out)
	}
	if !strings.Contains(out, "redacted") || !strings.Contains(out, `"option":"key"`) {
		t.Errorf("the redaction marker or the option name is missing: %s", out)
	}
}

func TestAuditRedactsTheValueWhenTheSectionMarksACredential(t *testing.T) {
	out := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeOK,
		Args: argsFromJSON(t, `{"changes":[{"config":"network","section":"vpn_password","option":"server","value":"vpn-value-secret"}]}`)})
	if strings.Contains(out, "vpn-value-secret") {
		t.Errorf("a value under a credential section reached the audit log: %s", out)
	}
}

func TestAuditRedactsTheWireguardPrivateKeyValue(t *testing.T) {
	priv := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeOK,
		Args: argsFromJSON(t, `{"changes":[{"config":"wireguard_server","section":"peer_1001","option":"private_key","value":"WGPRIVATEVALUE="}]}`)})
	if strings.Contains(priv, "WGPRIVATEVALUE") {
		t.Errorf("a WireGuard private key reached the audit log: %s", priv)
	}
	pub := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeOK,
		Args: argsFromJSON(t, `{"changes":[{"config":"wireguard_server","section":"peer_1001","option":"public_key","value":"WGPUBLICVALUE="}]}`)})
	if !strings.Contains(pub, "WGPUBLICVALUE") {
		t.Errorf("a public key was redacted, and an agent needs it to manage peers: %s", pub)
	}
}

// The secret travels in argv, which the audit log records as a list, and in the summary the
// tool writes. Both must be clean, so this goes through the tool and its real audit line.
func TestAuditRedactsSecretArgvElementsAndFlagValues(t *testing.T) {
	standInProgram(t, "uci")
	standInProgram(t, "wg")
	s, dir := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'exec'\n\tlist scopes 'uci'\n\tlist scopes 'wg'\n"+
		"\tlist argv 'uci set *'\n\tlist argv 'wg set wg0 private-key *'\n")

	callTool(t, s, "a", "exec", map[string]any{"argv": []string{"uci", "set", "wireless.guest.key=ARGVSECRET1"}})
	callTool(t, s, "a", "exec", map[string]any{"argv": []string{"wg", "set", "wg0", "private-key", "FLAGSECRET2"}})

	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ARGVSECRET1", "FLAGSECRET2"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("%s reached the audit log:\n%s", secret, b)
		}
	}
	if !strings.Contains(string(b), "wireless.guest.key") || !strings.Contains(string(b), "private-key") {
		t.Errorf("the names of the arguments were lost along with their values:\n%s", b)
	}
}

// Passes before the fix as well: it guards the boundary, so that the redaction does not
// swallow ordinary settings an agent needs to read back in the log.
func TestAuditKeepsOrdinaryValues(t *testing.T) {
	out := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeOK,
		Args: argsFromJSON(t, `{"changes":[{"config":"wireless","section":"guest","option":"ssid","value":"Guest WiFi"}]}`)})
	if !strings.Contains(out, "Guest WiFi") {
		t.Errorf("an ordinary SSID was redacted: %s", out)
	}
}

// uci's own words can reach an error the audit line keeps. A record that reads as a secret is
// hidden there too, wherever it appears.
func TestAuditRedactsUCIRecordsInErrors(t *testing.T) {
	out := recordOnce(t, AuditEvent{Time: "t", Client: "a", Tool: "uci_apply", Outcome: OutcomeError,
		Error: "commit failed: wireless.guest.key='hunter2-error'"})
	if strings.Contains(out, "hunter2-error") {
		t.Errorf("a secret record quoted in an error reached the audit log: %s", out)
	}
}
