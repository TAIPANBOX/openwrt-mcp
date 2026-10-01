package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The subcommands as an operator types them, against the real binary. main() itself cannot
// be called from a test, so this is what proves the dispatch (flags before the subcommand,
// stdin for the PIN, exit codes) is wired to the functions the other tests exercise.

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func cliBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "openwrt-mcp-cli")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "openwrt-mcp")
		if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
			binErr = err
			t.Logf("build: %s", out)
		}
	})
	if binErr != nil {
		t.Fatalf("cannot build the binary: %v", binErr)
	}
	return binPath
}

type cli struct {
	t          *testing.T
	state, cfg string
}

func newCLI(t *testing.T) *cli {
	dir := t.TempDir()
	return &cli{t: t, state: filepath.Join(dir, "state"), cfg: filepath.Join(dir, "config")}
}

func (c *cli) run(stdin string, args ...string) (stdout, stderr string, code int) {
	c.t.Helper()
	cmd := exec.Command(cliBinary(c.t), append([]string{"-config", c.cfg, "-state", c.state}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		c.t.Fatal(err)
	}
	return o.String(), e.String(), code
}

func TestCLIPinSetClearAndStatus(t *testing.T) {
	c := newCLI(t)
	os.WriteFile(c.cfg, []byte("config policy\n\toption client 'claude'\n\tlist tools 'exec'\n\tlist scopes '*'\n"+
		"\tlist mfa_tools 'exec'\n\toption mfa_factor 'pin'\n"), 0o600)

	// The PIN as an argument is refused, and nothing is written.
	if _, errOut, code := c.run("", "pin", "set", "claude", "482915"); code == 0 || strings.Contains(errOut, "482915") {
		t.Errorf("a PIN on the command line: exit %d, stderr %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(c.state, "pin")); !os.IsNotExist(err) {
		t.Fatal("a refused PIN left a file")
	}
	// Bad input is refused with a non-zero exit.
	if _, _, code := c.run("12\n", "pin", "set", "claude"); code == 0 {
		t.Error("a 2-digit PIN was accepted")
	}
	// Piped on stdin it is accepted.
	out, errOut, code := c.run("482915\n", "pin", "set", "claude")
	if code != 0 || strings.Contains(out+errOut, "482915") {
		t.Fatalf("pin set: exit %d, %q %q", code, out, errOut)
	}
	raw, _ := os.ReadFile(filepath.Join(c.state, "pin"))
	if strings.Contains(string(raw), "482915") || !strings.Contains(string(raw), "claude pbkdf2-sha256$") {
		t.Errorf("pin file: %s", raw)
	}

	// mfa status sees it, and warns that the factor is the only thing missing.
	out, _, code = c.run("", "mfa", "status")
	if code != 0 || !strings.Contains(out, "requires pin") || strings.Contains(out, "pin set claude") {
		t.Errorf("mfa status: %d %q", code, out)
	}

	// status --json carries the per-client mfa object, and never the hash.
	ts, _ := LoadTokens(filepath.Join(c.state, "tokens"))
	ts.Mint("claude")
	out, _, code = c.run("", "status", "--json", "--audit", "0")
	if code != 0 {
		t.Fatalf("status: %d %q", code, out)
	}
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Clients) != 1 {
		t.Fatalf("status json: %v %q", err, out)
	}
	if m := rep.Clients[0].MFA; m.Factor != "pin" || !m.PINSet || m.TOTPEnrolled || m.LiveState {
		t.Errorf("mfa = %+v", m)
	}
	if strings.Contains(out, "pbkdf2") {
		t.Error("status leaked the record")
	}

	// Clear.
	if out, _, code := c.run("", "pin", "clear", "claude"); code != 0 || !strings.Contains(out, "cleared") {
		t.Errorf("pin clear: %d %q", code, out)
	}
	if out, _, _ := c.run("", "mfa", "status"); !strings.Contains(out, "pin set claude") {
		t.Errorf("after clearing, mfa status should warn about the missing PIN: %q", out)
	}
	// Usage errors exit non-zero.
	if _, _, code := c.run("", "pin"); code == 0 {
		t.Error("pin with no subcommand exited 0")
	}
}

func TestCLIMFAEnrolPendingJSONThenActivate(t *testing.T) {
	c := newCLI(t)
	out, errOut, code := c.run("", "mfa", "enrol", "claude", "lab", "--pending", "--json")
	if code != 0 {
		t.Fatalf("enrol: %d %q %q", code, out, errOut)
	}
	var obj struct{ Client, URI, Secret, Qr_png_base64 string }
	if err := json.Unmarshal([]byte(out), &obj); err != nil || obj.Secret == "" || obj.Client != "claude" {
		t.Fatalf("enrol json: %v %q", err, out)
	}
	if _, err := os.Stat(filepath.Join(c.state, "mfa")); !os.IsNotExist(err) {
		t.Error("--pending made the secret live")
	}
	if _, _, code := c.run("", "mfa", "activate", "claude", "000000"); code == 0 {
		t.Error("a wrong code activated")
	}
	code6, _ := totpAt(obj.Secret, uint64(time.Now().Unix())/30)
	if out, _, code := c.run("", "mfa", "activate", "claude", code6); code != 0 || !strings.Contains(out, "activated") {
		t.Errorf("activate: %d %q", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(c.state, "mfa")); !strings.Contains(string(b), obj.Secret) {
		t.Error("the activated secret is not in the active file")
	}
	// Without flags the historical text, with --qr a drawing.
	if out, _, code := c.run("", "mfa", "enrol", "other", "--qr"); code != 0 ||
		!strings.Contains(out, "Enrolled \"other\"") || !strings.ContainsAny(out, "█▀▄") {
		t.Errorf("enrol --qr: %d %q", code, out)
	}
	if _, _, code := c.run("", "mfa", "enrol"); code == 0 {
		t.Error("enrol with no client exited 0")
	}
	if _, _, code := c.run("", "mfa", "bogus"); code == 0 {
		t.Error("an unknown mfa subcommand exited 0")
	}
}

func TestCLIVersionAndUnknownCommand(t *testing.T) {
	c := newCLI(t)
	if out, _, code := c.run("", "version"); code != 0 || !strings.Contains(out, "openwrt-mcp "+version) {
		t.Errorf("version: %d %q", code, out)
	}
	if _, _, code := c.run("", "frobnicate"); code == 0 {
		t.Error("an unknown command exited 0")
	}
}
