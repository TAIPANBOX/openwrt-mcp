package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Enrolment is where a secret first reaches a person, so what it prints and where it writes
// are the contract: the historical output must not change under anyone, a QR must encode
// the very URI printed beside it, and a pending secret must not be able to unlock anything
// until a code from the authenticator has proved it was scanned.

func enrolRig(t *testing.T) (*MFAStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	m, err := LoadMFA(filepath.Join(dir, "mfa"))
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

var secretLine = regexp.MustCompile(`(?m)^  secret: (\S+)$`)

func TestEnrolWithoutFlagsPrintsExactlyWhatItAlwaysDid(t *testing.T) {
	m, dir := enrolRig(t)
	var out bytes.Buffer
	if err := runMFAEnrol(&out, m, dir, []string{"a", "myrouter"}); err != nil {
		t.Fatal(err)
	}
	mm := secretLine.FindStringSubmatch(out.String())
	if mm == nil {
		t.Fatalf("no secret line in:\n%s", out.String())
	}
	secret := mm[1]
	uri := "otpauth://totp/openwrt-mcp:a@myrouter?secret=" + secret +
		"&issuer=openwrt-mcp&algorithm=SHA1&digits=6&period=30"
	want := "Enrolled \"a\". Scan this in your authenticator app:\n\n  " + uri + "\n\n" +
		"  secret: " + secret + "\n\n" +
		"Then require it for the tools that matter, e.g. in " + defaultConfigPath + ":\n" +
		"  list mfa_tools 'exec'\n" +
		"  list mfa_tools 'uci_apply'\n" +
		"  option mfa_window '15m'\n\n" +
		"Restart to apply: /etc/init.d/openwrt-mcp restart\n" +
		"The secret is stored at " + dir + "/mfa (mode 0600); anyone who reads it can generate codes.\n"
	if out.String() != want {
		t.Errorf("the plain enrol output changed.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
	if !m.Enrolled("a") {
		t.Error("a plain enrol is active at once, as before")
	}
	if strings.ContainsAny(out.String(), "█▀▄") {
		t.Error("a QR appeared without --qr")
	}
}

func TestEnrolQRPrintsTheCodeOfTheVeryURIItShows(t *testing.T) {
	m, dir := enrolRig(t)
	var out bytes.Buffer
	if err := runMFAEnrol(&out, m, dir, []string{"a", "--qr", "myrouter"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	uri := regexp.MustCompile(`(?m)^  (otpauth://\S+)$`).FindStringSubmatch(s)
	if uri == nil {
		t.Fatalf("no URI printed:\n%s", s)
	}
	qr, err := renderQR(uri[1])
	if err != nil {
		t.Fatal(err)
	}
	// Indented two spaces, like the URI, one line at a time.
	for _, line := range strings.Split(strings.TrimRight(qr, "\n"), "\n") {
		if !strings.Contains(s, "  "+line+"\n") {
			t.Fatalf("the QR line %q is not in the output:\n%s", line, s)
		}
	}
	if !strings.ContainsAny(s, "█▀▄") {
		t.Error("the QR is not drawn with half-block characters")
	}
	if !strings.Contains(s, "  secret: ") {
		t.Error("the text secret must remain beside the QR for hand entry")
	}
}

func TestEnrolJSONIsOneObjectAWebPageCanUse(t *testing.T) {
	m, dir := enrolRig(t)
	var out bytes.Buffer
	if err := runMFAEnrol(&out, m, dir, []string{"a", "--json", "--qr", "myrouter"}); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Errorf("there is more than one JSON value (or trailing text) on stdout:\n%s", out.String())
	}
	if len(obj) != 4 {
		t.Errorf("want exactly client, uri, secret, qr_png_base64; got %v", obj)
	}
	if obj["client"] != "a" {
		t.Errorf("client = %v", obj["client"])
	}
	secret, _ := obj["secret"].(string)
	uri, _ := obj["uri"].(string)
	if secret == "" || !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) ||
		!strings.Contains(uri, "a@myrouter") {
		t.Errorf("uri/secret do not agree: %q / %q", uri, secret)
	}
	raw, err := base64.StdEncoding.DecodeString(obj["qr_png_base64"].(string))
	if err != nil {
		t.Fatalf("qr_png_base64 is not base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("qr_png_base64 is not a PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() < 100 || b.Dx() != b.Dy() {
		t.Errorf("the QR image is %v, want a decent square", b)
	}
	// The secret in the JSON is the one that was stored.
	if !m.Enrolled("a") {
		t.Error("--json did not enrol")
	}
	if got, _ := parseMFAFile(filepath.Join(dir, "mfa")); got["a"] != secret {
		t.Errorf("the stored secret differs from the one printed")
	}
}

func TestEnrolPendingStoresApartAndUnlocksNothing(t *testing.T) {
	m, dir := enrolRig(t)
	var out bytes.Buffer
	if err := runMFAEnrol(&out, m, dir, []string{"a", "--pending"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mfa")); !os.IsNotExist(err) {
		t.Error("--pending wrote the active secret file")
	}
	pend, err := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	if err != nil || pend["a"] == "" {
		t.Fatalf("no pending secret on disk: %v %v", pend, err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "mfa.pending")); st.Mode().Perm() != 0o600 {
		t.Errorf("mfa.pending mode %v, want 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, want 0700", st.Mode().Perm())
	}
	if m.Enrolled("a") || !m.TOTPPending("a") {
		t.Errorf("enrolled=%v pending=%v, want false/true", m.Enrolled("a"), m.TOTPPending("a"))
	}
	// A code from the pending secret must not unlock anything yet.
	code, _ := totpAt(pend["a"], uint64(t0.Unix())/30)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, policyFor(factorTOTP), t0); err == nil {
		t.Error("a pending secret unlocked a client")
	}
	o := out.String()
	if !strings.Contains(o, "pending") || !strings.Contains(o, "openwrt-mcp mfa activate a") ||
		!strings.Contains(o, pend["a"]) {
		t.Errorf("the output does not explain how to finish:\n%s", o)
	}
}

func TestEnrolPendingLeavesAnActiveSecretInForce(t *testing.T) {
	m, dir := enrolRig(t)
	old, _, _ := m.Enrol("a", "openwrt-mcp", "r")
	runMFAEnrol(io.Discard, m, dir, []string{"a", "--pending"})
	got, _ := parseMFAFile(filepath.Join(dir, "mfa"))
	if got["a"] != old {
		t.Error("--pending replaced the working secret before it was proved")
	}
	code, _ := totpAt(old, uint64(t0.Unix())/30)
	if _, err := m.Attempt("a", unlockAttempt{Code: code}, policyFor(factorTOTP), t0); err != nil {
		t.Errorf("the old secret stopped working during a pending rotation: %v", err)
	}
}

func TestActivateMovesThePendingSecretOnlyForAValidCode(t *testing.T) {
	m, dir := enrolRig(t)
	runMFAEnrol(io.Discard, m, dir, []string{"a", "--pending"})
	runMFAEnrol(io.Discard, m, dir, []string{"b", "--pending"})
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	now := time.Now()
	good, _ := totpAt(pend["a"], uint64(now.Unix())/30)
	stale, _ := totpAt(pend["a"], uint64(now.Add(-10*time.Minute).Unix())/30)

	for name, code := range map[string]string{"wrong": "000000", "expired": stale, "short": "123", "empty": ""} {
		var out bytes.Buffer
		err := runMFAActivate(&out, m, []string{"a", code}, now)
		if err == nil {
			t.Errorf("%s: activated", name)
			continue
		}
		if !strings.Contains(err.Error(), "still pending") {
			t.Errorf("%s: %q does not say it stays pending", name, err)
		}
		if strings.Contains(err.Error(), pend["a"]) {
			t.Errorf("%s: the refusal prints the secret", name)
		}
	}
	if m.Enrolled("a") || !m.TOTPPending("a") {
		t.Fatal("a refused activation changed state")
	}

	var out bytes.Buffer
	if err := runMFAActivate(&out, m, []string{"a", good}, now); err != nil {
		t.Fatalf("a valid code was refused: %v", err)
	}
	if !strings.Contains(out.String(), "activated") {
		t.Errorf("no confirmation: %q", out.String())
	}
	active, _ := parseMFAFile(filepath.Join(dir, "mfa"))
	if active["a"] != pend["a"] {
		t.Error("the pending secret is not the active one")
	}
	left, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	if _, still := left["a"]; still {
		t.Error("a is still pending after activation")
	}
	if left["b"] != pend["b"] {
		t.Error("activating a disturbed b's pending secret")
	}
	if !m.Enrolled("a") || m.TOTPPending("a") || m.Enrolled("b") || !m.TOTPPending("b") {
		t.Error("in-memory view disagrees with the files")
	}
}

func TestActivatingTheLastPendingSecretRemovesTheFile(t *testing.T) {
	m, dir := enrolRig(t)
	runMFAEnrol(io.Discard, m, dir, []string{"a", "--pending"})
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	code, _ := totpAt(pend["a"], uint64(t0.Unix())/30)
	if err := runMFAActivate(io.Discard, m, []string{"a", code}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mfa.pending")); !os.IsNotExist(err) {
		t.Error("an empty mfa.pending was left behind")
	}
}

func TestActivateReplacesAnExistingSecretAndClosesItsWindow(t *testing.T) {
	m, dir := enrolRig(t)
	old, _, _ := m.Enrol("a", "openwrt-mcp", "r")
	oldCode, _ := totpAt(old, uint64(t0.Unix())/30)
	m.Attempt("a", unlockAttempt{Code: oldCode}, policyFor(factorTOTP), t0)
	runMFAEnrol(io.Discard, m, dir, []string{"a", "--pending"})
	pend, _ := parseMFAFile(filepath.Join(dir, "mfa.pending"))
	code, _ := totpAt(pend["a"], uint64(t0.Unix())/30)
	if err := runMFAActivate(io.Discard, m, []string{"a", code}, t0); err != nil {
		t.Fatal(err)
	}
	if _, open := m.UnlockedUntil("a", t0); open {
		t.Error("a window opened under the old secret survived its rotation")
	}
	active, _ := parseMFAFile(filepath.Join(dir, "mfa"))
	if active["a"] != pend["a"] || active["a"] == old {
		t.Error("the secret was not rotated")
	}
}

func TestActivateWithNothingPendingSaysHowToStart(t *testing.T) {
	m, dir := enrolRig(t)
	_ = dir
	err := runMFAActivate(io.Discard, m, []string{"ghost", "123456"}, t0)
	if err == nil || !strings.Contains(err.Error(), "no pending enrolment") ||
		!strings.Contains(err.Error(), "mfa enrol ghost --pending") {
		t.Errorf("err = %v", err)
	}
}

func TestEnrolAndActivateRefuseBadArguments(t *testing.T) {
	m, dir := enrolRig(t)
	for name, args := range map[string][]string{
		"no client":        {},
		"only flags":       {"--qr"},
		"too many":         {"a", "label", "extra"},
		"unknown flag":     {"a", "--frobnicate"},
		"single dash":      {"a", "-qr"},
		"client has space": {"a b"},
	} {
		if err := runMFAEnrol(io.Discard, m, dir, args); err == nil {
			t.Errorf("enrol %s: accepted", name)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("a refused enrolment still created state")
	}
	for name, args := range map[string][]string{"none": {}, "one": {"a"}, "three": {"a", "1", "2"}} {
		err := runMFAActivate(io.Discard, m, args, t0)
		if err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("activate %s: err = %v", name, err)
		}
	}
}

func TestEnrolFlagsMayComeAnywhere(t *testing.T) {
	m, dir := enrolRig(t)
	var out bytes.Buffer
	if err := runMFAEnrol(&out, m, dir, []string{"--json", "a", "--pending", "lab"}); err != nil {
		t.Fatal(err)
	}
	var obj map[string]string
	if err := json.Unmarshal(out.Bytes(), &obj); err != nil || obj["client"] != "a" ||
		!strings.Contains(obj["uri"], "a@lab") {
		t.Errorf("flags before and after the client were not understood: %v %s", err, out.String())
	}
	if m.Enrolled("a") {
		t.Error("--pending among the flags was ignored")
	}
}
