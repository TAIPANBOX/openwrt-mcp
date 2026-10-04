package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The PIN is the owner's secret, so every test here is about what happens to the digits:
// which shapes are refused, that only a salted hash ever reaches disk, and that a wrong
// guess and a right one are told apart by a real comparison rather than by length or luck.

// dataLines returns the non-comment lines of a state file.
func dataLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func newPINs(t *testing.T) (*PINStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "pin")
	p, err := LoadPINs(path)
	if err != nil {
		t.Fatal(err)
	}
	return p, path
}

func TestValidatePIN(t *testing.T) {
	for _, ok := range []string{"1234", "12345678", "0000", "00012", "987654"} {
		if err := validatePIN(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"three digits":      "123",
		"nine digits":       "123456789",
		"empty":             "",
		"letters":           "12ab",
		"all letters":       "abcd",
		"leading space":     " 1234",
		"trailing space":    "1234 ",
		"inner space":       "12 34",
		"newline inside":    "12\n34",
		"trailing newline":  "1234\n",
		"sign":              "+1234",
		"decimal":           "12.34",
		"arabic-indic":      "١٢٣٤",
		"fullwidth digits":  "１２３４",
		"superscript":       "¹²³⁴",
		"digits plus emoji": "1234🙂",
		"nul":               "1234\x00",
	} {
		err := validatePIN(bad)
		if err == nil {
			t.Errorf("%s (%q) was accepted", name, bad)
			continue
		}
		// The refusal must say what is wanted, and must never echo what was typed.
		if !strings.Contains(err.Error(), "4 to 8") {
			t.Errorf("%s: unhelpful message %q", name, err)
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("%s: the message echoes the input: %q", name, err)
		}
	}
}

func TestPINSetStoresOnlyASaltedHash(t *testing.T) {
	p, path := newPINs(t)
	const pin = "482915"
	if err := p.Set("claude-code", pin); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(pin)) {
		t.Fatalf("the plaintext PIN is on disk:\n%s", b)
	}
	lines := dataLines(b)
	if len(lines) != 1 {
		t.Fatalf("want one line per client, got %d:\n%s", len(lines), b)
	}
	client, rec, ok := strings.Cut(lines[0], " ")
	if !ok || client != "claude-code" {
		t.Fatalf("want '<client> <record>', got %q", lines[0])
	}
	parts := strings.Split(rec, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] != fmt.Sprint(pinIterations) {
		t.Fatalf("record shape is wrong: %q", rec)
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	hash, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		t.Fatalf("salt/hash are not base64: %v %v", err1, err2)
	}
	if len(salt) != 16 || len(hash) != 32 {
		t.Errorf("salt %d bytes, hash %d bytes; want 16 and 32", len(salt), len(hash))
	}
	// The stored hash is genuinely PBKDF2-HMAC-SHA256 of the PIN under that salt, computed
	// here with the standard library independently of the code under test.
	want, _ := pbkdf2.Key(sha256.New, pin, salt, pinIterations, 32)
	if !bytes.Equal(want, hash) {
		t.Error("the stored hash is not PBKDF2-HMAC-SHA256(pin, salt, iterations)")
	}
}

func TestPINSetUsesAFreshSaltEachTime(t *testing.T) {
	p, path := newPINs(t)
	p.Set("a", "1234")
	first, _ := os.ReadFile(path)
	p.Set("a", "1234")
	second, _ := os.ReadFile(path)
	if bytes.Equal(first, second) {
		t.Fatal("the same PIN produced an identical record twice, so the salt is not random")
	}
	// Two clients choosing the same PIN must not be recognisable as such from the file.
	p.Set("b", "1234")
	b, _ := os.ReadFile(path)
	recs := map[string]bool{}
	for _, l := range dataLines(b) {
		recs[strings.SplitN(l, " ", 2)[1]] = true
	}
	if len(recs) != 2 {
		t.Errorf("two clients with one PIN share a record: %s", b)
	}
}

func TestPINFilePermissions(t *testing.T) {
	p, path := newPINs(t)
	if err := p.Set("a", "1234"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("pin file mode %v, want 0600", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, want 0700", dst.Mode().Perm())
	}
}

// Write to a sidecar and rename, so a crash mid-write cannot leave a half-file that drops
// every client's PIN. A stale sidecar from an earlier crash must not block the next write.
func TestPINSetWritesBySidecarRename(t *testing.T) {
	p, path := newPINs(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".new", []byte("junk from a crashed write"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.Set("a", "1234"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Error("the sidecar was left behind, so the rename did not happen")
	}
	if st, _ := os.Stat(path); st == nil || st.Mode().Perm() != 0o600 {
		t.Error("the replaced file does not carry 0600")
	}
	if !p.Verify("a", "1234") {
		t.Error("PIN not usable after the sidecar write")
	}
}

func TestPINSetRefusesABadPINAndWritesNothing(t *testing.T) {
	p, path := newPINs(t)
	for _, bad := range []string{"123", "123456789", "abcd", "", " 1234"} {
		if err := p.Set("a", bad); err == nil {
			t.Errorf("Set accepted %q", bad)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused PIN still created a file")
	}
	if p.Has("a") {
		t.Error("a refused PIN is nevertheless set")
	}
}

func TestPINSetRefusesAClientNameThatBreaksTheFile(t *testing.T) {
	p, path := newPINs(t)
	for _, bad := range []string{"", "two words", "tab\tname", "line\nbreak", "cr\rname"} {
		if err := p.Set(bad, "1234"); err == nil {
			t.Errorf("accepted client name %q", bad)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a bad client name still created a file")
	}
}

func TestPINVerify(t *testing.T) {
	p, _ := newPINs(t)
	p.Set("a", "0042")
	p.Set("b", "987654")

	if !p.Verify("a", "0042") {
		t.Error("the right PIN was refused")
	}
	if !p.Verify("b", "987654") {
		t.Error("the right PIN of a second client was refused")
	}
	for name, tc := range map[string]struct{ client, pin string }{
		"wrong":             {"a", "0043"},
		"dropped zeros":     {"a", "42"},
		"another clients":   {"a", "987654"},
		"prefix":            {"b", "9876"},
		"extension":         {"b", "9876540"},
		"empty":             {"a", ""},
		"unknown client":    {"nobody", "0042"},
		"huge":              {"a", strings.Repeat("9", 1<<20)},
		"padded":            {"a", " 0042"},
		"unicode lookalike": {"a", "００４２"},
	} {
		if p.Verify(tc.client, tc.pin) {
			t.Errorf("%s: a wrong PIN was accepted", name)
		}
	}
	if !p.Has("a") || p.Has("nobody") {
		t.Error("Has disagrees with what was set")
	}
}

// The iteration count lives in the record, so raising the constant later does not strand
// PINs already set. Built here from the standard library, with SHA-256, so a verifier that
// quietly used another hash or ignored the stored count would fail.
func TestPINVerifyHonoursTheStoredIterationCount(t *testing.T) {
	salt := []byte("0123456789abcdef")
	hash, _ := pbkdf2.Key(sha256.New, "5555", salt, 1000, 32)
	rec := fmt.Sprintf("pbkdf2-sha256$1000$%s$%s",
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash))
	p, path := newPINs(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("a "+rec+"\n"), 0o600)
	p, _ = LoadPINs(path)

	if !p.Verify("a", "5555") {
		t.Error("a record with its own iteration count was not honoured")
	}
	if p.Verify("a", "5556") {
		t.Error("a wrong PIN passed against a hand-built record")
	}
}

func TestPINLoadSkipsMalformedRecords(t *testing.T) {
	salt := []byte("0123456789abcdef")
	good, _ := pbkdf2.Key(sha256.New, "1234", salt, 1000, 32)
	short, _ := pbkdf2.Key(sha256.New, "1234", salt, 1000, 16)
	enc := base64.StdEncoding.EncodeToString
	goodRec := fmt.Sprintf("pbkdf2-sha256$1000$%s$%s", enc(salt), enc(good))

	path := filepath.Join(t.TempDir(), "pin")
	os.WriteFile(path, []byte(strings.Join([]string{
		"# a comment",
		"",
		"noRecord",
		"scheme sha1$1000$" + enc(salt) + "$" + enc(good),
		"zeroiter pbkdf2-sha256$0$" + enc(salt) + "$" + enc(good),
		"hugeiter pbkdf2-sha256$99999999999$" + enc(salt) + "$" + enc(good),
		"negiter pbkdf2-sha256$-5$" + enc(salt) + "$" + enc(good),
		"notnum pbkdf2-sha256$abc$" + enc(salt) + "$" + enc(good),
		"badsalt pbkdf2-sha256$1000$!!!$" + enc(good),
		"badhash pbkdf2-sha256$1000$" + enc(salt) + "$!!!",
		"emptysalt pbkdf2-sha256$1000$$" + enc(good),
		"shorthash pbkdf2-sha256$1000$" + enc(salt) + "$" + enc(short),
		"fields pbkdf2-sha256$1000$" + enc(salt),
		"fine " + goodRec,
	}, "\n")+"\n"), 0o600)

	p, err := LoadPINs(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"noRecord", "scheme", "zeroiter", "hugeiter", "negiter", "notnum",
		"badsalt", "badhash", "emptysalt", "shorthash", "fields"} {
		if p.Has(c) {
			t.Errorf("%s: a malformed record counts as a PIN being set", c)
		}
		if p.Verify(c, "1234") {
			t.Errorf("%s: a malformed record verified", c)
		}
	}
	if !p.Verify("fine", "1234") {
		t.Error("the one valid record was lost among the bad ones")
	}
}

func TestPINClear(t *testing.T) {
	p, path := newPINs(t)
	p.Set("a", "1234")
	p.Set("b", "5678")

	was, err := p.Clear("a")
	if err != nil || !was {
		t.Fatalf("Clear(a) = %v, %v; want true, nil", was, err)
	}
	if p.Verify("a", "1234") || p.Has("a") {
		t.Error("the PIN still works after clear")
	}
	if !p.Verify("b", "5678") {
		t.Error("clearing one client removed another")
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "a pbkdf2") {
		t.Errorf("the record is still in the file: %s", b)
	}

	was, err = p.Clear("a")
	if err != nil || was {
		t.Errorf("clearing an absent PIN = %v, %v; want false, nil", was, err)
	}
}

// `openwrt-mcp pin set` is a separate process from the daemon, so a PIN changed or cleared
// from the CLI has to take effect on a running daemon, as enrolment and `allow` already do.
func TestPINHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin")
	daemon, _ := LoadPINs(path)
	cli, _ := LoadPINs(path)
	t0 := time.Unix(1700000000, 0)

	if daemon.Verify("a", "1234") {
		t.Fatal("verified with nothing set")
	}
	cli.Set("a", "1234")
	os.Chtimes(path, t0, t0)
	if !daemon.Verify("a", "1234") || !daemon.Has("a") {
		t.Fatal("the daemon did not pick up a PIN set by another process")
	}

	cli.Set("a", "9999") // rotate
	os.Chtimes(path, t0.Add(time.Hour), t0.Add(time.Hour))
	if daemon.Verify("a", "1234") {
		t.Error("the old PIN still works after a rotation")
	}
	if !daemon.Verify("a", "9999") {
		t.Error("the new PIN does not work")
	}

	cli.Clear("a")
	os.Chtimes(path, t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	if daemon.Verify("a", "9999") || daemon.Has("a") {
		t.Error("a cleared PIN still works on the running daemon")
	}
}

// A half-written file must never wipe PINs that work.
func TestPINReloadKeepsWorkingPINsWhenTheFileIsUnreadable(t *testing.T) {
	p, path := newPINs(t)
	p.Set("a", "1234")
	// Replace the file with a directory: stat succeeds with a new mtime, reading fails.
	os.Remove(path)
	os.Mkdir(path, 0o700)
	t0 := time.Unix(1800000000, 0)
	os.Chtimes(path, t0, t0)
	if !p.Verify("a", "1234") {
		t.Error("an unreadable file wiped the PINs held in memory")
	}
}

func TestPINFingerprintsChangeWithTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin")
	daemon, _ := LoadPINs(path)
	cli, _ := LoadPINs(path)
	cli.Set("a", "1111")
	cli.Set("b", "2222")
	t0 := time.Unix(1700000000, 0)
	os.Chtimes(path, t0, t0)
	before := daemon.Fingerprints()
	if len(before) != 2 || before["a"] == "" || before["a"] == before["b"] {
		t.Fatalf("fingerprints = %v", before)
	}

	cli.Set("a", "3333") // only a changes
	os.Chtimes(path, t0.Add(time.Hour), t0.Add(time.Hour))
	after := daemon.Fingerprints()
	if after["a"] == before["a"] {
		t.Error("a's fingerprint did not change when its PIN did")
	}
	if after["b"] != before["b"] {
		t.Error("b's fingerprint changed though b's PIN did not")
	}
	for _, f := range after {
		if strings.Contains(f, "pbkdf2") {
			t.Errorf("a fingerprint carries the record itself: %q", f)
		}
	}
}

func TestLoadPINsMissingFileIsEmptyAndDirectoryIsAnError(t *testing.T) {
	p, err := LoadPINs(filepath.Join(t.TempDir(), "absent"))
	if err != nil || p.Has("a") {
		t.Fatalf("a missing file must be a valid empty store: %v", err)
	}
	if _, err := LoadPINs(t.TempDir()); err == nil {
		t.Error("an unreadable pin path was treated as empty, which would silently disable the factor")
	}
}

func TestReadPINLine(t *testing.T) {
	for in, want := range map[string]string{
		"1234\n":     "1234",
		"1234\r\n":   "1234",
		"1234":       "1234", // piped with no newline
		"12\n34\n":   "12",   // exactly one line, never the rest
		"\n":         "",
		"  1234  \n": "  1234  ",
	} {
		got, err := readPINLine(strings.NewReader(in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if _, err := readPINLine(strings.NewReader("")); err == nil {
		t.Error("an empty stdin was not reported")
	}
	// Bounded: a runaway pipe must not be slurped into memory.
	if _, err := readPINLine(strings.NewReader(strings.Repeat("1", 1<<20))); err == nil {
		t.Error("a megabyte with no newline was accepted as a line")
	}
}

func TestRunPINSetReadsStdinAndPrintsNoSecret(t *testing.T) {
	state := t.TempDir()
	var out bytes.Buffer
	if err := runPIN(&out, strings.NewReader("482915\n"), state, []string{"set", "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "482915") {
		t.Errorf("the PIN was echoed: %q", out.String())
	}
	if !strings.Contains(out.String(), "claude-code") {
		t.Errorf("the output does not say which client: %q", out.String())
	}
	p, _ := LoadPINs(filepath.Join(state, "pin"))
	if !p.Verify("claude-code", "482915") {
		t.Error("the PIN piped on stdin was not stored")
	}
}

func TestRunPINSetRefusesBadInputWithAClearMessage(t *testing.T) {
	for name, in := range map[string]string{
		"short": "123\n", "long": "123456789\n", "letters": "12ab\n", "empty line": "\n",
		"no stdin": "", "spaces": "12 34\n", "unicode": "١٢٣٤\n",
	} {
		state := t.TempDir()
		var out bytes.Buffer
		err := runPIN(&out, strings.NewReader(in), state, []string{"set", "a"})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if in != "" && strings.TrimSpace(in) != "" && strings.Contains(err.Error(), strings.TrimSpace(in)) {
			t.Errorf("%s: error echoes the PIN: %v", name, err)
		}
		if _, statErr := os.Stat(filepath.Join(state, "pin")); !os.IsNotExist(statErr) {
			t.Errorf("%s: a file was written for a refused PIN", name)
		}
	}
}

// The PIN is never an argument: argv is world-readable in /proc and lands in shell history.
func TestRunPINRefusesAPINOnTheCommandLine(t *testing.T) {
	state := t.TempDir()
	var out bytes.Buffer
	err := runPIN(&out, strings.NewReader("482915\n"), state, []string{"set", "a", "123456"})
	if err == nil {
		t.Fatal("a PIN given as an argument was accepted")
	}
	if strings.Contains(err.Error(), "123456") {
		t.Errorf("the refusal echoes the argument: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(state, "pin")); !os.IsNotExist(statErr) {
		t.Error("a file was written despite the refusal")
	}
}

func TestRunPINClearAndUsage(t *testing.T) {
	state := t.TempDir()
	var out bytes.Buffer
	runPIN(&out, strings.NewReader("1234\n"), state, []string{"set", "a"})

	out.Reset()
	if err := runPIN(&out, strings.NewReader(""), state, []string{"clear", "a"}); err != nil {
		t.Fatal(err)
	}
	p, _ := LoadPINs(filepath.Join(state, "pin"))
	if p.Has("a") {
		t.Error("clear left the PIN in place")
	}
	if !strings.Contains(out.String(), "cleared") {
		t.Errorf("clear says nothing: %q", out.String())
	}
	out.Reset()
	if err := runPIN(&out, strings.NewReader(""), state, []string{"clear", "a"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no PIN") {
		t.Errorf("clearing nothing should say so: %q", out.String())
	}

	for _, args := range [][]string{nil, {"set"}, {"clear"}, {"frob", "a"}, {"set", "a", "b", "c"}, {"clear", "a", "b"}} {
		if err := runPIN(&out, strings.NewReader("1234\n"), state, args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: want a usage error, got %v", args, err)
		}
	}
	// A client name that cannot live in the file is refused before the PIN is read.
	if err := runPIN(&out, strings.NewReader("1234\n"), state, []string{"set", "two words"}); err == nil {
		t.Error("a client name with a space was accepted")
	}
}

// Measured on the router, not here: run
//
//	go test -run '^$' -bench BenchmarkPINVerify -benchtime 20x
//
// with a binary cross-built for the router (or the same bench on the box) to see what one
// verification costs. That number is the whole price of a guess for an attacker and of an
// unlock for the owner, and it is what pinIterations trades against.
func BenchmarkPINVerify(b *testing.B) {
	p, err := LoadPINs(filepath.Join(b.TempDir(), "pin"))
	if err != nil {
		b.Fatal(err)
	}
	if err := p.Set("a", "482915"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Verify("a", "482915") {
			b.Fatal("verify failed")
		}
	}
}
