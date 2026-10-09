package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// apk_add through the real tool handler, with a fake `apk` on PATH that records, for every
// call, its argv one element per line, the directory it ran in and what that directory held,
// $APK_CONFIG, and a copy of the repositories file it was handed (the tool deletes its own copy
// when it returns). It answers `update`, `add --simulate` and `add` the way apk 3.0.5 does in
// the 25.12.4 rootfs.

const apkGrantAll = "\nconfig policy\n\toption client 'a'\n\tlist tools 'apk_add'\n\tlist scopes '*'\n"

// customFeed is what a router with this project's own feed added has in customfeeds.list, and
// what a careless installer might put into distfeeds.list as well.
const customFeed = "https://feed.example.net/hermes-openwrt/packages.adb"

type apkRig struct {
	s        *Server
	stateDir string
	logDir   string
}

// newApkRig puts the 25.12.4 distfeeds.list, with a custom feed appended, and a customfeeds.list
// beside it, and a fake apk on PATH. failAdd makes `apk add` fail the way apk does for a name no
// feed has; addOutput, if not empty, replaces what a successful `apk add` prints.
func newApkRig(t *testing.T, policies string, failAdd bool, addOutput string) *apkRig {
	t.Helper()
	feeds := t.TempDir()
	dist := filepath.Join(feeds, "distfeeds.list")
	if err := os.WriteFile(dist, []byte(distfeeds25124+customFeed+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feeds, "customfeeds.list"), []byte(customFeed+"\n/tmp/feed/packages.adb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := apkDistfeedsPath
	apkDistfeedsPath = dist
	t.Cleanup(func() { apkDistfeedsPath = old })

	logDir := t.TempDir()
	if addOutput == "" {
		addOutput = "(1/2) Installing libpcap1 (1.10.6-r1)\n  Executing libpcap1-1.10.6-r1.post-install\n" +
			"(2/2) Installing tcpdump (4.99.6-r1)\n  Executing tcpdump-4.99.6-r1.post-install\nOK: 12.5 MiB in 138 packages"
	}
	if err := os.WriteFile(filepath.Join(logDir, "add.out"), []byte(addOutput+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fail := "0"
	if failAdd {
		fail = "1"
	}
	fakeCmd(t, "apk", `L="`+logDir+`"
n=$(ls "$L" | grep -c '\.argv$')
f="$L/call.$n"
printf '%s\n' "$@" > "$f.argv"
pwd -P > "$f.pwd"
ls -A > "$f.ls"
printf '%s' "${APK_CONFIG-unset}" > "$f.env"
prev=
for a in "$@"; do
	[ "$prev" = --repositories-file ] && cp "$a" "$f.repo"
	prev=$a
done
case " $* " in
*" update"*) echo "OK: 11283 distinct packages available"; exit 0 ;;
*" --simulate "*) printf '(1/2) Installing libpcap1 (1.10.6-r1)\n(2/2) Installing tcpdump (4.99.6-r1)\nOK: 12.5 MiB in 138 packages\n'; exit 0 ;;
esac
if [ `+fail+` = 1 ]; then
	printf 'ERROR: unable to select packages:\n  nosuchpkg (no such package):\n    required by: world[nosuchpkg]\n' >&2
	exit 1
fi
cat "$L/add.out"`)
	s, dir := newToolRig(t, policies)
	return &apkRig{s: s, stateDir: dir, logDir: logDir}
}

type apkCall struct {
	argv         []string
	pwd, ls, env string
	repo         string
	hadRepoFile  bool
}

func (r *apkRig) calls(t *testing.T) []apkCall {
	t.Helper()
	var out []apkCall
	for i := 0; ; i++ {
		f := filepath.Join(r.logDir, fmt.Sprintf("call.%d", i))
		argv, err := os.ReadFile(f + ".argv")
		if err != nil {
			break
		}
		read := func(ext string) string { b, _ := os.ReadFile(f + ext); return string(b) }
		_, statErr := os.Stat(f + ".repo")
		out = append(out, apkCall{
			argv: strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n"),
			pwd:  strings.TrimSpace(read(".pwd")), ls: read(".ls"), env: read(".env"),
			repo: read(".repo"), hadRepoFile: statErr == nil,
		})
	}
	return out
}

func (r *apkRig) add(t *testing.T, client string, packages []string, dryRun bool) (string, bool) {
	t.Helper()
	return callTool(t, r.s, client, "apk_add", map[string]any{"packages": packages, "dry_run": dryRun})
}

// apkLooseningFlags are the apk options that would let a package in from somewhere other than
// the official feeds, or past its signature. None may ever appear.
var apkLooseningFlags = []string{"--allow-untrusted", "--force", "-f", "--keys-dir", "--root", "-p", "--arch",
	"--repository", "-X", "--repository-config", "--no-network", "--network", "--check-certificate",
	"--no-check-certificate", "--force-overwrite", "--force-non-repository", "--force-broken-world",
	"--force-missing-repositories", "--force-old-apk", "--force-no-chroot", "--preserve-env", "--cache-dir"}

// assertOfficialApkCalls is the whole contract of a call that runs apk: exactly two calls,
// update then add, with the fixed argv, the official feeds and nothing else in the repositories
// file, an empty working directory, /etc/apk/config switched off, and the file gone afterwards.
func assertOfficialApkCalls(t *testing.T, r *apkRig, names []string, dryRun bool) {
	t.Helper()
	cs := r.calls(t)
	if len(cs) != 2 {
		t.Fatalf("apk ran %d times, want update then add: %+v", len(cs), cs)
	}
	repoPath := cs[0].argv[1]
	// Spelled out here rather than taken from apkArgv, so a change there cannot change what
	// this test expects with it.
	wantUpdate := []string{"--repositories-file", repoPath, "--no-interactive", "update"}
	wantAdd := []string{"--repositories-file", repoPath, "--no-interactive", "add"}
	if dryRun {
		wantAdd = append(wantAdd, "--simulate")
	}
	wantAdd = append(append(wantAdd, "--"), names...)
	for i, want := range [][]string{wantUpdate, wantAdd} {
		if got := strings.Join(cs[i].argv, " "); got != strings.Join(want, " ") {
			t.Errorf("call %d argv:\n  %s\nwant:\n  %s", i, got, strings.Join(want, " "))
		}
	}
	if cs[0].argv[0] != "--repositories-file" || cs[1].argv[1] != repoPath {
		t.Errorf("the two calls did not share one repositories file: %q %q", cs[0].argv, cs[1].argv)
	}
	if dryRun != strings.Contains(strings.Join(cs[1].argv, " "), " --simulate ") {
		t.Errorf("dry_run=%v but add argv is %q", dryRun, cs[1].argv)
	}
	for i, c := range cs {
		for _, a := range c.argv {
			for _, bad := range apkLooseningFlags {
				if a == bad || (strings.HasPrefix(bad, "--") && strings.HasPrefix(a, bad+"=")) || strings.HasPrefix(a, "--force") {
					t.Errorf("call %d passed %q", i, a)
				}
			}
		}
		if !c.hadRepoFile {
			t.Errorf("call %d: no repositories file to read", i)
		}
		if c.repo != distfeeds25124 {
			t.Errorf("call %d: repositories file holds:\n%s\nwant exactly the official feeds:\n%s", i, c.repo, distfeeds25124)
		}
		if strings.Contains(c.repo, "feed.example.net") || strings.Contains(c.repo, "/tmp/feed") {
			t.Errorf("call %d: a custom feed reached apk:\n%s", i, c.repo)
		}
		if c.ls != "" {
			t.Errorf("call %d: apk ran in a directory holding %q; a name with a dot could be read as that file", i, c.ls)
		}
		if c.env != "/dev/null" {
			t.Errorf("call %d: APK_CONFIG=%q, so /etc/apk/config could add options such as allow-untrusted", i, c.env)
		}
		if wd, _ := os.Getwd(); c.pwd == "" || c.pwd == wd {
			t.Errorf("call %d: apk ran in %q", i, c.pwd)
		}
	}
	if _, err := os.Stat(repoPath); !os.IsNotExist(err) {
		t.Errorf("the repositories file %s was left behind (%v)", repoPath, err)
	}
}

func TestApkAddDryRunSimulatesFromTheOfficialFeedsOnly(t *testing.T) {
	r := newApkRig(t, apkGrantAll, false, "")
	out, isErr := r.add(t, "a", []string{"tcpdump"}, true)
	if isErr {
		t.Fatalf("dry run failed:\n%s", out)
	}
	assertOfficialApkCalls(t, r, []string{"tcpdump"}, true)
	for _, want := range []string{"Dry run: nothing was installed", "official OpenWrt feeds only (8 feed(s))",
		"install libpcap1 1.10.6-r1", "install tcpdump 4.99.6-r1", "dependencies apk pulls in",
		"OK: 12.5 MiB in 138 packages"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
}

func TestApkAddInstallsFromTheOfficialFeedsOnly(t *testing.T) {
	r := newApkRig(t, apkGrantAll, false, "")
	out, isErr := r.add(t, "a", []string{"tcpdump", "golang1.26"}, false)
	if isErr {
		t.Fatalf("install failed:\n%s", out)
	}
	assertOfficialApkCalls(t, r, []string{"tcpdump", "golang1.26"}, false)
	for _, want := range []string{"Done, from the official OpenWrt feeds only", "Executing tcpdump-4.99.6-r1.post-install",
		"OK: 12.5 MiB in 138 packages"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, e := range auditEvents(t, r.stateDir) {
		if e.Tool == "apk_add" && (e.Outcome != OutcomeOK || e.Summary != "apk add tcpdump golang1.26") {
			t.Errorf("audited as %s %q", e.Outcome, e.Summary)
		}
	}
}

// A dependency that upgrades a package already installed is said so apart from the installs.
func TestApkAddNamesUpgradesOfInstalledPackages(t *testing.T) {
	r := newApkRig(t, apkGrantAll, false, "(1/2) Upgrading libiperf3 (3.19-r1 -> 3.20-r1)\n"+
		"(2/2) Installing iperf3 (3.20-r1)\nOK: 11.5 MiB in 139 packages")
	out, isErr := r.add(t, "a", []string{"iperf3"}, false)
	if isErr || !strings.Contains(out, "change packages already installed") ||
		!strings.Contains(out, "upgrading libiperf3 3.19-r1 -> 3.20-r1") {
		t.Errorf("an upgrade was not called out:\n%s (error=%v)", out, isErr)
	}
}

// Every way of naming something other than an official package is refused before apk runs at
// all, and audited as DENIED.
func TestApkAddRefusesWhatIsNotAPackageNameAndRunsNothing(t *testing.T) {
	cases := [][]string{
		{"https://evil.example/x.apk"}, {"http://evil.example/x"}, {"/tmp/x.apk"}, {"tmp/x"},
		{"x.apk"}, {"-x"}, {"--allow-untrusted"}, {"name=1.0"}, {"tcpdump>=4"}, {"tcpdump@custom"},
		{".build-deps"}, {"x;reboot"}, {}, {"tcpdump", "file:///tmp/evil.apk"},
	}
	many := make([]string, apkMaxPackages+1)
	for i := range many {
		many[i] = fmt.Sprintf("p%d", i)
	}
	cases = append(cases, many)
	for _, names := range cases {
		r := newApkRig(t, apkGrantAll, false, "")
		out, isErr := r.add(t, "a", names, false)
		if !isErr || !strings.Contains(out, "refused:") {
			t.Errorf("%q: not refused:\n%s", names, out)
		}
		if cs := r.calls(t); len(cs) != 0 {
			t.Errorf("%q: apk ran %d time(s)", names, len(cs))
		}
		evs := auditEvents(t, r.stateDir)
		if len(evs) != 1 || evs[0].Tool != "apk_add" || evs[0].Outcome != OutcomeDenied || !strings.Contains(evs[0].Error, "refused:") {
			t.Errorf("%q: audited as %+v", names, evs)
		}
	}
}

func TestApkAddRefusalIsAuditedDenied(t *testing.T) {
	r := newApkRig(t, apkGrantAll, false, "")
	_, _ = r.add(t, "a", []string{"https://evil.example/x.apk"}, true)
	var found bool
	for _, e := range auditEvents(t, r.stateDir) {
		if e.Tool == "apk_add" {
			found = true
			if e.Outcome != OutcomeDenied || !strings.Contains(e.Error, `refused: "https://evil.example/x.apk" is a URL`) {
				t.Errorf("audited as %s %q", e.Outcome, e.Error)
			}
			if e.Summary != "apk add --simulate https://evil.example/x.apk" {
				t.Errorf("summary %q", e.Summary)
			}
		}
	}
	if !found {
		t.Error("the refused apk_add was not audited")
	}
}

// When distfeeds.list names no official feed, or is missing, there is nothing to install from,
// and the refusal never repeats a line it dropped: a private feed's URL can carry a token.
func TestApkAddRefusesWhenNoOfficialFeedRemains(t *testing.T) {
	for name, content := range map[string]*string{
		"only custom feeds": ptr("https://user:SECRET-TOKEN@feed.example.net/packages.adb\n/tmp/feed/packages.adb\n" +
			"http://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb\n"),
		"only comments": ptr("# https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb\n"),
		"missing":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			r := newApkRig(t, apkGrantAll, false, "")
			if content == nil {
				if err := os.Remove(apkDistfeedsPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(apkDistfeedsPath, []byte(*content), 0o644); err != nil {
				t.Fatal(err)
			}
			out, isErr := r.add(t, "a", []string{"tcpdump"}, false)
			if !isErr || !strings.Contains(out, "names no official OpenWrt feed") {
				t.Errorf("not refused:\n%s", out)
			}
			if strings.Contains(out, "SECRET-TOKEN") || strings.Contains(out, "feed.example.net") {
				t.Errorf("the refusal repeats a dropped line:\n%s", out)
			}
			if cs := r.calls(t); len(cs) != 0 {
				t.Errorf("apk ran %d time(s)", len(cs))
			}
			for _, e := range auditEvents(t, r.stateDir) {
				if e.Tool == "apk_add" && e.Outcome != OutcomeDenied {
					t.Errorf("audited as %s", e.Outcome)
				}
				if strings.Contains(e.Error, "SECRET-TOKEN") {
					t.Error("the token reached the audit log")
				}
			}
		})
	}
}

func ptr(s string) *string { return &s }

// Nothing grants apk_add unless a policy names it: not the configuration the package ships,
// not a policy granting every other tool on every scope.
func TestApkAddIsGrantedByNoPolicyByDefault(t *testing.T) {
	shipped, err := os.ReadFile("files/etc/config/openwrt-mcp")
	if err != nil {
		t.Fatal(err)
	}
	others := "\nconfig policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist tools 'uci_apply'\n" +
		"\tlist tools 'uci_get'\n\tlist tools 'exec'\n\tlist tools 'logread'\n\tlist tools 'wg_new_client'\n\tlist scopes '*'\n"
	for name, policies := range map[string]string{"no policy": "", "every other tool": others} {
		t.Run(name, func(t *testing.T) {
			r := newApkRig(t, policies, false, "")
			out, isErr := r.add(t, "a", []string{"tcpdump"}, true)
			if !isErr || !strings.Contains(out, "no policy grants apk_add") {
				t.Errorf("not denied:\n%s", out)
			}
			if cs := r.calls(t); len(cs) != 0 {
				t.Errorf("apk ran %d time(s)", len(cs))
			}
		})
	}
	// The shipped config itself: loaded, it grants apk_add to nobody.
	cfg := filepath.Join(t.TempDir(), "openwrt-mcp")
	if err := os.WriteFile(cfg, shipped, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Authorise("claude-code", "apk_add", []string{"tcpdump"}, time.Now()); ok {
		t.Error("the shipped config grants apk_add")
	}
}

// The policy scope is the package name, and one policy must cover every name in the call.
func TestApkAddScopeIsThePackageName(t *testing.T) {
	only := "\nconfig policy\n\toption client 'a'\n\tlist tools 'apk_add'\n\tlist scopes 'tcpdump'\n\tlist scopes 'kmod-*'\n"
	for _, c := range []struct {
		names []string
		ok    bool
	}{
		{[]string{"tcpdump"}, true}, {[]string{"kmod-wireguard"}, true}, {[]string{"iperf3"}, false},
		{[]string{"tcpdump", "iperf3"}, false},
	} {
		r := newApkRig(t, only, false, "")
		out, isErr := r.add(t, "a", c.names, true)
		if c.ok == isErr {
			t.Errorf("%v: error=%v, want allowed=%v:\n%s", c.names, isErr, c.ok, out)
		}
		if !c.ok && !strings.Contains(out, "no policy scope covers") {
			t.Errorf("%v: denied for another reason:\n%s", c.names, out)
		}
	}
}

// apk failing is an ERROR (it broke), not a DENIED, and what apk said comes back, bounded.
func TestApkAddFailureIsAnErrorWithApksWords(t *testing.T) {
	r := newApkRig(t, apkGrantAll, true, "")
	out, isErr := r.add(t, "a", []string{"nosuchpkg"}, false)
	if !isErr || !strings.Contains(out, "apk add failed") || !strings.Contains(out, "nosuchpkg (no such package)") {
		t.Errorf("failure not reported:\n%s", out)
	}
	for _, e := range auditEvents(t, r.stateDir) {
		if e.Tool == "apk_add" && e.Outcome != OutcomeError {
			t.Errorf("audited as %s", e.Outcome)
		}
	}
	// A flood of output is cut, and apk's verdict at the end survives.
	r = newApkRig(t, apkGrantAll, false, strings.Repeat("(1/1) Installing x (1)\n", 20000)+"OK: 99 MiB in 9 packages")
	out, isErr = r.add(t, "a", []string{"x"}, false)
	if isErr || len(out) > apkOutputMax+4096 || !strings.Contains(out, "OK: 99 MiB in 9 packages") {
		t.Errorf("unbounded or verdict lost: %d bytes, error=%v", len(out), isErr)
	}
}

// What an MCP client is told the tool takes: a list of names, and a flag.
func TestApkAddToolSchema(t *testing.T) {
	s, _ := newToolRig(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.newServerForClient("a").Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name != "apk_add" {
			continue
		}
		b, _ := json.Marshal(tool.InputSchema)
		t.Logf("apk_add input schema: %s", b)
		var sc struct {
			Type       string   `json:"type"`
			Required   []string `json:"required"`
			Properties map[string]struct {
				Type  any `json:"type"`
				Items *struct {
					Type any `json:"type"`
				} `json:"items"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(b, &sc); err != nil {
			t.Fatal(err)
		}
		var props []string
		for k := range sc.Properties {
			props = append(props, k)
		}
		sort.Strings(props)
		if strings.Join(props, ",") != "dry_run,packages" || strings.Join(sc.Required, ",") != "packages" {
			t.Errorf("properties %v, required %v", props, sc.Required)
		}
		p := sc.Properties["packages"]
		// The SDK writes a Go slice as nullable; a null list is refused like an empty one
		// (TestApkAddRefusesWhatIsNotAPackageNameAndRunsNothing).
		if typ := fmt.Sprint(p.Type); (typ != "array" && typ != "[null array]") || p.Items == nil ||
			fmt.Sprint(p.Items.Type) != "string" {
			t.Errorf("packages is %v of %+v", p.Type, p.Items)
		}
		if fmt.Sprint(sc.Properties["dry_run"].Type) != "boolean" {
			t.Errorf("dry_run is %v", sc.Properties["dry_run"].Type)
		}
		return
	}
	t.Error("no apk_add tool is listed")
}
