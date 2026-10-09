package main

import (
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"testing"
)

// The rules apk_add decides with, as tables. The end-to-end tests (apk_add_e2e_test.go) prove
// the tool uses them; these prove what they decide.

// distfeeds25124 is /etc/apk/repositories.d/distfeeds.list as openwrt/rootfs:x86-64-25.12.4
// ships it, read on 2026-10-09.
const distfeeds25124 = "https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/packages/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/kmods/6.12.87-1-d037e17efc2c7cd4972f63d6de88677f/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/luci/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/packages/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/routing/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/telephony/packages.adb\n" +
	"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/video/packages.adb\n"

// apkNameCases: each bad name with the rule that must be the one to refuse it, and good names
// with "". A rule is named rather than its message compared, so rewording a message is free.
var apkNameCases = []struct{ in, rule string }{
	{"tcpdump", ""}, {"iperf3", ""}, {"libpcap1", ""}, {"kmod-wireguard", ""}, {"luci-app-sqm", ""},
	{"golang1.26", ""}, {"cqueues-lua5.4", ""}, {"UDPspeeder", ""}, {"cJSON", ""},
	{"perl-www_curl", ""}, {"libstdcpp+x", ""}, {"0ad", ""},
	{strings.Repeat("a", apkMaxNameLen), ""},

	{"", "empty"},
	{"-x", "flag"}, {"--allow-untrusted", "flag"}, {"--force-overwrite", "flag"}, {"-X", "flag"},
	{"https://evil.example/x.apk", "url"}, {"http://evil.example/x", "url"}, {"file:///tmp/x.apk", "url"},
	{"ftp://x/y", "url"},
	{"/tmp/x.apk", "path"}, {"./x", "path"}, {"tmp/x", "path"}, {"../../etc/passwd", "path"},
	{"x.apk", "apk-file"}, {"X.APK", "apk-file"}, {"tcpdump-4.99.6-r1.apk", "apk-file"},
	{"tcpdump=4.99.6-r1", "version"}, {"name=1.0", "version"}, {"tcpdump>=4", "version"},
	{"tcpdump<5", "version"}, {"tcpdump~4", "version"}, {"tcpdump><abc", "version"},
	{"tcpdump@custom", "tag"},
	{"tcpdump:x", "colon"}, {"c:x", "colon"},
	{".build-deps", "virtual"}, {".x", "virtual"},
	{"a..b", "dotdot"},
	{strings.Repeat("a", apkMaxNameLen+1), "too-long"},
	{"tcp dump", "grammar"}, {"tcpdump\n", "grammar"}, {"tcpdump\x00", "grammar"}, {"x;reboot", "grammar"},
	{"$(reboot)", "grammar"}, {"_x", "grammar"}, {"+x", "grammar"}, {"tcpdümp", "grammar"},
	{"x\\y", "grammar"}, {"x*", "grammar"}, {"x'y", "grammar"},
}

// apkNameRuleFired is the name of the rule that refuses n, or "".
func apkNameRuleFired(n string) string {
	for _, r := range apkNameRules {
		if r.bad(n) {
			return r.name
		}
	}
	return ""
}

func apkNameTableFailures() []string {
	var out []string
	for _, c := range apkNameCases {
		if got := apkNameRuleFired(c.in); got != c.rule {
			out = append(out, fmt.Sprintf("%q: refused by %q, want %q", c.in, got, c.rule))
		}
		if (apkNameRefusal(c.in) == "") != (c.rule == "") {
			out = append(out, fmt.Sprintf("%q: apkNameRefusal disagrees with the rules", c.in))
		}
	}
	return out
}

func TestApkNameTable(t *testing.T) {
	for _, f := range apkNameTableFailures() {
		t.Error(f)
	}
}

// Mutation, in-process: take any one rule out and the table must go red, either because a bad
// name is let through or because it is refused for a reason the agent was not meant to read.
func TestDroppingAnyApkNameRuleTurnsTheTableRed(t *testing.T) {
	if f := apkNameTableFailures(); len(f) != 0 {
		t.Fatalf("the table is red before anything is dropped: %v", f)
	}
	saved := apkNameRules
	defer func() { apkNameRules = saved }()
	for i, r := range saved {
		apkNameRules = append(saved[:i:i], saved[i+1:]...)
		if len(apkNameTableFailures()) == 0 {
			t.Errorf("dropping the %q rule turns nothing red", r.name)
		}
		apkNameRules = saved
	}
	for _, r := range saved {
		if strings.TrimSpace(r.why) == "" {
			t.Errorf("rule %q gives the agent no reason", r.name)
		}
	}
}

func TestApkNameListLimits(t *testing.T) {
	if err := refuseApkNames(nil); err == nil || !isRefused(err) {
		t.Errorf("an empty list: %v", err)
	}
	many := make([]string, apkMaxPackages+1)
	for i := range many {
		many[i] = fmt.Sprintf("p%d", i)
	}
	if err := refuseApkNames(many); err == nil || !isRefused(err) || !strings.Contains(err.Error(), "at most 20") {
		t.Errorf("%d names: %v", len(many), err)
	}
	if err := refuseApkNames(many[:apkMaxPackages]); err != nil {
		t.Errorf("%d names refused: %v", apkMaxPackages, err)
	}
	// Every bad name is named, not only the first, and a good one beside them is not.
	err := refuseApkNames([]string{"tcpdump", "https://x/y.apk", "x.apk", "name=1.0"})
	if err == nil || !isRefused(err) {
		t.Fatalf("not refused: %v", err)
	}
	for _, want := range []string{`"https://x/y.apk"`, `"x.apk"`, `"name=1.0"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %s:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), `"tcpdump"`) {
		t.Errorf("refusal names a good package:\n%s", err)
	}
}

// Every official name that holds anything beyond lowercase, digits and '-' is accepted: a
// grammar narrower than the feed would make real packages uninstallable.
func TestApkNameAcceptsEveryUnusualOfficialName(t *testing.T) {
	b, err := os.ReadFile("testdata/openwrt-25.12-package-names-unusual.txt")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if why := apkNameRefusal(line); why != "" {
			t.Errorf("official package %q refused: %s", line, why)
		}
	}
	if n != 214 {
		t.Errorf("read %d names, want the 214 the fixture holds", n)
	}
}

// Whatever string an agent sends, a name that is accepted has the shape of a package name and
// nothing apk would read as anything else. The seeds run on every `go test`; `go test -fuzz
// FuzzApkPackageName` explores.
func FuzzApkPackageName(f *testing.F) {
	for _, c := range apkNameCases {
		f.Add(c.in)
	}
	f.Fuzz(func(t *testing.T, n string) {
		if apkNameRefusal(n) != "" {
			return
		}
		if !apkNameGrammar.MatchString(n) || len(n) > apkMaxNameLen || strings.ContainsAny(n, "/:=<>~@ \\") ||
			strings.HasPrefix(n, "-") || strings.HasPrefix(n, ".") || strings.Contains(n, "..") ||
			strings.HasSuffix(strings.ToLower(n), ".apk") {
			t.Fatalf("accepted %q", n)
		}
	})
}

// apkFeedCases: each line of a distfeeds.list with the rule that must be the one to drop it, or
// "" for a line that is kept.
var apkFeedCases = []struct{ in, rule string }{
	{"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb", ""},
	{"https://downloads.openwrt.org/releases/25.12.4/targets/x86/64/kmods/6.12.87-1-d037e17efc2c7cd4972f63d6de88677f/packages.adb", ""},
	{"https://downloads.openwrt.org/snapshots/packages/aarch64_cortex-a53/luci/packages.adb", ""},

	{"@custom https://downloads.openwrt.org/x/packages.adb", "not-one-url"},
	{"v3 https://downloads.openwrt.org/x/packages.adb", "not-one-url"},
	{"set mirror=https://evil.example", "not-one-url"},
	{"https://downloads.openwrt.org/x y/packages.adb", "not-one-url"},
	{"https://downloads.openwrt.org/${APK_ARCH}/packages.adb", "variable"},
	{"http://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb", "not-https"},
	{"file:///tmp/feed/packages.adb", "not-https"},
	{"/tmp/feed/packages.adb", "not-https"},
	{"https://user:token@downloads.openwrt.org/x/packages.adb", "userinfo"},
	{"https://downloads.openwrt.org@evil.example/x/packages.adb", "userinfo"},
	{"https://mirror.example.org/openwrt/releases/25.12.4/packages/x86_64/base/packages.adb", "host"},
	{"https://downloads.openwrt.org.evil.example/x/packages.adb", "host"},
	{"https://downloads.openwrt.org:8443/x/packages.adb", "host"},
	{"https://DOWNLOADS.OPENWRT.ORG/x/packages.adb", "host"},
	{"https://feed.example.net/hermes-openwrt/packages.adb", "host"},
	{"https://evil.example/downloads.openwrt.org/packages.adb", "host"},
	{"https://downloads.openwrt.org/x/packages.adb?x=1", "query"},
	{"https://downloads.openwrt.org/x#/packages.adb", "query"},
	{"https://downloads.openwrt.org/../x/packages.adb", "dotdot"},
	{"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/", "not-index"},
	{"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/Packages.gz", "not-index"},
	{"https://downloads.openwrt.org/x%2f/packages.adb", "shape"},
	{"https://downloads.openwrt.org//packages.adb", "shape"},
	{"https://downloads.openwrt.org/x\\y/packages.adb", "shape"},
}

func apkFeedRuleFired(l string) string {
	for _, r := range apkFeedRules {
		if r.bad(l) {
			return r.name
		}
	}
	return ""
}

func apkFeedTableFailures() []string {
	var out []string
	for _, c := range apkFeedCases {
		if got := apkFeedRuleFired(c.in); got != c.rule {
			out = append(out, fmt.Sprintf("%q: dropped by %q, want %q", c.in, got, c.rule))
		}
	}
	return out
}

func TestApkFeedLineTable(t *testing.T) {
	for _, f := range apkFeedTableFailures() {
		t.Error(f)
	}
}

func TestDroppingAnyApkFeedRuleTurnsTheTableRed(t *testing.T) {
	if f := apkFeedTableFailures(); len(f) != 0 {
		t.Fatalf("the table is red before anything is dropped: %v", f)
	}
	saved := apkFeedRules
	defer func() { apkFeedRules = saved }()
	for i, r := range saved {
		apkFeedRules = append(saved[:i:i], saved[i+1:]...)
		if len(apkFeedTableFailures()) == 0 {
			t.Errorf("dropping the %q rule turns nothing red", r.name)
		}
		apkFeedRules = saved
	}
}

// What the firmware ships is kept whole and in order; a custom feed someone added to the same
// file is dropped; comments, blanks and duplicates are not lines to use.
func TestOfficialFeedsFromDistfeeds(t *testing.T) {
	in := "# shipped by the firmware\n\n" + distfeeds25124 +
		"https://downloads.openwrt.org/releases/25.12.4/packages/x86_64/base/packages.adb\n" + // duplicate
		"https://feed.example.net/hermes-openwrt/packages.adb\n" +
		"/tmp/feed/packages.adb\n"
	kept, dropped := officialFeeds(in)
	if got, want := strings.Join(kept, "\n")+"\n", distfeeds25124; got != want {
		t.Errorf("kept:\n%s\nwant:\n%s", got, want)
	}
	if dropped != 2 {
		t.Errorf("dropped %d lines, want 2", dropped)
	}
	// customfeeds.list as the firmware ships it, and with a feed in it, gives nothing.
	for _, custom := range []string{"# add your custom package feeds here\n#\n# http://www.example.com/path/to/files/packages.adb\n",
		"https://feed.example.net/hermes-openwrt/packages.adb\n/tmp/feed/packages.adb\n"} {
		if kept, _ := officialFeeds(custom); len(kept) != 0 {
			t.Errorf("a customfeeds.list gave official feeds: %v", kept)
		}
	}
	if kept, dropped := officialFeeds(""); len(kept) != 0 || dropped != 0 {
		t.Errorf("an empty file: %v, %d", kept, dropped)
	}
}

// A kept line has exactly the shape of an official feed, whatever was done to it. Starting
// from a real line, each seed inserts one to three pieces of the usual ways to point a URL
// somewhere else, and anything still kept must parse as https on the official host with no
// user, port, query or fragment, naming a packages.adb.
func TestOfficialFeedLineSweep(t *testing.T) {
	base := strings.Split(strings.TrimSpace(distfeeds25124), "\n")
	pieces := []string{"@", ":", ":443", ".evil.example", "evil.example/", "http://", "https://", "?", "#", "..",
		"$", " ", "%2f", "/", "x", "\t", "user:pw@", "DOWNLOADS", "\\", "@evil.example", ".", "packages.adb"}
	kept := 0
	for seed := int64(1); seed <= 2000; seed++ {
		r := rand.New(rand.NewSource(seed))
		l := base[r.Intn(len(base))]
		for k := 1 + r.Intn(3); k > 0; k-- {
			at := r.Intn(len(l) + 1)
			l = l[:at] + pieces[r.Intn(len(pieces))] + l[at:]
		}
		if apkFeedLineRefusal(l) != "" {
			continue
		}
		kept++
		assertOfficialShape(t, fmt.Sprintf("seed %d", seed), l)
	}
	if kept == 0 {
		t.Error("the sweep kept no line at all, so it checked nothing")
	}
}

func assertOfficialShape(t *testing.T, label, l string) {
	t.Helper()
	u, err := url.Parse(l)
	if err != nil {
		t.Fatalf("%s: kept %q, which does not parse: %v", label, l, err)
	}
	if u.Scheme != "https" || u.Host != apkOfficialHost || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.ForceQuery || !strings.HasSuffix(u.Path, "/packages.adb") ||
		strings.Contains(l, "..") || strings.ContainsAny(l, " \t$") {
		t.Fatalf("%s: kept %q (scheme %q host %q user %v path %q)", label, l, u.Scheme, u.Host, u.User, u.Path)
	}
}

func FuzzOfficialFeedLine(f *testing.F) {
	for _, c := range apkFeedCases {
		f.Add(c.in)
	}
	f.Fuzz(func(t *testing.T, l string) {
		if apkFeedLineRefusal(l) == "" {
			assertOfficialShape(t, "fuzz", l)
		}
	})
}

// The argv is fixed: the repositories file, no questions, and the names after "--".
func TestApkArgv(t *testing.T) {
	up, add := apkArgv("/tmp/r/repositories", []string{"tcpdump", "iperf3"}, false)
	if got := strings.Join(up, " "); got != "apk --repositories-file /tmp/r/repositories --no-interactive update" {
		t.Errorf("update: %s", got)
	}
	if got := strings.Join(add, " "); got != "apk --repositories-file /tmp/r/repositories --no-interactive add -- tcpdump iperf3" {
		t.Errorf("add: %s", got)
	}
	_, add = apkArgv("/tmp/r/repositories", []string{"tcpdump"}, true)
	if got := strings.Join(add, " "); got != "apk --repositories-file /tmp/r/repositories --no-interactive add --simulate -- tcpdump" {
		t.Errorf("dry run: %s", got)
	}
}

// apk 3.0.5's own output, as measured in the 25.12.4 rootfs, read into what changes.
func TestApkPlan(t *testing.T) {
	ins, ch := apkPlan("(1/2) Installing libpcap1 (1.10.6-r1)\n(2/2) Installing tcpdump (4.99.6-r1)\nOK: 12.5 MiB in 138 packages\n")
	if strings.Join(ins, ",") != "libpcap1 1.10.6-r1,tcpdump 4.99.6-r1" || len(ch) != 0 {
		t.Errorf("simulate: %v %v", ins, ch)
	}
	ins, ch = apkPlan("(1/3) Installing libatomic1 (14.3.0-r5)\n  Executing libatomic1-14.3.0-r5.post-install\n" +
		"(2/3) Upgrading libiperf3 (3.19-r1 -> 3.20-r1)\n(3/3) Installing iperf3 (3.20-r1)\nOK: 11.5 MiB in 139 packages\n")
	if strings.Join(ins, ",") != "libatomic1 14.3.0-r5,iperf3 3.20-r1" || strings.Join(ch, ",") != "upgrading libiperf3 3.19-r1 -> 3.20-r1" {
		t.Errorf("with an upgrade: %v %v", ins, ch)
	}
	if ins, ch = apkPlan("OK: 11.5 MiB in 139 packages\n"); len(ins)+len(ch) != 0 {
		t.Errorf("nothing to do: %v %v", ins, ch)
	}
}

func TestBoundApkOutput(t *testing.T) {
	small := "(1/1) Installing x (1)\nOK: 1 MiB in 1 packages\n"
	if boundApkOutput(small) != small {
		t.Error("short output changed")
	}
	big := strings.Repeat("(1/1) Installing x (1)\n", 20000) + "OK: 99 MiB in 9 packages\n"
	got := boundApkOutput(big)
	if len(got) > apkOutputMax+100 || !strings.Contains(got, "bytes of apk output cut") ||
		!strings.HasSuffix(got, "OK: 99 MiB in 9 packages\n") {
		t.Errorf("bounded to %d bytes, cut marked %v, verdict kept %v", len(got),
			strings.Contains(got, "cut"), strings.HasSuffix(got, "OK: 99 MiB in 9 packages\n"))
	}
}
