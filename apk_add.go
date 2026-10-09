package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// apk_add installs packages on the router, by name, from the official OpenWrt feeds and from
// nowhere else.
//
// @decided 2026-10-08: an agent may install packages only from the official OpenWrt feed, and
// only where the owner has opted in by granting this tool; never from a link, never from a
// local file, and never with signature checking turned off.
//
// The owner's opt-in is a policy that grants apk_add, like every other tool: nothing grants it
// by default. The policy scope is the package name, so a grant can name the packages
// ('tcpdump iperf3') or allow any ('*').
//
// "Official" is enforced here, not trusted to the router's configuration:
//
//   - apk is given its repositories with --repositories-file, a file this tool writes holding
//     only the lines of /etc/apk/repositories.d/distfeeds.list (what the firmware ships) that
//     are https URLs of a packages.adb on downloads.openwrt.org. With --repositories-file apk
//     reads neither /etc/apk/repositories nor any repositories.d/*.list (apk-tools 3.0.5
//     src/database.c, apk_db_open: the else branch of `if (ac->repositories_file == NULL)`),
//     so customfeeds.list, and any feed someone added, is not consulted at all. Measured on
//     2026-10-09 in openwrt/rootfs:x86-64-25.12.4: a package that exists only in a custom feed
//     is "no such package" this way, with that feed's index already in the cache.
//   - Mirrors are not accepted. apk checks an index's signature against every key in
//     /etc/apk/keys, and a router that uses a custom feed has that feed's key there too, so
//     the signature alone does not say "OpenWrt's". The host does.
//   - apk is run with APK_CONFIG=/dev/null. apk loads default options from $APK_CONFIG, else
//     /etc/apk/config, else /lib/apk/config (src/apk.c load_config), and one line there,
//     `allow-untrusted`, would turn signature checking off for this call. Measured on the same
//     image: with that line in /etc/apk/config, `apk add x.apk` installed an unsigned file;
//     with APK_CONFIG=/dev/null it was refused.
//   - apk is run in an empty directory of its own. `apk add` reads an argument as a local
//     package file when it holds a dot and a file of that name exists in the working
//     directory (src/app_add.c add_main: strchr(arg, '.') && access(arg, F_OK) == 0), and
//     official names hold dots (golang1.26). Measured: with a file named golang1.26 in the
//     working directory, apk tried to install that file.
//   - Names are checked before apk runs (apkNameRules), and are passed after "--".
//   - No flag that loosens anything is ever passed: no --allow-untrusted, no --force-*, no
//     --keys-dir, --root, --arch, --repository, --repository-config or --no-network. The argv
//     is fixed, and a test asserts it exactly.
//
// What this does NOT do, named so nobody assumes it:
//   - It does not stop apk add doing what apk add does: it pulls in dependencies, and if a new
//     package needs a newer version of an installed library, apk upgrades that library.
//     dry_run shows every package that would change before anything does.
//   - An official package's install scripts run as root. That is the trust placed in the
//     official signed feed, and it is the whole of what this tool trusts.
//   - Packages installed earlier from other feeds stay as they are; this tool neither touches
//     nor upgrades them (measured: an installed custom package survives an official add).

// apkDistfeedsPath is the repositories file the firmware ships. A variable so a test can point
// the tool at a fixture.
var apkDistfeedsPath = "/etc/apk/repositories.d/distfeeds.list"

const (
	apkOfficialHost = "downloads.openwrt.org"
	apkMaxPackages  = 20
	apkMaxNameLen   = 100
	// apkOutputMax bounds what apk's output may add to an answer, on the error path too, where
	// the tool wrapper passes it on without the result cap.
	apkOutputMax     = 16 << 10
	apkUpdateTimeout = 120 * time.Second
	apkAddTimeout    = 300 * time.Second
)

type apkAddIn struct {
	Packages []string `json:"packages" jsonschema:"names of packages in the official OpenWrt feeds, e.g. ['tcpdump']. 1 to 20 names. A name only: no version, no path, no URL, no .apk file."`
	DryRun   bool     `json:"dry_run,omitempty" jsonschema:"true to see every package that would be installed or changed, dependencies included, without installing anything"`
}

// apkNameGrammar is the package-name alphabet: letters, digits, '+', '-', '.', '_', beginning
// with a letter or a digit. Upper case is in it because official names have it (UDPspeeder,
// cJSON, the DejaVu fonts); every name in OpenWrt 25.12.4's official feeds matches
// (testdata/openwrt-25.12-package-names-unusual.txt).
var apkNameGrammar = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)

// apkNameRules are checked in order and the first that matches is the reason given. Most bad
// names would also fail the grammar at the end; the specific rules come first so the agent is
// told what it did wrong, and a test requires each to be the one that fires on its own case.
var apkNameRules = []struct {
	name, why string
	bad       func(string) bool
}{
	{"empty", "an empty name", func(n string) bool { return n == "" }},
	{"flag", "a name that begins with '-', which apk would read as an option",
		func(n string) bool { return strings.HasPrefix(n, "-") }},
	{"url", "a URL; apk_add installs from the official OpenWrt feeds only, never from a link",
		func(n string) bool { return strings.Contains(n, "://") }},
	{"path", "a path; apk_add never installs a local file",
		func(n string) bool { return strings.Contains(n, "/") }},
	{"apk-file", "a package file name (.apk); apk_add never installs a local file",
		func(n string) bool { return strings.HasSuffix(strings.ToLower(n), ".apk") }},
	{"version", "a version constraint (= < > ~); apk would pin it in /etc/apk/world, and a pinned " +
		"version blocks every later upgrade of that package",
		func(n string) bool { return strings.ContainsAny(n, "=<>~") }},
	{"tag", "a repository tag (@); apk_add uses the untagged official feeds only",
		func(n string) bool { return strings.Contains(n, "@") }},
	{"colon", "a name that contains ':', which no package name holds",
		func(n string) bool { return strings.Contains(n, ":") }},
	{"virtual", "a name that begins with '.', which apk uses for virtual packages",
		func(n string) bool { return strings.HasPrefix(n, ".") }},
	{"dotdot", "a name that contains '..', which no official name holds and every path that climbs does",
		func(n string) bool { return strings.Contains(n, "..") }},
	{"too-long", fmt.Sprintf("longer than %d characters; the longest official name is 50", apkMaxNameLen),
		func(n string) bool { return len(n) > apkMaxNameLen }},
	{"grammar", "outside the package-name alphabet (letters, digits, '+', '-', '.', '_', beginning " +
		"with a letter or a digit)",
		func(n string) bool { return !apkNameGrammar.MatchString(n) }},
}

// apkNameRefusal says why name is not a package name apk_add accepts, or "".
func apkNameRefusal(name string) string {
	for _, r := range apkNameRules {
		if r.bad(name) {
			return r.why
		}
	}
	return ""
}

// refuseApkNames checks the whole list before anything runs and names every bad entry.
func refuseApkNames(names []string) error {
	if len(names) == 0 {
		return &refusedError{"refused: no package named; give packages as a list of 1 to " +
			fmt.Sprint(apkMaxPackages) + " names"}
	}
	if len(names) > apkMaxPackages {
		return &refusedError{fmt.Sprintf("refused: %d packages named; apk_add takes at most %d in one call",
			len(names), apkMaxPackages)}
	}
	var lines []string
	for _, n := range names {
		if why := apkNameRefusal(n); why != "" {
			lines = append(lines, fmt.Sprintf("refused: %q is %s", n, why))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return &refusedError{strings.Join(lines, "\n") + "\nNothing was installed. apk_add installs " +
		"packages by name from the official OpenWrt feeds only."}
}

// apkOfficialURL is the whole shape of a line that is kept: an https URL of a packages.adb on
// the official host, with a path of plain characters.
var apkOfficialURL = regexp.MustCompile(`^https://` + regexp.QuoteMeta(apkOfficialHost) +
	`/[A-Za-z0-9._~+/-]+/packages\.adb$`)

// apkFeedRules decide which lines of distfeeds.list are used, checked in order, the first that
// matches being the reason a line is not used. The last is the whole shape; the ones before it
// make the reason specific, and a test requires each to be the one that fires on its own case.
var apkFeedRules = []struct {
	name, why string
	bad       func(string) bool
}{
	{"not-one-url", "not a single URL (a tag, a type, a component list or a `set` line)",
		func(l string) bool { return len(strings.Fields(l)) != 1 }},
	{"variable", "uses a variable ($), which apk would expand",
		func(l string) bool { return strings.Contains(l, "$") }},
	{"not-https", "not https",
		func(l string) bool { return !strings.HasPrefix(l, "https://") }},
	{"userinfo", "carries a user name or password",
		func(l string) bool {
			host, _, _ := strings.Cut(strings.TrimPrefix(l, "https://"), "/")
			return strings.Contains(host, "@")
		}},
	{"host", "not on " + apkOfficialHost + " (mirrors and other feeds are not used)",
		func(l string) bool {
			host, _, _ := strings.Cut(strings.TrimPrefix(l, "https://"), "/")
			return host != apkOfficialHost
		}},
	{"query", "carries a query or a fragment",
		func(l string) bool { return strings.ContainsAny(l, "?#") }},
	{"dotdot", "has '..' in its path",
		func(l string) bool { return strings.Contains(l, "..") }},
	{"not-index", "does not name a packages.adb index",
		func(l string) bool { return !strings.HasSuffix(l, "/packages.adb") }},
	{"shape", "outside the plain characters of an official feed URL",
		func(l string) bool { return !apkOfficialURL.MatchString(l) }},
}

// apkFeedLineRefusal says why this line of distfeeds.list is not used, or "". Blank lines and
// comments are not lines to judge and get "".
func apkFeedLineRefusal(line string) string {
	for _, r := range apkFeedRules {
		if r.bad(line) {
			return r.why
		}
	}
	return ""
}

// officialFeeds reads the lines of a distfeeds.list and returns the ones apk_add uses, without
// duplicates, and how many it did not use. What a dropped line said is never returned: a
// private feed's URL can carry a token.
func officialFeeds(content string) (kept []string, dropped int) {
	seen := map[string]bool{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if apkFeedLineRefusal(line) != "" {
			dropped++
			continue
		}
		if !seen[line] {
			seen[line] = true
			kept = append(kept, line)
		}
	}
	return kept, dropped
}

// apkArgv is the whole of what apk is asked to do: refresh the official indexes, then add (or
// simulate adding) the named packages. Nothing in it comes from the agent but the names, and
// they come after "--".
func apkArgv(repoFile string, names []string, dryRun bool) (update, add []string) {
	base := []string{"apk", "--repositories-file", repoFile, "--no-interactive"}
	update = append(append([]string{}, base...), "update")
	add = append(append([]string{}, base...), "add")
	if dryRun {
		add = append(add, "--simulate")
	}
	add = append(append(add, "--"), names...)
	return update, add
}

// apkEnv neutralises /etc/apk/config, see the header.
var apkEnv = []string{"APK_CONFIG=/dev/null"}

// apkStep matches apk's line for one package it changes: "(1/2) Installing libpcap1 (1.10.6-r1)".
var apkStep = regexp.MustCompile(`^\(\d+/\d+\) (\S+) (\S+) \((.*)\)$`)

// apkPlan reads what apk said it does (or would do) to each package. Installing a package that
// was not there is the expected change; anything else (Upgrading, Replacing, ...) changes a
// package already installed, and is listed apart so it is not missed.
func apkPlan(out string) (installs, changes []string) {
	for _, line := range strings.Split(out, "\n") {
		m := apkStep.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		entry := m[2] + " " + m[3]
		if m[1] == "Installing" {
			installs = append(installs, entry)
		} else {
			changes = append(changes, strings.ToLower(m[1])+" "+entry)
		}
	}
	return installs, changes
}

// apkPlanMax is how many packages of each kind the readable plan lists; apk's own output,
// bounded, follows it in full.
const apkPlanMax = 100

func capList(l []string) []string {
	if len(l) <= apkPlanMax {
		return l
	}
	return append(l[:apkPlanMax:apkPlanMax], fmt.Sprintf("... and %d more, see apk's output", len(l)-apkPlanMax))
}

// boundApkOutput keeps apk's output within apkOutputMax, keeping the head and the tail, which
// is where apk puts its verdict.
func boundApkOutput(s string) string {
	if len(s) <= apkOutputMax {
		return s
	}
	head, tail := s[:apkOutputMax/4], s[len(s)-apkOutputMax*3/4:]
	return fmt.Sprintf("%s\n[... %d bytes of apk output cut ...]\n%s", head, len(s)-len(head)-len(tail), tail)
}

func apkAdd(ctx context.Context, in apkAddIn) (string, string, error) {
	summary := "apk add " + strings.Join(in.Packages, " ")
	if in.DryRun {
		summary = "apk add --simulate " + strings.Join(in.Packages, " ")
	}
	if err := refuseApkNames(in.Packages); err != nil {
		return "", summary, err
	}

	b, err := os.ReadFile(apkDistfeedsPath)
	if err != nil && !os.IsNotExist(err) {
		return "", summary, &refusedError{fmt.Sprintf("refused: cannot read %s (%v), so the official "+
			"feeds are not known; nothing was installed", apkDistfeedsPath, err)}
	}
	feeds, dropped := officialFeeds(string(b))
	if len(feeds) == 0 {
		return "", summary, &refusedError{fmt.Sprintf("refused: %s names no official OpenWrt feed "+
			"(an https URL of a packages.adb on %s; %d other line(s) not used), and apk_add installs "+
			"from nowhere else; nothing was installed", apkDistfeedsPath, apkOfficialHost, dropped)}
	}

	dir, err := os.MkdirTemp("", "openwrt-mcp-apk-")
	if err != nil {
		return "", summary, err
	}
	defer os.RemoveAll(dir)
	repoFile := filepath.Join(dir, "repositories")
	if err := os.WriteFile(repoFile, []byte(strings.Join(feeds, "\n")+"\n"), 0o600); err != nil {
		return "", summary, err
	}
	// Empty, and nothing else ever written into it: see the header on apk's local-file rule.
	cwd := filepath.Join(dir, "cwd")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		return "", summary, err
	}

	update, add := apkArgv(repoFile, in.Packages, in.DryRun)
	if out, err := runIn(ctx, apkUpdateTimeout, cwd, apkEnv, update...); err != nil {
		return boundApkOutput(out), summary,
			fmt.Errorf("apk update against the official OpenWrt feeds failed: %w; nothing was installed", err)
	}
	out, err := runIn(ctx, apkAddTimeout, cwd, apkEnv, add...)
	out = boundApkOutput(out)
	if err != nil {
		return out, summary, fmt.Errorf("apk add failed: %w", err)
	}

	installs, changes := apkPlan(out)
	installs, changes = capList(installs), capList(changes)
	var b2 strings.Builder
	if in.DryRun {
		fmt.Fprintf(&b2, "Dry run: nothing was installed. From the official OpenWrt feeds only (%d feed(s)), "+
			"apk add %s would:\n", len(feeds), strings.Join(in.Packages, " "))
	} else {
		fmt.Fprintf(&b2, "Done, from the official OpenWrt feeds only (%d feed(s)): apk add %s\n",
			len(feeds), strings.Join(in.Packages, " "))
	}
	if len(installs) == 0 && len(changes) == 0 {
		b2.WriteString("  change nothing: every package named is already installed\n")
	}
	for _, p := range installs {
		b2.WriteString("  install " + p + "\n")
	}
	if len(changes) > 0 {
		b2.WriteString("and change packages already installed, which a new package needs:\n")
		for _, c := range changes {
			b2.WriteString("  " + c + "\n")
		}
	}
	b2.WriteString("Packages beyond the ones named are dependencies apk pulls in.\n\napk's output:\n")
	b2.WriteString(out)
	return b2.String(), summary, nil
}
