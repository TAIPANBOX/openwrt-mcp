package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ponytail: we parse UCI ourselves rather than shelling to `uci show`. It is ~60 lines
// of trivial format, and doing it in-process makes the whole policy engine unit-testable
// on a workstation that has no uci binary. The `uci` binary is still used for *router*
// config via the tools -- just not for our own.

type uciSection struct {
	Type    string
	Name    string
	Options map[string]string
	Lists   map[string][]string
}

func parseUCI(r *bufio.Scanner) []uciSection {
	var out []uciSection
	var cur *uciSection
	for r.Scan() {
		fields, ok := splitUCI(r.Text())
		if !ok || len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "config":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &uciSection{Options: map[string]string{}, Lists: map[string][]string{}}
			if len(fields) > 1 {
				cur.Type = fields[1]
			}
			if len(fields) > 2 {
				cur.Name = fields[2]
			}
		case "option":
			if cur != nil && len(fields) > 2 {
				cur.Options[fields[1]] = fields[2]
			}
		case "list":
			if cur != nil && len(fields) > 2 {
				cur.Lists[fields[1]] = append(cur.Lists[fields[1]], fields[2])
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// splitUCI tokenises a UCI line, honouring single and double quotes and dropping # comments.
func splitUCI(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	var fields []string
	var buf strings.Builder
	var quote rune
	for _, c := range line {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				buf.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			if buf.Len() > 0 {
				fields = append(fields, buf.String())
				buf.Reset()
			}
		case c == '#' && len(fields) >= 3:
			// trailing comment after a complete option line
			if buf.Len() > 0 {
				fields = append(fields, buf.String())
				buf.Reset()
			}
			return fields, true
		default:
			buf.WriteRune(c)
		}
	}
	if buf.Len() > 0 {
		fields = append(fields, buf.String())
	}
	return fields, true
}

// ---------------------------------------------------------------- policies

type Policy struct {
	Client string
	Tools  []string
	Scopes []string // globs matched against a per-tool scope string
	// Argv is the argument lists exec may run each granted program with. A program with none
	// here runs with no arguments. See argvAllowed.
	Argv      []argvGrant
	MaxPerMin int
	Expires   time.Time // zero == never expires
	Enabled   bool

	// MFATools names the granted tools that additionally require an unexpired TOTP unlock.
	// Empty == no second factor, which is the default and keeps older configs unchanged.
	MFATools  []string
	MFAWindow time.Duration

	// How the owner proves it is them: "totp" (default), "pin" or "pin+totp".
	MFAFactor string
	// Consecutive failed unlocks before unlocking is refused for MFALockout.
	MFAMaxFailures int
	MFALockout     time.Duration

	// Approval names the client's approval section (approval.go). It adds nothing by itself: a
	// client's change calls are classified whenever the client has one. Naming it here makes a
	// policy that expects the section fail to load without it, rather than run unclassified.
	Approval string
	// Hold makes every call this policy grants wait for the owner's approval, whatever the
	// classifier says: a reboot, say, which no rollback can undo. Only for a client with an
	// approval section.
	Hold bool

	mu   sync.Mutex
	hits []time.Time // rolling 60s window; process-scoped by design (see README)
}

type Config struct {
	Listen     string
	AuditPath  string
	AuditMaxMB int
	Policies   []*Policy
	// Approvals is each client's approval section, by client name (approval.go).
	Approvals map[string]*Approval
}

const (
	defaultListen     = "127.0.0.1:8730"
	defaultAuditPath  = "/etc/openwrt-mcp/audit.jsonl"
	defaultAuditMaxMB = 16
)

func LoadConfig(configPath string) (*Config, error) {
	c := &Config{Listen: defaultListen, AuditPath: defaultAuditPath, AuditMaxMB: defaultAuditMaxMB,
		Approvals: map[string]*Approval{}}
	f, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // no config == no policies == deny everything gated. Valid state.
		}
		return nil, err
	}
	defer f.Close()

	byName := map[string]*Approval{}
	for _, s := range parseUCI(bufio.NewScanner(f)) {
		switch s.Type {
		case "approval":
			a, err := approvalFromSection(s)
			if err != nil {
				return nil, fmt.Errorf("approval %q: %w", s.Name, err)
			}
			if _, twice := c.Approvals[a.Client]; twice {
				return nil, fmt.Errorf("approval %q: client %q already has an approval section; one per client", s.Name, a.Client)
			}
			c.Approvals[a.Client] = a
			if a.Name != "" {
				byName[a.Name] = a
			}
		case "server":
			if v := s.Options["listen"]; v != "" {
				c.Listen = v
			}
			if v := s.Options["audit"]; v != "" {
				c.AuditPath = v
			}
			if v, err := strconv.Atoi(s.Options["audit_max_mb"]); err == nil && v > 0 {
				c.AuditMaxMB = v
			}
		case "policy":
			p, err := policyFromSection(s)
			if err != nil {
				return nil, fmt.Errorf("policy %q: %w", s.Name, err)
			}
			c.Policies = append(c.Policies, p)
		}
	}
	if err := checkUnlockAgreement(c.Policies); err != nil {
		return nil, err
	}
	for _, p := range c.Policies {
		if p.Approval != "" {
			a, ok := byName[p.Approval]
			if !ok {
				return nil, fmt.Errorf("a policy for %q names approval section %q, which does not exist", p.Client, p.Approval)
			}
			if a.Client != p.Client {
				return nil, fmt.Errorf("a policy for %q names approval section %q, which is %q's", p.Client, p.Approval, a.Client)
			}
		}
		if p.Hold && c.Approvals[p.Client] == nil {
			return nil, fmt.Errorf("a policy for %q holds what it grants for approval, but %q has no approval section", p.Client, p.Client)
		}
		if p.Hold {
			for _, t := range p.Tools {
				if !heldTools[t] {
					return nil, fmt.Errorf("a policy for %q holds %s for approval, which an approval cannot run; a hold policy grants uci_apply or ubus_call", p.Client, t)
				}
			}
		}
	}
	return c, nil
}

// checkUnlockAgreement refuses a config where one client has two enabled policies that gate
// tools and disagree on how unlocking works. Unlocking is per client, not per policy: the
// refusal from a gated tool names its own policy's factor, while mfa_unlock checks the first
// gating policy's. Two that disagree would ask the owner for one thing and check another.
func checkUnlockAgreement(policies []*Policy) error {
	first := map[string]unlockPolicy{}
	for _, p := range policies {
		if !p.Enabled || len(p.MFATools) == 0 {
			continue
		}
		got := p.unlockPolicy()
		want, seen := first[p.Client]
		if !seen {
			first[p.Client] = got
			continue
		}
		var differ []string
		if got.Factor != want.Factor {
			differ = append(differ, "mfa_factor")
		}
		if got.Window != want.Window {
			differ = append(differ, "mfa_window")
		}
		if got.MaxFailures != want.MaxFailures {
			differ = append(differ, "mfa_max_failures")
		}
		if got.Lockout != want.Lockout {
			differ = append(differ, "mfa_lockout")
		}
		if len(differ) > 0 {
			return fmt.Errorf("client %q has policies that gate tools but disagree on %s; "+
				"unlocking is per client, so they must agree", p.Client, strings.Join(differ, ", "))
		}
	}
	return nil
}

func policyFromSection(s uciSection) (*Policy, error) {
	p := &Policy{
		Client:    s.Options["client"],
		Tools:     s.Lists["tools"],
		Scopes:    s.Lists["scopes"],
		MaxPerMin: 60,
		Enabled:   s.Options["enabled"] != "0",
	}
	if p.Client == "" {
		return nil, fmt.Errorf("missing 'client'")
	}
	// `option tools 'a b c'` is accepted alongside `list tools 'a'` for terser hand-editing.
	if v := s.Options["tools"]; v != "" {
		p.Tools = append(p.Tools, strings.Fields(v)...)
	}
	if v := s.Options["scopes"]; v != "" {
		p.Scopes = append(p.Scopes, strings.Fields(v)...)
	}
	if len(p.Tools) == 0 {
		return nil, fmt.Errorf("grants no tools")
	}
	// One entry is "program pattern..." (`list argv 'logread -l *'`). An argument list that
	// names a program this policy does not grant, or sits where exec is not granted, is a
	// configuration error, because it would otherwise look like a grant and grant nothing.
	for _, entry := range s.Lists["argv"] {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			return nil, fmt.Errorf("empty 'argv' entry")
		}
		g := argvGrant{program: fields[0], args: fields[1:]}
		if !contains(p.Tools, "exec") {
			return nil, fmt.Errorf("argv %q needs exec among this policy's tools", g.program)
		}
		if !matchAny(p.Scopes, g.program) {
			return nil, fmt.Errorf("argv names %q, which this policy's scopes do not grant", g.program)
		}
		p.Argv = append(p.Argv, g)
	}
	if v, err := strconv.Atoi(s.Options["max_per_min"]); err == nil && v > 0 {
		p.MaxPerMin = v
	}
	if v := s.Options["expires"]; v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if t, err = time.Parse("2006-01-02", v); err != nil {
				return nil, fmt.Errorf("bad 'expires' %q: want RFC3339 or YYYY-MM-DD", v)
			}
		}
		p.Expires = t
	}

	// Optional second factor. Absent means off, so every existing config keeps working
	// exactly as before -- this can only ever take permission away, never add it.
	p.MFATools = s.Lists["mfa_tools"]
	if v := s.Options["mfa_tools"]; v != "" {
		p.MFATools = append(p.MFATools, strings.Fields(v)...)
	}
	for _, t := range p.MFATools {
		if !contains(p.Tools, t) && t != "*" {
			return nil, fmt.Errorf("mfa_tools names %q, which this policy does not grant", t)
		}
	}
	w, err := parseMFAWindow(s.Options["mfa_window"])
	if err != nil {
		return nil, fmt.Errorf("bad 'mfa_window': %w", err)
	}
	p.MFAWindow = w

	// How the owner proves it is them, and what guessing costs. Defaults reproduce the
	// behaviour from before these options existed, so an old config unlocks exactly as it did.
	p.MFAFactor = factorTOTP
	if v := strings.TrimSpace(s.Options["mfa_factor"]); v != "" {
		switch v {
		case factorTOTP, factorPIN, factorPINTOTP:
			p.MFAFactor = v
		default:
			return nil, fmt.Errorf("bad 'mfa_factor' %q: want %s, %s or %s", v, factorTOTP, factorPIN, factorPINTOTP)
		}
	}
	p.MFAMaxFailures = defaultMFAMaxFailures
	if v := strings.TrimSpace(s.Options["mfa_max_failures"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad 'mfa_max_failures' %q: want a whole number of at least 1", v)
		}
		p.MFAMaxFailures = n
	}
	p.MFALockout = defaultMFALockout
	if v := strings.TrimSpace(s.Options["mfa_lockout"]); v != "" {
		d, err := parseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("bad 'mfa_lockout' %q: want a positive duration such as 15m", v)
		}
		p.MFALockout = d
	}
	p.Approval = strings.TrimSpace(s.Options["approval"])
	switch v := strings.TrimSpace(s.Options["hold"]); v {
	case "", "0":
	case "1":
		p.Hold = true
	default:
		return nil, fmt.Errorf("bad 'hold' %q: want 1 or 0", v)
	}
	return p, nil
}

// NeedsMFA reports whether this policy requires a second factor for the named tool.
// "*" in mfa_tools covers every tool the policy grants.
func (p *Policy) NeedsMFA(tool string) bool {
	for _, t := range p.MFATools {
		if t == "*" || t == tool {
			return true
		}
	}
	return false
}

// Authorise reports whether any single policy permits client/tool and covers *every*
// scope in scopes. Denial is the default: a miss on any dimension falls through to the
// next policy and, if none match, to a refusal. A policy can only ever *add* permission,
// never widen another policy's -- which is why all scopes must be satisfied by one policy
// rather than collected across several.
//
// One rate token is consumed per authorised call, not per scope.
// approvalFor is the client's approval section, or nil.
func (c *Config) approvalFor(client string) *Approval {
	if c == nil {
		return nil
	}
	return c.Approvals[client]
}

// approves reports whether approver is the client's approver.
func (c *Config) approves(approver, client string) bool {
	a := c.approvalFor(client)
	return a != nil && a.Approver == approver && approver != ""
}

// approvedBy lists the clients approver approves, sorted.
func (c *Config) approvedBy(approver string) []string {
	var out []string
	for client, a := range c.Approvals {
		if a.Approver == approver {
			out = append(out, client)
		}
	}
	sortStrings(out)
	return out
}

func (c *Config) Authorise(client, tool string, scopes []string, now time.Time) (bool, string) {
	p, reason := c.AuthorisePolicy(client, tool, scopes, now)
	return p != nil, reason
}

// AuthorisePolicy is Authorise plus the policy that granted the call, which the caller needs
// to know whether that grant additionally demands a second factor. Authorise remains as the
// boolean form because most callers only ask "may I".
func (c *Config) AuthorisePolicy(client, tool string, scopes []string, now time.Time) (*Policy, string) {
	return c.authorise(client, tool, scopes, nil, now)
}

// authorise is the one decision behind every tool. argv is nil for a tool with no argument
// vector; exec passes its whole argv, and then the policy that covers the program must also
// cover the arguments, in that same policy.
func (c *Config) authorise(client, tool string, scopes, argv []string, now time.Time) (*Policy, string) {
	if argv != nil && len(argv) == 0 {
		return nil, "denied: argv must not be empty"
	}
	var sawClientTool bool
	var uncovered, argvRefused string
	for _, p := range c.Policies {
		if !p.Enabled || p.Client != client || !contains(p.Tools, tool) {
			continue
		}
		if !p.Expires.IsZero() && now.After(p.Expires) {
			continue
		}
		sawClientTool = true
		if miss, ok := firstUncovered(tool, p.Scopes, scopes); !ok {
			uncovered = miss
			continue
		}
		if argv != nil {
			if ok, why := p.argvAllowed(argv); !ok {
				argvRefused = why
				continue
			}
		}
		if !p.takeToken(now) {
			return nil, fmt.Sprintf("rate limit: policy for %q allows %d calls/min to %s", client, p.MaxPerMin, tool)
		}
		return p, ""
	}
	if argvRefused != "" {
		return nil, argvRefused
	}
	if sawClientTool && uncovered != "" {
		return nil, fmt.Sprintf("denied: %s is granted to %q but no policy scope covers %q\n"+
			"  grant it: openwrt-mcp allow %s %s '%s' 60m", tool, client, uncovered, client, tool, uncovered)
	}
	return nil, fmt.Sprintf("denied: no policy grants %s to %q\n"+
		"  grant it: openwrt-mcp allow %s %s '%s' 60m", tool, client, client, tool, orStar(strings.Join(scopes, " ")))
}

// firstUncovered returns the first scope no glob covers. ok is true only when every scope is
// covered (vacuously true for an empty scope list).
func firstUncovered(tool string, globs, scopes []string) (string, bool) {
	for _, s := range scopes {
		if !scopeCovered(tool, globs, s) {
			return s, false
		}
	}
	return "", true
}

// scopeCovered reports whether one of a policy's globs covers a scope. For ubus_call a scope
// is an object and a method, and a glob covers it only when it covers the object and the method
// separately. A glob's object part ends at its last dot, so "network.*" covers the object
// "network" and its methods, and not "network.interface.lan", whose name merely begins the same
// way.
func scopeCovered(tool string, globs []string, scope string) bool {
	if tool != "ubus_call" {
		return matchAny(globs, scope)
	}
	obj, method, ok := splitUbusScope(scope)
	if !ok {
		return false
	}
	for _, g := range globs {
		if g == "*" {
			return true
		}
		gobj, gmethod, ok := splitUbusScope(g)
		if ok && globOK(gobj, obj) && globOK(gmethod, method) {
			return true
		}
	}
	return false
}

// splitUbusScope splits "object.method" at its last dot. The method of a call never holds a dot
// (ubusNameOK refuses one), so this is exact for a call; for a grant, the last dot ends the
// object part.
func splitUbusScope(s string) (string, string, bool) {
	i := strings.LastIndexByte(s, '.')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func globOK(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// ubusNameOK reports whether s can be a ubus object or method name as the call passes it. A
// name may not begin with a dash, which ubus's own option parser would read as a flag. An
// object may hold dots (network.interface.lan); a method may not, because the scope joins the
// two with a dot and only a method without one can be split back into the pair that was asked.
func ubusNameOK(s string, method bool) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		case c == '.' && !method:
		default:
			return false
		}
	}
	return true
}

// argvGrant is one argument list in a policy: the program it is for, and one pattern per
// argument, in order.
type argvGrant struct {
	program string
	args    []string
}

// argvAllowed reports whether this policy lets argv run. A program this policy gives no argument
// list runs with no arguments at all; a program that has lists runs only in a form one of them
// names. Each policy answers for itself, so one policy's list never widens another's grant.
func (p *Policy) argvAllowed(argv []string) (bool, string) {
	prog, args := argv[0], argv[1:]
	listed := false
	for _, g := range p.Argv {
		if !globOK(g.program, prog) {
			continue
		}
		listed = true
		if argsMatch(g.args, args) {
			return true, ""
		}
	}
	if !listed && len(args) == 0 {
		return true, ""
	}
	if !listed {
		return false, fmt.Sprintf("denied: %s runs with no arguments for %q; this grant names none\n"+
			"  grant an argument form: add 'argv %s <pattern>' to the policy", prog, p.Client, prog)
	}
	return false, fmt.Sprintf("denied: no argument form granted to %q lets %s run with these arguments\n"+
		"  grant the form: add 'argv %s <pattern>' to the policy", p.Client, prog, prog)
}

func argsMatch(patterns, args []string) bool {
	if len(patterns) != len(args) {
		return false
	}
	for i := range patterns {
		if !argMatch(patterns[i], args[i]) {
			return false
		}
	}
	return true
}

// argMatch matches one argument against one pattern. An exact pattern is an exact argument. A
// glob ('*' and the rest of path.Match) stays inside one argument and never crosses a '/', and
// an argument with a '..' component is never matched by a glob, so a wildcard in a path cannot
// climb out of the directory it names.
func argMatch(pattern, arg string) bool {
	if pattern == arg {
		return true
	}
	for _, part := range strings.Split(arg, "/") {
		if part == ".." {
			return false
		}
	}
	return globOK(pattern, arg)
}

func (p *Policy) takeToken(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	cut := now.Add(-time.Minute)
	kept := p.hits[:0]
	for _, h := range p.hits {
		if h.After(cut) {
			kept = append(kept, h)
		}
	}
	p.hits = kept
	if len(p.hits) >= p.MaxPerMin {
		return false
	}
	p.hits = append(p.hits, now)
	return true
}

func matchAny(globs []string, s string) bool {
	for _, g := range globs {
		if g == "*" {
			return true
		}
		if ok, err := path.Match(g, s); err == nil && ok {
			return true
		}
	}
	return false
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// ---------------------------------------------------------------- tokens

// Tokens are stored hash-only: the raw bearer is shown once at pair time and never
// recoverable. File format is "<sha256hex> <client name>" per line, mode 0600.
type TokenStore struct {
	path   string
	mu     sync.RWMutex
	byHash map[string]string
	mtime  time.Time
}

func LoadTokens(p string) (*TokenStore, error) {
	ts := &TokenStore{path: p, byHash: map[string]string{}}
	return ts, ts.reload()
}

func (ts *TokenStore) reload() error {
	st, err := os.Stat(ts.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f, err := os.Open(ts.path)
	if err != nil {
		return err
	}
	defer f.Close()
	fresh := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(strings.TrimSpace(sc.Text()), " ", 2)
		if len(parts) == 2 && parts[0] != "" {
			fresh[parts[0]] = parts[1]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	ts.mu.Lock()
	ts.byHash, ts.mtime = fresh, st.ModTime()
	ts.mu.Unlock()
	return nil
}

// reloadIfChanged picks up `pair` and `unpair` run from the CLI while the daemon is
// live. Without it a revoked token would stay valid until the next restart -- the
// dangerous direction of a stale cache, and a bug Haven shipped once already.
func (ts *TokenStore) reloadIfChanged() {
	st, err := os.Stat(ts.path)
	if err != nil {
		return
	}
	ts.mu.RLock()
	same := st.ModTime().Equal(ts.mtime)
	ts.mu.RUnlock()
	if !same {
		_ = ts.reload()
	}
}

// Resolve maps a raw bearer token to a client name in constant time with respect to
// the stored digests, so it cannot be used as a timing oracle.
func (ts *TokenStore) Resolve(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	ts.reloadIfChanged()
	sum := sha256.Sum256([]byte(raw))
	want := []byte(hex.EncodeToString(sum[:]))
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var name string
	var found int
	for h, n := range ts.byHash {
		if subtle.ConstantTimeCompare([]byte(h), want) == 1 {
			name, found = n, 1
		}
	}
	return name, found == 1
}

func (ts *TokenStore) Mint(client string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	ts.mu.Lock()
	ts.byHash[hex.EncodeToString(sum[:])] = client
	ts.mu.Unlock()
	return raw, ts.save()
}

func (ts *TokenStore) Revoke(client string) int {
	ts.mu.Lock()
	n := 0
	for h, c := range ts.byHash {
		if c == client {
			delete(ts.byHash, h)
			n++
		}
	}
	ts.mu.Unlock()
	if n > 0 {
		_ = ts.save()
	}
	return n
}

func (ts *TokenStore) Clients() []string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, c := range ts.byHash {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func (ts *TokenStore) save() error {
	if err := os.MkdirAll(path.Dir(ts.path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	ts.mu.RLock()
	for h, c := range ts.byHash {
		fmt.Fprintf(&b, "%s %s\n", h, c)
	}
	ts.mu.RUnlock()
	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ts.path)
}
