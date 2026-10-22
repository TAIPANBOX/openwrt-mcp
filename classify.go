package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Which changes wait for the owner's approval (tier 3), and which are refused outright because
// only a person may make them. Everything else (tier 2) runs as it always has: in the client's
// unlock window when its policy asks for one.
//
// This runs for a client with an approval section only, after its policy has authorised the
// call and before the window is consulted, so a window never lets a tier-3 change through and a
// closed window does not stop one being proposed. Built-in rules have no switch, for the same
// reason uci_noexec.go gives: a switch the agent can reach is a switch the agent can flip. The
// approval section can only add rules (`list hold`, `list refuse`).
//
// What decides a uci_apply is the state the batch would leave, not the batch: the change is
// applied to a scratch copy of the configs with the router's own uci (`uci -c <copy> -P <copy>`,
// the copy in the daemon's TMPDIR, which on OpenWrt is RAM), both states are read with
// `uci -X show`, and the predicates below compare them. So a port forward created disabled in one
// call and switched on in the next is held on the second call, though all it says is enabled=1.
// What cannot be read is not guessed at: it waits for the owner (tierHeld, "could not be checked").
//
// The candidates, each with how it reads the state:
//
//   - a port opened to the internet: an enabled redirect (target DNAT, the default) or rule
//     (target anything but DROP or REJECT, unset included) whose src is an internet zone or '*',
//     that was not there before, every option but its name compared;
//   - the firewall weakened: an internet zone's input or forward becoming ACCEPT (a zone's unset
//     policy read as the defaults' one, an unset default as DROP); a forwarding from an internet
//     zone; a change in which zones face the internet; the internet port joining another bridge
//     or interface. A zone faces the internet when its networks include wan or wan6 or it
//     masquerades (masq 1), and the internet port is what network.wan and network.wan6 name;
//   - VPN or policy routing: any change to a WireGuard interface or peer; a route or a routing
//     rule for every destination (0.0.0.0/0, ::/0, or no destination at all for a rule) added,
//     changed or removed; anything in pbr;
//   - who answers DNS: dnsmasq's server, address, noresolv, resolvfile and rebind_protection; a
//     DHCP option 6; a host, domain or cname answered locally for a name with a dot in it; an
//     interface's dns and peerdns;
//   - the time servers: any change to a timeserver section, because the codes that approve
//     changes are only as good as the router's clock;
//   - Wi-Fi without a password (encryption none, unset or owe) on an enabled access point whose
//     network is in a trusted zone (one whose input is ACCEPT and that does not face the internet),
//     that was not so before: a zone made trusted counts as much as a Wi-Fi made open;
//   - over ubus: a reboot, and rc.init stopping or disabling a service that guards the router.
//
// What this does NOT cover, named so nobody assumes it: a change whose danger lies in a value
// these predicates do not read (a port forward to a host that runs something, a firewall zone's
// extra rules, a mwan3 or sqm setting), a package's own config that opens something (a VPN
// server's listen address in its own config, a remote-administration switch), and ubus methods
// other than the two named. Those are tier 2: they run in the owner's unlock window, with the
// rollback.

type tier int

const (
	tierRun tier = iota // tier 2: as before, the window decides
	tierHeld
	tierRefused
)

// classification is what the gate needs to know about one change call.
type classification struct {
	tier      tier
	headlines []string // why it is held, one line each, for the card and the agent
	refusal   string   // why it is refused, for tierRefused
	diff      []string // the card's body: every changed key, before and after
	configs   []string // the configs read, for the fingerprint
}

// The configs every uci_apply is checked against, beside the ones it changes: a network change
// is read with the firewall's zones, a firewall change with the network's ports, a Wi-Fi change
// with both.
var classifyCrossConfigs = []string{"dhcp", "firewall", "network", "pbr", "system", "wireless"}

// ------------------------------------------------------------------ what only a person may do

// humanOnlyTools are tools a client with an approval section never runs, whatever its grants.
var humanOnlyTools = map[string]string{
	"exec": "run a command on the router",
	"wg_new_client": "issue a WireGuard client: its private key would be in the answer, which goes to " +
		"whoever reads the agent's context",
}

// humanOnlyConfigs are configs a client with an approval section never changes: the agent's own,
// its guard's, and the ways into the router.
var humanOnlyConfigs = map[string]string{
	"hermes":      "change the agent's own configuration (its profile is what keeps it off root)",
	"openwrt-mcp": "change this daemon's policies (a client could grant itself anything)",
	"rpcd":        "change rpcd's logins and ACLs",
	"dropbear":    "change how SSH lets people in",
	"uhttpd":      "change the web server that LuCI and ubus are reached through",
	"luci":        "change LuCI's own configuration",
	"fstab":       "change what is mounted where",
	"ucitrack":    "change which init scripts LuCI runs for a config",
}

// humanOnlyUbus are ubus grants a client with an approval section never uses, as object.method
// globs matched the way a policy's are.
var humanOnlyUbus = []struct{ glob, why string }{
	{"file.*", "use rpcd's file object, which runs commands and writes files"},
	{"system.sysupgrade", "flash a firmware"},
	{"system.signal", "send a signal to any process"},
	{"service.*", "use procd's service object, which starts any command as a service"},
	{"uci.*", "change configuration over ubus, which bypasses uci_apply's checks and its rollback"},
	{"rpc-sys.*", "use rpc-sys, which installs and upgrades packages and resets the router"},
}

// humanOnlyRefusal says why a call is one only the owner may make, by hand, or returns "".
func humanOnlyRefusal(tool string, scopes []string) string {
	why := ""
	if w, ok := humanOnlyTools[tool]; ok {
		why = w
	}
	switch tool {
	case "uci_apply":
		for _, sc := range scopes {
			config, _, _ := strings.Cut(sc, ".")
			if w, ok := humanOnlyConfigs[config]; ok {
				why = w
				break
			}
		}
	case "ubus_call":
		for _, sc := range scopes {
			for _, h := range humanOnlyUbus {
				if scopeCovered("ubus_call", []string{h.glob}, sc) {
					why = h.why
				}
			}
		}
	}
	if why == "" {
		return ""
	}
	return "refused: only the owner may " + why + ", by hand on the router. openwrt-mcp never lets a client " +
		"with an approval section do it, whatever its grants say. Nothing was run."
}

// ------------------------------------------------------------------ ubus calls

// guardServices are the services whose stop or disable leaves the router without a guard or
// without a way in.
var guardServices = map[string]bool{
	"firewall": true, "dropbear": true, "uhttpd": true, "rpcd": true, "openwrt-mcp": true,
	"network": true, "dnsmasq": true,
}

// classifyUbus decides a ubus_call by the call, since a ubus call has no state to compare.
func classifyUbus(in ubusCallIn) classification {
	switch in.Object + "." + in.Method {
	case "system.reboot":
		return classification{tier: tierHeld, headlines: []string{"REBOOTS THE ROUTER"}}
	case "rc.init":
		name, nameOK := in.Args["name"].(string)
		action, actionOK := in.Args["action"].(string)
		name, action = strings.TrimSpace(name), strings.ToLower(strings.TrimSpace(action))
		if !nameOK || !actionOK {
			return classification{tier: tierHeld, headlines: []string{
				"COULD NOT BE CHECKED: rc.init without a service name and an action as text"}}
		}
		// Printed as they are: both are one of the fixed names above.
		if guardServices[name] && (action == "stop" || action == "disable") {
			return classification{tier: tierHeld, headlines: []string{fmt.Sprintf(
				"STOPS A SERVICE THAT GUARDS THE ROUTER: %s (%s)", name, action)}}
		}
	}
	return classification{tier: tierRun}
}

// ------------------------------------------------------------------ state

// uciSect is one section as `uci -X show` prints it.
type uciSect struct {
	Name  string
	Type  string
	Index int // its position among the sections of its type, for the @type[n] a person reads
	Opts  map[string][]string
	Lists map[string]bool
}

// uciState is one config as `uci -X show` prints it.
type uciState struct {
	Config   string
	Sections []*uciSect
	byName   map[string]*uciSect
}

var anonName = regexp.MustCompile(`^cfg[0-9a-f]{6}$`)

// label is the name a person reads: the section's own, or @type[n] for an anonymous one.
func (s *uciSect) label() string {
	if anonName.MatchString(s.Name) {
		return fmt.Sprintf("@%s[%d]", s.Type, s.Index)
	}
	return s.Name
}

// get is an option's value, a list's elements joined by a space.
func (s *uciSect) get(opt string) string { return strings.Join(s.Opts[opt], " ") }

// word is an option's value as a keyword is decided on: trimmed and upper-cased, the way a reader
// that is lenient about both would take it. A decision on a raw value would let ' dnat ' through as
// something other than DNAT.
func (s *uciSect) word(opt string) string { return strings.ToUpper(strings.TrimSpace(s.get(opt))) }

// name is an option's value as a zone or interface name is decided on: trimmed.
func (s *uciSect) name(opt string) string { return strings.TrimSpace(s.get(opt)) }

// accepts reads a firewall policy the safe way round: anything but REJECT or DROP lets traffic in,
// so a value nobody knows counts as ACCEPT.
func accepts(policy string) bool { return policy != "REJECT" && policy != "DROP" }

// list is a list's elements, or an option's words: netifd and fw4 read an option where they expect
// a list as its whitespace-separated words, and uci_apply can only ever write an option. Each is
// trimmed, so ' wan' is wan.
func (s *uciSect) list(opt string) []string {
	if !s.Lists[opt] {
		return strings.Fields(s.get(opt))
	}
	var out []string
	for _, v := range s.Opts[opt] {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (st *uciState) sectionsOf(typ string) []*uciSect {
	var out []*uciSect
	if st == nil {
		return nil
	}
	for _, s := range st.Sections {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	return out
}

func (st *uciState) section(name string) *uciSect {
	if st == nil {
		return nil
	}
	return st.byName[name]
}

var errUnreadable = errors.New("unreadable")

// parseShow reads `uci -X show <config>` in libuci's grammar (see uci_redact.go): a section as
// "config.section=type", an option as "config.section.option=" and its value single-quoted, a
// quote inside closed, escaped and reopened, a list's elements each quoted and separated by one
// space. Anything else is unreadable, and so is an option of a section with no type line: what
// the state is cannot then be known.
func parseShow(config, out string) (*uciState, error) {
	st := &uciState{Config: config, byName: map[string]*uciSect{}}
	counts := map[string]int{}
	prefix := config + "."
	for rest := out; rest != ""; {
		line, after := rest, ""
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, after = rest[:i], rest[i+1:]
		}
		if line == "" {
			rest = after
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 || !strings.HasPrefix(line, prefix) {
			return nil, fmt.Errorf("%w: %s: a line uci does not print", errUnreadable, config)
		}
		key := line[len(prefix):eq]
		var raw string
		if eq+1 < len(line) && line[eq+1] == '\'' {
			end, ok := quotedValueEnd(rest, eq+1)
			if !ok {
				return nil, fmt.Errorf("%w: %s.%s: a value uci does not print", errUnreadable, config, key)
			}
			raw = rest[eq+1 : end]
			if end >= len(rest) {
				rest = ""
			} else {
				rest = rest[end+1:]
			}
		} else {
			raw = line[eq+1:]
			rest = after
		}
		section, option, isOption := strings.Cut(key, ".")
		if section == "" || (isOption && (option == "" || strings.Contains(option, "."))) {
			return nil, fmt.Errorf("%w: %s.%s: not a section or an option", errUnreadable, config, key)
		}
		if !isOption {
			if _, seen := st.byName[section]; seen || !uciName.MatchString(raw) {
				return nil, fmt.Errorf("%w: %s.%s: a section uci does not print", errUnreadable, config, section)
			}
			s := &uciSect{Name: section, Type: raw, Index: counts[raw], Opts: map[string][]string{}, Lists: map[string]bool{}}
			counts[raw]++
			st.Sections = append(st.Sections, s)
			st.byName[section] = s
			continue
		}
		s := st.byName[section]
		if s == nil {
			return nil, fmt.Errorf("%w: %s.%s: an option of a section with no type", errUnreadable, config, section)
		}
		vals, list, err := parseShowValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s.%s.%s: %v", errUnreadable, config, section, option, err)
		}
		s.Opts[option], s.Lists[option] = vals, list
	}
	return st, nil
}

// parseShowValue reads one quoted value: its elements, and whether it is a list. A quote inside
// an element is printed as the quote closing, \' and a quote reopening; elements are separated by
// one space.
func parseShowValue(v string) ([]string, bool, error) {
	if !strings.HasPrefix(v, "'") {
		return nil, false, errors.New("a value must open with a quote")
	}
	var out []string
	var cur strings.Builder
	for i := 0; ; {
		j := strings.IndexByte(v[i+1:], '\'')
		if j < 0 {
			return nil, false, errors.New("a quote that never closes")
		}
		cur.WriteString(v[i+1 : i+1+j])
		i += j + 2 // just past the closing quote
		switch {
		case i == len(v):
			out = append(out, cur.String())
			return out, len(out) > 1, nil
		case strings.HasPrefix(v[i:], `\''`):
			cur.WriteByte('\'')
			i += 2 // at the quote that reopens the same element
		case strings.HasPrefix(v[i:], " '"):
			out = append(out, cur.String())
			cur.Reset()
			i++ // at the quote that opens the next element
		default:
			return nil, false, errors.New("text after a value")
		}
	}
}

// states are the configs a classification reads, before and after.
type states map[string]*uciState

func (s states) get(config string) *uciState { return s[config] }

// buildStates applies changes to a scratch copy of configs and reads both states with the
// router's uci. It returns the configs it read, the states, and an error that says why the after
// state could not be built (a change uci itself refuses), or that a state is unreadable.
func buildStates(ctx context.Context, changes []UCIChange) ([]string, states, states, error) {
	want := map[string]bool{}
	for _, c := range classifyCrossConfigs {
		want[c] = true
	}
	for _, c := range changes {
		want[c.Config] = true
	}
	var configs []string
	for c := range want {
		if _, err := os.Stat(filepath.Join(uciConfigDir, c)); err == nil {
			configs = append(configs, c)
		}
	}
	sort.Strings(configs)

	tmp, err := os.MkdirTemp("", "openwrt-mcp-classify-")
	if err != nil {
		return configs, nil, nil, fmt.Errorf("%w: no scratch directory: %v", errUnreadable, err)
	}
	defer os.RemoveAll(tmp)
	dirs := map[string]string{}
	for _, phase := range []string{"before", "after"} {
		d := filepath.Join(tmp, phase)
		dirs[phase] = d
		if err := os.MkdirAll(filepath.Join(tmp, phase+"-changes"), 0o700); err != nil {
			return configs, nil, nil, fmt.Errorf("%w: %v", errUnreadable, err)
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return configs, nil, nil, fmt.Errorf("%w: %v", errUnreadable, err)
		}
		for _, c := range configs {
			b, err := os.ReadFile(filepath.Join(uciConfigDir, c))
			if err != nil {
				return configs, nil, nil, fmt.Errorf("%w: reading %s: %v", errUnreadable, c, err)
			}
			if err := os.WriteFile(filepath.Join(d, c), b, 0o600); err != nil {
				return configs, nil, nil, fmt.Errorf("%w: %v", errUnreadable, err)
			}
		}
	}
	uciIn := func(phase string, args ...string) (string, error) {
		argv := append([]string{"uci", "-c", dirs[phase], "-P", filepath.Join(tmp, phase+"-changes")}, args...)
		return run(ctx, defaultCmdTimeout, argv...)
	}
	for _, c := range changes {
		argv := uciArgv(c)
		if out, err := uciIn("after", argv[1:]...); err != nil {
			return configs, nil, nil, &refusedError{fmt.Sprintf("refused: uci refuses %s on a copy of the router's "+
				"configuration (%v): %s; nothing was applied", uciKey(c), err, strings.TrimSpace(redactUCIOutput(out)))}
		}
	}
	read := func(phase string) (states, error) {
		out := states{}
		for _, c := range configs {
			show, err := uciIn(phase, "-X", "show", c)
			if err != nil {
				return nil, fmt.Errorf("%w: uci -X show %s failed: %v", errUnreadable, c, err)
			}
			st, err := parseShow(c, show)
			if err != nil {
				return nil, err
			}
			out[c] = st
		}
		return out, nil
	}
	before, err := read("before")
	if err != nil {
		return configs, nil, nil, err
	}
	after, err := read("after")
	if err != nil {
		return configs, nil, nil, err
	}
	return configs, before, after, nil
}

// classifyUCI decides a uci_apply: refused when uci_apply itself would refuse it, held when its
// resulting state meets a predicate or cannot be read.
func classifyUCI(ctx context.Context, in uciApplyIn) classification {
	if len(in.Changes) == 0 {
		return classification{tier: tierRun} // uci_apply refuses it with its own words
	}
	for _, c := range in.Changes {
		if err := validateChange(c); err != nil {
			return classification{tier: tierRefused, refusal: err.Error()}
		}
	}
	if err := refuseCodeExec(ctx, in.Changes); err != nil {
		return classification{tier: tierRefused, refusal: err.Error()}
	}
	for _, c := range in.Changes {
		if _, err := os.Stat(filepath.Join(uciConfigDir, c.Config)); err != nil {
			return classification{tier: tierRefused, refusal: fmt.Sprintf("no such UCI config %q", c.Config)}
		}
	}
	if out, err := run(ctx, defaultCmdTimeout, "uci", "changes"); err == nil && strings.TrimSpace(out) != "" {
		return classification{tier: tierRefused, refusal: "refusing to apply: uncommitted UCI changes already exist:\n" +
			redactUCIOutput(out)}
	}
	configs, before, after, err := buildStates(ctx, in.Changes)
	if err != nil {
		var r *refusedError
		if errors.As(err, &r) {
			return classification{tier: tierRefused, refusal: r.msg, configs: configs}
		}
		return classification{tier: tierHeld, configs: configs,
			headlines: []string{"COULD NOT BE CHECKED: " + strings.TrimPrefix(err.Error(), errUnreadable.Error()+": ")},
			diff:      batchLines(in.Changes)}
	}
	cl := classification{tier: tierRun, configs: configs, headlines: predicates(before, after)}
	if len(cl.headlines) > 0 {
		cl.tier = tierHeld
	}
	touched := map[string]bool{}
	for _, c := range in.Changes {
		touched[c.Config] = true
	}
	for _, c := range configs {
		if touched[c] {
			cl.diff = append(cl.diff, diffConfig(before.get(c), after.get(c))...)
		}
	}
	return cl
}

// batchLines is the card's body when the states could not be read: the batch as given.
func batchLines(changes []UCIChange) []string {
	var out []string
	for _, c := range changes {
		switch {
		case c.Type != "":
			out = append(out, fmt.Sprintf("%s, new %s", c.Config+"."+c.Section, c.Type))
		case c.Delete:
			out = append(out, "- "+uciKey(c))
		case isSecretUCIOption(c.Option):
			out = append(out, uciKey(c)+" "+redacted)
		default:
			out = append(out, uciKey(c)+" "+showValue(c.Value))
		}
	}
	return out
}

// ------------------------------------------------------------------ the predicates

// predicates returns the headline of every candidate the change meets, in a fixed order.
func predicates(before, after states) []string {
	var out []string
	for _, p := range []func(states, states) []string{portsToTheInternet, firewallWeakened, rewiring, vpnRouting,
		upstreamDNS, timeServers, openWifiIntoTrusted} {
		out = append(out, p(before, after)...)
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// uciFalse is what uci's boolean options read as off.
func uciFalse(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "no", "off", "false", "disabled":
		return true
	}
	return false
}

// uciTrue is what uci's boolean options read as on.
func uciTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "on", "true", "enabled":
		return true
	}
	return false
}

// enabled is a section's `enabled`, which defaults to on.
func enabled(s *uciSect) bool { return !uciFalse(s.get("enabled")) }

// signature names a section by its type and every option but the ones given, so the same rule
// reads the same whatever it is called and wherever it sits.
func signature(s *uciSect, except ...string) string {
	skip := map[string]bool{}
	for _, e := range except {
		skip[e] = true
	}
	var keys []string
	for k := range s.Opts {
		if !skip[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(s.Type)
	for _, k := range keys {
		b.WriteString("\x00" + k + "=" + strings.Join(s.Opts[k], "\x01"))
	}
	return b.String()
}

// fwModel is what the firewall says about the internet.
type fwModel struct {
	wanZones map[string]bool   // zones that face the internet, by name
	zoneNets map[string]string // network -> the first zone that lists it
	zones    map[string]*uciSect
	defIn    string
	defFwd   string
}

func firewallOf(st states) fwModel {
	m := fwModel{wanZones: map[string]bool{}, zoneNets: map[string]string{}, zones: map[string]*uciSect{},
		defIn: "DROP", defFwd: "DROP"}
	fw := st.get("firewall")
	for _, d := range fw.sectionsOf("defaults") {
		if v := d.word("input"); v != "" {
			m.defIn = v
		}
		if v := d.word("forward"); v != "" {
			m.defFwd = v
		}
	}
	for _, z := range fw.sectionsOf("zone") {
		name := z.name("name")
		if name == "" {
			continue
		}
		if _, dup := m.zones[name]; !dup {
			m.zones[name] = z
		}
		nets := z.list("network")
		for _, n := range nets {
			if _, seen := m.zoneNets[n]; !seen {
				m.zoneNets[n] = name
			}
			if n == "wan" || n == "wan6" {
				m.wanZones[name] = true
			}
		}
		if uciTrue(z.get("masq")) {
			m.wanZones[name] = true
		}
		// fw4 also matches a zone by device and by subnet. Which devices a pattern or a subnet
		// takes in is not read here, so such a zone counts as facing the internet.
		if len(z.list("device"))+len(z.list("subnet")) > 0 {
			m.wanZones[name] = true
		}
	}
	return m
}

func (m fwModel) policy(zone, which string) string {
	z := m.zones[zone]
	def := m.defIn
	if which == "forward" {
		def = m.defFwd
	}
	if z == nil {
		return def
	}
	if v := z.word(which); v != "" {
		return v
	}
	return def
}

func (m fwModel) fromInternet(src string) bool {
	src = strings.TrimSpace(src)
	return src == "*" || m.wanZones[src]
}

// openings are the redirects and rules that let the internet in, by signature, with their headline.
// A redirect opens unless it is SNAT, outbound by definition: a target nobody knows counts as DNAT.
func openings(st states) map[string]string {
	out := map[string]string{}
	m := firewallOf(st)
	for _, s := range st.get("firewall").sectionsOf("redirect") {
		if !enabled(s) || s.word("target") == "SNAT" || !m.fromInternet(s.get("src")) {
			continue
		}
		dport := s.get("dest_port")
		if dport == "" {
			dport = s.get("src_dport")
		}
		to := "the router"
		if ip := s.get("dest_ip"); ip != "" {
			to = showAddr(ip)
		}
		if dport != "" {
			to += ":" + showPorts(dport)
		}
		out[signature(s, "name")] = fmt.Sprintf("OPENS THE ROUTER TO THE INTERNET: %s %s from %s to %s",
			showProto(s.get("proto")), showPortsOr(s.get("src_dport"), "every port"), showFrom(s.get("src_ip")), to)
	}
	for _, s := range st.get("firewall").sectionsOf("rule") {
		if !enabled(s) || !accepts(s.word("target")) || !m.fromInternet(s.get("src")) {
			continue
		}
		to := "the router"
		if d := s.get("dest"); d != "" {
			to = "zone " + showValue(d)
		}
		out[signature(s, "name")] = fmt.Sprintf("OPENS THE ROUTER TO THE INTERNET: %s %s from %s to %s",
			showProto(s.get("proto")), showPortsOr(s.get("dest_port"), "every port"), showFrom(s.get("src_ip")), to)
	}
	return out
}

func portsToTheInternet(before, after states) []string {
	was := openings(before)
	var out []string
	for sig, h := range openings(after) {
		if _, ok := was[sig]; !ok {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func firewallWeakened(before, after states) []string {
	var out []string
	b, a := firewallOf(before), firewallOf(after)
	for _, z := range sortedKeys(a.wanZones) {
		if accepts(a.policy(z, "input")) && (!b.wanZones[z] || !accepts(b.policy(z, "input"))) {
			out = append(out, fmt.Sprintf("WEAKENS THE FIREWALL: zone %s accepts what comes in from the internet", showValue(z)))
		}
		if accepts(a.policy(z, "forward")) && (!b.wanZones[z] || !accepts(b.policy(z, "forward"))) {
			out = append(out, fmt.Sprintf("WEAKENS THE FIREWALL: zone %s forwards whatever comes in from the internet", showValue(z)))
		}
	}
	forwards := func(st states, m fwModel) map[string]string {
		got := map[string]string{}
		for _, s := range st.get("firewall").sectionsOf("forwarding") {
			if !enabled(s) || !m.fromInternet(s.get("src")) {
				continue
			}
			dest := "every zone"
			if d := s.get("dest"); d != "" {
				dest = "zone " + showValue(d)
			}
			got[signature(s, "name")] = fmt.Sprintf("WEAKENS THE FIREWALL: zone %s forwards from the internet to %s",
				showValue(s.get("src")), dest)
		}
		return got
	}
	was := forwards(before, b)
	for sig, h := range forwards(after, a) {
		if _, ok := was[sig]; !ok {
			out = append(out, h)
		}
	}
	if bz, az := sortedKeys(b.wanZones), sortedKeys(a.wanZones); strings.Join(bz, " ") != strings.Join(az, " ") {
		out = append(out, fmt.Sprintf("WEAKENS THE FIREWALL: the zones that face the internet change (%s -> %s)",
			showList(bz), showList(az)))
	}
	// A zone may take devices and subnets as well as networks (fw4's device and subnet lists), so
	// one that takes the internet port, or every address, is an internet zone by another name:
	// any change to what a zone takes that way is held.
	takes := func(st states) map[string]string {
		got := map[string]string{}
		for _, z := range st.get("firewall").sectionsOf("zone") {
			d, n := z.list("device"), z.list("subnet")
			if len(d)+len(n) > 0 {
				got[z.name("name")] += "device " + showList(d) + ", subnet " + showList(n) + "; "
			}
		}
		return got
	}
	bt, at := takes(before), takes(after)
	zones := map[string]bool{}
	for z := range bt {
		zones[z] = true
	}
	for z := range at {
		zones[z] = true
	}
	for _, z := range sortedKeys(zones) {
		if bt[z] != at[z] {
			was, now := strings.TrimSuffix(bt[z], "; "), strings.TrimSuffix(at[z], "; ")
			if was == "" {
				was = "none"
			}
			if now == "" {
				now = "none"
			}
			out = append(out, fmt.Sprintf("WEAKENS THE FIREWALL: zone %s matches by device or subnet (%s -> %s)",
				showValue(z), was, now))
		}
	}
	// fw4 writes a rule's or a redirect's `extra` and a zone's `extra_src` and `extra_dest` into the
	// ruleset as they are, so what they do is nftables', not anything a rule here reads: any change
	// to one, in any section, is held.
	raw := func(st states) map[string]string {
		got := map[string]string{}
		for _, sec := range st.get("firewall").Sections {
			for opt := range sec.Opts {
				if strings.HasPrefix(opt, "extra") {
					got["firewall."+sec.label()+"."+opt] = sec.get(opt)
				}
			}
		}
		return got
	}
	br, ar := raw(before), raw(after)
	for k, v := range ar {
		if w, ok := br[k]; !ok || w != v {
			out = append(out, "WEAKENS THE FIREWALL: raw nftables in "+k)
		}
	}
	for k := range br {
		if _, ok := ar[k]; !ok {
			out = append(out, "WEAKENS THE FIREWALL: raw nftables in "+k+" is removed")
		}
	}
	sort.Strings(out)
	return out
}

// netdevExists reports whether the kernel already has a network device by this name, which a
// device section of that name would then configure rather than create.
var netdevExists = func(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return true
	}
	_, err := os.Lstat(filepath.Join("/sys/class/net", name))
	return err == nil
}

// rewiring holds a change to how the router is wired, whatever it wires to. Which port ends up
// carrying the internet is netifd's to resolve, through bridges, bridge and switch VLANs, aliases,
// devices stacked on others and a protocol's own device, and following every way it does that
// never ends. So any change to a VLAN table, to the ports or base (ifname) of a device, a new or
// removed device included, or to what an interface sits on is held, but for one shape: an
// interface put on a device made in the same change with neither ports nor a base, which is how a
// guest network is set up and wires nothing to anything.
func rewiring(before, after states) []string {
	var out []string
	bn, an := before.get("network"), after.get("network")
	for _, typ := range []string{"bridge-vlan", "switch_vlan", "switch_port"} {
		for _, l := range sectionChanges(bn, an, func(s *uciSect) bool { return s.Type == typ }) {
			out = append(out, "REWIRES THE NETWORK: network."+l)
		}
	}
	bridges := map[string]bool{}
	devices := func(st *uciState) map[string][]string {
		got := map[string][]string{}
		for _, d := range st.sectionsOf("device") {
			name := d.name("name")
			if name == "" {
				name = d.label()
			}
			got[name] = append(append(got[name], d.list("ports")...), d.list("ifname")...)
			if got[name] == nil {
				got[name] = []string{}
			}
			if st == an && d.word("type") == "BRIDGE" {
				bridges[name] = true
			}
		}
		return got
	}
	bd, ad := devices(bn), devices(an)
	fresh := map[string]bool{}
	names := map[string]bool{}
	for n := range bd {
		names[n] = true
	}
	for n := range ad {
		names[n] = true
	}
	for _, n := range sortedKeys(names) {
		was, inBefore := bd[n]
		now, inAfter := ad[n]
		// A device section names the netdev it configures, so one named as an existing port (wan,
		// lan3) or as a VLAN of one is that port. Only a new bridge with a name netifd makes for it
		// alone, br-<name> with no dot or alias in it, is a new device with nothing in it.
		if !inBefore && len(now) == 0 && bridges[n] && strings.HasPrefix(n, "br-") && !strings.ContainsAny(n, ".@") {
			fresh[n] = true
			continue
		}
		if inBefore && (inAfter && strings.Join(was, " ") == strings.Join(now, " ") || !inAfter && len(was) == 0) {
			continue
		}
		out = append(out, fmt.Sprintf("REWIRES THE NETWORK: device %s takes %s -> %s", showValue(n), showList(was), showList(now)))
	}
	sits := func(st *uciState) map[string][]string {
		got := map[string][]string{}
		for _, i := range st.sectionsOf("interface") {
			got[i.label()] = append(i.list("device"), i.list("ifname")...)
		}
		return got
	}
	bi, ai := sits(bn), sits(an)
	for _, n := range sortStrs(keysOf(ai)) {
		now, was := ai[n], bi[n]
		if strings.Join(was, " ") == strings.Join(now, " ") || len(now) == 0 {
			continue
		}
		if len(now) == 1 && fresh[now[0]] {
			continue
		}
		out = append(out, fmt.Sprintf("REWIRES THE NETWORK: interface %s sits on %s -> %s", showValue(n), showList(was), showList(now)))
	}
	return out
}

func keysOf(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sectionChanges reports, by label, the sections pick selects that were added, removed or changed
// between two states of one config. A named section is compared by name, an anonymous one by its
// whole content.
func sectionChanges(b, a *uciState, pick func(*uciSect) bool) []string {
	var out []string
	content := func(st *uciState) map[string]*uciSect {
		got := map[string]*uciSect{}
		if st == nil {
			return got
		}
		for _, s := range st.Sections {
			if !pick(s) {
				continue
			}
			key := "anon\x00" + signature(s)
			if !anonName.MatchString(s.Name) {
				key = "name\x00" + s.Name + "\x00" + signature(s)
			}
			got[key] = s
		}
		return got
	}
	bs, as := content(b), content(a)
	for k, s := range as {
		if _, ok := bs[k]; !ok {
			out = append(out, s.label())
		}
	}
	for k, s := range bs {
		if _, ok := as[k]; !ok {
			out = append(out, s.label())
		}
	}
	return dedupe(sortStrs(out))
}

func sortStrs(s []string) []string { sort.Strings(s); return s }

// defaultDestination reports whether a route or rule's destination is every destination.
func defaultDestination(v string) bool {
	switch strings.TrimSpace(v) {
	case "0.0.0.0/0", "::/0", "default", "::0/0":
		return true
	}
	return false
}

func vpnRouting(before, after states) []string {
	var out []string
	for _, l := range sectionChanges(before.get("network"), after.get("network"), func(s *uciSect) bool {
		return strings.HasPrefix(s.Type, "wireguard_") || (s.Type == "interface" && s.word("proto") == "WIREGUARD")
	}) {
		out = append(out, "CHANGES VPN OR POLICY ROUTING: network."+l)
	}
	everything := func(st states) map[string]string {
		got := map[string]string{}
		for _, typ := range []string{"route", "route6"} {
			for _, s := range st.get("network").sectionsOf(typ) {
				t := strings.TrimSpace(s.get("target"))
				if defaultDestination(t) || (t == "0.0.0.0" && strings.TrimSpace(s.get("netmask")) == "0.0.0.0") {
					got[signature(s)] = fmt.Sprintf("CHANGES VPN OR POLICY ROUTING: every destination through %s",
						showValue(s.get("interface")))
				}
			}
		}
		for _, typ := range []string{"rule", "rule6"} {
			for _, s := range st.get("network").sectionsOf(typ) {
				if d := strings.TrimSpace(s.get("dest")); d == "" || defaultDestination(d) {
					got[signature(s)] = "CHANGES VPN OR POLICY ROUTING: a routing rule for every destination"
				}
			}
		}
		return got
	}
	b, a := everything(before), everything(after)
	for sig, h := range a {
		if _, ok := b[sig]; !ok {
			out = append(out, h)
		}
	}
	for sig, h := range b {
		if _, ok := a[sig]; !ok {
			out = append(out, h+" is removed")
		}
	}
	if len(sectionChanges(before.get("pbr"), after.get("pbr"), func(*uciSect) bool { return true })) > 0 ||
		(before.get("pbr") == nil) != (after.get("pbr") == nil) {
		out = append(out, "CHANGES VPN OR POLICY ROUTING: pbr")
	}
	return dedupe(sortStrs(out))
}

// dnsFacts are the settings that decide who answers the router's DNS, keyed by where they sit.
func dnsFacts(st states) map[string]string {
	got := map[string]string{}
	dhcp := st.get("dhcp")
	if dhcp != nil {
		for _, s := range dhcp.Sections {
			switch s.Type {
			case "dnsmasq":
				for _, o := range []string{"server", "address", "noresolv", "resolvfile", "rebind_protection"} {
					if v, ok := s.Opts[o]; ok {
						got["dhcp."+s.label()+"."+o] = strings.Join(v, "\x01")
					}
				}
			case "dhcp":
				for _, v := range s.list("dhcp_option") {
					if strings.HasPrefix(v, "6,") || strings.HasPrefix(v, "option:dns-server,") {
						got["dhcp."+s.label()+".dhcp_option"] += v + "\x01"
					}
				}
			case "host", "domain", "cname":
				name := s.get("name")
				if s.Type == "cname" {
					name = s.get("cname")
				}
				if strings.Contains(name, ".") {
					got["dhcp."+s.label()] = signature(s)
				}
			}
		}
	}
	for _, s := range st.get("network").sectionsOf("interface") {
		for _, o := range []string{"dns", "peerdns"} {
			if v, ok := s.Opts[o]; ok {
				got["network."+s.label()+"."+o] = strings.Join(v, "\x01")
			}
		}
	}
	return got
}

func upstreamDNS(before, after states) []string {
	b, a := dnsFacts(before), dnsFacts(after)
	var keys []string
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			keys = append(keys, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	var out []string
	for _, k := range dedupe(sortStrs(keys)) {
		out = append(out, "CHANGES WHO ANSWERS DNS: "+k)
	}
	return out
}

func timeServers(before, after states) []string {
	var out []string
	for _, l := range sectionChanges(before.get("system"), after.get("system"), func(s *uciSect) bool {
		return s.Type == "timeserver"
	}) {
		out = append(out, "CHANGES THE ROUTER'S TIME SERVERS: system."+l)
	}
	return out
}

func openWifi(st states) map[string]string {
	got := map[string]string{}
	m := firewallOf(st)
	for _, s := range st.get("wireless").sectionsOf("wifi-iface") {
		if uciTrue(s.get("disabled")) {
			continue
		}
		if mode := s.word("mode"); mode != "" && mode != "AP" {
			continue
		}
		switch s.word("encryption") {
		case "", "NONE", "OWE":
		default:
			continue
		}
		for _, n := range s.list("network") {
			z, ok := m.zoneNets[n]
			if !ok || m.wanZones[z] || !accepts(m.policy(z, "input")) {
				continue
			}
			got[s.get("ssid")+"\x00"+s.get("device")+"\x00"+n+"\x00"+z] = fmt.Sprintf(
				"OPENS WI-FI WITHOUT A PASSWORD INTO A TRUSTED NETWORK: %s into zone %s", showValue(s.get("ssid")), showValue(z))
		}
	}
	return got
}

func openWifiIntoTrusted(before, after states) []string {
	was := openWifi(before)
	var out []string
	for k, h := range openWifi(after) {
		if _, ok := was[k]; !ok {
			out = append(out, h)
		}
	}
	return dedupe(sortStrs(out))
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------------ showing values

// showValue quotes what a client chose so that it reads as data and nothing else: single quotes
// around it, a quote or a backslash inside escaped, and anything that is not a printable
// character (a control character, a line break, a right-to-left override that would reorder the
// card) written as \uXXXX.
func showValue(v string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range v {
		switch {
		case r == '\'' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == ' ' || (unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r)):
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func showList(vals []string) string {
	if len(vals) == 0 {
		return "none"
	}
	var out []string
	for _, v := range vals {
		out = append(out, showValue(v))
	}
	return strings.Join(out, ", ")
}

var portRange = regexp.MustCompile(`^[0-9]{1,5}([-:][0-9]{1,5})?$`)

// showPorts reads a port, a range or a list of them; what does not read as one is shown as unreadable.
func showPorts(v string) string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' }) {
		ok := portRange.MatchString(p)
		for _, n := range strings.FieldsFunc(p, func(r rune) bool { return r == '-' || r == ':' }) {
			if i, err := strconv.Atoi(n); err != nil || i < 0 || i > 65535 {
				ok = false
			}
		}
		if !ok {
			return "(unreadable " + showValue(v) + ")"
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return "(unreadable " + showValue(v) + ")"
	}
	return strings.Join(out, ",")
}

func showPortsOr(v, none string) string {
	if strings.TrimSpace(v) == "" {
		return none
	}
	return showPorts(v)
}

var protoName = regexp.MustCompile(`^[a-z0-9]{1,12}$`)

func showProto(v string) string {
	if strings.TrimSpace(v) == "" {
		return "tcp and udp"
	}
	var out []string
	for _, p := range strings.Fields(strings.ToLower(v)) {
		if !protoName.MatchString(p) {
			return "(unreadable " + showValue(v) + ")"
		}
		out = append(out, p)
	}
	return strings.Join(out, " and ")
}

// showAddr reads an address or a prefix with netip; anything else is shown as unreadable.
func showAddr(v string) string {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.String()
	}
	return "(unreadable " + showValue(v) + ")"
}

func showFrom(srcIP string) string {
	if strings.TrimSpace(srcIP) == "" {
		return "any address"
	}
	var out []string
	for _, a := range strings.Fields(srcIP) {
		out = append(out, showAddr(a))
	}
	return strings.Join(out, ", ")
}

// showOpt is one option's value for the card: redacted when its name marks a secret.
func showOpt(name string, vals []string) string {
	if isSecretUCIOption(name) {
		return redacted
	}
	var out []string
	for _, v := range vals {
		out = append(out, showValue(v))
	}
	return strings.Join(out, " ")
}

// diffConfig is every changed key of one config, before and after, in the order a person reads.
func diffConfig(b, a *uciState) []string {
	var out []string
	if a == nil && b == nil {
		return nil
	}
	cfg := ""
	if a != nil {
		cfg = a.Config
	} else {
		cfg = b.Config
	}
	optLines := func(s *uciSect, mark string) []string {
		var keys []string
		for k := range s.Opts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var lines []string
		for _, k := range keys {
			lines = append(lines, "  "+mark+" "+k+" "+showOpt(k, s.Opts[k]))
		}
		return lines
	}
	if a != nil {
		for _, s := range a.Sections {
			old := b.section(s.Name)
			if old == nil {
				out = append(out, fmt.Sprintf("%s.%s, new %s", cfg, s.label(), s.Type))
				out = append(out, optLines(s, "+")...)
				continue
			}
			var lines []string
			if old.Type != s.Type {
				lines = append(lines, fmt.Sprintf("  ~ type %s -> %s", showValue(old.Type), showValue(s.Type)))
			}
			keys := map[string]bool{}
			for k := range s.Opts {
				keys[k] = true
			}
			for k := range old.Opts {
				keys[k] = true
			}
			var names []string
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				nv, nok := s.Opts[k]
				ov, ook := old.Opts[k]
				switch {
				case nok && !ook:
					lines = append(lines, "  + "+k+" "+showOpt(k, nv))
				case !nok && ook:
					lines = append(lines, "  - "+k+" "+showOpt(k, ov))
				case strings.Join(nv, "\x00") != strings.Join(ov, "\x00") || s.Lists[k] != old.Lists[k]:
					lines = append(lines, "  ~ "+k+" "+showOpt(k, ov)+" -> "+showOpt(k, nv))
				}
			}
			if len(lines) > 0 {
				out = append(out, fmt.Sprintf("%s.%s, changed %s", cfg, s.label(), s.Type))
				out = append(out, lines...)
			}
		}
	}
	if b != nil {
		for _, s := range b.Sections {
			if a.section(s.Name) == nil {
				out = append(out, fmt.Sprintf("%s.%s, removed %s", cfg, s.label(), s.Type))
				out = append(out, optLines(s, "-")...)
			}
		}
	}
	return out
}

// ------------------------------------------------------------------ the fingerprint

// fingerprint is the SHA-256 of every config a classification read, as the files are on disk,
// so an approval can tell that the router is still what the change was checked against.
func fingerprint(configs []string) string {
	h := sha256.New()
	for _, c := range sortStrs(append([]string(nil), configs...)) {
		b, err := os.ReadFile(filepath.Join(uciConfigDir, c))
		if err != nil {
			fmt.Fprintf(h, "%s\x00missing\x00", c)
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\x00", c, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalisedInput is the input as it is stored and hashed: the encoding of the typed value, so
// two spellings of one call are one record and what runs is what was hashed.
func normalisedInput(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
