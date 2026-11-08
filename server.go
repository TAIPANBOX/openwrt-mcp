package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Server struct {
	configPath string
	statePath  string
	audit      *Auditor
	mfa        *MFAStore
	tokens     *TokenStore

	mu      sync.RWMutex
	config  *Config
	cfgTime time.Time
	pending map[string]*pendingApply
	held    *heldStore // changes waiting for the owner's approval (approval.go)
}

// cfg returns the current policy set, re-reading the config file when it has changed on
// disk so that `openwrt-mcp allow` and hand edits take effect without a restart. A file
// that fails to parse is ignored and the previous good config is kept -- a syntax error
// must not silently drop every policy (which would fail closed and look like a bug) nor
// leave a half-parsed one in place.
func (s *Server) cfg() *Config {
	if st, err := os.Stat(s.configPath); err == nil {
		s.mu.RLock()
		stale := !st.ModTime().Equal(s.cfgTime)
		s.mu.RUnlock()
		if stale {
			if fresh, err := LoadConfig(s.configPath); err == nil {
				s.mu.Lock()
				s.config, s.cfgTime = fresh, st.ModTime()
				s.mu.Unlock()
				log.Printf("openwrt-mcp: reloaded config (%d policies)", len(fresh.Policies))
			} else {
				s.mu.Lock()
				s.cfgTime = st.ModTime() // don't retry the same broken file every call
				s.mu.Unlock()
				log.Printf("openwrt-mcp: config reload failed, keeping previous policies: %v", err)
			}
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func NewServer(configPath, statePath string) (*Server, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	mfa, err := LoadMFA(path.Join(statePath, "mfa"))
	if err != nil {
		return nil, err
	}
	tokens, err := LoadTokens(path.Join(statePath, "tokens"))
	if err != nil {
		return nil, err
	}
	s := &Server{
		configPath: configPath,
		statePath:  statePath,
		mfa:        mfa,
		config:     cfg,
		tokens:     tokens,
		audit:      NewAuditor(cfg.AuditPath, cfg.AuditMaxMB),
		pending:    map[string]*pendingApply{},
		held:       newHeldStore(),
	}
	s.audit.mono = mfa.mono // a delay's end is read on the clock it was set on
	s.recoverPending()
	return s, nil
}

// sweep is the daemon's minute: summaries of the runs that ended, a day of uptime forgotten on the
// disk, a throttle write that failed tried again.
func (s *Server) sweep() {
	s.audit.Sweep()
	s.mfa.Sweep()
}

// housekeep runs sweep on every tick until the daemon is told to stop. What is counted in a fold
// exists only in memory, so it goes to the log on the way out.
func (s *Server) housekeep(stop <-chan os.Signal, tick <-chan time.Time) {
	for {
		select {
		case <-tick:
			s.sweep()
		case <-stop:
			s.audit.Flush()
			return
		}
	}
}

// ---------------------------------------------------------------- the helper's side of a call
//
// The listener (frontend.go) holds no token store, no policy and no state: it asks the helper, which
// is this Server, who a bearer token is and to run each call. The helper resolves the token itself on
// every call, so a listener that lies about a client gains nothing (docs/privilege-split.md).

// maxTokenLen bounds what is taken as a bearer token: a real one is 43 characters.
const maxTokenLen = 512

// badToken is the audit line of a bad or missing bearer token. Any process on the router can send
// one as fast as a loop runs, so it is folded.
func (s *Server) badToken(remote string) {
	s.audit.Fold(foldNote{key: "bad-token", what: "bad or missing bearer tokens"}, AuditEvent{
		Time: nowISO(), Client: "<unauthenticated>", Outcome: OutcomeDenied,
		Error: "bad or missing bearer token from " + truncate(remote, 128),
	})
}

// auth resolves a bearer token to its client, and writes the folded audit line of a bad one.
func (s *Server) auth(token, remote string) (string, bool, error) {
	client, ok := s.tokens.Resolve(strings.TrimSpace(token))
	if !ok {
		s.badToken(remote)
	}
	return client, ok, nil
}

// call runs one tool call under the client its bearer token resolves to. The token is resolved
// here, not taken from the listener as a name.
func (s *Server) call(ctx context.Context, token, tool string, input json.RawMessage) (string, bool, error) {
	client, ok := s.tokens.Resolve(strings.TrimSpace(token))
	if !ok {
		s.badToken("the listener")
		return "unauthorized: bad or missing bearer token", true, nil
	}
	text, isErr := s.callJSON(ctx, client, tool, input)
	return text, isErr, nil
}

// health is what /health adds to its line: whether the last throttle write reached the disk.
func (s *Server) health() (bool, error) { return s.mfa.ThrottlePersisted(), nil }

// ---------------------------------------------------------------- uci apply/rollback
//
// rpcd's own apply/rollback (ubus call uci apply {"rollback":true}) is the obvious thing
// to use and was the first choice, but it is unreachable here: every uci write method
// requires a ubus_rpc_session, and session.login needs a username+password. Using it would
// mean storing the router's root password in a file on the router -- a worse hole than the
// one the rollback closes. Verified on OpenWrt 21.02 / rpcd 2022-02-19:
//   ubus call uci apply '{}'                          -> Invalid argument  (no session)
//   ubus call uci apply '{"ubus_rpc_session":"0..0"}' -> No response       (null session lacks write ACL)
//
// So we snapshot /etc/config ourselves, arm a timer, and restore unless confirmed. The
// pending record is written to disk so that a daemon restart mid-window still rolls back:
// on startup an unconfirmed apply is always reverted, because "we lost track of it" is
// exactly when you want the conservative answer.

// uciConfigDir is where the router keeps its UCI files. A variable only so tests can point
// the apply/rollback machinery at a scratch directory.
var uciConfigDir = "/etc/config"

type pendingApply struct {
	Token    string    `json:"token"`
	Snapshot string    `json:"snapshot"`
	Deadline time.Time `json:"deadline"`
	Configs  []string  `json:"configs"`
	// ApprovedFor is the client whose held change this apply is, once the owner approved it. That
	// client confirms it without an unlock: the approval was the owner's consent to this change.
	ApprovedFor string `json:"approved_for,omitempty"`

	timer *time.Timer
}

// approvedApply reports whether token is a pending apply the owner approved for client.
func (s *Server) approvedApply(token, client string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.pending[token]
	return p != nil && client != "" && p.ApprovedFor == client
}

func (s *Server) pendingPath() string { return path.Join(s.statePath, "pending.json") }

// rollbackDir holds the snapshots. It lives in the state directory, which is on flash and
// survives a reboot, and not in os.TempDir(): on OpenWrt /tmp is RAM, so a power cut or a
// crash mid-window used to leave a pending.json that named a snapshot that no longer existed,
// and the very change the rollback was armed for -- the one that strands the router -- could
// then not be undone at the next start. The snapshots hold wifi keys and the like, so the
// directory is 0700 and each file 0600.
func (s *Server) rollbackDir() string { return path.Join(s.statePath, "rollback") }

// newSnapshotPath makes sure the rollback directory exists with the right mode and returns
// where this apply's snapshot goes.
func (s *Server) newSnapshotPath(token string) (string, error) {
	dir := s.rollbackDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// MkdirAll leaves an existing directory as it found it; tighten one that was loose.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return path.Join(dir, "openwrt-mcp-rollback-"+token+".tar.gz"), nil
}

// A change is one of four things, decided by which fields are set:
//
//	type set                -> create the section:  uci set dhcp.pi=host
//	option set              -> set an option:       uci set dhcp.pi.ip=192.168.0.141
//	option set + delete     -> remove an option:    uci delete dhcp.pi.ip
//	neither, + delete       -> remove the section:  uci delete dhcp.pi
//
// Section creation exists because without it uci_apply cannot express "add a static lease",
// "add a firewall rule" or "add an interface" -- UCI refuses to set an option on a section
// that does not exist ("uci: Invalid argument"), so those jobs fell out of the rollback-armed
// path and into a raw root shell, which is the one thing this tool is for avoiding.
//
// Named sections rather than `uci add`: the caller picks the name, so later changes in the
// same batch can refer to it without knowing a generated id, and re-running the same apply
// is idempotent where `uci add` would append a duplicate every time.
func validateChange(c UCIChange) error {
	if c.Config == "" || c.Section == "" {
		return fmt.Errorf("each change needs at least a config and a section")
	}
	// Names are checked against uci's own alphabet, not only for "/" and ".": a "." or "=" inside a
	// section or option would make the key uci acts on differ from the key the policy and the
	// code-execution check read (section "@dnsmasq[0].dhcpscript" with a type is
	// `uci set dhcp.@dnsmasq[0].dhcpscript=<type>`).
	if !uciName.MatchString(c.Config) {
		return fmt.Errorf("bad config name %q", c.Config)
	}
	if !uciSectionName.MatchString(c.Section) {
		return fmt.Errorf("bad section %q: a name, or @type[index]", c.Section)
	}
	if c.Option != "" && !uciName.MatchString(c.Option) {
		return fmt.Errorf("bad option name %q", c.Option)
	}
	if c.Type != "" {
		if c.Option != "" {
			return fmt.Errorf("%s.%s: type creates a section, so it cannot be combined with option",
				c.Config, c.Section)
		}
		if c.Delete {
			return fmt.Errorf("%s.%s: type creates a section, so it cannot be combined with delete",
				c.Config, c.Section)
		}
		if !uciName.MatchString(c.Type) {
			return fmt.Errorf("bad section type %q", c.Type)
		}
		return nil
	}
	if c.Option == "" && !c.Delete {
		return fmt.Errorf("%s.%s: needs an option to set, a type to create the section, "+
			"or delete to remove the whole section", c.Config, c.Section)
	}
	// uci_get shows a secret as this marker. Written back it would become the secret, and a
	// Wi-Fi passphrase anyone can read in this source is no passphrase at all.
	if !c.Delete && strings.Contains(c.Value, redacted) {
		return fmt.Errorf("%s: the value is the marker uci_get shows in place of a secret, not the secret; "+
			"ask the operator for the real value", uciKey(c))
	}
	return nil
}

// uciName is what libuci accepts as a config, option or type name (util.c uci_validate_str):
// letters, digits, '_' and '-'. uciSectionName adds the "@type[index]" selector.
var (
	uciName        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	uciSectionName = regexp.MustCompile(`^([A-Za-z0-9_-]+|@[A-Za-z0-9_-]+\[-?[0-9]+\])$`)
)

// uciKey is the change's identity for error messages and policy scope: "config.section" for
// anything section-level, "config.section.option" otherwise. Creating a section is a
// different permission from setting an option in one, and the scope string says so.
func uciKey(c UCIChange) string {
	if c.Option == "" {
		return c.Config + "." + c.Section
	}
	return c.Config + "." + c.Section + "." + c.Option
}

func uciArgv(c UCIChange) []string {
	switch {
	case c.Type != "":
		return []string{"uci", "set", uciKey(c) + "=" + c.Type}
	case c.Delete:
		// Covers both the option and the whole-section case; uciKey already picked which.
		return []string{"uci", "delete", uciKey(c)}
	default:
		return []string{"uci", "set", uciKey(c) + "=" + c.Value}
	}
}

func (s *Server) uciApply(ctx context.Context, in uciApplyIn) (string, string, error) {
	return s.applyUCI(ctx, in, "", nil)
}

// applyUCI is uci_apply. approvedFor names the client whose held change this is, when the owner
// approved it (approval.go), and is empty otherwise; guard, when given, is asked last before
// anything is snapshotted or staged, and its error stops the apply.
func (s *Server) applyUCI(ctx context.Context, in uciApplyIn, approvedFor string, guard func() error) (string, string, error) {
	if len(in.Changes) == 0 {
		return "", "", fmt.Errorf("changes must not be empty")
	}
	timeout := clampSec(in.Timeout, 90, 600)

	s.mu.Lock()
	busy := len(s.pending) > 0
	s.mu.Unlock()
	if busy {
		return "", "", fmt.Errorf("an apply is already pending confirmation; call uci_confirm or wait for it to roll back")
	}

	// Refuse to start on top of somebody else's uncommitted edits -- committing those
	// as a side effect would apply changes nobody asked us for.
	// The refusal lists them, redacted: a passphrase the owner staged in the web UI is a
	// secret like any other, and this message goes to the agent.
	if out, err := run(ctx, defaultCmdTimeout, "uci", "changes"); err == nil && strings.TrimSpace(out) != "" {
		return "", "", fmt.Errorf("refusing to apply: uncommitted UCI changes already exist:\n%s", redactUCIOutput(out))
	}

	// Work out which configs are affected before snapshotting: the snapshot covers only
	// those files, never the whole of /etc/config. A whole-tree restore would silently
	// clobber an unrelated change made by another process during the confirmation window.
	configs := map[string]bool{}
	for _, c := range in.Changes {
		if err := validateChange(c); err != nil {
			return "", "", err
		}
		configs[c.Config] = true
	}
	var names []string
	for c := range configs {
		if _, err := os.Stat(path.Join(uciConfigDir, c)); err != nil {
			return "", "", fmt.Errorf("no such UCI config %q", c)
		}
		names = append(names, c)
	}
	sort.Strings(names)

	// Nothing that makes the router run code, for any client, ever (uci_noexec.go). Checked over
	// the whole batch before anything is snapshotted or staged.
	if err := refuseCodeExec(ctx, in.Changes); err != nil {
		return "", "refused: would run code as root", err
	}
	if guard != nil {
		if err := guard(); err != nil {
			return "", "refused: the router changed during the approval", err
		}
	}

	token := randToken()
	snapshot, err := s.newSnapshotPath(token)
	if err != nil {
		return "", "", fmt.Errorf("snapshot failed: %w", err)
	}
	if out, err := run(ctx, defaultCmdTimeout,
		append([]string{"tar", "-czf", snapshot, "-C", uciConfigDir}, names...)...); err != nil {
		_ = os.Remove(snapshot)
		return "", "", fmt.Errorf("snapshot failed: %w\n%s", err, out)
	}
	if err := os.Chmod(snapshot, 0o600); err != nil {
		_ = os.Remove(snapshot)
		return "", "", fmt.Errorf("snapshot failed: %w", err)
	}

	for _, c := range in.Changes {
		key := uciKey(c)
		argv := uciArgv(c)
		if out, err := run(ctx, defaultCmdTimeout, argv...); err != nil {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c.Config)
			_ = os.Remove(snapshot)
			return "", "", fmt.Errorf("staging %s failed: %w\n%s", key, err, out)
		}
	}

	for _, c := range names {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", c); err != nil {
			s.restoreSnapshot(ctx, snapshot, names)
			return "", "", fmt.Errorf("commit %s failed: %w\n%s", c, err, out)
		}
	}
	reloadOut, _ := run(ctx, defaultCmdTimeout, "ubus", "call", "uci", "reload_config", "{}")

	p := &pendingApply{Token: token, Snapshot: snapshot, Deadline: time.Now().Add(timeout), Configs: names,
		ApprovedFor: approvedFor}
	s.mu.Lock()
	p.timer = time.AfterFunc(timeout, func() { s.rollback(token, "timeout") })
	s.pending[token] = p
	s.mu.Unlock()
	s.savePending()

	return fmt.Sprintf(
		"Applied %d change(s) to %s and reloaded.\n\n"+
			"ROLLBACK ARMED: this reverts automatically at %s (in %s) unless you call\n"+
			"  uci_confirm {\"token\": \"%s\"}\n\n"+
			"Verify the router is still reachable and behaving BEFORE confirming.\n%s",
		len(in.Changes), strings.Join(names, ", "),
		p.Deadline.Format(time.RFC3339), timeout, token, reloadOut,
	), fmt.Sprintf("applied %d change(s), rollback armed %s", len(in.Changes), timeout), nil
}

func (s *Server) uciConfirm(ctx context.Context, token string) (string, string, error) {
	s.mu.Lock()
	p, ok := s.pending[token]
	if ok {
		if p.timer != nil {
			p.timer.Stop()
		}
		delete(s.pending, token)
	}
	s.mu.Unlock()
	if !ok {
		return "", "", fmt.Errorf("no pending apply with token %q (it may have already rolled back)", token)
	}
	_ = os.Remove(p.Snapshot)
	s.savePending()
	return fmt.Sprintf("Confirmed. Rollback cancelled; changes to %s are permanent.", strings.Join(p.Configs, ", ")),
		"confirmed " + token, nil
}

func (s *Server) rollback(token, reason string) {
	s.mu.Lock()
	p, ok := s.pending[token]
	delete(s.pending, token)
	s.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := s.restoreSnapshot(ctx, p.Snapshot, p.Configs)
	s.savePending()
	outcome, msg := OutcomeOK, fmt.Sprintf("rolled back %s (%s)", strings.Join(p.Configs, ", "), reason)
	if err != nil {
		outcome, msg = OutcomeError, "ROLLBACK FAILED: "+err.Error()
	}
	log.Printf("openwrt-mcp: %s", msg)
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<system>", Tool: "uci_rollback", Outcome: outcome, Summary: msg})
}

func (s *Server) restoreSnapshot(ctx context.Context, snapshot string, configs []string) error {
	if _, err := os.Stat(snapshot); err != nil {
		return fmt.Errorf("snapshot %s missing: %w", snapshot, err)
	}
	if out, err := run(ctx, defaultCmdTimeout, "tar", "-xzf", snapshot, "-C", uciConfigDir); err != nil {
		return fmt.Errorf("restore failed: %w\n%s", err, out)
	}
	for _, c := range configs {
		_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
	}
	if out, err := run(ctx, defaultCmdTimeout, "ubus", "call", "uci", "reload_config", "{}"); err != nil {
		return fmt.Errorf("reload after restore failed: %w\n%s", err, out)
	}
	_ = os.Remove(snapshot)
	return nil
}

func (s *Server) savePending() {
	s.mu.RLock()
	list := make([]*pendingApply, 0, len(s.pending))
	for _, p := range s.pending {
		list = append(list, p)
	}
	s.mu.RUnlock()
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	_ = os.MkdirAll(s.statePath, 0o700)
	_ = os.WriteFile(s.pendingPath(), b, 0o600)
}

// recoverPending rolls back any apply that was still unconfirmed when we stopped.
// A restart during the confirmation window means nobody ever vouched for the change.
func (s *Server) recoverPending() {
	b, err := os.ReadFile(s.pendingPath())
	if err != nil {
		return
	}
	var list []*pendingApply
	if json.Unmarshal(b, &list) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, p := range list {
		log.Printf("openwrt-mcp: unconfirmed apply %s found at startup, rolling back", p.Token)
		if err := s.restoreSnapshot(ctx, p.Snapshot, p.Configs); err != nil {
			log.Printf("openwrt-mcp: recovery rollback failed: %v", err)
		}
	}
	_ = os.Remove(s.pendingPath())
}
