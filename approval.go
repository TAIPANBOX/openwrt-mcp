package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Held actions: a high-impact change waits for the owner's approval, one change at a time.
//
// @decided 2026-10-22 (the owner's design for hermes-openwrt, paraphrased): reads always; reversible
// changes in the unlock window; high-impact changes (classify.go) held here as an immutable record
// and approved one by one, from the owner's own client, with a fresh PIN and code, against a hash
// of exactly the batch shown; what only a person may do, never. Approving needs the PIN and a code
// from the authenticator; a client may propose while its window is closed, at most one change at a
// time, six an hour, and none for an hour after three rejections; one approver per client; the
// window is opened by that approver too, never by the client itself.
//
// A record lives in memory only, like the window: a restart drops every one, which errs toward
// asking again. Its hash covers the id, the client, the tool, the normalised input, the card, the
// fingerprint of the configs it was checked against and its times, so an approval of a hash is an
// approval of everything the owner was shown and of nothing else. The record is never edited:
// what changes is its status.
//
// The approver's client is a separate client of this daemon (hermes-openwrt pairs it and gives
// its token only to the plugin that carries the owner's messages), so the agent's own token, which
// its terminal can reach, can neither approve nor spend the owner's tries.

// Approval is one client's approval section.
type Approval struct {
	Name       string
	Client     string
	Approver   string
	Factor     string // pin+totp, or totp; never a PIN alone, which is not fresh
	TTL        time.Duration
	MaxOpen    int
	MaxPerHour int
	PauseAfter int
	Pause      time.Duration
	On         bool
	Hold       []approvalRule
	Refuse     []approvalRule
}

// approvalRule is one `list hold` or `list refuse` entry: a tool and a scope glob matched the way a
// policy's are.
type approvalRule struct{ tool, glob string }

func (r approvalRule) covers(tool string, scopes []string) bool {
	if r.tool != tool {
		return false
	}
	for _, sc := range scopes {
		if scopeCovered(tool, []string{r.glob}, sc) {
			return true
		}
	}
	return false
}

// approvalTools are the tools a refuse rule may name: the ones that change something. heldTools are
// the ones a hold rule or a hold policy may name: what runHeld can run once approved. apk_add is not
// one yet, so holding it would cost the owner a PIN and a code for a change that can never run.
var (
	approvalTools = map[string]bool{"uci_apply": true, "ubus_call": true, "apk_add": true}
	heldTools     = map[string]bool{"uci_apply": true, "ubus_call": true}
)

const (
	defaultApprovalTTL   = 10 * time.Minute
	defaultMaxOpen       = 1
	defaultMaxPerHour    = 6
	defaultPauseAfter    = 3
	defaultApprovalPause = time.Hour
	approveRollback      = 300 // seconds an approved uci_apply waits for its confirmation
	maxCardRunes         = 3500
)

func approvalFromSection(s uciSection) (*Approval, error) {
	a := &Approval{Name: s.Name, Client: strings.TrimSpace(s.Options["client"]),
		Approver: strings.TrimSpace(s.Options["approver"]), Factor: factorPINTOTP, TTL: defaultApprovalTTL,
		MaxOpen: defaultMaxOpen, MaxPerHour: defaultMaxPerHour, PauseAfter: defaultPauseAfter,
		Pause: defaultApprovalPause, On: true}
	if a.Client == "" {
		return nil, fmt.Errorf("missing 'client'")
	}
	if a.Approver == "" {
		return nil, fmt.Errorf("missing 'approver': the client that approves %q's held changes", a.Client)
	}
	if a.Approver == a.Client {
		return nil, fmt.Errorf("%q cannot approve its own changes", a.Client)
	}
	if v := strings.TrimSpace(s.Options["factor"]); v != "" {
		switch v {
		case factorPINTOTP, factorTOTP:
			a.Factor = v
		default:
			return nil, fmt.Errorf("bad 'factor' %q: want %s or %s (a PIN alone is not fresh)", v, factorPINTOTP, factorTOTP)
		}
	}
	dur := func(name string, def, min, max time.Duration) (time.Duration, error) {
		v := strings.TrimSpace(s.Options[name])
		if v == "" {
			return def, nil
		}
		d, err := parseDuration(v)
		if err != nil || d < min || d > max {
			return 0, fmt.Errorf("bad '%s' %q: want a duration from %s to %s", name, v, min, max)
		}
		return d, nil
	}
	num := func(name string, def, min, max int) (int, error) {
		v := strings.TrimSpace(s.Options[name])
		if v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			return 0, fmt.Errorf("bad '%s' %q: want a whole number from %d to %d", name, v, min, max)
		}
		return n, nil
	}
	var err error
	if a.TTL, err = dur("ttl", defaultApprovalTTL, time.Second, time.Hour); err != nil {
		return nil, err
	}
	if a.Pause, err = dur("pause", defaultApprovalPause, time.Minute, 24*time.Hour); err != nil {
		return nil, err
	}
	if a.MaxOpen, err = num("max_open", defaultMaxOpen, 1, 5); err != nil {
		return nil, err
	}
	if a.MaxPerHour, err = num("max_per_hour", defaultMaxPerHour, 1, 60); err != nil {
		return nil, err
	}
	if a.PauseAfter, err = num("pause_after_rejects", defaultPauseAfter, 1, 20); err != nil {
		return nil, err
	}
	switch v := strings.TrimSpace(s.Options["approvals"]); v {
	case "", "on":
	case "off":
		a.On = false
	default:
		return nil, fmt.Errorf("bad 'approvals' %q: want on or off", v)
	}
	for _, kind := range []string{"hold", "refuse"} {
		for _, e := range s.Lists[kind] {
			tool, glob, ok := strings.Cut(strings.TrimSpace(e), ":")
			if !ok || !approvalTools[tool] || glob == "" || (kind == "hold" && !heldTools[tool]) {
				return nil, fmt.Errorf("bad '%s' %q: want <tool>:<scope glob>, the tool uci_apply or ubus_call (or apk_add, to refuse)", kind, e)
			}
			r := approvalRule{tool: tool, glob: glob}
			if kind == "hold" {
				a.Hold = append(a.Hold, r)
			} else {
				a.Refuse = append(a.Refuse, r)
			}
		}
	}
	return a, nil
}

// approvalReady says what stands in the way of approving a's held changes, or "".
func (s *Server) approvalReady(a *Approval) string {
	if !a.On {
		return "approval is switched off on this router"
	}
	// Pairing is a CLI run beside the daemon (hermes-openwrt pairs the approver at its service's
	// start), so the token file is read again when it has changed.
	s.tokens.reloadIfChanged()
	if !contains(s.tokens.Clients(), a.Approver) {
		return "the owner's client " + a.Approver + " is not paired, so nobody can approve it"
	}
	if a.Factor == factorPINTOTP && !s.mfa.PINSet(a.Client) {
		return "no PIN is set for " + a.Client + ", and approving takes the PIN and a code"
	}
	if !s.mfa.Enrolled(a.Client) {
		return "no authenticator app is set up for " + a.Client + ", and approving takes a code from it"
	}
	return ""
}

// ------------------------------------------------------------------ the store

const (
	statusHeld      = "held"
	statusApproving = "approving"
	statusApplied   = "applied"
	statusFailed    = "failed"
	statusRejected  = "rejected"
	statusExpired   = "expired"
	statusWithdrawn = "withdrawn"
)

// heldAction is one record. Nothing in it changes after it is made but Status, Decided and Result.
type heldAction struct {
	ID        string
	Client    string
	Tool      string
	Input     json.RawMessage
	Scopes    []string
	Argv      []string
	Headlines []string
	// Card is what the owner is shown. cardBase is the same card without its ref, which is what
	// the hash covers: the ref is the hash's first 8 hex, so the card the hash covers cannot hold it,
	// and as it is computed from the hash, the hash still covers all the card says.
	Card        string
	cardBase    string
	Fingerprint string
	Configs     []string
	Created     time.Time
	Expires     time.Time
	Hash        string

	Status  string
	Decided time.Time
	Result  string
}

// hashed is what the hash covers, in a fixed order.
type hashed struct {
	ID          string          `json:"id"`
	Client      string          `json:"client"`
	Tool        string          `json:"tool"`
	Input       json.RawMessage `json:"input"`
	Card        string          `json:"card"`
	Fingerprint string          `json:"fingerprint"`
	Created     string          `json:"created"`
	Expires     string          `json:"expires"`
}

func (h *heldAction) computeHash() string {
	b, _ := json.Marshal(hashed{h.ID, h.Client, h.Tool, h.Input, h.cardBase, h.Fingerprint,
		h.Created.UTC().Format(time.RFC3339Nano), h.Expires.UTC().Format(time.RFC3339Nano)})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type heldStore struct {
	mu          sync.Mutex
	byID        map[string]*heldAction
	proposed    map[string][]time.Time // client -> when each proposal was made
	rejects     map[string]int         // client -> rejections since the last approval or pause
	pausedUntil map[string]time.Time
}

func newHeldStore() *heldStore {
	return &heldStore{byID: map[string]*heldAction{}, proposed: map[string][]time.Time{},
		rejects: map[string]int{}, pausedUntil: map[string]time.Time{}}
}

// keepDecided is how long a decided record stays readable, so the agent and the approver's
// client can learn how it ended.
const keepDecided = time.Hour

// sweepLocked expires what has run out and forgets what was decided long ago.
func (st *heldStore) sweepLocked(now time.Time) {
	for id, h := range st.byID {
		if h.Status == statusHeld && !now.Before(h.Expires) {
			h.Status, h.Decided = statusExpired, h.Expires
		}
		if h.Status != statusHeld && h.Status != statusApproving && now.Sub(h.Decided) > keepDecided {
			delete(st.byID, id)
		}
	}
}

// heldID is five capital letters: no digits, so the PIN and code scrubber in the messenger leaves
// it alone. It names a record and grants nothing: approving one still takes its hash and the
// owner's factors.
func heldID() string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 5))
		}
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// renderCard is the card the owner reads, written here from the record and nothing else. ref is
// empty for the card the hash is taken over.
func renderCard(h *heldAction, ttl time.Duration, body []string, ref string) string {
	var b strings.Builder
	if ref != "" {
		ref = ", ref " + ref
	}
	fmt.Fprintf(&b, "Router change waiting for you (%s%s, expires in %s)\n", h.ID, ref, shortDuration(ttl))
	fmt.Fprintf(&b, "Asked by %s:\n", h.Client)
	for _, l := range h.Headlines {
		b.WriteString(l + "\n")
	}
	if len(body) > 0 {
		b.WriteString("\n")
		for _, l := range body {
			b.WriteString(l + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func shortDuration(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return d.Round(time.Second).String()
}

// ubusBody is the card's body for a ubus call: the call and its arguments, each value quoted.
func ubusBody(in ubusCallIn) []string {
	out := []string{"ubus call " + showValue(in.Object) + " " + showValue(in.Method)}
	keys := make([]string, 0, len(in.Args))
	for k := range in.Args {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		v, isString := in.Args[k].(string)
		if !isString {
			b, _ := json.Marshal(in.Args[k])
			v = string(b)
		}
		out = append(out, "  "+showValue(k)+" "+showValue(v))
	}
	return out
}

// hold makes the record for a call the classifier held, or says why it may not be proposed.
func (s *Server) hold(client, tool string, input any, scopes, argv []string, cl classification, body []string,
	a *Approval, now time.Time) (*heldAction, string) {
	st := s.held
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked(now)
	if until, ok := st.pausedUntil[client]; ok && now.Before(until) {
		return nil, fmt.Sprintf("refused: proposals from %s are paused until %s, after %d rejections in a row; "+
			"nothing was applied", client, until.Format(time.RFC3339), a.PauseAfter)
	}
	open := 0
	var openID string
	for _, h := range st.byID {
		if h.Client == client && (h.Status == statusHeld || h.Status == statusApproving) {
			open++
			openID = h.ID
		}
	}
	if open >= a.MaxOpen {
		return nil, fmt.Sprintf("refused: %s already has a change waiting for the owner (%s); wait for the owner's "+
			"answer, or withdraw it with action_withdraw; nothing was applied", client, openID)
	}
	var recent []time.Time
	for _, t := range st.proposed[client] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	st.proposed[client] = recent
	if len(recent) >= a.MaxPerHour {
		return nil, fmt.Sprintf("refused: %s has proposed %d changes in the last hour, the most allowed in an hour; "+
			"nothing was applied", client, len(recent))
	}
	h := &heldAction{Client: client, Tool: tool, Input: normalisedInput(input), Scopes: scopes, Argv: argv,
		Headlines: cl.headlines, Fingerprint: fingerprint(cl.configs), Configs: cl.configs,
		Created: now, Expires: now.Add(a.TTL), Status: statusHeld}
	for {
		h.ID = heldID()
		if _, taken := st.byID[h.ID]; !taken {
			break
		}
	}
	h.cardBase = renderCard(h, a.TTL, body, "")
	h.Hash = h.computeHash()
	h.Card = renderCard(h, a.TTL, body, h.Hash[:8])
	if utf8.RuneCountInString(h.Card) > maxCardRunes {
		return nil, fmt.Sprintf("refused: this change is too long to show the owner in one card (%d characters, "+
			"the most is %d), and a card is never cut short; split it into smaller changes; nothing was applied",
			utf8.RuneCountInString(h.Card), maxCardRunes)
	}
	st.byID[h.ID] = h
	st.proposed[client] = append(st.proposed[client], now)
	return h, ""
}

// heldText is what the agent is told of a held call: not an error, and not to be retried.
func heldText(h *heldAction) string {
	return fmt.Sprintf("HELD %s until %s\nThis change waits for the owner's approval, which they give in the "+
		"chat with their PIN and a code. Nothing was applied. Do not retry it or ask the owner for a PIN or a code; "+
		"you will be told the outcome, or read it with action_status.\n%s",
		h.ID, h.Expires.UTC().Format(time.RFC3339), strings.Join(h.Headlines, "\n"))
}

// actionView is a record as a client reads it. The agent's own view carries no card and no hash:
// it never needs them, and an approval it could forward should not be in its context.
type actionView struct {
	ID       string `json:"id"`
	Client   string `json:"client,omitempty"`
	Tool     string `json:"tool"`
	Status   string `json:"status"`
	Ref      string `json:"ref,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Headline string `json:"headline"`
	Card     string `json:"card,omitempty"`
	Created  string `json:"created"`
	Expires  string `json:"expires"`
	Decided  string `json:"decided,omitempty"`
	Result   string `json:"result,omitempty"`
}

func viewOf(h *heldAction, owner bool) actionView {
	v := actionView{ID: h.ID, Tool: h.Tool, Status: h.Status, Headline: strings.Join(h.Headlines, "\n"),
		Created: h.Created.UTC().Format(time.RFC3339), Expires: h.Expires.UTC().Format(time.RFC3339), Result: h.Result}
	if !h.Decided.IsZero() {
		v.Decided = h.Decided.UTC().Format(time.RFC3339)
	}
	if owner {
		v.Client, v.Hash, v.Ref, v.Card = h.Client, h.Hash, h.Hash[:8], h.Card
	}
	return v
}

func actionsJSON(views []actionView) string {
	if views == nil {
		views = []actionView{}
	}
	b, _ := json.MarshalIndent(struct {
		Actions []actionView `json:"actions"`
	}{views}, "", "  ")
	return string(b)
}

// views lists the records of the clients given, oldest first.
func (s *Server) views(clients []string, owner bool, now time.Time) []actionView {
	st := s.held
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked(now)
	var list []*heldAction
	for _, h := range st.byID {
		if contains(clients, h.Client) {
			list = append(list, h)
		}
	}
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].Created.Before(list[j-1].Created); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	var out []actionView
	for _, h := range list {
		out = append(out, viewOf(h, owner))
	}
	return out
}

// ------------------------------------------------------------------ the tools

type actionStatusIn struct{}

type actionIDIn struct {
	ID string `json:"id" jsonschema:"the five-letter id the HELD answer named"`
}

type actionApproveIn struct {
	ID   string `json:"id" jsonschema:"the five-letter id of the held change"`
	Hash string `json:"hash" jsonschema:"the 64-hex hash of the card that was shown to the owner"`
	PIN  string `json:"pin,omitempty" jsonschema:"the owner's PIN"`
	Code string `json:"code,omitempty" jsonschema:"a current 6-digit code from the owner's authenticator"`
}

func (s *Server) actionStatus(client string) (string, string, error) {
	return actionsJSON(s.views([]string{client}, false, time.Now())), "action_status", nil
}

func (s *Server) actionWithdraw(client, id string) (string, string, error) {
	st := s.held
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	st.sweepLocked(now)
	h := st.byID[strings.TrimSpace(id)]
	if h == nil || h.Client != client {
		return "", "action_withdraw", &refusedError{fmt.Sprintf("no change of %s waits as %q", client, id)}
	}
	if h.Status != statusHeld {
		return "", "action_withdraw", &refusedError{fmt.Sprintf("%s is %s, not waiting", h.ID, h.Status)}
	}
	h.Status, h.Decided = statusWithdrawn, now
	return "Withdrawn: " + h.ID + " no longer waits for the owner.", "withdrew " + h.ID, nil
}

func (s *Server) actionList(caller string) (string, string, error) {
	clients := s.cfg().approvedBy(caller)
	if len(clients) == 0 {
		return "", "action_list", &refusedError{"refused: " + caller + " approves no client's changes"}
	}
	return actionsJSON(s.views(clients, true, time.Now())), "action_list", nil
}

// decidable is the record the caller may decide on, or why there is none. Callers hold s.held.mu.
func (s *Server) decidable(caller, id string, now time.Time) (*heldAction, error) {
	st := s.held
	st.sweepLocked(now)
	h := st.byID[strings.TrimSpace(id)]
	if h == nil {
		if len(s.cfg().approvedBy(caller)) == 0 {
			return nil, &refusedError{"refused: only the owner's client approves or rejects a held change, and " +
				caller + " approves no client's changes"}
		}
		return nil, &refusedError{fmt.Sprintf("refused: no held change %q (a restart drops every one)", id)}
	}
	if !s.cfg().approves(caller, h.Client) {
		return nil, &refusedError{"refused: only the owner's client of " + h.Client + " approves or rejects its changes"}
	}
	switch h.Status {
	case statusHeld:
		return h, nil
	case statusExpired:
		return nil, &refusedError{fmt.Sprintf("refused: %s expired at %s", h.ID, h.Expires.UTC().Format(time.RFC3339))}
	}
	return nil, &refusedError{fmt.Sprintf("refused: %s is %s", h.ID, h.Status)}
}

func (s *Server) actionReject(caller, id string) (string, string, error) {
	st := s.held
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	h, err := s.decidable(caller, id, now)
	if err != nil {
		return "", "action_reject", err
	}
	s.rejectLocked(h, now)
	return "Rejected: " + h.ID + " will not be applied.", "rejected " + h.ID + " of " + h.Client, nil
}

// rejectLocked rejects one record and counts it toward the client's pause. Callers hold st.mu.
func (s *Server) rejectLocked(h *heldAction, now time.Time) {
	st := s.held
	h.Status, h.Decided = statusRejected, now
	st.rejects[h.Client]++
	if a := s.cfg().approvalFor(h.Client); a != nil && st.rejects[h.Client] >= a.PauseAfter {
		st.pausedUntil[h.Client] = now.Add(a.Pause)
		st.rejects[h.Client] = 0
	}
}

// rejectAll rejects every held change of a client: the owner's lock.
func (s *Server) rejectAll(client string) int {
	st := s.held
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	st.sweepLocked(now)
	n := 0
	for _, h := range st.byID {
		if h.Client == client && h.Status == statusHeld {
			s.rejectLocked(h, now)
			n++
		}
	}
	return n
}

// actionApprove checks, in order, that the caller approves the record's client, that the record
// is still held, that the hash is the record's, that the configs are what it was checked against,
// that no other apply waits for confirmation, that a policy still grants the call and that approval
// can work at all. Only then are the factors checked, which is the one step that counts a try. A
// record that passes is run once, through the tool's own function, so every check that tool makes
// (uci_apply's refusal of code execution among them) still stands.
func (s *Server) actionApprove(ctx context.Context, caller string, in actionApproveIn) (string, string, error) {
	st := s.held
	now := time.Now()
	st.mu.Lock()
	h, err := s.decidable(caller, in.ID, now)
	if err != nil {
		st.mu.Unlock()
		return "", "action_approve", err
	}
	if len(in.Hash) != 64 || subtle.ConstantTimeCompare([]byte(strings.ToLower(in.Hash)), []byte(h.Hash)) != 1 {
		st.mu.Unlock()
		return "", "action_approve", &refusedError{"refused: the hash is not that of " + h.ID +
			"'s card; approve exactly the card that was shown, with its whole hash"}
	}
	h.Status = statusApproving // one approval at a time: a second one finds it taken
	st.mu.Unlock()
	back := func(err error) (string, string, error) {
		st.mu.Lock()
		if h.Status == statusApproving {
			h.Status = statusHeld
		}
		st.mu.Unlock()
		return "", "action_approve", err
	}

	if fingerprint(h.Configs) != h.Fingerprint {
		return back(&refusedError{"refused: the router's configuration has changed since " + h.ID +
			" was checked, so it is not the change you were shown; reject it, and let it be proposed again"})
	}
	s.mu.Lock()
	busy := len(s.pending) > 0
	s.mu.Unlock()
	if busy {
		return back(&refusedError{"refused: another change waits for confirmation; once it is confirmed or rolled " +
			"back, approve " + h.ID + " again"})
	}
	if h.Tool == "uci_apply" {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "changes"); err == nil && strings.TrimSpace(out) != "" {
			return back(&refusedError{"refused: uncommitted UCI changes exist, made since " + h.ID + " was checked"})
		}
	}
	if p, reason := s.cfg().authorise(h.Client, h.Tool, h.Scopes, h.Argv, now); p == nil {
		return back(&refusedError{"refused: no policy grants " + h.ID + " any more: " + firstLine(reason)})
	}
	a := s.cfg().approvalFor(h.Client)
	if a == nil {
		return back(&refusedError{"refused: " + h.Client + " has no approval section any more"})
	}
	if why := s.approvalReady(a); why != "" {
		return back(&refusedError{"refused: " + why})
	}
	up := s.unlockPolicyFor(h.Client)
	up.Factor = a.Factor
	if err := s.mfa.Verify(h.Client, unlockAttempt{Code: in.Code, PIN: in.PIN}, up, now); err != nil {
		return back(err)
	}

	result, summary, runErr := s.runHeld(ctx, h)
	st.mu.Lock()
	h.Decided = time.Now()
	if runErr != nil {
		h.Status, h.Result = statusFailed, runErr.Error()
		if result != "" {
			h.Result += "\n" + result
		}
	} else {
		h.Status, h.Result = statusApplied, result
	}
	st.rejects[h.Client] = 0
	st.mu.Unlock()
	ev := AuditEvent{Time: nowISO(), Client: h.Client, Tool: h.Tool, Scope: strings.Join(h.Scopes, " "),
		Outcome: OutcomeOK, Summary: summary + " (approved " + h.ID + " by " + caller + ")"}
	if runErr != nil {
		ev.Outcome, ev.Error = OutcomeError, runErr.Error()
	}
	s.audit.Record(ev)
	if runErr != nil {
		return "", "approved " + h.ID + ", which failed", fmt.Errorf("approved, but %s failed: %v", h.ID, runErr)
	}
	return "Applied " + h.ID + ".\n" + result, "approved " + h.ID + " of " + h.Client, nil
}

// runHeld runs a record's stored input through its tool's own function.
func (s *Server) runHeld(ctx context.Context, h *heldAction) (string, string, error) {
	switch h.Tool {
	case "uci_apply":
		var in uciApplyIn
		if err := json.Unmarshal(h.Input, &in); err != nil {
			return "", "", err
		}
		in.Timeout = approveRollback
		// Checked again as the last step before anything is staged: the approval's own checks and
		// the slow PIN check ran with nothing held, and an edit in that time is not what was shown.
		return s.applyUCI(ctx, in, h.Client, func() error {
			if now := fingerprint(h.Configs); now != h.Fingerprint {
				return &refusedError{"refused: the router's configuration changed since " + h.ID +
					" was checked, while it was being approved; nothing was applied"}
			}
			return nil
		})
	case "ubus_call":
		var in ubusCallIn
		if err := json.Unmarshal(h.Input, &in); err != nil {
			return "", "", err
		}
		return ubusCall(ctx, in)
	}
	return "", "", fmt.Errorf("%s cannot be run after an approval", h.Tool)
}

// classifyCall is the gate's question for a client with an approval section: refused, held, or
// run as before.
func (s *Server) classifyCall(ctx context.Context, tool string, shape callShape, p *Policy, a *Approval) classification {
	for _, r := range a.Refuse {
		if r.covers(tool, shape.scopes) {
			return classification{tier: tierRefused, refusal: "refused: the owner's approval section keeps " + tool +
				" on " + strings.Join(shape.scopes, " ") + " for a person; nothing was run"}
		}
	}
	cl := classification{tier: tierRun}
	if shape.classify != nil {
		cl = shape.classify(ctx)
	}
	if cl.tier == tierRefused {
		return cl
	}
	why := ""
	if p.Hold {
		why = "WAITS FOR YOUR APPROVAL BY POLICY: " + tool + " " + strings.Join(shape.scopes, " ")
	}
	for _, r := range a.Hold {
		if r.covers(tool, shape.scopes) {
			why = "WAITS FOR YOUR APPROVAL BY POLICY: " + tool + " " + strings.Join(shape.scopes, " ")
		}
	}
	if why != "" {
		cl.tier = tierHeld
		cl.headlines = dedupe(append(cl.headlines, why))
	}
	return cl
}
