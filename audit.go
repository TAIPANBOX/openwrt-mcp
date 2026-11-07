package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Redaction is owned by the recorder, never by callers, so a new tool cannot
// accidentally leak a plaintext secret into the log by forgetting to scrub it.
//
// Note the deliberate omission of a bare "key": keyId / publicKey / pubkey are safe
// identifiers and redacting them would make the log useless for debugging. The
// router-specific additions over Haven's list are psk, wgkey and private_key.
var secretKeySubstrings = []string{
	"password", "passwd", "secret", "token", "credential",
	"apikey", "api_key", "privatekey", "private_key", "passphrase",
	"psk", "wgkey", "encryption_key",
}

// secretKeyExact are keys that are secret only when they are the whole name. "code" and
// "pin" are what mfa_unlock carries; as substrings they would also hide "ping", "mapping",
// "zipcode" and "country_code" in a ubus argument, making the log useless for no gain.
var secretKeyExact = map[string]bool{"code": true, "pin": true, "otp": true}

const redacted = "<redacted>"

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			switch {
			case isSecretKey(k):
				out[k] = redacted
			case k == "argv":
				out[k] = redactArgvValue(val)
			default:
				out[k] = redact(val)
			}
		}
		// A uci change names the option it sets and the section it sets it in, and carries the
		// value. The value is a secret when either name marks a credential, whatever the other
		// is: a Wi-Fi "key", a WireGuard "private_key", or any option in a "vpn_password" section.
		if _, has := out["value"]; has && marksCredential(t) {
			out["value"] = redacted
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(val)
		}
		return out
	default:
		return v
	}
}

// marksCredential reports whether the option or the section of a uci-shaped map names a credential.
func marksCredential(m map[string]any) bool {
	for _, k := range []string{"option", "section"} {
		if s, ok := m[k].(string); ok && credentialName(s) {
			return true
		}
	}
	return false
}

// credentialName reports whether a name, of an option, a section or a flag, marks a secret. The
// names the router holds (isSecretUCIOption) and the names the log has always redacted
// (isSecretKey) both count, and a hyphen reads as an underscore, so "private-key" and
// "private_key" are one name.
func credentialName(s string) bool {
	n := strings.ReplaceAll(strings.ToLower(s), "-", "_")
	return isSecretUCIOption(n) || isSecretKey(n)
}

// redactArgvValue redacts an argv list held in an audit argument. Anything that is not a list of
// strings is left to the ordinary walk, which cannot hide a value it cannot read.
func redactArgvValue(v any) any {
	list, ok := v.([]any)
	if !ok {
		return redact(v)
	}
	argv := make([]string, 0, len(list))
	for _, e := range list {
		s, isString := e.(string)
		if !isString {
			return redact(v)
		}
		argv = append(argv, s)
	}
	out := make([]any, 0, len(argv))
	for _, s := range redactArgv(argv) {
		out = append(out, s)
	}
	return out
}

// redactArgv returns argv with the value of every argument that carries a secret replaced by the
// marker. Two shapes carry one: "name=value", where the name is a credential (uci's
// "wireless.guest.key=..."), and a credential name followed by its value (wg's
// "private-key FILE", or a flag such as "--password VALUE"). The name stays, so the log still
// shows what was set; only the value is hidden.
func redactArgv(argv []string) []string {
	out := append([]string(nil), argv...)
	for i := 0; i < len(out); i++ {
		a := out[i]
		if name, _, hasValue := strings.Cut(a, "="); hasValue {
			last := name
			if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
				last = name[dot+1:]
			}
			if credentialName(last) {
				out[i] = name + "=" + redacted
			}
			continue
		}
		if i+1 < len(out) && credentialName(strings.TrimLeft(a, "-")) {
			out[i+1] = redacted
			i++
		}
	}
	return out
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	if secretKeyExact[lk] {
		return true
	}
	for _, s := range secretKeySubstrings {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

type Outcome string

const (
	OutcomeOK     Outcome = "OK"
	OutcomeDenied Outcome = "DENIED" // first-class: "we said no" is not the same as "it broke"
	OutcomeError  Outcome = "ERROR"
	// HELD: the call was authorised and is high-impact, so it was kept for the owner's approval
	// instead of being run (approval.go). Neither a yes nor a no yet.
	OutcomeHeld Outcome = "HELD"
)

type AuditEvent struct {
	Time     string  `json:"time"`
	Client   string  `json:"client"`
	Tool     string  `json:"tool,omitempty"`
	Scope    string  `json:"scope,omitempty"`
	Args     any     `json:"args,omitempty"`
	Outcome  Outcome `json:"outcome"`
	Summary  string  `json:"summary,omitempty"`
	Error    string  `json:"error,omitempty"`
	Duration int64   `json:"duration_ms"`
	// Folded is on a summary line: how many refusals it stands for that have no line of their own.
	Folded int `json:"folded,omitempty"`
}

// Some refusals cost the caller nothing and can be repeated as fast as a loop runs: a try inside a
// delay, a bad bearer token (any local process can send one), an mfa_unlock from a client that may
// not open its own window. A line each would wear the flash and, worse, hand the guesser a way to
// rotate the record of what it did out of the log: at 16 MB the log moves to audit.jsonl.1 and one
// generation is kept. So a run of them is folded: the first is written, the rest are counted, and
// one summary line follows when the run ends. The first line and the summary carry what an
// investigation needs, and a run's key never holds anything the caller chose, so the runs in
// memory are bounded by the clients paired.

// auditFoldPeriod is how long a run lasts when no delay ends it, so a flood costs two lines per
// period, whatever its size.
const auditFoldPeriod = 15 * time.Minute

// foldNote says which run a refusal belongs to. end is the moment on the monotonic clock the run
// ends, or zero for a run of auditFoldPeriod from its first refusal.
type foldNote struct {
	key, what string
	end       time.Duration
}

// foldable is an error that belongs to a run.
type foldable interface{ foldNote() foldNote }

// foldOf is the run a tool's error belongs to, or nil.
func foldOf(err error) *foldNote {
	var f foldable
	if errors.As(err, &f) {
		n := f.foldNote()
		return &n
	}
	return nil
}

// foldRun is a run being folded.
type foldRun struct {
	first AuditEvent // the line that was written
	what  string
	count int // refusals since it, not written
	end   time.Duration
}

type Auditor struct {
	mu    sync.Mutex
	path  string
	maxMB int

	runs map[string]*foldRun
	mono func() time.Duration
}

func NewAuditor(p string, maxMB int) *Auditor {
	epoch := time.Now()
	return &Auditor{path: p, maxMB: maxMB, runs: map[string]*foldRun{},
		mono: func() time.Duration { return time.Since(epoch) }}
}

// Record never returns an error and never blocks the request path on failure:
// auditing must not be able to break the thing it is auditing.
func (a *Auditor) Record(e AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked(a.mono())
	a.writeLocked(e)
}

// Fold records a refusal that belongs to a run: the first of a run is written, the rest are
// counted. A note with another end is another delay, so it closes the run it finds.
func (a *Auditor) Fold(n foldNote, e AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.mono()
	a.sweepLocked(now)
	if r := a.runs[n.key]; r != nil {
		if n.end == 0 || n.end == r.end {
			r.count++
			return
		}
		a.closeRunLocked(n.key, r)
	}
	end := n.end
	if end == 0 {
		end = now + auditFoldPeriod
	}
	a.runs[n.key] = &foldRun{first: e, what: n.what, end: end}
	a.writeLocked(e)
}

// Sweep closes the runs that have ended. The daemon calls it every minute, so a summary does not
// wait for the next line.
func (a *Auditor) Sweep() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked(a.mono())
}

// Flush closes every run, ended or not: the daemon is stopping, and what is counted only in its
// memory would go with it.
func (a *Auditor) Flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, key := range a.runKeysLocked() {
		a.closeRunLocked(key, a.runs[key])
	}
}

func (a *Auditor) sweepLocked(now time.Duration) {
	for _, key := range a.runKeysLocked() {
		if r := a.runs[key]; now >= r.end {
			a.closeRunLocked(key, r)
		}
	}
}

func (a *Auditor) runKeysLocked() []string {
	keys := make([]string, 0, len(a.runs))
	for key := range a.runs {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return keys
}

// closeRunLocked ends a run with its summary line, or with none when nothing was folded into it.
func (a *Auditor) closeRunLocked(key string, r *foldRun) {
	delete(a.runs, key)
	if r.count == 0 {
		return
	}
	a.writeLocked(AuditEvent{Time: nowISO(), Client: r.first.Client, Tool: r.first.Tool, Scope: r.first.Scope,
		Outcome: r.first.Outcome, Summary: fmt.Sprintf("%d more %s since %s", r.count, r.what, r.first.Time),
		Folded: r.count})
}

func (a *Auditor) writeLocked(e AuditEvent) {
	if e.Args != nil {
		e.Args = redact(e.Args)
	}
	// uci's own output can reach an error or a summary. A record that reads as a secret is hidden
	// there too, before the line is cut to length.
	e.Summary = truncate(redactUCIOutput(e.Summary), 240)
	e.Error = truncate(redactUCIOutput(e.Error), 240)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := os.MkdirAll(path.Dir(a.path), 0o700); err != nil {
		return
	}
	a.rotateLocked()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func (a *Auditor) rotateLocked() {
	st, err := os.Stat(a.path)
	if err != nil || st.Size() < int64(a.maxMB)*1024*1024 {
		return
	}
	_ = os.Rename(a.path, a.path+".1") // one generation is enough; eMMC is 64GB but logs are not the point
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }
