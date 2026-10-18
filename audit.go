package main

import (
	"encoding/json"
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
}

type Auditor struct {
	mu    sync.Mutex
	path  string
	maxMB int
}

func NewAuditor(p string, maxMB int) *Auditor { return &Auditor{path: p, maxMB: maxMB} }

// Record never returns an error and never blocks the request path on failure:
// auditing must not be able to break the thing it is auditing.
func (a *Auditor) Record(e AuditEvent) {
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
	a.mu.Lock()
	defer a.mu.Unlock()
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
