package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultCmdTimeout = 30 * time.Second

// run executes argv directly -- never through a shell -- so there is no quoting or
// injection surface regardless of what the model puts in the arguments.
func run(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
	return runIn(ctx, timeout, "", nil, argv...)
}

// runIn is run() in a chosen working directory with extra environment variables (each
// "NAME=value", later ones winning over the daemon's own). apk_add needs both: apk reads an
// argument with a dot in it as a local file when one of that name exists in the working
// directory, and it loads default options from $APK_CONFIG or /etc/apk/config.
func runIn(ctx context.Context, timeout time.Duration, dir string, env []string, argv ...string) (string, error) {
	if timeout <= 0 {
		timeout = defaultCmdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := stdout.String()
	if e := strings.TrimSpace(stderr.String()); e != "" {
		if out != "" {
			out += "\n"
		}
		out += e
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

// runStdin is run() with input piped in. It exists for `wg pubkey`, which reads a private
// key on stdin -- passing key material as an argv element would expose it in /proc to every
// process on the box for the lifetime of the call.
func runStdin(ctx context.Context, timeout time.Duration, stdin string, argv ...string) (string, error) {
	if timeout <= 0 {
		timeout = defaultCmdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := stdout.String()
	if e := strings.TrimSpace(stderr.String()); e != "" {
		if out != "" {
			out += "\n"
		}
		out += e
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

// maxResultBytes caps what any tool may return. A tool result lands in an agent's context
// window, so an unbounded one is a denial of service against the thing calling it. This is
// the backstop for output no structural pruning understands -- exec, logread, ubus replies
// that are one enormous object rather than long arrays.
const maxResultBytes = 64 << 10

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: resultText(s)}}}
}

// resultText is what a tool's answer becomes before it leaves the helper: never empty, and never
// longer than maxResultBytes.
func resultText(s string) string {
	if strings.TrimSpace(s) == "" {
		s = "(no output)"
	}
	return boundText(s)
}

// boundText cuts s at maxResultBytes and says so. An error's text is bounded the same way as an
// answer: a program that fails with a flood of output must still get its answer back to the agent.
func boundText(s string) string {
	if len(s) > maxResultBytes {
		// Marked loudly: a silently truncated result reads as a complete one.
		s = s[:maxResultBytes] + fmt.Sprintf(
			"\n\n[TRUNCATED: %d bytes total, %d shown. Output is cut mid-stream and may not parse. "+
				"Narrow the request -- a more specific ubus method, a logread pattern, or a filter.]",
			len(s), maxResultBytes)
	}
	return s
}

// maxArrayElems is how many elements of a long array survive pruning.
const maxArrayElems = 16

// pruner collapses long arrays in a decoded ubus reply, counting what it drops so the
// caller can tell "nothing to prune" from "pruned to nothing".
//
// The motivating case is measured, not hypothetical: on a GL-BE14000 with 49 clients
// attached, `ubus call gl-clients list` returned 100,587 bytes -- 60 samples of last_rx and
// 60 of last_tx per client, a wall of numbers that answers no question anyone asked.
// Pruning the decoded tree rather than truncating the string keeps the result parseable,
// which is the entire point.
type pruner struct {
	maxElems int
	dropped  int
}

func (p *pruner) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = p.walk(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = p.walk(e)
		}
		if len(t) > p.maxElems {
			n := len(t) - p.maxElems
			p.dropped += n
			// Full slice expression: never write the marker into the caller's backing array.
			return append(t[:p.maxElems:p.maxElems], fmt.Sprintf("...+%d more", n))
		}
		return t
	}
	return v
}

// mfaGate returns a refusal, or "" if the call may proceed. Named rather than inlined in the
// tool wrapper so a test can drive it: a second factor that is never actually consulted is
// exactly the kind of control that looks present and protects nothing.
func (s *Server) mfaGate(p *Policy, client, tool string, now time.Time) string {
	if p == nil || !p.NeedsMFA(tool) {
		return ""
	}
	if _, open := s.mfa.UnlockedUntil(client, now); open {
		return ""
	}
	var ask string
	switch p.unlockPolicy().Factor {
	case factorPIN:
		ask = "the operator's PIN"
	case factorPINTOTP:
		ask = "the operator's PIN and a current 6-digit code from their authenticator"
	default:
		ask = "a current 6-digit code from your authenticator"
	}
	return fmt.Sprintf("denied: %s requires a second factor for %q\n"+
		"  call mfa_unlock with %s; it stays unlocked for %s", tool, client, ask, p.unlockPolicy().Window)
}

// unlockPolicyFor is the policy that governs this client's unlocks: the first enabled one
// that gates anything, so a policy saying 5m is not silently stretched to the default. A
// client with none is held to the defaults, which is the historical behaviour.
func (s *Server) unlockPolicyFor(client string) unlockPolicy {
	for _, p := range s.cfg().Policies {
		if p.Client == client && p.Enabled && len(p.MFATools) > 0 {
			return p.unlockPolicy()
		}
	}
	return (&Policy{}).unlockPolicy()
}

// uciScopes derives the policy scopes for an apply. Named rather than inlined so a test can
// pin the section-level form: a scope of "dhcp.pi" (create the section) is a different
// permission from "dhcp.pi.ip" (set an option in it), and a policy must cover each on its
// own terms.
func uciScopes(in uciApplyIn) []string {
	var out []string
	for _, c := range in.Changes {
		out = append(out, uciKey(c))
	}
	return out
}

// uciGetScope is the read counterpart of uciScopes: a read is scoped with the same identity
// a write would use (see uciKey). A whole-config read addresses just "<config>", so it is
// covered by a "<config>" or "<config>*" grant but deliberately NOT by "<config>.*" --
// reading every section of a config is a broader permission than reading one named section.
func uciGetScope(in uciGetIn) []string {
	key := in.Config
	if in.Section != "" {
		key += "." + in.Section
		if in.Option != "" {
			key += "." + in.Option
		}
	}
	return []string{key}
}

// uciGet reads current configuration with `uci show`. It is the read path uci_apply lacked:
// an agent can inspect state before changing it without being handed exec (a root shell) or
// a broad ubus "uci.*" grant merely to look.
//
// Every answer is redacted (see uci_redact.go), on the error path as well, because the tool
// wrapper hands a failed command's output to the client inside the error.
func uciGet(ctx context.Context, in uciGetIn) (string, string, error) {
	if in.Config == "" {
		return "", "", fmt.Errorf("config is required")
	}
	if in.Option != "" && in.Section == "" {
		return "", "", fmt.Errorf("option requires a section")
	}
	// A selector that begins with "-" would be read by some getopt as a flag, and `uci -d`
	// changes how lists are printed, which is the shape the redaction reads.
	for _, part := range []string{in.Config, in.Section, in.Option} {
		if strings.HasPrefix(part, "-") {
			return "", "", fmt.Errorf("bad selector %q: config, section and option cannot begin with '-'", part)
		}
	}
	sel := in.Config
	if in.Section != "" {
		sel += "." + in.Section
		if in.Option != "" {
			sel += "." + in.Option
		}
	}
	out, err := run(ctx, defaultCmdTimeout, "uci", "show", sel)
	return redactUCIOutput(out), "read " + sel, err
}

// ubusCall is the ubus_call handler. It is a named function rather than a closure so a test
// can assert that the reply really is pruned on the way out -- deleting the pruneUbusJSON
// call here has to break something, or the pruner's own unit tests prove nothing about
// whether the tool uses it.
func ubusCall(ctx context.Context, in ubusCallIn) (string, string, error) {
	if in.Object == "" || in.Method == "" {
		return "", "", fmt.Errorf("object and method are required")
	}
	argv := []string{"ubus", "call", in.Object, in.Method}
	if len(in.Args) > 0 {
		b, err := json.Marshal(in.Args)
		if err != nil {
			return "", "", fmt.Errorf("args not encodable: %w", err)
		}
		argv = append(argv, string(b))
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if err == nil {
		out = pruneUbusJSON(out)
	}
	return out, in.Object + "." + in.Method, err
}

// pruneMinBytes is the size below which a reply is returned whole, however long its arrays.
//
// Not every array is a time series. `ubus call iwinfo devices` returns 17 radio interface
// names in 196 bytes: capping that at 16 discards a real interface, and the result was
// measured at 202 bytes -- longer than the original once the notice is added. Pruning has to
// earn its data loss, and on a reply small enough to read whole it never can.
const pruneMinBytes = 8 << 10

// pruneUbusJSON shortens long arrays in a ubus reply. Non-JSON output (ubus error text),
// small replies, and replies with nothing to prune are returned untouched, so the common
// case is byte-for-byte what ubus printed.
func pruneUbusJSON(out string) string {
	if len(out) < pruneMinBytes {
		return out
	}
	var v any
	if json.Unmarshal([]byte(out), &v) != nil {
		return out
	}
	p := &pruner{maxElems: maxArrayElems}
	pruned := p.walk(v)
	if p.dropped == 0 {
		return out
	}
	b, err := json.MarshalIndent(pruned, "", "\t")
	if err != nil {
		return out
	}
	// Belt and braces: re-indenting can outweigh what the pruning saved.
	if len(b) >= len(out) {
		return out
	}
	return fmt.Sprintf("%s\n\n[pruned: %d array element(s) dropped, arrays capped at %d; %d -> %d bytes. "+
		"Use a narrower ubus method if you need the full series.]",
		b, p.dropped, maxArrayElems, len(out), len(b))
}

func errResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// ---------------------------------------------------------------- tool inputs

type ubusListIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"optional ubus object path prefix, e.g. 'network' or 'gl-clients'. Omit to list every object on the bus."`
}

type ubusCallIn struct {
	Object string         `json:"object" jsonschema:"ubus object name, e.g. 'network.interface.lan' or 'iwinfo'"`
	Method string         `json:"method" jsonschema:"method to call on that object, e.g. 'status'"`
	Args   map[string]any `json:"args,omitempty" jsonschema:"JSON arguments for the method; omit for none"`
}

type UCIChange struct {
	Config  string `json:"config" jsonschema:"UCI config name, e.g. 'network'"`
	Section string `json:"section" jsonschema:"section name, e.g. 'lan', 'raspberrypi' or '@wifi-iface[0]'"`
	Option  string `json:"option,omitempty" jsonschema:"option name, e.g. 'ipaddr'. Omit when creating or deleting a whole section."`
	Type    string `json:"type,omitempty" jsonschema:"section type, e.g. 'host' or 'rule'. Set this (with no option) to CREATE the named section; put it before the changes that fill it in."`
	Value   string `json:"value,omitempty" jsonschema:"new value; ignored when delete is true"`
	Delete  bool   `json:"delete,omitempty" jsonschema:"delete the option, or the whole section when option is omitted"`
}

type uciApplyIn struct {
	Changes []UCIChange `json:"changes" jsonschema:"the set of UCI options to change, applied together"`
	Timeout int         `json:"timeout,omitempty" jsonschema:"seconds before automatic rollback if uci_confirm is not called (default 90, max 600)"`
}

type uciConfirmIn struct {
	Token string `json:"token" jsonschema:"the confirm_token returned by uci_apply"`
}

type uciGetIn struct {
	Config  string `json:"config" jsonschema:"UCI config to read, e.g. 'dhcp' or 'network'"`
	Section string `json:"section,omitempty" jsonschema:"section to narrow to, e.g. 'lan' or '@wifi-iface[0]'. Omit to read the whole config."`
	Option  string `json:"option,omitempty" jsonschema:"option to read a single value. Omit to read the whole section."`
}

type execIn struct {
	Argv    []string `json:"argv" jsonschema:"command and arguments, executed directly without a shell. argv[0] is the policy scope."`
	Timeout int      `json:"timeout,omitempty" jsonschema:"seconds before the command is killed (default 30, max 300)"`
}

type mfaLockIn struct {
	Client string `json:"client,omitempty" jsonschema:"for the owner's client only: the client whose window to close; its held changes are rejected too. Omit to close your own window."`
}

type mfaUnlockIn struct {
	Client string `json:"client,omitempty" jsonschema:"for the owner's client only: the client whose window to open. Omit to open your own."`
	Code   string `json:"code,omitempty" jsonschema:"the current 6-digit code from the operator's authenticator app; send it when the policy asks for a code"`
	PIN    string `json:"pin,omitempty" jsonschema:"the operator's PIN; send it when the policy asks for a PIN"`
}

type logreadIn struct {
	Lines   int    `json:"lines,omitempty" jsonschema:"how many recent lines to return (default 100, max 2000)"`
	Pattern string `json:"pattern,omitempty" jsonschema:"only return lines containing this substring"`
}

// ---------------------------------------------------------------- registration
//
// The tools are a fixed list of specs (toolSpecs). Each spec has two halves, one per process of the
// split (docs/privilege-split.md):
//
//   - call, in the helper: decodes the input strictly into the tool's own type, runs the gate
//     (gate: the policy, the owner's rules, the second factor, the audit) and the tool;
//   - add, in the listener: registers the tool with the MCP server, whose typed handler encodes the
//     input again and forwards it, with the caller's bearer token, to the helper.
//
// Identity therefore comes from a bearer token the helper resolves itself, on every call, and can
// never be spoofed by a tool argument, a self-asserted clientInfo.name or the listener.

// forwardFunc carries one call from an MCP handler to whatever runs the gate: the helper over its
// socket, or the Server in the same process (newServerForClient, the tests). It returns the text of
// the answer and whether it is an error.
type forwardFunc func(ctx context.Context, req *mcp.CallToolRequest, tool string, input json.RawMessage) (string, bool)

type toolSpec struct {
	name string
	call func(ctx context.Context, s *Server, client string, input json.RawMessage) (string, bool)
	add  func(srv *mcp.Server, fwd forwardFunc)
}

// toolOf makes a spec from a tool's input type, its shape and its function. fn does the work and
// returns (output, summary, error); it cannot bypass the gate: authorisation happens in gate, before
// fn is ever called.
func toolOf[In any](name, desc string, shapeOf func(In) callShape,
	fn func(ctx context.Context, s *Server, client string, in In) (string, string, error),
) toolSpec {
	return toolSpec{
		name: name,
		call: func(ctx context.Context, s *Server, client string, input json.RawMessage) (string, bool) {
			var in In
			if err := strictUnmarshal(input, &in); err != nil {
				r := "denied: the input of " + name + " is not its shape: " + err.Error()
				s.audit.Record(AuditEvent{Time: nowISO(), Client: client, Tool: name, Outcome: OutcomeDenied, Error: r})
				return r, true
			}
			return s.gate(ctx, client, name, in, shapeOf(in), func(ctx context.Context) (string, string, error) {
				return fn(ctx, s, client, in)
			})
		},
		add: func(srv *mcp.Server, fwd forwardFunc) {
			mcp.AddTool(srv, &mcp.Tool{Name: name, Description: desc},
				func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
					b, err := json.Marshal(in)
					if err != nil {
						return errResult("the input cannot be encoded: " + err.Error()), nil, nil
					}
					text, isErr := fwd(ctx, req, name, b)
					if isErr {
						return errResult(text), nil, nil
					}
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
				})
		},
	}
}

// scoped is toolOf for a tool that needs no more of a shape than its scopes.
func scoped[In any](scopeOf func(In) []string) func(In) callShape {
	return func(in In) callShape { return callShape{scopes: scopeOf(in)} }
}

func noScope[In any](In) []string { return nil }

// strictUnmarshal decodes one JSON object into v and refuses a field v does not have, a value of
// another type, and anything after the object.
func strictUnmarshal(b []byte, v any) error {
	t := bytes.TrimLeft(b, " \t\r\n")
	if len(t) == 0 || t[0] != '{' {
		return fmt.Errorf("not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("data after the object")
	}
	return nil
}

// toolSpecs is the whole list of tools, in the order they are registered. It is the set of actions
// the helper takes from the listener: a tool not on it is refused before its input is read.
var toolSpecs = []toolSpec{
	toolOf("ubus_list",
		"List ubus objects and their methods with argument signatures. This is the discovery tool: "+
			"call it first to learn what this router can actually do, rather than assuming a fixed catalogue. "+
			"Always permitted (introspection only, returns no configuration data).",
		scoped(noScope[ubusListIn]),
		func(ctx context.Context, s *Server, client string, in ubusListIn) (string, string, error) {
			argv := []string{"ubus", "-v", "list"}
			if in.Filter != "" {
				argv = append(argv, in.Filter)
			}
			out, err := run(ctx, defaultCmdTimeout, argv...)
			return out, "listed ubus objects", err
		}),

	toolOf("ubus_call",
		"Call any ubus method on the router. This is the main tool -- netifd, wireless, dnsmasq, "+
			"iwinfo, luci-rpc and the vendor's gl-* objects are all reachable through it. "+
			"Policy scope is the string \"<object>.<method>\", matched as a pair: a grant covers "+
			"the object and the method it names, and a dot in the method is refused.",
		ubusCallShape,
		func(ctx context.Context, s *Server, client string, in ubusCallIn) (string, string, error) {
			return ubusCall(ctx, in)
		}),

	toolOf("uci_apply",
		"Change router configuration safely. Stages the given UCI changes, commits them, and applies "+
			"with a rollback timer armed: if uci_confirm is not called before the timeout, the router "+
			"automatically reverts everything. Use this rather than 'uci' via exec -- it is the only path "+
			"that cannot strand you with an unreachable router.\n\n"+
			"A change sets an option, or -- with 'type' and no 'option' -- creates a named section, so "+
			"whole objects can be added in one rollback-armed step. To add a static DHCP lease:\n"+
			"  {config:dhcp, section:pi, type:host}\n"+
			"  {config:dhcp, section:pi, option:mac, value:'88:a2:9e:8a:e4:15'}\n"+
			"  {config:dhcp, section:pi, option:ip,  value:'192.168.0.141'}\n"+
			"Changes run in order, so the creating change must come first. Omit 'option' with "+
			"'delete' to remove a whole section.\n\n"+
			"Policy scope is \"<config>.<section>.<option>\", or \"<config>.<section>\" for a "+
			"section-level change; all must be covered by one policy.\n\n"+
			"A change that opens the router to the internet, weakens the firewall, changes VPN routing, "+
			"DNS or the time servers, or opens a Wi-Fi without a password into a trusted network may answer "+
			"HELD <id>: it then waits for the owner's approval and nothing was applied. Do not retry it.",
		uciApplyShape,
		func(ctx context.Context, s *Server, client string, in uciApplyIn) (string, string, error) {
			return s.uciApply(ctx, in)
		}),

	toolOf("uci_confirm",
		"Confirm a pending uci_apply and cancel its rollback timer. Call this only after verifying the "+
			"router is still reachable and behaving. Doing nothing is the safe default: the change reverts.",
		func(in uciConfirmIn) callShape { return callShape{confirmToken: in.Token} },
		func(ctx context.Context, s *Server, client string, in uciConfirmIn) (string, string, error) {
			return s.uciConfirm(ctx, in.Token)
		}),

	toolOf("uci_get",
		"Read router configuration. Returns settings as config.section.option=value lines. "+
			"Give a config to dump it (e.g. dhcp), add a section to narrow, or an option for a single value. "+
			"Use this to inspect state before changing it with uci_apply -- safer than being handed an exec shell. "+
			"Secrets are never returned: the value of a Wi-Fi key, a password, a private or preshared key, a "+
			"RADIUS secret and the like reads '<redacted>', however the read is narrowed. That marker is not a "+
			"value to write back; to set a secret, ask the operator for it. "+
			"Policy scope mirrors uci_apply: '<config>', '<config>.<section>' or '<config>.<section>.<option>'. "+
			"A section- or option-level read is covered by a '<config>.*' grant; a whole-config read needs '<config>'.",
		scoped(uciGetScope),
		func(ctx context.Context, s *Server, client string, in uciGetIn) (string, string, error) {
			return uciGet(ctx, in)
		}),

	toolOf("exec",
		"Run a command on the router. argv is executed directly with no shell, so pipes, redirection and "+
			"globs do not work -- pass a single program and its arguments. Policy scope is argv[0], and "+
			"the arguments must match an argument form the policy names for that program (a program "+
			"granted with no forms runs with no arguments). Output is returned unredacted.",
		execShape,
		func(ctx context.Context, s *Server, client string, in execIn) (string, string, error) {
			out, err := run(ctx, clampSec(in.Timeout, 30, 300), in.Argv...)
			return out, strings.Join(redactArgv(in.Argv), " "), err
		}),

	toolOf("wg_new_client",
		"Issue a new WireGuard client for the router's VPN server: generates a keypair, allocates a "+
			"free tunnel address, saves a peer the vendor UI still lists, and adds it to the running "+
			"interface without restarting it, so existing sessions are not dropped. Returns the client "+
			"config together with a QR code to scan straight into the WireGuard app.\n\n"+
			"Never reuse one client config on two devices -- WireGuard pins a key to one endpoint, so "+
			"the two will fight and both connections will flap. Issue one client per device.\n\n"+
			"This returns a NEW PRIVATE KEY in its output. Treat it as a credential: show it to the "+
			"operator, do not write it to a file or paste it anywhere it will persist. Policy scope is "+
			"\"wireguard_server.<server section>\"; gating this behind mfa_tools is sensible.",
		scoped(wgScopes),
		func(ctx context.Context, s *Server, client string, in wgNewClientIn) (string, string, error) {
			return s.wgNewClient(ctx, in)
		}),

	toolOf("apk_add",
		"Install packages from the official OpenWrt feeds (OpenWrt 25.12 and later, which use apk). "+
			"Give package names only, e.g. ['tcpdump']: no version, no path, no URL and no .apk file, "+
			"which are refused. Packages come only from the official feeds the firmware ships "+
			"(downloads.openwrt.org), never from a custom feed, a mirror or a local file, and signatures "+
			"are always checked. apk pulls in dependencies and may upgrade an installed library a new "+
			"package needs, so call it with dry_run first: that shows every package that would be "+
			"installed or changed and installs nothing. An official package's install scripts run as "+
			"root. Policy scope is the package name, and every name must be covered by one policy.",
		scoped(func(in apkAddIn) []string { return in.Packages }),
		func(ctx context.Context, s *Server, client string, in apkAddIn) (string, string, error) {
			return apkAdd(ctx, in)
		}),

	toolOf("mfa_unlock",
		"Unlock the tools this client's policy marks as needing a second factor. Which factor is "+
			"the operator's policy: a 6-digit TOTP code from their authenticator (send 'code'), "+
			"their PIN (send 'pin'), or both ('pin+totp'). Send exactly what the refusal from the "+
			"gated tool asked for. One unlock opens a time-boxed window rather than gating every "+
			"call, so ask the operator once and work normally until it expires. Codes are "+
			"single-use. Repeated wrong answers lock unlocking for a while, and each further wrong "+
			"answer makes the wait longer, up to an hour: do not guess, ask the operator. A restart "+
			"does not clear the wait. Does nothing unless the operator has set up a factor with "+
			"'openwrt-mcp mfa enrol' or 'openwrt-mcp pin set'.",
		scoped(noScope[mfaUnlockIn]),
		func(ctx context.Context, s *Server, client string, in mfaUnlockIn) (string, string, error) {
			target, err := s.unlockTarget(client, in.Client)
			if err != nil {
				return "", "mfa_unlock", err
			}
			up := s.unlockPolicyFor(target)
			until, err := s.mfa.Attempt(target, unlockAttempt{Code: in.Code, PIN: in.PIN}, up, time.Now())
			summary := "mfa_unlock"
			if target != client {
				summary += " for " + target
			}
			if err != nil {
				// Returned as an error so it audits as ERROR, distinct from a policy DENIED.
				return "", summary, err
			}
			return fmt.Sprintf("Unlocked until %s (%s).", until.Format(time.RFC3339), up.Window),
				summary, nil
		}),

	toolOf("mfa_lock",
		"Close this client's unlock window at once. Call it when the privileged work is done, "+
			"so that the gated tools ask for the second factor again. It only ever removes "+
			"access, so it needs no grant.",
		scoped(noScope[mfaLockIn]),
		func(ctx context.Context, s *Server, client string, in mfaLockIn) (string, string, error) {
			if in.Client != "" && in.Client != client {
				if err := s.mcpApproverRefusal(); err != nil {
					return "", "mfa_lock", err
				}
				if !s.cfg().approves(client, in.Client) {
					return "", "mfa_lock", &refusedError{"refused: only the owner's client of " + in.Client + " closes its window"}
				}
				was := s.mfa.Lock(in.Client)
				n := s.rejectAll(in.Client)
				state := "was not open"
				if was {
					state = "is closed"
				}
				return fmt.Sprintf("Locked. The unlock window for %s %s, and %d held change(s) of it were rejected.",
					in.Client, state, n), fmt.Sprintf("mfa_lock for %s, %d held rejected", in.Client, n), nil
			}
			if s.mfa.Lock(client) {
				return "Locked. The unlock window for " + client + " is closed; gated tools need " +
					"the second factor again.", "mfa_lock", nil
			}
			return "Already locked: " + client + " was not unlocked, so there was nothing to close.",
				"mfa_lock", nil
		}),

	toolOf("action_status",
		"Read how your changes that were HELD for the owner's approval stand: held, applied, failed, "+
			"rejected, expired or withdrawn, with the outcome of one that ran. An applied uci_apply names its "+
			"uci_confirm token: check the router, then confirm it, as after any apply. Needs no grant.",
		scoped(noScope[actionStatusIn]),
		func(ctx context.Context, s *Server, client string, in actionStatusIn) (string, string, error) {
			return s.actionStatus(client)
		}),

	toolOf("action_withdraw",
		"Withdraw one of your changes that is still HELD, so it no longer waits for the owner. It only ever "+
			"removes, so it needs no grant.",
		scoped(noScope[actionIDIn]),
		func(ctx context.Context, s *Server, client string, in actionIDIn) (string, string, error) {
			return s.actionWithdraw(client, in.ID)
		}),

	toolOf("action_list",
		"For the owner's client only: the held changes of the clients it approves, each with its card and "+
			"hash, and the guess throttle of those clients (failures, limit, locked_out_until, refused, persisted). "+
			"Refused on a router whose own bot is bound: the owner approves in the router's chat there.",
		scoped(noScope[actionStatusIn]),
		func(ctx context.Context, s *Server, client string, in actionStatusIn) (string, string, error) {
			return s.actionList(client)
		}),

	toolOf("action_approve",
		"For the owner's client only: approve one held change by its id and the hash of its card, with the "+
			"owner's PIN and a current code. The change runs once, exactly as held; an approval never opens "+
			"the unlock window. Refused on a router whose own bot is bound: the owner approves in the router's chat there.",
		scoped(noScope[actionApproveIn]),
		func(ctx context.Context, s *Server, client string, in actionApproveIn) (string, string, error) {
			return s.actionApprove(ctx, client, in)
		}),

	toolOf("action_reject",
		"For the owner's client only: reject one held change. Takes no factor. Refused on a router whose own "+
			"bot is bound.",
		scoped(noScope[actionIDIn]),
		func(ctx context.Context, s *Server, client string, in actionIDIn) (string, string, error) {
			return s.actionReject(client, in.ID)
		}),

	toolOf("logread",
		"Read the router's system log. Separate from exec so a policy can grant log access without "+
			"granting a root shell.",
		scoped(noScope[logreadIn]),
		func(ctx context.Context, s *Server, client string, in logreadIn) (string, string, error) {
			n := in.Lines
			if n <= 0 {
				n = 100
			}
			if n > 2000 {
				n = 2000
			}
			out, err := run(ctx, defaultCmdTimeout, "logread", "-l", fmt.Sprint(n))
			if err == nil && in.Pattern != "" {
				var keep []string
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, in.Pattern) {
						keep = append(keep, line)
					}
				}
				out = strings.Join(keep, "\n")
			}
			return out, fmt.Sprintf("%d lines", n), err
		}),
}

// toolByName finds a spec; the helper refuses a name it does not find before reading the input.
func toolByName(name string) (toolSpec, bool) {
	for _, t := range toolSpecs {
		if t.name == name {
			return t, true
		}
	}
	return toolSpec{}, false
}

// buildMCPServer registers every tool with a new MCP server whose handlers hand each call to fwd.
func buildMCPServer(fwd forwardFunc) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "openwrt-mcp", Version: version}, nil)
	for _, t := range toolSpecs {
		t.add(srv, fwd)
	}
	return srv
}

// newServerForClient is the MCP server of one client with the gate in the same process: the tests
// drive the tools through it. Each call goes through the same encoding and strict decoding as a call
// from the listener does.
func (s *Server) newServerForClient(client string) *mcp.Server {
	return buildMCPServer(func(ctx context.Context, _ *mcp.CallToolRequest, tool string, input json.RawMessage) (string, bool) {
		return s.callJSON(ctx, client, tool, input)
	})
}

// callJSON runs one call of a known client: the tool by name, the input as JSON.
func (s *Server) callJSON(ctx context.Context, client, tool string, input json.RawMessage) (string, bool) {
	t, ok := toolByName(tool)
	if !ok {
		r := "denied: there is no tool " + strconv.Quote(truncate(tool, 64))
		s.audit.Record(AuditEvent{Time: nowISO(), Client: client, Tool: truncate(tool, 64), Outcome: OutcomeDenied, Error: r})
		return r, true
	}
	return t.call(ctx, s, client, input)
}

func clampSec(v, def, max int) time.Duration {
	if v <= 0 {
		v = def
	}
	if v > max {
		v = max
	}
	return time.Duration(v) * time.Second
}

// callShape is what the gate needs to know about one call before it may run: the scope strings
// the policy globs are matched against, the argument vector for a tool that runs one (nil for
// every other tool), and a refusal for a call that is malformed whatever the grants say.
type callShape struct {
	scopes  []string
	argv    []string
	refusal string
	// For a client with an approval section (approval.go): the input as it would be held, and how
	// the call is classified. classify is nil for a tool whose calls are never held by themselves.
	input    any
	classify func(context.Context) classification
	// uci_confirm's token, so a change the owner approved can be confirmed without an unlock.
	confirmToken string
}

// uciApplyShape scopes an apply as uciScopes does, and classifies it by the state it would leave.
func uciApplyShape(in uciApplyIn) callShape {
	held := uciApplyIn{Changes: in.Changes}
	return callShape{scopes: uciScopes(in), input: held,
		classify: func(ctx context.Context) classification { return classifyUCI(ctx, held) }}
}

// ubusCallShape refuses an object or method that is not a plain ubus name before any grant is
// read: a name that could be read as a flag, or a method with a dot, would otherwise be matched
// as a different pair than the one ubus is asked to call.
func ubusCallShape(in ubusCallIn) callShape {
	if !ubusNameOK(in.Object, false) || !ubusNameOK(in.Method, true) {
		return callShape{refusal: fmt.Sprintf(
			"denied: %q.%q is not an object and method pair: an object is letters, digits, dots, "+
				"dashes and underscores, a method the same without dots, and neither begins with a dash",
			in.Object, in.Method)}
	}
	return callShape{scopes: []string{in.Object + "." + in.Method}, input: in,
		classify: func(context.Context) classification {
			cl := classifyUbus(in)
			cl.diff = ubusBody(in)
			return cl
		}}
}

// execShape scopes exec on argv[0] and carries the whole argument vector to the policy, which
// decides the arguments with the same grant that covers the program.
func execShape(in execIn) callShape {
	if len(in.Argv) == 0 {
		return callShape{refusal: "denied: argv must not be empty"}
	}
	return callShape{scopes: []string{in.Argv[0]}, argv: in.Argv}
}

// ungated are the tools no policy grant is asked for (see addToolShaped).
var ungated = map[string]bool{"ubus_list": true, "mfa_unlock": true, "mfa_lock": true, "action_status": true,
	"action_withdraw": true, "action_list": true, "action_approve": true, "action_reject": true}

// unlockTarget is whose window an mfa_unlock from caller opens: its own, or, for the owner's
// client, the client named. A client with an approval section never opens its own: its approver
// does, so the agent cannot spend the owner's tries on guesses.
func (s *Server) unlockTarget(caller, named string) (string, error) {
	if named != "" && named != caller {
		if err := s.mcpApproverRefusal(); err != nil {
			return "", &unlockRefusal{err.(*refusedError), caller}
		}
		if !s.cfg().approves(caller, named) {
			return "", &unlockRefusal{&refusedError{"refused: only the owner's client of " + named + " opens its window"}, caller}
		}
		return named, nil
	}
	if a := s.cfg().approvalFor(caller); a != nil {
		return "", &unlockRefusal{&refusedError{"refused: " + caller + "'s window is opened by the owner's client (" + a.Approver +
			"), never by " + caller + " itself; ask the owner to unlock in the chat. Nothing was tried."}, caller}
	}
	return caller, nil
}

// unlockRefusal is an mfa_unlock turned away before any try. It counts nothing, so the agent's own
// token can repeat it for free, and its audit lines are folded like any other free refusal.
type unlockRefusal struct {
	*refusedError
	caller string
}

func (e *unlockRefusal) Unwrap() error { return e.refusedError }

func (e *unlockRefusal) foldNote() foldNote {
	return foldNote{key: "unlock-refused:" + e.caller, what: "mfa_unlock calls turned away from " + e.caller}
}

// gate runs one call of client to the tool name: the shape's refusal, the policy, the owner's rules
// (refused, held), the second factor, then fn; every outcome is written to the audit log. It returns
// the text of the answer and whether it is an error. It runs in the helper, which is the only process
// that holds the policy, the factors, the held changes and the audit log.
func (s *Server) gate(ctx context.Context, client, name string, in any, shape callShape,
	fn func(context.Context) (string, string, error),
) (string, bool) {
	started := time.Now()
	ev := AuditEvent{Time: nowISO(), Client: client, Tool: name, Scope: strings.Join(shape.scopes, " ")}
	if b, err := json.Marshal(in); err == nil {
		var m any
		if json.Unmarshal(b, &m) == nil {
			ev.Args = m
		}
	}
	var fold *foldNote
	finish := func(text string, isErr bool, outcome Outcome, summary, errMsg string) (string, bool) {
		ev.Outcome, ev.Summary, ev.Error = outcome, summary, errMsg
		ev.Duration = time.Since(started).Milliseconds()
		// The approver's client asks for the held changes every few seconds; a line on
		// flash for each answered listing would wear the flash and drown the log. What it
		// lists is held in memory and changes nothing, and a refused listing is still kept.
		if !(name == "action_list" && outcome == OutcomeOK) {
			if fold != nil {
				s.audit.Fold(*fold, ev)
			} else {
				s.audit.Record(ev)
			}
		}
		if isErr {
			return boundText(text), true
		}
		return resultText(text), false
	}

	// A malformed call is refused whatever the grants say, before they are read.
	if shape.refusal != "" {
		return finish(shape.refusal, true, OutcomeDenied, "", shape.refusal)
	}
	// ubus_list is introspection only and is never gated; everything else must be
	// covered by a standing policy. Denial is the default.
	//
	// mfa_unlock is exempt for the obvious reason: it is how you satisfy the second
	// factor, so gating it behind the second factor would be a deadlock. It is safe
	// to leave open because it grants nothing on its own -- without the right
	// factors it does nothing but record a failed attempt, and the delays ration those.
	// mfa_lock is exempt because it can only remove access, never add it.
	//
	// The action_* tools are exempt too: action_status and action_withdraw only read or
	// remove the caller's own held changes, and the other three decide who may call them
	// from the approval sections, not from grants (approval.go).
	if !ungated[name] {
		now := time.Now()
		p, reason := s.cfg().authorise(client, name, shape.scopes, shape.argv, now)
		if p == nil {
			return finish(reason, true, OutcomeDenied, "", reason)
		}
		// A client with an approval section: what only a person may do is refused, and a
		// high-impact change is held, both before the window is asked, so a window lets
		// neither through and a closed one does not stop a proposal (classify.go).
		if a := s.cfg().approvalFor(client); a != nil {
			if r := humanOnlyRefusal(name, shape.scopes); r != "" {
				return finish(r, true, OutcomeDenied, "", r)
			}
			cl := s.classifyCall(ctx, name, shape, p, a)
			switch cl.tier {
			case tierRefused:
				return finish(cl.refusal, true, OutcomeDenied, "", cl.refusal)
			case tierHeld:
				if why := s.approvalReady(a); why != "" {
					r := "refused: " + strings.Join(cl.headlines, "; ") + ". A change like this waits for the " +
						"owner's approval, and " + why + "; nothing was applied."
					return finish(r, true, OutcomeDenied, "", r)
				}
				h, refusal := s.hold(client, name, shape.input, shape.scopes, shape.argv, cl, cl.diff, a, now)
				if h == nil {
					return finish(refusal, true, OutcomeDenied, "", refusal)
				}
				return finish(heldText(h, s.ownerBotChannel()), false, OutcomeHeld,
					"held "+h.ID+" ref "+h.Hash[:8]+": "+strings.Join(h.Headlines, "; "), "")
			}
		}
		// Second factor, checked after authorisation so an unauthorised caller
		// learns nothing about which tools are MFA-gated. A change the owner approved
		// is confirmed without one: the approval was the owner's consent to it.
		if name != "uci_confirm" || !s.approvedApply(shape.confirmToken, client) {
			if r := s.mfaGate(p, client, name, now); r != "" {
				return finish(r, true, OutcomeDenied, "", r)
			}
		}
	}

	out, summary, err := fn(ctx)
	fold = foldOf(err)
	if err != nil && isRefused(err) {
		// A refusal by rule (uci_apply's code-execution check) is a DENIED, like a policy
		// refusal, not an ERROR: nothing broke, the daemon said no.
		return finish(err.Error(), true, OutcomeDenied, summary, err.Error())
	}
	if err != nil {
		msg := err.Error()
		if out != "" {
			msg += "\n" + out
		}
		return finish(msg, true, OutcomeError, summary, err.Error())
	}
	return finish(out, false, OutcomeOK, summary, "")
}
