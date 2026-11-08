# The split of privileges

The daemon runs as two processes. The **listener** meets the network: it parses HTTP and MCP's
JSON-RPC and holds no root. The **helper** holds root: it makes every decision and takes every
action, and it does not listen on the network. This is the second step of the estate's gap G3.14.
`@decided 2026-11-08`: straight after the light cage of the first step, a split of privileges in
which the part that listens and parses input holds no root and has only the ubus methods its tools
need, and a narrow root helper runs a typed set of actions and checks the owner's approval itself
wherever one is needed, never taking a flag on trust.

- [Why](#why)
- [The boundary](#the-boundary)
- [Where the decisions sit, and why not in the listener](#where-the-decisions-sit-and-why-not-in-the-listener)
- [The protocol](#the-protocol)
- [The actions, and what the helper checks itself](#the-actions-and-what-the-helper-checks-itself)
- [The state in /etc/openwrt-mcp](#the-state-in-etcopenwrt-mcp)
- [ubus](#ubus)
- [exec](#exec)
- [Held changes, the rollback and a pending apply](#held-changes-the-rollback-and-a-pending-apply)
- [What this holds, and what it does not](#what-this-holds-and-what-it-does-not)
- [How it is checked](#how-it-is-checked)

## Why

The first step took from the daemon what its jobs never use: nine capabilities, `no_new_privs`, its
own seccomp filter. It did not contain a broken daemon. The daemon was root with the whole of ubus
(`ubus call service set` starts any command outside it) and with write access to `/etc`, and it was
the same process that parsed every byte an agent sent. A bug in the HTTP stack, in the MCP library or
in a tool's input handling was root on the router.

## The boundary

| | The listener: `openwrt-mcp serve` | The helper: `openwrt-mcp helper` |
|---|---|---|
| Account | `openwrt-mcp`, its own, made by the init script; no password, no shell | root |
| Capabilities | none: all five lists of `/etc/capabilities/openwrt-mcp-serve.json` are empty | the nine of `/etc/capabilities/openwrt-mcp.json`, as in the first step |
| `no_new_privs` | yes | yes |
| Seccomp | the daemon's list, and `execve` and `execveat`: it starts no program | the daemon's list |
| Network | listens on `127.0.0.1:8730` and refuses any other address; serves the pipe the router's own bot reaches Telegram through, and dials `api.telegram.org:443` for it | none: no IP socket at all; its bot's TLS runs over the listener's pipe |
| ubus | no ACL: every call is refused | root |
| Files of the daemon | none; even its listen address comes from the helper | all of `/etc/openwrt-mcp` and the configs |
| Parses | HTTP, the Origin header, the bearer header, MCP's JSON-RPC and sessions, each tool's JSON schema | one frame per connection, of one strict JSON shape, from one peer |
| Does | forwards each bearer token and each typed call to the helper | resolves the token, runs the gate, runs the tool, writes the audit log |

procd starts both, from one init script, each through a bare jail line: `ujail -U openwrt-mcp -G
openwrt-mcp -C <empty file> -c` for the listener, `ujail -C <the nine> -c` for the helper. Neither
gets a mount or a namespace. Each refuses to run unless `/proc/self/status` shows what it expects: the
helper the nine capabilities, `NoNewPrivs 1` and its filter; the listener not root, no effective,
permitted or ambient capability, and, as its account, an empty bounding set and `NoNewPrivs 1`.
`openwrt-mcp serve` run as root refuses to start.

## Where the decisions sit, and why not in the listener

The first sketch of the split put the policy, the classification of a change, the held changes, the
second factor and the throttle in the listener, with the helper checking the owner's approval for
what it runs. They are all in the helper, and the listener decides nothing. Each of them is an
authorisation decision, and a decision the listener makes reaches the helper as a flag it would have
to believe:

- **The policy and the classification.** If the listener decided that a call is granted, or that a
  `uci_apply` is not high-impact, a broken listener would say so for anything. The helper would have
  to read the policy and classify again, and then the listener's answer is worth nothing.
- **The second factor.** A TOTP code is checked with its secret, and anything that can read the
  secret can make codes. A PIN is checked against a PBKDF2 hash, and anything that can read the hash
  can try every four to eight digit PIN offline. Both files stay root-only, so the helper checks the
  factors.
- **The throttle.** Whoever checks a factor must count the tries, or a broken listener tries without
  limit. So the count, the delays and the unlock windows live where the factors are checked.
- **The held changes.** An approval runs a held change as root. The record, its hash and the check of
  the owner's factors are all the helper's, so an approval is one the helper saw, not one the listener
  reports.

So the listener is thin and the helper is narrow at its edge rather than in its size: it takes four
kinds of request from one peer, and holds the whole gate and every tool. The behaviour an agent and
the owner see is the same as before the split.

## The protocol

The helper serves one Unix socket, `/var/run/openwrt-mcp/helper.sock`. The directory is
`root:openwrt-mcp 0750` and the socket `root:openwrt-mcp 0660`, so no other account can reach it, and
for every connection the helper reads the peer's uid from the kernel (`SO_PEERCRED`) and serves only
the listener's. Root itself is refused: nothing but the listener talks to the helper.

A request is one frame, a four-byte big-endian length and one JSON object, and the answer is one frame
back; then the connection closes. The decoder refuses, before anything is looked up: an unknown
field, a value of another type, anything after the object, another protocol version, a field over its
bound, a field the operation does not take, and an operation or a tool not on the list.

| Operation | Takes | Answers |
|---|---|---|
| `auth` | a bearer token, the remote address for the audit line | the client, or that the token is no client's (and writes the folded audit line of a bad one) |
| `call` | a bearer token, a tool of the list, that tool's input | the text of the answer and whether it is an error |
| `config` | nothing | the listen address |
| `health` | nothing | whether the last throttle write reached the disk |

| Bound | Value |
|---|---|
| A request frame | 1 MiB |
| An answer frame | 4 MiB (an answer is cut at 64 KiB before that) |
| A bearer token | 512 bytes (a real one is 43); the listener sends no longer one |
| The remote address | 128 bytes |
| A tool's name | 64 bytes |
| Time to send a request | 10 seconds, then the connection is cut |
| A call | 6 minutes (exec stops at 300 seconds) |
| Requests at once | 32, then the answer is "busy" |

**An answer that does not arrive is never told as nothing run.** An error's text is cut at 64 KiB
like an answer's. An answer that still cannot be sent whole is replaced by a short one saying the call
ran and its answer was too large. If the connection breaks after the listener sent a call whole, the
call may have run: the listener tells the agent the result is unknown and to check the router before
it calls again, and the helper writes in the audit log that the answer did not reach the listener,
beside the call's own line. Only a call the helper never took whole, because it was not there or
refused it, is reported as having run nothing.

No request names a client, a policy, a window or an approval. The helper finds each of them itself
from the bearer token and its own state, on every call, so a token revoked with `openwrt-mcp unpair`
stops at its next call, and a call with no token is refused and audited as a bad token.

## The actions, and what the helper checks itself

The actions are the tools, and only the tools: there is no operation that runs a string, writes a
file or calls ubus by name. For every call the helper first resolves the bearer token to a client and
decodes the input strictly into that tool's own type; a field the type lacks is refused and audited.
Then:

| Tool | What the helper checks before it acts |
|---|---|
| `ubus_list` | nothing more: introspection, no configuration data |
| `ubus_call` | a policy grants the object and method pair; for a client with an approval section, what only a person may do is refused and a high-impact call is held; the second factor where the policy asks for it |
| `uci_apply` | a policy grants every key; the human-only configs; the state the batch would leave, classified, so a high-impact change is held; the second factor; no change that makes the router run code; no other apply pending; no one else's uncommitted edits |
| `uci_confirm` | a policy grants it, and the second factor, unless the pending apply is one the owner approved for this client, which the helper knows from its own record |
| `uci_get` | a policy grants the read; every secret value is redacted |
| `exec` | a policy grants `argv[0]` with an argument form that matches; refused outright for a client with an approval section; the second factor where the policy asks for it |
| `wg_new_client` | a policy grants the server; refused for a client with an approval section; the second factor |
| `apk_add` | a policy grants every package name; names only; the official feeds only, signatures on |
| `mfa_unlock` | whose window it may open; the factors, against files only the helper reads, with the count written before they are looked at |
| `mfa_lock` | nothing for the caller's own window; the approver relation to close another client's |
| `action_status`, `action_withdraw` | only the caller's own held changes |
| `action_list`, `action_reject` | the approver relation, from the configuration |
| `action_approve` | the approver relation; the change still held; the whole hash; the configs unchanged; no apply pending; a policy still granting it; approval set up; then the owner's PIN and code against the same throttle, and the code's step spent |
| `logread` | a policy grants it |

Where the owner's approval is required, the helper checks it itself: the held record is the helper's,
the card the owner approves is the helper's, and the PIN and code are checked against the helper's
files. Nothing the listener sends counts as an approval.

## The state in /etc/openwrt-mcp

| File | Holds | Read and written by |
|---|---|---|
| `tokens` | SHA-256 digests of the bearer tokens | the helper; `pair` and `unpair` on the router |
| `mfa`, `mfa.pending`, `mfa.used` | TOTP secrets, pending enrolments, spent steps | the helper; `mfa enrol`, `mfa activate` |
| `pin` | salted PBKDF2 hashes of the PINs | the helper; `pin set`, `pin clear` |
| `throttle` | per client, the failure count and the last accepted step | the helper; `mfa reset` |
| `pending.json`, `rollback/` | an apply waiting for confirmation, and its snapshot | the helper |
| `audit.jsonl` | the audit log | the helper; `status` reads it |

The directory is root's, `0700`, and the listener can read none of it. The configs the classifier
reads, `network` and `wireless` among them at mode `0600`, are read by the helper, which classifies;
the listener is handed no snapshot of them, because it decides nothing that needs one. The CLI runs
as root over SSH, as before, and the helper picks its changes up from the files.

## ubus

The listener's tools run in the helper, so the ubus methods the listener needs are none, and it has
no ACL. No file in `/usr/share/acl.d` names its account. Measured on OpenWrt 25.12.5 as the account,
with no ACL: `ubus list` lists the objects' names, and every call answers "Not found", among them
`system board`, `service set`, `service list`, `file exec` and `uci set`. The account is its own and
not `nobody`, because luci-base's ACL grants `nobody` `system board` and `system info`.

`ubus_call` runs in the helper as root, so what an agent can reach through it is what its policy
grants, as before, and the owner's rules for a client with an approval section still refuse `file.*`,
`service.*`, `uci.*`, `rpc-sys.*`, `system.sysupgrade` and `system.signal`.

## exec

`exec` is a root shell by design, under the owner's grant and second factor, and it stays one: it
runs in the helper, as root, with the helper's nine capabilities, and the programs it starts see the
router as before. The helper checks the grant, the argument forms and the second factor itself. For
a client with an approval section `exec` is refused whatever its grants say.

## Held changes, the rollback and a pending apply

They live in the helper, where they lived in the daemon, so they behave as before. A held change
waits in the helper's memory; a restart of the helper drops it and closes every unlock window, as a
restart of the daemon did. A pending apply's snapshot is on the flash, and a helper that starts rolls
back an apply nobody confirmed. A restart of the listener drops only its MCP sessions: the agent
connects again and finds its held changes, its window and its pending apply where they were.

## What this holds, and what it does not

A broken listener is the account `openwrt-mcp` with no capability, under a filter that kills
`execve`, `ptrace`, `mount`, `unshare` and the rest of the list. It cannot start a program, call a
ubus method, write `/etc/config` or anything else root owns, read `/etc/shadow`, the token digests, the
TOTP secrets, the PIN hashes or the `network` and `wireless` configs, or reach the helper with an
action that is not a tool. Through the helper it can do what a bearer token it holds is granted, and
nothing without one.

What it does not hold:

- **The listener sees what passes through it.** It terminates HTTP, so a broken listener sees every
  bearer token, PIN and code an agent or the owner sends while it is broken, and can act as those
  clients within their grants. It could also put the owner's PIN and code on another held change
  than the one the owner looked at, because a TOTP code is not bound to the card. It cannot approve
  anything without the owner giving a code at that moment. Once the router's own bot is bound, the
  owner's card, tap and factor do not pass the listener at all: the helper sends and reads them over
  TLS that ends in it, the listener carries only bytes it has no key for, and no MCP client approves
  any more ([approval-path.md](approval-path.md), invariant 13). On a router with no bot bound, this
  stands as written.
- **The helper is trusted, and it is large.** It holds the whole gate and every tool, as the daemon
  did. A bug in the gate, in a tool, or in the helper's decoder is still root.
- **`exec` is a root shell under the owner's grant and second factor**, and a broad grant is still a
  root shell, as [security.md](security.md#how-it-behaves-at-its-edges) says.
- **The helper keeps the nine capabilities and no jail**, as in the first step: it commits
  `/etc/config`, starts `uci`, `ubus` and `apk`, and runs `exec`.
- **The listener can still use the network.** It can open outbound connections and read the files any
  account can read. It can write audit lines through the helper as the clients whose tokens it holds,
  as those clients can.

## How it is checked

- `split_test.go`, `split_linux_test.go`: the helper serves the listener's uid only, takes its four
  operations and the tools of the list, decodes strictly within bounds, resolves the token itself on
  every call; the listener runs every tool through the helper, refuses root and any capability, and
  under its filter starts no program. A sweep of 200 seeds of mutated frames, and a fuzz target
  (`FuzzHelperRequest`), through the decoder and a running helper.
- `scripts/gate-split.sh` and its teeth: the init script, the empty capability file, the account, the
  helper's lack of a listener, the socket's modes and uid check, and the packaging.
- `scripts/mutate-split.py`: 29 ways of breaking the split, among them an answer lost after a call was
  sent being told as nothing run, each caught by the test named for it.
- `features/privilege-split.feature`: the scenarios, each bound to a test.
- The owner's approval past the listener, through the router's own bot, has its own invariant (13),
  gate, mutants, features and vlab test: [approval-path.md](approval-path.md) has the design.
- `scripts/e2e-vlab.sh`, `TestJailVlab`: the whole tool set through the listener on a virtual OpenWrt
  router, both parts as procd starts them, what the kernel shows for each, and what the listener
  cannot do there.
