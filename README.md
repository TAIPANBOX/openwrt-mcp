# openwrt-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/GlassOnTin/openwrt-mcp)](https://github.com/GlassOnTin/openwrt-mcp/releases)
[![ko-fi](https://img.shields.io/badge/Ko--fi-support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/glassontin)

> **This is the TAIPANBOX fork of [GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp).**
> It carries the owner-unlock work on top of upstream 0.5.0: a PIN factor stored as a salted
> PBKDF2 hash, a factor chosen per policy (`totp`, `pin`, `pin+totp`), a lockout after wrong
> tries, `mfa_lock`, redaction of secrets in the audit log, two-step QR enrolment, and the
> rollback snapshot kept in the state directory rather than in /tmp, so it survives a reboot. See
> [Optional: a second factor for the dangerous tools](#optional-a-second-factor-for-the-dangerous-tools).
> Since 0.5.0.2 it also keeps the router's secrets out of every `uci_get` answer; see
> [`uci_get` never returns a secret](#uci_get-never-returns-a-secret).
> Since 0.5.0.4 an agent the owner allows can install packages, from the official OpenWrt feeds
> only; see [`apk_add` installs from the official OpenWrt feeds only](#apk_add-installs-from-the-official-openwrt-feeds-only).
> The `openwrt-mcp` package in the [hermes-openwrt](https://github.com/TAIPANBOX/hermes-openwrt)
> feed is built from a tagged commit of this fork's `main`. The apk packaging was offered
> upstream in [GlassOnTin/openwrt-mcp#1](https://github.com/GlassOnTin/openwrt-mcp/pull/1);
> the rest is not upstream yet.

An MCP server that runs **on** an OpenWrt router, so Claude Code (or any MCP client) can
inspect and change it over an SSH tunnel.

Developed against **GL.iNet** routers — verified on a Flint 2, a Flint 4 (GL-BE14000,
firmware 4.9.0, router mode) and a Slate 7 Pro (GL-BE10000, firmware 4.8.4, AP mode).
GL.iNet firmware 4.x is OpenWrt 21.02 with `opkg`, which is what the `.ipk` targets, and it
should suit any `opkg`-based OpenWrt including stock 24.10.

Stock OpenWrt 25.12 replaced opkg with apk, so it needs the `.apk` that `make apk` builds
instead. That package is installed and exercised on every CI run inside OpenWrt's own
published rootfs image, by OpenWrt's own apk: `scripts/gate-apk-parity.sh` requires it to
land the same files with the same modes as the `.ipk`, to enable the service, to leave a
hand-edited `/etc/config/openwrt-mcp` alone across a reinstall, and to remove cleanly.
What CI cannot show is aarch64 hardware. This apk was installed and exercised on a Flint 2
and a Brume 2, both vanilla OpenWrt 25.12.5, aarch64, on 2026-09-27: paired a client,
granted scoped policies, and removed cleanly afterward.

Two differences from the `.ipk` worth knowing before you install one:

- `apk` refuses an unsigned local file, so installing by hand needs
  `apk add --allow-untrusted ./openwrt-mcp-0.5.0.2-r1.apk`. Signing belongs to a repository
  index rather than to a package, and OpenWrt's own package build does not sign either.
- The filename carries no architecture. For `.ipk` it did; for `.apk` the architecture is
  in the metadata, and `apk` refuses a package built for another one.

The other OpenWrt MCP servers I could find run *off*-router — they SSH in from your
workstation on every call. This one is resident: a single static Go binary under procd,
always on, with its own authorisation and audit trail.

It exposes ten generic tools rather than a hand-written catalogue of router features.
`ubus list -v` already self-describes every object, method and argument signature on the
box, so the agent discovers what your router can actually do instead of trusting a list
that goes stale with each firmware update. On a GL.iNet box that means the vendor's own
`gl-*` objects come through without a line of code per feature.

![The MCP Server page in GL.iNet's admin panel: daemon status, paired clients, standing
policies and the recent audit tail, including a refused call](docs/router-ui.png)

On GL.iNet firmware it adds a read-only page to the router's own admin panel, under
**Applications → MCP Server** — what is running, who is paired, what they may do, and what
they have been doing. Granting stays on the command line.

The refusal in that audit tail is the security model working, not a fault: `ubus_call` was
granted on `network.*`, `iwinfo.*`, `system.*` and `gl-clients.*`, so `dnsmasq.metrics` was
denied — and the denial names the uncovered scope and prints the `allow` line that would
cover it. Starting narrow costs little when widening is one command away.

---

## Use cases

### 1. Putting a new router through its paces

The one this was written for. Ask in plain language and let the agent find the objects:

> "What's on the 6GHz radio right now, and how much airtime is each client using?"

The agent calls `ubus_list` to see what's available (`iwinfo`, `network.wireless`,
`luci-rpc`, `gl-clients` …), then `ubus_call` to read them. A read-only grant covers this
and cannot change anything:

```sh
openwrt-mcp allow claude-code ubus_call,logread 'network.* iwinfo.* luci-rpc.* gl-*' 30d
```

### 2. "The wifi has been dropping out"

Correlating a symptom across sources is tedious by hand and well suited to an agent:
association lists, survey/scan data, DHCP lease churn and the system log, over the same
window. Still a read-only grant — worth having standing, since it can't break anything.

> "Cross-reference the last hour of logs against which clients disconnected, and tell me
> whether it correlates with a channel change or a DFS event."

### 3. Config changes with an undo you don't have to remember

The interesting one. `uci_apply` stages your changes, snapshots the configs it's touching,
commits, reloads — and **arms a rollback timer**. If `uci_confirm` isn't called before it
expires, the router puts everything back. Lock yourself out with a bad firewall rule and it
repairs itself while you're still typing.

```
uci_apply  {"changes": [{"config":"firewall","section":"@zone[1]","option":"input","value":"DROP"}],
            "timeout": 120}
  -> "ROLLBACK ARMED: reverts at 15:07:22Z (in 2m0s) unless you call uci_confirm {...}"

  ... you check you can still reach the router ...

uci_confirm {"token": "3Kc681oIe4IP"}
  -> "Confirmed. Rollback cancelled."
```

A change with `type` and no `option` **creates** a section, so whole objects go in under one
rollback. Pinning a DHCP lease is one call:

```
uci_apply {"changes": [
  {"config":"dhcp","section":"raspberrypi","type":"host"},
  {"config":"dhcp","section":"raspberrypi","option":"mac","value":"88:a2:9e:8a:e4:15"},
  {"config":"dhcp","section":"raspberrypi","option":"ip","value":"192.168.0.141"},
  {"config":"dhcp","section":"raspberrypi","option":"network","value":"lan"}]}
```

Changes run in order, so the creating change comes first. `delete` with no `option` removes
the whole section. Sections are **named**, not `uci add` anonymous ones: later changes in the
same batch can refer to the name, and re-running an apply is idempotent where `uci add` would
append a duplicate every time.

If the daemon is restarted mid-window the change is rolled back on startup, because nobody
ever vouched for it.

### 4. An audit trail for what the agent did

Every tool call is recorded at the wrapper, so a new tool is logged without opting in.
`DENIED` is a distinct outcome from `ERROR` — "we said no" isn't "it broke":

```
OK      uci_apply    system.@system[0].description   applied 1 change(s), rollback armed 20s
OK      uci_rollback -                               rolled back system (timeout)
DENIED  uci_apply    system.@system[0].description   denied: no policy grants uci_apply to "confirm-test"
OK      uci_confirm  -                               confirmed m2_glAwWSd5L
```

Secrets are redacted by the recorder rather than by callers, so a new tool can't leak a
password by forgetting to scrub it. `keyId` and `publicKey` deliberately survive — they're
identifiers, and redacting them would make the log useless.

---

## Install

`ROUTER` below is your router's LAN address. GL.iNet ships `192.168.8.1`; change it if you
have. Everything is `root@`, because that is the only account OpenWrt has.

### 1. Set up SSH key auth (required)

The install pipes over `ssh` non-interactively, so password auth is not enough. A factory
router has no `authorized_keys` yet:

```sh
ssh-keygen -f ~/.ssh/known_hosts -R 192.168.8.1   # only if that IP held another device before
ssh-copy-id root@192.168.8.1                      # asks for the router password, once
ssh root@192.168.8.1 true                         # must succeed with no prompt
```

Leave the router's password auth enabled — it is your way back in if the key is ever lost.

### 2. Install the daemon

Download `openwrt-mcp_*.ipk` from [Releases](https://github.com/GlassOnTin/openwrt-mcp/releases)
and push it over — no toolchain needed:

```sh
ssh root@192.168.8.1 'cat > /tmp/openwrt-mcp.ipk' < openwrt-mcp_0.5.0_aarch64_cortex-a53.ipk
ssh root@192.168.8.1 'opkg install /tmp/openwrt-mcp.ipk && rm -f /tmp/openwrt-mcp.ipk'
```

Or build it yourself — needs **Go 1.26+** on your workstation, nothing on the router:

```sh
make install-ipk ROUTER=root@192.168.8.1   # packaged; survives a firmware upgrade
make install     ROUTER=root@192.168.8.1   # straight onto the filesystem, no packaging
```

The router needs no Go, no compiler and no OpenWrt SDK: the binary is statically linked and
cross-compiled on your machine. `make` uses whatever `go` is on your PATH; override with
`make install-ipk GO=/usr/local/go/bin/go` if you keep it somewhere unusual.

### 3. Pair a client and grant it something

`pair` prints the token **once** — capture it, it is not recoverable:

```sh
TOK=$(ssh root@192.168.8.1 'openwrt-mcp pair claude-code')
ssh root@192.168.8.1 "openwrt-mcp allow claude-code ubus_list,ubus_call,logread 'network.* iwinfo.* system.*' 30d"
```

Nothing is granted by default. Start narrow: a refusal names the uncovered scope and prints
the exact `allow` line that would widen it, so it is cheap to loosen and expensive to notice
you were too loose.

### Optional: a second factor for the dangerous tools

A broad grant plus a stolen bearer token is root on your router. The token is something your
*workstation* has; a TOTP code is something *you* have, somewhere else. Enrol once and name
the tools that should need it:

```sh
ssh root@192.168.8.1 'openwrt-mcp mfa enrol claude-code'   # prints a QR-scannable otpauth:// URI
```

The router names itself in the account, so an authenticator holding secrets for several
routers can tell them apart — `claude-code@GL-BE14000` rather than a second identical
`claude-code`. It defaults to the hostname; pass a label to override:
`mfa enrol claude-code upstairs`.

```
config policy
	option client 'claude-code'
	...
	list   mfa_tools  'exec'
	list   mfa_tools  'uci_apply'
	option mfa_window '15m'
```

`list mfa_tools '*'` covers every tool the policy grants. Off unless you configure it, so
existing setups are unchanged.

One code then opens a **time-boxed window** rather than gating every call — an agent works in
bursts, and a control that demands six digits per call gets switched off, which protects
nothing. The agent calls `mfa_unlock` once, you read it a code, and it works normally until
the window lapses:

```
exec {"argv":["uptime"]}
  -> denied: exec requires a second factor for "claude-code"
     call mfa_unlock with a current 6-digit code from your authenticator; it stays unlocked for 15m0s
mfa_unlock {"code":"552575"}   -> Unlocked until 2026-08-07T07:39:48Z (15m0s).
exec {"argv":["uptime"]}       -> 08:24:51 up 12:57, load average: 2.39 …
mfa_unlock {"code":"552575"}   -> code already used
```

Codes are single-use, unlocks are per client and held in memory only, so a daemon restart
re-locks everything. Standard RFC 6238 (SHA-1, 6 digits, 30s), checked against the RFC's own
test vectors, so any authenticator app works.

> Run `mfa enrol` yourself over SSH. The secret is printed once and is *recoverable* from
> `/etc/openwrt-mcp/mfa` (mode 0600), unlike bearer tokens which are stored only as digests -
> so anything that sees your terminal or that file can generate codes. Enrolling on someone
> else's behalf, or pasting the secret into a chat, defeats the point of a second factor.

#### Enrolling with a QR, and proving the scan before it goes live

```sh
openwrt-mcp mfa enrol claude-code --qr        # also draws the QR in the terminal
openwrt-mcp mfa enrol claude-code --json      # one JSON object for a web page: client, uri, secret, qr_png_base64
openwrt-mcp mfa enrol claude-code --pending   # stored apart, NOT in force yet
openwrt-mcp mfa activate claude-code 123456   # in force only if that code is valid right now
```

A plain `mfa enrol` makes the new secret live at once, so a QR that was never scanned (or
scanned wrongly) leaves the client gated behind codes nobody can produce. With `--pending` the
secret waits in `mfa.pending` and unlocks nothing; `mfa activate` moves it into force only
after a code from the authenticator has proved it works, and refuses (keeping it pending) on a
wrong, expired or missing code. Any secret already in force keeps working until then, so it is
also the safe way to rotate. Without flags `mfa enrol` behaves exactly as it always did. The
code used to activate is recorded as spent in `mfa.used`, keyed to the new secret, so the
running daemon refuses it too.

#### Choosing the factor: a PIN, a code, or both

Each policy says what the owner must supply to unlock:

```
config policy
	option client 'claude-code'
	...
	list   mfa_tools         'exec'
	option mfa_factor        'pin+totp'   # totp (default) | pin | pin+totp
	option mfa_max_failures  '5'          # consecutive failed unlocks before a lockout
	option mfa_lockout       '15m'        # how long unlocking is refused after that
```

`totp` is the default, so an existing config behaves exactly as before. A bad value stops the
config loading with an error naming the option.

```sh
printf '%s\n' "$PIN" | openwrt-mcp pin set claude-code   # 4 to 8 digits, read from stdin
openwrt-mcp pin clear claude-code
```

The PIN is read from one line of stdin and never from an argument (which would sit in
`/proc` and in shell history). Only a salted PBKDF2-HMAC-SHA256 hash is stored, in
`/etc/openwrt-mcp/pin` (0600), and a PIN changed or cleared from the CLI takes effect on the
running daemon, closing any window opened under the old one. `mfa_unlock` then takes
`{"code": "...", "pin": "..."}` and requires exactly the factors the policy names. With
`pin+totp` the PIN is checked first, so a wrong PIN never spends the owner's TOTP code, and
no refusal says which factor was wrong.

A PIN is short, so the throttle is what protects it. After `mfa_max_failures` consecutive
failed unlocks the client is refused for `mfa_lockout`: every attempt in that time is
rejected without looking at any factor and without counting, and the refusal says when it
ends. A success resets the count. `mfa_lock` closes the calling client's window at once.

```
mfa_unlock {"pin":"0000"}   -> invalid credentials              (x5)
mfa_unlock {"pin":"4821"}   -> too many failed attempts: unlocking is locked out until 2026-10-01T22:15:00Z
mfa_lock {}                 -> Locked. The unlock window for claude-code is closed; ...
```

The PIN and the code never reach `audit.jsonl`: the `code` and `pin` arguments are redacted
at write time.

### 4. Connect over a tunnel

The daemon refuses to bind anything but loopback, so reach it through SSH:

```sh
ssh -N -f -L 8730:127.0.0.1:8730 root@192.168.8.1
claude mcp add --transport http openwrt http://127.0.0.1:8730/mcp \
  --header "Authorization: Bearer $TOK"
```

Pick a different local port if 8730 is taken on your workstation — `-L 8731:127.0.0.1:8730`,
and point the client at 8731 to match.

To keep the tunnel up across reboots and drops, run it under systemd rather than by hand:

```ini
# ~/.config/systemd/user/openwrt-mcp-tunnel.service
[Unit]
Description=SSH tunnel to openwrt-mcp
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/ssh -NT -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
    -L 8730:127.0.0.1:8730 root@192.168.8.1
Restart=always
RestartSec=10
StartLimitIntervalSec=0

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now openwrt-mcp-tunnel
```

No `autossh` needed: `Restart=always` handles respawn, and the `ServerAlive` options plus
`ExitOnForwardFailure` cover the case autossh exists for — a connection that is up but dead.

> OpenWrt's dropbear has no `sftp-server`, so plain `scp` fails with "Connection closed".
> The Makefile pipes over ssh instead; use `scp -O` if you're copying files by hand.

### Packaging notes

`mkipk.sh` builds the `.ipk` without the OpenWrt SDK — the binary is `CGO_ENABLED=0` static
Go, so there is nothing to cross-link and only the archive format is left. Two details cost
real time, both verified on opkg 1bf042dd (2021-06-13):

- **The container is a gzipped tar, not an `ar` archive.** `.ipk` exists in both forms and
  most documentation describes the `ar` one (identical to `.deb`). This opkg rejects `ar`
  with `pkg_init_from_file: Malformed package file` — both binutils' output *and* hand-written
  headers without binutils' trailing-slash name quirk.
- **`/etc/config/openwrt-mcp` is declared a conffile**, so an upgrade never clobbers live
  policies or pairings; opkg parks the new default at `…-opkg` instead.

The package also ships `/lib/upgrade/keep.d/openwrt-mcp`, which is how the binary, the init
script and the token store survive `sysupgrade`. GL.iNet's own packages use the same
mechanism.

---

## The router's own web UI

On GL.iNet firmware the package adds a page under **Applications → MCP Server**: whether the
daemon is running, which clients are paired, what each is granted, and the recent audit tail.

It is **read-only**. `pair`, `allow` and `unpair` stay command-line only, so nothing
reachable over the network can widen a grant — the same reason they are not MCP tools. The
page explains grants; it never issues them.

The data comes from `openwrt-mcp status --json` via an oui-httpd RPC module
(`openwrt-mcp.status`). Status is a CLI subcommand rather than a second HTTP endpoint on
purpose: the daemon's only listener is loopback and reachability is not treated as identity,
so another HTTP surface would mean either exposing policy and audit data to every process on
the router, or keeping a bearer token on the router for the UI to present. oui-httpd already
runs as root and can read the state directory, so a CLI read grants its caller nothing new.

On stock OpenWrt the two extra files are inert — nothing reads them — so it stays one package.

> Building a view for this UI needs no GL.iNet SDK and no bundler. The SPA fetches the file
> as text, `eval`s it, and uses the resulting value as the route component, so a plain IIFE
> returning a Vue 2 options object is enough. The shipped `module.exports=…` bundles work only
> because a direct `eval` inherits the enclosing webpack wrapper's scope. Vue is 2.6.12, so
> render functions avoid needing a template compiler at eval time. See `ui/view.js`.

---

## Security model

Adapted from [Haven](https://github.com/GlassOnTin/Haven)'s MCP backbone.

| | |
|---|---|
| **Reachability** | Loopback only, enforced in code — startup fails on a routable address. SSH key auth is the outer lock, the bearer token the inner one. |
| **No loopback auto-trust** | Any process on the router can reach `127.0.0.1`, and `ssh -R` can make remote traffic arrive there. Reachability is never treated as identity; origin is recorded for attribution only. |
| **Tokens** | 256-bit, base64url, shown once. Only the SHA-256 digest is stored (mode 0600), compared in constant time. `unpair` takes effect without a restart. |
| **Authorisation** | Standing policies in `/etc/config/openwrt-mcp`. Deny by default. A policy grants a client a tool list, scope globs, a calls/minute ceiling and an expiry — and can only ever *add* permission. |
| **Refusals are actionable** | A denial names the uncovered scope and prints the `openwrt-mcp allow …` line that would grant it. |
| **Grant management is CLI-only** | `pair`/`allow`/`unpair` are not MCP tools, so there's no tool for a policy to cover and no self-escalation path through the policy system. |
| **Rollback** | `uci_apply` reverts unless confirmed, including across a daemon restart or a reboot: the snapshot lives in `/etc/openwrt-mcp/rollback` (0700), not in RAM-backed `/tmp`. |
| **No code execution through `uci_apply`** | `uci_apply` refuses, before staging anything, any change that would make the router run a program or load configuration that can: a firewall include, dnsmasq's `dhcpscript`, uhttpd's interpreters, openvpn's scripts and the like. For every client, always, with no switch. See [below](#uci_apply-never-makes-the-router-run-code). |
| **Package installs** | `apk_add` installs packages by name from the official OpenWrt feeds on `downloads.openwrt.org` and from nowhere else: never a link, a local file, a custom feed or a mirror, and never with signature checks off. Nothing grants it by default. See [below](#apk_add-installs-from-the-official-openwrt-feeds-only). |
| **Secrets in config reads** | Every `uci_get` answer has the value of each secret option (Wi-Fi keys, passwords, private and preshared keys, RADIUS secrets) replaced by `'<redacted>'`, for every client, with no way to turn it off. What a tool answers reaches the agent's model provider. See [below](#uci_get-never-returns-a-secret). |

`ubus_list` is the one ungated tool: introspection returns method names and argument types,
never configuration data, and without it an agent can't discover what to ask for.

### Why not rpcd's ACLs or its own apply/rollback?

Both were the first choice; neither works for a resident daemon.

- **rpcd ACLs don't apply.** A root process calling ubus over the local unix socket bypasses
  them entirely — sessionless `uci get` returns data. ACLs only bind the uhttpd JSON-RPC
  path. Relying on them here would be theatre.
- **rpcd's `uci apply {"rollback":true}` needs credentials.** Every uci *write* method takes
  a `ubus_rpc_session`, and `session.login` wants a username and password. Verified on
  OpenWrt 21.02 / rpcd 2022-02-19:

  ```
  ubus call uci apply '{}'                          -> Invalid argument   (no session)
  ubus call uci apply '{"ubus_rpc_session":"0..0"}' -> No response        (null session, no write ACL)
  ```

  Storing the router's root password in a file on the router is a worse hole than the one
  the rollback closes, so `uci_apply` snapshots and restores itself.

---

## Tools

| Tool | Policy scope | |
|---|---|---|
| `ubus_list` | *(ungated)* | Objects, methods and argument signatures. The discovery tool. |
| `ubus_call` | `<object>.<method>` | The workhorse: netifd, wireless, dnsmasq, iwinfo, luci-rpc, `gl-*`. Replies over 8 KB have long arrays pruned — see Findings. |
| `uci_apply` | `<config>.<section>.<option>`, or `<config>.<section>` for a section-level change | Stage → snapshot → commit → reload, rollback armed. Sets options, and creates or deletes whole sections. All scopes must be covered by one policy. |
| `uci_confirm` | *(tool-level)* | Cancels the rollback timer. |
| `uci_get` | `<config>`, `<config>.<section>` or `<config>.<section>.<option>` | Reads configuration as `config.section.option=value` lines, narrowed by config, section or option: the read path `uci_apply` lacks, safer than an exec shell for inspecting state first. A section- or option-level read is covered by a `<config>.*` grant; a whole-config read needs `<config>`. Secret values read `'<redacted>'`, see below. |
| `exec` | `argv[0]` | Direct exec, **no shell** — no pipes, globs or redirection, and no quoting surface. |
| `logread` | *(tool-level)* | Split out from `exec` so logs can be granted without a root shell. |
| `wg_new_client` | `wireguard_server.<server section>`, or `wireguard_server` when unspecified | Issues a WireGuard client: keypair, next free tunnel address, a peer the vendor UI still lists, hot-added with `wg set` so live sessions are not dropped. Returns the config **and a UTF-8 QR** to scan. Emits a private key — see below. |
| `apk_add` | the package name, for each package named | Installs packages from the official OpenWrt feeds (OpenWrt 25.12 and later), by name only. `dry_run` lists every package that would be installed or changed and installs nothing. See below. |
| `mfa_unlock` | *(ungated)* | Supplies the owner's factors (`code`, `pin`, or both, as the policy's `mfa_factor` says) to open the second-factor window. Ungated because it is how you satisfy the factor; it grants nothing without the right ones, and repeated failures lock it for a while. |
| `mfa_lock` | *(ungated)* | Closes the calling client's unlock window at once. Ungated because it can only remove access. |

### `uci_get` never returns a secret

Whatever a tool returns goes into the agent's context, and from there to the agent's model
provider. An agent setting up a guest network has to read the Wi-Fi configuration, and that
config holds the passphrases next to the SSIDs. So `uci_get` replaces the value of every
secret option with a fixed marker, in every answer, for every client:

```
wireless.default_radio0.ssid='Home Net'
wireless.default_radio0.encryption='psk2'
wireless.default_radio0.key='<redacted>'
network.wg0.private_key='<redacted>'
network.peer1.public_key='hQ7r...='
```

- **By option name, in every config.** The list is in `uci_redact.go`, each entry with the
  config it comes from: the Wi-Fi `key`, `key1` to `key4`, `sae_password`, the EAP passwords
  and private keys, `auth_secret`, `acct_secret`, `dae_secret`, `r0kh` and `r1kh`; WireGuard
  `private_key` and `preshared_key`; the PPP, L2TP, 6in4 and VPN passwords; the SIM `pincode`;
  uhttpd's, dropbear's and OpenVPN's key files; and the families `*key`, `*password`,
  `*passwd`, `*pass`, `*pwd`, `*secret`, `*_psk`, `*token`, `*pin`. A WireGuard peer's
  `public_key` and the `*_rekey` intervals stay readable. A value that is only the path of a
  key file is hidden too: being wrong in that direction costs nothing.
- **Narrowing or widening the read does not get around it.** The redaction works on what
  `uci show` prints, so a whole config, one section and the option itself by name all come
  back the same way. It reads that output by libuci's own grammar, so a value with a quote,
  a list, or a newline in it is hidden whole, not just its first line.
- **There is no switch.** `uci_get` takes a config, a section and an option, nothing else.
- **The marker is not a value.** `uci_apply` refuses `<redacted>` as a value, so an agent
  copying one network's settings to another cannot give it a passphrase that is printed in
  this README. To set a secret, the agent asks the operator for it, and `uci_apply` taking
  that value as input is expected: the operator chose to give it.
- **A client can check for it** before granting reads of `wireless` or the whole of
  `network`: `openwrt-mcp status --json` reports
  `"capabilities": {"uci_get_redacts_credentials": true}`, and a binary without it has no
  such key. It is a named capability rather than a version comparison so that a caller tests
  for the guarantee it depends on.

What it does **not** cover:

- **Other tools.** `ubus_call` returns what the ubus method returns, and some return config
  with the keys inside it: `network.wireless status` lists every interface's settings,
  `key` included, and rpcd's `ubus call uci get` returns any option's value. None of that is
  redacted: do not grant those objects to an agent whose context should not hold the keys.
  `exec` can read `/etc/config/wireless` directly, and `wg_new_client` returns the new
  client's private key by design.
- **A secret under a name that gives no sign of it**, such as a token pasted into a ddns
  `update_url` or a password inside ppp's `pppd_options`.
- **Some harmless settings are hidden** because their names end like a secret's: for
  example `sae_ext_key`, OpenVPN's `persist_key`, GRE's `ikey`/`okey`, vpnc's `hexpasswd`.
  The rule errs that way on purpose.

`uci_apply`'s refusal to start on top of someone else's uncommitted edits lists those edits,
and that list is redacted the same way; so is the error `wg_new_client` returns when it
cannot read the WireGuard server's config.

### `uci_apply` never makes the router run code

A policy is a list of globs over `config.section.option`, and a glob cannot tell a firewall
rule from a firewall include. Both live under `firewall.*`, but an include's `path` is a
script the firewall runs as root on every reload, and `uci_apply` triggers that reload itself.
The same goes for dnsmasq's `dhcpscript`, run on every DHCP lease. So `uci_apply` checks every
change itself, before it stages anything, for every client, whatever the policy grants:

```
refused: firewall.evil makes the router run code as root; openwrt-mcp never applies that (firewall include: ...)
Nothing in this batch was applied. Ask the operator to make that change by hand if it is wanted.
```

- **One refused change refuses the batch.** Nothing is staged, committed or snapshotted, so a
  refusal never leaves half a hook in `/tmp/.uci` for the next commit to pick up.
- **What is refused.** The list is in `uci_noexec.go`, each entry naming the OpenWrt source it
  comes from:
  - creating a section of a type that runs something, or changing any option of one that
    exists: firewall and pbr `include`, net-snmp `exec`, `extend` and `pass`, LuCI's
    `command`, rpcd's `login`, collectd's exec sections. The section's type is read from
    `uci -X show`, so `@include[0]`, `@include[-1]`, a name and a `cfgXXXXXX` id are all
    caught. If the type cannot be read, the change is refused;
  - dnsmasq `dhcpscript`, `extraconftext` (raw dnsmasq config) and `confdir`; odhcpd
    `leasetrigger`; uhttpd `interpreter`, `cgi_prefix`, `lua_prefix`, `lua_handler`,
    `ucode_prefix`, `json_script`, `home` and `no_ubusauth`; ppp `connect`, `disconnect` and
    `pppd_options`; openvpn `up`, `down`, `route_up`, `ipchange`, the `client_*` and
    `*_verify` scripts, `script_security`, `config`, `plugin`, `providers`, `engine` and
    `iproute`; strongswan `updown`; keepalived `misc_path`; nebula `config_file`; openconnect
    `csd_wrapper`; acme `credentials` (evaluated as shell); the collectd exec `cmdline`,
    `PluginDir` and `Include`;
  - any option whose name ends in `script`, `cmd`, `command`, `exec`, `hook`, `handler` or
    `parm`, or in `conffile`, `confdir` (or their underscore spellings) or `config_file`:
    ddns `update_script`, adblock's and banIP's `*_fetchcmd` and `*_fetchparm`, ttyd's
    `command`, dropbear's `ForceCommand`, watchcat's `script` and the like;
  - every change to `nginx` (each option is written out as a raw nginx directive) and
    `ucitrack` (which names the commands LuCI runs);
  - an option named `PATH`, `LD_PRELOAD` or `LD_LIBRARY_PATH`: adblock, banIP and travelmate
    load every option of their config into a shell variable of the same name;
  - a line break anywhere in a change. Init scripts write uci values into config files one per
    line, so a second line in a value is a second directive (`lan` followed by a newline and
    `dhcp-script=/tmp/x.sh` as dnsmasq's `domain`);
  - a config, section, option or type name outside uci's own alphabet (letters, digits, `_`,
    `-`, and `@type[n]` for a section), because a dot or an `=` inside one would make the key
    uci acts on differ from the key that was checked.
- **What stays allowed.** Deleting a hook option, and deleting a whole include section:
  removing a hook runs nothing. (Deleting one option of an include is refused, because
  deleting `enabled` switches a disabled include back on.) A handful of names a suffix would
  catch run nothing and are exempt: keepalived's `track_script` (names of sections) and
  openvpn's `ifconfig_noexec` and `route_noexec` (they turn an exec off). sqm's `script` and
  acme's `dns` are allowed when the value is a plain file name such as `piece_of_cake.qos` or
  `dns_cf`, since that only picks an installed script; with a `/` or `..` in it they are
  refused. Every other option name in OpenWrt's own Wi-Fi, firewall, DHCP and network sources
  stays allowed; a test runs the check over all of them.
- **The refusal is audited** as `DENIED`, with the refused key and the reason.
- **A client can check for it** before granting `uci_apply`: `openwrt-mcp status --json`
  reports `"capabilities": {"uci_apply_refuses_code_exec": true}`.

What it does **not** cover:

- **Other tools.** `exec` is a root shell by design and is held back only by policy and the
  second factor: do not grant it to an agent that must not run commands. `ubus_call` reaches
  rpcd's `file.exec` and every service's own ubus methods.
- **Options that write a file, or read data from one**: dnsmasq's and odhcpd's `leasefile`,
  openvpn's `log`, dnsmasq's `addnhosts` and `serversfile`, hostapd's `eap_user_file`. These
  are data, not code, though a file written into the wrong place can become code at the next
  boot.
- **Raw directives of daemons that cannot run a program from them**, such as the Wi-Fi
  `hostapd_options` and the firewall's `extra` options.
- **Services that give a shell by design**, such as ttyd or rtty with their defaults: turning
  one on is a setting, and whoever connects still has to log in.
- **A package the list does not know**, that runs an option whose name gives no sign of it.
- **Some harmless settings are refused** because of the rules above: unetd's `connect` (a
  list of peers, refused because ppp's `connect` is a program), sqm or acme names that are not
  plain file names, and any value with a line break in it, such as multi-line `notes`. The
  operator can still make those changes by hand.

### `apk_add` installs from the official OpenWrt feeds only

An agent setting up a router sometimes needs a package: `tcpdump` to look at traffic, `iperf3`
to measure a link, a kernel module for a USB modem. The owner can let it install those, and
only those: `apk_add` takes package names and installs them from the official OpenWrt feeds,
and from nowhere else.

```
apk_add {"packages": ["tcpdump"], "dry_run": true}

Dry run: nothing was installed. From the official OpenWrt feeds only (8 feed(s)), apk add tcpdump would:
  install libpcap1 1.10.6-r1
  install tcpdump 4.99.6-r1
Packages beyond the ones named are dependencies apk pulls in.

apk's output:
(1/2) Installing libpcap1 (1.10.6-r1)
(2/2) Installing tcpdump (4.99.6-r1)
OK: 12.5 MiB in 138 packages
```

- **The owner opts in.** Like every tool, `apk_add` needs a policy that grants it, and the
  configuration the package ships grants nothing. The policy scope is the package name, so a
  grant can name the packages an agent may install (`'tcpdump iperf3 kmod-*'`) or allow any
  (`'*'`): `openwrt-mcp allow claude-code apk_add 'tcpdump iperf3' 1d`. Adding it to the
  policy's `mfa_tools` puts each install behind the owner's second factor.
- **Only the official feeds.** apk is given its repositories with `--repositories-file`, a
  file `apk_add` writes holding only the lines of `/etc/apk/repositories.d/distfeeds.list`
  (the feeds the firmware ships) that are `https` URLs of a `packages.adb` on
  `downloads.openwrt.org`. With that option apk reads neither `/etc/apk/repositories` nor any
  `repositories.d/*.list`, so `customfeeds.list` is never consulted, and a feed someone added
  to `distfeeds.list` is dropped. A package that exists only in another feed is "no such
  package" to this tool. If no official line is left, `apk_add` refuses and runs nothing.
- **No mirrors.** apk checks an index's signature against every key in `/etc/apk/keys`, and a
  router that uses a custom feed trusts that feed's key there too, so a signature does not say
  whose index it is. The host does. A router configured to use a mirror gets a refusal.
- **Signatures are always checked.** No option that loosens apk is ever passed:
  `--allow-untrusted`, `--force-*`, `--keys-dir`, `--root`, `--arch`, `--repository`. apk is
  run with `APK_CONFIG=/dev/null`, because apk loads default options from `/etc/apk/config`
  and one line there, `allow-untrusted`, would turn signature checks off for the call.
- **Never a link or a file.** A name must be a package name: letters, digits, `+`, `-`, `.`
  and `_`, beginning with a letter or a digit, up to 100 characters, 1 to 20 names a call.
  A URL, a path, an option, an `.apk` file, a version constraint such as `name=1.0` (which
  would pin that version in `/etc/apk/world` and block its upgrades) and a repository tag are
  refused before apk runs, and the refusal is audited as `DENIED`. apk also reads an argument
  as a local package file when it has a dot in it and a file of that name exists in the working
  directory, and official names have dots (`golang1.26`), so apk runs in an empty directory of
  its own and the names follow `--`.
- **A dry run first.** With `dry_run`, `apk_add` refreshes the official indexes (`apk update`)
  and runs `apk add --simulate`, which changes nothing, and lists every package that would be
  installed, and apart from those, any installed package that would be upgraded. apk does not
  print how much space an install adds unless it may ask questions, so the answer carries apk's
  total after the change instead.
- **A client can check for it** before granting `apk_add`: `openwrt-mcp status --json` reports
  `"capabilities": {"apk_add_official_feed_only": true}`.

Each of these was measured on 2026-10-09 in OpenWrt's own `openwrt/rootfs:x86-64-25.12.4`
image, with the apk-tools 3.0.5 it ships: a custom-only package is not found through the
official repositories file; with `allow-untrusted` in `/etc/apk/config`, an unsigned local file
installs unless `APK_CONFIG=/dev/null`; and a file named `golang1.26` in the working directory
is read as that package. The rules for names and for feed lines are each in `apk_add.go`, and
taking any single one out turns a named test red.

What it does **not** cover:

- **Install scripts.** An official package's install scripts run as root. That is the trust
  placed in the official, signed OpenWrt feeds, and it is the whole of what `apk_add` trusts.
- **Dependencies and upgrades.** `apk add` pulls in what a package depends on, and if a new
  package needs a newer version of an installed library, apk upgrades it. Only the names the
  agent asked for are checked against the policy scope; the dry run shows the rest.
- **Removing or upgrading packages on purpose.** There is no `apk del` or `apk upgrade` tool.
- **opkg.** Routers before OpenWrt 25.12 use opkg, and there `apk_add` fails because there is
  no apk.
- **Mirrors and other official hosts.** A router that fetches from a mirror, or from
  `archive.openwrt.org`, cannot use `apk_add`.
- **Other tools.** `exec` is a root shell by design: an agent granted `exec` on `apk` can run
  apk with any option it likes. Do not grant `exec` to an agent that must not install anything.

### `wg_new_client`

Adding a VPN client by hand is three fiddly steps — generate a keypair, find a free address,
write a peer section the vendor UI still recognises — and then you have to get the config onto
a phone. Transcription is what actually goes wrong, so the tool returns a scannable QR next to
the text:

```
Created client "laptop" as peer_1048 at 10.1.0.4/24.

[Interface]
PrivateKey = ...
Address = 10.1.0.4/24
DNS = 10.1.0.1
MTU = 1420

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0
Endpoint = eq64078.glddns.com:51820
PersistentKeepalive = 25

Scan with the WireGuard app:

    █▀▀▀▀▀█ ▄▀ ▀▄█ █▀▀▀▀▀█
    █ ███ █ ▀█▄▀▄▀ █ ███ █
    █ ▀▀▀ █ █▄▀ ▄█ █ ▀▀▀ █
    ▀▀▀▀▀▀▀ █ ▀ █▄ ▀▀▀▀▀▀▀
    ...
```

Three things it does deliberately:

- **Hot-adds with `wg set`** rather than restarting the interface. A restart drops every
  established session, which is a poor trade for adding one client. If the running interface
  cannot be identified the peer is still committed, and the output says so rather than
  implying nothing happened.
- **Prefers the router's dynamic-DNS name** over its WAN address for `Endpoint`. A dynamic
  address baked into a client config stops working at the next reconnect.
- **Refuses to reuse an address.** A full subnet is an error, never a silently recycled
  address — two devices sharing one tunnel address breaks whichever connects second.

**It returns a new private key in its output.** The key is not written to the audit log
(`audit.jsonl` records arguments and a summary, never tool output), but it does land in the
context of whatever called it. Show it to the operator and let them scan it; don't save it.
Issue one client per device — WireGuard pins a key to a single endpoint, so sharing one config
across two devices makes both connections flap. Gating this tool behind `mfa_tools` is
sensible:

```
config policy
	option client 'claude-code'
	list tools 'wg_new_client'
	list scopes 'wireguard_server.*'
	list mfa_tools 'wg_new_client'
```

---

## Status

Written against a GL.iNet **Flint 2**, now also verified on a **Flint 4** (GL-BE14000,
MT7988A, 2GB/64GB). The Flint 4 turned out to run the *same* base — OpenWrt 21.02-SNAPSHOT,
kernel 5.4.281, `aarch64_cortex-a53`, GL firmware 4.9.0 — so uci, ubus, procd and dropbear
behave identically and only the vendor `gl-*` layer differs.

**Verified on the Flint 4:** a real static DHCP lease pinned end to end — one `uci_apply`
deleting an anonymous `@host[2]`, creating a named `host` section and setting four options,
verified against dnsmasq's generated `dhcp-host=` line and a DNS lookup before confirming;
bearer auth (401 missing, 401 wrong, 200 valid, all three in the
audit log); the scope gate refusing an out-of-scope object *and* printing the `allow` line
that would grant it; `uci_apply` rollback-on-timeout restoring `/etc/config/system`
byte-identically against an independent `sha256sum` baseline; `uci_confirm` cancelling the
timer (value survived 25s past a 15s deadline, snapshot cleaned up); `exec` running a granted
`argv[0]`, refusing an ungranted one, and passing `|` through as a literal argument rather
than a pipe; `.ipk` install, conffile preservation and service enable via postinst; and the
whole path over a real `ssh -L` tunnel.

**Verified previously on the Flint 2 and not re-run here:** revocation taking effect without
a restart, per-client policy isolation.

`go test -list . ./...` lists 264 tests (plus a benchmark and four fuzz targets) and `go test ./...`
passes. The `uci_get` redaction was mutation-checked on 2026-10-08: 22 deliberate breaks of
the redaction and its wiring (a dropped name such as `key1` or `r0kh`, a parser that splits
on every newline, a missing call), each made a named test fail. `apk_add` was mutation-checked
on 2026-10-09: 13 deliberate breaks (apk run outside an empty directory, `/etc/apk/config` left
on, no `--` before the names, `distfeeds.list` unfiltered, the `.apk` or version rule dropped,
names not checked, `dry_run` not simulating, the tool exempt from policy, the capability gone,
the host check loosened to any `*openwrt.org`, a refusal audited as an error, the no-feed
refusal skipped), each made a named test fail. Historical, from when the
suite had 29 tests and not re-run against the current code: they were mutation-checked, and
neutering `Authorise` failed 5, neutering `redact` failed 2, neutering the response pruner failed 2, and removing the pruner *call* from
`ubus_call` failed 1 — that last test exists because an earlier version of the pruner had
working unit tests while nothing asserted the tool actually used it.

**Not verified:** that `keep.d` survives a real `sysupgrade` — the file is installed and
correct, but no firmware flash was performed. Concurrency beyond one apply at a time
(a second `uci_apply` is refused while one is pending).

### Findings from the Flint 4 `gl-*` surface

- **`gl-clients list` is enormous.** With 49 clients attached it returned 100,587 bytes —
  60 samples of `last_rx` and 60 of `last_tx` per client. `ubus_call` now caps arrays at 16
  elements in the decoded reply, which brought that call to 43,676 bytes and left it valid
  JSON. Still not small; the remaining bulk is one legitimate row per client.
- **Pruning applies only to replies over 8 KB, and only when it actually shrinks them.**
  Both conditions were added after the first version got it wrong: `ubus call iwinfo devices`
  returns 17 radio interface names in 196 bytes, and capping that at 16 dropped a real
  interface while growing the reply to 202 bytes. Not every array is a time series.
- **Do not grant `gl_screen.*`.** The Flint 4 has a 320x240 LCD and `gl_screen` accepts
  `set`, but `ubus -v list` declares no argument schema and the validation all lives in the
  oui-httpd Lua layer (`check_passcode`, `brightness_min/max`), which `ubus_call` bypasses.
  Called directly, `{"method":"config_update","params":{"config":{"BRIGHTNESS":"40"}}}`
  returns success and writes `BRIGHTNESS '"40"'` — the JSON quotes retained, the type
  corrupted — into both `/tmp/gl_screen/active_config` and UCI, while `gl_screen -l` never
  reflects the change. Other argument shapes are silently ignored. A useful screen tool
  would have to reimplement the Lua layer's validation; the generic path is not safe here.
- **`/tmp/gl_screen/active_config` holds the screen passcode in plaintext** (`PASSCODE
  "1402"`). Any `exec` grant broad enough to read it exposes the device unlock code. The
  auditor's `redact` covers the audit log, and `uci_get`'s redaction covers `uci_get`; nothing
  redacts what `exec` returns.
- `sms_manager` exists but exposes exactly one ubus method, `set_sms_log_level`. There is no
  send or read surface, and with no modem fitted (`cellular.modem status` → `{"modems": []}`)
  nothing to wrap.

**Known limitations**

- There is **no permanent denylist**. `sysupgrade`, `firstboot` and `mtd` are reachable if a
  policy grants them. That was a deliberate choice; keep recovery access to hand.
- A broadly scoped `exec` grant is a root shell, and from a root shell `openwrt-mcp allow`
  grants anything else. Scoped grants (`exec` limited to named binaries) keep the policy
  engine meaningful; an unscoped one reduces it to an audit trail.
- Unlock windows, failure counts and lockouts live in the daemon's memory only, so a restart
  re-locks everything but also forgives a lockout. For the same reason `openwrt-mcp status
  --json` (a separate process) reports each client's `mfa` object with `live_state: false`: the
  factor, `totp_enrolled`, `totp_pending` and `pin_set` are read from files and are accurate,
  but `unlocked_until`, `locked_out_until` and `failures` are only filled in by a process that
  holds the daemon's own state. There is deliberately no channel from `status` into the daemon.
- The lockout is per client and can be triggered by anyone holding that client's bearer
  token: five wrong guesses deny the owner an unlock for `mfa_lockout`. It grants the guesser
  nothing, and the owner can lift it at once by setting a new PIN or re-enrolling, which
  closes the old window and clears the throttle on a running daemon.
- Rate-limit windows are process-scoped, so a restart resets them — erring toward allowing
  what you already granted.
- Tool output is capped at 64 KB, and ubus replies over 8 KB have arrays capped at 16
  elements. Both cuts say so in the result, but a caller that needs a full time series has
  to reach for a narrower ubus method.
- `uci_get` redacts secret option values; `ubus_call` and `exec` do not, and some ubus
  methods (`network.wireless status`) return the Wi-Fi keys. See
  [`uci_get` never returns a secret](#uci_get-never-returns-a-secret).
- Install with `make install-ipk`, not `make install`, if you want the daemon to survive a
  firmware upgrade — only the packaged form ships the `keep.d` entry.

---

## Licence

Copyright (c) 2026 Ian Williams. **MIT** — see [LICENSE](LICENSE).

MIT rather than a copyleft licence so that anyone, vendors included, can ship this in a
firmware image without the licence being the reason not to. `GET /health` still returns the
version and a link back here; that began as AGPL §13 compliance and stays because a service
that says what it is and where it came from is useful regardless.

If it saved you an afternoon, [Ko-fi](https://ko-fi.com/glassontin) is appreciated and never
expected.
