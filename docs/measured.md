# What ran, and where

Every figure here comes from a run: on a router, in OpenWrt's own published images in CI, or in the
test suite. Newest first, each with its date, the machine and what it showed.

- [The owner's approval through the router's own bot](#the-owners-approval-through-the-routers-own-bot)
- [The split of privileges](#the-split-of-privileges)
- [The guess throttle](#the-guess-throttle)
- [The suite and its gates](#the-suite-and-its-gates)
- [In CI, on every change](#in-ci-on-every-change)
- [On routers with vanilla OpenWrt 25.12](#on-routers-with-vanilla-openwrt-2512)
- [`apk_add` in OpenWrt's own image](#apk_add-in-openwrts-own-image)
- [Mutation checks](#mutation-checks)
- [On GL.iNet firmware](#on-glinet-firmware)
- [The vendor `gl-*` objects on a Flint 4](#the-vendor-objects-on-a-flint-4)

## The owner's approval through the router's own bot

Run on 2026-11-08 on a virtual OpenWrt 25.12.5 x86_64 router (vlab on a Debian 13 host, QEMU/KVM), with
`scripts/e2e-vlab.sh`: the helper as procd started it, and in the listener's place a hostile one, run
as the account `openwrt-mcp` (uid 32768, CapEff 0, Seccomp 2) under the listener's filter, holding the
agent's and the owner's tokens and serving the pipe to Telegram with the listener's own dial, recording
every byte. Telegram was a stand-in on 127.0.0.1:443 with a certificate from a CA made for the run;
`/etc/hosts` sent `api.telegram.org` there and the router's trust store held that CA alone while the run
lasted. No real bot or token took part.

| Measured | This tree | origin/main (the red run, `--daemon`) |
|---|---|---|
| the owner's chat bound by the one-time code | in 1.6 s | (no bot) |
| the card in the owner's chat after the hold | 4 ms | (the card went through the listener) |
| the change the owner approved | applied | held |
| the listener's own change, with the owner's factor moved onto it | held, never ran | applied |
| bytes the pipe carried | 18,537 | 0 |
| of 10 secrets looked for in them (the PIN and code, the unlock, the token, a card, a Bot API request) | 0 in clear | |
| the helper's IP sockets | 0 (3 Unix sockets), NoNewPrivs 1, Seccomp 2, CapEff `30fb` | 0 |

The same run passed TestJailVlab's 22 subtests on this tree. In the test suite on the same host: the
whole package under `-race` (468 s); `mutate-ownbot.py` 44, `mutate-held.py` 169 and `mutate-split.py`
29 mutants, each caught by the test named for it; `FuzzTelegramUpdates` ran 1,392,133 inputs in two minutes with no failure; the
package's statement coverage read 89.7%, against 90.3% on origin/main, the difference being the
listener's dial to Telegram and the start of its pipe, which the vlab run above exercises and the
unit tests stand a server in for.

## The split of privileges

Run on 2026-11-08 on a virtual OpenWrt 25.12.5 x86_64 router (vlab on a Debian 13 host, QEMU/KVM),
with `scripts/e2e-vlab.sh`: the package files installed as `make install` copies them, both parts
started by procd, and every tool driven through the listener with a bearer token.

| Part | Uid | CapEff | CapBnd | CapPrm | NoNewPrivs | Seccomp | Sockets |
|---|---|---|---|---|---|---|---|
| `openwrt-mcp helper` | 0 | `30fb` | `30fb` | `30fb` | 1 | 2 | no IP socket |
| `openwrt-mcp serve` | 32768 (`openwrt-mcp`) | 0 | 0 | 0 | 1 | 2 | listens on 127.0.0.1:8730 only |

The socket's directory read `drwxr-x--- root:openwrt-mcp`, the socket `srw-rw---- root:openwrt-mcp`;
both parts are in init's mount and pid namespaces. TestJailVlab ran 22 subtests, all passing: the 15
that drive every tool (uci with its rollback and confirmation, a held change approved by the owner,
exec, a service restart, apk_add from the official feed, wg_new_client, state over a restart) and
7 on the split. As the listener's own identity, with its filter:

| Tried | Answer |
|---|---|
| start `ubus call service set` | the process ends with SIGSYS |
| create `/etc/config/mcpprobe`, append to `/etc/config/system`, to the init script, into `/etc/openwrt-mcp` | permission denied |
| read `/etc/shadow`, the token digests, the TOTP secrets, the PINs, `/etc/config/network` | permission denied |
| ask the helper for `op: exec`, for the tool `service_set`, with a `cmd` or a `client` field | refused by the protocol |
| ask the helper for `exec` with no token | `unauthorized`, and an audit line |
| as the account without the listener's `execve` rule, `ubus call` `service set`, `system board`, `file exec`, `uci set` | `Not found` for each |
| connect to the helper as another account (`nobody`), and as root | permission denied; root gets no answer |
| `openwrt-mcp serve` as root | refuses to start |
| `/health` with the helper stopped | 503 after 10 s |

The same 22 subtests against origin/main's daemon at `4d4c0ed` (one root process): the 15 that drive
the tools pass, the 7 on the split fail, each at its own assertion.

In the suite, on the same host with Go 1.27.3: `go test ./... -count=1` green, also with `-race` on
the split's tests; coverage 90.3% of statements (`frontend.go` all but one branch, `helper.go`'s
decoder 95.5%; the root-only lines of `serveIDs` and `listenHelper` run on the router, above);
`FuzzHelperRequest` 769,360 executions in 60 s, no failure; the sweep of 200 seeds, 20,000 mutated
frames, every one taken well formed; `scripts/gate-split.sh` with 22 planted faults and a comment,
each caught.

## The guess throttle

Run on 2026-11-07 on 0.5.0.8, on a Linux workstation with Go 1.27.3, every gate in
[CLAUDE.md](../CLAUDE.md#gates) but the two that need docker, which run in CI:

| Gate | Result |
|---|---|
| `go vet ./...` and `go test ./... -count=1` | 412 tests, all pass; also with `-race` |
| Coverage, `go test -cover` | 92.1% of statements, from 91.7%; `throttle.go` 99.4% |
| `scripts/gate-scenarios-bound.sh` | 122 scenarios in ten feature files, bound to tests that exist and pass; 24 of them in `second-factor-throttle.feature`, bound to 93 tests; the 10 scenarios of `apk-packaging.feature` bound to the checks of `gate-apk-parity.sh` |
| `scripts/gate-throttle.sh` and its teeth | nine rules read from the source; 12 planted faults, each red at its own check, the clean copy green, and a missing subject reading as measured nothing |
| `scripts/mutate-held.py` | 169 mutants, each caught by the test named for it: 77 of the classifier and the approval flow, 92 of the throttle and the folding of the audit log |

The real binary on loopback, with a throwaway state directory: five wrong PINs answered `invalid
credentials`, the right PIN then `locked out until` a moment 15 minutes on; 300 more tries and 1000
bad tokens left 7 lines in `audit.jsonl`; SIGTERM wrote the two summaries, `folded` 999 and 300; after
a start, the right PIN was refused with a fresh 15 minutes and `status` showed `failures` 5; `mfa
reset` cleared it, and the same daemon opened the window on the next try.

## The suite and its gates

Run on 2026-11-01 at `f45be95` (0.5.0.7), on a workstation with Go 1.27.3, every gate in
[CLAUDE.md](../CLAUDE.md#gates) green:

| Gate | Result |
|---|---|
| `go vet ./...` and `go test ./... -count=1` | 325 tests, 6 fuzz targets and 1 benchmark in `go test -list . ./...`; all pass, in 44 s |
| `scripts/gate-scenarios-bound.sh` | 98 scenarios in nine feature files, bound to 181 named tests, each of which exists and passes; the 8 scenarios of `apk-packaging.feature` bound to the checks of `gate-apk-parity.sh` |
| `scripts/gate-scenarios-bound-teeth.sh` | 14 planted faults, each caught, and the clean case green |
| `scripts/gate-wg-key-off-argv.sh` and its teeth | no `run` or `runIn` call in `wireguard.go` takes the private key; the planted fault caught |
| `scripts/mutate-held.py` | 77 mutants of the classifier and the approval flow, each caught by the test named for it |

The scenarios, by feature file:

| Feature | Scenarios | Bound tests |
|---|---|---|
| `owner-unlock.feature` | 27 | 74 |
| `approval.feature` | 19 | 39 |
| `apk-add-official-feed.feature` | 13 | 21 |
| `uci-apply-no-code-exec.feature` | 11 | 16 |
| `uci-get-redaction.feature` | 11 | 14 |
| `audit-keeps-secrets-out.feature` | 6 | 6 |
| `exec-argument-grants.feature` | 6 | 6 |
| `ubus-call-grants.feature` | 3 | 3 |
| `wireguard-key-off-argv.feature` | 2 | 2 |
| `apk-packaging.feature` | 8 | checks of `gate-apk-parity.sh` |

## In CI, on every change

[`ci.yml`](../.github/workflows/ci.yml) runs on every push and pull request to `main`; the run on
`f45be95` (2026-11-01) passed every job.

- **test**: `go vet`, `go test`, `scripts/mutate-held.py`, the WireGuard gate and its teeth, then a
  cross-build of the `.ipk` and a check that it holds the binary, the init script, the config and
  the `keep.d` entry, with `/etc/config/openwrt-mcp` declared a conffile.
- **apk**, twice: in `openwrt/rootfs:x86-64-25.12.4`, and in `openwrt/rootfs:aarch64_generic-25.12.4`
  under QEMU, OpenWrt's own published images:
  - every scenario bound to a check, and back;
  - `scripts/test-real-uci.sh`: the held-change classifier run on the router's own uci inside the
    rootfs, so the state it reads is the state libuci builds (`TestRealUCIClassification`);
  - `scripts/gate-apk-parity.sh`: OpenWrt's own apk installs the `.apk`, which must land the same
    files with the same modes as the `.ipk`, enable the service, leave a hand-edited
    `/etc/config/openwrt-mcp` alone across a reinstall, and remove cleanly;
  - the gate's teeth: a package with its `keep.d` entry dropped, one with no post-install script,
    and one built for another architecture each turn the gate red at the check named for it, and a
    rebuilt package turns it green again.

## On routers with vanilla OpenWrt 25.12

**2026-11-08, a GL.iNet Flint 2 (GL-MT6000), OpenWrt 25.12.5, 0.5.0.9 from the signed hermes-openwrt
feed** with hermes-agent 0.21.5-r23 in the owner profile, upgraded from 0.5.0.8 with `apk upgrade
hermes-agent openwrt-mcp`, no reboot:

| | `helper` | `serve` |
|---|---|---|
| Uid | 0 | 32769, the account the init made |
| CapEff, CapPrm, CapBnd | `30fb` | all 0, CapAmb 0 too |
| NoNewPrivs, Seccomp | 1, 2 on all 8 threads | 1, 2 on all 7 threads |
| Sockets | one, the Unix socket `/var/run/openwrt-mcp/helper.sock` | 127.0.0.1:8730 only |

procd showed the two instances with the capability files and `no_new_privs`; `/health` answered
`openwrt-mcp 0.5.0.9 ok` and `status` reported `listener_holds_no_root`. The post-upgrade restart put
both parts on the new binary, the configuration kept as it was. Hermes, restarted, discovered nine
tools through the listener, and a one-off scheduled job read the hostname with `uci_get`; the audit
log has that call, client `hermes-main`, OK in 2 ms. No change was made through the daemon. The
earlier packages stay on the router for a way back.

**2026-10-22, a GL.iNet Flint 2 (GL-MT6000), OpenWrt 25.12.5, openwrt-mcp 0.5.0.5** with
hermes-openwrt r16 in the owner profile, one Telegram id allowed:

- 20:09 to 20:15 BST, the owner's client driven with its token as the bot drives it: the agent's own
  `mfa_unlock` was refused without a try; the owner's opened the window; a port forward from wan in
  the open window answered `HELD`, with the firewall file and the ruleset unchanged;
  `action_approve` with the PIN and a fresh code applied it, and fw4 had
  `tcp dport 2224 dnat ip to 192.168.1.250:22`; the same approval again was refused; a second one,
  approved after a firewall section was added by hand, was refused for the changed configuration;
  reject needed no factor; `mfa_lock` closed the window. In one turn of a model asked for a port
  forward, the agent read with `uci_get`, called `uci_apply` once, got `HELD`, did not retry, and
  said it waits for the owner's approval.
- 22:52 BST, from the feed, the PIN and a phone set by the owner in LuCI: asked through Telegram
  for the same port forward, the agent got `HELD`, the card came from the bot, `/approve` and then
  the PIN and a code applied it, fw4 had the rule, and the agent, told the outcome, read the router
  back and called `uci_confirm` itself twelve seconds after that.

Each run recorded the router's state first and put it back after. The run is written up in
hermes-openwrt's [per-action-approval.md](https://github.com/TAIPANBOX/hermes-openwrt/blob/main/docs/per-action-approval.md).

**2026-10-04, from the hermes-openwrt feed:**

- On an `aarch64_cortex-a53` router with 512 MB of RAM and about 200 MB of free flash,
  `apk add openwrt-mcp` took 4 s and 4 MB of flash, and the daemon, idle, held 7.4 MB of memory.
  Hermes on a Flint 2 reached it through `ssh -N -L 8731:127.0.0.1:8730` with its own paired client,
  granted `ubus_call`, `logread` and `uci_get` on `system.*`, `network.*` and `iwinfo.*` for a day,
  and answered with that router's board, hostname and uptime; its audit log showed those three reads
  and nothing else.
- On a Brume 2 (GL-MT2500), a change made through openwrt-mcp in an unlock window and left
  unconfirmed, then a reboot: the router was back in 33 s, and openwrt-mcp rolled the change back as
  it started ("unconfirmed apply ... found at startup, rolling back").

**2026-10-02, a Brume 2, the hermes-openwrt owner profile:** a change asked for while locked was
refused, a wrong `/unlock` from Telegram was refused and the right one accepted, and a change made
in the window it opened (`uci_apply` then `uci_confirm` on the system description) went through.

**2026-09-27, a Flint 2 and a Brume 2, OpenWrt 25.12.5 on aarch64, openwrt-mcp 0.5.0:** the `.apk`
installed, listened on `127.0.0.1:8730` only, paired a client, granted scoped policies, and was
removed cleanly afterwards. On the Brume 2, Hermes on the router registered the daemon's tools, and
a `uci_apply` of the system description sent without confirmation rolled back by itself once its
30 seconds ran out. On the Flint 2, carrying the house's internet and granted read scopes only, the
board, firmware and interface calls answered, an ungranted `exec` was denied by policy, and 244
pings through it lost none. Both routers were back in their recorded state afterwards (UCI checksums
and package count). The run found that a scope on an anonymous section needs its brackets escaped:
[tools.md](tools.md#granting-a-tool).

**2026-09-08, `openwrt/rootfs:aarch64_generic-25.12.4` with apk-tools 3.0.5:** the package
`mkapk.sh` produces installed with `apk add`, registered with its metadata and dependencies intact,
landed all four files with the right modes, and the daemon ran.

## `apk_add` in OpenWrt's own image

Measured on 2026-10-09 in `openwrt/rootfs:x86-64-25.12.4`, with the apk-tools 3.0.5 it ships:

- a package that exists only in a custom feed is not found through the official repositories file;
- with `allow-untrusted` in `/etc/apk/config`, an unsigned local file installs unless
  `APK_CONFIG=/dev/null`;
- a file named `golang1.26` in the working directory is read as that package.

Each rule `apk_add` takes from these is in `apk_add.go`, and taking any single one out turns a named
test red (below).

## Mutation checks

A mutation check breaks the product code on purpose, in the way a wrong answer would be silent, and
requires a named test to go red.

- **Held changes**, `scripts/mutate-held.py`, on every CI run: 77 mutants of the classifier and the
  approval flow, from "the input is not in the hash" and "an approval opens the window" to "a device
  removed is not held", each caught by the test named beside it.
- **`apk_add`**, 2026-10-09: 13 breaks (apk run outside an empty directory, `/etc/apk/config` left
  on, no `--` before the names, `distfeeds.list` unfiltered, the `.apk` or version rule dropped,
  names unchecked, `dry_run` not simulating, the tool exempt from policy, the capability gone, the
  host check loosened to any `*openwrt.org`, a refusal audited as an error, the no-feed refusal
  skipped), each made a named test fail.
- **`uci_get` redaction**, 2026-10-08: 22 breaks of the redaction and its wiring (a dropped name
  such as `key1` or `r0kh`, a parser that splits on every newline, a missing call), each made a
  named test fail.
- **The second factor**, 0.4.0, 76 tests: nine mutations, all killed, among them gate-always-allows,
  accepts-any-code, replay-removed, window-never-expires, reload-removed and a file mode of 0644
  instead of 0600. TOTP is checked against RFC 6238's own vectors, because a hand-rolled
  implementation that is subtly wrong still agrees with itself.
- **The first check**, on the suite of 29 tests: neutering `Authorise` failed 5, neutering `redact`
  failed 2, neutering the response pruner failed 2, and removing the pruner *call* from `ubus_call`
  failed 1. That last test exists because an earlier pruner had working unit tests while nothing
  asserted the tool used it.

## On GL.iNet firmware

Upstream's releases 0.2.0 to 0.5.0 were written against a GL.iNet **Flint 2** and run on a
**Flint 4** (GL-BE14000, MT7988A, 2 GB/64 GB) and a **Slate 7 Pro** (GL-BE10000). The Flint 4 runs
the same base as the Flint 2 (OpenWrt 21.02-SNAPSHOT, kernel 5.4.281, `aarch64_cortex-a53`, GL
firmware 4.9.0), so uci, ubus, procd and dropbear behave the same and only the vendor `gl-*` layer
differs.

- **Flint 4:** a static DHCP lease pinned end to end, one `uci_apply` deleting an anonymous
  `@host[2]`, creating a named `host` section and setting four options, checked against dnsmasq's
  generated `dhcp-host=` line and a DNS lookup before confirming; bearer auth (401 missing, 401
  wrong, 200 valid, all three in the audit log); the scope gate refusing an out-of-scope object and
  printing the `allow` line that would grant it; `uci_apply`'s rollback on timeout restoring
  `/etc/config/system` byte for byte against an independent `sha256sum`; `uci_confirm` cancelling the
  timer (the value survived 25 s past a 15 s deadline, the snapshot cleaned up); `exec` running a
  granted `argv[0]`, refusing an ungranted one, and passing `|` through as a literal argument rather
  than a pipe; the `.ipk` install, its conffile kept and the service enabled by postinst; and the
  whole path over a real `ssh -L` tunnel.
- **The second factor, end to end on a router (0.4.0):** `exec` denied, a real code unlocked it for 15 minutes,
  `exec` worked, the same code was refused as replayed, and `ubus_call`, outside `mfa_tools`, was
  unaffected throughout.
- **Flint 2:** revocation taking effect without a restart, and per-client policy isolation.
- **Slate 7 Pro**, firmware 4.8.4 in AP mode (mt7987, the same `aarch64_cortex-a53`): the published
  `.ipk` installed unchanged; the auth matrix, the scope gate, response pruning, the RPC module and
  its access gate behaved as on the Flint 4, and the status page renders in both router and AP mode.

## The vendor objects on a Flint 4

- **`gl-clients list` is large.** With 49 clients attached it returned 100,587 bytes: 60 samples of
  `last_rx` and 60 of `last_tx` per client. `ubus_call` caps arrays at 16 elements in the decoded
  reply, which brought that call to 43,676 bytes of valid JSON; the remaining bulk is one row per
  client.
- **Pruning applies only to replies over 8 KB, and only when it shrinks them.**
  `ubus call iwinfo devices` returns 17 radio interface names in 196 bytes; capping that at 16
  dropped a real interface while growing the reply to 202 bytes. Not every array is a time series.
- **Keep `gl_screen.*` ungranted.** The Flint 4 has a 320x240 LCD and `gl_screen` accepts `set`, but
  `ubus -v list` declares no argument schema and the validation lives in the oui-httpd Lua layer
  (`check_passcode`, `brightness_min/max`), which `ubus_call` bypasses. Called directly,
  `{"method":"config_update","params":{"config":{"BRIGHTNESS":"40"}}}` returns success and writes
  `BRIGHTNESS '"40"'` (the JSON quotes kept, the type corrupted) into both
  `/tmp/gl_screen/active_config` and UCI, while `gl_screen -l` shows the old value. Other argument
  shapes are silently ignored.
- **`/tmp/gl_screen/active_config` holds the screen passcode in plaintext** (`PASSCODE "1402"`). Any
  `exec` grant broad enough to read it exposes the device unlock code; `exec` returns a file as it
  reads it.
- `sms_manager` exposes exactly one ubus method, `set_sms_log_level`, and with no modem fitted
  (`cellular.modem status` answers `{"modems": []}`) there is nothing to wrap.
