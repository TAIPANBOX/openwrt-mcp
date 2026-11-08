# CLAUDE.md

Working rules for this repository. The README is for people who run the daemon; this file says
which properties a change must keep, and which gate checks each one. The file did not exist
before the 2026-10-17 security wave, so the numbering starts here.

## Security invariants

1. **exec runs only the argument forms its grant names.** A program the policy grants with no
   `argv` line runs with no arguments. An argument form belongs to the policy that names it and
   never widens another policy's grant. A form for a program the policy does not grant stops the
   configuration from loading.
   (test: `TestExecProgramGrantedWithoutArgumentsRunsWithNone`,
   `TestExecArgumentListAllowsExactlyWhatItNames`,
   `TestExecArgumentPatternMatchesOneArgumentWithoutReachingUp`,
   `TestExecArgumentListBelongsToItsOwnPolicy`, `TestExecArgvNamesOnlyGrantedProgramsAndExec`)

2. **A ubus_call grant covers an object and a method pair.** Each part is matched on its own; a
   grant's object ends at its last dot. A call whose object or method is not a plain ubus name is
   refused before any grant is read, so no split of the joined scope can borrow another object's
   grant.
   (test: `TestUbusCallGrantsNameAnObjectAndAMethod`,
   `TestUbusCallRefusesWhatIsNotAPlainObjectAndMethod`,
   `TestUbusCallWildcardMethodStaysOnItsObject`)

3. **The audit log never holds the value of a secret.** A uci change's value is redacted when its
   option or its section names a credential. An exec argument is redacted when it is `name=value`
   with a credential name, or when it follows a credential name. The summary built from the
   arguments uses the same redacted list.
   A uci record quoted in an error or a summary is redacted the same way.
   (test: `TestAuditRedactsTheValueOfASecretUCIOptionInUciApply`,
   `TestAuditRedactsTheValueWhenTheSectionMarksACredential`,
   `TestAuditRedactsTheWireguardPrivateKeyValue`,
   `TestAuditRedactsSecretArgvElementsAndFlagValues`,
   `TestAuditRedactsUCIRecordsInErrors`)

4. **A WireGuard client's private key is never an argument to a command.** It reaches uci on
   standard input, as one `uci batch`. A value that cannot sit between single quotes in that batch
   is refused before uci writes anything.
   (gate: `scripts/gate-wg-key-off-argv.sh`, teeth: `scripts/gate-wg-key-off-argv-teeth.sh`;
   test: `TestWgNewClientKeepsThePrivateKeyOutOfEveryCommandLine`,
   `TestWgNewClientRefusesAValueThatCannotBeQuotedForUci`)

5. **A high-impact change of a client with an approval section is held for its approver, and runs
   only as approved.** The classifier reads the state the change would leave (classify.go), before
   the window is asked; a held record is immutable but for its status and is hashed over its id,
   client, tool, normalised input, card, fingerprint and times; an approval comes only from the
   approver, with the approval's factors, against the whole hash, on unchanged configs, with no
   apply pending, and spends the code's step without opening the window; what only a person may
   do is refused whatever the grants; the client never opens its own window.
   `@decided 2026-10-22`: the owner's design, paraphrased in approval.go's header.
   (test: `features/approval.feature`, every scenario bound; mutants: `scripts/mutate-held.py`, 77,
   each caught by the test named beside it; real uci: `scripts/test-real-uci.sh`
   `TestRealUCIClassification`, in OpenWrt's rootfs in CI's apk job)

6. **The disk holds a failure count and a TOTP step, and never a time.** The moment of the next try
   lives in memory on the monotonic clock, throttle.go reads no other clock, and a process that
   starts counts its own start as the last failure, so a client at or above the limit begins a fresh
   delay and neither a restart nor a reboot gets round one. The count is written before any factor
   is looked at and cleared on a success, atomically, with the file and the directory synced; a
   refusal inside a delay checks and writes nothing; a corrupt record reads as the limit, a missing
   file as zero; a failed write keeps working from memory and never refuses.
   `@decided 2026-11-07`: the scheme and the choice of no overall cap, in docs/security.md.
   (gate: `scripts/gate-throttle.sh`, teeth: `scripts/gate-throttle-teeth.sh`; test:
   `features/second-factor-throttle.feature`, every scenario bound; mutants: `scripts/mutate-held.py`)

7. **No MCP client can clear a count.** Only `openwrt-mcp mfa reset`, a new PIN and a new enrolment
   do, all on the router. `ResetThrottle` is called from mfa_cli.go alone, and nothing a request
   reaches touches a path that clears a count.
   (gate: `scripts/gate-throttle.sh` `check_reset_is_cli_only`; test: `TestNoMCPToolResetsTheThrottle`)

8. **A refusal that costs the caller nothing cannot rotate evidence out of the audit log.** A try
   refused inside a delay, a bad token and an `mfa_unlock` turned away are folded: the first is
   written, the rest are counted, one summary follows. A run's key holds nothing the caller chose.
   (gate: `scripts/gate-throttle.sh` `check_bad_token_is_folded`, `check_refusals_are_folded`; test:
   `TestAFloodCannotRotateTheEvidenceOut`, `TestRefusalsInADelayAreOneLineAndASummary`)

9. **The words of the delay's refusal are a contract.** hermes-openwrt's plugin reads "locked out"
   and the time after "until".
   (gate: `scripts/gate-throttle.sh` `check_refusal_words`; test: `TestRefusalWordsAreThePluginsContract`)

10. **An upgrade puts the running daemon on the new binary, and leaves the start at boot alone.** apk
    runs post-upgrade, not post-install, when it replaces a version.
    (gate: `scripts/gate-apk-parity.sh` `check_upgrade_restarts`, `check_upgrade_keeps_boot_start`;
    teeth: CI's apk job)

11. **The helper runs with no_new_privs, a named capability set and its own seccomp filter, a
    program it starts inherits all three, and it does not serve unless the kernel shows them.** The
    capability file names all five lists and holds no `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`,
    `CAP_SYS_RAWIO`, `CAP_SYS_PTRACE`, `CAP_SYS_BOOT`, `CAP_SYS_TIME` or `CAP_MKNOD`; procd gets it
    through a bare `procd_add_jail`, with no mount, no namespace and no `requirejail`; `helper`
    installs the filter (x32 numbers killed) before it reads the configuration, and refuses to serve
    unless `/proc/self/status` shows `NoNewPrivs 1`, `Seccomp 2` and `CapBnd` and `CapEff` equal to the
    file's mask; procd's own seccomp profile is never set, because it filters nothing for a static
    binary. This narrows the helper's kernel surface; what keeps a broken parser from root is
    invariant 12. `@decided 2026-11-08`: a light cage now, no jail.
    (gate: `scripts/gate-jail.sh`, teeth: `scripts/gate-jail-teeth.sh`; on a kernel of each
    architecture: `scripts/gate-seccomp-native.sh`, teeth: `scripts/gate-seccomp-native-teeth.sh`, in CI
    on amd64 and on an arm64 runner; test: `features/service-narrowing.feature`, every scenario bound;
    on a router: `scripts/e2e-vlab.sh`, `TestJailVlab`, needs a vlab)

12. **The part that listens and parses holds no root, and the helper that holds root does not listen
    and believes nothing it is told.** The listener (`openwrt-mcp serve`) runs as the account
    `openwrt-mcp` with an empty capability file in all five lists, `no_new_privs`, and a filter that
    also kills `execve` and `execveat`; it refuses to run as root or holding any capability, has no ubus
    ACL and reads no file of the daemon's state. The helper (`openwrt-mcp helper`) opens no IP socket;
    it serves one Unix socket, `root:openwrt-mcp 0660` in a `0750` directory, and only a peer whose
    `SO_PEERCRED` uid is the listener's; it takes `auth`, `call`, `config` and `health` and nothing
    else, a `call` only to a tool of `toolSpecs` with that tool's own input type, every frame decoded
    strictly and within its bounds; it resolves the bearer token itself on every call, so no request
    names a client, and the policy, the owner's rules, the second factor, the throttle, the held
    changes and the audit log are all decided and kept in the helper. `@decided 2026-11-08`: the split
    of privileges straight after the light cage; the reasons the decisions sit in the helper, and what
    the split does not hold, are in `docs/privilege-split.md`.
    (gate: `scripts/gate-split.sh`, teeth: `scripts/gate-split-teeth.sh`; test:
    `features/privilege-split.feature`, every scenario bound; mutants: `scripts/mutate-split.py`, each
    caught by the test named beside it; on a router: `scripts/e2e-vlab.sh`, `TestJailVlab`, needs a
    vlab)

Each invariant is restated as scenarios in `features/`: `exec-argument-grants.feature`,
`ubus-call-grants.feature`, `audit-keeps-secrets-out.feature`, `wireguard-key-off-argv.feature`,
`second-factor-throttle.feature`, `service-narrowing.feature` and `privilege-split.feature`.
Every scenario is bound to a named test, and `scripts/gate-scenarios-bound.sh` checks the binding
both ways and runs the tests.

Guarantees from earlier waves are not numbered here; they are stated in `docs/security.md` and
`docs/tools.md` and held by their feature files: `uci_get` never returns a secret
(`features/uci-get-redaction.feature`), `uci_apply` refuses a change that runs code
(`features/uci-apply-no-code-exec.feature`), and `apk_add` installs from the official feeds only
(`features/apk-add-official-feed.feature`).

## Gates

```sh
GOTOOLCHAIN=local go vet ./... && GOTOOLCHAIN=local go test ./... -count=1
./scripts/gate-scenarios-bound.sh
./scripts/gate-scenarios-bound-teeth.sh
./scripts/gate-wg-key-off-argv.sh && ./scripts/gate-wg-key-off-argv-teeth.sh
./scripts/gate-throttle.sh && ./scripts/gate-throttle-teeth.sh
./scripts/gate-jail.sh && ./scripts/gate-jail-teeth.sh
./scripts/gate-seccomp-native.sh && ./scripts/gate-seccomp-native-teeth.sh   # Linux, amd64 or arm64, natively
./scripts/gate-split.sh && ./scripts/gate-split-teeth.sh
python3 scripts/mutate-held.py
python3 scripts/mutate-split.py
./scripts/test-real-uci.sh   # needs docker
```

`scripts/gate-apk-parity.sh` needs docker and runs in CI's `apk` job only. `scripts/e2e-vlab.sh` needs the
vlab on forge and is run there by hand: it runs every tool against the daemon on a virtual router, in its
two parts, and the boundaries of the split; `--daemon DIR` runs the same tests against another tree's
daemon (origin/main's, for the red run).

## Rules for a change

- A new rule that can be checked from the source gets a gate in `scripts/`, and a teeth script that
  plants its fault and requires the gate to go red. A gate whose subject is missing must say
  "measured nothing", not pass.
- A new test runs against the unfixed code first and must go red there.
- Public text quotes no one. A decision is recorded as `@decided YYYY-MM-DD` with a paraphrase.
- No long dashes in prose.
