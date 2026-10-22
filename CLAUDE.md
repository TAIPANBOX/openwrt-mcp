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
   (test: `features/approval.feature`, every scenario bound; mutants: `scripts/mutate-held.py`, 55,
   each caught by the test named beside it; real uci: `scripts/test-real-uci.sh`
   `TestRealUCIClassification`, in OpenWrt's rootfs in CI's apk job)

Each invariant is restated as scenarios in `features/`: `exec-argument-grants.feature`,
`ubus-call-grants.feature`, `audit-keeps-secrets-out.feature` and `wireguard-key-off-argv.feature`.
Every scenario is bound to a named test, and `scripts/gate-scenarios-bound.sh` checks the binding
both ways and runs the tests.

Guarantees from earlier waves are not numbered here; they are stated in the README's security
model and held by their feature files: `uci_get` never returns a secret
(`features/uci-get-redaction.feature`), `uci_apply` refuses a change that runs code
(`features/uci-apply-no-code-exec.feature`), and `apk_add` installs from the official feeds only
(`features/apk-add-official-feed.feature`).

## Gates

```sh
GOTOOLCHAIN=local go vet ./... && GOTOOLCHAIN=local go test ./... -count=1
./scripts/gate-scenarios-bound.sh
./scripts/gate-scenarios-bound-teeth.sh
./scripts/gate-wg-key-off-argv.sh && ./scripts/gate-wg-key-off-argv-teeth.sh
python3 scripts/mutate-held.py
./scripts/test-real-uci.sh   # needs docker
```

`scripts/gate-apk-parity.sh` needs docker and runs in CI's `apk` job only.

## Rules for a change

- A new rule that can be checked from the source gets a gate in `scripts/`, and a teeth script that
  plants its fault and requires the gate to go red. A gate whose subject is missing must say
  "measured nothing", not pass.
- A new test runs against the unfixed code first and must go red there.
- Public text quotes no one. A decision is recorded as `@decided YYYY-MM-DD` with a paraphrase.
- No long dashes in prose.
