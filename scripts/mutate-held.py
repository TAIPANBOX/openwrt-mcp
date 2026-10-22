#!/usr/bin/env python3
"""mutate-held.py -- break held-action approval on purpose, and require a named test to notice.

Each mutant below is a change to the product code that would make a wrong answer silent: a
high-impact change run instead of held, an approval of something other than what was shown, a
try spent or a window opened that should not be. For each one the script copies the repository,
applies the mutant, runs the test named beside it, and requires that test to FAIL. It first runs
every named test on the unmutated code and requires each to PASS, so a red mutant run means the
mutant and not a broken harness. A mutant whose text is no longer in its file is a failure, not a
skip: the code moved, and the mutant must move with it, or it measures nothing.

    ./scripts/mutate-held.py            every mutant
    ./scripts/mutate-held.py 3 7        just those, by number
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (what it breaks, file, the text, what it becomes, the test that must go red)
MUTANTS = [
    ("a port to the internet is never found", "classify.go",
     "func portsToTheInternet(before, after states) []string {\n",
     "func portsToTheInternet(before, after states) []string {\n\treturn nil\n",
     "TestTier3HeldWithWindowOpen"),
    ("an opening is compared with nothing before it", "classify.go",
     "\twas := openings(before)\n", "\twas := openings(states{})\n", "TestTier2RunsInTheWindow"),
    ("a zone that masquerades does not face the internet", "classify.go",
     'if z.get("masq") == "1" {', 'if z.get("masq") == "never" {', "TestPredicatesReadTheState"),
    ("a zone that holds wan6 does not face the internet", "classify.go",
     'if n == "wan" || n == "wan6" {', 'if n == "wan" {', "TestPredicatesReadTheState"),
    ("an internet zone accepting input is not weakening", "classify.go",
     'if a.policy(z, "input") == "ACCEPT" && (', 'if a.policy(z, "input") == "NEVER" && (',
     "TestTier3HeldWithWindowOpen"),
    ("a zone's unset policy does not follow the defaults", "classify.go",
     "m.defIn = strings.ToUpper(v)", "_ = v", "TestPredicatesReadTheState"),
    ("a forwarding from the internet is compared with itself", "classify.go",
     "was := forwards(before, b)", "was := forwards(after, a)", "TestTier3HeldWithWindowOpen"),
    ("the internet port joining a bridge is compared with itself", "classify.go",
     "was = joins(before)", "was = joins(after)", "TestWanPortIntoLanBridgeHeld"),
    ("the zones that face the internet are not compared", "classify.go",
     'strings.Join(bz, " ") != strings.Join(az, " ")', "false", "TestZoneRenameHeld"),
    ("a WireGuard interface is not VPN routing", "classify.go",
     'return strings.HasPrefix(s.Type, "wireguard_") || (s.Type == "interface" && s.get("proto") == "wireguard")',
     "return false", "TestTier3HeldWithWindowOpen"),
    ("a default route is not VPN routing", "classify.go",
     'if defaultDestination(t) || (t == "0.0.0.0" && s.get("netmask") == "0.0.0.0") {', "if t == \"never\" {",
     "TestTier3HeldWithWindowOpen"),
    ("pbr is not policy routing", "classify.go",
     'out = append(out, "CHANGES VPN OR POLICY ROUTING: pbr")', "out = append(out)",
     "TestTier3HeldWithWindowOpen"),
    ("dnsmasq's upstream servers are not DNS", "classify.go",
     '[]string{"server", "address", "noresolv", "resolvfile", "rebind_protection"}', '[]string{"address"}',
     "TestTier3HeldWithWindowOpen"),
    ("the time servers are not held", "classify.go",
     'return s.Type == "timeserver"', "return false", "TestTier3HeldWithWindowOpen"),
    ("an open Wi-Fi into a trusted zone is not held", "classify.go",
     'if !ok || m.wanZones[z] || m.policy(z, "input") != "ACCEPT" {',
     'if !ok || m.wanZones[z] || m.policy(z, "input") != "ACCEPT" || true {',
     "TestTier3HeldWithWindowOpen"),
    ("stopping the firewall is not stopping a guard", "classify.go",
     '"firewall": true, "dropbear": true,', '"dropbear": true,', "TestTier3HeldWithWindowOpen"),
    ("a reboot is not held", "classify.go", 'case "system.reboot":', 'case "system.never":',
     "TestTier3HeldWithWindowOpen"),
    ("a state that cannot be read runs as if it were safe", "classify.go",
     "return classification{tier: tierHeld, configs: configs,",
     "return classification{tier: tierRun, configs: configs,", "TestUnreadableTypeHeld"),
    ("a secret is shown on the card", "classify.go",
     "if isSecretUCIOption(name) {\n\t\treturn redacted", "if false {\n\t\treturn redacted",
     "TestCardIsWhatIsApplied"),
    ("what the agent chose reaches the card unescaped", "classify.go",
     "case r == ' ' || (unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r)):",
     "case r == ' ' || (unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r)) || true:",
     "TestCardIsWhatIsApplied"),
    ("what only a person may do: a command", "classify.go",
     '"exec": "run a command on the router",', '"exec_": "run a command on the router",',
     "TestHumanOnlyRefusedWhateverTheGrant"),
    ("what only a person may do: the agent's own config", "classify.go",
     '"hermes":      "change', '"hermes_":     "change', "TestHumanOnlyRefusedWhateverTheGrant"),
    ("what only a person may do: rpcd's file object", "classify.go",
     '{"file.*",', '{"filex.*",', "TestHumanOnlyRefusedWhateverTheGrant"),
    ("the input is not in the hash", "approval.go",
     "hashed{h.ID, h.Client, h.Tool, h.Input, h.cardBase,", "hashed{h.ID, h.Client, h.Tool, nil, h.cardBase,",
     "TestHashCoversEveryField"),
    ("the card is not in the hash", "approval.go",
     "h.Input, h.cardBase, h.Fingerprint,", 'h.Input, "", h.Fingerprint,', "TestHashCoversEveryField"),
    ("the fingerprint is not in the hash", "approval.go",
     "h.cardBase, h.Fingerprint,\n", 'h.cardBase, "",\n', "TestHashCoversEveryField"),
    ("the approval's hash is not compared", "approval.go",
     "if len(in.Hash) != 64 || subtle.ConstantTimeCompare([]byte(strings.ToLower(in.Hash)), []byte(h.Hash)) != 1 {",
     "if false && subtle.ConstantTimeCompare([]byte(in.Hash), []byte(h.Hash)) != 1 {", "TestApproveRefusesAnotherHash"),
    ("anyone approves", "approval.go", "if !s.cfg().approves(caller, h.Client) {", "if false {",
     "TestAgentClientCannotApprove"),
    ("a code is accepted twice", "mfa.go", "seen && ctr <= last {", "seen && ctr < last {",
     "TestApproveStepSpent"),
    ("an approval opens the window", "mfa.go", "_, err := m.attempt(client, in, up, now, false)",
     "_, err := m.attempt(client, in, up, now, true)", "TestApproveNeverOpensWindow"),
    ("a changed router is approved anyway", "approval.go", "if fingerprint(h.Configs) != h.Fingerprint {",
     "if false {", "TestApproveRefusedAfterDrift"),
    ("an approval does not wait for another apply's confirmation", "approval.go",
     "\tif busy {\n\t\treturn back(", "\tif busy && false {\n\t\treturn back(",
     "TestApproveRefusedWhileAnApplyAwaitsConfirmation"),
    ("an approval takes the window's factor, not the PIN and a code", "approval.go",
     "up.Factor = a.Factor", "_ = a.Factor", "TestApproveNeedsPINAndCode"),
    ("a held change never expires", "approval.go", "Created: now, Expires: now.Add(a.TTL),",
     "Created: now, Expires: now.Add(100 * time.Hour),", "TestHeldExpires"),
    ("two changes may wait at once", "approval.go", "if open >= a.MaxOpen {", "if open >= a.MaxOpen+1 {",
     "TestOneOpenPerClient"),
    ("one more proposal an hour", "approval.go", "if len(recent) >= a.MaxPerHour {",
     "if len(recent) > a.MaxPerHour {", "TestProposalsPerHourAreLimited"),
    ("no pause after rejections", "approval.go", "st.pausedUntil[h.Client] = now.Add(a.Pause)", "_ = a.Pause",
     "TestProposalsPauseAfterRejections"),
    ("a card is cut short instead of refused", "approval.go",
     "if utf8.RuneCountInString(h.Card) > maxCardRunes {", "if false {", "TestCardOverTheLimitIsRefused"),
    ("the owner's lock rejects nothing", "tools.go", "n := s.rejectAll(in.Client)", "n := 0",
     "TestLockRejectsEveryHeld"),
    ("a high-impact change is held with no way to approve it", "tools.go",
     "if why := s.approvalReady(a); why != \"\" {\n\t\t\t\t\t\t\tr := ",
     "if why := \"\"; why != \"\" {\n\t\t\t\t\t\t\tr := ", "TestTier3RefusedUntilApprovalIsSetUp"),
    ("the gate never classifies", "tools.go", "cl := s.classifyCall(ctx, name, shape, p, a)",
     "cl := classification{}", "TestTier3HeldWithWindowOpen"),
    ("what only a person may do is not asked", "tools.go",
     "if r := humanOnlyRefusal(name, shape.scopes); r != \"\" {", "if r := \"\"; r != \"\" {",
     "TestHumanOnlyRefusedWhateverTheGrant"),
    ("the agent opens its own window", "tools.go", "if a := s.cfg().approvalFor(caller); a != nil {",
     "if a := s.cfg().approvalFor(caller); a != nil && false {", "TestAgentCannotUnlockItself"),
    ("an approved change needs an unlock to be confirmed", "server.go",
     "return p != nil && client != \"\" && p.ApprovedFor == client", "return false && p != nil",
     "TestApproveAppliesExactlyTheHeldBatch"),
    ("any change is confirmed without an unlock", "server.go",
     "return p != nil && client != \"\" && p.ApprovedFor == client", "return p != nil",
     "TestConfirmWithoutUnlockOnlyForApprovedChanges"),
    ("a hold policy holds nothing", "approval.go", "\tif p.Hold {\n", "\tif false {\n",
     "TestHoldPolicyHoldsWhatItGrants"),
    ("a refuse rule refuses nothing", "approval.go", "for _, r := range a.Refuse {",
     "for _, r := range a.Refuse[:0] {", "TestApprovalRulesAddHoldsAndRefusals"),
]


def go_test(where, tests):
    pattern = "^(" + "|".join(sorted(set(tests))) + ")$"
    p = subprocess.run(["go", "test", "-count=1", "-run", pattern, "."], cwd=where, capture_output=True, text=True,
                       env=dict(os.environ, GOTOOLCHAIN=os.environ.get("GOTOOLCHAIN", "local")))
    return p.returncode, p.stdout + p.stderr


def copy_repo():
    tmp = tempfile.mkdtemp(prefix="mutate-held-")
    dst = os.path.join(tmp, "repo")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(".git", "*.ipk", "*.apk", "openwrt-mcp.*"))
    return tmp, dst


def main(argv):
    picked = [int(a) for a in argv] if argv else list(range(1, len(MUTANTS) + 1))
    if not MUTANTS:
        print("FAIL: no mutants: measured nothing")
        return 1
    tests = [MUTANTS[i - 1][4] for i in picked]
    code, out = go_test(REPO, tests)
    if code != 0:
        print(out[-3000:])
        print("FAIL: the tests the mutants are judged by are not green on the unmutated code")
        return 1
    bad = 0
    for i in picked:
        what, path, old, new, test = MUTANTS[i - 1]
        tmp, dst = copy_repo()
        try:
            f = os.path.join(dst, path)
            with open(f, encoding="utf-8") as fh:
                src = fh.read()
            if src.count(old) != 1:
                print(f"FAIL mutant {i} ({what}): its text is in {path} {src.count(old)} times, not once; "
                      "the code moved, so move the mutant")
                bad += 1
                continue
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(src.replace(old, new, 1))
            code, out = go_test(dst, [test])
            if code == 0:
                print(f"FAIL mutant {i} ({what}): {test} stayed green")
                bad += 1
            elif re.search(r"^--- FAIL: " + re.escape(test) + r"\b", out, re.M):
                print(f"caught mutant {i} ({what}): {test}")
            elif "build failed" in out or "[build failed]" in out or re.search(r"^# ", out, re.M):
                print(out[-1500:])
                print(f"FAIL mutant {i} ({what}): it does not compile, so it proves nothing")
                bad += 1
            else:
                print(out[-1500:])
                print(f"FAIL mutant {i} ({what}): red, but not in {test}")
                bad += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        print(f"FAIL: {bad} of {len(picked)} mutants were not caught by the test named for them")
        return 1
    print(f"mutate-held: {len(picked)} mutants, each caught by the test named for it")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
