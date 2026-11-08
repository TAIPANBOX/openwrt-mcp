#!/usr/bin/env python3
"""mutate-held.py -- break held-action approval and the guess throttle on purpose, and require a
named test to notice.

Each mutant below is a change to the product code that would make a wrong answer silent: a
high-impact change run instead of held, an approval of something other than what was shown, a
try spent or a window opened that should not be, a delay a restart or a clock gets round, a flood
that rotates the evidence out of the log. For each one the script copies the repository,
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
     'if uciTrue(z.get("masq")) {', 'if z.get("masq") == "never" {', "TestPredicatesReadTheState"),
    ("a zone that holds wan6 does not face the internet", "classify.go",
     'if n == "wan" || n == "wan6" {', 'if n == "wan" {', "TestPredicatesReadTheState"),
    ("an internet zone accepting input is not weakening", "classify.go",
     'if accepts(a.policy(z, "input")) && (', 'if a.policy(z, "input") == "NEVER" && (',
     "TestTier3HeldWithWindowOpen"),
    ("a zone's unset policy does not follow the defaults", "classify.go",
     "m.defIn = v", "_ = v", "TestPredicatesReadTheState"),
    ("a forwarding from the internet is compared with itself", "classify.go",
     "was := forwards(before, b)", "was := forwards(after, a)", "TestTier3HeldWithWindowOpen"),
    ("a device's ports are compared with themselves", "classify.go",
     "bd, ad := devices(bn), devices(an)", "bd, ad := devices(an), devices(an)", "TestWanPortIntoLanBridgeHeld"),
    ("the zones that face the internet are not compared", "classify.go",
     'strings.Join(bz, " ") != strings.Join(az, " ")', "false", "TestZoneRenameHeld"),
    ("a WireGuard interface is not VPN routing", "classify.go",
     'return strings.HasPrefix(s.Type, "wireguard_") || (s.Type == "interface" && s.word("proto") == "WIREGUARD")',
     "return false", "TestTier3HeldWithWindowOpen"),
    ("a default route is not VPN routing", "classify.go",
     'if defaultDestination(t) || (t == "0.0.0.0" && strings.TrimSpace(s.get("netmask")) == "0.0.0.0") {', "if t == \"never\" {",
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
     'if !ok || m.netWan[z] || !accepts(m.policy(z, "input")) {',
     'if !ok || m.netWan[z] || !accepts(m.policy(z, "input")) || true {',
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
     "if why := s.approvalReady(a); why != \"\" {\n\t\t\t\t\tr := ",
     "if why := \"\"; why != \"\" {\n\t\t\t\t\tr := ", "TestTier3RefusedUntilApprovalIsSetUp"),
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
    # From the review of 2026-10-22.
    ("a policy nobody knows reads as closed", "classify.go",
     'func accepts(policy string) bool { return policy != "REJECT" && policy != "DROP" }',
     'func accepts(policy string) bool { return policy == "ACCEPT" }', "TestKeywordsAreReadTheWayTheyCouldBeApplied"),
    ("a keyword decided on with its spaces", "classify.go",
     "func (s *uciSect) word(opt string) string { return strings.ToUpper(strings.TrimSpace(s.get(opt))) }",
     "func (s *uciSect) word(opt string) string { return strings.ToUpper(s.get(opt)) }",
     "TestKeywordsAreReadTheWayTheyCouldBeApplied"),
    ("only a DNAT spelled DNAT opens", "classify.go", 'if !enabled(s) || s.word("target") == "SNAT" ||',
     'if !enabled(s) || (s.word("target") != "" && s.word("target") != "DNAT") ||', "TestKeywordsAreReadTheWayTheyCouldBeApplied"),
    ("masq read as the string 1 alone", "classify.go", 'if uciTrue(z.get("masq")) {', 'if z.get("masq") == "1" {',
     "TestKeywordsAreReadTheWayTheyCouldBeApplied"),
    ("a hold policy for a tool no approval can run", "config.go", "				if !heldTools[t] {",
     "				if false && !heldTools[t] {", "TestHoldIsOnlyForWhatAnApprovalCanRun"),
    ("an approved apply not checked again before staging", "server.go", "	if guard != nil {\n",
     "	if false && guard != nil {\n", "TestApprovedApplyRechecksTheConfigs"),
    ("a refused listing not audited", "tools.go", 'if !(name == "action_list" && outcome == OutcomeOK) {',
     'if name != "action_list" {', "TestApproverListingIsNotAudited"),
    ("every listing audited", "tools.go", 'if !(name == "action_list" && outcome == OutcomeOK) {',
     "if true {", "TestApproverListingIsNotAudited"),
    ("what an interface sits on is not compared", "classify.go",
     'if strings.Join(was, " ") == strings.Join(now, " ") || len(now) == 0 {', 'if true || len(now) == 0 {', "TestRewiringIsHeld"),
    ("a VLAN table is compared with itself", "classify.go",
     "for _, l := range sectionChanges(bn, an, func(s *uciSect) bool { return s.Type == typ }) {",
     "for _, l := range sectionChanges(bn, bn, func(s *uciSect) bool { return s.Type == typ }) {", "TestRewiringIsHeld"),
    ("a switch's VLAN table is not read", "classify.go",
     'for _, typ := range []string{"bridge-vlan", "switch_vlan", "switch_port"} {', 'for _, typ := range []string{"bridge-vlan"} {', "TestRewiringIsHeld"),
    ("a device's base is not read", "classify.go",
     'got[name] = append(append(got[name], d.list("ports")...), d.list("ifname")...)',
     'got[name] = append(got[name], d.list("ports")...)', "TestRewiringIsHeld"),
    ("a new device with ports counts as a guest bridge", "classify.go",
     'if !inBefore && len(now) == 0 && bridges[n] && strings.HasPrefix(n, "br-") && !strings.ContainsAny(n, ".@") && !netdevExists(n) {',
     'if !inBefore && bridges[n] && strings.HasPrefix(n, "br-") && !strings.ContainsAny(n, ".@") && !netdevExists(n) {', "TestRewiringIsHeld"),
    ("a new device that is not a bridge counts as a guest bridge", "classify.go",
     'if st == an && d.word("type") == "BRIDGE" {', 'if st == an {', "TestRewiringIsHeld"),
    ("a new device named as a port counts as a guest bridge", "classify.go",
     '&& bridges[n] && strings.HasPrefix(n, "br-") && !strings.ContainsAny(n, ".@") && !netdevExists(n) {',
     '&& (bridges[n] || !bridges[n]) && !strings.ContainsAny(n, ".@") && !netdevExists(n) {', "TestRewiringIsHeld"),
    ("a new bridge named as a VLAN counts as a guest bridge", "classify.go",
     '&& strings.HasPrefix(n, "br-") && !strings.ContainsAny(n, ".@") && !netdevExists(n) {', '&& strings.HasPrefix(n, "br-") && !netdevExists(n) {', "TestRewiringIsHeld"),
    ("an existing port-less device counts as a guest bridge", "classify.go",
     'if !inBefore && len(now) == 0 && bridges[n]', 'if len(now) == 0 && bridges[n]', "TestRewiringIsHeld"),
    ("an interface on any single device runs", "classify.go",
     "if len(now) == 1 && fresh[now[0]] {", "if len(now) == 1 {", "TestRewiringIsHeld"),
    ("a device removed is not held", "classify.go",
     '|| !inAfter && len(was) == 0) {', '|| !inAfter) {', "TestRewiringIsHeld"),
    ("a port-less device removed is held", "classify.go",
     'if inBefore && (inAfter && strings.Join(was, " ") == strings.Join(now, " ") || !inAfter && len(was) == 0) {',
     'if inBefore && (inAfter && strings.Join(was, " ") == strings.Join(now, " ")) {', "TestRewiringIsHeld"),
    ("raw nftables read from extra alone", "classify.go",
     'if strings.HasPrefix(opt, "extra") {', 'if opt == "extra" {', "TestRewiringIsHeld"),
    ("raw nftables are not compared", "classify.go",
     "if w, ok := br[k]; !ok || w != v {", "if w, ok := br[k]; false && (!ok || w != v) {", "TestRewiringIsHeld"),
    ("a br- bridge the kernel already has counts as a guest bridge", "classify.go",
     '!strings.ContainsAny(n, ".@") && !netdevExists(n) {', '!strings.ContainsAny(n, ".@") {', "TestRewiringIsHeld"),
    ("an open Wi-Fi skips every zone that takes a device", "classify.go",
     'if !ok || m.netWan[z] || !accepts(m.policy(z, "input")) {', 'if !ok || m.wanZones[z] || !accepts(m.policy(z, "input")) {', "TestRewiringIsHeld"),
    ("a network the internet zone lists is not on the internet side", "classify.go",
     "\t\tif b.wanZones[z] {\n\t\t\tside[n] = true", "\t\tif false && b.wanZones[z] {\n\t\t\tside[n] = true", "TestRewiringIsHeld"),
    ("the internet side joining a trusted zone is not held", "classify.go",
     "if side[n] && !had[n] {", "if false && side[n] && !had[n] {", "TestRewiringIsHeld"),
    ("what a zone takes by device or subnet is not compared", "classify.go",
     "if bt[z] != at[z] {", "if false {", "TestRewiringIsHeld"),
    ("a zone that takes devices does not face the internet", "classify.go",
     'if len(z.list("device"))+len(z.list("subnet")) > 0 {', "if false {", "TestRewiringIsHeld"),
    ("a default route's target read with its spaces", "classify.go",
     '\t\t\t\tt := strings.TrimSpace(s.get("target"))', '\t\t\t\tt := s.get("target")', "TestRewiringIsHeld"),
    ("a routing rule's destination read with its spaces", "classify.go",
     'if d := strings.TrimSpace(s.get("dest")); d == "" || defaultDestination(d) {',
     'if d := s.get("dest"); d == "" || defaultDestination(d) {', "TestRewiringIsHeld"),

    # ---- the guess throttle (throttle.go) and the folding of the audit log (audit.go)

    # The persistence order.
    ("the count is written after the factors are checked", "mfa.go",
     "\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n\n\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n",
     "\te.fails++\n\n\terr := m.checkFactorsLocked(client, in, up.Factor, now)\n\t_ = m.saveThrottleLocked(mono)\n\tif err != nil {\n",
     "TestTheCountIsOnDiskBeforeTheFactorsAreChecked"),
    ("the count is never written before the check", "mfa.go",
     "\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n", "\te.fails++\n", "TestATryThatDiesInTheCheckIsStillCounted"),
    ("a success is not written", "mfa.go", "\t_ = m.saveThrottleLocked(m.mono())\n", "", "TestSuccessClearsTheCountOnTheDisk"),
    ("the file is written in place", "mfa.go", "return atomicWriteFile(path, data, throttleFileMode)",
     "return os.WriteFile(path, data, throttleFileMode)", "TestTheStoreSyncsWhatItWrites"),
    ("the data is not synced", "throttle.go", "\t\terr = syncFile(f)\n", "\t\terr = nil\n",
     "TestAtomicWriteSyncsTheFileThenTheDirectory"),
    ("the directory is not synced", "throttle.go", "\treturn syncFile(d)\n", "\treturn nil\n",
     "TestAtomicWriteSyncsTheFileThenTheDirectory"),
    ("a failed sync is ignored", "throttle.go", "\tif err != nil {\n\t\treturn err\n\t}\n\tif err := os.Rename(tmp, path); err != nil {\n",
     "\tif err := os.Rename(tmp, path); err != nil {\n", "TestAtomicWriteLeavesTheOldFileOnAFailure"),
    ("a failed rename is ignored", "throttle.go", "\tif err := os.Rename(tmp, path); err != nil {\n\t\treturn err\n\t}\n",
     "\t_ = os.Rename(tmp, path)\n", "TestAtomicWriteReportsWhatStopsIt"),
    ("a stale sidecar keeps its mode", "throttle.go", "\terr = f.Chmod(mode)\n\tif err == nil {\n\t\t_, err = f.Write(data)\n\t}\n",
     "\t_, err = f.Write(data)\n", "TestAtomicWriteTightensAStaleSidecar"),
    ("restart-forgives: a new process does not read the count", "throttle.go", "\t\te.merge(client, tf, 0)\n", "",
     "TestRestartMidDelayStartsAFreshDelay"),
    ("restart-forgives: a restart counts as the delay having run", "throttle.go", "\t\te = &throttleEntry{up: up}\n",
     "\t\te = &throttleEntry{up: up, lastFail: -2 * time.Hour}\n", "TestRestartMidDelayStartsAFreshDelay"),
    ("the step is not read back", "mfa.go", "\t\t\tm.lastCtr[client] = rec.step\n", "\t\t\tm.lastCtr[client] = 0\n",
     "TestACodeCannotBeReplayedAfterARestart"),
    ("the step is not written", "throttle.go", 'fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])',
     'fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, 0)', "TestDiskHoldsOnlyACountAndAStep"),
    ("a time on the disk", "throttle.go", 'fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])',
     'fmt.Sprintf("%s %d %d %d", url.PathEscape(client), e.fails, m.lastCtr[client], time.Now().Unix())', "TestDiskHoldsOnlyACountAndAStep"),
    ("a client's name goes on the disk as it is", "throttle.go", 'fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])',
     'fmt.Sprintf("%s %d %d", client, e.fails, m.lastCtr[client])', "TestAClientNameThatCouldBreakTheFileKeepsItsCount"),
    ("a step spent by activate is lost on a restart", "mfa.go", "\tm.applySpentStepsLocked()\n\treturn m, nil\n", "\treturn m, nil\n",
     "TestRestartKeepsTheStepSpentByActivate"),

    # The monotonic delay.
    ("the delay is read on the wall clock", "mfa.go",
     "\tmono := m.mono()\n\te := m.entryLocked(client, up, m.syncThrottleLocked(mono), mono)\n\tif wait := e.wait(up, mono); wait > 0 {\n\t\te.refused++\n",
     "\tmono := time.Duration(now.UnixNano())\n\te := m.entryLocked(client, up, m.syncThrottleLocked(mono), mono)\n\tif wait := e.wait(up, mono); wait > 0 {\n\t\te.refused++\n",
     "TestAClockJumpInsideADelayChangesNothing"),
    ("the moment of the last failure is on the wall clock", "mfa.go", "\t\te.lastFail, e.refused = m.mono(), 0\n",
     "\t\te.lastFail, e.refused = time.Duration(now.UnixNano()), 0\n", "TestAClockJumpInsideADelayChangesNothing"),
    ("wall-clock-decay: the day is read on the wall clock", "mfa.go",
     "\tmono := m.mono()\n\te := m.entryLocked(client, up, m.syncThrottleLocked(mono), mono)\n\tst.Failures, st.Refused = e.fails, e.refused\n",
     "\tmono := time.Duration(now.UnixNano())\n\te := m.entryLocked(client, up, m.syncThrottleLocked(mono), mono)\n\tst.Failures, st.Refused = e.fails, e.refused\n",
     "TestTheWallClockCannotDecayTheCount"),
    ("a reboot skips the delay when the wall clock jumped", "throttle.go", "\treturn e.lastFail + delayAfter(e.fails, up) - mono\n",
     "\tif mono == 0 {\n\t\treturn 0\n\t}\n\treturn e.lastFail + delayAfter(e.fails, up) - mono\n", "TestRebootWithTheClockJumping"),

    # The scheme.
    ("fresh-count-after-lockout: the end of a delay gives the free tries back", "mfa.go", "\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n",
     "\tif e.fails >= up.MaxFailures {\n\t\te.fails = 0\n\t}\n\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n", "TestAfterADelayOneTryIsAllowed"),
    ("ceiling-removed: the wait grows past the hour", "throttle.go", "\treturn min(d, ceiling)\n", "\treturn d\n", "TestDelayScheme"),
    ("the wait does not double", "throttle.go", "\t\td *= 2\n", "\t\td += d / 2\n", "TestFiveFreeTriesThenFifteenThirtySixty"),
    ("the loop runs on past the ceiling", "throttle.go", "i < n && d < ceiling", "i < n", "TestDelayScheme"),
    ("mfa_lockout is not the first delay", "throttle.go", "\td := up.Lockout\n", "\td := defaultMFALockout\n",
     "TestConfiguredLimitAndDelayKeepTheirMeaning"),
    ("mfa_max_failures is not the first threshold", "throttle.go", "\tif n < up.MaxFailures {\n", "\tif n < defaultMFAMaxFailures {\n",
     "TestConfiguredLimitAndDelayKeepTheirMeaning"),
    ("the ceiling cuts a longer first delay", "throttle.go", "ceiling := max(throttleCeiling, up.Lockout)", "ceiling := throttleCeiling",
     "TestDelayScheme"),
    ("refused-counts: a refused try is counted", "mfa.go", "\t\te.refused++\n", "\t\te.refused++\n\t\te.fails++\n", "TestARefusalInADelayWritesNothing"),
    ("a refused try writes", "mfa.go", "\t\te.refused++\n", "\t\te.refused++\n\t\t_ = m.saveThrottleLocked(mono)\n",
     "TestARefusalInADelayWritesNothing"),
    ("a refused try extends the delay", "mfa.go", "\t\te.refused++\n", "\t\te.refused++\n\t\te.lastFail = mono\n", "TestLockoutBoundaries"),
    ("parallel tries all pass the wait before any is counted", "mfa.go",
     "\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n\n\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n",
     "\tm.mu.Unlock()\n\ttime.Sleep(10 * time.Millisecond)\n\tm.mu.Lock()\n\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n\n"
     "\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n",
     "TestParallelAttemptsCannotSlipUnderTheLimit"),
    ("the refusal's words change", "mfa.go", '"too many failed attempts: unlocking is locked out until "',
     '"too many failed attempts: unlocking is paused until "', "TestRefusalWordsAreThePluginsContract"),

    # The reset.
    ("success-does-not-reset", "mfa.go", "\te.fails, e.lastFail, e.refused = 0, 0, 0\n\t_ = m.saveThrottleLocked(m.mono())\n",
     "\t_ = m.saveThrottleLocked(m.mono())\n", "TestSuccessClearsTheCountOnTheDisk"),
    ("success-does-not-reset, after a delay", "mfa.go", "\te.fails, e.lastFail, e.refused = 0, 0, 0\n\t_ = m.saveThrottleLocked(m.mono())\n",
     "\t_ = m.saveThrottleLocked(m.mono())\n", "TestSuccessAfterADelayGivesTheFreeTriesBack"),
    ("uptime decay is gone", "throttle.go", "\tif e.fails > 0 && mono-e.lastFail >= throttleDecay {\n", "\tif false {\n",
     "TestADayOfUptimeResetsTheCount"),
    ("a day and a nanosecond", "throttle.go", "mono-e.lastFail >= throttleDecay", "mono-e.lastFail > throttleDecay",
     "TestADayOfUptimeResetsTheCount"),
    ("a refused try restarts the day", "mfa.go", "\t\te.refused++\n", "\t\te.refused++\n\t\te.fails = e.fails + 0\n\t\tdefer func() { e.lastFail = mono }()\n",
     "TestOnlyACountedFailureRestartsTheDay"),
    ("a restart does not start the day again", "throttle.go", "\t\te = &throttleEntry{up: up}\n", "\t\te = &throttleEntry{up: up, lastFail: -23 * time.Hour}\n",
     "TestARestartStartsTheDayAgain"),
    ("the day never reaches the disk", "throttle.go", "\t\te.decay(mono)\n\t\tif e.onDisk != throttleUnread", "\t\tif e.onDisk != throttleUnread",
     "TestSweepCarriesTheDayToTheDisk"),
    ("the sweep skips a client it has not met", "throttle.go", "\t\t\tm.entryLocked(client, m.policyLocked(client), tf, mono)\n\t\t}\n\t}\n\tchanged",
     "\t\t\tcontinue\n\t\t}\n\t}\n\tchanged", "TestSweepForgetsAClientThisProcessNeverMet"),
    ("the sweep always writes", "throttle.go", "\tif changed {\n", "\tif changed || true {\n", "TestSweepWritesNothingWhenNothingChanged"),
    ("the sweep does not retry a failed write", "throttle.go", "\tchanged := m.unsaved.Load()\n", "\tchanged := false\n",
     "TestASpentStepCatchesUpAfterAFullDisk"),
    ("`mfa reset` does not reach a running daemon", "throttle.go", "\tcase n != e.onDisk:\n", "\tcase n != e.onDisk && false:\n",
     "TestResetFromTheCLIReachesARunningDaemon"),
    ("the daemon writes a reset back over", "throttle.go", "\tcase n != e.onDisk:\n", "\tcase n != e.onDisk && n != 0:\n",
     "TestAResetIsNotUndoneByTheNextWrite"),
    ("a reset forgets the step", "throttle.go", "\te.fails, e.lastFail, e.refused = 0, 0, 0\n\treturn was, m.saveThrottleLocked(mono)\n",
     "\te.fails, e.lastFail, e.refused = 0, 0, 0\n\tdelete(m.lastCtr, client)\n\treturn was, m.saveThrottleLocked(mono)\n",
     "TestResetKeepsTheSpentStep"),
    ("a reset says it worked when the disk refused it", "throttle.go", "\treturn was, m.saveThrottleLocked(mono)\n",
     "\t_ = m.saveThrottleLocked(mono)\n\treturn was, nil\n", "TestResetReportsADiskThatWillNotTakeIt"),
    ("a tool resets the count", "tools.go", '\ttoolOf("mfa_lock",\n',
     '\ttoolOf("mfa_reset", "resets the count", scoped(noScope[mfaLockIn]),\n'
     '\t\tfunc(ctx context.Context, s *Server, client string, in mfaLockIn) (string, string, error) {\n'
     '\t\t\t_, err := s.mfa.ResetThrottle(client)\n\t\t\treturn "done", "mfa_reset", err\n\t\t}),\n\n'
     '\ttoolOf("mfa_lock",\n', "TestNoMCPToolResetsTheThrottle"),
    ("mfa_lock clears the count", "mfa.go", "\tuntil, was := m.unlocks[client]\n\tdelete(m.unlocks, client)\n",
     "\tuntil, was := m.unlocks[client]\n\tdelete(m.unlocks, client)\n\tm.clearThrottleLocked(client)\n", "TestNoMCPToolResetsTheThrottle"),
    ("a rotated credential keeps its record", "mfa.go", "\tdelete(m.lastCtr, client)\n\tm.clearThrottleLocked(client)\n",
     "\tdelete(m.lastCtr, client)\n", "TestRotatingATOTPSecretWithTheDaemonStoppedClearsTheRecord"),
    ("`pin set` leaves the record for a stopped daemon", "pin.go",
     '\t\tforgetRotated(statePath, client)\n\t\tfmt.Fprintf(out, "PIN set for', '\t\tfmt.Fprintf(out, "PIN set for',
     "TestRotatingAPINWithTheDaemonStoppedClearsTheRecord"),

    # What a bad file and a full disk read as.
    ("corrupt-reads-as-zero", "throttle.go", "\tcase on, tf.unreadable, len(tf.junk) > 0:\n\t\treturn 0, false\n",
     "\tcase on, tf.unreadable, len(tf.junk) > 0:\n\t\treturn 0, true\n", "TestACorruptRecordReadsAsTheLimit"),
    ("a corrupt record reads as more than the limit", "throttle.go", "\t\t\te.fails, e.lastFail = e.up.MaxFailures, mono\n",
     "\t\t\te.fails, e.lastFail = e.up.MaxFailures+2, mono\n", "TestACorruptRecordReadsAsTheLimit"),
    ("a file with no header is sound", "throttle.go", "\t\ttf.junk = append(tf.junk, throttleNoHeader)\n", "\t\t_ = throttleNoHeader\n",
     "TestACorruptRecordReadsAsTheLimit"),
    ("a corrupt record lowers a count", "throttle.go", "\t\tif e.fails < e.up.MaxFailures {\n\t\t\tlog.Printf",
     "\t\tif e.fails != e.up.MaxFailures {\n\t\t\tlog.Printf", "TestARecordThatGoesBadRaisesAndNeverLowers"),
    ("a corrupt record is charged after every success", "throttle.go", "\t\tif e.onDisk == throttleUnread {\n", "\t\tif false {\n",
     "TestACorruptRecordOnAFullDiskIsChargedOnce"),
    ("a missing file reads as the limit", "throttle.go", "\t\ttf.unreadable = !os.IsNotExist(err)\n", "\t\ttf.unreadable = true\n",
     "TestAMissingFileReadsAsZero"),
    ("another client's corrupt line is dropped", "throttle.go", "\tfor client, rec := range tf.recs {\n\t\tlines[client] = rec.line\n\t}\n",
     "\tfor client, rec := range tf.recs {\n\t\tif !rec.bad {\n\t\t\tlines[client] = rec.line\n\t\t}\n\t}\n",
     "TestAnotherClientsWriteKeepsACorruptLine"),
    ("a line that names nobody is dropped", "throttle.go", '\tfor _, line := range tf.junk {\n\t\tb.WriteString(line + "\\n")\n\t}\n', "",
     "TestAJunkLineStaysThroughAWrite"),
    ("a file that cannot be read is replaced", "throttle.go", "\tif tf.unreadable {\n\t\t// What it holds", "\tif false {\n\t\t// What it holds",
     "TestAFileThatCannotBeReadIsNotReplaced"),
    ("a full disk refuses the try", "mfa.go",
     "\t_ = m.saveThrottleLocked(mono)\n\n\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n",
     "\tif err := m.saveThrottleLocked(mono); err != nil {\n\t\treturn time.Time{}, err\n\t}\n\n\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n",
     "TestAFullDiskKeepsWorkingFromMemory"),
    ("a full disk goes unreported", "throttle.go", "m.unsaved.Swap(err != nil)", "m.unsaved.Swap(false)", "TestAFullDiskKeepsWorkingFromMemory"),
    ("a full disk forgets the count", "throttle.go", "\tcase n != e.onDisk:\n", "\tcase n != e.fails:\n", "TestAFullDiskKeepsWorkingFromMemory"),

    # What is told, and to whom.
    ("the owner's client hears nothing of the throttle", "approval.go", "s.throttleViews(clients, now)), \"action_list\"",
     "nil), \"action_list\"", "TestActionListTellsTheOwnerOfForeignTries"),
    ("the owner's client is not told how many were refused", "approval.go", "Refused: st.Refused,", "Refused: 0,",
     "TestActionListTellsTheOwnerOfForeignTries"),
    ("the owner's client is told the disk is fine", "approval.go", "Persisted: s.mfa.ThrottlePersisted()}", "Persisted: true}",
     "TestActionListSaysWhenTheCountIsNotOnTheDisk"),
    ("the agent's own view shows the throttle", "approval.go",
     'return actionsJSON(s.views([]string{client}, false, time.Now())), "action_status", nil',
     'return ownerActionsJSON(s.views([]string{client}, false, time.Now()), s.throttleViews([]string{client}, time.Now())), "action_status", nil',
     "TestTheAgentsOwnViewCarriesNoThrottle"),
    ("status reads no count from the disk", "status.go", "\tr.Failures = ms.RecordedFailures(client, up)\n", "",
     "TestStatusShowsTheFailuresOnRecord"),
    ("status ignores what the daemon says", "status.go",
     'return running, !(running && strings.Contains(string(body), "throttle_persisted: false"))', "return running, true",
     "TestStatusShowsThrottlePersistedFalseFromTheDaemon"),
    ("a stopped daemon reads as not persisted", "status.go", '\tc, err := net.DialTimeout("tcp", listen, 2*time.Second)\n\tif err != nil {\n\t\treturn false, true\n',
     '\tc, err := net.DialTimeout("tcp", listen, 2*time.Second)\n\tif err != nil {\n\t\treturn false, false\n',
     "TestProbeDaemonReportsNothingForAStoppedDaemon"),
    ("/health says nothing of a failed write", "frontend.go", "\t\tif !persisted {\n", "\t\tif false {\n",
     "TestHealthSaysNothingWhileTheThrottleIsSaved"),
    ("the capability is gone", "status.go", '"second_factor_throttle_persisted": true,', '"second_factor_throttle_persisted_": true,',
     "TestCLIStatusJSONSaysTheThrottleIsPersisted"),
    ("`pin set` takes a common PIN", "pin.go", "\t\tif commonPINs[pin] {\n", "\t\tif false {\n", "TestPinSetRefusesTheMostCommonPINs"),
    ("`pin set` takes no PIN at all", "pin.go", "\t\tif commonPINs[pin] {\n", "\t\tif pin != \"\" {\n", "TestPinSetAcceptsAPINOffTheList"),
    ("the list reaches a PIN already on file", "pin.go", "\tif err := validatePIN(pin); err != nil {\n\t\treturn err\n\t}\n\tsalt := make",
     "\tif err := validatePIN(pin); err != nil {\n\t\treturn err\n\t}\n\tif commonPINs[pin] {\n\t\treturn errCommonPIN\n\t}\n\tsalt := make",
     "TestAWeakPINAlreadyOnFileKeepsWorking"),

    # The folding.
    ("every refusal gets a line", "audit.go", "\t\t\tr.count++\n\t\t\treturn\n", "\t\t\tr.count++\n\t\t\ta.writeLocked(e)\n\t\t\treturn\n",
     "TestABadTokenFloodIsOneLineAndASummary"),
    ("a flood rotates the evidence out", "audit.go", "\t\t\tr.count++\n\t\t\treturn\n", "\t\t\tr.count++\n\t\t\ta.writeLocked(e)\n\t\t\treturn\n",
     "TestAFloodCannotRotateTheEvidenceOut"),
    ("a bad token is not folded", "server.go", 's.audit.Fold(foldNote{key: "bad-token", what: "bad or missing bearer tokens"}, AuditEvent{',
     "s.audit.Record(AuditEvent{", "TestABadTokenFloodIsOneLineAndASummary"),
    ("a refusal in a delay is not folded", "tools.go", "\tfold = foldOf(err)\n", "", "TestRefusalsInADelayAreOneLineAndASummary"),
    ("an mfa_unlock turned away is not folded", "tools.go", "func (e *unlockRefusal) foldNote() foldNote {", "func (e *unlockRefusal) noted() foldNote {",
     "TestTheAgentTokenSpendsNoTries"),
    ("the agent's token spends the owner's tries", "tools.go", '\tif a := s.cfg().approvalFor(caller); a != nil {\n\t\treturn "", &unlockRefusal{',
     '\tif a := s.cfg().approvalFor(caller); a != nil && false {\n\t\treturn "", &unlockRefusal{', "TestTheAgentTokenSpendsNoTries"),
    ("the summary is never written", "audit.go", "\tif r.count == 0 {\n", "\tif r.count >= 0 {\n", "TestRefusalsInADelayAreOneLineAndASummary"),
    ("a run of one gets a summary", "audit.go", "\tif r.count == 0 {\n", "\tif false {\n", "TestOneBadTokenNeedsNoSummary"),
    ("the summary loses the count", "audit.go", "Folded: r.count})", "Folded: 1})", "TestABadTokenFloodIsOneLineAndASummary"),
    ("the summary comes after the next try", "audit.go", "\ta.sweepLocked(a.mono())\n\ta.writeLocked(e)\n", "\ta.writeLocked(e)\n",
     "TestTheSummaryComesBeforeTheNextTry"),
    ("a new delay folds into the old run", "audit.go", "\t\tif n.end == 0 || n.end == r.end {\n", "\t\tif true {\n",
     "TestAResetInsideADelayStartsAnotherRun"),
    ("a run of bad tokens never ends", "audit.go", "\t\tend = now + auditFoldPeriod\n", "\t\tend = now + 1000*auditFoldPeriod\n",
     "TestEachPeriodOfAFloodCostsTwoLines"),
    ("a stop loses what is counted", "server.go", "\t\t\ts.audit.Flush()\n\t\t\treturn\n", "\t\t\treturn\n",
     "TestATermWritesTheSummaryOfAnOpenRun"),
    ("the daemon's minute sweeps nothing", "server.go", "\t\tcase <-tick:\n\t\t\ts.sweep()\n", "\t\tcase <-tick:\n",
     "TestTheDaemonsMinuteSweepsAndItsStopFlushes"),
    ("the minute forgets the audit", "server.go", "\ts.audit.Sweep()\n\ts.mfa.Sweep()\n", "\ts.mfa.Sweep()\n",
     "TestTheDaemonsMinuteSweepsAndItsStopFlushes"),
    ("the caller names the run", "server.go", 'foldNote{key: "bad-token",', 'foldNote{key: remote,', "TestAFloodOfDifferentTokensIsOneRun"),
    ("a flushed run is written again", "audit.go", "\tdelete(a.runs, key)\n\tif r.count == 0 {\n", "\tif r.count == 0 {\n",
     "TestAFlushLeavesNothingOnlyInMemory"),
    ("the folded line is not redacted", "audit.go", "\tif e.Args != nil {\n\t\te.Args = redact(e.Args)\n\t}\n", "", "TestTheFoldHoldsNoSecret"),
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
