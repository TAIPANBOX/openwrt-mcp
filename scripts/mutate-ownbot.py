#!/usr/bin/env python3
"""mutate-ownbot.py -- break the owner's approval path past the listener on purpose, and require a
named test to notice.

Each mutant below is a change to the router's own bot (ownbot.go), its Telegram client (telegram.go),
the listener's pipe (relay.go), or the refusal of the MCP approver path (approval.go, tools.go) that
would make a wrong answer silent: a tap or a factor taken from someone other than the owner, on a card
that is not its record's, with no prompt or after the prompt closed, read before it is deleted; the MCP
path left open; a certificate or a name not checked; the pipe serving anyone; the token in an error.
For each one the script copies the repository, applies the mutant, runs the test named beside it, and
requires that test to FAIL. It first runs every named test on the unmutated code and requires each to
PASS. A mutant whose text is no longer in its file is a failure, not a skip.

    ./scripts/mutate-ownbot.py            every mutant
    ./scripts/mutate-ownbot.py 3 7        just those, by number
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
    ("a tap is taken from another person", "ownbot.go",
     "if b.owner == 0 || cb.From.ID != b.owner || cb.Message.Chat.ID != b.owner ||",
     "if b.owner == 0 || cb.Message.Chat.ID != b.owner ||", "TestOnlyTheBoundChatsTapAndFactorCount"),
    ("a tap on one card is put on the record of another", "ownbot.go",
     "card.msgID != cb.Message.MessageID || b.byMsg[cb.Message.MessageID] != card.id ||", "false ||",
     "TestATapCountsOnlyOnTheCardOfItsRecord"),
    ("a tap with a forged hash is taken", "ownbot.go", "\t\tcard.hash[:16] != m[3] {", "\t\tfalse {",
     "TestATapCountsOnlyOnTheCardOfItsRecord"),
    ("a message from a chat that is not the bound one is read", "ownbot.go",
     "\tif b.owner == 0 || m.Chat.ID != b.owner {\n\t\treturn // until a chat is bound",
     "\tif b.owner == 0 {\n\t\treturn // until a chat is bound", "TestOnlyTheBoundChatsTapAndFactorCount"),
    ("a stranger's /unlock is read", "ownbot.go",
     "\tif b.owner == 0 || m.Chat.ID != b.owner {\n\t\treturn // until a chat is bound",
     "\tif b.owner == 0 {\n\t\treturn // until a chat is bound", "TestUnlockAndLockFromTheRoutersChat"),
    ("a prompt opens with no tap", "ownbot.go",
     "\t\t\tb.cards[v.ID] = &botCard{id: v.ID, hash: v.Hash, msgID: id, text: text, cut: cut}\n",
     "\t\t\tb.cards[v.ID] = &botCard{id: v.ID, hash: v.Hash, msgID: id, text: text, cut: cut}\n"
     "\t\t\tb.prompt = &botPrompt{id: v.ID, hash: v.Hash, until: b.opt.mono() + promptLife}\n",
     "TestAFactorWithNoPromptOrAfterItClosedCountsNothing"),
    ("a factor is taken after the prompt closed", "ownbot.go", "\tif b.opt.mono() >= p.until {", "\tif false {",
     "TestAFactorWithNoPromptOrAfterItClosedCountsNothing"),
    ("the factor is read before its message is deleted", "ownbot.go",
     "\tb.prompt = nil // one message per Approve\n\tb.deleteMsg(ctx, tc, m)\n",
     "\tb.prompt = nil // one message per Approve\n\tdefer b.deleteMsg(ctx, tc, m)\n",
     "TestTheFactorIsDeletedBeforeItIsRead"),
    ("the factor's message is left in the chat", "ownbot.go",
     "\tb.prompt = nil // one message per Approve\n\tb.deleteMsg(ctx, tc, m)\n",
     "\tb.prompt = nil // one message per Approve\n", "TestOnlyTheBoundChatsTapAndFactorCount"),
    ("an /unlock is left in the chat", "ownbot.go",
     "func (b *ownerBot) unlock(ctx context.Context, tc *telegramClient, m *tgMessage, text string) {\n\tb.deleteMsg(ctx, tc, m)\n",
     "func (b *ownerBot) unlock(ctx context.Context, tc *telegramClient, m *tgMessage, text string) {\n",
     "TestUnlockAndLockFromTheRoutersChat"),
    ("the card is not the record's own", "ownbot.go", "text, cut := cardMessage(v.Card)",
     "text, cut := cardMessage(v.Headline)", "TestTheCardIsTheRecordsOwnAndApprovesItsRecordOnly"),
    ("a card is sent whole, whatever its length", "ownbot.go", "text, cut := cardMessage(v.Card)",
     "text, cut := v.Card, false", "TestACardTooLongForOneMessageIsCutAndNotApproved"),
    ("a cut card keeps its Approve button", "ownbot.go",
     "\t\t\t\trow = row[1:] // a card the owner cannot read whole is not approved from the chat\n", "",
     "TestACardTooLongForOneMessageIsCutAndNotApproved"),
    ("a cut card is approved from the chat", "ownbot.go", "\t\tif card.cut {\n", "\t\tif false {\n",
     "TestACardTooLongForOneMessageIsCutAndNotApproved"),
    # The first version's fault: a refused card neither set aside nor passed, so the pass stopped at it.
    # (return in place of continue alone is now only a tick's delay: the card's own wait passes it.)
    ("one card Telegram refuses stops every card after it", "ownbot.go",
     "\t\t\t\toffline = !telegramRefused(err)\n\t\t\t\tb.later(v.ID, now)\n\t\t\t\tcontinue\n", "\t\t\t\treturn\n",
     "TestACardTelegramRefusesDoesNotHoldBackTheNext"),
    ("a card set aside is never tried again", "ownbot.go", "\tr.next = now + r.wait\n", "\tr.next = now + 1000000*time.Hour\n",
     "TestACardTelegramRefusesDoesNotHoldBackTheNext"),
    ("a card of wide characters is held", "approval.go", "if units := utf16Units(h.Card); units > maxCardUnits {",
     "if units := utf16Units(h.Card); false && units > maxCardUnits {", "TestAHeldCardMustFitOneTelegramMessage"),
    ("a binding code's own end is not read", "ownbot.go",
     "func bindEnded(ends time.Time) bool { return !ownerBotWall().Before(ends) }",
     "func bindEnded(ends time.Time) bool { return false }", "TestABindingCodeEndsOnTimeAcrossARestart"),
    ("an ended binding code is not removed as the helper starts", "ownbot.go",
     "\tb.mu.Lock()\n\tb.watchBind()\n\tb.mu.Unlock()\n\ts.bot.Store(b)\n", "\ts.bot.Store(b)\n",
     "TestABindingCodeEndsOnTimeAcrossARestart"),
    ("what arrived while the helper was not reading is used", "ownbot.go", "\t\tif !drained {", "\t\tif false && !drained {",
     "TestWhatArrivedWhileTheHelperWasNotReadingIsNotUsed"),
    ("a wrong binding code binds", "ownbot.go",
     "if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(h)) != 1 {",
     "if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(h)) != 1 && false {",
     "TestTheOwnersChatIsBoundByTheOneTimeCode"),
    ("a binding code never runs out", "ownbot.go", "\tbindCodeLife  = 30 * time.Minute",
     "\tbindCodeLife  = 100000 * time.Hour", "TestABindingCodeRunsOut"),
    ("the MCP approver path stays open with the bot bound", "ownbot.go",
     "func (s *Server) mcpApproverRefusal() error {\n\tif !s.ownerBotChannel() {",
     "func (s *Server) mcpApproverRefusal() error {\n\tif true {", "TestWithTheBotBoundNoMCPClientDecides"),
    ("action_approve over MCP is not refused with the bot bound", "approval.go",
     "\tif err := s.mcpApproverRefusal(); err != nil {\n\t\treturn \"\", \"action_approve\", err\n\t}\n", "",
     "TestWithTheBotBoundNoMCPClientDecides"),
    ("the owner's MCP client is not revoked at binding", "ownbot.go", "revoked := b.s.revokeApprovers()",
     "revoked := []string(nil)", "TestWithTheBotBoundNoMCPClientDecides"),
    ("the certificate is not checked", "telegram.go", "RootCAs: roots, MinVersion: tls.VersionTLS12}",
     "RootCAs: roots, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}",
     "TestAListenerThatAnswersInTelegramsPlaceIsRefused"),
    ("the name checked is not api.telegram.org", "telegram.go", "return &tls.Config{ServerName: telegramHost,",
     "return &tls.Config{ServerName: \"evil.example\",", "TestAListenerThatAnswersInTelegramsPlaceIsRefused"),
    ("the pipe serves any uid", "relay.go", "if err != nil || uid != r.allowUID {", "if err != nil {",
     "TestThePipeServesTheHelperOnly"),
    ("the helper speaks through a pipe that is not the listener's", "telegram.go", "if err != nil || uid != d.uid {",
     "if err != nil {", "TestTheHelperRefusesAPipeThatIsNotTheListeners"),
    ("the token is left in an error", "telegram.go", "c.scrub(unwrapURLError(err))", "err.Error()",
     "TestTheClientsErrorsHoldNoToken"),
    ("the decoder hands on an update out of bounds", "telegram.go", "\t\tif !checkUpdate(u) {", "\t\tif false {",
     "TestTelegramAnswersAreReadWithinTheirBounds"),
    ("the decoder takes more updates than it asked for", "telegram.go", "\tif len(items) > maxUpdatesPerPoll {",
     "\tif false {", "TestTelegramAnswersAreReadWithinTheirBounds"),
    ("a code is taken twice from the chat", "mfa.go", "seen && ctr <= last {", "seen && ctr < last {",
     "TestACodeIsNotTakenTwiceFromTheChat"),
    ("a token writer saves what it loaded earlier", "config.go",
     "\tif err := ts.reload(); err != nil {\n\t\treturn 0, err\n\t}\n\tts.mu.Lock()\n\tn := fn(ts.byHash)",
     "\tts.mu.Lock()\n\tn := fn(ts.byHash)", "TestTwoTokenWritersDoNotUndoEachOther"),
    ("a new bot's token keeps the old bot's chat", "owner_bot_cli.go",
     "\t\t// A new bot starts from nothing: its chat is bound again, with a new code.\n\t\tf.remove(\"chat\")\n",
     "\t\t// A new bot starts from nothing: its chat is bound again, with a new code.\n",
     "TestTheOwnerBotCommandLine"),
    ("Reject in the chat rejects nothing", "ownbot.go", "if _, _, err := b.s.rejectHeld(approverRef{}, card.id); err != nil {",
     "if err := error(nil); err != nil {", "TestRejectAndWithdrawCloseTheirCards"),
    ("the drain at start keeps asking, and takes a new message for backlog", "ownbot.go",
     "\t\tif len(ups) < maxUpdatesPerPoll {\n\t\t\treturn nil\n\t\t}\n", "",
     "TestTheFirstMessageAfterBindingIsRead"),
    ("a token Telegram does not know is not told as token_rejected", "ownbot.go",
     "\tcase errors.As(err, &te) && te.code == 401:\n", "\tcase false:\n", "TestTheBotsFailureIsOneWordOfAFixedSet"),
    ("a certificate that fails is told as the network", "ownbot.go",
     "\t\terrors.As(err, &ae), errors.As(err, &he):\n\t\treturn \"tls\"\n",
     "\t\terrors.As(err, &ae), errors.As(err, &he):\n\t\treturn \"network\"\n", "TestTheBotsFailureIsOneWordOfAFixedSet"),
    ("a pipe that is not the listener's is told as the network", "ownbot.go",
     "\tcase errors.As(err, &pe):\n\t\treturn \"pipe\"\n", "\tcase errors.As(err, &pe):\n\t\treturn \"network\"\n",
     "TestTheBotsFailureIsOneWordOfAFixedSet"),
    ("a seen file's text is shown as it came", "ownbot.go",
     "\t\ts.Failure = \"other\" // a file this binary did not write as it writes it\n", "",
     "TestTheBotsFailureIsOneWordOfAFixedSet"),
    ("a failure written as the error's text", "ownbot.go", "\t\ts.Failure = botFailure(err)\n",
     "\t\ts.Failure = printable(err.Error())\n", "TestTheBotsTokenIsInNoErrorAndNoFile"),
    ("mfa_lock for another client over MCP is not refused with the bot bound", "tools.go",
     "\t\t\t\tif err := s.mcpApproverRefusal(); err != nil {\n\t\t\t\t\treturn \"\", \"mfa_lock\", err\n\t\t\t\t}\n", "",
     "TestWithTheBotBoundNoMCPClientDecides"),
    ("mfa_unlock for another client over MCP is not refused with the bot bound", "tools.go",
     "\t\tif err := s.mcpApproverRefusal(); err != nil {\n\t\t\treturn \"\", &unlockRefusal{err.(*refusedError), caller}\n\t\t}\n",
     "", "TestWithTheBotBoundNoMCPClientDecides"),
]


def go_test(where, tests):
    pattern = "^(" + "|".join(sorted(set(tests))) + ")$"
    p = subprocess.run(["go", "test", "-count=1", "-run", pattern, "."], cwd=where, capture_output=True, text=True,
                       timeout=900)
    return p.returncode, p.stdout + p.stderr


def copy_repo():
    tmp = tempfile.mkdtemp(prefix="mutate-ownbot-")
    dst = os.path.join(tmp, "repo")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(".git", "*.ipk", "*.apk", "openwrt-mcp.amd64", "openwrt-mcp.arm64"))
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
    print(f"mutate-ownbot: {len(picked)} mutants, each caught by the test named for it")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
