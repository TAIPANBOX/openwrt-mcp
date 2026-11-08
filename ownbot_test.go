package main

// The router's own bot (ownbot.go) driven through a Telegram stand-in and the listener's pipe, as the
// owner and as strangers. Each test that shows a refusal also shows the same act working from the
// owner, so a check that refuses everything cannot pass.

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// The owner's chat is bound by the one-time code from the router, and by nothing else: not a wrong
// code, not the right code in a group, not a stranger. Until then the bot answers nobody, and the
// code binds once.
func TestTheOwnersChatIsBoundByTheOneTimeCode(t *testing.T) {
	r := newBotRig(t, "")
	code := r.bindCode()
	r.tg.say(777, 777, "private", "/start "+strings.Repeat("A", 22))
	r.tg.say(777, 777, "private", "hello")
	r.tg.say(testOwner, -100123, "group", "/start "+code)
	r.tg.say(testOwner, testOwner, "private", "/start")
	never(t, "the bot answered someone before a chat was bound", 1500*time.Millisecond, func() bool {
		return len(r.tg.sentTo(777))+len(r.tg.sentTo(-100123))+len(r.tg.sentTo(testOwner)) > 0
	})
	if c := ownerBotFilesOf(r.state).chat(); c != 0 {
		t.Fatalf("a chat was bound without the code from its own private chat: %d", c)
	}

	r.tg.say(testOwner, testOwner, "private", "/start "+code)
	waitFor(t, "the owner's chat to be bound", 10*time.Second, func() bool {
		return ownerBotFilesOf(r.state).chat() == testOwner
	})
	r.waitText(testOwner, 0, "This chat now approves changes for")
	if ownerBotFilesOf(r.state).bindHash() != "" {
		t.Error("the binding code is still waiting after it was used")
	}
	if st := ownerBotStatusOf(r.state); !st.Bound || st.Channel != "bot" || st.Bot != "router_test_bot" {
		t.Errorf("status does not say the chat is bound: %+v", st)
	}

	// The code is spent: another chat that sends it takes nothing over, and gets no answer.
	r.tg.say(888, 888, "private", "/start "+code)
	never(t, "a spent code bound another chat", time.Second, func() bool {
		return ownerBotFilesOf(r.state).chat() != testOwner || len(r.tg.sentTo(888)) > 0
	})
}

// The card in the owner's chat is the record's own card, byte for byte, with Approve and Reject; one
// tap and one message with the PIN and the code approve that record and no other.
func TestTheCardIsTheRecordsOwnAndApprovesItsRecordOnly(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	b := r.heldUbus("info")
	card := r.cardOf(a)
	v, _ := r.s.heldView(a)
	if card.Text != v.Card {
		t.Fatalf("the card in the chat is not the record's card:\n%q\n%q", card.Text, v.Card)
	}
	if len(card.Keyboard) != 1 || len(card.Keyboard[0]) != 2 || card.Keyboard[0][0].Text != "Approve" ||
		card.Keyboard[0][1].Text != "Reject" {
		t.Fatalf("the card's buttons are not Approve and Reject: %+v", card.Keyboard)
	}
	if got := r.approveInChat(a, apPIN+" "+r.code(time.Now())); !strings.HasPrefix(got, "Applied "+a) {
		t.Fatalf("the owner's approval did not apply %s: %q", a, got)
	}
	if !r.ran("board") || r.ran("info") {
		t.Fatalf("approving %s ran %q", a, r.ubusCalls())
	}
	if vb, _ := r.s.heldView(b); vb.Status != statusHeld {
		t.Fatalf("approving %s moved %s to %s", a, b, vb.Status)
	}
	waitFor(t, "the card to say it was applied", 10*time.Second, func() bool {
		for _, m := range r.tg.sentTo(testOwner) {
			if m.ID == card.ID {
				return m.Edited && strings.HasSuffix(m.Text, "APPLIED.") && len(m.Keyboard) == 0
			}
		}
		return false
	})
}

// A tap and a factor count only from the bound chat: another person's tap on the owner's card, a tap
// in a group, and a PIN and code from someone else, even while the owner's prompt is open, do nothing
// and count nothing. The owner's own tap and factor then work.
func TestOnlyTheBoundChatsTapAndFactorCount(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	card := r.cardOf(a)
	approve := card.Keyboard[0][0].Data
	code := r.code(time.Now())
	n := len(r.tg.sentTo(testOwner))
	r.tg.tapIn(777, testOwner, "private", card.ID, approve)
	r.tg.tapIn(777, 777, "private", card.ID, approve)
	r.tg.tapIn(testOwner, -100123, "group", card.ID, approve)
	r.tg.say(777, 777, "private", apPIN+" "+code)
	never(t, "a stranger's tap opened a prompt, or a stranger's factor was tried", 1500*time.Millisecond, func() bool {
		return len(r.tg.sentTo(testOwner)) > n || len(r.tg.sentTo(777)) > 0 || r.ran("board") || r.failures() > 0
	})

	r.tg.tap(testOwner, card.ID, approve)
	r.waitText(testOwner, n, "Approve "+a)
	r.tg.say(777, 777, "private", apPIN+" "+code)
	never(t, "a stranger answered the owner's prompt", time.Second, func() bool { return r.ran("board") || r.failures() > 0 })
	msg := r.tg.say(testOwner, testOwner, "private", apPIN+" "+code)
	waitFor(t, "the owner's factor to apply the change", 10*time.Second, func() bool { return r.ran("board") })
	if !r.tg.wasDeleted(msg) {
		t.Error("the owner's factor was left in the chat")
	}
}

// A tap counts only on the message the helper sent for that record: another record's button data, or
// a forged hash, on a card opens no prompt, and a factor with no prompt open tries nothing.
func TestATapCountsOnlyOnTheCardOfItsRecord(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	b := r.heldUbus("info")
	ca, cb := r.cardOf(a), r.cardOf(b)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, ca.ID, cb.Keyboard[0][0].Data)
	r.tg.tap(testOwner, ca.ID, "a:"+a+":0000000000000000")
	r.tg.tap(testOwner, ca.ID, "a:"+a)
	never(t, "a prompt opened from a button that is not its card's", 1500*time.Millisecond, func() bool {
		return len(r.tg.sentTo(testOwner)) > n
	})
	msg := r.tg.say(testOwner, testOwner, "private", apPIN+" "+r.code(time.Now()))
	r.waitText(testOwner, n, "That was not used")
	if !r.tg.wasDeleted(msg) || r.ran("board") || r.ran("info") || r.failures() != 0 {
		t.Fatalf("a factor with no prompt open was tried: ran %q, failures %d", r.ubusCalls(), r.failures())
	}
	if got := r.approveInChat(a, apPIN+" "+r.code(time.Now())); !strings.HasPrefix(got, "Applied "+a) || r.ran("info") {
		t.Fatalf("A's own button did not approve A alone: %q, ran %q", got, r.ubusCalls())
	}
}

// The factor's message is deleted before it is read: while the deletion has not been answered,
// nothing is tried and nothing runs.
func TestTheFactorIsDeletedBeforeItIsRead(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	card := r.cardOf(a)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	r.waitText(testOwner, n, "Approve "+a)
	release := r.tg.holdDeletes()
	defer release()
	msg := r.tg.say(testOwner, testOwner, "private", apPIN+" "+r.code(time.Now()))
	waitFor(t, "the factor's deletion to be asked for", 10*time.Second, func() bool { return r.tg.deleteAsked(msg) })
	never(t, "the factor was read before its message was deleted", time.Second, func() bool {
		return r.ran("board") || r.failures() > 0
	})
	release()
	waitFor(t, "the change to run once the message is gone", 10*time.Second, func() bool { return r.ran("board") })
}

// A message that looks like a factor with no prompt open, or after the prompt closed, is deleted and
// tries nothing. The same PIN and code then approve, so neither was spent.
func TestAFactorWithNoPromptOrAfterItClosedCountsNothing(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	card := r.cardOf(a)
	factor := apPIN + " " + r.code(time.Now())
	n := len(r.tg.sentTo(testOwner))
	m1 := r.tg.say(testOwner, testOwner, "private", factor)
	r.waitText(testOwner, n, "That was not used")
	if !r.tg.wasDeleted(m1) {
		t.Error("a factor with no prompt open was left in the chat")
	}

	n = len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	r.waitText(testOwner, n, "Approve "+a)
	r.mono.add(promptLife + time.Second)
	n = len(r.tg.sentTo(testOwner))
	m2 := r.tg.say(testOwner, testOwner, "private", factor)
	r.waitText(testOwner, n, "had closed")
	if !r.tg.wasDeleted(m2) || r.ran("board") || r.failures() != 0 {
		t.Fatalf("a factor after the prompt closed was tried, or left: ran %q, failures %d", r.ubusCalls(), r.failures())
	}

	if got := r.approveInChat(a, factor); !strings.HasPrefix(got, "Applied "+a) {
		t.Fatalf("the PIN and code that were not used did not approve: %q", got)
	}
}

// A code that approved one change approves no other: its step is spent.
func TestACodeIsNotTakenTwiceFromTheChat(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	b := r.heldUbus("info")
	code := r.code(time.Now())
	if got := r.approveInChat(a, apPIN+" "+code); !strings.HasPrefix(got, "Applied "+a) {
		t.Fatalf("the first approval did not apply: %q", got)
	}
	if got := r.approveInChat(b, apPIN+" "+code); !strings.HasPrefix(got, "Not approved") {
		t.Fatalf("a spent code approved a second change: %q", got)
	}
	if r.ran("info") {
		t.Fatal("the second change ran on a spent code")
	}
}

// A card whose record expired cannot be approved: the card says so, a tap on it opens nothing, and a
// prompt opened before it expired takes no factor.
func TestAnExpiredCardCannotBeApproved(t *testing.T) {
	r := newBotRig(t, botApproval+"\toption ttl '2s'\n")
	r.bind()
	a := r.heldUbus("board")
	card := r.cardOf(a)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	r.waitText(testOwner, n, "Approve "+a)
	waitFor(t, "the card to say it expired", 15*time.Second, func() bool {
		for _, m := range r.tg.sentTo(testOwner) {
			if m.ID == card.ID {
				return strings.HasSuffix(m.Text, "EXPIRED: nobody approved it in time.")
			}
		}
		return false
	})
	n = len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", apPIN+" "+r.code(time.Now()))
	r.waitText(testOwner, n, "That was not used")
	n = len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	never(t, "a tap on an expired card opened a prompt", time.Second, func() bool {
		ms := r.tg.sentTo(testOwner)
		return len(ms) > n && strings.Contains(ms[len(ms)-1].Text, "Approve "+a)
	})
	if r.ran("board") || r.failures() != 0 {
		t.Fatalf("an expired change was tried: ran %q, failures %d", r.ubusCalls(), r.failures())
	}
}

// Once the chat is bound no MCP client decides anything for an approval section: the owner's client
// lists, approves, rejects, unlocks and locks nothing, counting nothing, and its token is revoked at
// the moment of binding. Before binding the same client lists, as it always did.
func TestWithTheBotBoundNoMCPClientDecides(t *testing.T) {
	r := newBotRig(t, "")
	a := r.heldUbus("board")
	if out, isErr := callTool(t, r.s, "owner", "action_list", map[string]any{}); isErr || !strings.Contains(out, a) {
		t.Fatalf("before binding, the owner's client does not list: %s", out)
	}
	r.bind()
	if contains(r.s.tokens.Clients(), "owner") {
		t.Error("the owner's MCP client is still paired after the router's chat was bound")
	}
	h := r.action2(a)
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"action_list", map[string]any{}},
		{"action_approve", map[string]any{"id": a, "hash": h, "pin": apPIN, "code": r.code(time.Now())}},
		{"action_reject", map[string]any{"id": a}},
		{"mfa_unlock", map[string]any{"client": "a", "pin": apPIN}},
		{"mfa_lock", map[string]any{"client": "a"}},
	} {
		out, isErr := callTool(t, r.s, "owner", c.tool, c.args)
		if !isErr || !strings.Contains(out, "router's own Telegram chat") {
			t.Errorf("%s from the owner's MCP client was not refused: %s", c.tool, out)
		}
	}
	if v, _ := r.s.heldView(a); v.Status != statusHeld || r.ran("board") || r.failures() != 0 {
		t.Fatalf("an MCP client decided or tried: %s, ran %q, failures %d", v.Status, r.ubusCalls(), r.failures())
	}
	if _, open := r.s.mfa.UnlockedUntil("a", time.Now()); open {
		t.Fatal("an MCP client opened a's window")
	}
}

// action2 is the record's whole hash, read from the helper's own record.
func (r *botRig) action2(id string) string {
	v, ok := r.s.heldView(id)
	if !ok {
		r.t.Fatalf("no record %s", id)
	}
	return v.Hash
}

// A binding code lives for 30 minutes of the helper's own clock from when it first sees it, then is
// removed and binds nothing. A fresh code then binds.
func TestABindingCodeRunsOut(t *testing.T) {
	r := newBotRig(t, "")
	code := r.bindCode()
	r.bot.signal()
	waitFor(t, "the helper to see the code", 10*time.Second, func() bool {
		r.bot.mu.Lock()
		defer r.bot.mu.Unlock()
		return len(r.bot.bindSeen) == 1
	})
	// The life is 30 minutes, said here as a number: a test that read the constant would move with it.
	r.mono.add(29 * time.Minute)
	r.bot.signal()
	never(t, "the code was removed before its 30 minutes", time.Second, func() bool { return ownerBotFilesOf(r.state).bindHash() == "" })
	r.mono.add(time.Minute)
	r.bot.signal()
	waitFor(t, "the code to be removed", 10*time.Second, func() bool { return ownerBotFilesOf(r.state).bindHash() == "" })
	r.tg.say(testOwner, testOwner, "private", "/start "+code)
	never(t, "a code that ran out bound a chat", 1500*time.Millisecond, func() bool {
		return ownerBotFilesOf(r.state).chat() != 0 || len(r.tg.sentTo(testOwner)) > 0
	})
	r.bind()
}

// /unlock PIN opens the agent's window from the router's chat, deleted first; a stranger's does
// nothing; /lock closes it and rejects what waits.
func TestUnlockAndLockFromTheRoutersChat(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	r.tg.say(777, 777, "private", "/unlock "+apPIN)
	never(t, "a stranger's /unlock opened the window", time.Second, func() bool {
		_, open := r.s.mfa.UnlockedUntil("a", time.Now())
		return open || r.failures() > 0
	})
	n := len(r.tg.sentTo(testOwner))
	m := r.tg.say(testOwner, testOwner, "private", "/unlock "+apPIN)
	r.waitText(testOwner, n, "Unlocked a until")
	if _, open := r.s.mfa.UnlockedUntil("a", time.Now()); !open || !r.tg.wasDeleted(m) {
		t.Fatalf("/unlock did not open the window, or stayed in the chat")
	}
	a := r.heldUbus("board")
	card := r.cardOf(a)
	n = len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", "/lock")
	r.waitText(testOwner, n, "Locked.")
	if _, open := r.s.mfa.UnlockedUntil("a", time.Now()); open {
		t.Fatal("/lock left the window open")
	}
	waitFor(t, "the card to say it was rejected", 10*time.Second, func() bool {
		for _, m := range r.tg.sentTo(testOwner) {
			if m.ID == card.ID {
				return strings.HasSuffix(m.Text, "REJECTED.")
			}
		}
		return false
	})
}

// What reached the bot while the helper was not reading is not taken as an answer: a factor and an
// /unlock sent then are deleted, the owner is told once, nothing is tried, and the card of what waits
// goes out once the helper reads again.
func TestWhatArrivedWhileTheHelperWasNotReadingIsNotUsed(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	r.cancel()
	waitFor(t, "the old bot to stop reading", 30*time.Second, func() bool { return r.tg.polling.Load() == 0 })
	time.Sleep(100 * time.Millisecond)
	a := r.heldUbus("board")
	m1 := r.tg.say(testOwner, testOwner, "private", apPIN+" "+r.code(time.Now()))
	m2 := r.tg.say(testOwner, testOwner, "private", "/unlock "+apPIN)
	n := len(r.tg.sentTo(testOwner))
	r.runBot()
	r.waitText(testOwner, n, "was not used")
	r.cardOf(a)
	if !r.tg.wasDeleted(m1) || !r.tg.wasDeleted(m2) {
		t.Error("a factor sent while the helper was not reading was left in the chat")
	}
	if _, open := r.s.mfa.UnlockedUntil("a", time.Now()); open || r.ran("board") || r.failures() != 0 {
		t.Fatalf("what arrived while the helper was not reading was used: ran %q, failures %d", r.ubusCalls(), r.failures())
	}
}

// The bot's token is in no error the helper writes, in its log or in the file status reads, even when
// the transport fails with the URL, which holds the token, in its own error.
func TestTheBotsTokenIsInNoErrorAndNoFile(t *testing.T) {
	r := newBotRig(t, "")
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	r.pipe.target.Store("127.0.0.1:1") // nothing answers there
	r.ownerBot(testBotToken+"\n", "set")
	waitFor(t, "the bot to note its error", 15*time.Second, func() bool { return ownerBotFilesOf(r.state).seen().Error != "" })
	seen, _ := os.ReadFile(ownerBotFilesOf(r.state).path("seen"))
	var st bytes.Buffer
	json.NewEncoder(&st).Encode(ownerBotStatusOf(r.state))
	for what, b := range map[string][]byte{"the seen file": seen, "the log": logged.Bytes(), "status": st.Bytes()} {
		if bytes.Contains(b, []byte(testBotToken)) || bytes.Contains(b, []byte("TEST-not-a-real-token")) {
			t.Errorf("%s holds the bot's token: %s", what, b)
		}
	}
	if !strings.Contains(string(seen), "telegram get") {
		t.Errorf("the error does not say what failed: %s", seen)
	}
}

// status --json names the guarantee, and says where each client's held changes are approved.
func TestStatusSaysWhereHeldChangesAreApproved(t *testing.T) {
	if !capabilities()["owner_approves_past_the_listener"] {
		t.Fatal("status does not name owner_approves_past_the_listener")
	}
	r := newBotRig(t, "")
	read := func() statusReport {
		out := captureStdout(t, func() {
			if err := runStatus(r.cfgFile, r.state, 0, true); err != nil {
				t.Fatal(err)
			}
		})
		var rep statusReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return rep
	}
	approvalOf := func(rep statusReport) *approvalReport {
		for _, c := range rep.Clients {
			if c.Name == "owner" || c.Approval == nil {
				continue
			}
			return c.Approval
		}
		return nil
	}
	if _, err := r.s.tokens.Mint("a"); err != nil {
		t.Fatal(err)
	}
	rep := read()
	if a := approvalOf(rep); a == nil || a.Channel != "mcp" || !a.Ready || rep.OwnerBot.Channel != "mcp" {
		t.Fatalf("before the bot, status does not say the owner's client approves: %+v %+v", a, rep.OwnerBot)
	}
	r.bind()
	rep = read()
	if a := approvalOf(rep); a == nil || a.Channel != "bot" || !a.Ready || !rep.OwnerBot.Bound {
		t.Fatalf("with the bot bound, status does not say the router's chat approves: %+v %+v", a, rep.OwnerBot)
	}
}

// Two writers of the token file do not undo each other: `pair` on the router and the helper's revoke
// at binding each write from what the file holds at that moment.
func TestTwoTokenWritersDoNotUndoEachOther(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/tokens"
	one, _ := LoadTokens(p)
	if _, err := one.Mint("owner"); err != nil {
		t.Fatal(err)
	}
	two, _ := LoadTokens(p) // a second process, loaded now
	if _, err := one.Mint("agent"); err != nil {
		t.Fatal(err)
	}
	if n := two.Revoke("owner"); n != 1 {
		t.Fatalf("the revoke found %d tokens", n)
	}
	got, _ := LoadTokens(p)
	if cs := got.Clients(); !contains(cs, "agent") || contains(cs, "owner") {
		t.Fatalf("the file holds %v: one writer undid the other", cs)
	}
}

// Reject is one tap and takes no factor; a change the agent withdraws closes its card too.
func TestRejectAndWithdrawCloseTheirCards(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	b := r.heldUbus("info")
	ca, cb := r.cardOf(a), r.cardOf(b)
	r.tg.tap(testOwner, ca.ID, ca.Keyboard[0][1].Data)
	if out, isErr := callTool(t, r.s, "a", "action_withdraw", map[string]any{"id": b}); isErr {
		t.Fatalf("the agent could not withdraw %s: %s", b, out)
	}
	for id, want := range map[int64]string{ca.ID: "REJECTED.", cb.ID: "WITHDRAWN by a."} {
		waitFor(t, "the card to say "+want, 10*time.Second, func() bool {
			for _, m := range r.tg.sentTo(testOwner) {
				if m.ID == id {
					return strings.HasSuffix(m.Text, want) && len(m.Keyboard) == 0
				}
			}
			return false
		})
	}
	if v, _ := r.s.heldView(a); v.Status != statusRejected || r.ran("board") || r.failures() != 0 {
		t.Fatalf("Reject did not reject alone: %s, ran %q, failures %d", v.Status, r.ubusCalls(), r.failures())
	}
}

// An /unlock that is not of the shape unlocking takes, or names no such client, tries nothing; a wrong
// PIN is a real try and counts.
func TestAnUnlockOfTheWrongShapeTriesNothing(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	for text, want := range map[string]string{"/unlock 12": "not what unlocking takes", "/unlock nosuch " + apPIN: "No client"} {
		n := len(r.tg.sentTo(testOwner))
		m := r.tg.say(testOwner, testOwner, "private", text)
		r.waitText(testOwner, n, want)
		if !r.tg.wasDeleted(m) || r.failures() != 0 {
			t.Fatalf("%q was left in the chat or counted a try: failures %d", text, r.failures())
		}
	}
	n := len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", "/unlock 4822")
	r.waitText(testOwner, n, "Not unlocked")
	if r.failures() != 1 {
		t.Fatalf("a wrong PIN counted %d tries, not 1", r.failures())
	}
}

// The CLI takes a token only of a token's shape, from standard input; the same token again changes
// nothing, a new one drops the bound chat, so a new bot is bound again; bind needs a token; clear
// gives the approval back to the owner's client.
func TestTheOwnerBotCommandLine(t *testing.T) {
	r := newBotRig(t, "")
	var out bytes.Buffer
	if err := runOwnerBot(&out, strings.NewReader("not-a-token\n"), r.state, []string{"set"}); err == nil {
		t.Fatal("a token of the wrong shape was taken")
	}
	if err := runOwnerBot(&out, strings.NewReader(""), r.state, []string{"bind"}); err == nil {
		t.Fatal("bind made a code with no token set")
	}
	r.bind()
	if !strings.Contains(r.ownerBot(testBotToken+"\n", "set"), "nothing changed") || ownerBotFilesOf(r.state).chat() != testOwner {
		t.Fatal("the same token again dropped the bound chat")
	}
	if st := r.ownerBot("", "status"); !strings.Contains(st, "bound to chat 4242") || !strings.Contains(st, "@router_test_bot") {
		t.Fatalf("status does not say the chat is bound: %s", st)
	}
	r.ownerBot("987654321:ANOTHER-test-token-AAAAAAAAAAAAAAAAAA\n", "set")
	if f := ownerBotFilesOf(r.state); f.chat() != 0 || f.token() == testBotToken {
		t.Fatal("a new token kept the old bot's chat")
	}
	if !strings.Contains(r.ownerBot("", "status"), "no chat bound yet") {
		t.Fatal("status does not say a new token waits for its chat")
	}
	r.ownerBot("", "clear")
	if st := ownerBotStatusOf(r.state); st.Configured || st.Bound || st.Channel != "mcp" {
		t.Fatalf("clear left the bot: %+v", st)
	}
	if mode := fileMode(t, ownerBotFilesOf(r.state).dir); mode != 0o700 {
		t.Errorf("the bot's directory is %o, not 0700", mode)
	}
}

func fileMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}
