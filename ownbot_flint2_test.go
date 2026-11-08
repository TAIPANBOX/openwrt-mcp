package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ownerBotEventSent says whether the router was told, over ubus, that the owner's chat changed.
func ownerBotEventSent(calls []string, state string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, "call service event ") && strings.Contains(c, `"type":"openwrt-mcp.owner_bot"`) &&
			strings.Contains(c, `"state":"`+state+`"`) {
			return true
		}
	}
	return false
}

// Once the owner's chat is bound, the router itself is told, so the agent restarts to leave the
// approval path whether or not the page that set the bot up is still open: procd restarts it on this
// event (hermes-openwrt's init has the trigger).
func TestBindingTellsTheRouterTheChatIsBound(t *testing.T) {
	// A client of status (LuCI) learns from this that it need not restart the agent itself.
	if !capabilities()["owner_bot_tells_the_router"] {
		t.Fatal("status does not name owner_bot_tells_the_router")
	}
	r := newBotRig(t, "")
	if ownerBotEventSent(r.ubusLog(), "bound") {
		t.Fatal("the router was told of a bound chat before any chat was bound")
	}
	r.bind()
	waitFor(t, "the router to be told the chat is bound", 10*time.Second, func() bool {
		return ownerBotEventSent(r.ubusLog(), "bound")
	})
}

// Removing the bot, or giving it a new token, which drops the bound chat, tells the router too, so the
// agent restarts to take the approval path back.
func TestRemovingTheBotTellsTheRouter(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	r.ownerBot("", "clear")
	if !ownerBotEventSent(r.ubusLog(), "cleared") {
		t.Fatalf("clearing the bot told the router nothing: %q", r.ubusLog())
	}
	r2 := newBotRig(t, "")
	r2.bind()
	r2.ownerBot("123456789:ANOTHER-test-token-AAAAAAAAAAAAAAAAAAA\n", "set")
	if !ownerBotEventSent(r2.ubusLog(), "cleared") {
		t.Fatalf("a new token dropped the bound chat and told the router nothing: %q", r2.ubusLog())
	}
}

// The agent's answer to a held change, once the router's bot is bound, sends the owner to the card in
// the router's own chat: tap Approve, then the PIN and the code. It never says the agent will be told,
// since with the bot nobody tells it, and it never sends the owner to /unlock for it.
func TestTheHeldAnswerSendsTheOwnerToTheCard(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	r.unlock()
	r.setAfter("system", strings.Replace(apSystem, "'0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'", "'time.cloudflare.com'", 1))
	out, isErr := r.apply(map[string]any{"config": "system", "section": "ntp", "option": "server", "value": "time.cloudflare.com"})
	r.mustHold(out, isErr)
	for _, want := range []string{"router's own Telegram chat", "tap Approve", "PIN", "code from their authenticator app", "action_status"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the held answer does not say %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"you will be told", "with /unlock"} {
		if strings.Contains(out, not) && !strings.Contains(out, "/unlock does not approve") {
			t.Fatalf("the held answer says %q:\n%s", not, out)
		}
	}
	// Without the bot the answer is as it was.
	a := newApRig(t, apApproval)
	a.start()
	a.unlock()
	a.setAfter("system", strings.Replace(apSystem, "'0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'", "'time.cloudflare.com'", 1))
	out2, isErr2 := a.apply(map[string]any{"config": "system", "section": "ntp", "option": "server", "value": "time.cloudflare.com"})
	a.mustHold(out2, isErr2)
	if !strings.Contains(out2, "you will be told the outcome") || strings.Contains(out2, "tap Approve") {
		t.Fatalf("without the bot the held answer changed:\n%s", out2)
	}
}

// Each card the bot sends, and each it closes, is a line in the log, so the router's log says whether
// a held change reached the owner's chat.
func TestEachCardIsALineInTheLog(t *testing.T) {
	var mu sync.Mutex
	var logged bytes.Buffer
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logged.Write(p) }))
	defer log.SetOutput(os.Stderr)
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	r.cardOf(a)
	waitFor(t, "the log to say the card was sent", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(logged.String(), "sent the card of "+a)
	})
	if out, isErr := callTool(t, r.s, "a", "action_withdraw", map[string]any{"id": a}); isErr {
		t.Fatalf("withdraw: %s", out)
	}
	waitFor(t, "the log to say the card was closed", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(logged.String(), "the card of "+a+" now says")
	})
	r.cancel()
	for _, b := range r.bots {
		b.wait()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// tapApprove taps Approve on the card of id and returns the prompt the bot answered with.
func (r *botRig) tapApprove(id string) string {
	r.t.Helper()
	card := r.cardOf(id)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	return r.waitText(testOwner, n, "Approve "+id)
}

// The owner may send the PIN first and the code in a second message, while the same prompt lasts:
// each message is deleted before it is read, and the two are tried once, together.
func TestAFactorInTwoMessagesApproves(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	r.tapApprove(a)
	n := len(r.tg.sentTo(testOwner))
	m1 := r.tg.say(testOwner, testOwner, "private", apPIN)
	r.waitText(testOwner, n, "Now the 6 digits")
	if !r.tg.wasDeleted(m1) || r.ran("board") || r.failures() != 0 {
		t.Fatalf("the PIN alone was left in the chat, or tried: deleted %v, ran %q, failures %d", r.tg.wasDeleted(m1), r.ubusCalls(), r.failures())
	}
	n = len(r.tg.sentTo(testOwner))
	m2 := r.tg.say(testOwner, testOwner, "private", r.code(time.Now()))
	got := r.waitText(testOwner, n, "Applied "+a)
	if !r.tg.wasDeleted(m2) || !r.ran("board") {
		t.Fatalf("the code after the PIN did not approve, or was left: %q", got)
	}
}

// The code may be typed as the authenticator app shows it, split by a space: "305 917".
func TestACodeSplitAsTheAppShowsItApproves(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	b := r.heldUbus("info")
	c := r.code(time.Now())
	if got := r.approveInChat(a, apPIN+" "+c[:3]+" "+c[3:]); !strings.HasPrefix(got, "Applied "+a) {
		t.Fatalf("a code split as the app shows it did not approve: %q", got)
	}
	r.tapApprove(b)
	n := len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", apPIN)
	r.waitText(testOwner, n, "Now the 6 digits")
	n = len(r.tg.sentTo(testOwner))
	c2 := r.code(time.Now().Add(30 * time.Second))
	r.tg.say(testOwner, testOwner, "private", c2[:3]+" "+c2[3:])
	r.waitText(testOwner, n, "Applied "+b)
}

// Two messages are one try in one window: a code after the prompt closed tries nothing, a wrong code
// after the PIN counts one try, and a code with no PIN before it tries nothing.
func TestTwoMessagesAreOneTryInOneWindow(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	// The PIN halfway through the prompt does not renew it: the code is due when the prompt was.
	r.tapApprove(a)
	r.mono.add(promptLife/2 + 10*time.Second)
	n := len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", apPIN)
	r.waitText(testOwner, n, "Now the 6 digits")
	r.mono.add(promptLife/2 + 10*time.Second)
	n = len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", r.code(time.Now()))
	r.waitText(testOwner, n, "had closed")
	if r.ran("board") || r.failures() != 0 {
		t.Fatalf("a code after the prompt closed was tried: ran %q, failures %d", r.ubusCalls(), r.failures())
	}

	r.tapApprove(a)
	n = len(r.tg.sentTo(testOwner))
	r.tg.say(testOwner, testOwner, "private", apPIN)
	r.waitText(testOwner, n, "Now the 6 digits")
	n = len(r.tg.sentTo(testOwner))
	wrong := "000000"
	if r.code(time.Now()) == wrong || r.code(time.Now().Add(-30*time.Second)) == wrong {
		wrong = "111111"
	}
	r.tg.say(testOwner, testOwner, "private", wrong)
	r.waitText(testOwner, n, "Not approved")
	if r.ran("board") || r.failures() != 1 {
		t.Fatalf("a wrong code after the PIN: ran %q, failures %d, want one try", r.ubusCalls(), r.failures())
	}

	r.tapApprove(a)
	n = len(r.tg.sentTo(testOwner))
	c := r.code(time.Now())
	r.tg.say(testOwner, testOwner, "private", c[:3]+" "+c[3:])
	r.waitText(testOwner, n, "That was not a PIN and a code")
	if r.ran("board") || r.failures() != 1 {
		t.Fatalf("a code with no PIN was tried: ran %q, failures %d", r.ubusCalls(), r.failures())
	}
}

// After Approve the bot says exactly what to send: the PIN, a space and the six digits of the app's
// entry for this client on this router, in one message, with an example.
func TestThePromptSaysWhatToSend(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	got := r.tapApprove(a)
	entry := "openwrt-mcp, a@" + r.bot.host
	for _, want := range []string{"your PIN, a space and the 6 digits", entry, "in one message", "for example 482193 305917"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the prompt does not say %q:\n%s", want, got)
		}
	}
}

// The factor's shapes: a code whole or as the app shows it, and nothing looser.
func TestAFactorIsReadWholeOrAsTheAppShowsIt(t *testing.T) {
	for text, want := range map[string]bool{
		"4821 305917": true, "4821 305 917": true, "4821  305\t917": true,
		"4821 30 5917": false, "4821 3059 17": false, "4821 305 91 7": false, "305 917": false,
	} {
		if _, ok := parseFactor(text, factorPINTOTP); ok != want {
			t.Errorf("parseFactor(%q, pin+totp) = %v, want %v", text, ok, want)
		}
	}
	for text, want := range map[string]bool{"305917": true, "305 917": true, "30 5917": false} {
		if _, ok := parseFactor(text, factorTOTP); ok != want {
			t.Errorf("parseFactor(%q, totp) = %v, want %v", text, ok, want)
		}
	}
	if !looksLikeFactor("4821 305 917") {
		t.Error("a PIN and a code split as the app shows it is not taken for a factor, so it would be left in the chat")
	}
}
