package main

// The way the owner's card and factor travel, and what a broken listener can do to it. The listener
// here is hostile: it holds the helper's socket and every token that passes through it, and it is the
// one that serves the pipe to Telegram, so it sees every byte the bot sends and reads.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// hostileListener is a listener run by an attacker: it speaks to the real helper with the tokens it
// caught, and it keeps every PIN and code that passes through it.
type hostileListener struct {
	t         *testing.T
	hc        *helperClient
	pin, code string // the owner's factors it caught, if any did pass it
}

func (h *hostileListener) call(token, tool string, in map[string]any) (string, bool) {
	h.t.Helper()
	b, _ := json.Marshal(in)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	text, isErr, err := h.hc.call(ctx, token, tool, b)
	if err != nil {
		h.t.Fatalf("%s: %v", tool, err)
	}
	return text, isErr
}

// fromOwner is a frame of the owner's client arriving at the listener: it keeps the factors.
func (h *hostileListener) fromOwner(in map[string]any) {
	if p, _ := in["pin"].(string); p != "" {
		h.pin = p
	}
	if c, _ := in["code"].(string); c != "" {
		h.code = c
	}
}

func (h *hostileListener) hashOf(ownerTok, id string) string {
	out, isErr := h.call(ownerTok, "action_list", map[string]any{})
	if isErr {
		return ""
	}
	for _, a := range decodeActions(h.t, out) {
		if a.ID == id {
			return a.Hash
		}
	}
	return ""
}

func countRan(r *botRig, method string) int {
	n := 0
	for _, c := range r.ubusCalls() {
		if c == "call system "+method {
			n++
		}
	}
	return n
}

// The test docs/approval-path.md sets every option: a hostile listener in front of a real helper
// puts the owner's approval of one change on another, and sends the PIN and code of an unlock as an
// approval. A router whose binary has the router's own bot is set up with it, as a client of the
// capability would set it up; the owner then answers in the router's chat, and the listener sees no
// frame of the owner's and none of the owner's bytes in clear. Against a binary without the bot
// (origin/main), the owner's client answers through the listener as it does today, and this goes red.
func TestAHostileListenerCannotMoveTheOwnersFactor(t *testing.T) {
	r := newBotRigUnlock(t, "", factorPINTOTP)
	withBot := capabilities()["owner_approves_past_the_listener"]
	h := &hostileListener{t: t, hc: &helperClient{path: startHelper(t, r.s, os.Getuid())}}
	agentTok, _ := r.s.tokens.Mint("a")
	ownerTok, _ := r.s.tokens.Mint("owner")
	if withBot {
		r.bind()
	}
	// held reads the id of a HELD answer; the ubus log is judged once, at the end.
	held := func(out string, isErr bool) string {
		m := heldLine.FindStringSubmatch(out)
		if isErr || m == nil {
			t.Fatalf("not held: %q", out)
		}
		return m[1]
	}
	a := held(h.call(agentTok, "ubus_call", map[string]any{"object": "system", "method": "board"}))
	// The listener has the agent's token, so it proposes a change of its own beside the agent's.
	b := held(h.call(agentTok, "ubus_call", map[string]any{"object": "system", "method": "info"}))
	bHash := h.hashOf(ownerTok, b)
	codeApprove := r.code(time.Now())
	codeUnlock := r.code(time.Now().Add(30 * time.Second))
	var cards []string

	// 1. The owner approves A.
	if withBot {
		card := r.cardOf(a)
		cards = append(cards, card.Text)
		if got := r.approveInChat(a, apPIN+" "+codeApprove); !strings.HasPrefix(got, "Applied "+a) {
			t.Fatalf("the owner's approval of A in the router's chat did not apply: %q", got)
		}
		cards = append(cards, r.cardOf(b).Text)
	} else {
		in := map[string]any{"id": a, "hash": h.hashOf(ownerTok, a), "pin": apPIN, "code": codeApprove}
		h.fromOwner(in)
		in["id"], in["hash"] = b, bHash // the listener puts it on B
		h.call(ownerTok, "action_approve", in)
	}
	// 2. The owner opens the agent's window.
	if withBot {
		n := len(r.tg.sentTo(testOwner))
		r.tg.say(testOwner, testOwner, "private", "/unlock "+apPIN+" "+codeUnlock)
		r.waitText(testOwner, n, "Unlocked a until")
	} else {
		in := map[string]any{"client": "a", "pin": apPIN, "code": codeUnlock}
		h.fromOwner(in)
		if countRan(r, "info") > 0 {
			b = held(h.call(agentTok, "ubus_call", map[string]any{"object": "system", "method": "info"}))
			bHash = h.hashOf(ownerTok, b)
		}
		h.call(ownerTok, "action_approve", map[string]any{"id": b, "hash": bHash, "pin": h.pin, "code": h.code})
	}
	// 3. Whatever passed it, the listener tries B with what it caught.
	h.call(ownerTok, "action_approve", map[string]any{"id": b, "hash": bHash, "pin": h.pin, "code": h.code})

	if n := countRan(r, "info"); n != 0 {
		t.Fatalf("the listener ran a change the owner was never shown, %d time(s): the owner's factor was moved", n)
	}
	if countRan(r, "board") != 1 {
		t.Fatalf("A, which the owner approved, did not run once: %q", r.ubusCalls())
	}
	if h.pin != "" || h.code != "" {
		t.Fatal("the owner's PIN or code passed the listener")
	}
	carried := r.pipe.carried()
	if len(carried) < 2000 {
		t.Fatalf("the pipe carried %d bytes: the check below would read nothing", len(carried))
	}
	secrets := map[string]string{"the approval's message": apPIN + " " + codeApprove, "the approval's code": codeApprove,
		"the unlock's code": codeUnlock, "the unlock": "/unlock ", "the bot's token": testBotToken,
		"a request in clear": "POST /bot", "a method in clear": "getUpdates", "a card's header": "Router change waiting"}
	for i, c := range cards {
		secrets["card "+string(rune('A'+i))] = c
	}
	for what, s := range secrets {
		if bytes.Contains(carried, []byte(s)) {
			t.Errorf("%s passed the listener in clear", what)
		}
	}
}

// Without a bot the boundary stays, as docs/privilege-split.md says: the owner's client approves
// through the listener, and a broken listener can put the owner's factor on another change. This is
// the line the docs keep for a router with no bot; a test pins it so it cannot go stale.
func TestWithoutABotTheListenerStillCarriesTheFactor(t *testing.T) {
	r := newBotRig(t, "")
	h := &hostileListener{t: t, hc: &helperClient{path: startHelper(t, r.s, os.Getuid())}}
	agentTok, _ := r.s.tokens.Mint("a")
	ownerTok, _ := r.s.tokens.Mint("owner")
	a := r.mustHold(h.call(agentTok, "ubus_call", map[string]any{"object": "system", "method": "board"}))
	b := r.mustHold(h.call(agentTok, "ubus_call", map[string]any{"object": "system", "method": "info"}))
	in := map[string]any{"id": b, "hash": h.hashOf(ownerTok, b), "pin": apPIN, "code": r.code(time.Now())}
	_ = a // the owner meant A
	h.call(ownerTok, "action_approve", in)
	if countRan(r, "info") != 1 {
		t.Fatalf("without a bot the listener could not move the factor; the docs' line about it is stale: %q", r.ubusCalls())
	}
}

// A listener that alters the bytes it carries breaks the connection: TLS refuses the record, no
// update is read, no prompt opens. The same press goes through once the bytes are left alone.
func TestAListenerThatAltersTheBytesBreaksTheConnection(t *testing.T) {
	r := newBotRig(t, "")
	r.bind()
	a := r.heldUbus("board")
	card := r.cardOf(a) // the pipe works
	r.pipe.tamper.Store(true)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	waitFor(t, "the bot to fail on the altered bytes", 15*time.Second, func() bool {
		return strings.Contains(ownerBotFilesOf(r.state).seen().Error, "tls")
	})
	never(t, "an update read through altered bytes was acted on", 2*time.Second, func() bool {
		return len(r.tg.sentTo(testOwner)) > n || r.ran("board")
	})
	r.pipe.tamper.Store(false)
	r.waitText(testOwner, n, "Approve "+a)
}

// A listener that answers in Telegram's place, with a certificate of its own for api.telegram.org or
// with a trusted certificate for another name, is refused before a byte of the Bot API is read: the
// impostor is never asked anything.
func TestAListenerThatAnswersInTelegramsPlaceIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		cert func(r *botRig) testCA
		host string
	}{
		{"a certificate from a CA the router does not trust", func(r *botRig) testCA { return newTestCA(t, "impostor CA") }, telegramHost},
		{"a trusted certificate for another name", func(r *botRig) testCA { return r.ca }, "evil.example"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newBotRig(t, "")
			imp := newTGStandIn(t, c.cert(r).leaf(t, c.host))
			r.pipe.target.Store(imp.addr())
			code := r.bindCode()
			waitFor(t, "the bot to refuse the impostor's certificate", 15*time.Second, func() bool {
				return strings.Contains(ownerBotFilesOf(r.state).seen().Error, "certificate")
			})
			imp.say(testOwner, testOwner, "private", "/start "+code)
			never(t, "the impostor was asked something", 2*time.Second, func() bool {
				return imp.callCount() > 0 || ownerBotFilesOf(r.state).chat() != 0
			})
			r.pipe.target.Store(r.tg.addr())
			r.tg.say(testOwner, testOwner, "private", "/start "+code)
			waitFor(t, "the owner's chat to be bound through Telegram itself", 30*time.Second, func() bool {
				return ownerBotFilesOf(r.state).chat() == testOwner
			})
		})
	}
}

// The listener's pipe serves root, the helper, and no other uid: for any other peer it dials nothing.
func TestThePipeServesTheHelperOnly(t *testing.T) {
	r := newBotRig(t, "")
	r.cancel()
	r.pipe = startTestPipeUID(t, r.tg.addr(), os.Getuid()+1)
	r.runBot()
	r.ownerBot(testBotToken+"\n", "set")
	waitFor(t, "the helper to try the pipe", 30*time.Second, func() bool {
		return r.pipe.dials.Load() > 0 || ownerBotFilesOf(r.state).seen().Error != ""
	})
	if n := r.pipe.dials.Load(); n > 0 {
		t.Fatalf("the pipe dialled %d time(s) for a peer that is not the one it serves", n)
	}
	r.cancel()
	r.pipe = startTestPipeUID(t, r.tg.addr(), os.Getuid())
	r.runBot()
	waitFor(t, "the pipe to dial for the peer it serves", 30*time.Second, func() bool { return r.pipe.dials.Load() > 0 })
}

// The helper speaks through a pipe only when the kernel says its other end is the listener's uid: a
// socket that is someone else's gets nothing, not even a TLS hello.
func TestTheHelperRefusesAPipeThatIsNotTheListeners(t *testing.T) {
	r := newBotRig(t, "")
	for _, c := range []struct {
		uid  int
		sent bool
	}{{os.Getuid() + 1, false}, {os.Getuid(), true}} {
		before := len(r.pipe.carried())
		tc := newTelegramClient(testBotToken, pipeDialer{path: r.pipe.path, uid: c.uid, peer: peerUID}, r.ca.pool)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := tc.getMe(ctx)
		cancel()
		time.Sleep(200 * time.Millisecond)
		sent := len(r.pipe.carried()) > before
		if sent != c.sent || (err == nil) != c.sent {
			t.Fatalf("a pipe whose end is uid %d: sent %v, error %v", c.uid, sent, err)
		}
		if !c.sent && !strings.Contains(err.Error(), "is not the listener's") {
			t.Errorf("the refusal does not say why: %v", err)
		}
	}
}

// The token is in no error the client returns, though the URL, which holds it, is in the transport's.
func TestTheClientsErrorsHoldNoToken(t *testing.T) {
	r := newBotRig(t, "")
	r.pipe.target.Store("127.0.0.1:1")
	tc := newTelegramClient(testBotToken, pipeDialer{path: r.pipe.path, uid: os.Getuid(), peer: peerUID}, r.ca.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := tc.getMe(ctx)
	if err == nil || strings.Contains(err.Error(), "TEST-not-a-real-token") || strings.Contains(err.Error(), "123456789:") {
		t.Fatalf("the error holds the token, or there is none: %v", err)
	}
}
