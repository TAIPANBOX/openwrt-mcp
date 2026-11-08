package main

// The rig for the router's own bot: a Telegram stand-in over TLS with a CA of its own, which only the
// tests' pool trusts; the listener's pipe (relay.go) in front of it, honest or hostile; and a helper
// whose bot runs through that pipe. Nothing here reaches Telegram or uses a real token.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testBotToken is the shape of a token and no bot's.
const testBotToken = "123456789:TEST-not-a-real-token-AAAAAAAAAAAAAAAA"

// testOwner is the owner's Telegram id, and so the id of their private chat with the bot.
const testOwner int64 = 4242

// ---------------------------------------------------------------- certificates

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, pool: pool}
}

// leaf is a server certificate for host, signed by the CA.
func (ca testCA) leaf(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---------------------------------------------------------------- the Telegram stand-in

type tgCall struct {
	Method string
	Params map[string]any
}

type tgSent struct {
	ID       int64
	Chat     int64
	Text     string
	Keyboard [][]tgButton
	Edited   bool
	Deleted  bool
}

// tgStandIn answers the Bot API methods the bot uses, for one token, and lets a test play the people
// who write to the bot.
type tgStandIn struct {
	t     *testing.T
	srv   *httptest.Server
	token string

	mu      sync.Mutex
	wake    chan struct{}
	queue   []map[string]any
	nextUpd int64
	nextMsg int64
	calls   []tgCall
	sent    map[int64]*tgSent // the bot's messages
	userMsg map[int64]int64   // a person's message -> its chat
	deleted []int64
	asked   []int64 // deletions asked for, answered or not

	polling atomic.Int32  // getUpdates calls open now
	delGate chan struct{} // while not nil, a deleteMessage waits for it to close
}

func newTGStandIn(t *testing.T, cert tls.Certificate) *tgStandIn {
	t.Helper()
	return newTGStandInListener(t, cert, nil)
}

// newTGStandInListener is newTGStandIn on the listener given, or on one of its own when ln is nil.
func newTGStandInListener(t *testing.T, cert tls.Certificate, ln net.Listener) *tgStandIn {
	t.Helper()
	st := &tgStandIn{t: t, token: testBotToken, wake: make(chan struct{}), nextUpd: 100, nextMsg: 1000,
		sent: map[int64]*tgSent{}, userMsg: map[int64]int64{}}
	st.srv = httptest.NewUnstartedServer(http.HandlerFunc(st.serve))
	if ln != nil {
		st.srv.Listener.Close()
		st.srv.Listener = ln
	}
	st.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	st.srv.StartTLS()
	t.Cleanup(st.srv.Close)
	return st
}

func (st *tgStandIn) addr() string { return st.srv.Listener.Addr().String() }

func (st *tgStandIn) reply(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (st *tgStandIn) serve(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/bot")
	tok, method, _ := strings.Cut(rest, "/")
	if !ok || tok != st.token {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	var p map[string]any
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &p)
	num := func(k string) int64 {
		f, _ := p[k].(float64)
		return int64(f)
	}
	if method == "deleteMessage" {
		st.mu.Lock()
		st.asked = append(st.asked, num("message_id"))
		gate := st.delGate
		st.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
	}
	if method == "getUpdates" {
		st.polling.Add(1)
		defer st.polling.Add(-1)
		deadline := time.After(time.Duration(num("timeout")) * time.Second)
		for {
			st.mu.Lock()
			off := num("offset")
			kept := st.queue[:0]
			for _, u := range st.queue {
				if int64(u["update_id"].(int64)) >= off {
					kept = append(kept, u)
				}
			}
			st.queue = kept
			if len(st.queue) > 0 || num("timeout") == 0 {
				out := append([]map[string]any(nil), st.queue...)
				st.calls = append(st.calls, tgCall{method, p})
				st.mu.Unlock()
				st.reply(w, out)
				return
			}
			wake := st.wake
			st.mu.Unlock()
			select {
			case <-wake:
			case <-deadline:
				st.reply(w, []any{})
				return
			case <-r.Context().Done():
				return
			}
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.calls = append(st.calls, tgCall{method, p})
	switch method {
	case "getMe":
		st.reply(w, map[string]any{"id": 999, "is_bot": true, "first_name": "Router", "username": "router_test_bot"})
	case "sendMessage":
		st.nextMsg++
		m := &tgSent{ID: st.nextMsg, Chat: num("chat_id"), Text: fmt.Sprint(p["text"])}
		if kb, ok := p["reply_markup"].(map[string]any); ok {
			kbb, _ := json.Marshal(kb)
			var k tgKeyboard
			_ = json.Unmarshal(kbb, &k)
			m.Keyboard = k.Rows
		}
		st.sent[m.ID] = m
		st.reply(w, map[string]any{"message_id": m.ID, "chat": map[string]any{"id": m.Chat, "type": "private"},
			"from": map[string]any{"id": 999, "is_bot": true}, "text": m.Text})
	case "editMessageText":
		if m := st.sent[num("message_id")]; m != nil && m.Chat == num("chat_id") {
			m.Text, m.Keyboard, m.Edited = fmt.Sprint(p["text"]), nil, true
			st.reply(w, map[string]any{"message_id": m.ID, "chat": map[string]any{"id": m.Chat, "type": "private"}})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"ok":false,"error_code":400,"description":"Bad Request: message to edit not found"}`)
	case "deleteMessage":
		id := num("message_id")
		if m := st.sent[id]; m != nil {
			m.Deleted = true
		}
		st.deleted = append(st.deleted, id)
		st.reply(w, true)
	case "answerCallbackQuery":
		st.reply(w, true)
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"ok":false,"error_code":404,"description":"Not Found"}`)
	}
}

func (st *tgStandIn) push(u map[string]any) {
	st.mu.Lock()
	st.nextUpd++
	u["update_id"] = st.nextUpd
	st.queue = append(st.queue, u)
	close(st.wake)
	st.wake = make(chan struct{})
	st.mu.Unlock()
}

// say is a person writing text in a chat. It returns the message's id.
func (st *tgStandIn) say(from, chat int64, chatType, text string) int64 {
	st.mu.Lock()
	st.nextMsg++
	id := st.nextMsg
	st.userMsg[id] = chat
	st.mu.Unlock()
	st.push(map[string]any{"message": map[string]any{"message_id": id, "date": time.Now().Unix(),
		"from": map[string]any{"id": from, "is_bot": false, "first_name": "P"},
		"chat": map[string]any{"id": chat, "type": chatType}, "text": text}})
	return id
}

// tap is a person pressing a button with data on the bot's message msg, in the chat it is in.
func (st *tgStandIn) tap(from, msg int64, data string) {
	st.mu.Lock()
	chat := int64(0)
	if m := st.sent[msg]; m != nil {
		chat = m.Chat
	}
	st.mu.Unlock()
	st.tapIn(from, chat, "private", msg, data)
}

func (st *tgStandIn) tapIn(from, chat int64, chatType string, msg int64, data string) {
	st.push(map[string]any{"callback_query": map[string]any{"id": fmt.Sprintf("cb%d", time.Now().UnixNano()),
		"from": map[string]any{"id": from, "is_bot": false, "first_name": "P"}, "data": data, "chat_instance": "x",
		"message": map[string]any{"message_id": msg, "date": time.Now().Unix(),
			"from": map[string]any{"id": 999, "is_bot": true}, "chat": map[string]any{"id": chat, "type": chatType}}}})
}

// sentTo is every message the bot sent to chat, oldest first, as it stands now.
func (st *tgStandIn) sentTo(chat int64) []tgSent {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []tgSent
	for _, m := range st.sent {
		if m.Chat == chat {
			out = append(out, *m)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// holdDeletes makes every deleteMessage wait until the returned release is called.
func (st *tgStandIn) holdDeletes() (release func()) {
	st.mu.Lock()
	defer st.mu.Unlock()
	g := make(chan struct{})
	st.delGate = g
	var once sync.Once
	return func() {
		once.Do(func() {
			st.mu.Lock()
			st.delGate = nil
			st.mu.Unlock()
			close(g)
		})
	}
}

func (st *tgStandIn) deleteAsked(id int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.asked {
		if d == id {
			return true
		}
	}
	return false
}

func (st *tgStandIn) wasDeleted(id int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.deleted {
		if d == id {
			return true
		}
	}
	return false
}

// callsSince is the methods called from index i on.
func (st *tgStandIn) callsSince(i int) []tgCall {
	st.mu.Lock()
	defer st.mu.Unlock()
	if i > len(st.calls) {
		return nil
	}
	return append([]tgCall(nil), st.calls[i:]...)
}

func (st *tgStandIn) callCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.calls)
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waited %s for %s", d, what)
}

// never asserts ok stays false for d.
func never(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			t.Fatalf("%s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------- the pipe, honest or not

// tapConn is a connection whose bytes are recorded, and, while tamper is on, altered on the way from
// the server: what a broken listener can do to the pipe.
type tapConn struct {
	net.Conn
	mu       *sync.Mutex
	up, down *bytes.Buffer // helper -> Telegram, Telegram -> helper
	tamper   *atomic.Bool
}

func (c *tapConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.tamper.Load() {
			b[n-1] ^= 0x5a
		}
		c.mu.Lock()
		c.down.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *tapConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.up.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

type testPipe struct {
	path   string
	relay  *telegramRelay
	mu     sync.Mutex
	up     bytes.Buffer
	down   bytes.Buffer
	tamper atomic.Bool
	target atomic.Value // the address dialled
	dials  atomic.Int64
}

// startTestPipe serves the listener's pipe on a fresh socket, its dial pointed at addr instead of
// api.telegram.org:443, recording what it copies.
func startTestPipe(t *testing.T, addr string) *testPipe {
	t.Helper()
	return startTestPipeUID(t, addr, os.Getuid())
}

// startTestPipeUID is startTestPipe serving the uid given.
func startTestPipeUID(t *testing.T, addr string, uid int) *testPipe {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "omr") // a socket's path must fit in 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := &testPipe{path: filepath.Join(dir, "relay", "telegram.sock")}
	p.target.Store(addr)
	p.relay = newTelegramRelay(uid)
	p.relay.dial = func(ctx context.Context) (net.Conn, error) {
		p.dials.Add(1)
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", p.target.Load().(string))
		if err != nil {
			return nil, err
		}
		return &tapConn{Conn: c, mu: &p.mu, up: &p.up, down: &p.down, tamper: &p.tamper}, nil
	}
	ln, err := listenRelay(p.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go p.relay.serve(ln)
	return p
}

// carried is every byte the pipe copied, both ways.
func (p *testPipe) carried() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append(append([]byte(nil), p.up.Bytes()...), p.down.Bytes()...)
}

// ---------------------------------------------------------------- the rig

// testMono is a monotonic clock a test moves by hand.
type testMono struct{ d atomic.Int64 }

func (m *testMono) now() time.Duration  { return time.Duration(m.d.Load()) }
func (m *testMono) add(d time.Duration) { m.d.Add(int64(d)) }
func newTestMono() *testMono            { m := &testMono{}; m.d.Store(int64(time.Hour)); return m }

// botApproval holds two harmless reads by rule, so a test has two held changes of one client at once.
const botApproval = apApproval + "\toption max_open '2'\n" +
	"\tlist hold 'ubus_call:system.board'\n\tlist hold 'ubus_call:system.info'\n"

type botRig struct {
	*apRig
	ca     testCA
	tg     *tgStandIn
	pipe   *testPipe
	mono   *testMono
	bot    *ownerBot
	cancel context.CancelFunc
}

// newBotRig is the router of approval_e2e_test.go with its approval section as given, a Telegram
// stand-in, the listener's pipe to it and the helper's bot running through that pipe. The bot has
// no token yet.
func newBotRig(t *testing.T, approval string) *botRig {
	t.Helper()
	return newBotRigUnlock(t, approval, factorPIN)
}

// newBotRigUnlock is newBotRig with the agent's window opened by the factor given.
func newBotRigUnlock(t *testing.T, approval, unlock string) *botRig {
	t.Helper()
	if approval == "" {
		approval = botApproval
	}
	r := &botRig{apRig: newApRig(t, approval), ca: newTestCA(t, "openwrt-mcp test CA"), mono: newTestMono()}
	if unlock != factorPIN {
		b, _ := os.ReadFile(r.cfgFile)
		body := strings.Replace(string(b), "option mfa_factor 'pin'", "option mfa_factor '"+unlock+"'", 1)
		if err := os.WriteFile(r.cfgFile, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		later := time.Now().Add(2 * time.Second)
		os.Chtimes(r.cfgFile, later, later)
		if got := r.s.unlockPolicyFor("a").Factor; got != unlock {
			t.Fatalf("the agent's window is opened by %s, not %s", got, unlock)
		}
	}
	r.tg = newTGStandIn(t, r.ca.leaf(t, telegramHost))
	r.pipe = startTestPipe(t, r.tg.addr())
	r.runBot()
	return r
}

// start runs the bot, as a helper that starts does.
func (r *botRig) runBot() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.t.Cleanup(cancel)
	r.bot = r.s.startOwnerBot(ctx, ownerBotOptions{relay: r.pipe.path, relayUID: os.Getuid(), roots: r.ca.pool,
		mono: r.mono.now})
}

// ownerBot runs the CLI the way LuCI will: the token on standard input.
func (r *botRig) ownerBot(stdin string, args ...string) string {
	r.t.Helper()
	var out bytes.Buffer
	if err := runOwnerBot(&out, strings.NewReader(stdin), r.state, args); err != nil {
		r.t.Fatalf("owner-bot %v: %v", args, err)
	}
	return out.String()
}

// bindCode sets the token and makes a binding code, and returns the code.
func (r *botRig) bindCode() string {
	r.t.Helper()
	r.ownerBot(testBotToken+"\n", "set")
	var v struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(r.ownerBot("", "bind", "--json")), &v); err != nil || v.Code == "" {
		r.t.Fatalf("owner-bot bind gave no code: %v", err)
	}
	return v.Code
}

// bind sets the bot up and binds the owner's chat by pressing Start on the link.
func (r *botRig) bind() {
	r.t.Helper()
	code := r.bindCode()
	r.tg.say(testOwner, testOwner, "private", "/start "+code)
	waitFor(r.t, "the owner's chat to be bound", 10*time.Second, func() bool {
		return ownerBotFilesOf(r.state).chat() == testOwner
	})
}

// cardOf waits for the card of record id in the owner's chat.
func (r *botRig) cardOf(id string) tgSent {
	r.t.Helper()
	var card tgSent
	waitFor(r.t, "the card of "+id, 10*time.Second, func() bool {
		for _, m := range r.tg.sentTo(testOwner) {
			if len(m.Keyboard) > 0 && strings.Contains(m.Text, "("+id+",") {
				card = m
				return true
			}
		}
		return false
	})
	return card
}

// lastTo is the text of the newest message the bot sent the chat.
func (r *botRig) lastTo(chat int64) string {
	ms := r.tg.sentTo(chat)
	if len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1].Text
}

// waitText waits for a message to chat that contains want, sent after index from of sentTo.
func (r *botRig) waitText(chat int64, from int, want string) string {
	r.t.Helper()
	var got string
	waitFor(r.t, fmt.Sprintf("a message with %q", want), 10*time.Second, func() bool {
		ms := r.tg.sentTo(chat)
		for i := from; i < len(ms); i++ {
			if strings.Contains(ms[i].Text, want) {
				got = ms[i].Text
				return true
			}
		}
		return false
	})
	return got
}

// heldUbus asks, as the agent, for a ubus call the approval section holds, and returns its id.
func (r *botRig) heldUbus(method string) string {
	r.t.Helper()
	out, isErr := r.ubusCall("system", method, nil)
	return r.mustHold(out, isErr)
}

func (r *botRig) ran(method string) bool {
	for _, c := range r.ubusCalls() {
		if c == "call system "+method {
			return true
		}
	}
	return false
}

// approveInChat taps Approve on id's card and sends text as the owner, and waits for the answer.
func (r *botRig) approveInChat(id, text string) string {
	r.t.Helper()
	card := r.cardOf(id)
	n := len(r.tg.sentTo(testOwner))
	r.tg.tap(testOwner, card.ID, card.Keyboard[0][0].Data)
	r.waitText(testOwner, n, "Approve "+id)
	n = len(r.tg.sentTo(testOwner))
	msg := r.tg.say(testOwner, testOwner, "private", text)
	waitFor(r.t, "the factor's message to be deleted", 10*time.Second, func() bool { return r.tg.wasDeleted(msg) })
	var got string
	waitFor(r.t, "the answer to the factor", 10*time.Second, func() bool {
		ms := r.tg.sentTo(testOwner)
		for i := n; i < len(ms); i++ {
			if strings.HasPrefix(ms[i].Text, "Applied") || strings.HasPrefix(ms[i].Text, "Not approved") ||
				strings.HasPrefix(ms[i].Text, "That was") {
				got = ms[i].Text
				return true
			}
		}
		return false
	})
	return got
}
