package main

// The router's own bot: the owner's approval path past the listener (docs/approval-path.md, A2).
//
// @decided 2026-11-08 (paraphrased): the root helper sends the card of a held change and reads the
// owner's answer itself, through a bot of the router's own; TLS ends in the helper and the listener
// only carries encrypted bytes; the Hermes gateway and the listener leave the approval path; the
// owner approves as before, one tap and one message with the PIN and the code, in the router's own
// chat; once per router the owner makes a bot, gives the router its token and presses Start.
//
// What it holds (CLAUDE.md, invariant 13): once a token is set and a chat is bound, the bot is the
// approval channel for every approval section on the router. The card the owner reads is the
// record's own card, sent by the helper; a press counts only from the bound chat, on the message the
// helper sent for a record that is still held; the factor is the next message after Approve, within
// its 180 seconds, deleted before it is read, and it runs the checks action_approve runs, in the same
// order, the factor last and its step spent; and no MCP client approves, lists, rejects, unlocks or
// locks for an approval section any more, so no card, tap or factor of the owner's passes the
// listener at all. Until a chat is bound, the bot listens to nobody and approvals work as before.
//
// The files, each with one writer, in /etc/openwrt-mcp/owner-bot (0700, each 0600):
//
//	token  the bot's token                       the CLI (owner-bot set, from standard input)
//	bind   SHA-256 of a one-time binding code,   the CLI (owner-bot bind); the helper removes it
//	       and the moment it ends
//	chat   the bound chat's id                   the helper, when the code arrives
//	seen   the bot's name and its last error     the helper, for status; it decides nothing

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	ownerBotDir   = "owner-bot"
	bindCodeLife  = 30 * time.Minute
	promptLife    = 180 * time.Second
	cardsInterval = 3 * time.Second

	// Telegram counts a message's length in UTF-16 units, at most 4096. A card leaves room for the
	// line its outcome adds; a card that does not fit is refused when it is held (approval.go).
	telegramTextUnits = 4096
	outcomeReserve    = 400
	maxCardUnits      = telegramTextUnits - outcomeReserve
	cardRetryFirst    = 5 * time.Second
	cardRetryMax      = 5 * time.Minute
)

// ownerBotWall is the wall clock a binding code's end is written and read by. A variable only so a
// test can move it.
var ownerBotWall = time.Now

// botTokenShape is what BotFather hands out: the bot's id, a colon, and the secret.
var botTokenShape = regexp.MustCompile(`^[0-9]{5,16}:[A-Za-z0-9_-]{30,80}$`)

// bindCodeShape is a code `owner-bot bind` makes: 16 random bytes, base64url, so it fits a t.me start
// parameter.
var bindCodeShape = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ---------------------------------------------------------------- the files

type ownerBotFiles struct{ dir string }

func ownerBotFilesOf(statePath string) ownerBotFiles {
	return ownerBotFiles{dir: filepath.Join(statePath, ownerBotDir)}
}

func (f ownerBotFiles) path(name string) string { return filepath.Join(f.dir, name) }

func (f ownerBotFiles) read(name string, max int) string {
	fh, err := os.Open(f.path(name))
	if err != nil {
		return ""
	}
	defer fh.Close()
	b := make([]byte, max+1)
	n, _ := fh.Read(b)
	if n > max {
		return ""
	}
	return strings.TrimSpace(string(b[:n]))
}

// token is the bot's token, or "" when there is none or it is not a token's shape.
func (f ownerBotFiles) token() string {
	t := f.read("token", 256)
	if !botTokenShape.MatchString(t) {
		return ""
	}
	return t
}

// chat is the bound chat's id, or 0.
func (f ownerBotFiles) chat() int64 {
	n, err := strconv.ParseInt(f.read("chat", 32), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// bindEntry is the SHA-256 of the binding code waiting to be sent and the moment it ends, as
// `owner-bot bind` wrote them. ok is false for no file, or one that does not read.
func (f ownerBotFiles) bindEntry() (hash string, ends time.Time, ok bool) {
	fs := strings.Fields(f.read("bind", 128))
	if len(fs) != 2 || len(fs[0]) != 64 {
		return "", time.Time{}, false
	}
	if _, err := hex.DecodeString(fs[0]); err != nil {
		return "", time.Time{}, false
	}
	n, err := strconv.ParseInt(fs[1], 10, 64)
	if err != nil || n <= 0 {
		return "", time.Time{}, false
	}
	return fs[0], time.Unix(n, 0), true
}

// bindHash is the SHA-256 of a binding code that is waiting and has not ended, or "".
func (f ownerBotFiles) bindHash() string {
	h, ends, ok := f.bindEntry()
	if !ok || bindEnded(ends) {
		return ""
	}
	return h
}

// bindEnded says whether a binding code's own end, written in its file, has come.
func bindEnded(ends time.Time) bool { return !ownerBotWall().Before(ends) }

func (f ownerBotFiles) write(name, body string) error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(f.dir, 0o700); err != nil {
		return err
	}
	return atomicWriteFile(f.path(name), []byte(body), 0o600)
}

func (f ownerBotFiles) remove(name string) { _ = os.Remove(f.path(name)) }

// botSeen is what the helper last learned of the bot, for status. It decides nothing. A failure is
// one word of botFailures and never an error's text, which could carry what a URL carried.
type botSeen struct {
	Bot     string `json:"bot,omitempty"`
	Failure string `json:"failure,omitempty"`
}

func (f ownerBotFiles) seen() botSeen {
	var s botSeen
	_ = json.Unmarshal([]byte(f.read("seen", 4096)), &s)
	if s.Failure != "" && botFailures[s.Failure] == "" {
		s.Failure = "other" // a file this binary did not write as it writes it
	}
	if !botNameShape.MatchString(s.Bot) {
		s.Bot = ""
	}
	return s
}

// botNameShape is a bot's username as Telegram allows it.
var botNameShape = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// botFailures are the words a failure of the bot is told by, in the seen file, the status and the
// log, each with what it says. Nothing else is said of a failure outside the helper's memory.
var botFailures = map[string]string{
	"token_rejected":   "Telegram does not know the token",
	"telegram_refused": "Telegram refused a call",
	"telegram_error":   "Telegram answered with an error",
	"tls":              "the connection to api.telegram.org failed its TLS check",
	"pipe":             "the listener's pipe could not be reached, or is not the listener's",
	"network":          "api.telegram.org could not be reached",
	"other":            "a failure this binary does not name",
}

// botFailure is the word for what went wrong: the kind of failure, never its text.
func botFailure(err error) string {
	var te *telegramError
	var pe *pipeError
	var ae tls.AlertError
	var he tls.RecordHeaderError
	var ve *tls.CertificateVerificationError
	var ue x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var oe *net.OpError
	switch {
	case errors.As(err, &te) && te.code == 401:
		return "token_rejected"
	case errors.As(err, &te) && te.code >= 400 && te.code < 500:
		return "telegram_refused"
	case errors.As(err, &te):
		return "telegram_error"
	case errors.As(err, &pe):
		return "pipe"
	case errors.As(err, &ve), errors.As(err, &ue), errors.As(err, &hn), errors.As(err, &ci),
		errors.As(err, &ae), errors.As(err, &he):
		return "tls"
	case errors.As(err, &oe) && (oe.Op == "local error" || oe.Op == "remote error"):
		return "tls" // how crypto/tls reports an alert, a record that fails its check among them
	}
	return "network"
}

// ownerBotChannel says whether the router's own bot is the approval channel: a token set and a chat
// bound. From then on no MCP client decides anything for an approval section.
func (s *Server) ownerBotChannel() bool {
	f := ownerBotFilesOf(s.statePath)
	return f.chat() != 0 && f.token() != ""
}

// mcpApproverRefusal is the answer to an approver's tool over MCP once the bot is the channel. It is
// given before anything is looked up, and counts nothing.
func (s *Server) mcpApproverRefusal() error {
	if !s.ownerBotChannel() {
		return nil
	}
	return &refusedError{"refused: on this router the owner approves held changes, and opens and closes windows, " +
		"in the router's own Telegram chat, and no MCP client does; nothing was tried"}
}

// approvalClients are the clients with an approval section, sorted: the ones the router's chat
// decides for once it is bound.
func (c *Config) approvalClients() []string {
	var out []string
	for client := range c.Approvals {
		out = append(out, client)
	}
	sortStrings(out)
	return out
}

// revokeApprovers revokes the tokens of every client named as an approver: once the router's chat
// approves, the owner's MCP client is a token on the router that can do nothing, so it goes.
func (s *Server) revokeApprovers() []string {
	seen := map[string]bool{}
	var revoked []string
	for _, a := range s.cfg().Approvals {
		if a.Approver == "" || seen[a.Approver] {
			continue
		}
		seen[a.Approver] = true
		if s.tokens.Revoke(a.Approver) > 0 {
			revoked = append(revoked, a.Approver)
		}
	}
	sortStrings(revoked)
	return revoked
}

// notifyBot tells the bot something changed in the held changes, so a card goes out at once.
func (s *Server) notifyBot() {
	if b := s.bot.Load(); b != nil {
		select {
		case b.notify <- struct{}{}:
		default:
		}
	}
}

// ---------------------------------------------------------------- the bot

type ownerBotOptions struct {
	relay    string // the listener's pipe
	relayUID int    // whose the pipe must be: the listener's
	peer     func(*net.UnixConn) (int, error)
	roots    *x509.CertPool // nil: the system's
	mono     func() time.Duration
}

type botCard struct {
	id, hash string
	msgID    int64
	text     string
	final    bool
	cut      bool // too long for one message: shown cut, and never approved from the chat
}

type botPrompt struct {
	id, hash string
	until    time.Duration
}

type ownerBot struct {
	s      *Server
	f      ownerBotFiles
	opt    ownerBotOptions
	host   string
	notify chan struct{}

	// mu is held across one update or one pass over the cards, never across a long poll.
	mu       sync.Mutex
	tc       *telegramClient
	token    string
	owner    int64
	cards    map[string]*botCard // by record id
	byMsg    map[int64]string    // message id -> record id
	prompt   *botPrompt
	bindSeen map[string]time.Duration // bind hash -> when the helper first saw it
	retry    map[string]botRetry      // a card Telegram did not take, by record id ("edit:" for its edit)
	seen     botSeen

	loops sync.WaitGroup // the two loops, so a caller that ended ctx can wait for them to be gone
}

// botRetry is when a card that Telegram did not take is tried again, and the wait after that.
type botRetry struct{ next, wait time.Duration }

// startOwnerBot starts the bot's two loops: one reads the updates, one sends and closes cards. Both
// idle while no token is set.
func (s *Server) startOwnerBot(ctx context.Context, opt ownerBotOptions) *ownerBot {
	if opt.peer == nil {
		opt.peer = peerUID
	}
	if opt.mono == nil {
		epoch := time.Now()
		opt.mono = func() time.Duration { return time.Since(epoch) }
	}
	host := deviceLabel()
	if host == "" {
		host = "this router"
	}
	b := &ownerBot{s: s, f: ownerBotFilesOf(s.statePath), opt: opt, host: host, notify: make(chan struct{}, 1),
		cards: map[string]*botCard{}, byMsg: map[int64]string{}, bindSeen: map[string]time.Duration{},
		retry: map[string]botRetry{}}
	b.seen = b.f.seen()
	// A code that lay on disk while the helper was not running is judged by the end written in it,
	// and one that has ended is removed before anything is read.
	b.mu.Lock()
	b.watchBind()
	b.mu.Unlock()
	s.bot.Store(b)
	b.loops.Add(2)
	go func() { defer b.loops.Done(); b.poll(ctx) }()
	go func() { defer b.loops.Done(); b.cardsLoop(ctx) }()
	return b
}

// wait returns once both loops have ended, which they do once their ctx is done.
func (b *ownerBot) wait() { b.loops.Wait() }

// client is the Telegram client of the token on disk, made again when the token changes. A new
// token starts from nothing: no cards, no prompt.
func (b *ownerBot) client() (*telegramClient, bool) {
	tok := b.f.token()
	b.mu.Lock()
	defer b.mu.Unlock()
	if tok == b.token {
		return b.tc, false
	}
	b.token, b.tc, b.prompt = tok, nil, nil
	b.cards, b.byMsg, b.retry = map[string]*botCard{}, map[int64]string{}, map[string]botRetry{}
	if tok != "" {
		b.tc = newTelegramClient(tok, pipeDialer{path: b.opt.relay, uid: b.opt.relayUID, peer: b.opt.peer}, b.opt.roots)
	}
	return b.tc, true
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// poll reads the bot's updates until ctx ends.
func (b *ownerBot) poll(ctx context.Context) {
	var offset int64
	drained := false
	backoff := time.Second
	for ctx.Err() == nil {
		tc, changed := b.client()
		if changed {
			offset, drained = 0, false
			if tc != nil {
				cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
				me, err := tc.getMe(cctx)
				cancel()
				if err != nil && ctx.Err() == nil {
					b.noteErr(err)
				} else if err == nil {
					b.noteOK(me.Username)
				}
			}
		}
		if tc == nil {
			sleepCtx(ctx, 2*time.Second)
			continue
		}
		if !drained {
			if err := b.drain(ctx, tc, &offset); err != nil {
				if ctx.Err() != nil {
					return
				}
				b.noteErr(err)
				sleepCtx(ctx, backoff)
				backoff = min(backoff*2, time.Minute)
				continue
			}
			drained = true
		}
		pctx, cancel := context.WithTimeout(ctx, telegramPollWait+20*time.Second)
		ups, err := tc.getUpdates(pctx, offset, telegramPollWait)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.noteErr(err)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		b.noteOK("")
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if !u.Bad {
				b.handle(ctx, tc, u)
			}
		}
	}
}

// noteOK and noteErr record what the helper learned of the bot, writing only when it changed: the
// state directory is on flash. The Locked forms are for callers that hold b.mu.
func (b *ownerBot) noteOK(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.noteLocked(name, nil)
}

func (b *ownerBot) noteErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.noteLocked("", err)
}

func (b *ownerBot) noteLocked(name string, err error) {
	s := b.seen
	if name != "" && botNameShape.MatchString(name) {
		s.Bot = name
	}
	s.Failure = ""
	if err != nil {
		s.Failure = botFailure(err)
	}
	if s == b.seen {
		return
	}
	if s.Failure != "" && s.Failure != b.seen.Failure {
		log.Printf("openwrt-mcp: the router's bot: %s (%s)", botFailures[s.Failure], s.Failure)
	}
	b.seen = s
	if js, err := json.Marshal(s); err == nil {
		_ = b.f.write("seen", string(js)+"\n")
	}
}

// drain reads what reached the bot while the helper was not reading, and takes none of it as an
// answer: a message from the owner that looks like a factor is deleted and the owner is told once.
// A binding code is still taken, since it decides nothing but which chat is the owner's.
func (b *ownerBot) drain(ctx context.Context, tc *telegramClient, offset *int64) error {
	told := false
	for i := 0; i < 50; i++ {
		cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
		ups, err := tc.getUpdates(cctx, *offset, 0)
		cancel()
		if err != nil {
			return err
		}
		if len(ups) == 0 {
			return nil
		}
		for _, u := range ups {
			if u.UpdateID >= *offset {
				*offset = u.UpdateID + 1
			}
			if u.Bad || u.Message == nil || !privateFromItself(u.Message) {
				continue
			}
			b.mu.Lock()
			m := u.Message
			if code, ok := startCode(m.Text); ok && b.tryBind(ctx, tc, m, code) {
				b.mu.Unlock()
				continue
			}
			if owner := b.f.chat(); owner != 0 && m.Chat.ID == owner && carriesFactor(m.Text) {
				b.deleteMsg(ctx, tc, m)
				if !told {
					b.say(ctx, tc, owner, "A message sent while the router was not reading was not used, and was "+
						"deleted. If a change waits, tap Approve on its card again.")
					told = true
				}
			}
			b.mu.Unlock()
		}
	}
	return nil
}

// privateFromItself is a message in a private chat from the person the chat is with: the only
// kind the bot reads.
func privateFromItself(m *tgMessage) bool {
	return m.From != nil && !m.From.IsBot && m.Chat.Type == "private" && m.From.ID == m.Chat.ID
}

func (b *ownerBot) say(ctx context.Context, tc *telegramClient, chat int64, text string) {
	cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
	defer cancel()
	if _, err := tc.send(cctx, chat, text, nil); err != nil {
		log.Printf("openwrt-mcp: the router's bot could not send a message: %s", botFailure(err))
	}
}

func (b *ownerBot) deleteMsg(ctx context.Context, tc *telegramClient, m *tgMessage) {
	cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
	defer cancel()
	if err := tc.delete(cctx, m.Chat.ID, m.MessageID); err != nil {
		log.Printf("openwrt-mcp: the router's bot could not delete a message: %s", botFailure(err))
	}
}

// handle reads one update.
func (b *ownerBot) handle(ctx context.Context, tc *telegramClient, u tgUpdate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.owner = b.f.chat()
	if cb := u.CallbackQuery; cb != nil {
		b.press(ctx, tc, cb)
		return
	}
	m := u.Message
	if !privateFromItself(m) {
		return // a group, a channel, a bot, or a message on someone's behalf: never read
	}
	text := strings.TrimSpace(m.Text)
	if code, ok := startCode(text); ok && b.tryBind(ctx, tc, m, code) {
		return
	}
	if b.owner == 0 || m.Chat.ID != b.owner {
		return // until a chat is bound the bot answers nobody, and then only that chat
	}
	switch {
	case isCommand(text, "/start"):
		b.say(ctx, tc, b.owner, "This chat approves changes for "+b.host+".")
	case isCommand(text, "/unlock"):
		b.unlock(ctx, tc, m, text)
	case isCommand(text, "/lock"):
		b.lock(ctx, tc, text)
	case b.prompt != nil:
		b.factor(ctx, tc, m, text)
	case looksLikeFactor(text):
		b.deleteMsg(ctx, tc, m)
		b.say(ctx, tc, b.owner, "That was not used, and nothing was tried: no change is waiting for your PIN and code "+
			"now. Tap Approve on a card first; to open the agent's window, send /unlock PIN code.")
	default:
		b.say(ctx, tc, b.owner, "Changes that wait for you appear here as cards. Approve one with a tap and then one "+
			"message: your PIN and the code. /unlock PIN code opens the agent's window; /lock closes it.")
	}
}

// isCommand says whether text is the command, alone or with arguments, Telegram's @botname form
// included.
func isCommand(text, cmd string) bool {
	f := strings.Fields(text)
	if len(f) == 0 {
		return false
	}
	c, _, _ := strings.Cut(strings.ToLower(f[0]), "@")
	return c == cmd
}

// startCode is the binding code in "/start <code>" or alone.
func startCode(text string) (string, bool) {
	f := strings.Fields(text)
	switch {
	case len(f) == 2 && isCommand(text, "/start") && bindCodeShape.MatchString(f[1]):
		return f[1], true
	case len(f) == 1 && bindCodeShape.MatchString(f[0]):
		return f[0], true
	}
	return "", false
}

// watchBind removes a binding code whose life is over: at the end `owner-bot bind` wrote in its file,
// or 30 minutes of the helper's own clock after the helper first saw it, whichever comes first. The
// second bound holds when the wall clock is wrong; the first holds across a restart, which starts the
// helper's own clock again. Callers hold b.mu.
func (b *ownerBot) watchBind() {
	h, ends, ok := b.f.bindEntry()
	if !ok {
		if _, err := os.Stat(b.f.path("bind")); err == nil {
			b.f.remove("bind") // a file that does not read binds nothing
		}
		return
	}
	first, seen := b.bindSeen[h]
	if !seen {
		first = b.opt.mono()
		b.bindSeen[h] = first
	}
	if bindEnded(ends) || b.opt.mono()-first >= bindCodeLife {
		b.f.remove("bind")
		delete(b.bindSeen, h)
		log.Printf("openwrt-mcp: the router's bot: a binding code ran out unused")
	}
}

// tryBind binds the chat that sent the code waiting in the bind file, and reports whether it did.
// Callers hold b.mu.
func (b *ownerBot) tryBind(ctx context.Context, tc *telegramClient, m *tgMessage, code string) bool {
	b.watchBind()
	h, ends, ok := b.f.bindEntry()
	if !ok || bindEnded(ends) {
		return false
	}
	if first, seen := b.bindSeen[h]; !seen || b.opt.mono()-first >= bindCodeLife {
		return false
	}
	sum := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(h)) != 1 {
		return false
	}
	old := b.f.chat()
	if err := b.f.write("chat", strconv.FormatInt(m.Chat.ID, 10)+"\n"); err != nil {
		log.Printf("openwrt-mcp: the router's bot could not keep the bound chat: %v", err)
		return true
	}
	b.f.remove("bind")
	delete(b.bindSeen, h)
	b.owner, b.prompt = m.Chat.ID, nil
	b.cards, b.byMsg, b.retry = map[string]*botCard{}, map[int64]string{}, map[string]botRetry{}
	revoked := b.s.revokeApprovers()
	summary := "the router's chat is bound"
	if len(revoked) > 0 {
		summary += "; revoked the token of " + strings.Join(revoked, ", ") + ": the router's chat approves now"
	}
	b.s.audit.Record(AuditEvent{Time: nowISO(), Client: "<owner-bot>", Tool: "owner_bot_bind", Outcome: OutcomeOK, Summary: summary})
	b.deleteMsg(ctx, tc, m)
	b.say(ctx, tc, m.Chat.ID, "This chat now approves changes for "+b.host+". A change that waits for you appears here "+
		"as a card: approve it with a tap and then one message, your PIN and the code. /unlock PIN code opens the "+
		"agent's window, and /lock closes it.")
	if old != 0 && old != m.Chat.ID {
		b.say(ctx, tc, old, "This chat no longer approves changes for "+b.host+".")
	}
	b.signal()
	return true
}

func (b *ownerBot) signal() {
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

// cardData is a card button's data: the action, the record's id and the first 16 hex of its hash.
func cardData(act byte, id, hash string) string { return string(act) + ":" + id + ":" + hash[:16] }

var cardDataShape = regexp.MustCompile(`^([ar]):([A-Z]{5}):([0-9a-f]{16})$`)

// press reads a tap on a card's button. It counts only from the bound chat, on the message the
// helper sent for that record, while the record is held. Callers hold b.mu.
func (b *ownerBot) press(ctx context.Context, tc *telegramClient, cb *tgCallback) {
	if b.owner == 0 || cb.From.ID != b.owner || cb.Message.Chat.ID != b.owner || cb.Message.Chat.Type != "private" {
		return
	}
	reply := func(text string) {
		cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
		defer cancel()
		_ = tc.answer(cctx, cb.ID, text)
	}
	m := cardDataShape.FindStringSubmatch(cb.Data)
	if m == nil {
		reply("This is not a card of this router.")
		return
	}
	card := b.cards[m[2]]
	if card == nil || card.final || card.msgID != cb.Message.MessageID || b.byMsg[cb.Message.MessageID] != card.id ||
		card.hash[:16] != m[3] {
		reply("This card is not one the router is waiting on.")
		return
	}
	v, ok := b.s.heldView(card.id)
	if !ok || v.Status != statusHeld {
		reply("This change is not waiting any more.")
		b.sync(ctx, tc)
		return
	}
	switch m[1] {
	case "a":
		if card.cut {
			reply("This card was too long to show whole, so it is not approved from the chat.")
			return
		}
		b.prompt = &botPrompt{id: card.id, hash: card.hash, until: b.opt.mono() + promptLife}
		reply("")
		b.say(ctx, tc, b.owner, promptText(v, b.s.approvalFactor(v.Client)))
	case "r":
		b.prompt = nil
		if _, _, err := b.s.rejectHeld(approverRef{}, card.id); err != nil {
			reply(truncate(firstLine(err.Error()), 190))
		} else {
			reply("Rejected.")
		}
		b.sync(ctx, tc)
	}
}

// promptText restates the change from the record and asks for the factor.
func promptText(v actionView, factor string) string {
	ask := "Send your PIN and the code from your authenticator, in one message: for example 1234 567890."
	if factor == factorTOTP {
		ask = "Send the code from your authenticator."
	}
	return fmt.Sprintf("Approve %s (ref %s)? It does this:\n%s\n\n%s This waits for %d minutes; the message is deleted "+
		"as soon as it arrives.", v.ID, v.Ref, v.Headline, ask, int(promptLife/time.Minute))
}

// factor reads the message after Approve: deleted first, then read, and tried once. Callers hold
// b.mu.
func (b *ownerBot) factor(ctx context.Context, tc *telegramClient, m *tgMessage, text string) {
	p := b.prompt
	b.prompt = nil // one message per Approve
	b.deleteMsg(ctx, tc, m)
	if b.opt.mono() >= p.until {
		b.say(ctx, tc, b.owner, "That was not used, and nothing was tried: the prompt for "+p.id+" had closed. Tap "+
			"Approve again.")
		return
	}
	v, ok := b.s.heldView(p.id)
	if !ok {
		b.say(ctx, tc, b.owner, "That was not used: "+p.id+" is not waiting any more.")
		return
	}
	f, ok := parseFactor(text, b.s.approvalFactor(v.Client))
	if !ok {
		b.say(ctx, tc, b.owner, "That was not a PIN and a code, so nothing was tried. Tap Approve again.")
		return
	}
	out, _, err := b.s.approveHeld(ctx, approverRef{}, p.id, p.hash, f)
	if err != nil {
		b.say(ctx, tc, b.owner, "Not approved: "+truncate(err.Error(), 1500))
	} else {
		b.say(ctx, tc, b.owner, truncate(firstLine(out), 500))
	}
	b.sync(ctx, tc)
}

// unlock is /unlock [client] PIN [code]: deleted first, then read. Callers hold b.mu.
func (b *ownerBot) unlock(ctx context.Context, tc *telegramClient, m *tgMessage, text string) {
	b.deleteMsg(ctx, tc, m)
	args := strings.Fields(text)[1:]
	clients := b.s.cfg().approvalClients()
	target := ""
	if len(args) > 0 && !isDigits(args[0]) {
		target, args = args[0], args[1:]
	}
	if target == "" {
		if len(clients) != 1 {
			b.say(ctx, tc, b.owner, "Name the client first: /unlock <client> PIN code, one of: "+strings.Join(clients, ", ")+".")
			return
		}
		target = clients[0]
	}
	if !contains(clients, target) {
		b.say(ctx, tc, b.owner, "No client "+strconv.Quote(truncate(target, 64))+" has its window opened from this chat.")
		return
	}
	up := b.s.unlockPolicyFor(target)
	f, ok := parseFactor(strings.Join(args, " "), up.Factor)
	if !ok {
		b.say(ctx, tc, b.owner, "That was not what unlocking takes, so nothing was tried: /unlock PIN code.")
		return
	}
	until, err := b.s.mfa.Attempt(target, f, up, time.Now())
	ev := AuditEvent{Time: nowISO(), Client: target, Tool: "mfa_unlock", Outcome: OutcomeOK,
		Summary: "mfa_unlock for " + target + " from the router's chat"}
	if err != nil {
		ev.Outcome, ev.Error = OutcomeError, err.Error()
		if fn := foldOf(err); fn != nil {
			b.s.audit.Fold(*fn, ev)
		} else {
			b.s.audit.Record(ev)
		}
		b.say(ctx, tc, b.owner, "Not unlocked: "+err.Error())
		return
	}
	b.s.audit.Record(ev)
	b.say(ctx, tc, b.owner, fmt.Sprintf("Unlocked %s until %s (%s).", target, until.UTC().Format(time.RFC3339), up.Window))
}

// lock is /lock [client]: the named client's window closed and its held changes rejected, or every
// such client's. It only ever takes access away. Callers hold b.mu.
func (b *ownerBot) lock(ctx context.Context, tc *telegramClient, text string) {
	args := strings.Fields(text)[1:]
	targets := b.s.cfg().approvalClients()
	if len(args) > 0 {
		if !contains(targets, args[0]) {
			b.say(ctx, tc, b.owner, "No client "+strconv.Quote(truncate(args[0], 64))+" is locked from this chat.")
			return
		}
		targets = []string{args[0]}
	}
	b.prompt = nil
	var said []string
	for _, c := range targets {
		was := b.s.mfa.Lock(c)
		n := b.s.rejectAll(c)
		state := "was not open"
		if was {
			state = "is closed"
		}
		said = append(said, fmt.Sprintf("%s: the window %s, %d held change(s) rejected", c, state, n))
		b.s.audit.Record(AuditEvent{Time: nowISO(), Client: c, Tool: "mfa_lock", Outcome: OutcomeOK,
			Summary: fmt.Sprintf("mfa_lock for %s from the router's chat, %d held rejected", c, n)})
	}
	b.say(ctx, tc, b.owner, "Locked. "+strings.Join(said, "; ")+".")
	b.sync(ctx, tc)
}

// cardsLoop sends a card for each held change and closes the card of each one decided, on every
// tick and whenever the held changes move.
func (b *ownerBot) cardsLoop(ctx context.Context) {
	t := time.NewTicker(cardsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-b.notify:
		}
		b.mu.Lock()
		b.watchBind()
		if b.tc != nil {
			b.sync(ctx, b.tc)
		}
		b.mu.Unlock()
	}
}

// sync brings the chat in line with the held changes. A card Telegram does not take is set aside with
// a wait of its own, which doubles each time up to five minutes, and the pass goes on: one card never
// holds back another. When Telegram does not answer at all, the rest of the pass sends nothing, since
// each card would only wait the same timeout with b.mu held. Callers hold b.mu.
func (b *ownerBot) sync(ctx context.Context, tc *telegramClient) {
	b.owner = b.f.chat()
	if b.owner == 0 || !b.s.ownerBotChannel() {
		return
	}
	now := b.opt.mono()
	views := b.s.views(b.s.cfg().approvalClients(), true, time.Now())
	present := map[string]bool{}
	for _, v := range views {
		present[v.ID] = true
	}
	offline := false
	for _, v := range views {
		c := b.cards[v.ID]
		switch {
		case c == nil && v.Status == statusHeld:
			if r, waiting := b.retry[v.ID]; offline || (waiting && now < r.next) {
				continue
			}
			text, cut := cardMessage(v.Card)
			row := []tgButton{{Text: "Approve", Data: cardData('a', v.ID, v.Hash)}, {Text: "Reject", Data: cardData('r', v.ID, v.Hash)}}
			if cut {
				row = row[1:] // a card the owner cannot read whole is not approved from the chat
			}
			cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
			id, err := tc.send(cctx, b.owner, text, &tgKeyboard{Rows: [][]tgButton{row}})
			cancel()
			if err != nil {
				b.noteLocked("", fmt.Errorf("the card of %s: %w", v.ID, err))
				offline = !telegramRefused(err)
				b.later(v.ID, now)
				continue
			}
			delete(b.retry, v.ID)
			b.cards[v.ID] = &botCard{id: v.ID, hash: v.Hash, msgID: id, text: text, cut: cut}
			b.byMsg[id] = v.ID
		case c != nil && !c.final && v.Status != statusHeld && v.Status != statusApproving && !offline:
			if err := b.closeCard(ctx, tc, c, outcomeLine(v), now); err != nil && !telegramRefused(err) {
				offline = true
			}
		}
	}
	for id, c := range b.cards {
		if present[id] {
			continue
		}
		if !c.final && !offline {
			b.closeCard(ctx, tc, c, "No longer waiting.", now)
		}
		delete(b.byMsg, c.msgID)
		delete(b.cards, id)
	}
	for id := range b.retry {
		if v := strings.TrimPrefix(id, "edit:"); !present[v] {
			delete(b.retry, id)
		}
	}
	if b.prompt != nil {
		if v, ok := b.s.heldView(b.prompt.id); !ok || v.Status != statusHeld {
			b.prompt = nil
		}
	}
}

// later sets a card aside after Telegram did not take it. Callers hold b.mu.
func (b *ownerBot) later(key string, now time.Duration) {
	r := b.retry[key]
	r.wait = min(max(r.wait*2, cardRetryFirst), cardRetryMax)
	r.next = now + r.wait
	b.retry[key] = r
}

// closeCard edits a card with its outcome and takes its buttons away; an edit Telegram does not take
// waits like a card. Callers hold b.mu.
func (b *ownerBot) closeCard(ctx context.Context, tc *telegramClient, c *botCard, line string, now time.Duration) error {
	key := "edit:" + c.id
	if r, waiting := b.retry[key]; waiting && now < r.next {
		return nil
	}
	text, _ := fitUnits(c.text+"\n\n"+line, telegramTextUnits)
	cctx, cancel := context.WithTimeout(ctx, telegramCallWait)
	defer cancel()
	if err := tc.edit(cctx, b.owner, c.msgID, text); err != nil {
		b.noteLocked("", fmt.Errorf("the card of %s: %w", c.id, err))
		b.later(key, now)
		return err
	}
	delete(b.retry, key)
	c.final = true
	if b.prompt != nil && b.prompt.id == c.id {
		b.prompt = nil
	}
	return nil
}

// telegramRefused says whether Telegram answered and said no, rather than not answering.
func telegramRefused(err error) bool {
	var te *telegramError
	return errors.As(err, &te)
}

// utf16Units is a text's length as Telegram counts it.
func utf16Units(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// fitUnits cuts s, at a whole character, to at most max UTF-16 units, and says whether it cut.
func fitUnits(s string, max int) (string, bool) {
	n := 0
	for i, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if n+w > max {
			return s[:i], true
		}
		n += w
	}
	return s, false
}

// cardCutNote ends a card that did not fit one message.
const cardCutNote = "\n\n[This card is too long for one message and is cut here, so it is not approved from the " +
	"chat. Reject it, and let it be proposed in smaller parts.]"

// cardMessage is the text a card is sent as: the record's card whole when it fits, with room for its
// outcome, or cut with a note saying so. The record keeps the whole card in the helper either way.
func cardMessage(card string) (string, bool) {
	if utf16Units(card) <= maxCardUnits {
		return card, false
	}
	head, _ := fitUnits(card, maxCardUnits-utf16Units(cardCutNote))
	return head + cardCutNote, true
}

func outcomeLine(v actionView) string {
	switch v.Status {
	case statusApplied:
		return "APPLIED."
	case statusFailed:
		return "APPROVED, BUT IT FAILED: " + truncate(firstLine(v.Result), 300)
	case statusRejected:
		return "REJECTED."
	case statusExpired:
		return "EXPIRED: nobody approved it in time."
	case statusWithdrawn:
		return "WITHDRAWN by " + v.Client + "."
	}
	return strings.ToUpper(v.Status) + "."
}

// ---------------------------------------------------------------- the factor in a message

// digitValue is the value of a decimal digit in any script, or -1: a phone keyboard can type
// Arabic-Indic or full-width digits, and they are read as the digits they are.
func digitValue(r rune) int {
	if r >= '0' && r <= '9' {
		return int(r - '0')
	}
	if !unicode.Is(unicode.Nd, r) {
		return -1
	}
	// Decimal digits come in runs of ten from a zero, and a range of the table starts at a zero.
	if r <= 0xFFFF {
		for _, rg := range unicode.Nd.R16 {
			if uint16(r) >= rg.Lo && uint16(r) <= rg.Hi {
				return int(uint16(r)-rg.Lo) % 10
			}
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if uint32(r) >= rg.Lo && uint32(r) <= rg.Hi {
			return int(uint32(r)-rg.Lo) % 10
		}
	}
	return -1
}

// digitGroups splits text into runs of digits separated by spaces, tabs or commas, each turned into
// ASCII. ok is false if anything else is in it.
func digitGroups(text string) ([]string, bool) {
	var groups []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			groups = append(groups, cur.String())
			cur.Reset()
		}
	}
	for _, r := range text {
		switch {
		case r == ' ' || r == '\t' || r == ',' || r == '\n' || r == '\r':
			flush()
		case digitValue(r) >= 0:
			cur.WriteByte(byte('0' + digitValue(r)))
		default:
			return nil, false
		}
	}
	flush()
	return groups, len(groups) > 0
}

func isDigits(s string) bool {
	g, ok := digitGroups(s)
	return ok && len(g) == 1
}

// looksLikeFactor says whether a message could carry a PIN or a code: one or two groups of digits.
// Such a message is never left in the chat.
func looksLikeFactor(text string) bool {
	g, ok := digitGroups(text)
	return ok && len(g) <= 2
}

// carriesFactor says whether a message may hold a PIN or a code: one that looks like a factor, or an
// /unlock.
func carriesFactor(text string) bool { return looksLikeFactor(text) || isCommand(text, "/unlock") }

// parseFactor reads "PIN code", "PIN" or "code", as the factor asks.
func parseFactor(text, factor string) (unlockAttempt, bool) {
	g, ok := digitGroups(text)
	if !ok {
		return unlockAttempt{}, false
	}
	pinOK := func(s string) bool { return len(s) >= 4 && len(s) <= 8 }
	codeOK := func(s string) bool { return len(s) == totpDigits }
	switch factor {
	case factorPINTOTP:
		if len(g) == 2 && pinOK(g[0]) && codeOK(g[1]) {
			return unlockAttempt{PIN: g[0], Code: g[1]}, true
		}
	case factorPIN:
		if len(g) == 1 && pinOK(g[0]) {
			return unlockAttempt{PIN: g[0]}, true
		}
	case factorTOTP:
		if len(g) == 1 && codeOK(g[0]) {
			return unlockAttempt{Code: g[0]}, true
		}
	}
	return unlockAttempt{}, false
}

// errNoBotToken is what owner-bot bind says before a token is set.
var errNoBotToken = errors.New("the router's bot has no token yet: set it first with: openwrt-mcp owner-bot set (the token on standard input)")
