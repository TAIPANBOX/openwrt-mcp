package main

// The helper's Telegram client, for the router's own bot (ownbot.go; docs/approval-path.md, A2).
//
// TLS ends here, in the helper, and the helper opens no IP socket: every connection is a Unix one to
// the listener's pipe (relay.go), whose other end must be the listener's uid, and the listener copies
// the bytes to api.telegram.org:443 without a key for them. So the listener can delay or drop what
// passes, as it can drop any call, and can neither read nor change it: a record it alters fails TLS's
// own check and the connection ends, and a server that is not api.telegram.org fails the certificate.
//
// Every answer is read within a bound and decoded into the few fields the bot uses; one that is too
// large, not JSON, or not what the method answers is an error, and nothing in it is acted on. An
// error never carries the bot's token, which is part of every URL.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// telegramHost is the one name the bot speaks to, and the name its certificate must carry.
	telegramHost = "api.telegram.org"
	// telegramAddr is what the listener's pipe dials for every connection the helper makes to it.
	telegramAddr = telegramHost + ":443"

	defaultRelaySocket = "/var/run/openwrt-mcp-relay/telegram.sock"

	maxTelegramAnswer = 1 << 20 // a getUpdates of 100 updates of 4096 characters fits
	maxTelegramText   = 4096    // Telegram's own limit on a message
	maxCallbackData   = 64      // Telegram's own limit on a button's data
	maxUpdatesPerPoll = 100
	telegramPollWait  = 25 * time.Second
	telegramCallWait  = 20 * time.Second
)

// telegramClient calls the Bot API of one token over the listener's pipe.
type telegramClient struct {
	token string
	hc    *http.Client
}

// pipeDialer dials the listener's pipe and nothing else, and refuses a pipe whose other end is not
// the uid it was told to expect. The address http.Transport asks for is ignored: whatever it names,
// the connection is the pipe, and TLS then checks it reached api.telegram.org.
type pipeDialer struct {
	path string
	uid  int
	peer func(*net.UnixConn) (int, error)
}

func (d pipeDialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "unix", d.path)
	if err != nil {
		return nil, &pipeError{fmt.Sprintf("the listener's pipe %s: %v", d.path, err)}
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, &pipeError{fmt.Sprintf("the listener's pipe %s is not a Unix socket", d.path)}
	}
	uid, err := d.peer(uc)
	if err != nil || uid != d.uid {
		c.Close()
		return nil, &pipeError{fmt.Sprintf("the pipe %s is not the listener's: uid %d (%v), not %d", d.path, uid, err, d.uid)}
	}
	return c, nil
}

// pipeError is a pipe the helper could not reach or would not use.
type pipeError struct{ text string }

func (e *pipeError) Error() string { return e.text }

// telegramTLS is the TLS the bot runs over the pipe: api.telegram.org's certificate checked against
// roots (nil: the system's), TLS 1.2 at least.
func telegramTLS(roots *x509.CertPool) *tls.Config {
	return &tls.Config{ServerName: telegramHost, RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func newTelegramClient(token string, d pipeDialer, roots *x509.CertPool) *telegramClient {
	tr := &http.Transport{
		Proxy:                  nil, // never an environment's proxy: the pipe is the only way out
		DialContext:            d.dial,
		TLSClientConfig:        telegramTLS(roots),
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  telegramPollWait + 15*time.Second,
		MaxIdleConns:           2,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &telegramClient{token: token, hc: &http.Client{Transport: tr}}
}

// telegramError is an answer of Telegram's that says no. code is its error_code (401 for a token
// that is no bot's).
type telegramError struct {
	method string
	code   int
	desc   string
}

func (e *telegramError) Error() string {
	return fmt.Sprintf("telegram %s: %d %s", e.method, e.code, e.desc)
}

// call sends one method with its parameters as JSON and decodes the answer's result into out.
func (c *telegramClient) call(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+telegramHost+"/bot"+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram %s: the request could not be made", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return &transportError{method: method, text: c.scrub(unwrapURLError(err)), cause: unwrapURLError(err)}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxTelegramAnswer+1))
	if err != nil {
		return fmt.Errorf("telegram %s: reading the answer: %v", method, c.scrub(err))
	}
	if len(b) > maxTelegramAnswer {
		return fmt.Errorf("telegram %s: an answer over %d bytes", method, maxTelegramAnswer)
	}
	return decodeTelegramAnswer(method, resp.StatusCode, b, out)
}

// transportError is a call that got no answer. Its text has the token taken out; its cause, which
// holds no URL, is kept so botFailure can name the kind of failure.
type transportError struct {
	method, text string
	cause        error
}

func (e *transportError) Error() string { return "telegram " + e.method + ": " + e.text }
func (e *transportError) Unwrap() error { return e.cause }

// unwrapURLError drops the URL from a transport error: the URL holds the token.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// scrub takes the token out of any text that might hold it.
func (c *telegramClient) scrub(err error) string {
	s := err.Error()
	if c.token != "" {
		s = strings.ReplaceAll(s, c.token, "<token>")
	}
	return s
}

// telegramEnvelope is every answer of the Bot API.
type telegramEnvelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
}

func decodeTelegramAnswer(method string, status int, b []byte, out any) error {
	var env telegramEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("telegram %s: the answer is not the Bot API's (HTTP %d)", method, status)
	}
	if !env.OK {
		code := env.ErrorCode
		if code == 0 {
			code = status
		}
		return &telegramError{method: method, code: code, desc: truncate(printable(env.Description), 200)}
	}
	if out == nil {
		return nil
	}
	if len(env.Result) == 0 {
		return fmt.Errorf("telegram %s: the answer has no result", method)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("telegram %s: the result is not what %s answers", method, method)
	}
	return nil
}

// printable keeps a text from Telegram fit for a log line: no control characters.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// ---------------------------------------------------------------- what the bot reads

type tgUser struct {
	ID       int64  `json:"id"`
	IsBot    bool   `json:"is_bot"`
	Username string `json:"username"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

// tgUpdate is one update. Bad is set when it is not within the bounds below: its id still moves the
// offset on, and nothing else in it is read.
type tgUpdate struct {
	UpdateID      int64       `json:"update_id"`
	Message       *tgMessage  `json:"message"`
	CallbackQuery *tgCallback `json:"callback_query"`
	Bad           bool        `json:"-"`
}

var chatTypes = map[string]bool{"private": true, "group": true, "supergroup": true, "channel": true}

// checkUpdate says whether an update is within the bounds the bot reads it under.
func checkUpdate(u tgUpdate) bool {
	if u.UpdateID <= 0 || (u.Message == nil) == (u.CallbackQuery == nil) {
		return false
	}
	checkMsg := func(m *tgMessage) bool {
		return m.MessageID > 0 && chatTypes[m.Chat.Type] && m.Chat.ID != 0 && len(m.Text) <= maxTelegramText &&
			(m.From == nil || m.From.ID != 0)
	}
	if m := u.Message; m != nil {
		return checkMsg(m)
	}
	cb := u.CallbackQuery
	return cb.ID != "" && len(cb.ID) <= 64 && cb.From.ID != 0 && len(cb.Data) <= maxCallbackData &&
		cb.Message != nil && checkMsg(cb.Message)
}

// decodeUpdates reads getUpdates' result: at most maxUpdatesPerPoll updates, each one checked. An
// update that is out of bounds comes back marked Bad, so its id still moves the offset on.
func decodeUpdates(raw json.RawMessage) ([]tgUpdate, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("telegram getUpdates: the result is not a list")
	}
	if len(items) > maxUpdatesPerPoll {
		return nil, fmt.Errorf("telegram getUpdates: %d updates, more than the %d asked for", len(items), maxUpdatesPerPoll)
	}
	out := make([]tgUpdate, 0, len(items))
	for _, it := range items {
		var u tgUpdate
		if err := json.Unmarshal(it, &u); err != nil {
			// Its id, if it has one, still moves the offset on.
			var id struct {
				UpdateID int64 `json:"update_id"`
			}
			_ = json.Unmarshal(it, &id)
			out = append(out, tgUpdate{UpdateID: id.UpdateID, Bad: true})
			continue
		}
		if !checkUpdate(u) {
			out = append(out, tgUpdate{UpdateID: u.UpdateID, Bad: true})
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

// ---------------------------------------------------------------- the methods the bot uses

type tgButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

type tgKeyboard struct {
	Rows [][]tgButton `json:"inline_keyboard"`
}

func (c *telegramClient) getMe(ctx context.Context) (tgUser, error) {
	var u tgUser
	err := c.call(ctx, "getMe", struct{}{}, &u)
	return u, err
}

func (c *telegramClient) getUpdates(ctx context.Context, offset int64, wait time.Duration) ([]tgUpdate, error) {
	var raw json.RawMessage
	err := c.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": int(wait / time.Second),
		"limit": maxUpdatesPerPoll, "allowed_updates": []string{"message", "callback_query"}}, &raw)
	if err != nil {
		return nil, err
	}
	return decodeUpdates(raw)
}

// send sends plain text, with no parse mode, so nothing in it is read as markup.
func (c *telegramClient) send(ctx context.Context, chat int64, text string, kb *tgKeyboard) (int64, error) {
	p := map[string]any{"chat_id": chat, "text": text}
	if kb != nil {
		p["reply_markup"] = kb
	}
	var m tgMessage
	if err := c.call(ctx, "sendMessage", p, &m); err != nil {
		return 0, err
	}
	if m.MessageID <= 0 {
		return 0, fmt.Errorf("telegram sendMessage: no message id in the answer")
	}
	return m.MessageID, nil
}

// edit replaces a message's text and takes its buttons away.
func (c *telegramClient) edit(ctx context.Context, chat, msg int64, text string) error {
	return c.call(ctx, "editMessageText", map[string]any{"chat_id": chat, "message_id": msg, "text": text,
		"reply_markup": tgKeyboard{Rows: [][]tgButton{}}}, nil)
}

func (c *telegramClient) delete(ctx context.Context, chat, msg int64) error {
	return c.call(ctx, "deleteMessage", map[string]any{"chat_id": chat, "message_id": msg}, nil)
}

func (c *telegramClient) answer(ctx context.Context, id, text string) error {
	return c.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}
