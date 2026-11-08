package main

// `openwrt-mcp owner-bot`: the router's own bot, set up on the router (ownbot.go). Like pair, allow
// and pin, it is CLI only: nothing an MCP client reaches sets a token or binds a chat.
//
//	owner-bot set             the bot's token, read from standard input, never from an argument
//	owner-bot bind [--json]   a one-time code, and the t.me link that sends it when Start is pressed
//	owner-bot status [--json] what is set up, and the bot's last error
//	owner-bot clear           the bot gone; approvals go back to the owner's MCP client

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ownerBotStatus struct {
	Configured bool   `json:"configured"`
	Bound      bool   `json:"bound"`
	Chat       int64  `json:"chat,omitempty"`
	Bot        string `json:"bot,omitempty"`
	Error      string `json:"error,omitempty"`
	Binding    bool   `json:"binding"`
	// Channel is where held changes are approved: "bot" once a chat is bound, "mcp" before.
	Channel string `json:"channel"`
}

func ownerBotStatusOf(statePath string) ownerBotStatus {
	f := ownerBotFilesOf(statePath)
	seen := f.seen()
	st := ownerBotStatus{Configured: f.token() != "", Chat: f.chat(), Bot: seen.Bot, Error: seen.Error,
		Binding: f.bindHash() != "", Channel: "mcp"}
	st.Bound = st.Configured && st.Chat != 0
	if st.Bound {
		st.Channel = "bot"
	}
	return st
}

func runOwnerBot(w io.Writer, stdin io.Reader, statePath string, args []string) error {
	f := ownerBotFilesOf(statePath)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	asJSON := len(args) > 1 && args[1] == "--json"
	switch sub {
	case "set":
		line, err := bufio.NewReader(io.LimitReader(stdin, 512)).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		tok := strings.TrimSpace(line)
		if !botTokenShape.MatchString(tok) {
			return fmt.Errorf("that is not a bot token as BotFather gives it (digits, a colon, then the secret)")
		}
		if tok == f.token() {
			fmt.Fprintln(w, "the router's bot already has this token; nothing changed")
			return nil
		}
		if err := f.write("token", tok+"\n"); err != nil {
			return err
		}
		// A new bot starts from nothing: its chat is bound again, with a new code.
		f.remove("chat")
		f.remove("bind")
		f.remove("seen")
		fmt.Fprintln(w, "the bot's token is saved; bind the owner's chat with: openwrt-mcp owner-bot bind")
		return nil

	case "bind":
		if f.token() == "" {
			return errNoBotToken
		}
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		code := base64.RawURLEncoding.EncodeToString(buf)
		sum := sha256.Sum256([]byte(code))
		// The code's end goes in the file, so a code that lies there while the helper is stopped, or
		// across its restart, ends on time all the same.
		ends := ownerBotWall().Add(bindCodeLife).Unix()
		if err := f.write("bind", hex.EncodeToString(sum[:])+" "+strconv.FormatInt(ends, 10)+"\n"); err != nil {
			return err
		}
		link := ""
		if bot := f.seen().Bot; bot != "" {
			link = "https://t.me/" + bot + "?start=" + code
		}
		if asJSON {
			return json.NewEncoder(w).Encode(map[string]any{"code": code, "link": link,
				"expires_in_seconds": int(bindCodeLife.Seconds())})
		}
		fmt.Fprintf(w, "one-time code: %s\n", code)
		if link != "" {
			fmt.Fprintf(w, "open %s and press Start\n", link)
		} else {
			fmt.Fprintln(w, "send it to the router's bot after pressing Start (the bot's name shows in `owner-bot status` once the router has reached Telegram)")
		}
		fmt.Fprintf(w, "it works once, for %d minutes\n", int(bindCodeLife.Minutes()))
		return nil

	case "status", "":
		st := ownerBotStatusOf(statePath)
		if asJSON || (sub == "status" && len(args) > 1 && args[1] == "--json") {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		}
		switch {
		case !st.Configured:
			fmt.Fprintln(w, "the router's bot: not set up; held changes are approved by the owner's MCP client")
		case !st.Bound:
			fmt.Fprintln(w, "the router's bot: token set, no chat bound yet; held changes are still approved by the owner's MCP client")
		default:
			fmt.Fprintf(w, "the router's bot: bound to chat %d; held changes are approved there, and by no MCP client\n", st.Chat)
		}
		if st.Bot != "" {
			fmt.Fprintf(w, "  bot: @%s\n", st.Bot)
		}
		if st.Binding {
			fmt.Fprintln(w, "  a binding code is waiting to be sent")
		}
		if st.Error != "" {
			fmt.Fprintf(w, "  last error: %s\n", st.Error)
		}
		return nil

	case "clear":
		for _, n := range []string{"token", "chat", "bind", "seen"} {
			f.remove(n)
		}
		fmt.Fprintln(w, "the router's bot is gone; held changes are approved by the owner's MCP client again, if one is paired")
		return nil
	}
	return fmt.Errorf("usage: openwrt-mcp owner-bot set | bind [--json] | status [--json] | clear")
}
