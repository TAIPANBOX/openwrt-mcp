#!/bin/sh
# gate-ownbot-teeth.sh -- gate-ownbot.sh must go red on each fault planted in a copy of the tree, stay
# green on the tree as it is, not be fooled by a word in a comment, and say "measured nothing" when a
# file it reads is gone.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
GATE="$REPO/scripts/gate-ownbot.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
rc=0

fresh() { rm -rf "$TMP/t"; mkdir -p "$TMP/t"; (cd "$REPO" && tar cf - files ./*.go) | (cd "$TMP/t" && tar xf -); }
gate() { OWNBOT_ROOT="$TMP/t" sh "$GATE" "$@" 2>&1; }

fresh
out=$(gate) || { echo "FAIL: the gate is red on the tree as it is:"; echo "$out"; exit 1; }
echo "ok   green on the tree as it is"

# plant <check> <description> <file> <sed expression>
plant() {
	fresh
	sed -i.bak "$4" "$TMP/t/$3" && rm -f "$TMP/t/$3.bak"
	if cmp -s "$TMP/t/$3" "$REPO/$3"; then echo "FAIL: the fault '$2' changed nothing in $3 (the case is dead)"; rc=1; return; fi
	if out=$(gate "$1"); then echo "FAIL: '$2' was not caught by $1"; echo "$out"; rc=1; return; fi
	echo "$out" | grep -q "^FAIL $1:" || { echo "FAIL: '$2' failed $1 but not with its own message: $out"; rc=1; return; }
	echo "ok   $1 catches: $2"
}

I=files/etc/init.d/openwrt-mcp
plant check_ip_sockets_are_the_listeners "the bot dials Telegram itself" telegram.go 's|c, err := nd.DialContext(ctx, "unix", d.path)|c, err := nd.DialContext(ctx, "tcp", telegramAddr)|'
plant check_ip_sockets_are_the_listeners "the helper opens a socket of its own" ownbot.go 's|^\(func (s \*Server) ownerBotChannel() bool {\)|\1\n\t_, _ = net.Dial("udp", "8.8.8.8:53")|'
plant check_ip_sockets_are_the_listeners "the bot takes Go's default client" ownbot.go 's|^\(func (s \*Server) ownerBotChannel() bool {\)|\1\n\t_ = http.DefaultClient|'
plant check_ip_sockets_are_the_listeners "the bot calls the pipe's dial in-process" ownbot.go 's|^\(func (s \*Server) ownerBotChannel() bool {\)|\1\n\t_, _ = dialTelegram(context.Background())|'
plant check_ip_sockets_are_the_listeners "the pipe's uid is not checked" telegram.go 's/uid != d.uid/false/'
plant check_ip_sockets_are_the_listeners "the transport dials on its own" telegram.go 's/DialContext:\([[:space:]]*\)d.dial,/DialContext:\1nil,/'
plant check_bot_speaks_to_telegram_only "another host" telegram.go 's/telegramHost = "api.telegram.org"/telegramHost = "api.telegram.org.example"/'
plant check_bot_speaks_to_telegram_only "the URL names another host" telegram.go 's|"https://"+telegramHost+"/bot"|"https://evil.example/bot"|'
plant check_bot_speaks_to_telegram_only "the certificate not checked" telegram.go 's/MinVersion: tls.VersionTLS12}/MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}/'
plant check_bot_speaks_to_telegram_only "the name not checked" telegram.go 's/ServerName: telegramHost, //'
plant check_bot_speaks_to_telegram_only "TLS 1.0 allowed" telegram.go 's/MinVersion: tls.VersionTLS12/MinVersion: tls.VersionTLS10/'
plant check_bot_speaks_to_telegram_only "a proxy from the environment" telegram.go 's/Proxy:\([[:space:]]*\)nil,/Proxy:\1http.ProxyFromEnvironment,/'
plant check_approver_tools_refused_with_the_bot "action_approve not refused" approval.go '/^func (s \*Server) actionApprove(/,/^}/{/mcpApproverRefusal/s/s.mcpApproverRefusal()/error(nil)/;}'
plant check_approver_tools_refused_with_the_bot "action_list not refused" approval.go '/^func (s \*Server) actionList(/,/^}/{/mcpApproverRefusal/s/s.mcpApproverRefusal()/error(nil)/;}'
plant check_approver_tools_refused_with_the_bot "action_reject not refused" approval.go '/^func (s \*Server) actionReject(/,/^}/{/mcpApproverRefusal/s/s.mcpApproverRefusal()/error(nil)/;}'
plant check_approver_tools_refused_with_the_bot "mfa_unlock for another client not refused" tools.go '/^func (s \*Server) unlockTarget(/,/^}/{/mcpApproverRefusal/s/s.mcpApproverRefusal()/error(nil)/;}'
plant check_approver_tools_refused_with_the_bot "mfa_lock for another client not refused" tools.go '/toolOf("mfa_lock"/,/toolOf("action_status"/{/mcpApproverRefusal/s/s.mcpApproverRefusal()/error(nil)/;}'
plant check_approver_tools_refused_with_the_bot "the refusal never fires" ownbot.go 's/^\(\t\)if !s.ownerBotChannel() {/\1if true {/'
plant check_pipe_serves_the_helper_only "the pipe serves any uid" relay.go 's/uid != r.allowUID/false/'
plant check_pipe_serves_the_helper_only "the pipe serves the listener's own uid" relay.go 's/newTelegramRelay(0)/newTelegramRelay(os.Getuid())/'
plant check_pipe_serves_the_helper_only "the listener does not serve the pipe" main.go '/^[[:space:]]*startRelay(\*relayPath)/d'
plant check_pipe_serves_the_helper_only "the helper serves the pipe" main.go 's|must(runHelper(s, \*socketPath, \*relayPath))|startRelay(*relayPath); must(runHelper(s, *socketPath, *relayPath))|'
plant check_init_makes_the_pipe_dir "the directory open to every account" $I 's/chmod 0700 "$RELAY_DIR"/chmod 0755 "$RELAY_DIR"/'
plant check_init_makes_the_pipe_dir "the directory left to root" $I 's/chown "$ACCOUNT:$ACCOUNT" "$RELAY_DIR" \&\& //'
plant check_init_makes_the_pipe_dir "the directory never made" $I '/^[[:space:]]*ensure_relay_dir ||/d'
plant check_init_makes_the_pipe_dir "the socket elsewhere" telegram.go 's|/var/run/openwrt-mcp-relay/telegram.sock|/tmp/telegram.sock|'
plant check_factor_deleted_before_read "the reply to Approve read before it is deleted" ownbot.go '/^func (b \*ownerBot) factor(/,/^}/{s/^\(\t\)b.deleteMsg(ctx, tc, m)/\1defer b.deleteMsg(ctx, tc, m)/;}'
plant check_factor_deleted_before_read "an /unlock never deleted" ownbot.go '/^func (b \*ownerBot) unlock(/,/^}/{/^\tb.deleteMsg(ctx, tc, m)/d;}'

# A word in a comment is not code: the refusal of action_approve commented out.
fresh
sed -i.bak '/^func (s \*Server) actionApprove(/,/^}/{s|^\(\t\)if err := s.mcpApproverRefusal(); err != nil {|\1// if err := s.mcpApproverRefusal(); err != nil {\n\tif false {|;}' "$TMP/t/approval.go"
if gate check_approver_tools_refused_with_the_bot >/dev/null; then echo "FAIL: a commented-out refusal passed"; rc=1; else echo "ok   a commented-out refusal is not a refusal"; fi

# A gate whose subject is gone says so; it does not pass.
for f in telegram.go relay.go ownbot.go approval.go $I; do
	fresh; rm "$TMP/t/$f"
	out=$(gate); if echo "$out" | grep -q "measured nothing" && ! gate >/dev/null; then echo "ok   a missing $f reads 'measured nothing', not ok"; else echo "FAIL: a missing $f did not read 'measured nothing': $out"; rc=1; fi
done

[ "$rc" -eq 0 ] && echo "gate-ownbot-teeth: every planted fault is caught"
exit $rc
