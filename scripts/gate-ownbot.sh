#!/bin/sh
# gate-ownbot.sh -- CI gate enforcing this invariant (CLAUDE.md, 13):
#
#   "Once the router's own bot is bound, the owner's card and factor never pass the listener: the
#   helper's TLS to api.telegram.org runs over the listener's pipe, which serves the helper only and
#   dials that one address; no MCP client approves, lists, rejects, unlocks or locks for an approval
#   section; and a factor's message is deleted before it is read."
#
# It reads the source of what ships. The behaviour behind it is held by tests (ownbot_test.go,
# ownbot_transport_test.go, features/owner-bot.feature) and by the mutants of scripts/mutate-ownbot.py;
# scripts/e2e-vlab.sh shows it on a running router.
#
#   gate-ownbot.sh                run every check
#   gate-ownbot.sh <check>        run one (features/owner-bot.feature binds a test to each)
#   gate-ownbot.sh --selftest     list the checks, run nothing
#
# OWNBOT_ROOT points it at another tree, which is how scripts/gate-ownbot-teeth.sh plants its faults.
set -u

CHECKS='check_ip_sockets_are_the_listeners check_bot_speaks_to_telegram_only check_approver_tools_refused_with_the_bot check_pipe_serves_the_helper_only check_init_makes_the_pipe_dir check_factor_deleted_before_read'

if [ "${1:-}" = "--selftest" ]; then
	for c in $CHECKS; do echo "$c"; done
	exit 0
fi

ROOT=${OWNBOT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
INIT="$ROOT/files/etc/init.d/openwrt-mcp"

fail() { echo "FAIL $1: $2"; return 1; }
need() { [ -f "$1" ] || { echo "FAIL measured nothing: $1 is not there"; exit 1; }; }
src() { (cd "$ROOT" && ls *.go | grep -v '_test\.go$'); }
# body <file> <the start of its first line> prints one function, from that line to its closing brace,
# without its comment lines: a word in a comment is not code.
body() { awk -v s="$2" 'index($0, s) == 1 {on=1} on && $0 !~ /^[[:space:]]*\/\// {print} on && /^}/ {exit}' "$ROOT/$1"; }

# Every IP socket of the binary, by its literal: the listener's HTTP (frontend.go), the listener's pipe
# to api.telegram.org (relay.go) and the status command's probe of /health (status.go), and no other.
# The helper's own code names no IP network at all, so its bot reaches Telegram through the pipe.
check_ip_sockets_are_the_listeners() {
	need "$ROOT/telegram.go"; need "$ROOT/relay.go"; need "$ROOT/ownbot.go"
	got=$(cd "$ROOT" && grep -nE '"(tcp|tcp4|tcp6|udp|udp4|udp6|ip|ip4|ip6)(:[^"]*)?"|DialTCP|DialUDP|DialIP|ListenPacket|ListenTCP|ListenUDP|http\.(Get|Post|Head)\(|DefaultTransport|DefaultClient' $(src) |
		sed -E 's/^([^:]+):[0-9]+:[[:space:]]*/\1: /')
	want='frontend.go: ln, err := net.Listen("tcp", listen)
relay.go: return d.DialContext(ctx, "tcp", telegramAddr)
status.go: c, err := net.DialTimeout("tcp", listen, 2*time.Second)'
	[ "$got" = "$want" ] || { fail check_ip_sockets_are_the_listeners "the IP sockets are not the three of the listener and the status probe:
$got"; return 1; }
	# The pipe's dial is called from the listener's relay only, and the probe from the status command only.
	for f in $(src); do
		case "$f" in relay.go) ;; *) if grep -q 'dialTelegram' "$ROOT/$f"; then fail check_ip_sockets_are_the_listeners "$f reaches the pipe's dial"; return 1; fi ;; esac
		case "$f" in status.go) ;; *) if grep -qE 'probeDaemon|daemonRunning' "$ROOT/$f"; then fail check_ip_sockets_are_the_listeners "$f reaches the status probe"; return 1; fi ;; esac
	done
	# The bot's client dials the pipe, a Unix socket, and checks whose it is before a byte is sent.
	d=$(body telegram.go 'func (d pipeDialer) dial(')
	echo "$d" | grep -q 'DialContext(ctx, "unix", d.path)' && echo "$d" | grep -q 'uid != d.uid' ||
		{ fail check_ip_sockets_are_the_listeners "the bot's dialer does not dial the pipe as a Unix socket and check its uid"; return 1; }
	grep -q 'DialContext:[[:space:]]*d.dial,' "$ROOT/telegram.go" ||
		{ fail check_ip_sockets_are_the_listeners "the bot's transport does not dial through the pipe"; return 1; }
	echo "ok   check_ip_sockets_are_the_listeners"
}

# The bot speaks to api.telegram.org and nothing else, over TLS checked against the roots, with no
# proxy and nothing that skips the check.
check_bot_speaks_to_telegram_only() {
	need "$ROOT/telegram.go"
	grep -qE '^[[:space:]]*telegramHost[[:space:]]*=[[:space:]]*"api\.telegram\.org"' "$ROOT/telegram.go" &&
		grep -qE '^[[:space:]]*telegramAddr[[:space:]]*=[[:space:]]*telegramHost \+ ":443"' "$ROOT/telegram.go" ||
		{ fail check_bot_speaks_to_telegram_only "the bot's host is not api.telegram.org:443"; return 1; }
	grep -q '"https://"+telegramHost+"/bot"' "$ROOT/telegram.go" ||
		{ fail check_bot_speaks_to_telegram_only "the bot's URL is not built from telegramHost"; return 1; }
	t=$(body telegram.go 'func telegramTLS(')
	echo "$t" | grep -q 'ServerName: telegramHost' && echo "$t" | grep -q 'MinVersion: tls.VersionTLS12' ||
		{ fail check_bot_speaks_to_telegram_only "the bot's TLS does not check api.telegram.org's name, or allows less than TLS 1.2"; return 1; }
	if (cd "$ROOT" && grep -nE 'InsecureSkipVerify|VerifyPeerCertificate|VerifyConnection' $(src)) >/dev/null; then
		fail check_bot_speaks_to_telegram_only "something skips or replaces the certificate check"; return 1
	fi
	grep -qE '^[[:space:]]*Proxy:[[:space:]]*nil,' "$ROOT/telegram.go" ||
		{ fail check_bot_speaks_to_telegram_only "the bot's transport may take a proxy from the environment"; return 1; }
	echo "ok   check_bot_speaks_to_telegram_only"
}

# Once the bot is bound, an approver's tool over MCP is refused before anything is looked up.
check_approver_tools_refused_with_the_bot() {
	need "$ROOT/approval.go"; need "$ROOT/tools.go"
	for fn in actionList actionApprove actionReject; do
		b=$(body approval.go "func (s *Server) $fn(")
		[ -n "$b" ] || { fail check_approver_tools_refused_with_the_bot "approval.go has no $fn"; return 1; }
		first=$(echo "$b" | sed -n '2p')
		echo "$first" | grep -qE '^[[:space:]]*if err := s\.mcpApproverRefusal\(\); err != nil \{$' ||
			{ fail check_approver_tools_refused_with_the_bot "$fn does not refuse first when the router's bot is bound"; return 1; }
	done
	u=$(body tools.go 'func (s *Server) unlockTarget(')
	echo "$u" | awk '/mcpApproverRefusal\(\)/ {r=NR} /approves\(caller, named\)/ {a=NR} END {exit !(r && a && r < a)}' ||
		{ fail check_approver_tools_refused_with_the_bot "mfa_unlock for another client is not refused before the approver is looked up"; return 1; }
	awk '/toolOf\("mfa_lock"/ {on=1} on && /^[[:space:]]*\/\// {next} on && /mcpApproverRefusal\(\)/ {r=NR} on && /approves\(client, in.Client\)/ {a=NR; exit} END {exit !(r && a && r < a)}' "$ROOT/tools.go" ||
		{ fail check_approver_tools_refused_with_the_bot "mfa_lock for another client is not refused before the approver is looked up"; return 1; }
	m=$(body ownbot.go 'func (s *Server) mcpApproverRefusal(')
	echo "$m" | grep -q 'if !s.ownerBotChannel() {' ||
		{ fail check_approver_tools_refused_with_the_bot "the refusal is not tied to the bot being bound"; return 1; }
	echo "ok   check_approver_tools_refused_with_the_bot"
}

# The pipe serves root, the helper, compared before it dials; the listener starts it, the helper never.
check_pipe_serves_the_helper_only() {
	need "$ROOT/relay.go"; need "$ROOT/main.go"
	body relay.go 'func (r *telegramRelay) handle(' |
		awk '/uid != r.allowUID/ {u=NR} /r.dial\(/ {d=NR} END {exit !(u && d && u < d)}' ||
		{ fail check_pipe_serves_the_helper_only "the pipe does not compare its peer's uid before it dials"; return 1; }
	grep -q 'newTelegramRelay(0)' "$ROOT/relay.go" ||
		{ fail check_pipe_serves_the_helper_only "the pipe serves another uid than root's"; return 1; }
	serve=$(awk '/case "serve":/ {on=1; next} on && /case "/ {exit} on' "$ROOT/main.go")
	helper=$(awk '/case "helper":/ {on=1; next} on && /case "/ {exit} on' "$ROOT/main.go")
	echo "$serve" | grep -q 'startRelay(' || { fail check_pipe_serves_the_helper_only "the listener does not serve the pipe"; return 1; }
	if echo "$helper" | grep -qE 'startRelay|newTelegramRelay'; then
		fail check_pipe_serves_the_helper_only "the helper serves the pipe itself"; return 1
	fi
	echo "ok   check_pipe_serves_the_helper_only"
}

# The init script makes the pipe's directory the listener's own, 0700, before procd starts a part, and
# the binary's default socket is in it.
check_init_makes_the_pipe_dir() {
	need "$INIT"; need "$ROOT/telegram.go"
	live=$(sed -e 's/^[[:space:]]*//' -e '/^#/d' "$INIT")
	echo "$live" | grep -qx 'RELAY_DIR=/var/run/openwrt-mcp-relay' ||
		{ fail check_init_makes_the_pipe_dir "RELAY_DIR is not /var/run/openwrt-mcp-relay"; return 1; }
	f=$(echo "$live" | awk '/^ensure_relay_dir\(\)/ {on=1} on {print} on && /^}/ {exit}')
	echo "$f" | grep -q 'chown "$ACCOUNT:$ACCOUNT" "$RELAY_DIR"' && echo "$f" | grep -q 'chmod 0700 "$RELAY_DIR"' ||
		{ fail check_init_makes_the_pipe_dir "the pipe's directory is not the listener's own, 0700"; return 1; }
	echo "$live" | awk '/^start_service\(\)/ {on=1} on && /^ensure_relay_dir/ {e=NR} on && /^procd_open_instance/ {p=NR; exit} END {exit !(e && p && e < p)}' ||
		{ fail check_init_makes_the_pipe_dir "start_service does not make the pipe's directory before it opens an instance"; return 1; }
	grep -q 'defaultRelaySocket = "/var/run/openwrt-mcp-relay/telegram.sock"' "$ROOT/telegram.go" ||
		{ fail check_init_makes_the_pipe_dir "the pipe's default socket is not in that directory"; return 1; }
	echo "ok   check_init_makes_the_pipe_dir"
}

# A message that carries the owner's factor is deleted before it is read: the deletion comes before the
# parse, in the reply to Approve and in /unlock.
check_factor_deleted_before_read() {
	need "$ROOT/ownbot.go"
	for fn in factor unlock; do
		body ownbot.go "func (b *ownerBot) $fn(" |
			awk '/b.deleteMsg\(ctx, tc, m\)/ && !d {d=NR} /parseFactor\(/ && !p {p=NR} END {exit !(d && p && d < p)}' ||
			{ fail check_factor_deleted_before_read "$fn reads the factor before it deletes the message"; return 1; }
		if body ownbot.go "func (b *ownerBot) $fn(" | grep -qE 'defer b\.deleteMsg'; then
			fail check_factor_deleted_before_read "$fn defers the deletion past the read"; return 1
		fi
	done
	echo "ok   check_factor_deleted_before_read"
}

if [ $# -gt 0 ]; then
	case " $CHECKS " in *" $1 "*) "$1"; exit $? ;; esac
	echo "FAIL no check named $1"; exit 1
fi
rc=0
for c in $CHECKS; do "$c" || rc=1; done
[ "$rc" -eq 0 ] && echo "gate-ownbot: $(echo $CHECKS | wc -w | tr -d ' ') checks, all ok"
exit $rc
