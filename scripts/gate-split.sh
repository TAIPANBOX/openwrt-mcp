#!/bin/sh
# gate-split.sh -- CI gate enforcing this invariant (CLAUDE.md, 12):
#
#   "The part that listens and parses holds no root: it runs as its own account with no capability
#   and starts no program, and the helper, which holds root, does not listen on the network and
#   serves only the listener's uid on its socket."
#
# What it reads is the source of what ships: the init script, the listener's capability file, the
# packaging, main.go and the helper's socket code. The behaviour behind it is held by tests
# (split_test.go, split_linux_test.go, features/privilege-split.feature) and by the mutants of
# scripts/mutate-split.py; scripts/e2e-vlab.sh shows it on a running router.
#
#   gate-split.sh                run every check
#   gate-split.sh <check>        run one (features/privilege-split.feature binds a test to each)
#   gate-split.sh --selftest     list the checks, run nothing
#
# SPLIT_ROOT points it at another tree, which is how scripts/gate-split-teeth.sh plants its faults.
set -u

CHECKS='check_listener_runs_as_its_account check_listener_holds_no_capability check_account_is_made check_helper_does_not_listen check_socket_is_the_listeners check_packages_ship_the_listener_file'

if [ "${1:-}" = "--selftest" ]; then
	for c in $CHECKS; do echo "$c"; done
	exit 0
fi

ROOT=${SPLIT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
INIT="$ROOT/files/etc/init.d/openwrt-mcp"
SCAPS="$ROOT/files/etc/capabilities/openwrt-mcp-serve.json"

fail() { echo "FAIL $1: $2"; return 1; }
need() { [ -f "$1" ] || { echo "FAIL measured nothing: $1 is not there"; exit 1; }; }
live() { sed -e 's/^[[:space:]]*//' -e '/^#/d' "$INIT"; }
# instance <name> prints the lines of one procd instance, from its open to its close.
instance() { live | awk -v n="$1" '$1 == "procd_open_instance" {on = ($2 == n); next} $1 == "procd_close_instance" {on = 0} on'; }

check_listener_runs_as_its_account() {
	need "$INIT"
	s=$(instance serve); h=$(instance helper)
	[ -n "$s" ] && [ -n "$h" ] || { fail check_listener_runs_as_its_account "the init script does not open the instances helper and serve"; return 1; }
	echo "$h" | grep -qE '^procd_set_param[[:space:]]+command[[:space:]]+"\$PROG"[[:space:]]+helper[[:space:]]*$' &&
		echo "$s" | grep -qE '^procd_set_param[[:space:]]+command[[:space:]]+"\$PROG"[[:space:]]+serve[[:space:]]*$' ||
		{ fail check_listener_runs_as_its_account "the instances do not run 'helper' and 'serve'"; return 1; }
	for p in 'user "\$ACCOUNT"' 'group "\$ACCOUNT"' 'no_new_privs 1' 'capabilities /etc/capabilities/openwrt-mcp-serve\.json'; do
		echo "$s" | grep -qE "^procd_set_param[[:space:]]+$p[[:space:]]*\$" ||
			{ fail check_listener_runs_as_its_account "the serve instance lacks 'procd_set_param $p'"; return 1; }
	done
	echo "$s" | grep -qE '^procd_add_jail[[:space:]]+openwrt-mcp-serve[[:space:]]*$' ||
		{ fail check_listener_runs_as_its_account "no bare jail line in the serve instance: procd would apply neither the account's capability file nor the account through ujail"; return 1; }
	live | grep -qE '^ACCOUNT=openwrt-mcp[[:space:]]*$' ||
		{ fail check_listener_runs_as_its_account "ACCOUNT is not openwrt-mcp"; return 1; }
	if echo "$h" | grep -qE '^procd_set_param[[:space:]]+(user|group)[[:space:]]'; then
		fail check_listener_runs_as_its_account "the helper instance switches account: the account is the listener's"; return 1
	fi
	echo "ok   check_listener_runs_as_its_account"
}

check_listener_holds_no_capability() {
	need "$SCAPS"
	python3 - "$SCAPS" <<'PY' || return 1
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("FAIL check_listener_holds_no_capability: %s does not parse: %s" % (sys.argv[1], e)); sys.exit(1)
sets = ["bounding", "effective", "permitted", "inheritable", "ambient"]
missing = [s for s in sets if s not in d]
if missing:
    print("FAIL check_listener_holds_no_capability: list(s) not named: %s (procd reads an absent list as every capability)" % ", ".join(missing)); sys.exit(1)
held = sorted({c for s in sets for c in d[s]})
if held:
    print("FAIL check_listener_holds_no_capability: the listener's file holds %s" % ", ".join(held)); sys.exit(1)
PY
	echo "ok   check_listener_holds_no_capability"
}

check_account_is_made() {
	need "$INIT"
	body=$(live | awk '/^start_service\(\)/ {on=1} on {print} on && /^procd_open_instance/ {exit}')
	echo "$body" | grep -qE '^ensure_account([[:space:]]|$)' ||
		{ fail check_account_is_made "start_service does not make the account before it opens an instance"; return 1; }
	live | awk '/^ensure_account\(\)/ {on=1} on {print} on && /^}/ {exit}' | grep -q 'user_add "\$ACCOUNT"' ||
		{ fail check_account_is_made "ensure_account does not add the account"; return 1; }
	echo "ok   check_account_is_made"
}

# The helper never opens a network socket: only the listener (frontend.go) calls net.Listen, and the
# helper's command never reaches the listener's code, nor the listener's the Server.
check_helper_does_not_listen() {
	need "$ROOT/main.go"; need "$ROOT/frontend.go"; need "$ROOT/helper.go"
	bad=$(cd "$ROOT" && grep -lE 'net\.Listen\(|ListenTCP\(|ListenUDP\(|ListenPacket\(' $(ls *.go | grep -v '_test\.go$') | grep -vx frontend.go)
	[ -z "$bad" ] || { fail check_helper_does_not_listen "a network listener outside frontend.go: $bad"; return 1; }
	helper=$(awk '/case "helper":/ {on=1; next} on && /case "/ {exit} on' "$ROOT/main.go")
	serve=$(awk '/case "serve":/ {on=1; next} on && /case "/ {exit} on' "$ROOT/main.go")
	[ -n "$helper" ] && [ -n "$serve" ] || { fail check_helper_does_not_listen "main.go has no helper or serve command"; return 1; }
	if echo "$helper" | grep -qE 'newFrontend|\.Serve\('; then fail check_helper_does_not_listen "the helper command starts the listener"; return 1; fi
	if echo "$serve" | grep -qE 'NewServer|runHelper'; then fail check_helper_does_not_listen "the serve command builds the helper's Server"; return 1; fi
	echo "$helper" | grep -q 'runHelper(' || { fail check_helper_does_not_listen "the helper command does not run the helper's socket"; return 1; }
	echo "ok   check_helper_does_not_listen"
}

# The socket: the directory 0750 and the socket 0660, both root:<the listener's group> when root, and
# every connection's kernel-reported uid compared with the listener's before a byte is read.
check_socket_is_the_listeners() {
	need "$ROOT/helper.go"; need "$ROOT/peer_linux.go"
	grep -q 'mode = 0o750' "$ROOT/helper.go" && grep -q 'sock = 0o660' "$ROOT/helper.go" ||
		{ fail check_socket_is_the_listeners "the socket's directory is not 0750 or the socket not 0660"; return 1; }
	grep -q 'SO_PEERCRED' "$ROOT/peer_linux.go" ||
		{ fail check_socket_is_the_listeners "the peer's uid is not read from SO_PEERCRED"; return 1; }
	awk '/^func \(h \*helperServer\) handle\(/ {on=1} on && /uid != h.parserUID/ {u=NR} on && /readFrame\(/ {r=NR} on && /^}/ {exit} END {exit !(u && r && u < r)}' "$ROOT/helper.go" ||
		{ fail check_socket_is_the_listeners "handle does not compare the peer's uid with the listener's before it reads a frame"; return 1; }
	echo "ok   check_socket_is_the_listeners"
}

check_packages_ship_the_listener_file() {
	for f in mkipk.sh mkapk.sh Makefile files/lib/upgrade/keep.d/openwrt-mcp; do need "$ROOT/$f"; done
	for f in mkipk.sh mkapk.sh; do
		grep -q 'files/etc/capabilities/\$PKG-serve.json' "$ROOT/$f" ||
			{ fail check_packages_ship_the_listener_file "$f does not install the listener's capability file: procd would not start the listener"; return 1; }
	done
	grep -q 'files/etc/capabilities/openwrt-mcp-serve.json' "$ROOT/Makefile" ||
		{ fail check_packages_ship_the_listener_file "make install does not copy the listener's capability file"; return 1; }
	grep -qx '/etc/capabilities/openwrt-mcp-serve.json' "$ROOT/files/lib/upgrade/keep.d/openwrt-mcp" ||
		{ fail check_packages_ship_the_listener_file "keep.d does not carry the listener's capability file across a firmware upgrade"; return 1; }
	echo "ok   check_packages_ship_the_listener_file"
}

if [ $# -gt 0 ]; then
	case " $CHECKS " in *" $1 "*) "$1"; exit $? ;; esac
	echo "FAIL no check named $1"; exit 1
fi
rc=0
for c in $CHECKS; do "$c" || rc=1; done
[ "$rc" -eq 0 ] && echo "gate-split: $(echo $CHECKS | wc -w | tr -d ' ') checks, all ok"
exit $rc
