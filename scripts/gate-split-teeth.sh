#!/bin/sh
# gate-split-teeth.sh -- gate-split.sh must go red on each fault planted in a copy of the tree, stay
# green on the tree as it is, not be fooled by a word in a comment, and say "measured nothing" when a
# file it reads is gone.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
GATE="$REPO/scripts/gate-split.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
rc=0

fresh() { rm -rf "$TMP/t"; mkdir -p "$TMP/t"; (cd "$REPO" && tar cf - files ./*.go mkipk.sh mkapk.sh Makefile) | (cd "$TMP/t" && tar xf -); }
gate() { SPLIT_ROOT="$TMP/t" sh "$GATE" "$@" 2>&1; }

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
plant check_listener_runs_as_its_account "the listener runs as root (no user line)" $I '/procd_set_param user "$ACCOUNT"/d'
plant check_listener_runs_as_its_account "the listener keeps root's group" $I '/procd_set_param group "$ACCOUNT"/d'
plant check_listener_runs_as_its_account "the listener without no_new_privs" $I '/procd_open_instance serve/,/procd_close_instance/{/no_new_privs/d;}'
plant check_listener_runs_as_its_account "the listener given the helper's nine capabilities" $I 's|capabilities /etc/capabilities/openwrt-mcp-serve.json|capabilities /etc/capabilities/openwrt-mcp.json|'
plant check_listener_runs_as_its_account "the listener's jail line gone" $I '/procd_add_jail openwrt-mcp-serve/d'
plant check_listener_runs_as_its_account "the account renamed to root" $I 's/^ACCOUNT=openwrt-mcp/ACCOUNT=root/'
plant check_listener_runs_as_its_account "the helper switched to the account" $I 's|^\(.*\)procd_set_param command "$PROG" helper|&\n\1procd_set_param user "$ACCOUNT"|'
plant check_listener_runs_as_its_account "one instance runs both" $I 's|procd_set_param command "$PROG" serve|procd_set_param command "$PROG" helper|'
plant check_listener_holds_no_capability "CAP_NET_ADMIN in the listener's bounding set" files/etc/capabilities/openwrt-mcp-serve.json 's/"bounding": \[\]/"bounding": ["CAP_NET_ADMIN"]/'
plant check_listener_holds_no_capability "CAP_DAC_OVERRIDE effective" files/etc/capabilities/openwrt-mcp-serve.json 's/"effective": \[\]/"effective": ["CAP_DAC_OVERRIDE"]/'
plant check_listener_holds_no_capability "the bounding list not named" files/etc/capabilities/openwrt-mcp-serve.json '/"bounding"/d'
plant check_account_is_made "the account never made" $I '/^[[:space:]]*ensure_account ||/d'
plant check_account_is_made "the account made without user_add" $I 's/user_add "$ACCOUNT"/true "$ACCOUNT"/'
plant check_helper_does_not_listen "the helper listens on TCP" helper.go 's|ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})|ln, err := net.ListenUnix("unix", \&net.UnixAddr{Name: path, Net: "unix"}); _, _ = net.Listen("tcp", "0.0.0.0:1")|'
plant check_helper_does_not_listen "the helper command starts the listener" main.go 's|must(runHelper(s, \*socketPath, \*relayPath))|go newFrontend(s).Serve(s.cfg().Listen); must(runHelper(s, *socketPath, *relayPath))|'
plant check_helper_does_not_listen "the serve command builds the Server" main.go 's|hc := &helperClient{path: \*socketPath}|_, _ = NewServer(*configPath, *statePath); hc := \&helperClient{path: *socketPath}|'
plant check_socket_is_the_listeners "the socket open to everyone" helper.go 's/sock = 0o660/sock = 0o666/'
plant check_socket_is_the_listeners "the directory open to everyone" helper.go 's/mode = 0o750/mode = 0o755/'
plant check_socket_is_the_listeners "no uid check before the frame" helper.go 's/uid != h.parserUID/false/'
plant check_packages_ship_the_listener_file "the .ipk lacks the listener's file" mkipk.sh '/\$PKG-serve.json/d'
plant check_packages_ship_the_listener_file "the .apk lacks the listener's file" mkapk.sh '/\$PKG-serve.json/d'
plant check_packages_ship_the_listener_file "make install lacks it" Makefile '/openwrt-mcp-serve.json/d'
plant check_packages_ship_the_listener_file "keep.d lacks it" files/lib/upgrade/keep.d/openwrt-mcp '/openwrt-mcp-serve.json/d'

# A word in a comment is not a command: the real user line removed, a comment left.
fresh
sed -i.bak 's/^\([[:space:]]*\)procd_set_param user "$ACCOUNT"/\1# procd_set_param user "$ACCOUNT"/' "$TMP/t/$I"
if gate check_listener_runs_as_its_account >/dev/null; then echo "FAIL: a commented-out user line passed"; rc=1; else echo "ok   a commented-out user line is not an account"; fi

# A gate whose subject is gone says so; it does not pass.
fresh; rm "$TMP/t/files/etc/capabilities/openwrt-mcp-serve.json"
out=$(gate check_listener_holds_no_capability); echo "$out" | grep -q "measured nothing" && ! gate check_listener_holds_no_capability >/dev/null &&
	echo "ok   a missing capability file reads 'measured nothing', not ok" || { echo "FAIL: a missing file did not read 'measured nothing': $out"; rc=1; }
fresh; rm "$TMP/t/helper.go"
out=$(gate check_helper_does_not_listen); echo "$out" | grep -q "measured nothing" || { echo "FAIL: a missing helper.go did not read 'measured nothing': $out"; rc=1; }

[ "$rc" -eq 0 ] && echo "gate-split-teeth: every planted fault is caught"
exit $rc
