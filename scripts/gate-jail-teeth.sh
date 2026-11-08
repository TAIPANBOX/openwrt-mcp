#!/bin/sh
# gate-jail-teeth.sh -- gate-jail.sh must go red on each fault planted in a copy of the tree, stay
# green on the tree as it is, not be fooled by a word in a comment, and say "measured nothing" when
# a file it reads is gone.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
GATE="$REPO/scripts/gate-jail.sh"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
rc=0

fresh() { rm -rf "$TMP/t"; mkdir -p "$TMP/t"; (cd "$REPO" && tar cf - files seccomp main.go seccomp_linux.go seccomp_filter.go mkipk.sh mkapk.sh Makefile) | (cd "$TMP/t" && tar xf -); }
gate() { JAIL_ROOT="$TMP/t" sh "$GATE" "$@" 2>&1; }

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

plant check_ujail_carries_the_capabilities "the jail line deleted" files/etc/init.d/openwrt-mcp '/^[[:space:]]*procd_add_jail openwrt-mcp/d'
plant check_no_namespaces_and_no_mounts "a mount added" files/etc/init.d/openwrt-mcp 's|^\(.*\)procd_add_jail openwrt-mcp$|&\n\1procd_add_jail_mount_rw /etc|'
plant check_no_namespaces_and_no_mounts "a read-only mount added" files/etc/init.d/openwrt-mcp 's|^\(.*\)procd_add_jail openwrt-mcp$|&\n\1procd_add_jail_mount /etc/config/openwrt-mcp|'
plant check_no_namespaces_and_no_mounts "procfs asked of ujail" files/etc/init.d/openwrt-mcp 's|procd_add_jail openwrt-mcp$|procd_add_jail openwrt-mcp procfs|'
plant check_no_namespaces_and_no_mounts "ubus socket asked of ujail" files/etc/init.d/openwrt-mcp 's|procd_add_jail openwrt-mcp$|procd_add_jail openwrt-mcp ubus|'
plant check_no_namespaces_and_no_mounts "requirejail asked" files/etc/init.d/openwrt-mcp 's|procd_add_jail openwrt-mcp$|procd_add_jail openwrt-mcp requirejail|'
plant check_no_new_privs "no_new_privs deleted" files/etc/init.d/openwrt-mcp '/no_new_privs/d'
plant check_no_new_privs "no_new_privs set to 0" files/etc/init.d/openwrt-mcp 's/no_new_privs 1/no_new_privs 0/'
plant check_capability_set "CAP_SYS_ADMIN in the bounding set" files/etc/capabilities/openwrt-mcp.json 's/"CAP_CHOWN",/"CAP_CHOWN", "CAP_SYS_ADMIN",/'
plant check_capability_set "CAP_SYS_MODULE added" files/etc/capabilities/openwrt-mcp.json 's/"CAP_KILL",/"CAP_KILL", "CAP_SYS_MODULE",/'
plant check_capability_set "the ambient list not named" files/etc/capabilities/openwrt-mcp.json '/"ambient"/d'
plant check_capability_set "the capability file not handed to procd" files/etc/init.d/openwrt-mcp '/set_param capabilities/d'
plant check_seccomp_is_in_the_daemon "a procd seccomp profile set" files/etc/init.d/openwrt-mcp 's|^\(.*\)procd_set_param no_new_privs 1|&\n\1procd_set_param seccomp /etc/seccomp/openwrt-mcp.json|'
plant check_seccomp_is_in_the_daemon "confine() not called in serve" main.go '/^[[:space:]]*confine()$/d'
plant check_seccomp_is_in_the_daemon "ptrace off the list" seccomp/denied.txt '/^ptrace$/d'
plant check_seccomp_is_in_the_daemon "mount off the list" seccomp/denied.txt '/^mount$/d'
plant check_seccomp_is_in_the_daemon "the x32 numbers not killed" seccomp_filter.go 's/bpfJGE/bpfJAx/g'
plant check_seccomp_is_in_the_daemon "no check of the capability sets" seccomp_filter.go 's/checkCapabilities(status, expectedCaps)/nil/'
plant check_seccomp_is_in_the_daemon "no check of /proc/self/status" seccomp_linux.go 's/checkSeccompStatus/skipSeccompStatus/g'
plant check_packages_ship_the_capability_file "the .ipk does not install the file" mkipk.sh '/etc\/capabilities\/\$PKG.json/d'
plant check_packages_ship_the_capability_file "the .apk does not install the file" mkapk.sh '/etc\/capabilities\/\$PKG.json/d'
plant check_packages_ship_the_capability_file "make install does not copy the file" Makefile '/capabilities/d'
plant check_packages_ship_the_capability_file "keep.d lacks the file" files/lib/upgrade/keep.d/openwrt-mcp '/capabilities/d'

# A word in a comment is not a command: the real line removed, the comment left.
fresh
sed -i.bak 's/^\([[:space:]]*\)procd_add_jail openwrt-mcp.*/\1# procd_add_jail openwrt-mcp/' "$TMP/t/files/etc/init.d/openwrt-mcp"
if gate check_ujail_carries_the_capabilities >/dev/null; then echo "FAIL: a commented-out jail line passed"; rc=1; else echo "ok   a commented-out jail line is not a jail"; fi
# ... and a mount in a comment is not a mount.
fresh
sed -i.bak 's|^\([[:space:]]*\)procd_add_jail openwrt-mcp$|&\n\1# procd_add_jail_mount_rw /etc|' "$TMP/t/files/etc/init.d/openwrt-mcp"
if gate check_no_namespaces_and_no_mounts >/dev/null; then echo "ok   a mount in a comment is not a mount"; else echo "FAIL: a commented-out mount was counted"; rc=1; fi

# A gate whose subject is gone says so; it does not pass.
fresh; rm "$TMP/t/files/etc/capabilities/openwrt-mcp.json"
out=$(gate check_capability_set); echo "$out" | grep -q "measured nothing" && ! gate check_capability_set >/dev/null &&
	echo "ok   a missing capability file reads 'measured nothing', not ok" || { echo "FAIL: a missing file did not read 'measured nothing': $out"; rc=1; }
fresh; rm "$TMP/t/seccomp/denied.txt"
out=$(gate check_seccomp_is_in_the_daemon); echo "$out" | grep -q "measured nothing" || { echo "FAIL: a missing seccomp list did not read 'measured nothing'"; rc=1; }

[ "$rc" -eq 0 ] && echo "gate-jail-teeth: every planted fault is caught"
exit $rc
