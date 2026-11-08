#!/bin/sh
# gate-jail.sh -- CI gate enforcing this invariant:
#
#   "The daemon runs in a procd jail, with no_new_privs and a named capability set that leaves out
#   everything its jobs do not use, and installs its own seccomp filter before it reads anything."
#
# What it reads is the source of what ships: the init script, the capability file, main.go, the
# seccomp list and the packaging. It does not start a router; scripts/e2e-vlab.sh does, and shows
# the same properties on a running one (/proc/PID/status). A gate that stops at the source can be
# true of a file that is never installed, so the packaging is one of the checks.
#
#   gate-jail.sh                run every check
#   gate-jail.sh <check>        run one (features/service-jail.feature binds a test to each)
#   gate-jail.sh --selftest     list the checks, run nothing
#
# JAIL_ROOT points it at another tree, which is how scripts/gate-jail-teeth.sh plants its faults.
set -u

CHECKS='check_jail_is_requested check_no_new_privs check_capability_set check_mounts check_seccomp_is_in_the_daemon check_packages_ship_the_capability_file'

if [ "${1:-}" = "--selftest" ]; then
	for c in $CHECKS; do echo "$c"; done
	exit 0
fi

ROOT=${JAIL_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
INIT="$ROOT/files/etc/init.d/openwrt-mcp"
CAPS="$ROOT/files/etc/capabilities/openwrt-mcp.json"

fail() { echo "FAIL $1: $2"; return 1; }
need() { [ -f "$1" ] || { echo "FAIL measured nothing: $1 is not there"; exit 1; }; }
# live prints the init script without comment lines: a word in a comment is not a command.
live() { sed -e 's/^[[:space:]]*//' -e '/^#/d' "$INIT"; }

check_jail_is_requested() {
	need "$INIT"
	live | grep -E '^procd_add_jail[[:space:]]+openwrt-mcp([[:space:]]|$)' | grep -qw requirejail ||
		fail check_jail_is_requested "no 'procd_add_jail openwrt-mcp ... requirejail' in the init script: the daemon would run outside a jail, or fall out of it silently" || return 1
	echo "ok   check_jail_is_requested"
}

check_no_new_privs() {
	need "$INIT"
	live | grep -qE '^procd_set_param[[:space:]]+no_new_privs[[:space:]]+1([[:space:]]|$)' ||
		fail check_no_new_privs "the init script does not set no_new_privs" || return 1
	echo "ok   check_no_new_privs"
}

# Capabilities the daemon and the programs it starts never need. Any of them in the file is a
# fault. The set that is there is named in the file itself, all five lists, bounding included:
# procd 2026.03 reads a list that is absent as every capability.
check_capability_set() {
	need "$INIT"; need "$CAPS"
	live | grep -qE '^procd_set_param[[:space:]]+capabilities[[:space:]]+/etc/capabilities/openwrt-mcp\.json([[:space:]]|$)' ||
		fail check_capability_set "the init script does not hand /etc/capabilities/openwrt-mcp.json to procd" || return 1
	python3 - "$CAPS" <<'PY' || return 1
import json, sys
FORBIDDEN = {"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_TIME",
             "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_SETPCAP", "CAP_SETFCAP", "CAP_BPF", "CAP_PERFMON", "CAP_SYSLOG",
             "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_AUDIT_READ",
             "CAP_LINUX_IMMUTABLE", "CAP_SYS_PACCT", "CAP_SYS_TTY_CONFIG", "CAP_IPC_OWNER", "CAP_IPC_LOCK",
             "CAP_LEASE", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_CHECKPOINT_RESTORE", "CAP_NET_BROADCAST",
             "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_DAC_READ_SEARCH", "CAP_NET_BIND_SERVICE"}
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("FAIL check_capability_set: %s does not parse: %s" % (sys.argv[1], e)); sys.exit(1)
sets = ["bounding", "effective", "permitted", "inheritable", "ambient"]
missing = [s for s in sets if s not in d]
if missing:
    print("FAIL check_capability_set: list(s) not named: %s (procd reads an absent list as every capability)" % ", ".join(missing)); sys.exit(1)
bad = sorted({c for s in sets for c in d[s]} & FORBIDDEN)
if bad:
    print("FAIL check_capability_set: the set holds %s, which nothing the daemon does needs" % ", ".join(bad)); sys.exit(1)
if not d["bounding"]:
    print("FAIL check_capability_set: an empty bounding set is not the daemon's: it needs CHOWN and DAC_OVERRIDE to write /etc and apk's files"); sys.exit(1)
if not (set(d["effective"]) <= set(d["bounding"]) and set(d["permitted"]) <= set(d["bounding"])):
    print("FAIL check_capability_set: effective or permitted holds a capability the bounding set lacks"); sys.exit(1)
if d["ambient"] or d["inheritable"]:
    print("FAIL check_capability_set: ambient or inheritable capabilities would pass to every program the daemon starts"); sys.exit(1)
if "CAP_DAC_OVERRIDE" not in d["bounding"]:
    print("FAIL check_capability_set: no CAP_DAC_OVERRIDE: the daemon could not write the root-only files under /etc/config"); sys.exit(1)
PY
	echo "ok   check_capability_set"
}

# The jail is made of the directories the daemon's jobs use. These are never mounted: /root,
# /overlay, /mnt, /rom and /boot hold what the jobs do not touch, /dev and /sys are provided by
# ujail's own flags, and "/" would be no jail at all.
check_mounts() {
	need "$INIT"
	mounts=$(live | sed -n -e 's/^procd_add_jail_mount_rw[[:space:]]*//p' -e 's/^procd_add_jail_mount[[:space:]]*//p' | tr ' ' '\n' | sed '/^$/d')
	[ -n "$mounts" ] || fail check_mounts "the jail mounts nothing: the daemon would find no uci, ubus or /etc/config" || return 1
	for m in $mounts; do
		case "$m" in
		/ | /root* | /overlay* | /mnt* | /rom* | /boot* | /dev* | /sys* | /proc* | /home* | /opt* | /run*)
			fail check_mounts "the jail mounts $m, which the daemon never reads or writes"; return 1 ;;
		/etc | /usr | /lib | /bin | /sbin | /www | /tmp | /var/run | /var/lock | /var/log | /var/state) ;;
		*) fail check_mounts "the jail mounts $m, which is not on the list of what the daemon's jobs use (/etc /usr /lib /bin /sbin /www /tmp and /var/{run,lock,log,state})"; return 1 ;;
		esac
	done
	echo "ok   check_mounts"
}

check_seccomp_is_in_the_daemon() {
	need "$INIT"; need "$ROOT/main.go"; need "$ROOT/seccomp/denied.txt"; need "$ROOT/seccomp_linux.go"
	# procd's own profile filters nothing for a static binary and lands on the programs it starts.
	if live | grep -qE 'procd_set_param[[:space:]]+seccomp'; then
		fail check_seccomp_is_in_the_daemon "the init script sets a procd seccomp profile, which a static binary never loads"; return 1
	fi
	# serve installs the filter before it reads the configuration, a token or a policy.
	awk '/case "serve":/ {s=1; next} s && /confine\(\)/ {c=NR} s && /NewServer\(/ {n=NR} s && /case "pair":/ {exit} END {exit !(c && n && c < n)}' "$ROOT/main.go" ||
		fail check_seccomp_is_in_the_daemon "serve does not call confine() before NewServer" || return 1
	for name in ptrace mount unshare setns init_module finit_module bpf reboot kexec_load pivot_root; do
		grep -qx "$name" "$ROOT/seccomp/denied.txt" ||
			{ fail check_seccomp_is_in_the_daemon "$name is not on seccomp/denied.txt"; return 1; }
	done
	grep -q 'seccompFilterFlagTSYNC' "$ROOT/seccomp_linux.go" && grep -q 'checkSeccompStatus' "$ROOT/seccomp_linux.go" ||
		fail check_seccomp_is_in_the_daemon "the filter is not put on every thread, or the daemon does not check /proc/self/status afterwards" || return 1
	echo "ok   check_seccomp_is_in_the_daemon"
}

check_packages_ship_the_capability_file() {
	for f in mkipk.sh mkapk.sh Makefile files/lib/upgrade/keep.d/openwrt-mcp; do need "$ROOT/$f"; done
	for f in mkipk.sh mkapk.sh; do
		grep -q 'files/etc/capabilities/\$PKG.json' "$ROOT/$f" ||
			{ fail check_packages_ship_the_capability_file "$f does not install the capability file: an installed init script would name a file that is not there"; return 1; }
	done
	grep -q 'files/etc/capabilities/openwrt-mcp.json' "$ROOT/Makefile" ||
		fail check_packages_ship_the_capability_file "make install does not copy the capability file" || return 1
	grep -qx '/etc/capabilities/openwrt-mcp.json' "$ROOT/files/lib/upgrade/keep.d/openwrt-mcp" ||
		fail check_packages_ship_the_capability_file "keep.d does not carry the capability file across a firmware upgrade, which keeps the init script that names it" || return 1
	echo "ok   check_packages_ship_the_capability_file"
}

if [ $# -gt 0 ]; then
	case " $CHECKS " in *" $1 "*) "$1"; exit $? ;; esac
	echo "FAIL no check named $1"; exit 1
fi
rc=0
for c in $CHECKS; do "$c" || rc=1; done
[ "$rc" -eq 0 ] && echo "gate-jail: $(echo $CHECKS | wc -w | tr -d ' ') checks, all ok"
exit $rc
