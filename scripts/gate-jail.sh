#!/bin/sh
# gate-jail.sh -- CI gate enforcing this invariant:
#
#   "The daemon runs with no_new_privs, a named capability set that leaves out everything its jobs
#   do not use, and its own seccomp filter, and does not listen unless the kernel shows all three."
#
# This narrows the kernel surface; it is not a jail and not containment of a broken daemon, which is
# root with the whole of ubus and a writable /etc. The init script says so, and the gate holds it to
# it: no mount and no namespace is asked of ujail, because those would cost every program started by
# `exec` its view of the router (ps, kill, reboot, sysupgrade -b) for almost nothing in return.
#
# What it reads is the source of what ships: the init script, the capability file, main.go, the
# seccomp list and the packaging. It does not start a router; scripts/e2e-vlab.sh does, and shows
# the same properties on a running one (/proc/PID/status). A gate that stops at the source can be
# true of a file that is never installed, so the packaging is one of the checks.
#
#   gate-jail.sh                run every check
#   gate-jail.sh <check>        run one (features/service-narrowing.feature binds a test to each)
#   gate-jail.sh --selftest     list the checks, run nothing
#
# JAIL_ROOT points it at another tree, which is how scripts/gate-jail-teeth.sh plants its faults.
set -u

CHECKS='check_ujail_carries_the_capabilities check_no_new_privs check_capability_set check_no_namespaces_and_no_mounts check_seccomp_is_in_the_daemon check_packages_ship_the_capability_file'

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

# procd applies a capability file only through ujail (measured on OpenWrt 25.12.5: without a jail
# section the daemon runs with CapBnd 000001ffffffffff). A bare `procd_add_jail openwrt-mcp` makes
# procd run `ujail -C <file> -c -- daemon`, which drops capabilities and builds no jail.
check_ujail_carries_the_capabilities() {
	need "$INIT"
	live | grep -qE '^procd_add_jail[[:space:]]+openwrt-mcp[[:space:]]*$' ||
		fail check_ujail_carries_the_capabilities "no bare 'procd_add_jail openwrt-mcp' in the init script: procd would not apply the capability file" || return 1
	echo "ok   check_ujail_carries_the_capabilities"
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

# No mount and no namespace: a jail would hide /root and /overlay and the router's process table
# from the daemon and take ps, kill, reboot, sysupgrade -b, firstboot and mtd from every program
# `exec` starts, and would not hold a daemon that is root with ubus and a writable /etc.
check_no_namespaces_and_no_mounts() {
	need "$INIT"
	if live | grep -qE '^procd_add_jail_mount'; then
		fail check_no_namespaces_and_no_mounts "the init script mounts into a jail: every program started by exec would lose the router's file system view"; return 1
	fi
	if live | grep -E '^procd_add_jail[[:space:]]' | grep -qE '[[:space:]](log|ubus|udebug|procfs|sysfs|ronly|requirejail|netns|userns|cgroupsns)([[:space:]]|$)'; then
		fail check_no_namespaces_and_no_mounts "the jail line asks ujail for a namespace, a mount or a socket"; return 1
	fi
	echo "ok   check_no_namespaces_and_no_mounts"
}

check_seccomp_is_in_the_daemon() {
	need "$INIT"; need "$ROOT/main.go"; need "$ROOT/seccomp/denied.txt"; need "$ROOT/seccomp_linux.go"; need "$ROOT/seccomp_filter.go"
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
	# The x32 numbers are killed, and the daemon refuses to listen unless the capability sets are the file's.
	grep -q 'bpfJGE' "$ROOT/seccomp_filter.go" && grep -q '0x40000000' "$ROOT/seccomp_filter.go" ||
		fail check_seccomp_is_in_the_daemon "the filter does not kill the x32 numbers (bit 30), which skip every comparison by whole number" || return 1
	grep -q 'checkCapabilities(status, expectedCaps)' "$ROOT/seccomp_filter.go" ||
		fail check_seccomp_is_in_the_daemon "the daemon does not check CapBnd and CapEff before it listens" || return 1
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
