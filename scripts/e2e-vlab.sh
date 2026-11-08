#!/bin/sh
# e2e-vlab.sh -- every tool of the daemon, through its HTTP listener, against the installed daemon
# that procd started with its narrowed capabilities and filter, on a virtual OpenWrt router (vlab, QEMU/KVM, an isolated bridge).
# Run it on the machine that has the lab (forge), from a copy of the tree there. Not on a laptop.
#
#   scripts/e2e-vlab.sh            the init script, capability file and daemon of this tree
#   scripts/e2e-vlab.sh --old      the same daemon under the init script of origin/main (no
#                                  capability file): jail_vlab_test.go must go red on it
#
# It needs: go, python3, `sudo -n` for the vlab binary, and the vlab image. It brings one router up
# on 10.34.0.0/24 with a route to the internet (apk_add reaches the official feeds), installs the
# package files by the same copy `make install` makes, runs TestJailVlab on the router, prints what
# the kernel shows for the daemon, and takes the lab down.
set -eu

REPO=${E2E_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
VLAB=${VLAB:-$HOME/vlab/bin/vlab}
OLD=0; [ "${1:-}" = "--old" ] && OLD=1
export PATH="$PATH:/usr/local/go/bin"
[ -x "$VLAB" ] || { echo "FAIL: measured nothing: no vlab at $VLAB"; exit 1; }
WORK=$(mktemp -d); trap 'sudo -n "$VLAB" down >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

rsh() { printf '%s\n' "$1" | sudo -n "$VLAB" ssh r1 sh -s; }
rput() { sudo -n "$VLAB" ssh r1 "cat > $2.new && chmod $3 $2.new && mv $2.new $2" < "$1"; }

cd "$REPO"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local go build -ldflags="-s -w" -o "$WORK/openwrt-mcp" .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local go test -c -o "$WORK/e2e.test" .
if [ "$OLD" = 1 ]; then
	# E2E_OLD_INIT names a copy of origin/main's init script when the tree has no git history.
	if [ -n "${E2E_OLD_INIT:-}" ]; then cp "$E2E_OLD_INIT" "$WORK/init"; else git show origin/main:files/etc/init.d/openwrt-mcp > "$WORK/init"; fi
else
	cp files/etc/init.d/openwrt-mcp "$WORK/init"
fi

cat > "$WORK/topology.json" <<'JSON'
{
  "name": "mcpjail",
  "note": "openwrt-mcp with its narrowed kernel surface: one router with internet for apk",
  "segments": [ {"name": "net", "cidr": "10.34.0.0/24", "internet": true} ],
  "nodes": [ {"name": "r1", "wan": "net", "mem_mb": 384} ]
}
JSON
sudo -n "$VLAB" up "$WORK/topology.json" --ttl 2h >/dev/null
rsh 'echo "router: $(. /etc/openwrt_release; echo $DISTRIB_RELEASE) $(uname -m), apk $(apk --version | cut -d" " -f2)"'

rput "$WORK/openwrt-mcp" /usr/bin/openwrt-mcp 755
rput "$WORK/init" /etc/init.d/openwrt-mcp 755
rsh 'mkdir -p /etc/capabilities'
rput files/etc/capabilities/openwrt-mcp.json /etc/capabilities/openwrt-mcp.json 644
rput files/etc/config/openwrt-mcp /etc/config/openwrt-mcp 644
rput "$WORK/e2e.test" /tmp/e2e.test 755

rc=0
rsh 'cd /tmp && OPENWRT_MCP_JAIL_E2E=1 /tmp/e2e.test -test.run "^TestJailVlab$" -test.v -test.count=1 2>&1' > "$WORK/e2e.out" || rc=$?
grep -E '^(---|    ---|SECCOMP|PROBE|FAIL|PASS|ok)|jail_vlab_test' "$WORK/e2e.out" || tail -30 "$WORK/e2e.out"

echo "--- what the kernel shows, from the router"
rsh 'for p in $(pidof openwrt-mcp); do
  printf "pid %s: " "$p"; head -c 60 /proc/$p/cmdline | tr "\0" " "; echo
  grep -E "^(NSpid|NoNewPrivs|Seccomp|Seccomp_filters|CapBnd|CapEff|CapPrm|CapAmb|CapInh):" /proc/$p/status | tr "\n" " "; echo
done
echo "audit lines mentioning a seccomp death: $(logread | grep -c -i "bad system call" || true)"'
exit $rc
