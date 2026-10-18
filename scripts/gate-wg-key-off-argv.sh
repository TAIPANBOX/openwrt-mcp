#!/bin/sh
# gate-wg-key-off-argv.sh -- no command the daemon runs is given a WireGuard private key as an argument.
#
# Every process on the router can read another process's argument list while the command runs
# (/proc/<pid>/cmdline). So the private key of a WireGuard client reaches uci on standard input,
# as one `uci batch`, and never as an argv element. This is the structural half of that rule: a
# run() or runIn() call in wireguard.go that names the key variable is a fault. The behavioural
# half is TestWgNewClientKeepsThePrivateKeyOutOfEveryCommandLine, which reads the arguments a
# stand-in uci was given. runStdin is the one helper that takes the key, and it writes it to
# standard input.
#
# Measured nothing is a failure, not a pass: if wireguard.go is gone, or the key variable is no
# longer used where the check looks, the gate says so rather than reporting a clean scan.
#
# GATE_REPO overrides the repository root, so scripts/gate-wg-key-off-argv-teeth.sh can point the
# gate at planted faults.
set -eu

REPO="${GATE_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
SRC="$REPO/wireguard.go"

[ -f "$SRC" ] || { echo "gate-wg-key-off-argv: measured nothing: no $SRC"; exit 1; }

# The subject must be there: the public-key derivation is the one call that takes the private key
# on standard input, and the scan below is only meaningful if it finds that call.
if ! grep -qE '[^A-Za-z_.]runStdin\(.*[^A-Za-z_]priv[^A-Za-z_]' "$SRC"; then
	echo "gate-wg-key-off-argv: measured nothing: wireguard.go no longer passes the private key to runStdin"
	exit 1
fi

hits=$(grep -nE '[^A-Za-z_.]run(In)?\(.*[^A-Za-z_]priv[^A-Za-z_]' "$SRC" || true)
if [ -n "$hits" ]; then
	echo "FAIL: the WireGuard private key is an argument to a command:"
	echo "$hits"
	exit 1
fi

echo "gate-wg-key-off-argv: no run or runIn call in wireguard.go takes the private key"
