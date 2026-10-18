#!/bin/sh
# gate-wg-key-off-argv-teeth.sh -- the WireGuard key gate's own teeth.
#
# A gate that cannot go red proves nothing. This plants the fault the gate exists to catch (a
# private key handed to run) in a scratch copy of wireguard.go and requires the gate to go red, then
# requires a clean copy to stay green, then removes the subject and requires "measured nothing".
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="$REPO/scripts/gate-wg-key-off-argv.sh"
[ -x "$GATE" ] || { echo "FAIL: $GATE is missing or not executable"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rc=0

# A scratch repository holding only what the gate reads.
fresh() {
	rm -rf "$WORK/repo"
	mkdir -p "$WORK/repo"
	cp "$REPO/wireguard.go" "$WORK/repo/wireguard.go"
}

fresh
if ! GATE_REPO="$WORK/repo" "$GATE" >/dev/null 2>&1; then
	echo "FAIL: the gate is red on the clean wireguard.go"
	rc=1
fi

# The fault: the key as an argument to a run call, the shape the old `uci set ...private_key=` had.
fresh
printf '\nfunc plantedLeak(ctx context.Context, priv string) {\n\trun(ctx, defaultCmdTimeout, "uci", "set", "x="+priv)\n}\n' \
	>> "$WORK/repo/wireguard.go"
if GATE_REPO="$WORK/repo" "$GATE" >/dev/null 2>&1; then
	echo "FAIL: the gate did not catch a private key passed to run"
	rc=1
else
	echo "teeth ok: a private key passed to run is caught"
fi

# The subject gone: the key no longer reaches runStdin. The gate must say so, not pass.
fresh
sed 's/runStdin(ctx, defaultCmdTimeout, priv, "wg", "pubkey")/runStdin(ctx, defaultCmdTimeout, "", "wg", "pubkey")/' \
	"$REPO/wireguard.go" > "$WORK/repo/wireguard.go"
out=$(GATE_REPO="$WORK/repo" "$GATE" 2>&1 || true)
if GATE_REPO="$WORK/repo" "$GATE" >/dev/null 2>&1 || ! echo "$out" | grep -q "measured nothing"; then
	echo "FAIL: with the key gone from its subject, the gate did not say measured nothing"
	rc=1
else
	echo "teeth ok: a gate whose subject is gone says measured nothing"
fi

# No file at all.
rm -rf "$WORK/repo"
mkdir -p "$WORK/repo"
out=$(GATE_REPO="$WORK/repo" "$GATE" 2>&1 || true)
if ! echo "$out" | grep -q "measured nothing"; then
	echo "FAIL: a missing wireguard.go did not say measured nothing"
	rc=1
else
	echo "teeth ok: a missing wireguard.go says measured nothing"
fi

[ "$rc" -eq 0 ] || exit 1
echo "gate-wg-key-off-argv-teeth: every planted fault was caught"
