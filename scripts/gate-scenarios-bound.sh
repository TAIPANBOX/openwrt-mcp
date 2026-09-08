#!/bin/sh
# gate-scenarios-bound.sh -- every scenario names a check, every check has a scenario.
#
# features/apk-packaging.feature is meant to be readable instead of the packaging code,
# which only works while it still describes what is actually tested. Two ways for that
# to rot quietly: a scenario stays in the file after its check is deleted, so the
# feature file promises a guarantee nobody enforces; or a check is added with no
# scenario, so the readable description silently stops being the whole story. This
# asserts both directions, which is the only version of the check worth having.
#
# The binding is a comment line in the feature file:  # bound to: <check_name>
# and the check names come from the gate's own --selftest list, not from a second copy
# of them kept here. A gate that named its checks in two places would drift between
# them, which is the same failure one level up.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
FEATURE="$REPO/features/apk-packaging.feature"
GATE="$REPO/scripts/gate-apk-parity.sh"

[ -f "$FEATURE" ] || { echo "FAIL: no $FEATURE"; exit 1; }
[ -x "$GATE" ]    || { echo "FAIL: $GATE is missing or not executable"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

"$GATE" --selftest | sort > "$WORK/checks"
sed -n 's/^[[:space:]]*#[[:space:]]*bound to:[[:space:]]*//p' "$FEATURE" | sort > "$WORK/bound"

# An empty list on either side would make every comparison below trivially pass, which
# is exactly how a check ends up reporting a clean run over nothing.
if [ ! -s "$WORK/checks" ]; then echo "FAIL: the gate lists no checks"; exit 1; fi
if [ ! -s "$WORK/bound" ];  then echo "FAIL: the feature file binds no scenarios"; exit 1; fi

rc=0
while read -r c; do
	grep -qxF "$c" "$WORK/bound" || { echo "FAIL: check '$c' has no scenario in $(basename "$FEATURE")"; rc=1; }
done < "$WORK/checks"
while read -r b; do
	grep -qxF "$b" "$WORK/checks" || { echo "FAIL: scenario binds to '$b', which the gate does not run"; rc=1; }
done < "$WORK/bound"

[ "$rc" -eq 0 ] || exit 1
echo "gate-scenarios-bound: $(wc -l < "$WORK/checks" | tr -d ' ') scenarios and checks agree, both ways"
