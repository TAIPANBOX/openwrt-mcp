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
#
# A second kind of binding covers the features whose scenarios are proved by Go tests rather
# than by the apk gate (features/owner-unlock.feature). There a scenario is preceded by one or
# more  "# bound to: TestName[, TestName...]"  comment lines, and the gate asserts both ways:
# no scenario without a binding, and no binding to a test that does not exist in a *_test.go
# file. Unless BOUND_SKIP_RUN=1 it also runs the named tests and requires each to PASS, so a
# name that matches nothing, or a test that is skipped or red, fails the gate instead of
# reading as proof. The list of tests is not kept here: it is read from the feature files.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
FEATURE="$REPO/features/apk-packaging.feature"
GATE="$REPO/scripts/gate-apk-parity.sh"
# Overridable so scripts/gate-scenarios-bound-teeth.sh can point the gate at planted faults.
GO_FEATURES="${BOUND_GO_FEATURES:-$REPO/features/owner-unlock.feature}"
TEST_DIR="${BOUND_TEST_DIR:-$REPO}"   # where the *_test.go files live and where `go test` runs

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

# ---- scenarios bound to Go tests ------------------------------------------------------

grep -hoE '^func (Test[A-Za-z0-9_]+)\(' "$TEST_DIR"/*_test.go 2>/dev/null | sed -E 's/^func (Test[A-Za-z0-9_]+)\(/\1/' | sort -u > "$WORK/gotests"

for f in $GO_FEATURES; do
	[ -f "$f" ] || { echo "FAIL: no $f"; exit 1; }
	name=$(basename "$f")
	# One pass: every Scenario needs at least one binding above it (and above the next), and a
	# binding with no scenario after it is a dangling promise. Output is the list of bound
	# names, one per line, or FAIL lines.
	awk -v feat="$name" '
		/^[[:space:]]*#[[:space:]]*bound to:/ {
			line = $0
			sub(/^[[:space:]]*#[[:space:]]*bound to:[[:space:]]*/, "", line)
			gsub(/,/, " ", line)
			n = split(line, parts, /[[:space:]]+/)
			for (i = 1; i <= n; i++) if (parts[i] != "") { pending++; names[++count] = parts[i] }
			next
		}
		/^[[:space:]]*Scenario( Outline)?:/ {
			scenarios++
			if (!pending) { printf "FAIL: %s: scenario has no binding: %s\n", feat, $0; bad = 1 }
			pending = 0
			next
		}
		END {
			if (pending) { printf "FAIL: %s: a binding is not followed by a scenario\n", feat; bad = 1 }
			if (!scenarios) { printf "FAIL: %s: no scenarios, so nothing is bound\n", feat; bad = 1 }
			for (i = 1; i <= count; i++) print "NAME " names[i]
			printf "COUNT %d\n", scenarios
			exit bad
		}' "$f" > "$WORK/awk.out" || { grep '^FAIL' "$WORK/awk.out"; exit 1; }
	grep '^NAME ' "$WORK/awk.out" | sed 's/^NAME //' | sort -u > "$WORK/bound-go"
	[ -s "$WORK/bound-go" ] || { echo "FAIL: $name binds no test"; exit 1; }
	[ -s "$WORK/gotests" ]  || { echo "FAIL: no Go tests found under $TEST_DIR"; exit 1; }
	while read -r b; do
		grep -qxF "$b" "$WORK/gotests" || { echo "FAIL: $name binds to '$b', which is not a Test function in any *_test.go"; rc=1; }
	done < "$WORK/bound-go"
	[ "$rc" -eq 0 ] || exit 1

	if [ "${BOUND_SKIP_RUN:-0}" != 1 ]; then
		command -v go >/dev/null 2>&1 || { echo "FAIL: go is not on PATH, so the bound tests cannot be run (BOUND_SKIP_RUN=1 skips running them)"; exit 1; }
		re="^($(paste -sd'|' "$WORK/bound-go"))\$"
		( cd "$TEST_DIR" && go test -count=1 -run "$re" -v . ) > "$WORK/gotest.out" 2>&1 || { tail -30 "$WORK/gotest.out"; echo "FAIL: a test bound by $name is red"; exit 1; }
		while read -r b; do
			grep -q "^--- PASS: $b " "$WORK/gotest.out" || { echo "FAIL: '$b' (bound by $name) did not run and pass"; rc=1; }
		done < "$WORK/bound-go"
		[ "$rc" -eq 0 ] || exit 1
	fi
	how="exist and pass"
	[ "${BOUND_SKIP_RUN:-0}" != 1 ] || how="exist (not run)"
	echo "gate-scenarios-bound: $name: $(sed -n 's/^COUNT //p' "$WORK/awk.out") scenarios, $(wc -l < "$WORK/bound-go" | tr -d ' ') bound tests, all $how"
done
