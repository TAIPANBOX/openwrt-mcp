#!/bin/sh
# gate-scenarios-bound-teeth.sh -- plant each fault the binding gate exists to catch and
# require it to go red, then require it to stay green on a clean case.
#
# A gate nobody has seen fail is a gate nobody has tested. This one reads feature files and
# Go tests, so the faults are small files written to a scratch directory and the gate is
# pointed at them through BOUND_GO_FEATURES and BOUND_TEST_DIR. The real repository is never
# touched.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
GATE="$REPO/scripts/gate-scenarios-bound.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rc=0

new_case() { # name -> fresh dir with one passing test and a bound scenario
	d="$WORK/$1"; mkdir -p "$d"
	cat > "$d/go.mod" <<'MOD'
module teeth

go 1.22
MOD
	cat > "$d/x_test.go" <<'GO'
package teeth

import "testing"

func TestPasses(t *testing.T) {}
GO
	cat > "$d/f.feature" <<'FEAT'
Feature: teeth
  # bound to: TestPasses
  Scenario: a bound one
    Given a thing
FEAT
	echo "$d"
}

# run_gate <dir> [BOUND_SKIP_RUN value] -> sets OUT, returns the gate's status
run_gate() {
	set +e
	OUT=$(BOUND_GO_FEATURES="$1/f.feature" BOUND_TEST_DIR="$1" BOUND_SKIP_RUN="${2:-1}" "$GATE" 2>&1)
	st=$?
	set -e
	return $st
}

expect_red() { # name dir skip want
	if run_gate "$2" "$3"; then
		echo "TEETH FAIL: $1 did not make the gate go red"; echo "$OUT"; rc=1; return
	fi
	if ! printf '%s' "$OUT" | grep -q "$4"; then
		echo "TEETH FAIL: $1 went red, but not with '$4'"; echo "$OUT"; rc=1; return
	fi
	echo "teeth ok: $1 -> $4"
}

# the fixed point first: a clean case is green, so the reds below are the faults and not the harness
d=$(new_case clean)
if run_gate "$d" 1; then echo "teeth ok: a clean case is green (static)"; else echo "TEETH FAIL: a clean case is red"; echo "$OUT"; rc=1; fi
if run_gate "$d" 0; then echo "teeth ok: a clean case is green (tests run)"; else echo "TEETH FAIL: a clean case is red when run"; echo "$OUT"; rc=1; fi

d=$(new_case unbound)
cat >> "$d/f.feature" <<'FEAT'

  Scenario: nobody tests this
    Given a promise
FEAT
expect_red "a scenario with no binding" "$d" 1 "scenario has no binding"

d=$(new_case ghost)
sed 's/TestPasses/TestDoesNotExist/' "$d/f.feature" > "$d/g" && mv "$d/g" "$d/f.feature"
expect_red "a binding to a test that does not exist" "$d" 1 "TestDoesNotExist.*not a Test function"

d=$(new_case comment-only)
printf '\n// func TestOnlyInAComment(t *testing.T) {}\n' >> "$d/x_test.go"
sed 's/TestPasses/TestOnlyInAComment/' "$d/f.feature" > "$d/g" && mv "$d/g" "$d/f.feature"
expect_red "a binding to a name that only appears in a comment" "$d" 1 "TestOnlyInAComment.*not a Test function"

d=$(new_case dangling)
printf '\n  # bound to: TestPasses\n' >> "$d/f.feature"
expect_red "a binding with no scenario after it" "$d" 1 "not followed by a scenario"

d=$(new_case empty)
printf 'Feature: nothing\n' > "$d/f.feature"
expect_red "a feature with no scenarios" "$d" 1 "no scenarios"

d=$(new_case nobinding-at-all)
printf 'Feature: x\n  Scenario: y\n    Given z\n' > "$d/f.feature"
expect_red "a feature whose scenarios bind nothing" "$d" 1 "no binding"

d=$(new_case missing)
rm "$d/f.feature"
expect_red "a missing feature file" "$d" 1 "FAIL: no "

d=$(new_case no-tests)
rm "$d/x_test.go"
expect_red "no Go tests at all" "$d" 1 "no Go tests found"

d=$(new_case red-test)
cat > "$d/x_test.go" <<'GO'
package teeth

import "testing"

func TestPasses(t *testing.T) { t.Fatal("this one is broken") }
GO
expect_red "a bound test that fails" "$d" 0 "is red"

d=$(new_case skipped-test)
cat > "$d/x_test.go" <<'GO'
package teeth

import "testing"

func TestPasses(t *testing.T) { t.Skip("not today") }
GO
expect_red "a bound test that is skipped" "$d" 0 "did not run and pass"

# Which feature files are bound to Go tests is not a list kept by hand: by default the gate
# reads every features/*.feature but the apk one. To see that default itself, a copy of the
# gate runs in a scratch layout with no override.
layout() { # name -> a scratch repository holding the gates and the apk feature only
	l="$WORK/$1"; mkdir -p "$l/scripts" "$l/features"
	cp "$REPO/scripts/gate-scenarios-bound.sh" "$REPO/scripts/gate-apk-parity.sh" "$l/scripts/"
	cp "$REPO/features/apk-packaging.feature" "$l/features/"
	echo "$l"
}

expect_red_layout() { # name layout want
	set +e
	OUT=$(env -u BOUND_GO_FEATURES -u BOUND_TEST_DIR BOUND_SKIP_RUN=1 "$2/scripts/gate-scenarios-bound.sh" 2>&1)
	st=$?
	set -e
	if [ "$st" -eq 0 ]; then
		echo "TEETH FAIL: $1 did not make the gate go red"; echo "$OUT"; rc=1; return
	fi
	if ! printf '%s' "$OUT" | grep -q "$3"; then
		echo "TEETH FAIL: $1 went red, but not with '$3'"; echo "$OUT"; rc=1; return
	fi
	echo "teeth ok: $1 -> $3"
}

l=$(layout no-go-features)
expect_red_layout "no feature file bound to Go tests" "$l" "no feature file is bound to Go tests"

l=$(layout unlisted-feature)
printf 'Feature: new\n  Scenario: nobody bound this\n    Given a thing\n' > "$l/features/new.feature"
expect_red_layout "a new feature file that no list names" "$l" "scenario has no binding"

[ "$rc" -eq 0 ] && echo "gate-scenarios-bound-teeth: every planted fault was caught" || exit 1
