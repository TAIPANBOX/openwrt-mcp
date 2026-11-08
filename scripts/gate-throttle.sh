#!/bin/sh
# gate-throttle.sh -- the rules of the guess throttle that can be read from the source.
#
# The tests prove what the throttle does; this holds the shape that keeps it true when the code
# moves, in the places where a wrong answer is silent:
#
#   check_no_wall_clock          throttle.go never reads the wall clock
#   check_record_shape           a record on the disk is a client, a count and a step, and no time
#   check_count_before_factors   the count is written before any factor is looked at
#   check_refusal_writes_nothing a refusal inside a delay writes nothing to the throttle file
#   check_write_is_atomic        data synced, then renamed, then the directory synced
#   check_reset_is_cli_only      only the CLI reaches the reset, and no tool reaches a clearing path
#   check_bad_token_is_folded    a bad token is folded, never recorded line by line
#   check_refusals_are_folded    the tool wrapper folds what a refusal asks to have folded
#   check_refusal_words          the words hermes-openwrt's plugin reads
#
# Measured nothing is a failure, not a pass: a file or a function that is gone, or a marker that no
# longer matches, says so and goes red. GATE_REPO points the gate at a scratch copy, which is how
# scripts/gate-throttle-teeth.sh plants each fault.
set -eu

REPO=${GATE_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
rc=0
fail() { echo "FAIL $1: $2"; rc=1; }
pass() { echo "PASS $1"; }

for f in throttle.go mfa.go tools.go server.go approval.go mfa_cli.go helper.go frontend.go; do
	[ -f "$REPO/$f" ] || { echo "FAIL: measured nothing: $f is gone"; exit 1; }
done

# code <file>: the file without its comments, so a sentence about the wall clock is not a fault.
code() { sed -E 's#^[[:space:]]*//.*$##; s#[[:space:]]//.*$##' "$REPO/$1"; }

# body <file> <first line>: from the line that starts with that text up to the closing brace at
# column one. A plain prefix, because awks differ on what a backslash in a -v pattern means, and it
# reads to the end, so nothing upstream dies on a closed pipe.
body() { code "$1" | awk -v start="$2" '!done && index($0, start) == 1 { on = 1 } on { print } on && /^}/ { on = 0; done = 1 }'; }

# line <text> <pattern>: the number of the first line that matches, or nothing.
line() { printf '%s\n' "$1" | grep -n -m1 -E -- "$2" | cut -d: -f1; }

check_no_wall_clock() {
	hits=$(code throttle.go | grep -nE 'time\.(Now|Since|Until|Date|Parse|Unix|Time)\b|\.Unix(Nano|Milli)?\(|RFC3339|\.Format\(' || true)
	if [ -n "$hits" ]; then
		fail check_no_wall_clock "throttle.go reads a clock that is not the monotonic one: $hits"
	else
		pass check_no_wall_clock
	fi
}

check_record_shape() {
	writers=$(code throttle.go | grep -cE 'fmt\.(Sprintf|Fprintf)\("%s %d' || true)
	shape=$(code throttle.go | grep -cF 'fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])' || true)
	if [ "$writers" -eq 0 ]; then
		fail check_record_shape "measured nothing: no record is formatted in throttle.go"
	elif [ "$writers" -ne 1 ] || [ "$shape" -ne 1 ]; then
		fail check_record_shape "a record must be exactly client, count, step: $writers formats, $shape of that shape"
	else
		pass check_record_shape
	fi
}

check_count_before_factors() {
	b=$(body mfa.go 'func (m *MFAStore) attempt(')
	save=$(line "$b" 'm\.saveThrottleLocked\(')
	check=$(line "$b" 'm\.checkFactorsLocked\(')
	if [ -z "$save" ] || [ -z "$check" ]; then
		fail check_count_before_factors "measured nothing: attempt() has no write or no check to order"
	elif [ "$save" -ge "$check" ]; then
		fail check_count_before_factors "the count is written at line $save of attempt(), after the check at $check"
	else
		pass check_count_before_factors
	fi
}

check_refusal_writes_nothing() {
	b=$(body mfa.go 'func (m *MFAStore) attempt(')
	refusal=$(printf '%s\n' "$b" | awk '!done && index($0, "wait := e.wait(") { on = 1 } on { print } on && /^\t}/ { on = 0; done = 1 }')
	if [ -z "$refusal" ]; then
		fail check_refusal_writes_nothing "measured nothing: attempt() has no refusal branch"
	elif printf '%s\n' "$refusal" | grep -qE 'saveThrottle|writeThrottle|checkFactors'; then
		fail check_refusal_writes_nothing "the refusal inside a delay writes or checks something"
	else
		pass check_refusal_writes_nothing
	fi
}

check_write_is_atomic() {
	b=$(body throttle.go 'func atomicWriteFile(')
	data=$(line "$b" 'syncFile\(f\)')
	move=$(line "$b" 'os\.Rename\(')
	dir=$(line "$b" 'syncFile\(d\)')
	if [ -z "$data" ] || [ -z "$move" ] || [ -z "$dir" ]; then
		fail check_write_is_atomic "atomicWriteFile lacks one of: sync of the file, rename, sync of the directory"
	elif [ "$data" -ge "$move" ] || [ "$move" -ge "$dir" ]; then
		fail check_write_is_atomic "the order must be sync, rename, sync of the directory ($data, $move, $dir)"
	else
		pass check_write_is_atomic
	fi
}

check_reset_is_cli_only() {
	callers=""
	for f in "$REPO"/*.go; do
		case "$f" in *_test.go) continue ;; esac
		n=$(basename "$f")
		[ "$n" = throttle.go ] && continue
		grep -qE '\.ResetThrottle\(' "$f" && callers="$callers $n"
	done
	if [ "$callers" != " mfa_cli.go" ]; then
		fail check_reset_is_cli_only "ResetThrottle must be called from mfa_cli.go alone; it is called from:${callers:- nowhere}"
		return
	fi
	# A tool's body, and what a request reaches, stay away from every path that clears a count.
	for f in tools.go approval.go server.go helper.go frontend.go; do
		if code "$f" | grep -qE 'clearThrottleLocked|forgetLocked|\.Forget\(|\.ResetThrottle\(|writeThrottle|saveThrottleLocked|runMFAReset'; then
			fail check_reset_is_cli_only "$f reaches a path that clears a count"
			return
		fi
	done
	if code tools.go | grep -qiE '(addTool[A-Za-z]*|toolOf)\(.*"[a-z_]*reset[a-z_]*"|^[[:space:]]*"[a-z_]*reset[a-z_]*",$'; then
		fail check_reset_is_cli_only "tools.go registers a tool named for a reset"
		return
	fi
	pass check_reset_is_cli_only
}

check_bad_token_is_folded() {
	b=$(body server.go 'func (s *Server) badToken(')
	if [ -z "$b" ] || ! printf '%s\n' "$b" | grep -q 'bearer token'; then
		fail check_bad_token_is_folded "measured nothing: badToken() records no bad token"
	elif printf '%s\n' "$b" | grep -q 's\.audit\.Record('; then
		fail check_bad_token_is_folded "badToken() writes a line for each bad token"
	elif ! printf '%s\n' "$b" | grep -q 's\.audit\.Fold('; then
		fail check_bad_token_is_folded "badToken() folds nothing"
	elif ! body server.go 'func (s *Server) auth(' | grep -q 's\.badToken(' || ! body server.go 'func (s *Server) call(' | grep -q 's\.badToken('; then
		fail check_bad_token_is_folded "a bad token reaching the helper's auth or call is not written by badToken()"
	else
		pass check_bad_token_is_folded
	fi
}

check_refusals_are_folded() {
	b=$(body tools.go 'func (s *Server) gate(')
	if [ -z "$b" ]; then
		fail check_refusals_are_folded "measured nothing: the gate is gone"
	elif ! printf '%s\n' "$b" | grep -q 'fold = foldOf(err)' || ! printf '%s\n' "$b" | grep -q 's\.audit\.Fold('; then
		fail check_refusals_are_folded "the tool wrapper does not fold what a refusal asks to have folded"
	elif ! code mfa.go | grep -q 'func (e \*lockedOutError) foldNote()'; then
		fail check_refusals_are_folded "a refusal inside a delay does not ask to be folded"
	elif ! code tools.go | grep -q 'func (e \*unlockRefusal) foldNote()'; then
		fail check_refusals_are_folded "an mfa_unlock turned away does not ask to be folded"
	else
		pass check_refusals_are_folded
	fi
}

check_refusal_words() {
	if grep -qF '"too many failed attempts: unlocking is locked out until " + e.until.Format(time.RFC3339)' "$REPO/mfa.go"; then
		pass check_refusal_words
	else
		fail check_refusal_words "the plugin reads \"locked out\" and the time after \"until\"; the words moved"
	fi
}

check_no_wall_clock
check_record_shape
check_count_before_factors
check_refusal_writes_nothing
check_write_is_atomic
check_reset_is_cli_only
check_bad_token_is_folded
check_refusals_are_folded
check_refusal_words

[ "$rc" -eq 0 ] && echo "gate-throttle: every rule holds"
exit "$rc"
