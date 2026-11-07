#!/bin/sh
# gate-throttle-teeth.sh -- the throttle gate's own teeth.
#
# A gate that cannot go red proves nothing. Each case plants, in a scratch copy of the sources, the
# fault one check exists to catch and requires that check, by name, to go red; a clean copy must
# stay green, so the reds are the faults and not the harness; and a subject that is gone must say
# "measured nothing". A fault whose text no longer matches is itself a failure: the code moved, and
# the case must move with it, or it plants nothing and measures nothing.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="$REPO/scripts/gate-throttle.sh"
[ -x "$GATE" ] || { echo "FAIL: $GATE is missing or not executable"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rc=0

fresh() {
	rm -rf "$WORK/repo"
	mkdir -p "$WORK/repo"
	cp "$REPO"/*.go "$WORK/repo/"
}

run_gate() { GATE_REPO="$WORK/repo" "$GATE" 2>&1; }

# plant <file> <python-replace-from> <to>: exactly one occurrence, or the case is broken.
plant() {
	python3 - "$WORK/repo/$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
old, new = old.encode().decode("unicode_escape"), new.encode().decode("unicode_escape")
src = open(path, encoding="utf-8").read()
if src.count(old) != 1:
    sys.exit("plant: %r is in %s %d times, not once" % (old, path, src.count(old)))
open(path, "w", encoding="utf-8").write(src.replace(old, new))
PY
}

expect_red() { # what, check
	if out=$(run_gate); then
		echo "TEETH FAIL: $1 did not make the gate go red"; echo "$out"; rc=1; return
	fi
	if ! printf '%s\n' "$out" | grep -q "^FAIL $2:"; then
		echo "TEETH FAIL: $1 went red, but not at $2"; echo "$out"; rc=1; return
	fi
	echo "teeth ok: $1 -> $2"
}

fresh
if out=$(run_gate); then
	echo "teeth ok: a clean copy is green"
else
	echo "TEETH FAIL: the gate is red on clean sources"; echo "$out"; rc=1
fi

fresh
plant throttle.go 'func (e *throttleEntry) decay(mono time.Duration) {\n' 'func (e *throttleEntry) decay(mono time.Duration) {\n\t_ = time.Now()\n'
expect_red "the wall clock read in throttle.go" check_no_wall_clock

fresh
plant throttle.go 'lines[client] = fmt.Sprintf("%s %d %d", url.PathEscape(client), e.fails, m.lastCtr[client])' 'lines[client] = fmt.Sprintf("%s %d %d %d", url.PathEscape(client), e.fails, m.lastCtr[client], e.lastFail)'
expect_red "a fourth field on the disk" check_record_shape

fresh
plant mfa.go '\te.fails++\n\t_ = m.saveThrottleLocked(mono)\n\n\tif err := m.checkFactorsLocked(client, in, up.Factor, now); err != nil {\n' '\te.fails++\n\n\terr := m.checkFactorsLocked(client, in, up.Factor, now)\n\t_ = m.saveThrottleLocked(mono)\n\tif err != nil {\n'
expect_red "the count written after the check" check_count_before_factors

fresh
plant mfa.go '\t\te.refused++\n' '\t\te.refused++\n\t\t_ = m.saveThrottleLocked(mono)\n'
expect_red "a refusal that writes" check_refusal_writes_nothing

fresh
plant throttle.go '\treturn syncFile(d)\n' '\treturn nil\n'
expect_red "the directory never synced" check_write_is_atomic

fresh
plant throttle.go '\tif err := os.Rename(tmp, path); err != nil {\n\t\treturn err\n\t}\n' ''
expect_red "no rename" check_write_is_atomic

fresh
plant tools.go '\taddTool(s, srv, client, "mfa_lock",\n' '\taddTool(s, srv, client, "mfa_reset", "resets", func(in mfaLockIn) []string { return nil },\n\t\tfunc(ctx context.Context, in mfaLockIn) (string, string, error) {\n\t\t\t_, err := s.mfa.ResetThrottle(client)\n\t\t\treturn "", "", err\n\t\t})\n\n\taddTool(s, srv, client, "mfa_lock",\n'
expect_red "a tool that resets" check_reset_is_cli_only

fresh
plant tools.go '\t\t\t\twas := s.mfa.Lock(in.Client)\n' '\t\t\t\twas := s.mfa.Lock(in.Client)\n\t\t\t\ts.mfa.Forget(in.Client)\n'
expect_red "mfa_lock clearing the count" check_reset_is_cli_only

fresh
plant server.go 's.audit.Fold(foldNote{key: "bad-token", what: "bad or missing bearer tokens"}, AuditEvent{' 's.audit.Record(AuditEvent{'
expect_red "a line for each bad token" check_bad_token_is_folded

fresh
plant tools.go '\t\t\tfold = foldOf(err)\n' ''
expect_red "the wrapper not folding" check_refusals_are_folded

fresh
plant mfa.go 'func (e *lockedOutError) foldNote() foldNote {' 'func (e *lockedOutError) noted() foldNote {'
expect_red "a refusal in a delay not asking to be folded" check_refusals_are_folded

fresh
plant mfa.go '"too many failed attempts: unlocking is locked out until "' '"too many failed attempts: unlocking is paused until "'
expect_red "the plugin's words changed" check_refusal_words

# The subject gone must read as measuring nothing, never as clean.
fresh
rm "$WORK/repo/throttle.go"
if out=$(run_gate); then
	echo "TEETH FAIL: the gate is green with throttle.go gone"; rc=1
elif printf '%s\n' "$out" | grep -q "measured nothing"; then
	echo "teeth ok: throttle.go gone reads as measured nothing"
else
	echo "TEETH FAIL: red, but not measured nothing: $out"; rc=1
fi

fresh
plant mfa.go 'func (m *MFAStore) attempt(' 'func (m *MFAStore) attemptRenamed('
if out=$(run_gate); then
	echo "TEETH FAIL: the gate is green with attempt() gone"; rc=1
elif printf '%s\n' "$out" | grep -q "measured nothing"; then
	echo "teeth ok: attempt() gone reads as measured nothing"
else
	echo "TEETH FAIL: red, but not measured nothing: $out"; rc=1
fi

[ "$rc" -eq 0 ] && echo "gate-throttle-teeth: every planted fault went red at its check"
exit "$rc"
