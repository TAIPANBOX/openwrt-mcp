#!/bin/sh
# gate-seccomp-native-teeth.sh -- gate-seccomp-native.sh must go red, at the test named, on each fault
# planted in a copy of this architecture's table, go green on the copy as it is, and say "measured
# nothing" when asked to run under another architecture. Run where the gate runs: natively.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
rc=0
ARCH=$(cd "$REPO" && go env GOARCH)
case $ARCH in
	amd64) WRONG_ARCH='s/unix.AUDIT_ARCH_X86_64/unix.AUDIT_ARCH_I386/' ;;
	arm64) WRONG_ARCH='s/unix.AUDIT_ARCH_AARCH64/unix.AUDIT_ARCH_ARM/' ;;
	*) echo "FAIL: measured nothing: no filter for $ARCH"; exit 1 ;;
esac
TABLE=seccomp_linux_$ARCH.go

fresh() {
	rm -rf "$TMP/t"; mkdir -p "$TMP/t"
	(cd "$REPO" && tar cf - --exclude=./.git --exclude='./*.ipk' --exclude='./*.apk' --exclude=./openwrt-mcp.amd64 \
		--exclude=./openwrt-mcp.arm64 .) | (cd "$TMP/t" && tar xf -)
}
gate() { GATE_REPO="$TMP/t" sh "$REPO/scripts/gate-seccomp-native.sh" > "$TMP/out" 2>&1; }

# plant <description> <file> <sed expression> <the test that must go red>
plant() {
	fresh
	sed -i "$3" "$TMP/t/$2"
	if cmp -s "$TMP/t/$2" "$REPO/$2"; then echo "FAIL: the fault '$1' changed nothing in $2 (the case is dead)"; rc=1; return; fi
	if gate; then echo "FAIL: '$1' did not make the gate go red"; rc=1; return; fi
	grep -q -- "--- FAIL: $4 " "$TMP/out" || { echo "FAIL: '$1' went red, but not at $4:"; cat "$TMP/out"; rc=1; return; }
	echo "ok   red at $4: $1"
	# What the red test said, from its own run and not from a neighbour's log.
	awk -v t="$4" '$0 ~ "^=== RUN   "t"$" {on=1; next} on && /^(=== RUN|--- )/ {exit} on && /_test\.go:[0-9]+:/' "$TMP/out" |
		head -2 | sed 's/^[[:space:]]*/       /'
}

plant "mount points at umount2's number in the $ARCH table" "$TABLE" \
	's/"mount": unix.SYS_MOUNT,/"mount": unix.SYS_UMOUNT2,/' TestEveryNameOfTheListHasANumberOnThisArchitecture
plant "kexec_file_load points at a number that is no call in the $ARCH table" "$TABLE" \
	's/"kexec_file_load": unix.SYS_KEXEC_FILE_LOAD,/"kexec_file_load": 9999,/' TestEveryDeniedCallIsKilledByThisKernel
plant "the $ARCH filter checks another audit architecture" "$TABLE" "$WRONG_ARCH" TestFilterOnARealKernel

fresh
if out=$(cd "$TMP/t" && GOARCH=mips GATE_REPO="$TMP/t" sh "$REPO/scripts/gate-seccomp-native.sh" 2>&1); then
	echo "FAIL: the gate passed under GOARCH=mips: $out"; rc=1
elif echo "$out" | grep -q "measured nothing"; then
	echo "ok   another GOARCH reads 'measured nothing'"
else
	echo "FAIL: under GOARCH=mips the gate did not say 'measured nothing': $out"; rc=1
fi

fresh
if gate; then echo "ok   green again on the copy as it is: $(tail -1 "$TMP/out")"; else echo "FAIL: the gate is red on the tree as it is:"; cat "$TMP/out"; rc=1; fi

[ "$rc" -eq 0 ] && echo "every planted fault is caught"
exit "$rc"
