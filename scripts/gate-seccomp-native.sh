#!/bin/sh
# gate-seccomp-native.sh -- the seccomp filter of this machine's architecture, on this machine's
# kernel, natively: the filter goes on, ordinary work runs under it, and every call of
# seccomp/denied.txt, by the number the kernel's own headers give its name, is ended by SIGSYS.
#
# The filter is built per architecture (seccomp_linux_amd64.go, seccomp_linux_arm64.go), and a
# router is arm64. A machine of one architecture only compiles the other's table, so CI runs this
# on an amd64 runner and on an arm64 runner (ubuntu-24.04-arm), each on its own kernel. It refuses to
# run under another GOARCH than the machine's, which would be emulation or no run at all, and says
# "measured nothing" there. The faults it must catch are planted by gate-seccomp-native-teeth.sh.
set -eu

REPO=${GATE_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
TESTS='TestBPFConstantsAreTheKernels TestEveryNameOfTheListHasANumberOnThisArchitecture TestFilterOnARealKernel
TestEveryDeniedCallIsKilledByThisKernel TestExpectedCapabilityMaskIsTheCapabilityFile
TestFilterDeniesEveryListedCallAndAllowsTheRest TestFilterKillsAnotherArchitecturesCalls
TestFilterRefusesClone3AndNamespaceClones TestFilterKillsEveryX32Number TestFilterRefusesAListThatNamesCloneOrIsEmpty
TestDeniedListIsWellFormedAndKeepsTheDaemonsOwnCallsOut TestSeccompStatusMustShowTheFilterInForce
TestFilterIsNotBuiltWhenTwoNamesShareANumber'

[ "$(uname -s)" = Linux ] || { echo "FAIL: measured nothing: $(uname -s) is not Linux, and the filter is Linux's"; exit 1; }
case $(uname -m) in
	x86_64) native=amd64 ;;
	aarch64 | arm64) native=arm64 ;;
	*) echo "FAIL: measured nothing: $(uname -m) has no seccomp filter in this daemon"; exit 1 ;;
esac
goarch=$(cd "$REPO" && go env GOARCH)
[ "$goarch" = "$native" ] || { echo "FAIL: measured nothing: GOARCH is $goarch on a $native machine, so the tests would not run on this kernel natively"; exit 1; }
[ -f "$REPO/seccomp_linux_$goarch.go" ] || { echo "FAIL: measured nothing: no seccomp_linux_$goarch.go"; exit 1; }

OUT=$(mktemp); trap 'rm -f "$OUT"' EXIT
re="^($(echo $TESTS | tr ' ' '|'))\$"
if ! (cd "$REPO" && OPENWRT_MCP_KERNEL_HEADERS=required go test -count=1 -v -run "$re" .) > "$OUT" 2>&1; then
	grep -E '^(=== RUN|--- FAIL|FAIL|ok|panic)|_test\.go:[0-9]+:' "$OUT" | head -60
	echo "FAIL: the seccomp tests are red on $goarch, kernel $(uname -r)"
	exit 1
fi
rc=0
for t in $TESTS; do
	grep -q "^--- PASS: $t " "$OUT" || { echo "FAIL: $t did not run and pass on $goarch"; rc=1; }
done
[ "$rc" -eq 0 ] || exit 1
grep -o 'kernel numbers from .*' "$OUT" | head -1 | sed 's/^/     /'
echo "ok   seccomp on $goarch natively, kernel $(uname -r): $(echo $TESTS | wc -w | tr -d ' ') tests pass"
