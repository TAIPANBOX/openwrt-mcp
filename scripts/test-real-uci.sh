#!/bin/sh
# test-real-uci.sh -- the held-action classifier on OpenWrt's own uci, in OpenWrt's own rootfs.
#
# The Go tests answer `uci -X show` from fixtures, which proves the predicates and the plumbing
# but not that the state the classifier reads is the state libuci builds. This builds the test
# binary for the image's architecture, runs TestRealUCIClassification inside the published rootfs
# with OPENWRT_MCP_REAL_UCI=1 (it writes that container's /etc/config), and requires the test to
# have run and passed: a skip, or a binary that ran nothing, is a failure, not a pass.
#
#   ROOTFS_IMAGE=openwrt/rootfs:x86-64-25.12.4 PLATFORM=linux/amd64 GOARCH=amd64 ./scripts/test-real-uci.sh
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
GOARCH=${GOARCH:-amd64}
IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:x86-64-25.12.4}
PLATFORM=${PLATFORM:-linux/amd64}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go test -c -o "$WORK/openwrt-mcp.test" . )
docker run --rm -i --platform "$PLATFORM" -v "$WORK:/t:ro" -e OPENWRT_MCP_REAL_UCI=1 "$IMAGE" \
	/bin/sh -c 'cd /tmp && /t/openwrt-mcp.test -test.run "^TestRealUCIClassification$" -test.v -test.count=1' \
	> "$WORK/out" 2>&1 || { cat "$WORK/out"; echo "FAIL: the classifier on OpenWrt's uci"; exit 1; }
grep -q -- '^--- PASS: TestRealUCIClassification ' "$WORK/out" || {
	cat "$WORK/out"; echo "FAIL: TestRealUCIClassification did not run and pass (measured nothing)"; exit 1; }
n=$(grep -c -- '^    --- PASS: TestRealUCIClassification/' "$WORK/out" || true)
[ "$n" -ge 12 ] || { cat "$WORK/out"; echo "FAIL: only $n cases passed, want 12"; exit 1; }
echo "test-real-uci: $n cases on $IMAGE, all pass"
