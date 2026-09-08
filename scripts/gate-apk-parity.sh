#!/bin/sh
# gate-apk-parity.sh -- CI gate enforcing this invariant:
#
#   "apk from OpenWrt 25.12 installs our .apk and leaves the system in the same state
#   opkg leaves after our .ipk: the same file set with the same modes, the service
#   enabled, and a locally edited /etc/config/openwrt-mcp untouched by upgrade."
#
# OpenWrt 25.12 is moving from opkg to apk, and this repo will end up shipping both
# package formats for a while. The two package builders (mkipk.sh and whatever builds
# the .apk) are separate pieces of code with separate ideas of what "the package"
# contains, so nothing stops them from drifting: a file added to one and not the
# other, a mode that survives one packaging tool's tar step and not the other's, a
# conffiles-equivalent declaration that only one of the two remembers to make. None of
# that shows up in `go test`, and none of it shows up until someone's router ends up
# with half the files or a config file that got clobbered on upgrade. This script is
# the check that would have caught it before a router did.
#
# It needs a real apk binary against a real OpenWrt rootfs, not a description of one,
# so the apk-side checks run inside a container. Docker is not a nice-to-have here:
# apk's behaviour (trigger scripts, conffile handling, `--allow-untrusted`) is part of
# what is being verified, and there is no way to fake that from the host.
set -eu

# ---------------------------------------------------------------------------
# --selftest: list the checks this gate would run, without running them. The CI
# teeth step (scripts/gates-have-teeth.sh) uses this to prove the gate actually has
# checks wired up, rather than trusting that a script with the right name does
# something. It must work with no artefacts built and no docker daemon running.
# ---------------------------------------------------------------------------
# These names are the binding to features/apk-packaging.feature. Each scenario there
# names the check that proves it, and CI asserts the two lists agree in both directions,
# so a scenario cannot lose its check and a check cannot lose its scenario.
CHECKS='check_format_is_not_an_archive check_installs check_path_parity check_modes check_service_enabled check_config_survives check_clean_removal check_arch_is_honoured'

if [ "${1:-}" = "--selftest" ]; then
	n=0
	for check_name in $CHECKS; do
		echo "$check_name"
		n=$((n + 1))
	done
	if [ "$n" -eq 0 ]; then
		# A gate that lists zero checks would look identical to a healthy one in CI
		# output right up until it silently stopped testing anything. Fail loudly
		# instead of reporting a clean run over nothing.
		echo "measured nothing" >&2
		exit 1
	fi
	exit 0
fi

total=0
for check_name in $CHECKS; do
	total=$((total + 1))
done

REPO=$(cd "$(dirname "$0")/.." && pwd)

# First match of the naming pattern each builder produces, unless the caller pins one.
default_artefact() {
	set -- "$REPO"/$1
	if [ -f "$1" ]; then
		printf '%s\n' "$1"
	fi
}

IPK=${IPK:-$(default_artefact 'openwrt-mcp_*.ipk')}
APK=${APK:-$(default_artefact 'openwrt-mcp-*.apk')}
# OpenWrt publishes its OCI platform string as the package architecture; plain
# "linux/arm64" fails with "no matching manifest" even though it is the same silicon.
ROOTFS_IMAGE=${ROOTFS_IMAGE:-openwrt/rootfs:aarch64_generic-25.12.4}
PLATFORM=${PLATFORM:-linux/aarch64_generic}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---- precondition: both artefacts exist ----
missing=""
[ -n "$IPK" ] && [ -f "$IPK" ] || missing="$missing .ipk (build it: make ipk)"
[ -n "$APK" ] && [ -f "$APK" ] || missing="$missing .apk (build it: make apk)"
if [ -n "$missing" ]; then
	echo "FAIL: artefacts exist: missing$missing"
	exit 1
fi
echo "PASS: artefacts exist: ipk=$IPK apk=$APK"

# Extract the file set the .ipk actually ships, so the container can diff against it
# without needing tar or the .ipk itself inside the rootfs image.
#
# The .ipk is a gzipped tar of three members, not an ar archive (see mkipk.sh for why);
# data.tar.gz is the filesystem tree that lands on the router, rooted at "./".
(cd "$WORK" && tar -xzf "$IPK")
if [ ! -f "$WORK/data.tar.gz" ]; then
	echo "FAIL: $IPK has no data.tar.gz -- is it really an .ipk?"
	exit 1
fi
# Strip the leading "./" opkg/tar use, and drop directory-only entries (they end in
# "/"): apk's file list is files only, so a directory entry here would show up as a
# spurious diff even though both tools agree on the actual content.
tar -tzf "$WORK/data.tar.gz" \
	| sed 's#^\./##' \
	| grep -v '/$' \
	| grep -v '^$' \
	| sort > "$WORK/ipk-files"

# ---- 2 through 6: everything that needs a real apk binary and a real OpenWrt rootfs.
# One container, one script, because each `docker run` is a fresh container and state
# (the installed package, the edited config file) does not carry between invocations.
echo "-- container checks: $ROOTFS_IMAGE ($PLATFORM) --"
# -i is load-bearing, not decoration. Without it docker gives the container an empty
# stdin, so "sh -s" reads nothing, runs nothing and exits 0 -- the whole gate then
# reports success having measured nothing at all. That happened once on 2026-09-08 and
# the only symptom was the absence of the PASS lines below.
if ! docker run --rm -i --platform "$PLATFORM" \
	-v "$WORK:/work" \
	-v "$APK:/openwrt-mcp.apk:ro" \
	-v "$IPK:/openwrt-mcp.ipk:ro" \
	"$ROOTFS_IMAGE" /bin/sh -s <<'CONTAINER_EOF'
set -eu

PKG=openwrt-mcp
APK=/openwrt-mcp.apk

# A booted router has /var as a symlink to /tmp and /var/lock already created, so
# rc.common's enable can take its lock. A bare rootfs container has neither, and without
# them the postinst's "enable" writes no rc.d link at all while the install still
# reports success. Creating them here reproduces the router, it does not paper over a
# fault: the same install was run both ways on 2026-09-08, and the only difference was
# this directory.
mkdir -p /var/lock /var/run /var/state

# ---- 1. the format is not an archive ----
# The .ipk renamed. This is the hypothesis the repo's own no-SDK reasoning invites, and
# it has to be red, or mkapk.sh reaching for apk-tools would be unjustified ceremony.
cp /openwrt-mcp.ipk /tmp/renamed.apk
if apk add --allow-untrusted /tmp/renamed.apk >/tmp/renamed.out 2>&1; then
	echo "FAIL [1/8] check_format_is_not_an_archive: apk ACCEPTED a renamed .ipk"
	exit 1
fi
if ! grep -q 'format error' /tmp/renamed.out; then
	echo "FAIL [1/8] check_format_is_not_an_archive: refused, but not for a format reason:"
	cat /tmp/renamed.out
	exit 1
fi
rm -f /tmp/renamed.apk
echo "PASS [1/8] check_format_is_not_an_archive"

# ---- 2. installs and registers ----
# Not signed by a repo key, only built locally -- that is expected for a package that
# has not been published anywhere, not a sign something is wrong with it.
if ! apk add --allow-untrusted "$APK"; then
	echo "FAIL [2/8] check_installs: apk add rejected the package"
	exit 1
fi
if ! apk info -e "$PKG" >/dev/null 2>&1; then
	echo "FAIL [2/8] check_installs: apk add succeeded but the package is not registered"
	exit 1
fi
echo "PASS [2/8] check_installs"

# ---- 3. path-set parity ----
# "apk info -L" prints a header line ending in "contains:" before the file list, and
# that header is apk's own framing, not package content -- left in, it would show up
# as a permanent one-line diff against the .ipk's file list no matter how well the two
# packages actually match.
apk info -L "$PKG" \
	| grep -v 'contains:$' \
	| grep -v '^$' \
	| sort > /work/apk-files
# Compared with shell string equality rather than diff: this rootfs is a minimal
# busybox with no diff applet, and a gate that needs a tool the target does not have is
# a gate that does not run.
if [ "$(cat /work/ipk-files)" != "$(cat /work/apk-files)" ]; then
	echo "FAIL [3/8] check_path_parity: apk and ipk disagree on the file set"
	# Both lists in full rather than only the differing lines. A package this size is a
	# handful of paths, and a reader chasing a parity failure wants to see what each
	# side actually shipped, not a delta they then have to reconstruct.
	echo "-- the .ipk ships --"
	sed 's/^/  /' /work/ipk-files
	echo "-- the .apk ships --"
	sed 's/^/  /' /work/apk-files
	exit 1
fi
echo "PASS [3/8] check_path_parity"

# ---- 4. modes ----
# A non-executable binary is a router that cannot exec the service at all; a config
# file that is not 0644 is either unreadable to something that expects it, or
# writable in a way opkg's install never allowed.
if [ ! -x /usr/bin/openwrt-mcp ]; then
	echo "FAIL [4/8] check_modes: /usr/bin/openwrt-mcp is not executable"
	exit 1
fi
# No "stat -c" here -- this rootfs is busybox, not coreutils -- so parse busybox's
# "ls -l" instead. The permission string is always the first field.
perm=$(ls -l /etc/config/openwrt-mcp | awk '{print $1}')
if [ "$perm" != "-rw-r--r--" ]; then
	echo "FAIL [4/8] check_modes: /etc/config/openwrt-mcp is $perm, want -rw-r--r-- (644)"
	exit 1
fi
echo "PASS [4/8] check_modes"

# ---- 5. service enabled ----
# This file is procd's own enable marker. Its presence is what proves the postinst
# script actually ran "/etc/init.d/openwrt-mcp enable", not just that the init script
# was unpacked onto disk.
if [ ! -e /etc/rc.d/S95openwrt-mcp ]; then
	echo "FAIL [5/8] check_service_enabled: /etc/rc.d/S95openwrt-mcp is missing"
	exit 1
fi
echo "PASS [5/8] check_service_enabled"
# The same postinst also calls "restart", which fails harmlessly here because there is
# no procd running in a bare rootfs container. That failure is expected, not a package
# fault, and it does not reach here as a failed install because the postinst's own
# trailing "exit 0" keeps a failed restart from failing the apk transaction.

# ---- 6. config survives upgrade ----
marker="# gate-apk-parity marker $$"
echo "$marker" >> /etc/config/openwrt-mcp
# apk has no way to express "install the identical version again" as an upgrade from a
# single package file -- a same-version reinstall is the closest one file can get. It
# still exercises the failure that matters on a router: losing a live policy file on
# any apk operation that touches an already-installed package, upgrade or not.
if ! apk add --allow-untrusted --force-refresh "$APK"; then
	echo "FAIL [6/8] check_config_survives: reinstall failed"
	exit 1
fi
if ! grep -qF "$marker" /etc/config/openwrt-mcp; then
	echo "FAIL [6/8] check_config_survives: marker line lost after reinstall"
	exit 1
fi
echo "PASS [6/8] check_config_survives"

# ---- 7. the architecture in the metadata is honoured ----
# For .ipk the architecture was in the filename, so a mismatch was visible. In apk it
# lives only in the metadata, and a wrong value would install a binary this router
# cannot execute. Rebuild the same tree claiming an architecture that is not ours and
# require a refusal.
mkdir -p /tmp/wrongarch/usr/bin
echo '#!/bin/sh' > /tmp/wrongarch/usr/bin/openwrt-mcp
chmod 0755 /tmp/wrongarch/usr/bin/openwrt-mcp
if apk mkpkg --help >/dev/null 2>&1; then
	apk mkpkg --info name:openwrt-mcp-wrongarch --info version:0-r1 \
		--info "arch:$(cat /etc/apk/arch)x" --info license:MIT \
		--files /tmp/wrongarch --output /tmp/wrongarch.apk >/dev/null 2>&1
	if apk add --allow-untrusted /tmp/wrongarch.apk >/dev/null 2>&1; then
		echo "FAIL [7/8] check_arch_is_honoured: apk installed a foreign-architecture package"
		exit 1
	fi
	echo "PASS [7/8] check_arch_is_honoured"
else
	# The rootfs ships apk-tools without mkpkg, so the wrong-arch package cannot be
	# built here. Assert the installed package at least declares this router's arch,
	# which is the half of the property that is still observable.
	want=$(cat /etc/apk/arch)
	got=$(apk list --installed 2>/dev/null | grep "^openwrt-mcp-" | awk '{print $2}' | head -1)
	if [ "$got" != "$want" ]; then
		echo "FAIL [7/8] check_arch_is_honoured: package declares $got, router is $want"
		exit 1
	fi
	echo "PASS [7/8] check_arch_is_honoured (declared arch only; no mkpkg in this rootfs)"
fi
# ---- 8. clean removal ----
if ! apk del "$PKG"; then
	echo "FAIL [8/8] check_clean_removal: apk del failed"
	exit 1
fi
if [ -e /usr/bin/openwrt-mcp ] || [ -e /etc/rc.d/S95openwrt-mcp ]; then
	echo "FAIL [8/8] check_clean_removal: files remain after apk del"
	exit 1
fi
echo "PASS [8/8] check_clean_removal"
CONTAINER_EOF
then
	echo "FAIL: apk-side checks failed inside the container (see above)"
	exit 1
fi

echo "gate-apk-parity: all $total checks passed"
