#!/bin/sh
# Build an apk v3 package for OpenWrt 25.12 and later.
#
# mkipk.sh gets away without any OpenWrt tooling because an .ipk is only an archive, and
# a CGO_ENABLED=0 static Go binary has nothing to link. The same argument leads somewhere
# different here, because an apk v3 package is not an archive. It is a binary ADB blob:
# one ADB block carrying the schema and metadata, zero or more SIG blocks, then DATA
# blocks holding the file contents, all as tagged 32-bit little-endian values. Handing
# apk a renamed .ipk is not a near miss, it is a different file format, and OpenWrt's own
# apk says so:
#
#   $ apk add --allow-untrusted renamed-openwrt-mcp-0.5.0-r1.apk
#   ERROR: renamed-openwrt-mcp-0.5.0-r1.apk: v2 package format error
#
# Exactly one program writes that format: apk-tools v3, via `apk mkpkg`. There is no Go
# or Python implementation of the ADB container anywhere, and nfpm and go-apk both write
# the older tar-based v2 layout instead. So the honest minimum is not "no tooling", it is
# "the smallest thing that contains the one writer".
#
# That thing is not the OpenWrt SDK. The SDK is 241 MiB for mediatek/filogic, and every
# part of it before the last step exists to produce a file tree that `go build` and
# `install` have already produced here. OpenWrt's include/package-pack.mk ends in a
# single command, and it is the same command this script runs:
#
#   apk mkpkg --info name:... --info version:... --files <dir> --output <file>
#
# apk-tools v3 ships in alpine:edge, an 8 MB image, and that is what this script reaches
# for when the host has no apk of its own. Alpine 3.22 and earlier are still on
# apk-tools 2 and cannot do this.
#
# Two differences from the .ipk that show up for whoever installs the result:
#
#   - apk v3 refuses an unsigned local file unless you pass --allow-untrusted. opkg never
#     asked for that. Signing is a repository-index concern (apk adbsign over an index
#     built by apk mkndx), not a per-package one, and package-pack.mk does not sign
#     either, so an unsigned package here matches what OpenWrt itself produces.
#   - The feed names packages <name>-<version>-r<N>.apk with no architecture in the
#     filename, because the architecture lives in the metadata and in the repository
#     path. The .ipk convention of name_version_arch.ipk does not carry over.
#
# Verified 2026-09-08: the package this script produces installs with `apk add` inside
# openwrt/rootfs:aarch64_generic-25.12.4 (apk-tools 3.0.5), registers with its metadata
# and dependencies intact, lands all four files with the right modes, and the daemon runs.
#
# Usage: ./mkapk.sh <binary> <version> [apk-arch]
set -eu

BIN=${1:?usage: mkapk.sh <binary> <version> [arch]}
VERSION=${2:?usage: mkapk.sh <binary> <version> [arch]}
# `cat /etc/apk/arch` on the target reports this. It is the OpenWrt package architecture,
# not the OCI or uname one.
ARCH=${3:-aarch64_cortex-a53}
# The package release. Bump when the packaging changes but the binary version does not.
PKGREL=${PKGREL:-1}
PKG=openwrt-mcp
OUT="${PKG}-${VERSION}-r${PKGREL}.apk"

# Pinned so a rebuild cannot silently pick up a different apk-tools. Bump deliberately.
ALPINE=${ALPINE:-alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000}

SRC=$(cd "$(dirname "$0")" && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

# ---- the file tree, identical to what mkipk.sh stages
#
# The two scripts stage the same tree on purpose, and scripts/gate-apk-parity.sh asserts
# they still agree. Sharing the code would couple a working packager to a new one for the
# sake of twenty lines; asserting the result instead catches the drift that actually
# matters, which is the two packages disagreeing about what lands on the router.
DATA="$BUILD/root"
mkdir -p "$DATA/usr/bin" "$DATA/etc/init.d" "$DATA/etc/config" "$DATA/lib/upgrade/keep.d" \
         "$DATA/usr/lib/oui-httpd/rpc" "$DATA/usr/share/oui/menu.d"
install -m 0755 "$BIN"                               "$DATA/usr/bin/$PKG"
install -m 0755 "$SRC/files/etc/init.d/$PKG"         "$DATA/etc/init.d/$PKG"
install -m 0644 "$SRC/files/etc/config/$PKG"         "$DATA/etc/config/$PKG"
install -m 0644 "$SRC/files/lib/upgrade/keep.d/$PKG" "$DATA/lib/upgrade/keep.d/$PKG"
install -m 0644 "$SRC/files/usr/lib/oui-httpd/rpc/$PKG" "$DATA/usr/lib/oui-httpd/rpc/$PKG"

VIEW_SRC="$SRC/ui/view.js"
if [ -f "$VIEW_SRC" ]; then
	mkdir -p "$DATA/www/views" "$DATA/www/i18n"
	gzip -9 -c "$VIEW_SRC" > "$DATA/www/views/gl-sdk4-ui-$PKG.common.js.gz"
	chmod 0644 "$DATA/www/views/gl-sdk4-ui-$PKG.common.js.gz"
	install -m 0644 "$SRC/files/usr/share/oui/menu.d/$PKG.json" "$DATA/usr/share/oui/menu.d/$PKG.json"
	for lang in "$SRC/files/www/i18n/gl-sdk4-ui-$PKG."*.json; do
		[ -f "$lang" ] && install -m 0644 "$lang" "$DATA/www/i18n/$(basename "$lang")"
	done
else
	echo "note: no ui/view.js, so the view and its menu entry are not packaged" >&2
fi

# ---- lifecycle scripts
#
# apk's stage names differ from opkg's. post-install covers both a fresh install and an
# upgrade, so the enable+restart pair belongs there; pre-deinstall is opkg's prerm. There
# is no IPKG_INSTROOT guard to write, because apk runs scripts inside the target root
# rather than on the build host.
cat > "$BUILD/post-install" <<EOF
#!/bin/sh
/etc/init.d/$PKG enable
/etc/init.d/$PKG restart
exit 0
EOF
cat > "$BUILD/pre-deinstall" <<EOF
#!/bin/sh
/etc/init.d/$PKG stop
/etc/init.d/$PKG disable
exit 0
EOF
chmod 0755 "$BUILD/post-install" "$BUILD/pre-deinstall"

# ---- find a writer for the format
#
# A host apk is only usable if it is v3; apk-tools 2 has no mkpkg subcommand at all, so
# probing for the subcommand is the check, not the version string.
run_mkpkg() {
	if command -v apk >/dev/null 2>&1 && apk mkpkg --help >/dev/null 2>&1; then
		apk mkpkg "$@"
	elif command -v docker >/dev/null 2>&1; then
		docker run --rm -v "$BUILD:$BUILD" -w "$BUILD" "$ALPINE" apk mkpkg "$@"
	else
		echo "mkapk.sh: need either apk-tools v3 on PATH or docker to run $ALPINE" >&2
		echo "mkapk.sh: apk v3 is the only writer of the package format; see the header" >&2
		exit 1
	fi
}

# Keep the description on one line: mkpkg takes it as a single --info value, and a
# newline inside it ends up in the metadata where apk info renders it badly.
run_mkpkg \
	--info "name:$PKG" \
	--info "version:$VERSION-r$PKGREL" \
	--info "arch:$ARCH" \
	--info "license:MIT" \
	--info "origin:$PKG" \
	--info "url:https://github.com/GlassOnTin/openwrt-mcp" \
	--info "maintainer:Ian Williams" \
	--info "description:MCP server hosted on the router. Exposes ubus, uci and logs to an AI agent over loopback, behind bearer auth, standing policies and an audit log." \
	--info "depends:libc ubus ubox" \
	--script "post-install:$BUILD/post-install" \
	--script "pre-deinstall:$BUILD/pre-deinstall" \
	--files "$DATA" \
	--output "$BUILD/$OUT"

rm -f "$SRC/$OUT"
cp "$BUILD/$OUT" "$SRC/$OUT"

echo "$OUT"
