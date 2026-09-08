# GL.iNet's default LAN address; override for your own router:
#   make install ROUTER=root@192.168.1.1
ROUTER ?= root@192.168.8.1
# Whatever `go` is on PATH. Override for a specific toolchain:
#   make build GO=/usr/local/go/bin/go
GO     ?= go
ARCH   ?= arm64

# OpenWrt's dropbear has no sftp-server, so modern scp (which defaults to SFTP)
# fails with "Connection closed". Pipe over ssh instead.
#
# Write to a sidecar and rename: `cat >` onto a running binary fails with "Text file
# busy" (ETXTBSY), which is every install after the first. rename(2) replaces the
# directory entry and leaves the running process on the old inode, so the upgrade is
# atomic and there is never a window with no binary on disk.
DEPLOY = ssh $(ROUTER) 'cat > $(1).new && chmod +x $(1).new && mv $(1).new $(1)'

test:
	$(GO) vet ./... && $(GO) test ./...

build: test
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -ldflags="-s -w" -o openwrt-mcp.$(ARCH) .

install: build
	$(call DEPLOY,/usr/bin/openwrt-mcp) < openwrt-mcp.$(ARCH)
	ssh $(ROUTER) 'cat > /etc/init.d/openwrt-mcp && chmod +x /etc/init.d/openwrt-mcp' < files/etc/init.d/openwrt-mcp
	ssh $(ROUTER) '[ -f /etc/config/openwrt-mcp ] || cat > /etc/config/openwrt-mcp' < files/etc/config/openwrt-mcp
	ssh $(ROUTER) '/etc/init.d/openwrt-mcp enable && /etc/init.d/openwrt-mcp restart && sleep 1 && logread -l 5 | grep openwrt-mcp'

# Staging install for testing: /tmp only, nothing persisted.
stage: build
	$(call DEPLOY,/tmp/openwrt-mcp) < openwrt-mcp.$(ARCH)

# Version comes from the binary, so the package can never claim a version it isn't.
VERSION = $(shell sed -n 's/^var version = "\(.*\)"/\1/p' main.go)

ipk: build
	./mkipk.sh openwrt-mcp.$(ARCH) $(VERSION) $(IPK_ARCH)

# Unlike `install`, this survives a firmware upgrade: the package ships a
# /lib/upgrade/keep.d entry, and opkg treats /etc/config as a conffile.
install-ipk: ipk
	ssh $(ROUTER) 'cat > /tmp/openwrt-mcp.ipk' < openwrt-mcp_$(VERSION)_$(or $(IPK_ARCH),aarch64_cortex-a53).ipk
	ssh $(ROUTER) 'opkg install --force-reinstall /tmp/openwrt-mcp.ipk && rm -f /tmp/openwrt-mcp.ipk'

# OpenWrt 25.12 replaced opkg with apk, so a router on a current release needs this one
# instead. The two packages carry the same tree; scripts/gate-apk-parity.sh asserts it.
apk: build
	./mkapk.sh openwrt-mcp.$(ARCH) $(VERSION) $(APK_ARCH)

# apk refuses an unsigned local file unless told not to. Signing belongs to a repository
# index rather than to a package, and OpenWrt's own package build does not sign either,
# so an unsigned package here is what the feed would produce, not a corner cut.
install-apk: apk
	ssh $(ROUTER) 'cat > /tmp/openwrt-mcp.apk' < openwrt-mcp-$(VERSION)-r$(or $(PKGREL),1).apk
	ssh $(ROUTER) 'apk add --allow-untrusted /tmp/openwrt-mcp.apk && rm -f /tmp/openwrt-mcp.apk'

# Installs the .apk into a real OpenWrt 25.12 rootfs and checks it leaves the same state
# the .ipk does. Needs docker; builds both packages first.
gate-apk: ipk apk
	./scripts/gate-apk-parity.sh

clean:
	rm -f openwrt-mcp openwrt-mcp.* *.ipk *.apk

.PHONY: test build install stage ipk install-ipk apk install-apk gate-apk clean
