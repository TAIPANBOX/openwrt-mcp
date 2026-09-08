# Where these scenarios come from
#
# They are not derived from the code. They restate what was asked for, on 2026-09-08,
# by the person who wanted this package to exist. His words, verbatim:
#
#   "я хочу, щоб можна було його зробити пакетом для OpenWRT в принципі, щоб могли
#    його скачувати і встановлювати на інших роутерах, де підтримуються OpenWRT"
#   -> I want this to be an OpenWrt package in general, so that people can download it
#      and install it on other routers that run OpenWrt.
#
#   "Я розраховую на версію OpenWRT ... подивись саму останню"
#   -> I am counting on the current OpenWrt release. Check which one is the latest.
#      (Checked: 25.12.5 is the current stable, 24.10.8 the older maintained line.)
#
#   "щоб сумісність була з роутерами від 512 мегабайт оперативною пам'яттю"
#   -> so that it is compatible with routers from 512 MB of RAM upwards.
#
# Every scenario below is bound by name to a check in scripts/gate-apk-parity.sh. The
# gate's --selftest mode lists those names, and CI asserts the two lists agree, so a
# scenario cannot quietly lose its test and a test cannot quietly lose its scenario.

Feature: openwrt-mcp installs on a current OpenWrt release

  Background:
    Given a router running stock OpenWrt 25.12, which uses apk rather than opkg
    And the package built by mkapk.sh for that router's architecture

  # bound to: check_format_is_not_an_archive
  Scenario: a renamed .ipk is not a package
    Given the .ipk that opkg accepts, renamed to end in .apk
    When apk on OpenWrt 25.12 is asked to install it
    Then it is refused with a package format error
    And nothing is installed
    # This is the hypothesis the repository's own no-SDK argument invites, and it is
    # wrong: apk v3 is a binary ADB container, not an archive. Proving it red here is
    # what justifies mkapk.sh reaching for apk-tools at all.

  # bound to: check_installs
  Scenario: the package installs and registers
    When apk installs the package
    Then apk reports openwrt-mcp as installed
    And its declared dependencies libc, ubus and ubox resolve against the release

  # bound to: check_path_parity
  Scenario: the apk delivers exactly what the ipk delivers
    When the file list apk records is compared with the file list inside the .ipk
    Then the two lists are identical
    # Two packagers for one project drift silently. The .ipk is the proven one, so it
    # is the reference; a difference means one of the two is wrong about the router.

  # bound to: check_modes
  Scenario: the installed files carry the modes the router needs
    Then /usr/bin/openwrt-mcp is executable
    And /etc/config/openwrt-mcp is mode 644

  # bound to: check_service_enabled
  Scenario: installing enables the service
    When apk installs the package
    Then /etc/rc.d/S95openwrt-mcp exists
    # Which proves the post-install script ran and rc.common enable worked. The test
    # rootfs must have /var/lock created first: on a booted router /var is a symlink to
    # /tmp and the directory is there, but a bare rootfs container has neither, and
    # without it enable fails and writes no link. That is the container's gap, not the
    # package's, and it was confirmed both ways before this scenario was written.

  # bound to: check_config_survives
  Scenario: my own policies survive an upgrade
    Given a policy I added by hand to /etc/config/openwrt-mcp
    When the package is installed over itself
    Then my policy is still there
    # Losing this on a router means losing every standing grant on a routine upgrade,
    # silently, which is the worst shape of failure this package could have.

  # bound to: check_clean_removal
  Scenario: removing the package leaves nothing behind
    When apk removes the package
    Then the binary is gone
    And the rc.d link is gone

  # bound to: check_arch_is_honoured
  Scenario: a package built for the wrong architecture is refused
    Given a package whose metadata claims an architecture the router does not use
    When apk is asked to install it
    Then it is refused
    # The architecture lives in the metadata, not in the filename as it did for .ipk,
    # so a mistake here would otherwise install a binary the router cannot execute.
