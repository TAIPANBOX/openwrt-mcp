# Where these scenarios come from
#
# They restate the first step of gap G3.14 in the estate's gap list (the daemon ran as root with no
# jail, no filter and no capability limit), paraphrased: the daemon runs in a procd jail with the
# mounts it needs, with no_new_privs, a minimal capability set and a seccomp filter, as the
# neighbouring daemons llm-gateway and rollcall do, and every tool still works inside it.
# `@decided 2026-11-08`: the daemon stays root in this step, because committing /etc/config and
# apk_add's writes need it; the split of input parsing from the actions that need root is the second
# step and is not done here.
#
# Each scenario is bound to a test below it, and scripts/gate-scenarios-bound.sh checks the binding
# both ways. The same properties on a running router are shown by scripts/e2e-vlab.sh, which runs
# every tool through the HTTP listener against the daemon that procd started in its jail.

Feature: the daemon runs in a jail

  Background:
    Given the init script and the files the package installs

  # bound to: TestJailIsRequestedForTheDaemon
  Scenario: the daemon is started in a jail, and not started without one
    When procd starts the daemon
    Then it is started through ujail with requirejail
    And a router where ujail cannot build the jail does not run the daemon outside it

  # bound to: TestNoNewPrivsIsSetForTheDaemon
  Scenario: no program gains privileges from a setuid file
    When procd starts the daemon
    Then no_new_privs is set for it, and so for every program it starts

  # bound to: TestCapabilitySetIsNamedAndLeavesOutWhatTheDaemonNeverUses
  Scenario: the capability set holds only what the jobs use, in every list
    When procd reads /etc/capabilities/openwrt-mcp.json
    Then the file names bounding, effective, permitted, inheritable and ambient
    And it leaves out loading modules, raw I/O, tracing, rebooting the kernel, the clock, mknod and mount
    And nothing is ambient or inheritable

  # bound to: TestJailMountsLeaveOutWhatTheDaemonNeverReads
  Scenario: the jail has only the directories the daemon's jobs use
    When the jail is built
    Then /etc, /usr, /lib, /bin, /sbin, /www and the run-time directories are in it
    And /root, /overlay, /mnt, /rom and /boot are not

  # bound to: TestSeccompIsInstalledByTheDaemonBeforeItReadsAnything
  Scenario: the filter is the daemon's own, and goes on before the configuration is read
    When openwrt-mcp serve starts
    Then it installs its seccomp filter on every thread first
    And it refuses to listen unless the kernel shows the filter in force
    And procd is not asked for a profile that a static binary would never load

  # bound to: TestPackagesShipTheCapabilityFile
  Scenario: an installed init script finds the file it names
    When the package is installed or upgraded, by apk, by opkg or by make install
    Then /etc/capabilities/openwrt-mcp.json is installed
    And a firmware upgrade carries it across

  # bound to: TestJailGateHasTeeth
  Scenario: the gate goes red on each way the jail can be lost
    When a fault is planted in a copy of the tree
    Then the gate fails that check, and says it measured nothing when a file it reads is gone
