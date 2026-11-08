# Where these scenarios come from
#
# They restate the first step of gap G3.14 in the estate's gap list (the daemon ran as root with no
# jail, no filter and no capability limit), paraphrased, and the decision that followed:
# `@decided 2026-11-08`: a light cage now, a split of privileges in a separate change straight after
# it. The light cage narrows the kernel surface (system calls, capabilities, setuid) and builds no
# jail, because a jail around a daemon that is root with the whole of ubus and a writable /etc holds
# nothing in, and it would cost every program started by exec its view of the router.
#
# What this does not do: contain a broken daemon. Root, ubus (service.set starts any command outside
# the daemon's own process) and write access to the file system remain ways out; the split of the
# part that parses input from the part that acts closes them and is not in this change.
#
# Each scenario is bound to a test below it, and scripts/gate-scenarios-bound.sh checks the binding
# both ways. The same properties on a running router are shown by scripts/e2e-vlab.sh, which runs
# every tool through the HTTP listener against the daemon that procd started.

Feature: the daemon runs with a narrowed kernel surface

  Background:
    Given the init script and the files the package installs

  # bound to: TestUjailCarriesTheCapabilitiesWithoutAJail
  Scenario: procd applies the capability file through ujail, which builds no jail
    When procd starts the daemon
    Then it is started through ujail with the capability file and no mount or namespace

  # bound to: TestNoNamespaceAndNoMountIsAskedOfUjail
  Scenario: a program started by exec sees the router as before
    When procd starts the daemon
    Then the init script asks ujail for no mount, no namespace, no socket and no jail requirement

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

  # bound to: TestExpectedCapabilityMaskIsTheCapabilityFile
  Scenario: the mask the daemon insists on is the file procd is given
    When the capability file or the daemon's expected mask changes
    Then the two still name the same nine capabilities

  # bound to: TestDaemonRefusesToListenUnlessProcdAppliedTheCapabilities, TestCapabilitySetsAreRequiredOfRootAndOnlyOfRoot, TestRootOnAPlatformWithNoFilterStillNeedsTheCapabilitiesAndNoNewPrivs
  Scenario: the daemon does not listen when procd did not apply the capabilities
    When the bounding or the effective set of the daemon is not the expected one, or is not shown
    Then the daemon refuses to start, so a router without ujail does not run it with every capability
    And a daemon that is not root, as in the tests that run the binary, is not held to the sets
    And on a platform with no seccomp filter root still needs the capability sets and no_new_privs, and only then starts

  # bound to: TestSeccompIsInstalledByTheDaemonBeforeItReadsAnything
  Scenario: the filter is the daemon's own, and goes on before the configuration is read
    When openwrt-mcp serve starts
    Then it installs its seccomp filter on every thread first
    And it refuses to listen unless the kernel shows the filter in force
    And procd is not asked for a profile that a static binary would never load

  # bound to: TestFilterKillsEveryX32Number
  Scenario: the x32 form of a call is no way round the filter
    When a call is made with bit 30 set in its number
    Then it is killed, a denied call, a clone into a user namespace and an allowed call alike

  # bound to: TestEveryDeniedCallIsKilledByThisKernel, TestFilterIsNotBuiltWhenTwoNamesShareANumber
  Scenario: the filter of each architecture is run by a kernel of that architecture
    When the tests run natively on amd64 and on arm64, the architecture of a router
    Then every call on the list, by the number the kernel's own headers give its name, ends the caller with SIGSYS
    And a name in the table that points at another call's number fails the test
    And a table that gives two names one number builds no filter, so the daemon does not start on it

  # bound to: TestPackagesShipTheCapabilityFile
  Scenario: an installed init script finds the file it names
    When the package is installed or upgraded, by apk, by opkg or by make install
    Then /etc/capabilities/openwrt-mcp.json is installed
    And a firmware upgrade carries it across

  # bound to: TestJailGateHasTeeth
  Scenario: the gate goes red on each way the narrowing can be lost
    When a fault is planted in a copy of the tree
    Then the gate fails that check, and says it measured nothing when a file it reads is gone
