# Where these scenarios come from
#
# They are not derived from the code. They restate what was asked for on 2026-10-08 (relayed by
# the coordinating session, paraphrased here): an agent working inside an unlock window may change
# the router's settings, its VPN and its services, but may never make the router run arbitrary
# commands. Policies are globs over config.section.option and cannot tell a firewall rule from a
# firewall include, so today a uci_apply that creates an include pointing at a script, or sets
# dnsmasq's dhcpscript, has the router run that script as root on the next reload. The daemon
# itself must refuse such a change before staging anything, for every client, always, with no
# switch; the agent must be told plainly why; the audit log must record it; and a client must be
# able to check that the binary does this.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass.

Feature: uci_apply never makes the router run code as root

  Background:
    Given an MCP client with a policy that grants uci_apply on every config

  # bound to: TestUciApplyRefusesCreatingAFirewallInclude
  Scenario: creating a firewall include that points at a script is refused
    When the agent creates a firewall section of type include and sets its path to a script
    Then uci_apply answers "refused: firewall.<name> makes the router run code as root; openwrt-mcp never applies that"
    And nothing was staged or committed, and no rollback snapshot was taken

  # bound to: TestUciApplyRefusesAnOptionOnAnExistingInclude
  Scenario: an include that already exists cannot be changed, however it is named
    Given the firewall config already has an include, named and anonymous
    When the agent sets its path through @include[0], @include[-1], its name, or its cfg id
    Or removes one of its options, which can switch a disabled include back on
    Then the change is refused and nothing is staged

  # bound to: TestUciApplyRefusesDhcpscript
  Scenario: dnsmasq's dhcpscript is refused
    When the agent sets dhcpscript on the dnsmasq section
    Then the change is refused and nothing is staged

  # bound to: TestUciApplyRefusesTheWholeBatchWhenOneChangeRunsCode
  Scenario: one refused change refuses the whole batch
    When a batch holds an ordinary network change, an ordinary firewall change and a dhcpscript
    Then none of the three is staged and the network config is untouched

  # bound to: TestUciApplyStillAppliesOrdinaryChanges
  Scenario: settings, the VPN and services can still be changed
    When the agent adds a firewall rule and a port forward, changes the Wi-Fi, adds a WireGuard peer and a static lease
    And removes a dhcpscript and deletes a whole include section
    Then the batch is applied with the rollback armed

  # bound to: TestExecRefusalKnownChanges, TestEveryExecRuleSaysWhereItComesFrom, TestDroppingAnyExecRuleTurnsThisRed
  Scenario: what counts as running code is an explicit list, each entry with its source
    Then firewall and pbr includes, dnsmasq's dhcpscript, extra config text and config directories, odhcpd's lease trigger, uhttpd's interpreters and CGI and Lua and ucode prefixes, pppd options and connect scripts, openvpn's scripts, plugins and config file, and the usual spellings of a hook (script, cmd, command, exec, hook, handler) are refused
    And every entry names the OpenWrt source it comes from
    And taking any single entry out of the list turns a named test red

  # bound to: TestOpenWrtOptionNamesOnlyTheHooksAreRefused, TestExecRefusalKnownChanges
  Scenario: the settings an agent needs stay allowed
    Then of every option name OpenWrt's own Wi-Fi, firewall, DHCP and network sources define, only the hooks are refused
    And firewall rule, redirect, zone and forwarding options, Wi-Fi options, static, DHCP and WireGuard interface and peer options, and DHCP host and domain options are allowed

  # bound to: TestUciApplyRefusesALineBreakInAValue, TestUciApplyRefusesASelectorThatHidesAnotherKey
  Scenario: a value or a name cannot smuggle a hook past the check
    When a value carries a line break that would become a second line of a generated config file
    Or a section or option name carries a dot, an "=" or a space, so the key uci acts on is not the key that was checked
    Then the change is refused and nothing is staged

  # bound to: TestParseUCISectionTypesSweep, TestSelectorType, TestUciApplyRefusesWhenTheSectionTypeCannotBeRead
  Scenario: what kind of section a change lands in is read, not guessed
    Then a section's type is read from uci -X show for its config, or from an @type[n] selector
    And a value that imitates a section line can only add a type to check, never hide an include
    And when the type cannot be read, the change is refused

  # bound to: TestUciApplyCodeExecRefusalIsAudited
  Scenario: the refusal is in the audit log
    Then the audit log records the uci_apply as DENIED, with the refused key and the reason

  # bound to: TestCLIStatusJSONSaysUciApplyRefusesCodeExec
  Scenario: a client can check for the guarantee before granting uci_apply
    When it runs openwrt-mcp status --json
    Then capabilities.uci_apply_refuses_code_exec is true
