# Where these scenarios come from
#
# They are not derived from the code. They restate a decision recorded as @decided 2026-10-08
# (relayed by the coordinating session, paraphrased here): an agent may install packages on the
# router only from the official OpenWrt feed, and only where the owner has opted in; never from
# a link, never from a local file, and never with signature checks turned off. The request that
# came with it (2026-10-09, paraphrased): a tool that takes a list of package names and a dry-run
# flag; apk is given a repositories file holding only the official feeds the firmware ships, and
# a package that exists only in another feed, such as this agent's own, cannot be installed
# through it; URLs, paths, flags, .apk files and version pins are refused and audited as DENIED;
# the dry run shows what would be installed; nothing grants the tool by default; and a client
# can check for the guarantee in status --json.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass.

Feature: apk_add installs packages from the official OpenWrt feeds only

  Background:
    Given an OpenWrt 25.12 router whose distfeeds.list names the official feeds on downloads.openwrt.org
    And a custom feed in customfeeds.list, and one appended to distfeeds.list as well

  # bound to: TestApkAddIsGrantedByNoPolicyByDefault
  Scenario: nobody can install anything until the owner grants apk_add
    Given the configuration the package ships, or a policy that grants every other tool on every scope
    When the agent calls apk_add
    Then it is denied and apk never runs

  # bound to: TestApkAddScopeIsThePackageName
  Scenario: the owner can grant some packages and not others
    Given a policy that grants apk_add on tcpdump and kmod-*
    Then tcpdump and kmod-wireguard may be installed
    And iperf3 is denied, alone or in one call with tcpdump

  # bound to: TestApkAddDryRunSimulatesFromTheOfficialFeedsOnly, TestApkAddNamesUpgradesOfInstalledPackages
  Scenario: a dry run shows what would be installed and installs nothing
    When the agent calls apk_add with tcpdump and dry_run
    Then apk refreshes the official indexes and runs add --simulate
    And the answer lists every package that would be installed, dependencies included
    And a package already installed that would be upgraded is listed apart

  # bound to: TestApkAddInstallsFromTheOfficialFeedsOnly, TestApkAddDryRunSimulatesFromTheOfficialFeedsOnly, TestApkArgv
  Scenario: apk is handed the official feeds and nothing else
    When the agent installs tcpdump and golang1.26
    Then apk runs with --repositories-file naming a file that holds exactly the official feeds, with --no-interactive, and with the names after --
    And no custom feed reaches that file
    And apk is never passed --allow-untrusted, a --force option, --keys-dir, --root, --arch or a --repository
    And /etc/apk/config is switched off for the call, so it cannot turn signature checks off
    And apk runs in an empty directory, so a name with a dot cannot be read as a local file
    And the repositories file is gone afterwards

  # bound to: TestOfficialFeedsFromDistfeeds, TestApkFeedLineTable, TestDroppingAnyApkFeedRuleTurnsTheTableRed, TestOfficialFeedLineSweep
  Scenario: what counts as an official feed is a fixed rule
    Then a line is used only if it is an https URL of a packages.adb on downloads.openwrt.org, with no user, port, query, fragment, variable or '..'
    And mirrors, http, local paths, tagged lines and look-alike hosts are not used
    And taking any single rule out of the list turns a named test red

  # bound to: TestApkAddRefusesWhenNoOfficialFeedRemains
  Scenario: with no official feed left there is nothing to install from
    When distfeeds.list is missing, commented out, or names only other feeds
    Then apk_add refuses, apk never runs, and the refusal never repeats a line it did not use

  # bound to: TestApkAddRefusesWhatIsNotAPackageNameAndRunsNothing, TestApkNameTable, TestDroppingAnyApkNameRuleTurnsTheTableRed
  Scenario: anything but a package name is refused before apk runs
    When the agent names a URL, a path, an option, an .apk file, name=1.0 or another version constraint, a repository tag, or a virtual package
    Then apk_add refuses and says why, and apk never runs
    And taking any single rule out of the list turns a named test red

  # bound to: TestApkNameListLimits
  Scenario: one call installs between 1 and 20 packages
    When the agent sends no names, or 21
    Then apk_add refuses, naming every bad entry and none of the good ones

  # bound to: TestApkNameAcceptsEveryUnusualOfficialName
  Scenario: every official package can be named
    Then every name in OpenWrt 25.12.4's official feeds with upper case, a dot or an underscore in it is accepted

  # bound to: TestApkAddRefusalIsAuditedDenied
  Scenario: the refusal is in the audit log
    Then the audit log records the apk_add as DENIED, with the name refused and why

  # bound to: TestApkAddFailureIsAnErrorWithApksWords, TestBoundApkOutput
  Scenario: when apk fails, the agent reads apk's own words, bounded
    When apk cannot find a package
    Then the call is an error audited as ERROR, carrying apk's message
    And a flood of output is cut to a bounded size that keeps apk's verdict

  # bound to: TestApkAddToolSchema
  Scenario: an MCP client is told what the tool takes
    Then apk_add takes packages, a list of strings, and dry_run, a boolean

  # bound to: TestCLIStatusJSONSaysApkAddIsOfficialFeedOnly
  Scenario: a client can check for the guarantee before granting apk_add
    When it runs openwrt-mcp status --json
    Then capabilities.apk_add_official_feed_only is true
