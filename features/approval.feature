# Where these scenarios come from
#
# They are not derived from the code. They restate the design for per-action approval that the
# owner of the routers this fork serves approved on 2026-10-22, with the seven choices made that
# day, relayed by the coordinating session and paraphrased here.
#
# A client's unlock window lets it change settings, the VPN and services, each with a rollback.
# Some changes are too consequential for a window: opening a port to the internet, weakening the
# firewall, changing VPN routing, upstream DNS or the time source the codes depend on, opening a
# Wi-Fi network without a password into a trusted network, stopping a service that guards the
# router, and a reboot. Those are held: nothing runs, the daemon keeps an immutable record of the
# exact batch in memory, and only the owner's own client may approve it, one change at a time, with
# a fresh PIN and a fresh code from the authenticator, against a hash of exactly what is shown.
# Rejecting takes no code. The decision is made on the state a change would leave, not on the call,
# so a change split over two calls is held on the call that completes it; what cannot be checked
# waits for the owner. Approving never opens the window, and the owner's client is also the only
# one that opens it, so the agent cannot spend the owner's tries. A client may propose while its
# window is closed, within limits: one open at a time, six an hour, a pause of an hour after three
# rejections. What only a person may do (a firmware, a shell, a file, the agent's own or its
# guard's configuration) is refused outright, whatever a grant says.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass.

Feature: a high-impact change waits for the owner's approval, one change at a time

  Background:
    Given a client whose approval section names the owner's client as its approver
    And the owner has set up a PIN and an authenticator app for that client

  # bound to: TestTier3HeldWithWindowOpen
  Scenario: a high-impact change is held even while changes are unlocked
    Given the client's unlock window is open
    When it asks for a change that opens a port to the internet, weakens the firewall, changes VPN or policy routing, upstream DNS or the time servers, opens Wi-Fi without a password into a trusted network, stops a service that guards the router, or reboots it
    Then nothing is staged, committed or called
    And the answer is not an error: it says HELD, with a five-letter id and when it expires
    And the audit log records the call as HELD

  # bound to: TestTier2RunsInTheWindow, TestRewiringIsHeld
  Scenario: an ordinary change still runs in the window
    Given the client's unlock window is open
    When it changes the router's description, adds a static lease, or restarts a service
    Or it sets up a guest network: a bridge with no ports, an interface on it, a Wi-Fi with a password on that network
    Then the change is applied as before, with the rollback armed

  # bound to: TestSplitRedirectHeldOnSecondCall, TestWanPortIntoLanBridgeHeld, TestZoneRenameHeld
  # bound to: TestPredicatesReadTheState, TestKeywordsAreReadTheWayTheyCouldBeApplied, TestRewiringIsHeld
  Scenario: what decides is the state a change leaves, not the call
    When a port forward from the internet is made disabled in one call and switched on in the next
    Or the internet port is added to the LAN bridge
    Or the router is rewired: a VLAN table, the ports or base of a device, or what an interface sits on
    Or a zone takes a device or a subnet, or a raw nftables fragment is set anywhere in the firewall
    Or the LAN zone is renamed so that it becomes an internet zone
    Then the call that completes it is held
    And a keyword is read trimmed and in any case, and a value nobody knows reads as the one that opens

  # bound to: TestUnreadableTypeHeld, TestParseShowReadsWhatUciPrints
  Scenario: what cannot be checked waits for the owner
    When the state a change would leave cannot be read
    Then the change is held, and the card says it could not be checked

  # bound to: TestCardIsWhatIsApplied, TestCardOverTheLimitIsRefused
  Scenario: the owner is shown exactly what would be applied
    When a change is held
    Then its card is written by the daemon from the record: a headline built from parsed values, and every changed key with its value before and after
    And a secret's value is shown as redacted, and what the agent chose is quoted after its key with anything unprintable escaped
    And a card over 3500 characters is refused, never cut short

  # bound to: TestApproveAppliesExactlyTheHeldBatch, TestApproveNeverOpensWindow, TestApproveNeedsPINAndCode
  # bound to: TestConfirmWithoutUnlockOnlyForApprovedChanges
  Scenario: the owner approves with a PIN and a code, and exactly that change runs
    When the owner's client approves the id and hash with the PIN and a current code, either alone being refused
    Then the held batch, and nothing else, is applied with a rollback of 300 seconds
    And the agent reads the outcome and can confirm the change without an unlock, which a change made in a window cannot
    And the window stays closed, so an ordinary change still needs an unlock

  # bound to: TestApproveRefusesAnotherHash, TestHashCoversEveryField
  Scenario: an approval names the exact change it approves
    When the hash sent with the approval is not the record's whole hash
    Then nothing is applied, and no try is counted
    And the hash changes with any field of the record: id, client, tool, input, card, fingerprint, times

  # bound to: TestAgentClientCannotApprove, TestAgentCannotUnlockItself
  Scenario: only the owner's client approves or unlocks
    When the agent's own client tries to approve, reject, list the cards, or open its own window
    Then it is refused, and no try is counted against the owner
    But the owner's client opens the agent's window with the agent's factor

  # bound to: TestApproveStepSpent
  Scenario: a code approves once
    When a code has been used to approve one change
    Then the same code does not approve another

  # bound to: TestApproveRefusedAfterDrift, TestApproveRefusedWhileAnApplyAwaitsConfirmation, TestApprovedApplyRechecksTheConfigs
  Scenario: when the router has changed since, the approval is refused and costs no try
    When a config the change was checked against has changed on disk, or another apply still waits for confirmation
    Then the approval is refused and nothing is applied
    And an edit made while the approval is checked is caught by the apply, before anything is staged

  # bound to: TestRejectIsOneTapAndCostsNoTry, TestLockRejectsEveryHeld
  Scenario: rejecting needs no code
    When the owner rejects a held change, or locks the client
    Then the change is rejected without a factor, and nothing is applied

  # bound to: TestHeldExpires, TestRestartDropsHeld
  Scenario: a held change does not wait forever
    When its time runs out, or the daemon restarts
    Then it can no longer be approved

  # bound to: TestOneOpenPerClient, TestProposalsPerHourAreLimited, TestProposalsPauseAfterRejections
  Scenario: proposals are limited, so a flood of cards cannot wear the owner down
    Then a client has at most one change waiting, at most six proposals an hour, and none for an hour after three rejections in a row

  # bound to: TestHoldPolicyHoldsWhatItGrants, TestApprovalRulesAddHoldsAndRefusals
  Scenario: the owner can hold or refuse more, never less
    When a policy says hold, or the approval section lists a hold or a refuse rule
    Then what it names is held, or refused, on top of the built-in rules

  # bound to: TestHumanOnlyRefusedWhateverTheGrant
  Scenario: what only a person may do is refused, whatever a grant says
    When the client runs a command, issues a WireGuard client, changes the agent's or its guard's configuration, or calls file, firmware, signal, service, uci or rpc-sys methods over ubus
    Then it is refused, even with the window open and a grant of everything

  # bound to: TestTier3RefusedUntilApprovalIsSetUp
  Scenario: with no way to approve, a high-impact change is refused, not run
    When approvals are switched off, or the PIN or the app is missing, or the owner's client is not paired
    Then a high-impact change is refused, and says what is missing

  # bound to: TestApprovalConfigIsChecked, TestHoldIsOnlyForWhatAnApprovalCanRun
  Scenario: an approval section that cannot work stops the configuration loading
    When a policy names an approval section that does not exist or belongs to another client, or a section's values are out of range
    Or a hold policy or rule names a tool an approval cannot run
    Then the configuration does not load

  # bound to: TestApproverListingIsNotAudited
  Scenario: the approver's poll writes nothing to flash
    When the owner's client lists the held changes every few seconds
    Then an answered listing writes no audit line, and a refused one does

  # bound to: TestCLIStatusJSONSaysActionsHeldForApproval
  Scenario: a caller can ask for the guarantee by name
    Then status --json reports actions_held_for_approval
