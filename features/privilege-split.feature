# Where these scenarios come from
#
# They restate the second step of gap G3.14 in the estate's gap list, paraphrased, and the decision
# recorded with the first step: `@decided 2026-11-08`: a light cage now, then straight after it a split
# of privileges, in which the part that listens and parses input holds no root, has only the ubus
# methods its tools need, and a narrow root helper runs a typed set of actions and checks the owner's
# approval itself where one is needed, never taking a flag on trust. The shape of the split and the
# reasons are in docs/privilege-split.md.
#
# The listener's tools run in the helper, so the ubus methods the listener needs are none, and it has
# no ubus ACL at all. What the listener cannot do on a running router (ubus call service set, a write
# to /etc/config, a read of /etc/shadow, an action off the helper's list) is shown by
# scripts/e2e-vlab.sh, TestJailVlab, which needs a vlab and so is not bound here.
#
# Each scenario is bound to a test below it, and scripts/gate-scenarios-bound.sh checks the binding
# both ways and runs the tests.

Feature: the part that meets the network holds no root

  Background:
    Given the daemon in two parts: the listener, which parses HTTP and MCP, and the helper, which holds root

  # bound to: TestTheListenerRunsAsItsOwnAccountUnderProcd, TestTheInitScriptMakesTheAccount
  Scenario: procd starts the listener as its own account
    When procd starts the daemon
    Then the listener runs as the account openwrt-mcp, which the init script makes when it is missing
    And the helper runs as root, and nothing else switches account

  # bound to: TestTheListenersCapabilityFileHoldsNothing, TestTheListenerRefusesRootAndAnyCapability
  Scenario: the listener holds no capability and does not run as root
    When the listener starts
    Then its capability file names all five lists and every one is empty
    And it refuses to listen as root, with an effective, permitted or ambient capability, or, as its own account, with a bounding set or without no_new_privs

  # bound to: TestTheListenersFilterStartsNoProgram
  Scenario: the listener starts no program
    When the listener, under its own filter, starts a program or calls execve itself
    Then the kernel ends the caller with SIGSYS, so it cannot run ubus, uci or a shell

  # bound to: TestTheHelperDoesNotListenOnTheNetwork
  Scenario: the helper does not listen on the network
    When the helper starts
    Then it opens no network socket, and only the listener's code listens, on loopback

  # bound to: TestHelperServesOnlyTheListenersUID, TestHelperRefusesAPeerWhoseUIDCannotBeRead, TestListenerSocketIsItsOwn, TestTheHelperSocketIsTheListenersOnly
  Scenario: the helper serves the listener and nobody else
    When something connects to the helper's socket
    Then it is served only if the kernel reports the listener's uid for it
    And the socket and its directory are open to the listener's group only

  # bound to: TestHelperTakesOnlyItsFourOperations, TestHelperRefusesAnActionOffTheList
  Scenario: the helper takes a typed set of actions and nothing else
    When the listener asks for an operation or a tool off the list, or gives a tool an input of another shape
    Then the helper refuses it before anything runs, and there is no operation that runs a string

  # bound to: TestHelperDecodesEveryFrameStrictly, TestHelperBoundsItsFrames, TestHelperIsBusyRatherThanUnbounded, TestTheListenerSendsNoOversizeToken
  Scenario: every frame is read strictly and within bounds
    When a frame has an unknown field, another version, data after it, a field over its bound, or a size over the bound
    Then the helper refuses it, cuts off a peer that stops halfway, and says it is busy rather than taking requests without a bound

  # bound to: TestHelperDecoderSurvivesASweepOfHostileFrames, TestHelperSurvivesHostileFramesOnItsSocket
  Scenario: hostile frames do not get through
    When frames are mutated from good ones, seed after seed, and sent to the decoder and to a running helper
    Then nothing panics, whatever is taken is one of the four operations or a tool on the list, the helper keeps serving and no program runs

  # bound to: TestHelperResolvesTheTokenItselfOnEveryCall
  Scenario: the helper finds the client itself, on every call
    When the listener forwards a call
    Then the helper resolves the bearer token itself, so no request names a client, a revoked token stops at its next call, and a missing one is audited

  # bound to: TestTheListenerRunsToolsOnlyThroughTheHelper, TestTheListenerWithoutItsHelperRunsNothing
  Scenario: every tool runs in the helper, behind the gate, as before
    When an agent calls a tool through the listener
    Then the helper's gate grants or refuses it per client and writes the audit log, exec and held changes included
    And the listener with no helper answers that nothing was run

  # bound to: TestCLIStatusJSONSaysTheListenerHoldsNoRoot
  Scenario: a caller can ask whether the listener holds no root
    When a package reads openwrt-mcp status --json
    Then the capabilities name listener_holds_no_root

  # bound to: TestSplitGateHasTeeth
  Scenario: the gate goes red on each way the split can be lost
    When a fault is planted in a copy of the tree
    Then the gate fails that check, and says it measured nothing when a file it reads is gone
