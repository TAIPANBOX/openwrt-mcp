# Where these scenarios come from
#
# @decided 2026-10-17: a WireGuard client's private key is key material, and it must not be
# handed to any program as an argument, because every process on the router can read another
# process's arguments. It reaches uci on standard input instead. Paraphrased here, not derived
# from the code; the finding is F-019 of the security review of 2026-10-17.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]

Feature: a WireGuard client's private key never goes on a command line

  Background:
    Given an MCP client granted wg_new_client

  # bound to: TestWgNewClientKeepsThePrivateKeyOutOfEveryCommandLine
  Scenario: the private key reaches uci on standard input and never in an argument list
    When the client issues a WireGuard client
    Then no command the daemon runs has the private key among its arguments
    And uci receives the private key on its standard input

  # bound to: TestWgNewClientRefusesAValueThatCannotBeQuotedForUci
  Scenario: a name that would break the staged batch is refused before uci writes anything
    When the client issues a client whose name contains a quote
    Then the call is refused
    And uci is not asked to write
