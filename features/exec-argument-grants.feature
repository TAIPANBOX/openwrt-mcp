# Where these scenarios come from
#
# @decided 2026-10-17: a grant for exec names the programs it may run and, for each one, the
# argument lists it may run them with. A program granted without an argument list runs with no
# arguments. Paraphrased here, not derived from the code; the finding is F-019 of the security
# review of 2026-10-17, and CLAUDE.md states the invariant.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests.

Feature: exec runs only the argument lists its grant names

  Background:
    Given an MCP client whose policy grants exec

  # bound to: TestExecProgramGrantedWithoutArgumentsRunsWithNone
  Scenario: a program granted with no argument list runs with no arguments
    When the client asks for the program with an argument
    Then the call is refused and the program never starts
    But the program run with no arguments still works

  # bound to: TestExecArgumentListAllowsExactlyWhatItNames
  Scenario: an argument list allows exactly the arguments it names
    Given the grant names one program with a value flag, and one program with a fixed flag
    When the client runs a form the list names
    Then it runs
    When the client runs a form that differs by one argument, drops one, or adds one
    Then the call is refused

  # bound to: TestExecArgumentPatternMatchesOneArgumentWithoutReachingUp
  Scenario: a wildcard matches inside one argument and never climbs a directory tree
    Given the grant names a directory with a wildcard in the last part
    When the client names a file inside that directory
    Then it runs
    When the client names a path that climbs out with dot-dot, or one that goes deeper
    Then the call is refused

  # bound to: TestExecArgvNamesOnlyGrantedProgramsAndExec
  Scenario: an argument list for a program the policy does not grant is refused at load
    Given a policy whose argument list names a program its scopes do not grant
    Or a policy whose argument list sits in a policy that does not grant exec
    Then the configuration does not load

  # bound to: TestExecArgumentListBelongsToItsOwnPolicy
  Scenario: one policy's argument list does not widen another policy's grant
    Given two policies for one client, one granting the program with no arguments and one with an argument list
    When the client runs a form only the second names
    Then it runs through the second policy alone

  # bound to: TestExecRefusedArgumentsAreAuditedAsDenied
  Scenario: a refused argument list is audited as a refusal
    When the client runs a program with arguments outside its list
    Then the audit log records the call as DENIED
