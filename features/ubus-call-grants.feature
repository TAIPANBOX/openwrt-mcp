# Where these scenarios come from
#
# @decided 2026-10-17: a grant for ubus_call covers an object and a method pair. A grant does not
# cover a neighbouring object because its name shares a prefix, and a name that is not a plain
# ubus object or method is refused under every grant. Paraphrased here, not derived from the code;
# the finding is F-019 of the security review of 2026-10-17.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]

Feature: ubus_call covers the object and method pairs a grant names, and nothing else

  Background:
    Given an MCP client whose policy grants ubus_call

  # bound to: TestUbusCallGrantsNameAnObjectAndAMethod
  Scenario: a grant covers the pair it names and no other object or method
    Given the grant is network.*
    When the client calls method reload on object network
    Then the call runs
    When the client calls method status on object network.interface.lan
    Or it calls a method whose name contains a dot on object network
    Then the call is refused

  # bound to: TestUbusCallRefusesWhatIsNotAPlainObjectAndMethod
  Scenario: an object or method that is not a plain ubus name is refused under any grant
    Given the grant is the wildcard that covers every pair
    When the client names an object that begins with a dash, an object with a space, or a method with a dot or a slash
    Then each call is refused before ubus runs
    But a plain object and method still run under the same grant

  # bound to: TestUbusCallWildcardMethodStaysOnItsObject
  Scenario: a wildcard method covers the methods of one object only
    Given the grant is iwinfo.*
    When the client calls any method on object iwinfo
    Then the call runs
    When the client calls a method on object iwinfo.devices
    Then the call is refused
