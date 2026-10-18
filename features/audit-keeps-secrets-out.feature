# Where these scenarios come from
#
# @decided 2026-10-17: the audit log is the record an operator reads, so it must not be a second
# copy of the secrets the router holds. A value is redacted by the name of the option it sets, by
# the name of its section, or by the name of the argument it travels in. Paraphrased here, not
# derived from the code; the finding is F-019 of the security review of 2026-10-17.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]

Feature: the audit log never holds the value of a secret

  Background:
    Given an MCP client whose every call is written to the audit log

  # bound to: TestAuditRedactsTheValueOfASecretUCIOptionInUciApply
  Scenario: a Wi-Fi key set through uci_apply is not written to the audit log
    When the client sets option key on a wireless section
    Then the audit line holds the redaction marker where the value was
    And the option name is still there

  # bound to: TestAuditRedactsTheValueWhenTheSectionMarksACredential
  Scenario: a value is redacted when its section marks a credential, whatever its option is named
    When the client sets an ordinary option in a section whose name marks a password
    Then the value is not in the audit log

  # bound to: TestAuditRedactsTheWireguardPrivateKeyValue
  Scenario: a WireGuard private key is redacted and a public key is not
    When the client sets a private_key option and then a public_key option
    Then the private key is not in the audit log
    And the public key is

  # bound to: TestAuditRedactsSecretArgvElementsAndFlagValues
  Scenario: an exec argument that carries a secret is redacted in the log and in its summary
    Given the grant names uci and wg with arguments that carry a secret
    When the client runs them with a key=value argument, and with a flag followed by its value
    Then neither secret appears in the audit line or in its summary

  # bound to: TestAuditRedactsUCIRecordsInErrors
  Scenario: a uci record quoted in an error is redacted in the audit line too
    When a uci step fails and its error repeats a secret option's record
    Then the audit line holds the redaction marker where the value was

  # bound to: TestAuditKeepsOrdinaryValues
  Scenario: ordinary settings stay readable in the log
    When the client sets an ordinary option such as an SSID
    Then its value is in the audit log as it was
