# Where these scenarios come from
#
# They are not derived from the code. They restate what was asked for on 2026-10-08 (relayed
# by the coordinating session, paraphrased here): everything a tool returns to the agent goes
# on to the agent's model provider, so the agent must be able to read the router's Wi-Fi and
# network configuration (to set up a guest network, for instance) without ever seeing a secret
# held there: Wi-Fi passphrases, WireGuard private and preshared keys, RADIUS secrets, PPPoE
# passwords and the like. It applies to every uci_get answer, for every client, always, with
# no way to switch it off through a tool, and narrowing or widening the read must not get
# around it. A client must be able to check that the binary does this before granting reads.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass.

Feature: uci_get shows the router's configuration but never its secrets

  Background:
    Given an MCP client with a policy that grants uci_get

  # bound to: TestUciGetNeverReturnsASecretWhateverTheReadShape, TestUciGetKeepsWhatIsNotSecret
  Scenario: the agent reads the Wi-Fi and network configuration without its secrets
    When it reads the wireless or the network config with uci_get
    Then every setting is there as uci printed it, the SSID, the encryption and a peer's public key included
    And the value of every secret option reads '<redacted>' instead

  # bound to: TestUciGetNeverReturnsASecretWhateverTheReadShape
  Scenario: narrowing or widening the read does not get around it
    When it reads the whole config, one section, or the secret option itself by name
    Then the secret is absent from every one of those answers

  # bound to: TestUciGetHasNoWayToTurnRedactionOff
  Scenario: there is no way to ask for the unredacted value
    Then uci_get takes a config, a section and an option, and no switch that turns redaction off
    And the redaction does not depend on which client is asking

  # bound to: TestIsSecretUCIOptionKnownNames, TestEverySecretRuleSaysWhereItComesFrom
  Scenario: the secret option names are an explicit, sourced list
    Then the Wi-Fi key and WEP keys, SAE and EAP passwords, RADIUS and DAE secrets, 802.11r key holders, WireGuard private and preshared keys, PPP, L2TP, 6in4 and VPN passwords, the SIM PIN, and the key files of uhttpd, dropbear and OpenVPN are secret
    And every rule names the config it comes from
    And removing the rule for any one of those names fails a test that names the option
    But the settings an agent needs, such as ssid, encryption, public_key and the rekey intervals, stay readable

  # bound to: TestRedactUCIOutput, TestRedactUCIOutputSweep
  Scenario: quoting, lists and values over several lines never let a secret through
    Given secret values holding quotes, backslashes, spaces, "=" signs, newlines, and lines that imitate other records
    And list options with several elements
    When uci prints them the way libuci does
    Then each secret collapses to the marker and every record after it is untouched
    And output that breaks uci's grammar can only make more disappear, never less

  # bound to: TestRedactUCIOutput
  Scenario: an option named like a secret is a secret in any config
    When an option called key or password sits in a config that does not usually hold one
    Then its value is redacted all the same, including a value that is only a key file's path

  # bound to: TestUciGetRedactsEvenWhenUciFails
  Scenario: a failed read is redacted too
    When uci prints part of a config and then fails
    Then the error the client receives carries uci's message but not the secret

  # bound to: TestUciGetRefusesASelectorThatLooksLikeAFlag
  Scenario: a selector cannot change how uci prints
    When the config, section or option begins with "-"
    Then the read is refused before uci runs

  # bound to: TestUciApplyRefusesTheRedactionMarkerAsAValue
  Scenario: the marker cannot be written back as a secret
    When the agent copies settings and sends '<redacted>' as a value to uci_apply
    Then the change is refused and the agent is told to ask the operator for the real value

  # bound to: TestUciApplyRefusalDoesNotShowAStagedSecret, TestWgNewClientErrorDoesNotShowTheServerKey
  Scenario: the other places that hand uci's output to the agent are redacted the same way
    When uci_apply refuses to start because someone else's edits are staged, and lists them
    Then a passphrase staged there is not in what the agent receives
    And when wg_new_client fails to read the WireGuard server's config, the server's private key is not in its error either

  # bound to: TestCLIStatusJSONSaysUciGetRedactsCredentials, TestVersionIsAValidPackageVersion
  Scenario: a client can check the guarantee before granting reads
    When it runs "openwrt-mcp status --json --audit 0"
    Then capabilities.uci_get_redacts_credentials is true
    And the version is one apk accepts, so the package that carries it builds
