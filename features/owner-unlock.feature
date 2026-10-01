# Where these scenarios come from
#
# They are not derived from the code. They restate what was asked for on 2026-10-01 (relayed
# by the coordinating session, paraphrased here): the owner of a router decides who may use
# the powerful tools, by unlocking them with a PIN, a TOTP code, or both, as policy chooses;
# a stolen bearer token alone must not be enough; guessing must be throttled; secrets must
# never be written down in clear; and an unconfirmed config change must be undone even after
# a reboot.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass. scripts/gate-scenarios-bound-teeth.sh plants each of those faults and requires
# the gate to go red.

Feature: the owner unlocks the powerful tools with a PIN and/or a TOTP code

  Background:
    Given an MCP client authenticated by its bearer token
    And a policy that gates some of its tools behind mfa_tools

  # bound to: TestRunPINSetReadsStdinAndPrintsNoSecret, TestRunPINRefusesAPINOnTheCommandLine
  # bound to: TestRunPINSetRefusesBadInputWithAClearMessage, TestValidatePIN, TestCLIPinSetClearAndStatus
  Scenario: the owner sets a PIN by piping it in, never on the command line
    When the owner runs "openwrt-mcp pin set <client>" with one line on stdin
    Then a PIN of exactly 4 to 8 ASCII digits is stored
    And anything else (3 digits, 9 digits, letters, spaces, other scripts' digits, nothing) is refused with a message that does not repeat it
    And a PIN given as a command-line argument is refused

  # bound to: TestPINSetStoresOnlyASaltedHash, TestPINSetUsesAFreshSaltEachTime
  # bound to: TestPINFilePermissions, TestPINSetWritesBySidecarRename
  Scenario: only a salted PBKDF2 hash of the PIN is ever written
    When a PIN is set
    Then the pin file holds "<client> pbkdf2-sha256$<iterations>$<salt>$<hash>" with a 16-byte random salt
    And the plaintext PIN is nowhere on disk
    And the file is mode 0600 in a 0700 directory, replaced by sidecar and rename

  # bound to: TestPINHotReload, TestRotatingAPINClosesTheWindowAndLiftsTheLockout
  # bound to: TestPINFingerprintsChangeWithTheRecord
  Scenario: a PIN changed from the CLI takes effect on the running daemon
    Given the daemon is running
    When the owner sets a new PIN from another process
    Then the old PIN stops working without a restart
    And any window opened under the old PIN is closed
    And a lockout caused by someone else's guesses is lifted

  # bound to: TestPINClear, TestRunPINClearAndUsage, TestClearingAPINClosesTheWindow
  Scenario: the owner clears a PIN
    When the owner runs "openwrt-mcp pin clear <client>"
    Then the PIN no longer unlocks anything
    And the open window is closed

  # bound to: TestPolicyFactorOptionsParse, TestAttemptTOTPFactorIsUnchanged, TestPolicyMFADefaultsToOff
  Scenario: with no mfa_factor a policy behaves exactly as it did before
    Given a policy without mfa_factor
    Then the factor is totp, with the same messages, window and replay protection as before
    And a PIN, even a right one, cannot stand in for the code

  # bound to: TestPolicyRejectsBadFactorOptions
  Scenario: a bad factor or limit stops the config loading
    When a policy says mfa_factor is anything but totp, pin or pin+totp, or mfa_max_failures is not a whole number of at least 1, or mfa_lockout is not a positive duration
    Then the config fails to load with an error naming the option

  # bound to: TestAttemptPINFactor, TestUnlockAndLockEndToEnd, TestAttemptPINFactorWithNoPINSetFailsLikeAWrongPIN
  Scenario: a pin policy is unlocked by the PIN alone
    Given a policy with mfa_factor pin
    When mfa_unlock is called with the right pin
    Then the gated tools open for the policy's window
    And a TOTP code alone does not open them

  # bound to: TestAttemptPINPlusTOTPNeedsBothAndSaysNothingAboutWhich, TestPINPlusTOTPReplayIsGeneric
  # bound to: TestToolRefusalsDoNotNameTheWrongFactor
  Scenario: a pin+totp policy needs both, and a refusal never says which was wrong
    Given a policy with mfa_factor pin+totp
    When either factor is wrong or missing
    Then nothing opens
    And the refusal reads the same whichever factor failed, a replayed code included

  # bound to: TestAWrongPINDoesNotBurnTheTOTPCounter
  Scenario: a wrong PIN does not spend the owner's TOTP code
    Given a policy with mfa_factor pin+totp
    When someone submits a wrong PIN with the owner's current code
    Then the PIN is checked first and fails
    And the owner can still use that same code with the right PIN

  # bound to: TestLockoutBoundaries, TestToolUnlockLocksOutAfterTheConfiguredFailures
  # bound to: TestWindowExpiresExactlyAtItsEnd, TestLockoutIsPerClient
  Scenario: too many failed unlocks lock unlocking for a while
    Given mfa_max_failures and mfa_lockout on the policy (5 and 15 minutes by default)
    When a client fails to unlock that many times in a row
    Then every further attempt is refused until the lockout ends, even with the right factors
    And the refusal names the time the lockout ends
    And one failure fewer than the limit locks nothing, and a success resets the count
    And another client is not affected

  # bound to: TestALockoutChecksNoFactor, TestAfterALockoutTheCountStartsAgain
  Scenario: during a lockout nothing is checked and nothing is counted
    Given a client that is locked out
    When it keeps trying
    Then no factor is examined, so no TOTP code is consumed
    And the lockout is neither extended nor shortened
    And when it ends the count starts again from zero

  # bound to: TestUnlockAndLockEndToEnd, TestMFALockIsUngatedAndHonestWhenNothingWasOpen
  # bound to: TestMFALockOnlyClosesTheCallersOwnWindow, TestLockClosesTheWindowAndSaysWhetherItWasOpen
  Scenario: mfa_lock closes the window at once
    Given a client whose window is open
    When it calls mfa_lock
    Then the gated tools ask for the factors again and it is told the window is closed
    And the call needs no grant, and touches no other client's window

  # bound to: TestAuditNeverHoldsAPINOrACode, TestRedactionCoversCodeAndPinByExactKeyOnly
  Scenario: the PIN and the code never reach the audit log
    When unlock attempts, right and wrong, are made
    Then each is recorded with the code and pin arguments redacted
    And neither the PIN nor any code appears anywhere in audit.jsonl

  # bound to: TestRollbackSurvivesTheMachinesTmpBeingWiped, TestSnapshotIsKeptUnderTheStateDirNotInTmp
  # bound to: TestRollbackDirIsTightenedIfItAlreadyExistsLoose, TestRecoveryHonoursARecordPointingAtTheOldTmpLocation
  Scenario: an unconfirmed uci_apply is rolled back even after a reboot
    Given uci_apply armed a rollback and the router then restarted
    And the machine's /tmp came back empty
    When the daemon starts
    Then the old configuration is restored from the snapshot kept under the state directory
    And the snapshot is readable by root only

  # bound to: TestConfirmDeletesTheSnapshotAndKeepsTheChange, TestTimerRollbackRestoresAndDeletesTheSnapshot
  # bound to: TestFailedRollbackKeepsTheSnapshotForManualRecovery
  Scenario: the snapshot is deleted once it is no longer needed
    When the change is confirmed, or rolled back
    Then the snapshot is removed
    But a rollback that fails keeps it, as the only copy of the old configuration

  # bound to: TestEnrolWithoutFlagsPrintsExactlyWhatItAlwaysDid
  Scenario: enrolling without flags is unchanged
    When the owner runs "openwrt-mcp mfa enrol <client>" with no flags
    Then the output is exactly what it was before, and the secret is live at once

  # bound to: TestEnrolQRPrintsTheCodeOfTheVeryURIItShows
  Scenario: --qr draws the QR of the same URI in the terminal
    When the owner adds --qr
    Then a half-block QR of the printed otpauth URI follows it, beside the text secret

  # bound to: TestEnrolJSONIsOneObjectAWebPageCanUse
  Scenario: --json gives a web page everything it needs and nothing else
    When the owner adds --json
    Then stdout is one JSON object with client, uri, secret and qr_png_base64
    And the PNG decodes to a square image

  # bound to: TestEnrolPendingStoresApartAndUnlocksNothing, TestEnrolPendingLeavesAnActiveSecretInForce
  # bound to: TestActivateMovesThePendingSecretOnlyForAValidCode, TestActivateReplacesAnExistingSecretAndClosesItsWindow
  # bound to: TestActivateWithNothingPendingSaysHowToStart, TestActivatingTheLastPendingSecretRemovesTheFile
  # bound to: TestCLIMFAEnrolPendingJSONThenActivate
  Scenario: --pending enrolment is not live until a code proves the scan
    When the owner enrols with --pending
    Then the secret is kept in mfa.pending and unlocks nothing, and any secret already in force keeps working
    And "openwrt-mcp mfa activate <client> <code>" moves it into force only if the code is valid now
    And a wrong, expired or missing code refuses and keeps it pending

  # bound to: TestStatusReportsEachClientsUnlockFactors, TestMFAReportFromTheDaemonShowsLiveState
  # bound to: TestStatusTextSaysWhichFactorsAreMissing, TestMFAStatusWarnsWhereAGateCannotBeOpened
  Scenario: status shows each client's unlock state
    When the owner runs "openwrt-mcp status --json"
    Then every paired client has an mfa object with factor, totp_enrolled, totp_pending, pin_set, unlocked_until, locked_out_until and failures
    And the runtime fields are marked as not live when status runs as a separate process, because that state lives only in the daemon's memory

  # bound to: TestStatusNeverContainsASecretAHashOrASalt
  Scenario: status never carries a secret
    When status is printed, as JSON or as text
    Then no TOTP secret, PIN, salt or hash appears in it

  # bound to: TestUnlockingOneClientDoesNotUnlockAnother
  Scenario: unlocking one client does not unlock another
    Given two clients with the same PIN
    When one of them unlocks
    Then the other still needs to unlock for itself

  # bound to: TestAnUnauthorisedCallerLearnsNothingAboutWhichToolsAreGated
  Scenario: a client with no grant learns nothing about which tools are gated
    Given a client with a valid token but no policy
    When it calls a tool another client has gated
    Then the refusal is the ordinary denial and does not mention a second factor

  # bound to: TestPINWritesReportADiskFailureInsteadOfPretending, TestEnrolReportsADiskFailure
  # bound to: TestLoadMFAErrorsAreNotSilent, TestMFAReloadKeepsSecretsWhenTheFileBecomesUnreadable
  # bound to: TestNewServerFailsOnABrokenConfigOrStateFile, TestPINReloadKeepsWorkingPINsWhenTheFileIsUnreadable
  Scenario: a state file that cannot be written or read is never treated as success or as empty
    When saving a PIN or a secret fails, the command reports the failure
    And when a factor's file is unreadable at startup, the daemon refuses to start
    But a file that becomes unreadable while running does not wipe the factors already loaded

  # bound to: TestADaemonRefusesTheCodeThatActivatedASecret, TestASpentStepOnlyCountsForTheSecretItWasSpentOn
  Scenario: the code typed to activate a secret is spent for the running daemon too
    Given the owner activates a new secret with "openwrt-mcp mfa activate", outside the daemon
    When the same code is sent to mfa_unlock within its acceptance span
    Then the daemon refuses it, and the next code works
    But a step spent on an older secret never blocks a newer one

  # bound to: TestAClientsGatingPoliciesMustAgreeOnHowToUnlock
  Scenario: one client's gating policies agree on how it unlocks
    Given two enabled policies for one client that both gate tools
    When they differ in mfa_factor, mfa_window, mfa_max_failures or mfa_lockout
    Then the config does not load, and the error names the client and what differs
    But a policy that gates nothing may say anything
