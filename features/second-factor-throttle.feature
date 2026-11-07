# Where these scenarios come from
#
# They are not derived from the code. @decided 2026-11-07, the design for the throttle on guessing
# the second factor, paraphrased: five free tries, then waits of 15, 30 and 60 minutes, capped at
# one try an hour, with mfa_max_failures and mfa_lockout keeping their meaning as the first
# threshold and the first delay; the disk holds a failure count and the last accepted TOTP step per
# client and never a time, and the moment of the next try lives in memory on the monotonic clock, so
# after a restart or a reboot a client at or above the limit starts a fresh delay; a success
# resets, and so does a day of uptime with no counted failure; there is no overall cap, because a
# lockout does not outlive the attack, which is a deliberate departure from NIST SP 800-63B-4
# section 3.2.2; a full disk never turns into a refusal; only root resets a count, from the CLI; a
# flood of refusals cannot rotate the evidence out of the audit log; and `pin set` refuses the most
# common PINs.
#
# Every scenario below is bound by name to Go tests, in the comment line above it:
#   # bound to: TestName[, TestName...]
# scripts/gate-scenarios-bound.sh asserts both ways that no scenario is without a binding and
# that no binding names a test that does not exist, and it runs the named tests and requires
# each to pass.

Feature: guessing the second factor costs time that grows, and a restart forgives none of it

  Background:
    Given a client whose policy asks for a second factor
    And mfa_max_failures and mfa_lockout on that policy (5 and 15 minutes by default)

  # bound to: TestFiveFreeTriesThenFifteenThirtySixty, TestConfiguredLimitAndDelayKeepTheirMeaning
  Scenario: five wrong tries in a row, then a pause of fifteen minutes
    When a client fails to unlock mfa_max_failures times in a row
    Then those tries cost nothing and the last of them starts a wait of mfa_lockout
    And one failure fewer starts no wait

  # bound to: TestDelayScheme, TestFiveFreeTriesThenFifteenThirtySixty, TestAfterADelayOneTryIsAllowed
  Scenario: each further failure lengthens the wait, up to an hour
    Given a wait has run its course
    When the one try it allows fails
    Then the next wait is twice as long, up to an hour, or up to mfa_lockout where that is longer
    And the free tries do not come back with the end of a wait

  # bound to: TestARefusalInADelayWritesNothing, TestALockoutChecksNoFactor, TestLockoutBoundaries
  Scenario: a try during the wait checks nothing and counts nothing
    Given a client inside a wait
    When it tries, with the right factors or the wrong ones
    Then no factor is examined, so no TOTP code is spent
    And the count does not move, the wait does not move, and nothing is written to the disk

  # bound to: TestRefusalWordsAreThePluginsContract
  Scenario: the refusal keeps the words the owner's chat reads
    When a try is refused inside a wait
    Then the answer says unlocking is locked out until the moment the wall clock will show when the wait ends

  # bound to: TestRestartMidDelayStartsAFreshDelay, TestARestartBelowTheLimitChangesNothing
  # bound to: TestAClientWithNoApprovalSectionIsThrottledAcrossARestart
  Scenario: restarting the service forgives nothing
    Given a client at or above the limit
    When the daemon restarts in the middle of a wait
    Then the client starts a fresh wait of the length its count asks for
    And even the right factors are refused until that wait ends
    But a client below the limit keeps its count and meets no wait

  # bound to: TestRebootWithTheClockJumping
  Scenario: a reboot forgives nothing, wherever the clock comes up
    Given a client at or above the limit on a router with no battery
    When the router reboots with the clock far behind, or ntpd then steps it far ahead
    Then the client starts a fresh wait, measured in uptime
    And no reading of the wall clock shortens or lengthens it

  # bound to: TestAClockJumpInsideADelayChangesNothing, TestTheRefusalNamesWhenTheWallClockWillSayTheDelayEnds
  # bound to: TestTheWallClockCannotDecayTheCount
  Scenario: a jump of the clock changes no wait
    Given a client inside a wait
    When the wall clock jumps forward or backward by any amount
    Then the wait ends after the same uptime as before
    And only the time named in the refusal moves with the clock

  # bound to: TestDiskHoldsOnlyACountAndAStep, TestACodeCannotBeReplayedAfterARestart
  # bound to: TestAnApprovalsCodeStaysSpentAfterARestart, TestRestartKeepsTheStepSpentByActivate
  Scenario: the disk holds a count and a step, and never a time
    When tries are made
    Then /etc/openwrt-mcp/throttle holds, per client, the failure count and the last accepted TOTP step
    And it holds no clock reading of any kind
    And a code that was accepted stays spent across a restart

  # bound to: TestTheCountIsOnDiskBeforeTheFactorsAreChecked, TestATryThatDiesInTheCheckIsStillCounted
  # bound to: TestTheStoreSyncsWhatItWrites, TestAtomicWriteSyncsTheFileThenTheDirectory
  # bound to: TestAtomicWriteLeavesTheOldFileOnAFailure, TestAtomicWriteReportsADirectoryThatCannotBeSynced
  # bound to: TestAtomicWriteTightensAStaleSidecar, TestAtomicWriteMakesItsDirectory, TestAtomicWriteReportsWhatStopsIt
  Scenario: the count reaches the disk before any factor is looked at
    When a try is counted
    Then the new count is written, atomically and with the file and the directory synced, before the factors are checked
    And a process that dies inside the check has not given a free guess
    And a failed write leaves the old file whole

  # bound to: TestParallelAttemptsCannotSlipUnderTheLimit
  Scenario: tries made at the same moment cannot slip under the limit
    When many tries arrive at once
    Then they are taken one at a time, and exactly the free ones are checked

  # bound to: TestSuccessClearsTheCountOnTheDisk, TestSuccessAfterADelayGivesTheFreeTriesBack
  Scenario: a right try resets the count
    Given a client with failures on record
    When it unlocks with the right factors
    Then the count is cleared on the disk, and the free tries are back, across a restart too

  # bound to: TestADayOfUptimeResetsTheCount, TestOnlyACountedFailureRestartsTheDay, TestARestartStartsTheDayAgain
  # bound to: TestSweepCarriesTheDayToTheDisk, TestSweepForgetsAClientThisProcessNeverMet
  # bound to: TestSweepWritesNothingWhenNothingChanged
  Scenario: a day without a counted failure resets the count
    Given a client with failures on record
    When 24 hours of uptime pass with no counted failure
    Then the count is forgotten, in memory and on the disk
    But a refused try does not keep the count alive
    And a counted failure, or a restart, starts the day again

  # bound to: TestACorruptRecordReadsAsTheLimit, TestAnotherClientsWriteKeepsACorruptLine
  # bound to: TestARecordThatGoesBadRaisesAndNeverLowers, TestAJunkLineStaysThroughAWrite
  # bound to: TestACorruptRecordOnAFullDiskIsChargedOnce, TestAnUnreadableFileIsNotReplaced
  # bound to: TestAFileThatCannotBeReadIsNotReplaced, TestAClientNameThatCouldBreakTheFileKeepsItsCount
  Scenario: a corrupt record gives one pause, and neither a free pass nor a lockout
    When a client's record cannot be read
    Then it reads as the limit, so the client meets the first wait and no more
    And a record that goes bad never lowers what the daemon has counted
    And what the file holds for other clients stays as it is

  # bound to: TestAMissingFileReadsAsZero
  Scenario: a missing file is a new install
    Given no throttle file
    Then every client starts from zero

  # bound to: TestAFullDiskKeepsWorkingFromMemory, TestAFullDiskCatchesUpWhenItCanWriteAgain
  # bound to: TestAReadOnlyDirectoryDoesNotLockTheOwnerOut, TestASpentStepCatchesUpAfterAFullDisk
  # bound to: TestStatusShowsThrottlePersistedFalseFromTheDaemon, TestHealthSaysNothingWhileTheThrottleIsSaved
  # bound to: TestProbeDaemonReportsNothingForAStoppedDaemon, TestActionListSaysWhenTheCountIsNotOnTheDisk
  Scenario: a full disk does not lock the owner out
    When the overlay is full and the count cannot be written
    Then the daemon goes on counting in memory, and the right factors still unlock
    And status shows throttle_persisted false
    And the count reaches the disk as soon as a write succeeds

  # bound to: TestTheAgentTokenSpendsNoTries, TestAClientNamingAnotherIsFoldedToo
  Scenario: the agent's token spends none of the owner's tries
    Given a client with an approval section
    When its own token calls mfa_unlock, any number of times
    Then it is refused uncounted, and nothing is written to the throttle file

  # bound to: TestActionListTellsTheOwnerOfForeignTries, TestTheAgentsOwnViewCarriesNoThrottle
  # bound to: TestStatusShowsTheFailuresOnRecord, TestCLIStatusJSONSaysTheThrottleIsPersisted
  Scenario: the owner's client can tell the owner about foreign tries
    Given failed or refused tries on a client
    When the owner's client lists the held changes
    Then the answer carries each client's failures, the limit, when the wait ends, how many were refused and whether the count is on the disk
    And status reports the count on record to any process, and the capability says the count outlives a restart
    But the agent's own view carries none of it

  # bound to: TestResetFromTheCLIReachesARunningDaemon, TestAResetIsNotUndoneByTheNextWrite
  # bound to: TestResetKeepsTheSpentStep, TestResetHealsACorruptRecord, TestResetSaysWhenThereIsNothingToReset
  # bound to: TestResetReportsADiskThatWillNotTakeIt, TestCLIMFAReset, TestMFAStatusNamesTheWayOut
  Scenario: the owner clears a wait from the router
    When root runs "openwrt-mcp mfa reset <client>"
    Then the count is cleared at once, on a running daemon too, with no restart
    And the last accepted step stays, so a spent code stays spent
    And another client's count is not touched

  # bound to: TestNoMCPToolResetsTheThrottle, TestLockLeavesTheCountOnTheDisk, TestLockDoesNotForgiveFailures
  Scenario: no MCP client can clear a count
    When any client calls any tool, mfa_lock and the owner's own tools included
    Then the count stays where it was

  # bound to: TestRotatingAPINWithTheDaemonStoppedClearsTheRecord, TestRotatingATOTPSecretWithTheDaemonStoppedClearsTheRecord
  # bound to: TestRotatingAPINClosesTheWindowAndLiftsTheLockout, TestRotatingTheTOTPSecretLiftsALockout
  Scenario: a new PIN or a new secret clears the count
    When the owner sets a new PIN or enrols a new secret, with the daemon running or stopped
    Then what the old credentials cost is gone

  # bound to: TestABadTokenFloodIsOneLineAndASummary, TestAFloodCannotRotateTheEvidenceOut
  # bound to: TestEachPeriodOfAFloodCostsTwoLines, TestAFloodOfDifferentTokensIsOneRun, TestOneBadTokenNeedsNoSummary
  Scenario: a flood of bad tokens cannot rotate the evidence out of the log
    When any process sends bad bearer tokens as fast as it can
    Then the first is written with where it came from, the rest are counted, and one summary line follows
    And the log does not move on, so what was in it stays in it

  # bound to: TestRefusalsInADelayAreOneLineAndASummary, TestTheSummaryComesBeforeTheNextTry
  # bound to: TestEachDelayHasItsOwnFirstLine, TestAResetInsideADelayStartsAnotherRun
  # bound to: TestAnApprovalRefusedInADelayIsFolded, TestTheFoldHoldsNoSecret
  Scenario: refusals inside a wait are one line and a summary
    Given a client inside a wait
    When it keeps trying, with mfa_unlock or action_approve
    Then the first refusal is written, the rest are counted, and one summary line follows when the wait ends
    And every counted failure still has a line of its own

  # bound to: TestATermWritesTheSummaryOfAnOpenRun, TestAFlushLeavesNothingOnlyInMemory
  # bound to: TestTheDaemonsMinuteSweepsAndItsStopFlushes
  Scenario: stopping the daemon loses no count of refusals
    Given refusals counted and not yet summed up
    When the daemon is told to stop
    Then the summary is written first

  # bound to: TestPinSetRefusesTheMostCommonPINs, TestPinSetAcceptsAPINOffTheList
  # bound to: TestAWeakPINAlreadyOnFileKeepsWorking, TestCommonPINsAreAllValidPINs
  Scenario: pin set refuses the most common PINs
    When the owner sets a PIN from a short built-in list of the most common ones
    Then it is refused with one clear message that does not repeat it, and nothing is written
    But any other PIN is taken, and a PIN already on file keeps working
