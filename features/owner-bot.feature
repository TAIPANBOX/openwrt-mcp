# Where these scenarios come from
#
# They restate the decision recorded in docs/approval-path.md, paraphrased: `@decided 2026-11-08`: the
# root helper sends the card of a held change and reads the owner's answer itself, through a bot of the
# router's own; TLS ends in the helper and the listener only carries encrypted bytes, so the helper
# still opens no IP socket; the Hermes gateway and the listener leave the approval path; the owner
# approves as before, one tap and one message with the PIN and the code, in the router's own chat; once
# per router the owner makes a bot, gives the router its token and presses Start; the owner's chat is
# bound by a one-time code from the router, and until then the bot listens to nobody; a router with no
# bot keeps today's path. The details are in that page's last section.
#
# What a broken listener can do on a running router (the helper's sockets, the pipe's bytes, the whole
# flow as procd starts both parts) is shown by scripts/e2e-vlab.sh, TestOwnBotVlab, which needs a vlab
# and so is not bound here.
#
# Each scenario is bound to a test below it, and scripts/gate-scenarios-bound.sh checks the binding
# both ways and runs the tests.

Feature: the owner approves past the listener, through the router's own bot

  Background:
    Given a client whose high-impact changes are held for the owner
    And the router's own bot, its token set on the router

  # bound to: TestAHostileListenerCannotMoveTheOwnersFactor
  Scenario: a broken listener cannot move the owner's factor
    Given a listener run by an attacker, which holds every token that passes it and serves the pipe to Telegram
    And it proposes a change of its own beside the agent's
    When the owner approves the agent's change and then opens the agent's window, in the router's chat
    Then the change the owner approved runs, and the attacker's never does
    And no PIN, no code, no card and no Bot API request passes the listener in clear

  # bound to: TestWithoutABotTheListenerStillCarriesTheFactor
  Scenario: a router with no bot keeps today's path, and its boundary
    Given no bot is bound on the router
    When the owner approves through the owner's MCP client
    Then the approval passes the listener as it always did, which is the line the docs keep for such a router

  # bound to: TestTheOwnersChatIsBoundByTheOneTimeCode
  Scenario: the owner's chat is bound by the router's one-time code and nothing else
    When a stranger, a wrong code or the right code in a group writes to the bot
    Then the bot answers nobody and binds nothing
    When the owner presses Start on the link with the router's code
    Then the owner's private chat is bound, the code is spent, and another chat that sends it takes nothing over

  # bound to: TestTheOwnerBotCommandLine
  Scenario: the token is set on the router, and a new bot is bound again
    When the token is given on standard input
    Then only a token's shape is taken, the same token again changes nothing, and a new one drops the bound chat
    And a code needs a token, and clearing the bot gives the approval back to the owner's client

  # bound to: TestABindingCodeRunsOut, TestABindingCodeEndsOnTimeAcrossARestart
  Scenario: a binding code runs out
    Given a binding code the router made, its end written in its file
    When 30 minutes of the helper's own clock pass from when it first saw the code
    Then the code is removed and binds nothing, and a fresh code binds
    When the helper starts again after the end written in the file
    Then the code is removed as the helper starts and binds nothing, however new the helper's own clock is

  # bound to: TestACardTelegramRefusesDoesNotHoldBackTheNext
  Scenario: a card Telegram refuses does not hold back the next
    When Telegram does not take one card
    Then that card waits with a delay of its own while the cards after it go out, and it goes out once Telegram takes it

  # bound to: TestACardTooLongForOneMessageIsCutAndNotApproved, TestAHeldCardMustFitOneTelegramMessage
  Scenario: a card is never cut for the owner to approve
    When a change's card would not fit one Telegram message as Telegram counts it
    Then the change is refused when it is held, as an over-long card always was
    And a card that reaches the bot too long anyway goes out cut, says so, offers only Reject, and the cards after it still go out

  # bound to: TestTheCardIsTheRecordsOwnAndApprovesItsRecordOnly
  Scenario: the card is the helper's own, and one tap and one message approve it
    When a change is held
    Then the owner's chat gets the record's card byte for byte, with Approve and Reject
    When the owner taps Approve and sends the PIN and the code
    Then that change runs and no other, and the card says it was applied

  # bound to: TestRejectAndWithdrawCloseTheirCards
  Scenario: Reject is one tap, and a withdrawal closes the card
    When the owner taps Reject on a card, and the agent withdraws another change
    Then the first is rejected with no factor asked, and both cards say how they ended

  # bound to: TestOnlyTheBoundChatsTapAndFactorCount
  Scenario: only the bound chat's tap and factor count
    When someone else taps the owner's card, or taps in a group, or sends a PIN and a code, even while the owner's prompt is open
    Then nothing opens, nothing runs and no try is counted
    And the owner's own tap and factor then work

  # bound to: TestATapCountsOnlyOnTheCardOfItsRecord
  Scenario: a tap counts only on the card the helper sent for that record
    When another record's button, or a forged hash, arrives on a card
    Then no prompt opens, and a factor sent then tries nothing

  # bound to: TestTheFactorIsDeletedBeforeItIsRead, TestTheSourceDeletesAFactorBeforeItReadsIt
  Scenario: the factor's message is deleted before it is read
    When the owner sends the PIN and the code after Approve
    Then nothing is tried until the message has been deleted from the chat

  # bound to: TestAFactorWithNoPromptOrAfterItClosedCountsNothing
  Scenario: a factor with no prompt, or after the prompt closed, counts nothing
    When the owner sends a PIN and a code with no prompt open, or more than 180 seconds after Approve
    Then the message is deleted, nothing is tried, and the same PIN and code still approve afterwards

  # bound to: TestACodeIsNotTakenTwiceFromTheChat
  Scenario: a code approves one change
    When the owner sends a code that approved one change as the approval of another
    Then the second is refused and does not run

  # bound to: TestAnExpiredCardCannotBeApproved
  Scenario: an expired card cannot be approved
    When a held change expires, even with the owner's prompt open
    Then its card says so, a tap on it opens nothing, and a factor tries nothing

  # bound to: TestWithTheBotBoundNoMCPClientDecides, TestTheApproversToolsAreRefusedFirstWithTheBot
  Scenario: with the bot bound, no MCP client decides for an approval section
    Given the owner's MCP client, which listed the held changes before the bot was bound
    When the owner's chat is bound
    Then that client's token is revoked
    And listing, approving, rejecting, unlocking and locking for an approval section over MCP are refused before anything is looked up, counting nothing

  # bound to: TestUnlockAndLockFromTheRoutersChat, TestAnUnlockOfTheWrongShapeTriesNothing
  Scenario: the window is opened and closed from the router's chat
    When the owner sends /unlock with the PIN in the router's chat
    Then the agent's window opens and the message is deleted, while a stranger's /unlock does nothing
    When the owner sends /lock
    Then the window closes and the held changes are rejected
    And an /unlock of the wrong shape, or for no such client, tries nothing, while a wrong PIN counts as a try

  # bound to: TestWhatArrivedWhileTheHelperWasNotReadingIsNotUsed, TestTheFirstMessageAfterBindingIsRead
  Scenario: what reached the bot while the helper was not reading is not used
    When the helper starts with a PIN and an /unlock waiting in the chat
    Then both are deleted, the owner is told, nothing is tried, and the card of what waits goes out
    And a message sent once the helper reads, the owner's first right after binding among them, is read as it is

  # bound to: TestAListenerThatAltersTheBytesBreaksTheConnection
  Scenario: a listener that alters the bytes breaks the connection
    When the listener alters what it carries from Telegram
    Then TLS refuses it and no update is read, and the same tap goes through once the bytes are left alone

  # bound to: TestAListenerThatAnswersInTelegramsPlaceIsRefused, TestTheBotSpeaksToTelegramOnly
  Scenario: a listener that answers in Telegram's place is refused
    When the listener answers with a certificate the router does not trust, or a trusted one for another name
    Then the impostor is never asked anything, and the owner's chat is bound through Telegram itself

  # bound to: TestThePipeServesTheHelperOnly, TestThePipeIsServedByTheListenerForTheHelperOnly, TestTheInitScriptMakesThePipesDirectory
  Scenario: the pipe serves the helper and nobody else
    When something that is not the helper connects to the listener's pipe
    Then the pipe dials nothing for it, and the pipe's directory is the listener's own

  # bound to: TestTheHelperRefusesAPipeThatIsNotTheListeners, TestTheOnlyIPSocketsAreTheListenersAndTheStatusProbe
  Scenario: the helper speaks only through the listener's pipe, and opens no IP socket
    When the pipe's other end is not the listener's uid
    Then the helper sends it nothing, not even a TLS hello
    And the binary's only IP sockets are the listener's and the status probe's

  # bound to: TestTheBotsTokenIsInNoErrorAndNoFile, TestTheClientsErrorsHoldNoToken, TestTheSourceSaysAFailureByItsWordOnly
  Scenario: the bot's token is in no error and no file but its own
    When the transport fails with the URL, which holds the token, in its error
    Then neither the client's error, the log, the status nor the seen file holds the token

  # bound to: TestTheBotsFailureIsOneWordOfAFixedSet
  Scenario: a failure of the bot is told by one word of a fixed set
    When Telegram does not know the token, a certificate is not api.telegram.org's, or the pipe is not the listener's
    Then the seen file, the status and the log say token_rejected, tls or pipe, and nothing of the error's text
    And a seen file holding anything else is read as other, so its text never reaches the status

  # bound to: TestTelegramAnswersAreReadWithinTheirBounds, TestTelegramDecoderSurvivesASweepOfHostileAnswers, TestAFactorIsReadAsTheOwnerTypesIt
  Scenario: what Telegram sends is read within its bounds
    When an answer is not the Bot API's, holds too many updates, or an update out of its bounds
    Then nothing in it is acted on, and a factor is read only in the shape the owner types it

  # bound to: TestStatusSaysWhereHeldChangesAreApproved, TestTwoTokenWritersDoNotUndoEachOther
  Scenario: status says where held changes are approved
    When status runs before and after the owner's chat is bound
    Then it names the guarantee, and says the owner's client approves before and the router's chat after
    And the token file's writers do not undo each other
