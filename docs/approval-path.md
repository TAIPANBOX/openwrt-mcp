# The owner's approval path, past the listener

The ways the owner's card and the owner's answer can reach the helper without passing through the
listener, what each costs the owner, what each changes here and in hermes-openwrt, and what each
leaves; then the options side by side, the one chosen, and what was settled while it was built.

`@decided 2026-11-08`: the card a held change is approved by, and the owner's answer to it (the tap,
the PIN and the code), reach the helper by a path the listener does not see, and the owner types
nothing more than today.

`@decided 2026-11-08`: A, carried as A2. The root helper sends the card of a held change and reads the
owner's answer itself, through a bot of the router's own; TLS ends in the helper and the listener only
carries encrypted bytes, so invariant 12 stays as written; the Hermes gateway and the listener leave
the approval path; the owner approves as before, one tap and one message with the PIN and the code, in
the router's own chat; once per router the owner makes a bot with BotFather, pastes its token in LuCI
and presses Start. This deliberately replaces the earlier choice of the same bot for the cards.
[What was settled while building it](#what-was-settled-while-building-it) has the details.

- [What passes through the listener today](#what-passes-through-the-listener-today)
- [What a broken listener can do with it](#what-a-broken-listener-can-do-with-it)
- [What a path has to give](#what-a-path-has-to-give)
- [A. The router's own bot](#a-the-routers-own-bot)
- [B. Approving on the router's page](#b-approving-on-the-routers-page)
- [C. Binding the code to the card by what the owner already sees](#c-binding-the-code-to-the-card-by-what-the-owner-already-sees)
- [D. A socket of its own for the owner's messenger](#d-a-socket-of-its-own-for-the-owners-messenger)
- [E. One bot, held by a relay on the trusted side](#e-one-bot-held-by-a-relay-on-the-trusted-side)
- [Side by side](#side-by-side)
- [Recommendation](#recommendation)
- [The test every option has to pass](#the-test-every-option-has-to-pass)
- [What was settled while building it](#what-was-settled-while-building-it)

## What passes through the listener today

The scope is a client with an approval section, which today means hermes-openwrt's agent, and its
approver. A client without one (`claude-code` in the README) is given its code by its own operator
and sends it itself, by design, and is not part of this.

| Step | Who | Over what |
|---|---|---|
| The agent's `uci_apply` or `ubus_call` is held | the agent's token | the listener, then the helper (`approval.go` `hold`) |
| The held changes, each with its card and hash, are listed every 5 s | the owner's token, in hermes-openwrt's plugin `openwrt-unlock` | `action_list`, through the listener |
| The card is sent to the owner | the plugin | the same Telegram bot the agent talks through |
| The owner taps Approve, the plugin restates the headline, the owner sends `PIN code` | the plugin | Telegram |
| The approval is asked for | the owner's token, with `id`, `hash`, `pin`, `code` | `action_approve`, through the listener |
| The owner's `/unlock PIN code` opens the agent's window | the owner's token | `mfa_unlock {client}`, through the listener |

So everything the owner is shown and everything the owner answers crosses the listener, and so does
the owner's token. [privilege-split.md](privilege-split.md#what-this-holds-and-what-it-does-not)
names this as what the split does not hold.

## What a broken listener can do with it

A TOTP code is a function of the secret and the time step and of nothing else. It says nothing about
the card it was typed for. A listener that is broken, and runs code of an attacker's choosing as the
account `openwrt-mcp`, holds the agent's token and the owner's token as they pass, and can:

1. **Show one change and hold another.** Rewrite the agent's call (it has the agent's token), so the
   helper holds change B, and answer the plugin's `action_list` with a card it wrote for change A
   and B's id and hash. The owner approves what reads as A, and B runs.
2. **Move the code.** Take an `action_approve` for A and send it with B's id and hash, which it can
   list for itself with the owner's token.
3. **Change its purpose.** Take the PIN and code of an `/unlock` and send them as an approval of B. A
   code is accepted for one step before its own and two after it, so this has about 90 seconds.
4. **Lie about the outcome.** Tell the plugin the approval was refused, or applied, whatever happened.

It cannot approve anything without a code the owner types at that moment, and the helper's own
checks (the approver, the whole hash, the unchanged configs, no apply pending, the policy, the
factor last, the step spent) all still run. They run on whatever the listener chose to send.

## What a path has to give

| | Requirement |
|---|---|
| R1 | The card the owner reads is the helper's own text, and nothing between can change it |
| R2 | The tap and the factor reach the helper without the listener |
| R3 | Nothing between can put the factor on another change or to another purpose |
| R4 | The owner does no more than today: one tap and one message per change, one message per unlock |
| R5 | The helper keeps what invariant 12 says of it: it listens on no network socket and believes nothing it is told |

One more line is worth reading beside them, though the decision does not ask for it:

| | |
|---|---|
| G | Whether the Hermes gateway stays in the path. Today it carries the card and the factor too, and it runs as the account the agent's tools run as, in the same sandbox, with its configuration in the data directory that account writes (hermes-openwrt invariant 7 and `hermes-jail`) |

## A. The router's own bot

The helper talks to the owner itself, through a Telegram bot of its own whose token only the helper
holds, and TLS ends in the helper.

**Out.** When `hold` makes a record, the helper sends the record's card, as plain text with no parse
mode, to the approver's private chat, with Approve and Reject under it. It keeps which message
carries which record. **Back.** The helper reads the bot's updates itself (`getUpdates`, long poll,
`message` and `callback_query` only). A press counts only from the approver's Telegram id, in that
private chat, on the message the helper sent for a record that is still held. Approve restates the
headline from the helper's own record and opens a 180 s prompt; the next text from the approver in
that chat is deleted first and then read as `PIN code`, and the approval runs the checks
`action_approve` runs today, in the same order, the factor last, against the same throttle, with the
step spent. Reject is the press. `/unlock PIN code` and `/lock` from the approver, in the same chat,
open and close the client's window. The outcome edits the card.

**Why nothing between can touch it.** The card, the press and the factor never pass the listener or
the gateway. Telegram accepts a `getUpdates` from one reader per bot at a time, so no other process
reads this bot's updates, and only the token's holder can send or edit its messages, so no other
process can write a card in that chat or change one. While the bot is the approval's channel, the
helper refuses `action_list`, `action_approve`, `action_reject` and an approver's `mfa_unlock` or
`mfa_lock` over MCP for that approval section: no factor for it is taken from an MCP client at all,
and the owner's MCP client and its token are no longer paired.

**The transport, two ways.**

- **A2, through a pipe that sees ciphertext.** The listener gains one duty: it serves one more
  socket, and for each connection the helper makes to it, it opens TCP to `api.telegram.org:443` and
  copies bytes both ways. It takes no request: there is no host or port to name. The helper checks
  the pipe's uid with `SO_PEERCRED`, does the TLS handshake for `api.telegram.org` over that
  connection and verifies the certificate against the system roots, so the listener carries TLS
  records it has no key for. It can delay or drop them, as it can drop any call today, and it can
  neither read nor alter them. Invariant 12 stays as written: the helper opens no IP socket.
- **A1, the helper dials itself**, with a dialer fixed to `api.telegram.org`, as rollcall's channel
  does. Less code; invariant 12 then reads that the helper listens on no network socket and its one
  outbound connection is TLS to `api.telegram.org`.

DNS and the clock matter to both: a forged answer for `api.telegram.org` fails the certificate check,
and a wrong clock fails it too until NTP has run. A change to the time servers or to who answers DNS
is held already.

**What the owner sees and does.**

| | Today | With A |
|---|---|---|
| A change waits | a card in the agent's chat, Approve and Reject | the same card in the router's chat |
| Approving | one tap, one message `PIN code` | the same |
| Rejecting | one tap | the same |
| Unlocking | `/unlock PIN code` in the agent's chat | the same message in the router's chat |
| Once | nothing | make a bot with BotFather, paste its token on the Security page, press Start in it; about two minutes, once per router |

**What changes.**

- *openwrt-mcp.* A Telegram client in the helper: strict, bounded decoding of each answer, the host
  fixed, only the approver's private chat. The approval core of `actionApprove` shared by the MCP
  path and the bot path, so both run one order of checks. In the approval section, `option
  approver_telegram '<id>'` and the bot's token file (root, 0600) in place of `option approver`, and
  in that form the MCP approver tools refused. `openwrt-mcp owner-bot set` (the token on standard
  input) and `owner-bot status`. In A2, the pipe in the listener. A new invariant: the owner's card
  and factor never pass the listener, with its gate and teeth. A capability in `status --json`, so
  hermes-openwrt can tell it is there.
- *hermes-openwrt.* The Security page: the router bot's token, write-only like the other keys, a
  t.me link to press Start, and whether the chat is bound; rpcd methods that hand the token to
  `openwrt-mcp owner-bot set` on standard input. The init writes `approver_telegram` from
  `hermes.security.approver_id` and stops pairing `hermes-main-owner`. The plugin drops the owner's
  token, the poller and the approval path; it keeps its four lines of defence, so a PIN typed in the
  agent's chat by habit is still deleted and never reaches the model, and answers that unlocking and
  approving are in the router's chat now; it tells the agent each outcome from `action_status` on the
  agent's own token. The owner note says where the card goes.
- *rollcall.* Nothing. An owner who already has a bot of their own for rollcall's alarms could use it
  as the router's bot too, since rollcall stops reading its bot once it is bound; rollcall would then
  hold the same token and could write in that chat.

**What it leaves.**

- Cards come from a second bot, which turns round the choice of the same bot recorded in
  hermes-openwrt (`@decided 2026-10-22` in `docs/per-action-approval.md`), and the approver stops being
  an MCP client, which `approval.go`'s header records from the same day. Both need a new decision.
- A second bot per router and a second chat on the phone.
- The helper reads JSON from `api.telegram.org`, and anyone on Telegram can write to a bot. Every
  update that is not from the approver's private chat is dropped once its sender is read, and counts
  nothing.
- Approving needs the internet and Telegram, as it does today.
- The listener still holds the agent's token, so it can still rewrite what the agent proposes. The
  owner is then shown the change that is really held, and rejects it.
- The agent's own chat can still say anything; the card in the router's chat is the record.

**How it is checked.**

- A Telegram stand-in over TLS with its own CA, as rollcall's channel tests use, driving the helper's
  bot loop: the card in the chat equals the record's card byte for byte; a press from another id,
  from a group, on an old message or on a decided record does nothing and counts nothing; the factor's
  message is deleted before it is read; a factor with no prompt open is refused and counts nothing;
  the MCP approver tools are refused in this form; in A2, neither the card, the PIN nor the code
  appears in the bytes the pipe copied.
- Mutants, each caught by a named test: a press put on the record of another message; a press taken
  from another id; a factor taken with no prompt; the message read before it is deleted; the MCP
  approver path left open; the certificate not verified.
- A gate: the helper's Telegram client dials the pipe's socket only and names `api.telegram.org` only;
  the pipe dials `api.telegram.org:443` only; teeth for each.
- The vlab: the stand-in served as `api.telegram.org` on forge, its CA in the virtual router's trust
  store, the whole flow through both parts as procd starts them. Then one run on a Flint 2 with the
  owner's phone: one card, one tap, one message, as on 2026-10-22.

## B. Approving on the router's page

The owner approves in LuCI. rpcd runs as root and reaches the helper by a socket only root may use.

**Out and back.** The helper serves a socket for root, in a directory of its own (`0700`), and serves
only a peer whose `SO_PEERCRED` uid is 0. It takes: the held changes with their cards, approve one by
its id and the hash of the card listed, reject one, open a client's window, close it. A command line
uses it (`openwrt-mcp held list --json`, `held approve <id> <hash>`, `held reject <id>`, `unlock
<client>`, `lock <client>`), and rpcd's `hermes` script calls that command line. The page shows the
card as text, exactly as the helper wrote it, with Approve and Reject; Approve sends the id and the
hash of the card on the page.

**Why nothing between can touch it.** The listener is not on the path, and the socket refuses every
uid but root's. The card goes helper, rpcd, browser, and the click comes back the same way.

**The factor.** A LuCI session is root's, logged in with the router's root password, and root can
change any setting directly. So a PIN and a code add nothing against someone who holds that session.
**B1**: a click approves. **B2**: the page also asks for the PIN and the code, as Telegram does today.

**What the owner sees and does.** In Telegram, a short notice from the agent's chat: a change waits
on the router's page, with its id. Then, on the home network: open the page, log in if the session
has ended, read the card, click. Away from home there is no way to approve, short of a VPN to the
router: the change expires after ten minutes, and the agent asks again later.

**What changes.**

- *openwrt-mcp.* The root socket and its command line, the approval core shared with
  `actionApprove`, with the factor step replaced in B1 by "asked by root on the router", written as
  such in the audit log.
- *hermes-openwrt.* rpcd methods (`held_list` to read; `held_approve`, `held_reject`, `unlock`,
  `lock` to write) and their ACL; an Approvals view; the plugin's card becomes a notice with no
  buttons that asks for nothing.
- *rollcall.* Nothing.

**What it leaves.**

- The home network only.
- In B1, the PIN and code of each approval (`@decided 2026-10-22` in hermes-openwrt) give way to the
  LuCI session: that needs a decision.
- Any process running as root on the router can approve. Root can already change anything, and
  `exec` for a client without an approval section is already a root shell.
- uhttpd, rpcd, LuCI and the owner's browser are on the path: root's or the owner's own.
- The notice in Telegram comes from the gateway, which can fake it or drop it; the page is the record.

**How it is checked.** The root socket refuses the listener's uid and any other but 0; the listing
equals the record's card; an approval with any hash but that of the card listed is refused and counts
nothing; rpcd's methods against the real command line in hermes-openwrt's LuCI gate; the view test
renders the card as text, never as HTML; in the vlab, an rpcd session logged in over ubus approves a
held change through the page's own calls.

B is cheap to add to any other option, as the approval at home and over SSH.

## C. Binding the code to the card by what the owner already sees

The question here is whether the code can be tied to the card with no new path and no new input.
It cannot, on its own. A TOTP code carries no information about the card, so whatever carries it can
offer it to anything that takes a code at that moment. Three ways were looked at:

1. **One change at a time, and a code made after the card.** The helper would refuse a code whose
   step is not later than the record's creation, with nothing else waiting. The listener still writes
   what the owner reads, because the card comes back through `action_list`, so it shows a card of its
   own over the record it holds. This holds only once the card reaches the owner without the
   listener: that is D or A.
2. **Buttons the helper signs.** The helper sends the card itself through the same bot, with a MAC of
   the record in each button's data, so a press names one record and nothing else can make a press
   for another. The presses and the factor still come back through the gateway, which reads that bot,
   and the gateway holds the bot's token and can edit the helper's message while keeping its signed
   button. It needs the helper on the network, as A does, and still trusts the gateway, which A does
   not.
3. **The owner types the card's ref with the code.** That binds them, and it is new input, which the
   decision rules out.

What C is reaching for is in the helper already and stays in every option: an approval names one
record, by its id and its whole hash; it runs only on unchanged configs; the code's step is spent, so
it neither approves another change nor opens the window.

## D. A socket of its own for the owner's messenger

The plugin talks to the helper directly, on a second socket, and the owner's token stops working
anywhere else.

**Out and back.** The helper serves a second socket in a directory of its own, `0660` to a group the
configuration names, and serves only a peer whose `SO_PEERCRED` uid is the one it names (the
gateway's account, `hermes`). It takes the approver's tools and nothing else: `action_list`,
`action_approve`, `action_reject`, and `mfa_unlock` and `mfa_lock` naming the approved client. The
approver's token is taken there and refused on the listener's socket; the agent's token is refused
there. The plugin speaks the helper's framing (a four-byte length and one JSON object) over a Unix
socket, with the standard library, and checks that the other end is root before it sends the token
or a factor: the agent's tools run as the same account and could leave a socket of their own where
the plugin looks.

**Why the listener cannot touch it.** It is not on the path and never sees the owner's token, a card,
a press or a factor. What it holds is the agent's token, as today.

**What the owner sees and does.** Nothing changes.

**What changes.**

- *openwrt-mcp.* The second socket, the uid and group it serves named in the configuration, the
  approver's token refused on the listener's socket, a capability in `status --json`.
- *hermes-openwrt.* The plugin's `call_tool` over the socket, with the peer check; the socket's
  directory staged into the gateway's ujail sandbox, which has no `/var` today; the init writing the
  socket's options and checking the capability before it relies on it.
- *rollcall.* Nothing.

**What it leaves.**

- The gateway carries the card and the factor, as it does today, and it is the part G describes. So
  the thing D still trusts is not smaller than the one it takes out.
- The same bot lets the gateway send a message made to look like a card; the plugin's restated
  headline guards against habit, not against the gateway.
- The agent's tools share the gateway's uid, so the peer check cannot tell them apart. The owner's
  token does, as it does today over HTTP.

**How it is checked.** Every uid but the named one refused, the listener's included; the approver's
token refused on the listener's socket, red first, since it is accepted there today; the agent's token
refused on the owner's socket; the plugin refuses a socket whose other end is not root; hermes-openwrt's
`gate-unlock.sh` approval checks run against the real daemon over the new socket; the vlab; the
Flint 2 run unchanged for the owner.

## E. One bot, held by a relay on the trusted side

One bot stays, and the gateway gives it up. A small relay on the router, written in Go, under its own
account with no capability and with a way out to `api.telegram.org` only, holds the bot's token and
reads every update, the way stickwise's guard holds its bot and relays the chat to its agent. The
card's buttons, a factor after a prompt, `/unlock` and `/lock` go to the helper over D's socket, bound
to the relay's uid; everything else goes to the Hermes gateway through the gateway's own API, and the
gateway's answers come back and are sent with a label.

**What the owner sees and does.** One chat, as now, and the same taps and messages; the agent's
messages carry a label.

**What changes.** A new Go program and package in hermes-openwrt, with Hermes's Telegram adapter off
and the plugin's four lines of defence moved into the relay; D's socket in openwrt-mcp. rollcall
nothing.

**What it leaves.** The relay carries the card and the factor, so it is trusted for them, though it
is far smaller than the gateway: Telegram's JSON in, the gateway's text out. Hermes's own Telegram
features (voice, files, images, its commands) become what the relay carries. It is the largest change
of the five.

**How it is checked.** The relay's tests as stickwise's chat relay has them, D's tests, and the same
vlab and Flint 2 runs.

## Side by side

| | A. Router's own bot | B. Router's page | C. Binding alone | D. Owner's socket | E. Relay holds the bot |
|---|---|---|---|---|---|
| Listener off the path (R1 to R3) | yes | yes | no | yes | yes |
| Gateway off the path (G) | yes | yes | no | no | yes |
| Per change (R4) | as now, in a second chat | open the page, log in, click | | as now | as now |
| Once | a bot per router, about two minutes | nothing | | nothing | nothing |
| Away from home | yes | no | | yes | yes |
| The helper's network (R5) | none in A2; one TLS connection in A1 | none | | none | none |
| Owner's MCP client and token | gone | stay for Telegram, or gone | | stay, off the listener | stay, held by the relay |
| Works for an agent other than Hermes | yes | yes, at home | | needs a messenger | no |
| Size | medium, both repositories | small to medium | | small | large, mostly hermes-openwrt |
| Turns round an earlier decision | the same bot, the approver as an MCP client (2026-10-22) | the PIN and code per approval, in B1 (2026-10-22) | | none | none |

## Recommendation

**A, carried as A2.** `@claude`, the reasons:

- **It trusts the fewest things.** The card and the factor pass only the helper, Telegram and the
  owner's phone, and the first already holds the gate. The listener carries ciphertext it has no key
  for, and the gateway is off the path, which is the one larger thing D keeps and E shrinks.
- **It costs the owner nothing per change.** One tap and one message, as now; unlocking is the same
  message in the other chat. The price is paid once: a bot per router, about two minutes.
- **It takes a secret off the router.** The owner's MCP client and its token go, and with them the
  only token that could approve.
- **It outlives the agent.** The router asks its owner itself, so a held change works the same for
  Hermes, for another agent, or for a client over SSH, without a messenger built for each.
- **Invariant 12 stays as written** in A2: the helper opens no IP socket and believes nothing it is
  told, because what it reads from Telegram comes over TLS it verified itself.

What it costs, said plainly: it turns round the 2026-10-22 choice of the same bot, adds a second chat
and a second bot per router, and puts a Telegram client in the helper.

If one bot is to stay, **E** is the strongest of the rest and the largest piece of work, and **D**
closes exactly what the decision names, with nothing changed for the owner and the gateway still on
the path. **B** suits any of them as the approval at home and over SSH.

## The test every option has to pass

One test shows the gap and then its end, whichever option is built: a hostile listener in front of a
real helper, which rewrites an `action_approve` to another held change and sends an `/unlock`'s PIN
and code as an approval. Against today's code it approves the change the owner was not shown, which
is the red run. With A, B, D or E it sees no frame of the owner's at all, so it has nothing to rewrite,
which is the green one. It goes into `features/` as a scenario bound to its test, with a mutant that
routes the owner's factor back through the listener and must turn it red.

## What was settled while building it

- **The pipe.** The listener serves `/var/run/openwrt-mcp-relay/telegram.sock`, in a directory
  `openwrt-mcp:openwrt-mcp 0700` that the init script makes, and serves only a peer whose
  `SO_PEERCRED` uid is 0. For each connection it dials `api.telegram.org:443` itself, a name fixed in
  its code, and copies bytes both ways, at most four connections at once, each cut after two minutes
  without a byte. The helper connects to that socket, checks that the other end is the listener's
  uid, and runs TLS for `api.telegram.org` over it against the system's roots, TLS 1.2 at least, with
  no proxy. The other way was a descriptor passed over the socket (`SCM_RIGHTS`): it would put a TCP
  socket in the helper's hands, so invariant 12 would hold only by agreement, and the helper would
  have to check what kind of socket it had been given. The copy costs the listener a few kilobytes a
  minute.
- **When the bot is the channel.** Once a token is set and a chat is bound. From then on, for every
  approval section on the router, the MCP approver tools are refused (`action_list`,
  `action_approve`, `action_reject`, and `mfa_unlock` and `mfa_lock` naming another client), and at
  the moment of binding the helper revokes the tokens of the clients named as approvers. Until a chat
  is bound, approvals work as before, so setting the bot up never leaves a gap.
- **Binding the chat.** `openwrt-mcp owner-bot bind` makes a one-time code of 128 bits and prints it
  with the link `https://t.me/<bot>?start=<code>`. LuCI shows that link, so pressing Start sends the
  code and the owner types nothing. `owner-bot bind` writes the code's end in its file, 30 minutes on;
  the helper takes the code until that end and for at most 30 minutes of its own monotonic clock from
  when it first sees it, binds the private chat that sends it, and removes it. A code past its end is
  removed as the helper starts, so a restart gives it no new life. Until then
  the bot answers nobody, and a wrong code, a group or a channel gets no answer at all.
- **Files.** `/etc/openwrt-mcp/owner-bot/`, root's, `0700`, each file `0600` with one writer: `token`
  (the CLI, from standard input), `bind` (the CLI writes the code's SHA-256, the helper removes it),
  `chat` (the helper writes the bound id), `seen` (the helper writes the bot's name and its last
  failure, for `status`). A failure is one word of a fixed set (`token_rejected`, `telegram_refused`,
  `telegram_error`, `tls`, `pipe`, `network`, `other`), in that file, in the status and in the log,
  and never an error's text, which could carry what a URL carried.
- **In the chat.** The card is the record's card, plain text, with Approve and Reject. Approve
  restates the headline from the record and opens a prompt of 180 seconds; the next text from the
  owner is deleted, then read as `PIN code` (or `code`, for a section whose factor is `totp`), and
  approved by the same checks in the same order as `action_approve`, the factor last and the step
  spent. A message that looks like a factor with no prompt open, or after it closed, is deleted and
  counts nothing. `/unlock PIN code` and `/lock` work as they did in the agent's chat; with more than
  one approval section they name the client first. The outcome edits the card, and so does an
  expiry, a withdrawal or a `/lock`.
- **A card is one message.** Telegram counts a message in UTF-16 units, at most 4096, so a change whose
  card would not fit one message whole, with room for its outcome, is refused when it is held, as an
  over-long card always was. A card Telegram does not take for any reason waits with a delay of its
  own, doubling up to five minutes, while the other cards go out. One that reaches the bot too long
  anyway goes out cut, says so, and offers only Reject; the record keeps the whole card in the helper.
- **Reject, a withdrawal, a new bot.** Reject is one tap and takes no factor; a change the agent
  withdraws, or that expires, has its card edited to say so. A new token drops the bound chat, so a new
  bot is bound again with a new code; the same token given again changes nothing.
- **A restart.** Held changes and prompts live in memory, so a restart drops them, as before. What
  reached the bot while the helper was not reading is read once at its start and never acted on: a
  message that looks like a factor is deleted, and the owner is told it was not used.
- **Without a bot.** A router with no bot bound keeps today's path, and the gap this page opens with
  stays for it: the listener carries the card and the factor.
