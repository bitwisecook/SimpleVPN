# 1Password as a sign-in source

`SimpleVPN/Credentials/OnePasswordProvider.swift` · `OnePasswordNative.swift` ·
`OnePasswordPreflight.swift` · `OnePasswordBrowse.swift` · `OnePasswordDropItem.swift` ·
`OnePasswordVaultAdapter` in `LocalVaultAdapters.swift` · settings in **Settings ▸ Sign-In
Sources ▸ 1Password** · manual anchor `creds-onepassword-enabled`

**This is the one vault that is claimed as tested** — `FeatureMaturity.signInSources` says
`.vault(.onePassword): .tested`, and the reason is unglamorous: 1Password is the only password app
installed on the machine the credentials programme was written on. Everything else in the family is
`.untested`. So this doc is not "what somebody should try"; it is what the path is, plus the recipe
for confirming it on a Mac that is not ours.

## The channel, and why it is a separate process

The transport is `.signedIPC`: the **official 1Password Go SDK**, talking to the running
1Password 8 desktop app over its local integration. Fully offline — no network, no service-account
token, no `op` CLI.

The SDK does not live in the app. It lives in `opnative-helper`, our own signed one-shot tool in
`Contents/MacOS`, and the reason is a hard platform constraint rather than taste: the SDK's IPC path
`dlopen`s 1Password's own AgileBits-signed dylib, which needs the library-validation relaxation —
and AMFI kills any app that embeds a System Extension while carrying that relaxation ("Hardened
Runtime relaxation entitlements disallowed on System Extensions"; build 87 died exactly this way).
SimpleVPN embeds a System Extension, so the relaxation had to move out of the app. The helper speaks
a JSON contract over stdin/stdout (`Vendor/onepassword-native/include/opnative.h`,
`OPNativeHelper/main.swift`, `Vendor/onepassword-native/src/main.go`), and every helper run is
serialised on one queue — 1Password shows one authorization prompt at a time.

**The `op` CLI was retired for our path.** It is still in `ToolCatalog` (`name: "op"`, vendor
`.onePassword`, with 1Password's own documented `/usr/local/bin/op`) so that its presence and
version appear in a diagnostic report — but nothing reads a sign-in through it, and there is no
setting to point at it. The enablement banner therefore names 1Password's **SDK** setting and links
1Password's SDK page, not the CLI's app-integration toggle.

Sessions last about ten minutes; the shim caches the SDK client and transparently re-authenticates
once when one expires.

## The gate: one checkbox, and not the one the SDK names

**1Password ▸ Settings ▸ Developer ▸ Developer Integrations ▸ "Integrate with 1Password SDKs".**
That string is a constant (`UserFacingError.sdkIntegrationSetting`) with a test asserting the
copy contains it, because getting it wrong is expensive: 1Password's *own* refusal message still
names "Integrate with other apps", a toggle 1Password removed. Our copy says what today's Settings
shows and says so in a note.

This is the setting the prompt-free probe cannot see. `OnePasswordNative.probe()` only proves the
SDK dylib is on disk — i.e. that 1Password is installed. Nothing short of a real call establishes
whether the checkbox is on.

## How it authenticates, and when a fetch is interactive

**1Password does the unlocking.** It shows its own authorization prompt — Touch ID, or an Allow
button — naming SimpleVPN. The 1Password account password never reaches this process and there is
nothing for SimpleVPN to store, prompt for, or lose.

Interactive exactly once per approval, and then not again until the session lapses. The one place
this is deliberately paid up front is `OnePasswordPreflight`: **choosing 1Password as a sign-in
source runs one real `listVaults` call**, which may raise the approval prompt. That is legitimate —
picking the source is the first genuine need. Running it at launch, or merely on opening the editor
of a VPN that is already set up, would not be, and is not done.

The preflight has a six-second timeout, and the timeout is the interesting part: a reachable,
enabled integration answers in well under a second, so silence past six seconds almost certainly
means 1Password's dialog is sitting somewhere waiting. "1Password is asking for your approval" is a
far better thing to say than a spinner. Cancellation terminates the helper, so a timed-out check
leaves nothing running.

Six states come out of it (`OnePasswordPreflight.State`): `notInstalled`, `integrationOff`,
`needsAccount`, `waitingForApproval`, `ready(vaults:)`, `failed(UserFacingError)`. Each has its own
headline, SF Symbol and numbered walkthrough.

## Two read shapes, and why the narrow one is preferred

| Shape | When | What is granted |
|---|---|---|
| **Secret references** — `op://vault/item/field` | the coordinates are explicit enough: a vault, a non-URL item reference | exactly the two or three fields asked for |
| **Full item read** — `getItem` | a link-style reference, no vault, or our default field-name guesses missed | the whole entry, once |

The narrow path is the narrowest possible grant, so it is tried first. A VPN that names an entry by
title alone used to fall back to the whole-item read every time; `OPNativeLookup` fixed that —
`lookupOne` answers "which vault is this in?", so one lookup buys the coordinates and the request
that follows grants three fields instead of everything in the entry. A failure in the lookup is
best-effort: it just leaves the old path.

Roles the field map does not name fall back to a standard Login item's field names (`username`,
`password`, `one-time password`). A wrong guess there is the **one** failure that quietly retries
via the full-item read, which auto-detects by field purpose instead — because a guess of ours
missing is not the user's mistake.

The verification code is asked for as `?attribute=otp`, i.e. **the computed current code**. The
`otpauth://` enrollment seed is never released by the shim: on an OTP field `value` is always empty
and `otp` carries the code.

`CredentialSourceKind.onePassword.suppliesOTP` is **`true`** — one of only two sources for which it
is (KeePassXC is the other). That flag is a promise that Connect works with nothing typed, and it is
made here because it has been watched working.

## Cardinality: single, and the reason is not a simplification

`LocalVaultVendor.onePassword.cardinality` is `.single`, and
`SignInSourceSettings.fields(for: .onePassword)` is **empty** — no path, no socket, no endpoint.
There is literally nothing about reaching 1Password that can be configured wrongly.

1Password accounts and vaults are real, and a person may well have several — but they are
1Password's own namespace and are addressed **per VPN** (`CredentialSource.account`,
`CredentialSource.vault`), which is level 3 where they belong. An instance list here would be a list
of rows with no fields in them, and a test asserts a single-instance vendor has no instance-level
fields precisely so that cannot happen.

**The account is not optional in practice.** The SDK's desktop integration refuses to build a client
for an account it cannot match — empty string included — with "Account not found". So a blank
Account field is a first-class nudge (`OnePasswordPreflight.accountNudge`, one wording shared by the
editor field, the browse popover and the setup card) rather than an error. A name that has worked is
remembered in `onePassword.defaultAccount` and reused by every other VPN; a failed lookup retries
once with it.

## The four states, and the one action that clears each

`OnePasswordVaultAdapter.quickScan()` is file and bundle checks only — no subprocess, safe on every
refresh. `deepScan` adds one thing.

| State | What SimpleVPN says | The fix |
|---|---|---|
| `.notInstalled` — no 1Password bundle (`com.1password.1password`, `com.agilebits.onepassword7`, `com.1password.1password-launcher`) | the row is not offered at all | install 1Password 8 (we never install it) |
| `.blocked(.appNotRunning)` | "1Password isn't running" | open 1Password and sign in to it |
| `.blocked(.needsUpdate)` — app present, SDK dylib absent, from `deepScan` | "1Password needs updating on this Mac" | update 1Password to 8 or later |
| `.blocked(.integrationOff)` — a **real call** said so | "1Password needs one setting turned on", with the walkthrough | tick "Integrate with 1Password SDKs" |
| `.unchecked(.checkOwedOnUse)` | "SimpleVPN checks with 1Password when you pick this. 1Password may ask you to allow it, once." | pick the row; that pays the check |
| `.ready` — verified before | nothing to say | — |

Two remembered flags keep those apart, and both are `UserDefaults`, not secrets:
`onePassword.sdkVerified` ("we have seen this work, skip the walkthrough") and
`onePassword.sdkIntegrationOff` ("a real call said the checkbox is off"). "Nobody has looked yet"
and "we looked and it is off" need opposite copy — one offers a check, the other shows the exact
setting — which is why there are two flags rather than one tri-state.

The re-arming matters as much as the setting: **every** real failure funnels through
`OnePasswordNative.nativeError`, which calls `OnePasswordPreflight.noteFailure`. So somebody who
turns the checkbox back off after setup gets the walkthrough back, from a connect or a browse rather
than only from the setup card. And a success clears both flags, so following the walkthrough flips
the row to ready on the next poll with no restart.

## What is stored, and where — none of it secret

| Thing | Where | Secret? |
|---|---|---|
| `kind`, `reference` (item title or UUID), `account`, `vault`, `fieldMap` | the VPN's profile | no — names and ids |
| `onePassword.sdkVerified`, `onePassword.sdkIntegrationOff` | `UserDefaults` | no — two booleans |
| `onePassword.defaultAccount` | `UserDefaults` | no — a sidebar name or an account UUID |
| the 1Password account password | **nowhere.** 1Password holds it | — |
| the approval / session | inside 1Password and the helper's cached client | never persisted by us |

`fieldMap` is keyed on `AuthKind.rawValue`, and a test pins those raw values — renaming a case would
silently unmap somebody's 1Password fields.

## What it withholds

* **The account password.** By construction: there is no path by which it could arrive.
* **The `otpauth://` seed.** Only the current code, via `?attribute=otp`.
* **Objects that are not field values.** Passkeys, certificates and SSH keys are items rather than
  fields, and 1Password's secret-reference syntax cannot name them. `nativeSecretRefs` switches
  exhaustively over `AuthKind` rather than using a `default`, so a new kind has to state which
  reason applies to it.
* **A list of accounts.** The SDK offers none, and the app is not readable from here — which is why
  an unknown account can only be answered by the user naming it.
* **Other items' ids.** An ambiguous lookup names at most four candidates by title and vault, and
  never prints ids.

## Failure modes, and the three that are ambiguous

`OnePasswordNativeError` mirrors the Go shim's `kind*` constants: `appNotInstalled`, `appNotRunning`,
`integrationDisabled`, `userCancelled`, `sessionExpired`, `itemNotFound`, `accountNotFound`,
`ambiguous`, `rateLimited`, `badRequest`, `badResponse`, `other`. Every one has a sentence naming
its fix.

The ones a tester should treat with suspicion:

1. **`waitingForApproval` from a timeout is an inference, not an observation.** Six seconds of
   silence is *assumed* to be a dialog. Anything else that takes longer than six seconds — a wedged
   helper, a pathologically slow first launch — will be reported as "1Password is asking for your
   approval". The inference is a good one and it is still an inference.
2. **`userCancelled` and "the dialog is still up" are the same picture from outside.** Both become
   `waitingForApproval`, deliberately: the user's next action is identical.
3. **`itemNotFound` means two things** — a genuinely absent item, or our default field names missing
   on an item built from custom fields. The narrow path cannot tell, so it does not try: when
   `usedDefaults` was set it logs "default field names missed" and falls through to the full-item
   read. Only a failure there is surfaced.
4. **`accountNotFound` with an empty account** is not "your account is wrong", it is "1Password will
   not pick one for you". Different sentence, same error kind — completed with the name we tried in
   `nativeError`, because the helper does not know what was asked for.

## Dragging an item in

`OnePasswordDropItem` reads four pasteboard flavours, and the order was settled by live testing
rather than by reading a spec. Dragging an item **row** offers `public.utf8-plain-text` (the title
and nothing else) plus `org.chromium.web-custom-data` — 1Password's own JSON carrying account, vault
**and** item UUIDs, because 1Password 8 is an Electron app and its drags carry Chromium's flavour.
Dragging a **field** gives an `op://vault/item/field` reference (a vault, never an account), and only
"Copy Private Link" produces a link naming the account.

So the plain text alone can never finish the setup and the custom data always can, which is the
priority: 1Password's payload, then an account-naming link, then `op://`, then the bare title. A
dragged account UUID seeds `onePassword.defaultAccount` **only when it is blank** — a name that has
actually worked is more use to a human than a UUID.

## Manual test recipe

You need: 1Password 8, an account you can sign in to, a Login item with a username, a password and a
one-time password field, and a VPN in SimpleVPN that signs in with a username and password.

### 0. Baseline — the app absent

1. On a Mac with no 1Password at all, open a VPN's sign-in chooser.
   **Expect:** no 1Password row. **Not** a row saying it is broken.
2. Install 1Password 8 but leave it **quit**. Reopen the chooser.
   **Expect:** "1Password isn't running", with the step to open and sign in to it. SimpleVPN must
   not launch it for you.

### 1. The integration off — the state most first-time users meet

1. Open 1Password, sign in, and make sure **Settings ▸ Developer ▸ Developer Integrations ▸
   "Integrate with 1Password SDKs"** is **off**.
2. In SimpleVPN, pick 1Password as this VPN's sign-in source.
   **Expect:** within about six seconds, "1Password needs one setting turned on" and a four-step
   walkthrough naming **Developer Integrations** and the tick box — including the note that
   1Password's own message names an older setting. It must **not** say 1Password is not installed,
   and must not say the account is missing.
3. Tick the box. Press **Check Again**.
   **Expect:** it goes to ready (or to the account nudge below) **without restarting SimpleVPN**.
4. Now turn the box **back off** and connect the VPN.
   **Expect:** the failure re-arms the walkthrough — the setup card comes back on the next visit.
   This is the `noteFailure` path and it is the one most likely to have rotted.

### 2. The approval prompt

1. With the integration on and 1Password freshly launched, pick 1Password as the source.
   **Expect:** 1Password raises its own prompt naming **SimpleVPN**. SimpleVPN says "1Password is
   asking for your approval" with the step to switch to it.
2. **Dismiss** the prompt without approving.
   **Expect:** still `waitingForApproval` — the same sentence, not an error. Press **Check Again**
   and approve; it goes to ready.
3. Leave the Mac idle for fifteen minutes, then connect.
   **Expect:** either a silent success (the shim re-authenticated) or one fresh 1Password prompt.
   **Not** a failed connect. If it fails, the session-expiry retry has regressed and that is worth
   reporting.

### 3. The account

1. Clear the **Account** field on the VPN and connect.
   **Expect:** "Almost there — add your account name (the name at the top left of 1Password's
   sidebar) and SimpleVPN will check the item." — a nudge, not an error, and the same wording in the
   editor, the browse popover and the setup card.
2. Type a name 1Password does not have.
   **Expect:** "1Password doesn't have an account called …", naming what you typed, and telling you
   where to read the real one.
3. Type the real one and connect.
   **Expect:** success, and `defaults read com.bragi0.SimpleVPN onePassword.defaultAccount` now
   holds it.
4. Set up a **second** VPN, leaving its Account blank.
   **Expect:** it works, using the remembered name.

### 4. Addressing the item — all four ways

With the integration on and approved:

1. **Drag the item's row** from 1Password onto the editor's drop well.
   **Expect:** the item's real title shown (not a UUID, not "Item 1"), the vault filled in, and the
   account filled in if it was blank. Confirm the reference stored is the **UUID** — immune to
   renaming.
2. **Drag a single field** instead.
   **Expect:** an `op://vault/item/field` reference, a vault, and **no** account. That is what the
   flavour carries.
3. Type the item's **exact title**, leaving Vault empty.
   **Expect:** it works — `lookupOne` learns the vault. Then check the log (below): the fetch should
   have taken the **narrow** path, not the whole-item read.
4. Type a title that matches **two** items in different vaults.
   **Expect:** "N items match: "…" in vault "…", …" naming at most four, and **no** silent choice.
   Set the Vault and confirm it resolves.
5. Rename the item in 1Password, then connect a VPN that stored its **UUID**.
   **Expect:** it still works. Then do the same for one that stored the **title**.
   **Expect:** "1Password couldn't find that item or field". Both behaviours are correct; the point
   is that they differ and the doc says so.

### 5. The verification code — the promise being tested

1. On an item **with** a one-time password field, and a VPN that requires a code, leave the code
   field empty and press Connect.
   **Expect:** Connect is **enabled** and the sign-in succeeds with nothing typed. This is
   `suppliesOTP == true` being kept.
2. Do it again across a code rollover (wait out the 30-second window mid-connect).
   **Expect:** success both times.
3. Now point the same VPN at an item with **no** one-time password field.
   **Expect:** the fetch still succeeds for username and password. The narrow path asks for the OTP
   field optionally, so a missing one must not fail the run.
4. Confirm no seed ever arrives: take a diagnostic report and search it for `otpauth://`.
   **Expect:** nothing.

### 6. Secrets discipline — checked, not assumed

1. While a connect is in flight: `ps -Ao args | grep -i '[o]pnative-helper'`.
   **Expect:** `opnative-helper resolve` (or `item` / `list` / `lookup` / `probe`) and **nothing
   else**. No `op://` references, no account, no secret — the request rides **stdin**.
2. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` across a connect.
   **Expect:** at most "native resolve: default field names missed — retrying via full-item read".
   No username, no password, no code, no item title.
3. `defaults read com.bragi0.SimpleVPN | grep -i onepassword`.
   **Expect:** `onePassword.sdkVerified`, `onePassword.sdkIntegrationOff`,
   `onePassword.defaultAccount` — two booleans and a name. **Nothing else.**
4. Search a diagnostic report for the item's password.
   **Expect:** absent.

### 7. Cancellation must not wedge anything

1. Start a connect, let 1Password's prompt appear, and press **Cancel** in SimpleVPN (not in
   1Password).
   **Expect:** the connect stops promptly, and `ps` shows **no** surviving `opnative-helper`. Task
   cancellation terminates it; a leaked helper holding an unanswered prompt would block every later
   fetch, because runs are serialised.

### 8. MDM

1. Force `SignInSourcesForbidden = ["onepassword"]`.
   **Expect:** no 1Password row anywhere — not in the chooser, not as a pointer — and the Settings
   switch visibly locked with a reason.
2. Force `SignInSourcesAllowed = ["onepassword"]`.
   **Expect:** every other vault row gone, 1Password's kept.

There is **no** `SignInSourceToolPaths` entry to test: 1Password has no tool path, because it has no
tool.

## Known limitations, stated rather than discovered

* **The probe cannot see the setting.** `probe()` proves the dylib is on disk and nothing more, so
  "installed" and "will actually answer" are genuinely different questions here — which is exactly
  why the preflight makes a real call and why `.unchecked(.checkOwedOnUse)` exists.
* **Sessions expire on 1Password's clock, not ours.** About ten minutes. One transparent retry is
  built in; a second consecutive expiry surfaces.
* **`listItemsAcrossVaults` is a fan-out.** The SDK has no "everything" list. The `lookup` endpoint
  does the fan-out inside one helper run and one authorization and is preferred; the Swift-side
  fan-out (bounded at four) remains only for an archive predating `OPNativeLookup`. A vault that
  refuses is **skipped**, not fatal — one unreadable drawer must not hide the other twenty.
* **A helper missing from the bundle** is reported as "The 1Password helper is missing from the app
  bundle", not as 1Password being absent. It means a damaged or stripped build.
* **We cannot read 1Password's config.** So an account name cannot be discovered for the user, only
  remembered once they have typed one that worked.

## What is fixture-tested

`SimpleVPNTests/Credentials/OnePasswordPreflightTests.swift` pins the whole state mapping — every
error kind to its state, the timeout to `waitingForApproval`, the raw "connection channel is closed"
prose to `integrationOff` through the same predicate the failure classifier uses, and the
remembered-flag transitions in both directions. `OnePasswordListTests.swift` pins the wire shapes and
the account-aware error completion without spawning the helper. `OnePasswordBrowseTests.swift` pins
the account-memory precedence, the seed-only-when-blank rule, and the drop-flavour priority.
`SignInSourceTests.swift` asserts the enablement copy contains
`UserFacingError.sdkIntegrationSetting` verbatim.
