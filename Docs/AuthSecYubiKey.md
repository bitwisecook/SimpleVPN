# Security keys (YubiKey and similar) — manual test recipe

**Status: NOT exercised against real hardware.** There was no YubiKey attached to the machine this was
built on, and `ykman` was not installed on it. Everything below the process/registry boundary is
covered by fixture tests (see "What is fixture-tested" at the end); everything above it needs a person
with a key. This document is that person's script.

If you run it, please record the result — that is the only way these move from "written and reviewed"
to "tested".

---

## What was built, and which YubiKey this is

This is the **non-PIV** YubiKey: the secrets a key *types* or *computes*. It is not PKCS#11/PIV
(certificates and a PIN) — that was a separate piece of work with a separate editor surface, and it
has since been **removed**: SimpleVPN does not sign in with a certificate held on a card or a PIV
applet at all (`Docs/AuthSecPKCS11.md`). **Nothing on this page is affected.** The two shared a device
and no code: the removal touched no `YubiKeyCapture`, `Presence`, `TouchCapture`, `Conflicts` or
`YubiKeySlot`, and no `ykman` call site. What went was the *certificate* half.

Four mechanisms, chosen per VPN in **Manage VPNs ▸ (a VPN) ▸ Sign-In ▸ Security Key**:

| Mechanism | What happens | Needs `ykman`? |
|---|---|---|
| **The code my key types** (Yubico OTP) | Short touch; the key types 44 modhex characters (`cccc…`) then Return | No |
| **A verification code stored on my key** (OATH TOTP/HOTP) | SimpleVPN asks `ykman oath accounts code --single <name>` | **Yes** |
| **My key answers a challenge** (slot HMAC-SHA1) | `ykman otp calculate <slot> <hex>` | **Yes** |
| **A fixed password stored on my key** (static password) | Long touch; the key types its stored password then Return | No |

`ykman` is **never installed by SimpleVPN**. When a mechanism needs it and it is absent, the editor
shows the enablement banner with `brew install ykman` to copy.

---

## Before you start

1. A build installed per `AGENTS.md` (`./Tools/build-notarize-install.sh` → `/Applications`), because
   the packet tunnel needs the notarized path.
2. A VPN that asks for a verification code. Either a profile with `static-challenge`, or turn on
   **Requires a verification code (OTP)** in the Sign-In tab.
3. Your key plugged in. Check SimpleVPN sees it: the Security Key section says
   *"<family> is plugged in and ready to type a code when you touch it."*
4. For the two `ykman` mechanisms: `brew install ykman`, then `ykman info` in Terminal to confirm the
   tool and the key are talking.

**Check your keyboard layout first.** Menu bar ▸ input source, or System Settings ▸ Keyboard ▸ Input
Sources. Modhex survives QWERTY/QWERTZ/AZERTY; Dvorak and non-Latin layouts scramble it. SimpleVPN
will tell you if that is what happened, and step 4 below deliberately tests that.

---

## Test 1 — Yubico OTP, joined onto the password (the core case)

The one the feature was asked for: *password, then a touch appends the code.*

1. Sign-In tab: **Use a Security Key** on, **What the Key Supplies** = "The code my key types",
   **Where the Code Goes** = "Joined onto the end of my password". Save.
2. Note that the **password template** row (Verification Code ▸ Advanced) has gone unavailable and
   says the delivery setting decides it. That is intentional: one control, one meaning.
3. Select the VPN. The credential form appears and — because **Wait for a Touch Automatically** is on
   — the prompt should already say **"Touch your security key now"**, with a countdown and a Cancel
   button, and the cursor should already be in the **verification code** box.
4. Type your username and password. **Do not press Return.**
5. Touch the gold disc, short press.

**Expected:**
- 44 characters appear in the code box (masked).
- The prompt flips to **"Code ready to send"** and shows **From key `cccc ccjj bbbb`** — the public
  ID, grouped in fours. Compare it with what your gateway's administrator has on file.
- **Nothing connects.** This is the load-bearing assertion. Your key pressed Return and SimpleVPN
  swallowed it.
- Focus has moved on to whatever is still empty.

6. Now press Return yourself (or click Connect). It connects, and what reaches the gateway is
   `password` + the 44 characters, in one field.

### ✱ The failure this exists to prevent

If step 5 connects on its own, the trailing-Return guard has regressed. Every attempt then burns a
one-time code, and on gateways that count failures it walks towards a lockout. This is the single most
important thing to check.

### ✱ The retry, which must ask again

7. Deliberately get the password wrong and connect. When it fails:
   - the code box is **empty**;
   - the prompt says **"That code has been used… touch your key again for a fresh one"**;
   - Connect is disabled and says why.

   It must NOT re-send the spent code. If it does, the single-use guard has regressed.

---

## Test 2 — Yubico OTP in its own field

Same as test 1 with **Where the Code Goes** = "Sent on its own, separately". Use a profile with
`static-challenge`. The code should travel as the engine's challenge response and never appear inside
the password. The delivery row should be unavailable, saying the profile decides it.

---

## Test 3 — Cancel and timeout

1. Arm the wait (select the VPN, or click **Wait for My Touch**).
2. Press **ESC**. It should stop, say so, and invite another go — not report a failure.
3. Arm again and wait out the countdown without touching. It should say *"No code arrived…"* exactly
   once, and offer **Try Again**.
4. Touch the key **after** it has timed out. Nothing should be accepted — the screen said nothing
   arrived, and quietly taking a late code would make the screen and the state disagree.
5. Set **How Long to Wait for a Touch** to 5 seconds and check the countdown really is 5.

---

## Test 4 — The keyboard-layout diagnosis (worth doing once)

1. Switch your input source to **Dvorak**.
2. Arm the wait and touch the key.

**Expected:** SimpleVPN says the right number of characters arrived but they are not the ones a
security key sends, blames the **keyboard layout**, and tells you where to change it. It must not say
the code is invalid or suggest resetting the key.

3. Switch back and confirm it works.

---

## Test 5 — OATH code from the key (`ykman`)

1. `ykman oath accounts list` in Terminal. Note an account name (`Issuer:name`).
2. Sign-In tab: **What the Key Supplies** = "A verification code stored on my key", and put that name
   in **Account on the Key**. Save.
3. Connect. SimpleVPN asks the key; a six- or eight-digit code appears.

Also check:
- **A touch-required account** (added with `ykman oath accounts add -t`): the key's light flashes and
  SimpleVPN keeps waiting until you touch it. The deadline is longer for these.
- **An HOTP account**: it works, and it is fetched with `--single` so no other account's counter is
  stepped.
- **A wrong account name**: the error names the query and points at `ykman oath accounts list`.
- **A password-protected OATH applet**: SimpleVPN refuses rather than putting your password on a
  command line, and tells you to run `ykman oath accounts code -r <name>` once so `ykman` remembers
  it on this Mac. Then check it works.
- **Uninstall `ykman`** (`brew uninstall ykman`) and confirm the row goes unavailable with the
  enablement banner and a copyable `brew install ykman`.

---

## Test 6 — Challenge-response, and the KeePassXC interop check

`ykman otp chalresp -g 2` programmes slot 2 with a random secret. **This overwrites slot 2** — check
nothing is using it first (`ykman otp info`).

1. Sign-In tab: **What the Key Supplies** = "My key answers a challenge", **Key Slot** = Slot 2.
2. SimpleVPN currently reports that it has no gateway challenge to answer for this VPN kind — the
   mechanism is configurable and honest about the gap rather than silently doing nothing. Wiring the
   challenge from the engine is engine-side work that has not landed.

### The interop check that matters (do this one)

The same primitive is what a KeePass `.kdbx` uses to unlock, and the padding has to match exactly or
a database that unlocks everywhere else silently fails here.

```sh
# What SimpleVPN sends for a 32-byte database challenge: the challenge, then
# 32 bytes of 0x20 (PKCS#7 to 64 bytes — KeePassXC's own scheme).
ykman otp calculate 2 $(python3 -c "print('ab'*32 + '20'*32)")
```

Take the same key, the same slot and the same database into KeePassXC and confirm it unlocks. If it
does, `YubiKeyChallengeResponse.Padding.keePassPKCS7To64` is right and the kdbx adapter can use it as
is.

---

## Test 7 — Static password (the "don't mangle it" case)

`ykman otp static --generate 2 --length 38` programmes slot 2 with a static password. **Overwrites
slot 2.**

1. **What the Key Supplies** = "A fixed password stored on my key".
2. The capture box is now the **password** box, not the code box — a static password is a password.
3. Optionally type a PIN first, then long-touch (about three seconds).

**Expected:** the whole thing arrives verbatim — your prefix plus what the key typed, not truncated to
44 characters, not validated as modhex, not rejected. Its Return is swallowed, same as everything
else. The prompt must NOT call it a one-time code.

---

## Test 8 — Mutual exclusion

Each of these should make the security-key rows unavailable **with a sentence saying why**, not
silently:

| Do this | Expect |
|---|---|
| Turn **Requires a verification code** off | "This VPN doesn't ask for a verification code…" and the master switch disabled |
| Set the credential source to **1Password** or **KeePassXC** | "1Password already supplies this VPN's verification code…" naming the app |
| Set the credential source to **Apple Passwords** or **Keeper** | No conflict — neither promises a code |
| Add an authenticator setup key to a **Touch ID-protected** sign-in | "Your saved sign-in already covers the verification code…" |
| Unplug the key | A **note**, not a block — the setup still saves |
| Enable MDM `lockConfiguration` | Every row visibly locked, with the administrator named |

---

## Test 9 — VoiceOver (⌘F5)

The touch prompt must be **announced**, not merely animated. This is the half no automated test can
reach (`AccessibilityNotification.Announcement` leaves no trace in the tree).

1. Arm the wait. You should hear *"Touch your security key now. The cursor is in the verification code
   box, and SimpleVPN will not connect on its own."*
2. Touch the key. You should hear *"Verification code ready, from security key c c c c c c j j b b b
   b"* — spelled out, because a public ID read as a word is noise and the point is comparing it.
3. Let it time out: *"No code arrived from your security key."*
4. Press ESC: *"Stopped waiting for your security key."*
5. Consume a code and fail the connect: *"That verification code has been used. Touch your security
   key again for a fresh one."*
6. VO-focus the prompt itself. Its value should speak the state **and the countdown** — the countdown
   is in the value so it is spoken on focus, and deliberately not announced every second.
7. Tab through the section: every row named from its setting, the "Check Again" button named for what
   it checks, and the enablement banner's commands readable as content (not hover-only).

---

## Test 10 — Two keys

Plug in two. The section should count them and say how many will type. Set **Security Key Serial
Number** to one of them (`ykman list --serials`) and confirm the OATH/challenge mechanisms use that
one. A non-numeric serial must be ignored rather than passed on.

---

## What is fixture-tested versus really exercised

**Fixture-tested (no hardware, no `ykman`), and these all pass:**

- modhex: every byte round-trips; the alphabet; rejection of every non-modhex letter.
- Reading a code: the public-ID split (from the END, so a reprogrammed public-ID length still works),
  case normalisation, whitespace/newline trimming.
- Every near miss separately: layout-mangled (44 characters of the wrong letters), too short, too
  long (two touches), odd length (a dropped keystroke), and non-modhex at the wrong length — which is
  deliberately *not* blamed on the layout.
- The composition state machine: arming, partial codes staying silent, a second touch replacing the
  first, a code refused after a timeout, cancel versus timeout.
- **The trailing Return**, in every ordering the two events can arrive in, and at the exact grace
  boundary.
- **The single-use guard**: consume-once, a retry getting nothing, and the state saying a fresh touch
  is needed.
- Composition and the rescue path for a code that landed in the password box.
- The mutual exclusions, and that the stored setup holds no secrets.
- `ykman` output parsing from **recorded** fixtures whose formats are pinned to named sources: Yubico's
  own `ykman/_cli/{__main__,otp,oath}.py` (BSD-2-Clause) and the published CLI guide at
  `docs.yubico.com/software/yubikey/tools/ykman/`.
- KeePassXC's PKCS#7-to-64 padding at every length, verified against KeePassXC's own
  `YubiKeyInterfaceUSB.cpp`.

**NOT exercised — needs the hardware:**

- A real touch typing into a real focused field, and therefore the real trailing Return arriving as a
  real keystroke through AppKit. The policy is tested; the keystroke is not.
- Whether a gateway accepts any of it. **We cannot check a Yubico OTP** — it is verified by the server
  or by YubiCloud, which hold the key's AES secret. SimpleVPN checks the shape and carries the code,
  and no UI string claims more than that.
- `ykman` actually running (it is not installed here), so: the real exit codes, the real stderr
  wording behind the failure classification, and the real touch-required timing.
- The `ykman info` "Applications" block's exact column spacing, which Yubico does not publish. The
  parser is lenient about it and nothing important depends on it.
- IORegistry detection against a real key. The scan runs and returns cleanly on a machine with none;
  the product-id table is Yubico's own, but no row has been produced from real hardware.
- Announcement timing and wording as actually spoken.

## Privacy note, stated once

SimpleVPN **never reads your keyboard**. It takes no **Input Monitoring** permission and must never
take one: the key types into a field SimpleVPN has focused, so there is nothing to monitor. Detection
reads the IORegistry — the device list macOS already publishes — which needs no permission and opens
no device. If a future change appears to need `IOHIDDeviceOpen`, the design is wrong.

Nothing single-use is ever logged, put in `argv`, written to `providerConfiguration`, or kept after
use. The 12-character public ID *is* safe to display — Yubico publishes public IDs in cleartext by
design — and it is the only part of a code that ever appears on screen.
