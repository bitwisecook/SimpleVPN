# Sign-in sources

One map of every way SimpleVPN can get a sign-in, what each actually supplies, and what
has really been proven. Per-vendor setup lives in that vendor's own doc; this is the
overview and the honesty ledger.

## The per-source docs — one index, two families

Every source with a doc of its own is listed here, and the filename prefix says which
family it belongs to. The distinction is not cosmetic: **a password app hands over a
secret; a security source proves possession without releasing one.** That is the
`.value` versus `.possession` split in `Docs/AuthArchitecture.md`, which is where the
reasoning lives — it is why a single `resolve() -> RawCredentials` seam could not express
all of them, and it is not restated here.

**`AuthPwd*` — password apps** (all ten; each doc ends in a manual test recipe):

| Doc | Source |
|---|---|
| `AuthPwd1Password.md` | 1Password, over the app's signed IPC |
| `AuthPwdBitwarden.md` | Bitwarden, over `bw serve` |
| `AuthPwdDashlane.md` | Dashlane, over `dcli` |
| `AuthPwdKeePassFile.md` | a KeePass `.kdbx` file — also Strongbox and KeePassium |
| `AuthPwdKeePassXC.md` | KeePassXC, over its browser protocol |
| `AuthPwdKeeper.md` | Keeper, through Keeper Commander |
| `AuthPwdLastPass.md` | LastPass, over `lpass` |
| `AuthPwdPassbolt.md` | Passbolt — a server, not a file |
| `AuthPwdPasswordStore.md` | `pass` / `gopass`, read with `gpg` |
| `AuthPwdProtonPass.md` | Proton Pass, over `pass-cli` |

**`AuthSec*` — security sources**, which never hand over bytes:

| Doc | Source | State |
|---|---|---|
| `AuthSecSSHAgent.md` | an SSH agent — it signs, and decides whether to | ✅ built |
| `AuthSecYubiKey.md` | security keys, including the one that *types* its answer | ✅ built |
| `AuthSecPKCS11.md` | smartcards, PIV and HSMs | ❌ **not implemented** |

The third row keeps its place in this group rather than being deleted, and the **State**
column exists because of it. Smartcard sign-in *was* built and was removed: it had never
been run against a real card or a real gateway, and finding out whether it worked would
have spent attempts from a PIN counter whose exhaustion destroys the key it protects. So
`AuthSecPKCS11.md` is no longer a description of a source — it is the record of **why**
(the OpenSSL/GnuTLS backend split, the AMFI `dlopen` prohibition, why a GnuTLS rebuild
would not have helped), what it would take to build properly, and where a use case
should go. Leaving it in the group is what stops the removal reading as an oversight.

Two sources deliberately have no doc of their own, because they have no vendor to
describe: **typing it each time** and **Save in SimpleVPN** (the Apple keychain). Apple
Passwords is covered below rather than separately — it is an AutoFill row, and the reason
is the first of the three findings.

## The rule that shapes all of it

**SimpleVPN never bundles or installs a vendor's tool.** It runs a program you installed
yourself, or speaks to one already running. Nothing is statically linked and no vendor
code is compiled in — so a feature simply does not appear when its tool is absent, and
the licence badge in About describes *that* project, not this one.

Two consequences worth stating plainly:

- **Discovery and execution are deliberately different.** `ToolDiscovery` searches widely
  — every package manager, version manager and vendor installer location, plus `PATH`.
  `LocalToolRunner` executes from an allow-list only and **never consults `PATH`**. The
  gap is a feature: it turns a misleading "not installed" into "found at
  `~/.bun/bin/bw`, but not somewhere SimpleVPN will run from — set an explicit path."
- **Secrets travel on stdout, or on stdin, and nowhere else.** Never argv (world-readable
  through `ps`), never a log line, never an error string, never a diagnostic bundle.

## The abstraction: three axes, and a plan rather than a secret

Built last, deliberately — after all twelve sources — so it could be derived from what
they converged on rather than guessed at. Three axes, and delivery is not one of them.

| Axis | Type | Grows when |
|---|---|---|
| **Kind** — what is wanted | `AuthKind` (`Shared/AuthKind.swift`) | a **protocol** needs a new sort of thing. Closed; every switch exhaustive. |
| **Transport** — the shape of the channel | `AuthTransport` | almost never. Nine shapes: five for vaults, plus keychain, AutoFill, agent, hardware. |
| **Vendor / source** — who holds it | `LocalVaultVendor`, `AuthSourceID` | freely. A thirteenth vendor is one file and adds nothing to the other two axes. |

`AuthKind` replaced **two** enums that overlapped by convention — `CredentialField` (four
cases, "what a source is asked for") and `CredentialRole` (seven, "what slot a VPN needs
filled"). The old header said the ids "reuse `CredentialField.rawValue` where they
overlap", and every profile's stored `fieldMap` is keyed on those strings. One enum makes
that structural; a test pins the raw values, because a rename would silently unmap
somebody's 1Password fields.

**The unified call returns a plan, not a secret** (`AuthPlan`). Three of the nine
mechanisms never hand over bytes, and a `resolve() -> RawCredentials` seam could not
express them — which is exactly why they sat outside the credential seam
with their own return shapes and error conventions:

- `.value` → the bytes (`RawCredentials`, unchanged: it was right for this delivery);
- `.possession` → a **name** — an agent socket path, a security-key slot number;
- `.typedByDevice` → an **armed capture**, because a security key *types* and focus
  management is therefore the whole feature.

`AuthSourceCatalog` declares all sixteen mechanisms in one table — supplies / proves /
**withholds**, transport, cardinality, delivery, probe ceiling — reading each vault's
transports and cardinality from the adapter that owns them, so the table cannot drift
from the code.

**Not modelled, and said so rather than fudged:** OpenConnect's conversational SSO and
Tailscale's control-URL sign-in. In both the *engine* authenticates and our whole role is
to open a browser; there is no credential to plan, name or arm. A `.conductedByEngine`
case is the shape they would take, and it is not added until something produces one.

### Where a failure lives

`AuthLocus` × `AuthCause` replaced "every caller gets a `LocalizedError` string out of
twelve different enums, and can do nothing with it". The locus is the three configuration
levels **plus a fourth**:

| Locus | Level | Example | Who fixes it |
|---|---|---|---|
| `.transport` | 1 | the binary is missing, nobody is signed in | Settings ▸ Sign-In Sources |
| `.instance` | 2 | the database has moved, the vault is locked | choose or re-point it |
| `.reach` | — | the server does not answer, TLS fails, its identity changed | **nobody** — it is the network |
| `.entry` | 3 | that entry does not exist any more | this VPN's sign-in settings |

`.reach` is the Passbolt finding. For a `.kdbx` the channel to the instance is free and
`stat` settles it, so levels 1 and 2 describe everything; for a **server** the channel is
a network, and reachability is none of "the tool", "the address" or "the entry". It
deliberately has no `configLevel`: there is no field anybody can go and correct, and
saying that is more useful than sending them to a screen where nothing would help.

There is deliberately **no `.reach` block**. Reach problems are never *probed* — see the
ceiling below — so they are learned at fetch time and arrive as an `AuthFailure`.

### `.unchecked` now says why it is unchecked

`AuthProbeCeiling` is the second Passbolt fix. The bare `.unchecked` said the same thing
about two states needing opposite handling:

- **the check is owed** (`.checkOwedOnUse`) — cheap, local, and picking the row pays it.
  1Password, Keeper, Bitwarden, Dashlane, Proton Pass, LastPass.
- **the check will never happen** — `.wouldSignInToServer` (Passbolt: a deeper probe is a
  real authentication attempt against somebody else's machine, spending their rate
  limiter from a background refresh nobody asked for), `.wouldPromptTheUser` (a `.kdbx`
  passphrase, GnuPG's pinentry), `.wouldSpendSingleUseCode` (burning a code to find out
  whether codes work).

`willBeProbed` is the distinction, and it is what stops a row promising "SimpleVPN checks
this when you pick it" about something nothing will ever check. A related bug went with
it: a vendor with no `uncheckedNote` of its own used to fall through with its state left
at `.ready`, so an unproven row announced itself to VoiceOver as "Ready to use".

### One question, one answer

`AuthSatisfaction` — `.ready` / `.unproven(ceiling)` / `.broken(locus:block:)` /
`.typedInstead(reason)` — replaced a `canServe(_:) -> Bool` that the connect form read
while the unattended reconnect path re-derived the same question its own way, from
different inputs, in a different file. `SignInSourceAvailability.satisfaction(for:)` owns
levels 1–3; `VPNController.authSatisfaction(for:)` adds only what a profile knows.

Everything goes through the same two calls: connect, the connect form, the unattended
reconnect, the editor's Test button — and the CLI and App Intents, which bottom out at
`connectUsingConfiguredSource` and so were covered for free.

## Three levels of configuration

Getting these confused is how "which vault" ends up unable to express "work and
personal". They are separate types, and a field's level is derived from its kind in one
exhaustive switch rather than decided per declaration.

| Level | What it answers | Where it lives |
|---|---|---|
| **Transport** | How we reach the vendor at all — binary path, socket, daemon endpoint, enable/disable | Per Mac, one per vendor |
| **Instance** | *Which* vault — which `.kdbx`, which store folder, which server | Per Mac, **one or more** per vendor |
| **Per VPN** | Which instance + which entry + optional username | In the profile, and never a secret |

Cardinality is a **fact about the vendor**, not a preference. A test asserts a
single-instance vendor has no instance-level fields, so a meaningless one-row list cannot
appear.

## The sources

| Source | Transport | Supplies | Instances | Notes |
|---|---|---|---|---|
| Type it each time | — | everything you type | — | The floor. Always available. |
| Save in SimpleVPN | OS keychain | username, password, TOTP | single | Apple keychain, protected by macOS. Touch ID optional. |
| Apple Passwords | OS AutoFill | username, password | single | **Fill, not fetch** — see below. |
| 1Password | signed IPC to the app | username, password, TOTP | single | The app does the unlocking; its password never reaches us. |
| KeePassXC | app socket | username, password, TOTP | single | Its browser protocol, reimplemented. |
| Keeper | local daemon → CLI | username, password | single | Commander. Its session lives in the OS keychain. |
| Bitwarden | local daemon (`bw serve`) | username, password, TOTP code | single | The CLI **cannot** read without a session key — see below. |
| KeePass file | file | username, password | **multiple** | Covers KeePassXC-as-file, Strongbox, KeePassium. |
| pass / gopass | file | username, password, TOTP code | **multiple** | Read with `gpg`; neither tool required. |
| Dashlane | CLI | username, password, TOTP code | single | Asked for JSON, because its console output can ask a question. |
| LastPass | CLI | username, password | single | Best-effort; its tool can supply no code at all. |
| Proton Pass | CLI | username, password, TOTP code | single | Needs a paid Proton plan — a first-class state, not a failure. |
| Passbolt | CLI | username, password, TOTP sometimes | **multiple** | Server-based; the only source we prompt for. |

### Three findings that changed a design

**Apple Passwords is read-mostly, and we cannot write to it at all.** Verified against the
macOS 26.6 SDK: `SecAddSharedWebCredential` is the only public path that lands an entry
there, it needs associated-domains *plus* the VPN server operator serving an
app-site-association file naming us, and it is deprecated at macOS 26.2 with a
macOS-unavailable replacement. Our own `SecItem` query also cannot see anything Safari or
Passwords manages — those live under an access group our entitlement does not hold. So
that row is an **AutoFill** row, and no UI anywhere implies saving into Apple Passwords.
What we do offer instead: the keychain on this Mac, optional iCloud Keychain sync *within
our own access group* ("your other Macs"), and a user-initiated `otpauth://` hand-off for
verification codes.

**The Bitwarden CLI cannot read a vault without a session key.** Its unlocked user key is
stored encrypted with `BW_SESSION`, so a `bw status` *we* run reports `locked` even for a
signed-in user whose own Terminal is unlocked. So `bw serve` is the fetch transport and
the CLI is only the state transport. We do not prompt for a master password — that would
falsify the promise that the vendor does the unlocking — and we do not persist a vault
key, so the CLI fetch path is **deliberately dormant** with its reasons stated.

**Three tools write the password to the clipboard, and each needed a different answer.**
Dashlane's `dcli` defaults to the pasteboard, so we ask for JSON instead — and JSON rather than
its console mode, because console output runs an interactive picker when two entries match, which
would hang against a closed stdin. LastPass prints to stdout by default, but its alias file can
prepend a clipboard flag to our own argv — its own manual suggests doing so — and there is no
counter-flag, so we read that file and *refuse to fetch*. Proton Pass has no clipboard code at
all. `pass show -c` exists and is simply never called.

**`pass` is read with `gpg`, not with `pass`.** `gpg` is far more likely to be installed
(it is here; `pass` is not), the store layout is a decade-stable documented format while
CLI output is not a contract, and it keeps us away from `pass show -c`, which puts a
password on the pasteboard. The guard that matters: with no graphical pinentry installed,
GnuPG cannot ask for a passphrase from inside an app and would wait forever, so we detect
that and run `--pinentry-mode error` — a cached passphrase still works, an uncached one
fails immediately with what to install.

## `suppliesOTP` is a promise, not a capability flag

It tells Connect that nothing will need typing. Being wrong costs a failed sign-in **and a
burned one-time code**, which some gateways count toward a lockout. So it is `false`
unless verified against a real vault: currently true only for 1Password and KeePassXC.

Every other source is `false` for one of three distinct reasons, and the difference matters:
*unproven* (Bitwarden, Dashlane, Proton Pass — the code arrives, nobody has watched it work),
*unknowable in advance* (pass/gopass, Passbolt, Dashlane again — whether a given entry carries a
seed cannot be known until the fetch has already happened, so a promise would be a claim about
the user's data), and *impossible* (LastPass — its tool's own JSON has no field for a code, and
Apple Passwords withholds codes from other apps by design). Only the last is permanent.
Several sources still *use* a code when the entry has one — that is not the same as
promising it.

## Maturity: what has actually been proven

`FeatureMaturity.swift` is the single registry, and flipping an entry to tested is a
one-line change with no view edits (asserted two ways, including a test that fails if any
view file contains a maturity decision at all).

Only **1Password** is claimed as a tested vault, because it is the only one installed on
the development machine. Everything else is `.untested`: written, reviewed, fixture-tested
against formats taken from each vendor's own published source — and never once run
against a real vault. That is not pessimism, it is the actual state, and a single user
report clears any given row.

**What has been proven for real**, and is worth distinguishing:

- the `pass` GPG round trip — a throwaway key and store, encrypted and read back through
  the real reader, in both pinentry modes;
- PKCS#11 enumeration against a real SoftHSM token through real `p11tool`;
- SSH agent authentication against a real `ssh-agent` and a real `sshd`;
- WireGuard's handshake against real vendored wireguard-go (no live tunnel).

## Testing a source you actually have

Each vendor's doc ends with a manual recipe. The general shape:

1. Settings ▸ Sign-In Sources — the row should show its real state, not "not installed".
2. Break it deliberately (rename the tool, lock the vault, point at the wrong folder) and
   check the sentence names the fix.
3. Connect. Then connect again, to confirm the returning flow does not re-ask.
4. Tell us either way — the Untested banner's report button collects the environment for
   you, with everything shown before it leaves the Mac.
