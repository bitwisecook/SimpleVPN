# Sign-in sources

One map of every way SimpleVPN can get a sign-in, what each actually supplies, and what
has really been proven. Per-vendor setup lives in that vendor's own doc; this is the
overview and the honesty ledger.

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
