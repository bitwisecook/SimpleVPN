# Passbolt as a sign-in source

`SimpleVPN/Credentials/PassboltServer.swift` (how a server is read) ·
`SimpleVPN/Credentials/PassboltProvider.swift` (the two seams) ·
`SimpleVPN/Credentials/PassboltCopy.swift` (everything a user reads) ·
settings in **Settings ▸ Sign-In Sources ▸ Passbolt** · manual anchors `creds-passbolt-*`

**Nobody has run this against a live Passbolt server.** Passbolt is not installed on the machine it
was written on and there is no Passbolt server anywhere near it. Everything above "Manual test
recipe" is derived from `passbolt/go-passbolt-cli`'s own source and its own `internal/testdata`,
with the file named per claim; everything below it is what a person who *has* a Passbolt should do to
find out, including the parts that are expected to fail.

## The shape of it

Passbolt is a **server**. It is the first sign-in source here whose level-2 instance is not a thing
on disk, and that single fact drives most of the design below.

| Level | What it is | Where it lives |
|---|---|---|
| 1 — transport | where the `passbolt` program is, and the vendor's on/off switch | app settings, one per Mac |
| 2 — instance | **one server**: its `https` address, plus which of the program's own setup files holds that server's key | app settings, one *or more* per Mac |
| 3 — per VPN | which server, plus which resource (a UUID, or a name), plus an optional username | the profile |

SimpleVPN reaches it through Passbolt's own command-line program and nothing else — there is no
daemon, no socket and no library. `LocalVaultTransport` is `[.cli]`.

## The program has two names, and both are real

* `brew install passbolt/tap/go-passbolt-cli` — the tap's formula ends `bin.install "passbolt"`, so
  the **formula** is `go-passbolt-cli` and the **binary** is `passbolt`.
* `go install github.com/passbolt/go-passbolt-cli@latest` names the binary after the module, so it
  lands as `go-passbolt-cli` (usually `~/go/bin`, which discovery's `goBin` class already covers).

The cobra root command is `Use: "passbolt"` either way (`internal/cmd/root.go`), so the subcommands
are identical. Discovery searches **both** names and maps both to the Passbolt vendor — searching one
would report "not installed" for a perfectly ordinary install. There is one settings row, pointing at
`passbolt`; a full path typed into it may legitimately end in `go-passbolt-cli`, because
`LocalToolRunner.userConfiguredPath` checks that a path is absolute and safe, not what the file is
called.

## Where the passphrase lives, and how it travels

A Passbolt sign-in is OpenPGP: a server address, an armoured private key, and that key's passphrase.
Two separate questions, and conflating them is how this got designed wrong the first time.

### How it travels — one route, and it is not negotiable

| Route | Used? | Why |
|---|---|---|
| **the program's stdin** | **yes, and only this** | `util.ReadPassword` (`internal/util/client.go`) reads a line from stdin whenever stdin is not a terminal, so `LocalToolRunner`'s `stdin:` channel is a supported, documented way in. Decided in one place, `PassboltCLI.run`. |
| `--userPassword` on argv | **never** | argv is world-readable through `ps`. A passphrase there is a passphrase published to every process on the Mac. |
| the environment variable | **never** | viper is initialised with `AutomaticEnv()` and **no prefix and no key replacer**, so the variable is the bare, un-namespaced `USERPASSWORD`. That is the route somebody automating this in a script reaches for. `LocalToolRunner` builds the child environment from scratch, so SimpleVPN could not deliver it even if it wanted to — and a `USERPASSWORD` exported in your shell will **not** make a fetch from SimpleVPN work. |

`PassboltPassphrase` has **no API that hands back its characters** except `stdinLine()`, which
appends the newline `bufio.Reader.ReadString('\n')` requires — without it the program returns a read
error, which reads to a user as "wrong passphrase". So "never in argv" is structural rather than a
habit: there is nothing to interpolate. A passphrase containing a line break is refused **before
anything is spawned**, because the program reads exactly one line and would otherwise report it as a
rejected sign-in.

### Who holds it — nowhere by default, Touch ID by opt-in

This is a **VPN client on somebody's laptop**, not server infrastructure, and the tiers are the
`.kdbx` source's for the same reasons (`PassboltUnlock.swift`, `KeePassUnlock.swift`):

1. **DEFAULT: nowhere.** Typed once per *run* of SimpleVPN — not once per connect — held in memory,
   gone when the app quits.
2. **OPT-IN: the Touch ID keychain, and only that one.** Never an ordinary keychain item, which would
   let this app open somebody's whole Passbolt silently any time it liked. `.userPresence` means
   macOS will not release it without a fingerprint, an Apple Watch or the account password — a bar a
   background process cannot clear on its own. **Off by default.**
3. **Already in Passbolt's own config file: honoured, not recommended.** `passbolt configure
   --userPassword` writes one there (viper creates the file `0600` and re-`chmod`s it `0600` on every
   run). If somebody has it set up that way it keeps working and SimpleVPN needs nothing — breaking
   an existing setup to make a point would be worse than the point. But it is not what the app steers
   anyone towards, and no copy advertises it.
4. **Never** `providerConfiguration`, a defaults key, a log line, or argv.

**Why not the config file as the primary answer?** Because a long-lived passphrase sitting at rest in
a plaintext file is what an *operator* provisions for a job that runs with nobody watching.
`go-passbolt-cli` is used that way in CI by plenty of people, and that is not this use case. The
affordance a person on a Mac recognises is a Touch ID sheet, or typing a passphrase once when they
open the app — and it is also better protected, because the keychain item cannot be read without the
person present.

**Why hold it at all, given the "don't own a prompt you shouldn't" rule?** Because for Passbolt there
is no other human-facing owner *at connect time*. The program's own prompt exists only on a terminal;
from a GUI app there is no Passbolt sheet to defer to. So the choice is between a long-lived secret at
rest and one typed per app run, and the second is what the `.kdbx` source already does for a secret
of exactly the same blast radius. (Bitwarden is the case where deferring IS possible — `bw serve`
holds the unlock — which is why that feed stays dormant instead.)

Kept **per server**, not per VPN: it is the key's passphrase, so several VPNs reading one Passbolt
share it. The keychain account is `"passbolt:" + SHA256(normalised address)` — hashed because a
keychain item's account is visible in Keychain Access and an address names an employer. The address
is normalised (lower-cased, trailing slashes dropped) so typing a slash later does not silently lose
a remembered passphrase.

**Cancelling the Touch ID sheet is its own state** (`PassboltError.cancelled`), never a rejected
sign-in, and it is never retried: a retry would count against the server's own limit on failed
attempts for something that was the user's decision.

**And with nothing at all**, the source is visibly dormant: `PassboltError.passphraseUnavailable`,
whose sentence points at the field in Settings. **Nothing is spawned** in that state — a sign-in
that is going to ask for input we cannot give is still an authentication attempt against somebody's
server. Even if one were, stdin is `/dev/null` and the program hits EOF and fails at once rather than
waiting for input that can never arrive: the same bounded-failure shape as `--pinentry-mode error` in
the `pass` reader.

### No unattended paths

There is no service account here, no machine identity, no long-lived token to provision, and no code
path designed to work while nobody is logged in. `--mfaMode none` is passed rather than
`noninteractive-totp` precisely because the latter needs the verification code's **seed**, which
beside the passphrase is not a second factor at all — it is the arrangement an automated job would
use, and it would quietly undo the reason for having MFA on.

## Certificate verification is not negotiable

`internal/util/http.go` is the whole of the program's TLS decision:

```go
TLSClientConfig: &tls.Config{ Certificates: []tls.Certificate{cert},
                              InsecureSkipVerify: tlsSkipVerify },
```

`tlsSkipVerify` comes from one flag, `--tlsSkipVerify` ("Allow servers with self-signed
certificates", `internal/cmd/root.go`). **SimpleVPN never passes it, and there is no setting that
could.** Never emitting the flag is therefore the entire control, and a test asserts it is never
emitted.

Self-hosting is the *normal* case for Passbolt, so the pressure to add that toggle is real — and a
toggle like it, once present, ends up switched on across an estate. The supported answer for a
**private certificate authority** is to trust the CA on this Mac (System Settings ▸ Keychain Access ▸
System ▸ add the CA, mark it *Always Trust*), which fixes it for every program at once. The app's
copy and the certificate error sentence both say that and neither hints that the check could be
skipped.

*Unverified:* whether Go's `crypto/x509` on darwin honours `SSL_CERT_FILE` / `SSL_CERT_DIR` as an
alternative to the system trust store. It does not matter for us either way — `LocalToolRunner`
passes neither variable — but it means "put the CA in a file and point an environment variable at it"
is **not** a workaround anybody should be told about here. The check that would settle it is a run
against a private-CA Passbolt with and without those variables set.

Also worth knowing: the program's `Transport` uses `http.ProxyFromEnvironment`, and
`LocalToolRunner.childEnvironment()` passes no proxy variables — so a fetch from SimpleVPN never goes
through an `HTTPS_PROXY` the user's shell has set, even when their own `passbolt` runs do.

## Read-only, by construction

The only subcommands `PassboltReader` can build are `get resource` and `list resource`.
`create`, `update`, `delete`, `share`, `move` and `export` are unreachable, and a test asserts it.

`verify` is in that list too, deliberately: it **writes the program's config file**
(`viper.WriteConfig()`), and writing another program's configuration is not SimpleVPN's business.
`passbolt verify` is worth running — it makes the program check the server's own OpenPGP identity on
every sign-in as well as its certificate — but it is the *user's* one-time command, shown in the
enablement banner, never ours. SimpleVPN reports whether it has been run (`serverVerifyToken` is
present in the config) and never requires it.

## Addressing a resource: UUID or name

| | Stable across edits? | Ambiguous? | Secret? |
|---|---|---|---|
| UUID (`--id`) | **yes** — a rename, a move between folders, a permission change all leave it alone | never | no. It identifies a row; it does not open it |
| name | no — it changes the moment anybody renames it | **yes**, names are not unique | no |

SimpleVPN decides from the *shape*: 8-4-4-4-12 hex is an id, anything else is a name. So pasting an
identifier just works and nobody has to be told about a mode switch. `UUID(uuidString:)` is
deliberately **not** used — it also accepts a braced form, which the server would then not recognise.

A **name** is resolved by listing and matching in Swift, not by the program's `--filter`:

* `--filter` takes a **CEL expression** (`internal/cmd/list.go`). Building one out of text somebody
  typed means quoting their text into a small language, and that is a class of bug worth not having.
* The listing asks for `-c id -c name -c username -c uri` — none of which is secret-bearing, so
  `RequiresSecrets` stays false, the server never joins secrets in, and "which one did you mean"
  costs a metadata read and never a password.
* **Several matches is an error**, never a choice made for the user. Reading the wrong sign-in
  because two resources share a name is worse than failing; the message names the count and says to
  use the identifier instead.

## What "available" can honestly mean for a server

The `.kdbx` and `pass` sources settle a level-2 question with a `stat`. A server cannot be probed
without talking to it, and talking to a Passbolt server means completing an OpenPGP sign-in — an
authentication attempt, against somebody else's machine, with somebody else's rate limiter and
lockout policy.

So `PassboltVaultAdapter.deepScan` adds **nothing**, and the best a background pass can offer is
`.unchecked` — "set up, and ready to try". The row's `uncheckedNote` says exactly that, and says why.
A real sign-in happens when the user presses **Test** in the editor, or when a VPN connects.

The cheap probe is filesystem-only: `LocalToolRunner.locate` for the binary (a `stat` per candidate
directory), `PassboltServerLocation.validate` on the address (pure string work), and one read of the
program's config file for **key names only** — the scanner keeps the text before the first `=` and
discards the rest inside the loop, so no value is ever assigned anywhere. That is what lets these be
three different sentences with three different fixes:

| State | Block | The one thing the user does |
|---|---|---|
| the program is not installed | `toolMissing` | `brew install passbolt/tap/go-passbolt-cli` |
| it is installed somewhere we won't run from | `toolOutsideAllowList` | paste the path into the settings row (the banner names it) |
| no server address yet | `noServerConfigured` | type the address |
| the program has no key for this server | `notSignedIn` | `passbolt configure …` once |
| a key, and nothing to unlock it | `vaultLocked` | type the passphrase in Settings (Touch ID optional) |
| set up, never proven | `.unchecked` | press **Test**, or connect |

The cheap probe also asks `PassboltPassphraseStore.couldSupply`, which answers "held for this run, or
remembered behind Touch ID" **without prompting**. That distinction matters: a background refresh
must never raise a Touch ID sheet, because an unexplained sheet from nowhere is exactly what teaches
people to click through them. The sheet appears only on a connect the user asked for.

Everything past that point is a **fetch error**, not an availability state, because only a real
sign-in produces it: server unreachable, certificate not trusted, server identity changed, sign-in
rejected, a verification code required, resource not found, several matches, timed out.

## Two servers, one broken

`go-passbolt-cli`'s config holds exactly **one** `serverAddress`, one key and one passphrase — which
is precisely why a second server needs a second config file and `--config`, and why that file path is
an *instance* setting rather than a per-Mac one:

```
passbolt configure --config ~/passbolt-work.toml \
  --serverAddress https://passbolt.work.example.com \
  --userPrivateKeyFile ~/keys/work.asc
```

Each server is probed on its own. The vendor row is the **best** of them (the registry's `max` over
`rank`), so a work server you cannot reach today does not hide a personal one that works — hiding it
would be a lie — and the per-server answers ride alongside so the pane, the chooser and a diagnostic
report can each say which is which.

## What is stored, and what a report says

Settings hold an address, a file path and a binary path. A profile holds
`{kind, instanceID, reference, account}`. **Neither is a secret and there is no field one could be
put in** — the passphrase is not a setting: it is in memory, or it is a keychain item's existence, and
that is exactly why it is an `extraSpec` rather than a `VendorConfigField`. A diagnostic report says
whether the config file *has* a key and *has* a passphrase — two Booleans — and never a path from
inside it, never its contents, and never the server's address.

MDM can pin every level: `SignInSourcesAllowed` / `SignInSourcesForbidden` for the vendor,
`SignInSourceToolPaths` for the binary, `SignInSourceInstances` for the server list (which then
becomes read-only), and `SignInSourceForbidAddingInstances` to stop more being added. See
`Docs/MDM.md`.

---

# Manual test recipe

You need: a Mac, and a Passbolt server you can sign in to. **Nothing below has been run.** Report
what happens, including which steps fail — a failure with its exact sentence is as useful as a
success.

## 0. Before you start

Note which of the two program names you end up with:

```
brew install passbolt/tap/go-passbolt-cli
which passbolt go-passbolt-cli
```

Then, in SimpleVPN, open **Settings ▸ Sign-In Sources ▸ Passbolt**. The tool-path row should show
your path as *detected* (grey placeholder, not a value). If it says "installed, but not somewhere
SimpleVPN will run it from" and names a path, that is the `toolOutsideAllowList` state working — note
the path and carry on by pasting it into the row.

## 1. Tool missing

Before installing anything (or with the tool moved aside), a VPN set to Passbolt should say **"Passbolt's
own program isn't installed on this Mac"** with `brew install passbolt/tap/go-passbolt-cli` in the
banner. It must **not** say "not installed" if `which` finds one anywhere.

## 2. Outside the allow-list

```
mkdir -p ~/somewhere-odd && mv "$(which passbolt)" ~/somewhere-odd/
```

Expect **"Passbolt's own program is installed, but not somewhere SimpleVPN will run it from"**, with
your exact path in the banner and a Settings row to paste it into. Paste it; the row should say
"SimpleVPN doesn't look in this folder on its own — it will use this one because you chose it".

## 3. No server configured

Remove the server address in Settings. Expect **"No Passbolt server set up yet"**. Then type these,
one at a time, and note the sentence each gives:

* `passbolt.example.com` — expect "that is not a web address"
* `http://passbolt.example.com` — expect a refusal that **names https**
* `https://me:secret@passbolt.example.com` — expect "take the name and password out of the address"
* `https://passbolt.example.com` — expect "Ready to use."

## 4. Server unreachable

Point a server at an address that does not answer (an unrouteable IP is easiest:
`https://192.0.2.1`). Connect. Expect **"SimpleVPN couldn't reach your Passbolt server"** — *not* a
passphrase or certificate message. Then unplug the network and try a real address; note whether the
sentence changes.

## 5. TLS failure, and a private CA

If your Passbolt uses a certificate from your organization's own authority, try it **before**
trusting the CA. Expect **"Your Passbolt server's certificate isn't trusted by this Mac"**, naming
the keychain fix, and explicitly saying SimpleVPN will not skip the check. Then add the CA to the
System keychain and mark it *Always Trust*, and try again.

**Confirm there is no way to skip verification** — search the settings pane, look for any toggle, and
confirm the failure sentence never suggests one. If any of those is not true, that is a bug worth
reporting loudly.

If you have no private CA, an expired-certificate host reaches the same state.

## 6. Not set up

Move the program's config file aside:

```
mv ~/Library/Application\ Support/go-passbolt-cli/go-passbolt-cli.toml{,.bak}
```

Expect **"Passbolt's own program isn't set up for this server"**, with `passbolt configure` in the
banner. Put it back afterwards.

## 7. The passphrase — dormant, typed, and remembered

Set the program up **without** a passphrase (this is the recommended setup):

```
passbolt configure --serverAddress https://passbolt.example.com \
  --userPrivateKeyFile ~/keys/mine.asc
```

**(a) Dormant.** With nothing typed in SimpleVPN, expect **"Your Passbolt key needs its
passphrase"**, and a banner that says where it goes and that it is kept nowhere by default. **The
important thing to check is that it fails immediately** — no spinner, no hang, and no prompt from
anywhere.

**(b) Typed, held for this run.** Type it in **Settings ▸ Sign-In Sources ▸ Passbolt ▸ Passbolt key
passphrase** and press **Use**. The row should say "Held until SimpleVPN quits." Connect. Then quit
and reopen SimpleVPN and confirm you are asked again — that is the default working as intended.

**(c) Remembered behind Touch ID.** With a passphrase held, turn on **Remember the passphrase with
Touch ID**. Quit and reopen SimpleVPN, then connect: expect exactly **one** system prompt, naming
Passbolt. Connect a second time in the same run and expect **no** second prompt.

**(d) Cancel the prompt.** Expect **"Nothing was read from Passbolt — you cancelled."** It must *not*
say your passphrase was wrong, and it must not retry.

**(e) A wrong passphrase, once.** Expect **"Your Passbolt server wouldn't accept that key and
passphrase"** — a *different* sentence from (a). Note whether your server counts that against a
lockout; SimpleVPN will not retry it, and that is deliberate. Then use **Forget This Server's
Passphrase** and confirm both the run's copy and the keychain item go.

**(f) A passphrase with a line break** (paste one in). Expect SimpleVPN to say so when you type it,
and to say nothing is wrong with your key.

**(g) The file route still works.** If you already had `--userPassword` in the program's config,
confirm SimpleVPN reads without asking you for anything, and that the row says Passbolt's own program
already has one rather than claiming nothing is set up.

**(h) The environment variable does not.** `export USERPASSWORD=…` in your shell, relaunch SimpleVPN
from the Finder, and confirm it still asks — that is `LocalToolRunner` building a clean environment,
and it is deliberate.

## 8. Verification codes

If your account has MFA on, expect **"Your Passbolt account asks for a verification code, and
SimpleVPN can't supply one"**. It should not hang and should not ask you for one. Confirm the connect
form still lets you type a code for the *VPN* — that is a different code and a different thing.

## 9. Resource not found, and several matches

* A well-formed UUID that does not exist: expect "Your Passbolt server has nothing called …".
* A name that matches nothing: expect "Nothing in your Passbolt server is called …".
* **Create two resources with the same name**, point a VPN at that name, and expect a refusal that
  names the count and tells you to use the identifier. It must **not** pick one.
* Then use the identifier of the one you want and confirm it works.

## 10. Two servers, one broken

Add a second server in Settings with its own config file (see above). Give one a good address and one
a bad one. Confirm:

* the Passbolt **row** is still offered;
* the pane shows them **separately**, with different sentences;
* a VPN pointed at the good one connects while the bad one is still broken;
* removing a server that a VPN uses **names that VPN first**, and says nothing on the server changes.

## 11. A verification code from Passbolt itself

If you have a Passbolt resource of a TOTP-bearing type, point a VPN at it and see whether the code is
filled in. `suppliesOTP` is `false`, so SimpleVPN will still *ask* for one — it fills it in when the
resource happens to carry it. Report whether it did, because that is what would justify flipping the
promise.

## 12. Read-only, confirmed from the other side

After all of the above, check in Passbolt's own activity log (or `passbolt list resource`) that
**nothing was created, changed, shared, moved or deleted**, and that
`~/Library/Application Support/go-passbolt-cli/go-passbolt-cli.toml` still has the modification time
it had before SimpleVPN ran. SimpleVPN never writes that file; if its timestamp moved, something is
wrong.

## What to report

The exact sentence for each numbered step, whether anything hung, and — for step 5 — whether a
private CA worked once trusted on the Mac. That is what flips
`FeatureMaturityRegistry.signInSources[.vault(.passbolt)]` off `.untested`.
