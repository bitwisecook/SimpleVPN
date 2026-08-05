# Proton Pass as a sign-in source

`SimpleVPN/Credentials/ProtonPassProvider.swift` · copy in `ProtonPassCopy.swift` · settings in
**Settings ▸ Sign-In Sources ▸ Proton Pass** · manual anchors `creds-protonpass-*`

**Nobody has run this against a live Proton account.** Neither Proton Pass nor `pass-cli` was
installed on the machine it was written on, and there was no Proton account to sign in to. Every
fixture in `SimpleVPNTests/Credentials/ProtonPassTests.swift` is quoted from Proton's own GPL-3
source with a file and function named per fixture. Everything below "Manual test recipe" is what a
person with a Proton Pass subscription should do to find out, and it is written to be followed
exactly — including the parts that are expected to fail.

## First: this is not the unix password store

Two different products sit next to each other in the sign-in list and their tools are named almost
identically.

| Row | Vendor | Tool SimpleVPN runs | Reads |
|---|---|---|---|
| **Proton Pass** | Proton AG | `pass-cli` | Proton Pass vaults, over Proton's API |
| **pass / gopass** | the unix password store | `gpg` (never `pass` itself) | a folder of GPG-encrypted files on this Mac |

Discovery searches **by binary name**, so the difference is load-bearing rather than cosmetic:
`ToolCatalog` carries three separate entries (`pass`, `gopass`, `pass-cli`) and only `pass-cli` is
mapped to the `protonPass` vendor. Nothing in the Proton Pass code resolves the bare name `pass`, and
nothing in the password-store code resolves `pass-cli`. The setting slugs are `protonpass` and
`passwordstore` — neither a prefix of the other — because those slugs are what an MDM payload names
when it allows or forbids a vendor.

`ProtonPassIsNotThePasswordStoreTests` exists to fail if any of that drifts.

## The shape of it

One channel, `.cli`. There is no daemon and no socket: `pass-cli` has an SSH agent, but that serves
keys to `ssh`, not usernames and passwords to us, so listing a second transport would claim a channel
that does not exist.

A fetch is **field by field**, not one JSON read. `pass-cli item view --field password …` prints that
field's value on stdout and nothing else (`pass-cli/src/commands/item/view.rs`), which is exactly the
shape `LocalToolRunner` is built around: the secret is on stdout, stderr carries only diagnostics, and
nothing has to be parsed out of an item schema we have never seen. `--output json` would hand back
every field of the item and tie us to that schema.

**Username or e-mail.** A Proton Pass login has both, and a field only exists when it is non-empty. So
SimpleVPN asks for `username` and, if the item has not got one, for `email`. A username typed into the
VPN's own profile wins over both and costs no extra run.

**Verification codes.** `item view --field totp` prints the current code (`TotpOutput::Code` is the
default). SimpleVPN uses it when the item has one and stays silent when it has not — but
`CredentialSourceKind.protonPass.suppliesOTP` is **false**, following Keeper's and Bitwarden's
precedent. That flag is a promise that Connect works with nothing typed, and nobody has watched a code
come back from a live account. Asking for a code you then do not need costs one keystroke; promising
one that does not arrive costs a failed sign-in.

**Nothing goes to the clipboard.** Established by absence and stated as such: Proton's repository
contains no clipboard code and no subcommand declares a `-c`/`--clipboard` flag. `noClipboardFlagIsEverPassed`
pins our side, so a future release that adds one does not find SimpleVPN already reaching for it.

## Naming an item, and the trade-off

Each VPN stores a `pass://` reference — a vault and an item, either of which may be a name or one of
Proton's identifiers. All of these are accepted:

```
pass://Work/GR Lab                    ← names
Work/GR Lab                           ← the same, without the scheme
pass://<share-id>/<item-id>           ← identifiers (88 characters, ending "==")
pass://Work/GR Lab/password           ← the field is DROPPED, deliberately
```

**Prefer the identifiers for a VPN you depend on.** They survive renames and moves; names do not.

**Names are not unique, and Proton's tool does not say so.** `find_item_by_name` takes the first
match (`pass/src/item/find.rs`), and Proton's own documentation confirms the consequence: "If there
are several objects that match the name, one of them will be used." There is no ambiguity error to
catch. So when the reference is by name, SimpleVPN lists the vault itself
(`item list --output json`, a listing Proton's own source marks as carrying no secret material),
counts exact title matches, and **refuses when more than one login carries the title** — then reads by
identifier. Reading the wrong sign-in is worse than failing to read one, which is the same rule the
KeePass file source applies to entry paths.

**A bare title with no vault is refused**, with a sentence that says why. `pass-cli` would search
whichever vault its own `settings set default-vault` names — something SimpleVPN cannot see and did not
choose — and then take the first match inside it. Two guesses to read a password with. Naming the vault
costs one word.

Titles are matched **exactly, case-sensitively**, because that is what the tool does. Being more
forgiving than the tool we are about to run would mean SimpleVPN resolving a name to one item and
`pass-cli` to another.

## The four states, and the fourth is a subscription

| State | What it means | The one fix |
|---|---|---|
| `toolMissing` | The Proton Pass app is here; `pass-cli` is not | `brew install protonpass/tap/pass-cli` |
| `toolOutsideAllowList` | `pass-cli` IS here, somewhere SimpleVPN will not run from | paste the path the banner shows into Settings |
| `notSignedIn` | No session file, or the API rejects the session | `pass-cli login` — **and check the plan** |
| `vaultLocked` | The session is gated by a lock code | `pass-cli session unlock` |
| `planExcludesTool` | Everything works and the plan does not include the tool | change the Proton plan, or use another source |

**The entitlement gate is a state, not an error.** Proton's command-line tool is part of Pass Plus,
Pass Family, Pass Professional and the Proton bundles. Somebody on a free plan can install it, watch it
start, and still be refused: Proton checks `Plan.cli_allowed` inside `pass-cli login`
(`pass/src/user/access.rs`), prints *"Your account is not yet allowed to use our CLI"*, and then
**logs the tool back out and exits 1**.

Two consequences, both deliberate:

1. SimpleVPN never runs `login` — signing somebody in to their password manager is not ours to do — so
   the state a free-plan account normally lands in is `notSignedIn`, because that is genuinely what the
   tool has been left in. **So the `notSignedIn` copy names the plan as one of its two reasons.**
2. The sentence is recognised wherever it appears on a `pass-cli` run's stderr, so it is never reported
   as a generic failure — in the chooser, in the editor's warning, at connect time, and in a diagnostic
   bundle (which says "not a fault on this Mac" in as many words, because a maintainer reading "not
   signed in" would start debugging a tool that is behaving correctly).

## The cheap probe

`quickScan` does **one `stat`**: is there a session file at
`~/Library/Application Support/proton-pass-cli/.session/session.json`? (`get_base_dir()` in
`pass-cli/src/utils.rs`; `PROTON_PASS_SESSION_DIR` moves it and is honoured.) No subprocess, no prompt,
no network, nothing spent — which is what lets the chooser refresh while it is on screen.

Its answer is **one-sided**. No file means definitely not signed in: the tool writes it on sign-in and
deletes it on sign-out. A file means a session existed once, not that the API still accepts it — so that
way round is `.unchecked`, and `deepScan` runs one `pass-cli info --output json` to earn `.ready`.
`deepScan` spawns nothing when the cheap pass already established a missing tool, a tool outside the
allow-list, or no session file.

Only `session_has_lock` is read out of `info`. It also prints the account's e-mail address and username,
and neither is anything SimpleVPN needs, keeps or reports — what is not read cannot leak into a
diagnostic bundle. Note the distinction Proton draws: "Having a session lock does not mean that the
session is locked at this moment", so a `true` there is never a blocked state.

## Configuration levels

* **Level 1 (transport, per Mac):** `creds.protonpass.tool-path` → `signin.tool.pass-cli.path`, plus
  the vendor switch `creds.protonpass.enabled`. That is all of it.
* **Level 2 (instance):** **none.** Proton Pass is single-instance — one session file, one signed-in
  account, no `--config`/`--account`/`--profile` flag anywhere in the command surface, and
  `pass-cli logout` is how you change accounts. A Proton account can hold several vaults, but a vault is
  named inside the item reference, which is level 3.
* **Level 3 (per VPN):** the `pass://` reference and an optional username. No secrets — there is no
  field one could go in.

MDM can pin the tool path (`SignInSourceToolPaths`), and allow or forbid the vendor by slug
(`SignInSourcesAllowed` / `SignInSourcesForbidden`, slug `protonpass`). See `Docs/MDM.md`.

## Install locations

Proton's installer script prefers `$HOME/.local/bin` and falls back to `/usr/local/bin`; the Homebrew
tap (`brew install protonpass/tap/pass-cli`) lands in the Homebrew prefix. All three are already on
`LocalToolRunner`'s list, so this feed needed no new location class. `PROTON_PASS_CLI_INSTALL_DIR` lets
a copy end up anywhere at all — which is exactly the case `toolOutsideAllowList` and the explicit-path
setting exist for, rather than something to guess at. See `Docs/ToolDiscovery.md`.

## Secrets: the route, in writing

* The password and the code arrive on the child's **stdout** and are returned as `RawCredentials`,
  which the connect path hands to the engine through `startTunnel(options:)`.
* **argv carries only** the item's identifiers and the field's NAME. `ps` shows argv to every process on
  this Mac. `nothingSecretIsEverAnArgument` asserts it over a whole fetch.
* Nothing travels the other way, so `LocalToolRunner`'s `stdin:` channel is unused and stdin stays
  `/dev/null`.
* Nothing reaches `providerConfiguration`, a log line, an error string, a defaults key or a diagnostic
  bundle.
* SimpleVPN never sets `PROTON_PASS_PASSWORD`, `PROTON_PASS_TOTP`, `PROTON_PASS_EXTRA_PASSWORD` or
  their `_FILE` variants. Proton's own documentation warns that a password in an environment variable is
  "readable by all other processes under the same session", and SimpleVPN holds none of those secrets
  anyway. `theSecretBearingEnvironmentVariablesAreNeverSet` pins the names.
* The **deadline is load-bearing**, not a nicety: `pass-cli`'s prompt helper loops on an empty answer
  (`pass-cli/src/utils.rs`), so a tool that decided to prompt against `/dev/null` would spin rather than
  stop. `LocalToolRunner`'s hard deadline plus SIGKILL is what makes that bounded. The read path is not
  supposed to prompt at all — only `login`, `session unlock` and the extra-password step do.

## Manual test recipe

You need: a Proton account **on a plan that includes the CLI** (Pass Plus, Pass Family, Pass
Professional, or a Proton bundle), a login item with a username and a password, and a VPN in SimpleVPN
that signs in with a username and password.

### 1. Before installing anything

1. Open **Settings ▸ Sign-In Sources**. Proton Pass should read *not installed* — or, if you have the
   Proton Pass app, *its app is here but the command-line tool is not*, with `brew install
   protonpass/tap/pass-cli` shown.
2. In the sign-in chooser for a VPN, confirm Proton Pass appears **either** as a source row with that
   setup state **or** as a pointer under "Other password apps on this Mac" — never both. If it appears
   twice, that is a bug in `PasswordAppCatalog.gatedVendor`.

### 2. Install, and check the path handling

```sh
brew install protonpass/tap/pass-cli
pass-cli --version
```

3. Settings should now say Proton Pass is *installed and reachable, never proven end to end*, and the
   row should be offered.
4. **Deliberately break it**, to exercise `toolOutsideAllowList`:
   ```sh
   mkdir -p ~/pp-elsewhere && cp "$(command -v pass-cli)" ~/pp-elsewhere/
   brew uninstall pass-cli
   ```
   The row must now say the tool **is** installed, name `~/pp-elsewhere/pass-cli`, and offer the path to
   paste. It must **not** say "not installed". Paste the path into **Proton Pass CLI location**; the row
   should go back to being offered. Then reinstall with Homebrew and clear the field.

### 3. Not signed in

5. With the tool installed and `pass-cli logout --force` run, the row must say *isn't signed in* and its
   steps must mention **both** `pass-cli login` **and** the plan requirement. Note that no network
   request was made to reach that answer — the session file simply is not there.

### 4. Sign in

```sh
pass-cli login          # opens your browser
pass-cli info
pass-cli vault list
```

6. Settings should flip to **ready** within a couple of seconds without restarting SimpleVPN.
7. Watch for a keychain prompt. `pass-cli` keeps its local encryption key in the macOS keyring, and
   whether accessing it from a child process SimpleVPN spawned behaves exactly as it does from your own
   Terminal is **unverified**. If macOS asks, note the exact wording and which binary it names.

### 5. Fetch, by name and then by identifier

8. In the VPN's **Sign-In** tab, choose Proton Pass and type `<YourVault>/<Your Item>`. Press **Test**.
   Expect the username and password to come back.
9. Connect. The password should be used with nothing typed except a verification code, if the VPN needs
   one.
10. Now switch to identifiers. Get them from `pass-cli item list --vault-name "<YourVault>" --output json`
    and use `pass://<share_id>/<item_id>`. **Test** again. This path should make **no** `item list` call
    — which you can confirm because it is noticeably faster on a slow link.
11. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` while you do all of
    this. The only Proton Pass line should be `proton pass item resolved for <profile>`. **No password,
    username or code may appear anywhere.**

### 6. The failures, on purpose

12. **A bare title.** Type just `<Your Item>` with no vault. Expect a refusal naming the vault-and-item
    form and saying that Proton would otherwise pick the first match. Not a lookup.
13. **Several matches.** Create a second login in the same vault with **the same title**. Test with the
    name. Expect *"2 Proton Pass items in that vault are called the same thing"* and advice to use the
    identifiers. **It must not read either one.** Delete the duplicate afterwards.
14. **A title that does not exist.** Expect the title and the vault both named, and a note that titles
    match exactly.
15. **A vault that does not exist.** Expect the same "no such item" shape, not a channel error.
16. **An item with no password** (a secure note, or a login you have emptied). Expect *"has no password
    in it"*, naming the item.
17. **A locked session.**
    ```sh
    pass-cli session create-lock --idle-timeout 30
    pass-cli session lock
    ```
    The row must say *signed in, but locked* and point at `pass-cli session unlock` — **not** "not
    signed in". Then `pass-cli session unlock` and `pass-cli session remove-lock`.
18. **A dead session.** `pass-cli logout` while SimpleVPN is open. Within a couple of seconds the row
    must go back to *isn't signed in*, and a connect attempt must offer the recovery notice ("type your
    sign-in once to connect now, or choose another way") rather than failing silently.

### 7. The one thing this recipe cannot test on a paid plan

19. **The entitlement gate.** On a plan that includes the CLI you cannot reach it. If you have access to
    a **free** Proton account, run `pass-cli login` with it and capture the exact stderr. What SimpleVPN
    matches is the substring *"allowed to use our CLI"*. If Proton's wording has changed, that is the
    one string to update — `ProtonPassWire.state(exitCode:stderr:)`.
20. Whatever you find, check that SimpleVPN's message for that state says the word **plan** and says
    nothing is broken on this Mac. The whole point of the state is that nobody spends an afternoon
    debugging a subscription.

### 8. Accessibility

21. With VoiceOver on, walk the Proton Pass row in the chooser in each state. Each must be **one
    sentence**, not five fragments, and must say what the state is. The enablement banner's commands and
    its link must be read as content — they are never hover-only.
22. On the entitlement row, confirm the spoken summary contains "Pass Plus": the plan is the single most
    useful thing that row can say, and a VoiceOver user must hear it.

## What to write down

Whatever happens, record it in `SimpleVPN/ControlPlane/FeatureMaturity.swift` at
`.vault(.protonPass)` — what was proven, and what was not. The line is currently `.untested` with the
split spelled out; a totality test fails the build if it goes missing.
