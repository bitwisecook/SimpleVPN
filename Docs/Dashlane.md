# Dashlane as a sign-in source

`SimpleVPN/Credentials/DashlaneProvider.swift` · copy in `SimpleVPN/Credentials/DashlaneCopy.swift` ·
settings in **Settings ▸ Sign-In Sources ▸ Dashlane** · manual anchors `creds-dashlane-*`

**Nobody has run this against a live Dashlane vault.** Neither Dashlane nor `dcli` was installed on
the machine it was written on: no device has ever been registered, no vault has ever answered, and no
Touch ID sheet has ever been raised by it. Everything below the "Manual test recipe" heading is what
a person with Dashlane should do to find out, and it is written to be followed exactly — including
the parts that are expected to fail.

## The one decision this source is built around

`dcli password` **copies the password to your clipboard by default.** That is the vendor's own
declaration, in `src/commands/index.ts`:

```
program.command('password').alias('p')
  .description('Retrieve a password from the local vault and copy it to the clipboard')
  .addOption(new Option('-o, --output <type>', …)
      .choices(['clipboard', 'console', 'json']).default('clipboard'))
  .addOption(new Option('-f, --field <type>', …)
      .choices(['login', 'email', 'otp', 'password']).default('password'))
```

A VPN password on the pasteboard is readable by every program on this Mac, so that mode is the one
thing SimpleVPN may never invoke. There are two ways out, both in
`src/command-handlers/passwords.ts` (`runPassword`):

```js
if (output === 'json') { logger.content(JSON.stringify(foundCredentials)); return; }   // ← we use this
…
const selectedCredential = await selectCredential(foundCredentials, Boolean(filters?.length));
…
if (output === 'console') { logger.content(result); return; }
const clipboard = new Clipboard();
clipboard.setText(result);                                                            // ← never reached by us
```

**SimpleVPN runs `dcli password --output json -- <filter>`.** Both `json` and `console` return before
the `Clipboard` is constructed, so either would keep the password off the pasteboard — but `json`
returns before `selectCredential` as well, and `selectCredential` calls `askCredentialChoice`, an
**interactive list prompt**, whenever more than one entry matches. SimpleVPN spawns tools with
`/dev/null` on stdin (`LocalToolRunner`), so a prompt can never be answered: `--output console` would
work for a filter matching one entry and hang for a filter matching two. `--output json` prints every
match and SimpleVPN picks by username itself, which is also the only way to express "the admin login
on that entry, not the personal one". Bitwarden's channel lists-then-picks for the same reason.

Consequences worth knowing:

* the whole match set (with passwords) arrives on stdout, which `LocalToolResult` already treats as
  secret-bearing — never logged, never quoted in an error, never in a diagnostic;
* **only the filter rides argv**, after `--`. `ps` shows argv to every process on this Mac, and the
  filter is the user's own label for the entry;
* no `--field` is passed: the `json` branch returns before the field switch, so a field flag would be
  a lie about what was asked for.

## What has to be true before a fetch is attempted

`runPassword` calls `connectAndPrepare({})`, which will call `askMasterPassword()` **on stdin** when
the local key is not in the OS keychain (`getLocalConfigurationWithoutKeychain` in
`src/modules/crypto/keychainManager.ts`). With `/dev/null` on stdin that question can never be
answered, so SimpleVPN **checks the state first and refuses to spawn a fetch against a locked
vault** — "locked" becomes a sentence with a fix, rather than a connect that stalls and then says
nothing useful. The `pass` source reached the identical conclusion about gpg's pinentry.

The state probe is `dcli status`, and it is genuinely cheap: `runStatus`
(`src/command-handlers/status.ts`) never calls `connectAndPrepare`, so it cannot prompt, cannot verify
user presence and cannot synchronise. It prints either

```
Logged in: no
```

or

```
Logged in: yes
Login: you@example.com
Locked: yes|no
```

`Locked` is computed by `isVaultLocked` from three facts: the master password is not to be saved, or
there is no encrypted master password in `dcli`'s database, or the OS keychain holds no local key for
that login. SimpleVPN reads the two boolean lines and **drops the email address on the floor** —
nothing needs it, so it cannot reach a report.

## Where the keychain and the fingerprint come in

* The local key is an **OS keychain item**: `new Entry('dashlane-cli', <login>)` from
  `@napi-rs/keyring` (`src/modules/crypto/keychainManager.ts`). Dashlane puts it there by default;
  `dcli configure save-master-password false` stops it, and then Dashlane asks for the master
  password on **every** run — which SimpleVPN cannot answer, so the row reads "locked" instead.
* `dcli lock` deletes that keychain item and nulls the stored encrypted master password. So locking
  takes effect immediately as far as SimpleVPN is concerned; nothing is cached on our side.
* With `dcli configure user-presence --method biometrics`, **Dashlane raises the Touch ID sheet
  itself** — `promptTouchID({reason: 'validate your identity before accessing your vault'})` in
  `src/modules/auth/userPresenceVerification.ts`, in `dcli`'s own process. SimpleVPN neither raises
  it nor sees its result; it waits, with a deadline. There is no path here that asks anyone for a
  Dashlane master password.

## A fetch may go to the network

`connectAndPrepare` synchronises the vault when the last sync is over an hour old and auto-sync has
not been switched off, so an occasional `dcli password` is a sync as well as a read. Two consequences:

* the fetch deadline is generous (60s) because it may cover a sync *and* a Touch ID sheet;
* sync's own progress lines land on the same stdout stream (one winston Console transport,
  `src/logger.ts`), which is why `DashlaneWire` reads the **last** JSON array rather than the whole
  stream.

`dcli configure disable-auto-sync true` stops it, and you then run `dcli sync` when you want fresh
data. That makes connects purely local.

## Install locations

`brew install dashlane/tap/dashlane-cli` lands somewhere SimpleVPN will run from. Dashlane's own
manual-install instructions move the standalone binary to `/usr/local/bin/dcli`, which SimpleVPN also
runs from. Installing with Yarn lands in Yarn's global folder, which SimpleVPN will **find** but
decline to **run** — in which case the row says exactly that and offers the path to paste into
**Settings ▸ Sign-In Sources ▸ Dashlane CLI Location**. Source: <https://cli.dashlane.com/install>.

## Manual test recipe

You need: a Dashlane account, an entry with an address (or a title) plus a username and password, and
a VPN in SimpleVPN that signs in with a username and password.

1. **Before installing anything.** Open **Settings ▸ Sign-In Sources**. Dashlane's row should say
   either nothing at all (no Dashlane app, no `dcli`, no `dcli` database) or "Dashlane's command-line
   tool isn't installed on this Mac" with the Homebrew command. It must **never** claim Dashlane is
   unavailable if the app is installed.
2. **Install it somewhere SimpleVPN won't run from**, on purpose, to test the state that used to be
   reported as "not installed":
   ```
   yarn global add @dashlane/cli     # or: mkdir -p ~/bin && cp <the standalone binary> ~/bin/dcli
   ```
   Expected: the row says "installed, but not somewhere SimpleVPN will run it from", **names the
   path**, and offers both ways out (paste the path, or install with Homebrew). Paste the path into
   **Dashlane CLI Location** and the row must change without restarting SimpleVPN.
3. **Install it properly.**
   ```
   brew install dashlane/tap/dashlane-cli
   ```
   Clear the explicit path you set in step 2. Expected: the row is offered with the check owed.
4. **Not signed in.** With a fresh `dcli` (nothing registered yet), expect "This Mac isn't signed in
   to Dashlane yet" and the `dcli sync` banner. Check `dcli status` prints `Logged in: no`.
5. **Register this Mac.**
   ```
   dcli sync
   ```
   Dashlane asks for your email address, then a token (by email, or from your authenticator app if
   you have 2FA on), then your Dashlane password. Expected afterwards: `dcli status` prints
   `Logged in: yes` / `Locked: no`, and SimpleVPN's row goes ready **without a restart** (it polls).
6. **Point a VPN at an entry.** In the VPN's editor, choose Dashlane and type the entry's address
   (for example `vpn.example.com`). Connect. Expected: it connects with nothing typed.
   **Then check your clipboard** — paste into a text editor. Your VPN password must not be there.
   That is the single most important observation in this recipe.
7. **Several matches.** Make a second entry with the same title or address and a different username.
   Connect again. Expected: SimpleVPN says how many matched and tells you to narrow it down or set
   the username — **not** a hang, and not a wrong password. Set the username in the editor and
   connect again; expected: the right entry.
8. **No such entry.** Point the VPN at a title that does not exist. Expected: "Dashlane has no entry
   matching …", named, with no mention of your password being wrong.
9. **Locked.**
   ```
   dcli lock
   ```
   Expected: SimpleVPN's row says "signed in on this Mac, but locked", with `dcli sync` as the fix; a
   connect fails immediately with that sentence and **does not hang for 60 seconds**. That is the
   hang guard doing its job — verify it by timing the failure.
10. **The always-asks case.**
    ```
    dcli configure save-master-password false
    dcli lock
    ```
    Expected: the row stays "locked" and says that with this setting off, Dashlane asks every time
    and SimpleVPN cannot read the vault. Undo with `dcli configure save-master-password true` and
    `dcli sync`.
11. **Biometrics — who owns the prompt.**
    ```
    dcli configure user-presence --method biometrics
    ```
    Connect. Expected: a **Touch ID sheet whose wording is Dashlane's**, not ours ("validate your
    identity before accessing your vault"). *This is the observation most likely to surprise:* the
    sheet is raised by a child process SimpleVPN spawned, and whether macOS presents it that way for
    a non-GUI child is exactly what has never been verified here. If no sheet appears and the fetch
    times out at 60s, that is the finding — record it, and turn biometrics back off with
    `--method none`.
12. **Verification codes.** If the entry carries one, SimpleVPN computes it locally from the entry's
    seed. It still does **not** promise codes (`suppliesOTP` is false), so a VPN that needs one will
    still offer you the field. Check the computed code matches what Dashlane's own app shows.
13. **Auto-sync.** Leave it alone for over an hour, then connect and time it: the fetch should take
    noticeably longer once, because it syncs. Then
    ```
    dcli configure disable-auto-sync true
    ```
    and check connects are fast and offline-capable, with `dcli sync` run by hand when you want fresh
    data.
14. **Nothing leaks.** Take a diagnostic report and search it for your VPN password, your Dashlane
    email address, and the entry's password. None must appear. Check `log stream --predicate
    'subsystem == "com.bragi0.SimpleVPN"'` during a connect for the same.

## What is NOT possible

* **SimpleVPN cannot write to Dashlane.** `dcli`'s personal-vault commands are read-only —
  `password`, `note`, `secret`, `read`, `inject`, `exec`, `backup`, plus `sync`, `lock`, `logout` and
  `configure`. There is no "create entry" command for the personal vault, so nothing in SimpleVPN
  offers to save a sign-in into Dashlane, and nothing should ever imply otherwise.
* **SimpleVPN cannot register a device, sign in, or unlock.** All three are Dashlane's, interactive,
  and stay the user's to perform. SimpleVPN prints the commands.
* **There is no second channel.** Dashlane's desktop app exposes no socket, no daemon and no IPC, and
  `dcli` has no serve mode. If `dcli` is not runnable, the source is not available — unlike Keeper and
  Bitwarden, there is nothing to fall back to.

## Fixture-tested versus unverified

Fixture-tested (`SimpleVPNTests/Credentials/DashlaneTests.swift`, provenance in its header): the
argument list, the JSON reader including sync chatter ahead of the payload, seed-versus-code, the
picker (one match, several, username selection, wrong username, nothing usable), the `dcli status`
parse for all three states plus an unrecognised shape, the four availability states, the deep scan's
refusal to spawn for a tool it would not run, the hang guard, timeouts, and the copy/banner gates.

Unverified: everything requiring a real Dashlane. Above all — whether a Touch ID sheet raised by a
spawned `dcli` is presented to the user at all (step 11), and whether `dcli`'s own keychain read
prompts macOS for keychain access after a `dcli` update changes the binary's signature.
