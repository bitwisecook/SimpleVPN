# Keeper as a sign-in source

`SimpleVPN/Credentials/KeeperProvider.swift` (provider, `KeeperChannel`,
`KeeperCommanderChannel`, `KeeperRecordParser`, `KeeperServiceMode`) · `KeeperVaultAdapter` in
`LocalVaultAdapters.swift` · settings in **Settings ▸ Sign-In Sources ▸ Keeper** · manual anchors
`creds-keeper-enabled`, `creds-keeper-tool-path`

**Nobody has run this against a live Keeper vault.** Neither Keeper nor Keeper Commander is installed
on the machine it was written on, and `FeatureMaturity` says `.vault(.keeper): .untested`. Everything
below the recipe heading is what a person who actually has Keeper should do to find out, including the
steps expected to fail.

## The channel: Commander, because the app has no local API

**The Keeper desktop app exposes nothing SimpleVPN can talk to.** The supported local path is
**Keeper Commander** — Keeper's own command-line tool, MIT-licensed and actively maintained (it is
listed in **About ▸ Acknowledgements** as such, describing *that* project, not this one). It is a real
path rather than a grudging one: `persistent-login` gives genuine non-interactive use, and Commander
keeps its own sign-in in **this Mac's keychain**, where macOS protects it — exactly what SimpleVPN
tells users about its own stored sign-ins.

So the row is offered when **Commander** is present. The Keeper app on its own is a *pointer*
(`PasswordAppCatalog.pathToIntegration`): the signal that this person uses Keeper, and therefore that
Commander is worth telling them about.

Getting this wrong once cost a rewrite, which is why the seam exists. The first cut of the feature
hard-coded "Keeper has no local integration". That was simply false, and being wrong about one vendor
paid for `LocalVaultAdapter` — being wrong about the next one now costs one file.

### Two transports, preferred in this order

`transports: [.localDaemon, .cli]`, and the order is the preference rather than a fallback chain
bolted on afterwards.

| | What it is | Cost |
|---|---|---|
| **Service Mode** | Commander's own local REST daemon (`service-create` / `service-start`) | no Python start-up per fetch; architecturally the same shape as the KeePassXC socket |
| **The CLI** | one `keeper get <record> --format json --unmask` per fetch | a Python process each time |

Service Mode is read from Commander's own config — `~/.keeper/service_config.json` or
`~/.keeper/service/service_config.json`, whichever is there — for a port and an api key, with
tolerant key matching (`port` / `service_port` / `servicePort`; `api_key` / `apiKey` / `token` /
`service_api_key`). The request is `POST http://127.0.0.1:<port>/api/v1/executecommand` with the key
in an `api-key` header, on an **ephemeral** `URLSession` because nothing about a secret-bearing
response belongs in a cache.

That request shape is Commander's documented "run a command" endpoint **as of writing**, and it is
deliberately the only place that assumption lives. **Every** failure there falls back to the CLI
rather than failing the connect, so a Commander release that renames the route costs a slower fetch,
not a broken sign-in.

## We read Commander's configuration and never write it

This is a hard rule, not a preference. **Keeper's own documentation warns that reusing or rewriting a
Commander config on a second device revokes both sessions and breaks persistent login.** So setup is
the user's to perform: SimpleVPN prints the commands (`LocalVaultCopyBook.keeper`) and the user runs
them. Nothing in this app writes `~/.keeper`, and `--config` is never passed — which is also why the
vendor is single-instance (below).

Nothing is cached, either: **each connect asks again**, so revoking access in Keeper takes effect
immediately rather than after some expiry of ours.

## How it authenticates, and whether a fetch is interactive

Commander holds the session; SimpleVPN never sees a Keeper master password and there is no field for
one. The one-time setup, which is what the row's guidance shows verbatim:

```sh
pipx install keepercommander            # SimpleVPN never installs it for you
keeper shell                            # sign in to Keeper once, in Terminal
this-device register
this-device persistent-login on
biometric register                      # optional: unlock Keeper with Touch ID instead
```

**After that, a fetch is not interactive.** Liveness is `keeper whoami` with a 10-second deadline,
which persistent login answers without prompting — and which, *without* one, fails fast because stdin
is `/dev/null`. That is the whole anti-hang guard on this row: there is no prompt a wedged Commander
could sit on, because there is no stdin for it to read.

The fetch itself is `keeper get <record> --format json --unmask` with a 25-second deadline. Only the
record's own name or UID rides argv — `ps` shows argv to every process on this Mac. The secret
arrives on **stdout** (or in the daemon's response body) and is never logged, never quoted in an
error, never placed in argv.

## Verification codes: `suppliesOTP` is deliberately `false`

`CredentialSourceKind.keeper.suppliesOTP` is **`false`**, and not because Keeper cannot. Commander has
a `totp` command, and SimpleVPN does better than calling it: when the record carries a TOTP field the
code is computed **locally** from the field's `otpauth://` URL with the same RFC 6238 engine the Touch
ID store uses — no second round trip.

The flag is `false` because **it is a promise Connect relies on**: `true` means "Connect is enabled
with nothing typed". A broken promise costs a failed sign-in *and* a consumed one-time code, which
some gateways count toward a lockout. Nobody has proven this end-to-end against a live Keeper vault
from here. Asking for a code that turns out to be unnecessary costs one keystroke; the other mistake
costs the connect.

**The fetch still uses a code when Commander hands one over.** That is not the same as promising one.

To clear it to `true`, someone has to report: a record with a TOTP field, a VPN that requires a code,
a connect with the code field left empty, and a successful sign-in — twice, across a code rollover.

One guard worth knowing: only an **enrollment URL** is accepted as a seed
(`otpauth://…`). A bare six-digit value in a `totp`-ish field is a *code*, not a seed, and taking it
would freeze one code for ever. It is refused.

## Reading a record: three shapes, and all of them

`KeeperRecordParser` is deliberately tolerant, because a Commander version bump must not silently
stop finding the password:

* the flat legacy shape — `{"login": …, "password": …}`, also accepting `username` / `user` and
  `secret`;
* the typed v3 shape — `{"fields": [{"type": "login", "value": ["…"]}]}`, plus `custom` and
  `custom_fields`, each either a list of `{type,value}` objects or a plain label→value map;
* either of those wrapped in a single-element **array**, which some builds emit;
* and, for Service Mode only, either wrapped one level deeper in `data` / `result` / `response` /
  `output`, as a nested object or as a JSON string.

Label matching is case-insensitive over `login`/`username`/`user`/`email`,
`password`/`secret`, and `onetimecode`/`one_time_code`/`totp`/`otp`/`twofactor`/`two_factor_code`.
First value wins. A parse that finds neither a login nor a password returns nil rather than an empty
record.

## Cardinality: single

Commander keeps **one** configuration and one persistent-login session on this Mac, and SimpleVPN
passes no `--config` — see the rule above about not touching that file. So there is exactly one
Commander to talk to, `LocalVaultVendor.keeper.cardinality` is `.single`, and there are no
instance-level fields. A test asserts that, so a meaningless one-row "which vault" list cannot
appear.

Keeper's own folders and shared folders are addressed **inside** the reference (level 3): the
per-VPN reference is a record **UID**, a title, or a folder path like `Work/VPN/GR Lab`.

## The four states, and the one action that clears each

`quickScan()` is file checks only. Whether a persistent-login session is live needs a real `whoami`,
which is `deepScan` — so until that answers, the row says **the check is owed** rather than accusing
anybody of not being signed in.

| State | What SimpleVPN says | The fix |
|---|---|---|
| `.notInstalled` — nothing Keeper on this Mac | the row is not offered at all | — |
| `.blocked(.toolMissing)` — the **Keeper app** is here, Commander is not | "Keeper Commander isn't installed on this Mac", with `pipx install keepercommander` and the sign-in commands | install Commander (we never do it for you) |
| `.blocked(.toolOutsideAllowList)` — discovery found `keeper` somewhere execution won't run from | "Keeper Commander is installed, but not somewhere SimpleVPN will run it from", **naming the actual path** | paste that path into **Settings ▸ Sign-In Sources ▸ Keeper**, or install it with Homebrew |
| `.unchecked(.checkOwedOnUse)` — Commander is here | "SimpleVPN checks Keeper Commander when you pick this." | pick the row; that pays the check |
| `.blocked(.notSignedIn)` — `whoami` failed | "Keeper Commander isn't signed in on this Mac", with `keeper shell` / `this-device register` / `this-device persistent-login on` | sign Commander in once |
| `.ready` — `whoami` succeeded | nothing to say | — |

`deepScan` refuses to spawn for `.toolMissing` and `.toolOutsideAllowList`: probing the first would
be pointless and "not signed in" would be the wrong thing to say, and probing the second would mean
executing **exactly** the binary the allow-list declined.

**`.toolOutsideAllowList` is why discovery and execution are deliberately different.**
`ToolDiscovery` searches every package manager, version manager and vendor installer location plus
`PATH`; `LocalToolRunner` executes from an allow-list only and never consults `PATH`. Keeper is the
vendor that makes the gap obvious: Keeper's own guide is `pip3 install --user` (landing in
`~/Library/Python/3.x/bin`) or **a virtualenv**, and a venv is by definition somewhere nothing can
guess. That is precisely what the explicit-path setting is for.

`ToolCatalog` asserts **no** vendor installer path for `keeper`, on purpose: Keeper's standalone
`.pkg` documents its filename but not its install path, and a guessed path presented as documented is
worse than none.

## What is stored, and where — none of it secret

| Thing | Where | Secret? |
|---|---|---|
| `kind`, `reference` (record UID, title, or folder path), `account` | the VPN's profile | no — a name and a username |
| `signin.tool.keeper.path` | `UserDefaults` | no — a path |
| `signin.vendor.keeper.enabled` | `UserDefaults` | no — a switch |
| Commander's session | **Commander's own item in this Mac's keychain** | yes, and it is Keeper's to manage — we never read or write it |
| Service Mode's port and api key | **Commander's own `~/.keeper/service_config.json`**, read only | we hold it in memory for one request; never persisted, never logged |
| the Keeper master password | **nowhere.** Commander holds the session; nothing asks for the password | — |
| the record's password / code | in memory for the connect | never cached — each connect asks again |

## What it withholds

* **The Keeper master password**, absolutely — there is no field and no code path.
* **Every other field of the record.** `KeeperRecord` carries exactly three things: a login, a
  password, and an `otpauth://` seed. Notes, attachments, custom fields for other purposes and the
  rest of the record are read past and dropped.
* **Every other record.** There is no list call in this path and no browse.
* **A promised verification code.** See above: used when present, never promised.
* **Any write.** No `keeper add`, no `keeper edit`, and — the load-bearing one — no write to
  Commander's configuration.
* **Commander's stderr, unfiltered.** It is scrubbed by the runner before it can reach a message, and
  only `.unreadable` quotes any of it.

## Failure modes, and the two that are ambiguous

| Case | Sentence names |
|---|---|
| `.noRecord` | add the record's name or its UID |
| `.notSignedIn` | `keeper shell`, then `this-device register` and `this-device persistent-login on` |
| `.noPassword(ref)` | the record, by name — not a silent empty sign-in |
| `.wrongAccount(account)` | clear the account, or point the VPN at the right record |
| `.unreadable(detail)` | whatever Commander said, scrubbed — or "didn't answer in time" on the 25-second deadline |

Two are genuinely ambiguous and a tester should know it:

1. **`.notSignedIn` is decided by sniffing stderr.** `record(reference:)` lower-cases Commander's
   stderr and looks for `logged in`, `login` or `session`, because Commander says "Not logged in" and
   "session expired" in various spellings across versions. A genuinely different failure whose
   message happens to contain one of those words **will be reported as "not signed in"**. That is a
   deliberate trade — the far more common case is the one it catches — but it means a puzzling "not
   signed in" on a Commander that plainly is deserves the raw stderr in a report.
2. **Service Mode failing and Service Mode not existing are not distinguished at the row.** If
   `service_config.json` is there but the daemon is dead, or answers non-200, or the route has been
   renamed, the fetch logs "keeper service mode didn't answer; falling back to the CLI" and proceeds
   on the CLI. The user sees a slower success, which is the right outcome and an invisible one. The
   log line is the only evidence.

## Manual test recipe

You need: a Keeper account, a record with a username and a password (and ideally a second with a TOTP
field), Python with `pipx` available, and a VPN in SimpleVPN that signs in with a username and
password.

### 0. Baseline — nothing Keeper at all

1. With no Keeper app and no Commander, open a VPN's sign-in chooser.
   **Expect:** no Keeper row at all.
2. Install the **Keeper desktop app** only, then reopen the chooser.
   **Expect:** a Keeper row saying **Keeper Commander** isn't installed, showing
   `pipx install keepercommander` and a link to Keeper's Commander page. **SimpleVPN must not offer
   to install anything.**

### 1. Installed outside the allow-list — the state Keeper exists to demonstrate

1. Install Commander into a **virtualenv**:
   `python3 -m venv ~/kc && ~/kc/bin/pip install keepercommander`.
2. Reopen the chooser.
   **Expect:** "Keeper Commander is installed, but not somewhere SimpleVPN will run it from",
   **naming `~/kc/bin/keeper`**, with two ways out: paste that path into Settings, or install it with
   Homebrew. It must **not** say "not installed".
   *If discovery does not find a venv at all, write that down* — it is a real gap and the sentence
   would silently become "not installed".
3. Confirm nothing was executed: `deepScan` must not spawn for this state. There is no direct way to
   observe that from outside, so instead check the timing — the row must settle instantly rather than
   after a Python start-up.
4. Paste the path into **Settings ▸ Sign-In Sources ▸ Keeper ▸ tool location**.
   **Expect:** the row's validation says SimpleVPN will use it *because you chose it*, and the row
   stops complaining without an app restart.

### 2. Not signed in

1. `pipx install keepercommander` (or keep the venv path from step 1). Do **not** sign in.
2. Press **Check Again**.
   **Expect:** first "SimpleVPN checks Keeper Commander when you pick this" (the check is owed), then
   "Keeper Commander isn't signed in on this Mac" once the deep scan has run — with `keeper shell`
   and the two `this-device` commands shown.
3. Confirm it fails **fast**, not after a hang: `keeper whoami` with stdin at `/dev/null` must
   return promptly rather than sitting on a prompt. Time it.
   **Expect:** under the 10-second deadline, comfortably. **If it hangs, stop and report that** — it
   is the one place this row could wedge.

### 3. Signed in, no persistent login

1. `keeper shell`, sign in, then **quit without** running `this-device persistent-login on`.
2. Press **Check Again**.
   **Expect:** *probably* still "not signed in", because a session that needs interaction is not a
   session SimpleVPN can use. **Write down which it is** — this is the boundary the code guesses at.
3. Now `keeper shell` again and run `this-device register` and
   `this-device persistent-login on`. Press **Check Again**.
   **Expect:** **Ready to use**, without an app restart.

### 4. A real fetch, on the CLI

1. Point the VPN at the record: set the reference to the record's **title**, leave the username
   empty. Connect.
   **Expect:** username and password arrive with nothing typed. If the VPN needs a verification code,
   **expect to type it** — `suppliesOTP` is deliberately `false`.
2. Repeat with the record's **UID**.
   **Expect:** works, exactly.
3. Repeat with a **folder path** (`Work/VPN/GR Lab`).
   **Expect:** works.
4. A reference that matches **nothing**.
   **Expect:** Commander's own failure, surfaced as "Keeper couldn't provide the sign-in: …" with
   scrubbed detail — not a silent empty sign-in.
5. A record with a username but **no password**.
   **Expect:** "The Keeper record "…" has no password in it."
6. Set **Account** to a username that is **not** the record's.
   **Expect:** "The Keeper record's username isn't "…" — clear the account, or point this VPN at the
   right record." Note this is checked *after* the fetch: the record was read and then rejected.
7. Set Account to the record's actual username.
   **Expect:** works.

### 5. Service Mode — the preferred channel

1. In `keeper shell`: `service-create`, then `service-start`. Leave it running.
2. Confirm the config landed: `cat ~/.keeper/service_config.json` (or
   `~/.keeper/service/service_config.json`).
   **Expect:** a port and an api key. **Write down the exact key names** — the parser accepts several
   spellings and knowing which one Commander actually writes is worth having.
3. Connect.
   **Expect:** a **noticeably faster** fetch than step 4, because no Python starts.
4. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` and connect again.
   **Expect:** `keeper record resolved for <profile>` and **no** "service mode didn't answer" line.
5. Now stop the daemon but leave the config file in place. Connect.
   **Expect:** success anyway, and the log now carries "keeper service mode didn't answer; falling
   back to the CLI". This is the fallback that makes the route assumption safe, and it is the single
   most valuable thing to confirm.
6. Corrupt the config (`echo '{}' > ~/.keeper/service_config.json`). Connect.
   **Expect:** success on the CLI, with no complaint about the config — a config we cannot parse is
   the same as no Service Mode.
7. Confirm we changed nothing: `md5 ~/.keeper/service_config.json` before and after several connects,
   and the same for every file in `~/.keeper`.
   **Expect:** identical. **This is the check that matters most on this row** — a written config
   revokes Keeper sessions.

### 6. Verification codes

1. On a record **with** a TOTP field, connect a VPN that needs a code, leaving the code field empty.
   **Expect:** Connect asks for the code — the promise is not made. Type it; it should succeed.
2. Now type nothing and let SimpleVPN supply what it found: if the connect *does* succeed with the
   code field empty, that is the evidence needed to flip `suppliesOTP`. **Do it twice, across a
   30-second rollover**, and report both results.
3. Put a bare six-digit number in a `totp` custom field instead of an `otpauth://` URL.
   **Expect:** it is **ignored**, not used. A code is not a seed.
4. Search a diagnostic report for `otpauth://`.
   **Expect:** nothing.

### 7. Secrets discipline — checked, not assumed

1. While a connect is in flight: `ps -Ao args | grep '[k]eeper'`.
   **Expect:** at most `keeper get <record name or uid> --format json --unmask` and
   `keeper whoami`. The record's name is fine — it is not a secret. **Nothing that looks like a
   password, a token or an api key.**
2. The same during a Service Mode fetch.
   **Expect:** no `keeper` process at all, and **no api key anywhere in any argv** — it rides an HTTP
   header.
3. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` across a connect.
   **Expect:** `keeper record resolved for <profile>` and the fallback line, and nothing else. No
   username, no password, no code, no record contents.
4. `defaults read com.bragi0.SimpleVPN | grep -i keeper`.
   **Expect:** `signin.tool.keeper.path` and `signin.vendor.keeper.enabled` — a path and a switch.
   **No key, no password, no session.**
5. Take a diagnostic report and search it for the record's password and for the Service Mode api key.
   **Expect:** neither appears.
6. `sudo tcpdump -i any -n 'not (host 127.0.0.1)' ` across a Service Mode fetch.
   **Expect:** nothing from our request — the daemon is loopback-only by construction, because the
   URL is built as `http://127.0.0.1:<port>/…` and the port is all the config can influence.

### 8. Revocation takes effect immediately

1. Connect successfully. Then in Keeper's web vault, **revoke this device** (or
   `this-device persistent-login off` in Commander).
2. Connect again **without restarting SimpleVPN**.
   **Expect:** failure, and the row moves to "isn't signed in" on its next refresh. Nothing is
   cached, so there should be no window in which a revoked session still works.

### 9. MDM

1. Force `SignInSourcesForbidden = ["keeper"]`.
   **Expect:** no Keeper row anywhere — not in the chooser, not as a pointer — and the Settings switch
   visibly locked with a reason.
2. Force `SignInSourceToolPaths = {"keeper": "/opt/homebrew/bin/keeper"}`.
   **Expect:** the path row shows policy's value, read-only, and says who set it.

## Known limitations, stated rather than discovered

* **The Service Mode route is one documented assumption.** `/api/v1/executecommand` is where it lives
  today; the fallback is what makes that survivable.
* **"Not signed in" is inferred from stderr text.** See the ambiguity above.
* **No browse, no record picker.** The reference is typed. Listing records would mean asking Commander
  to enumerate a vault, which is a much larger grant than reading one record.
* **A record's non-standard field names may not be found.** The parser knows the conventional labels;
  a record whose password lives under a bespoke custom label will report "has no password in it". The
  fix is to name the record's fields conventionally, and there is deliberately no configurable
  field-name setting here (unlike `pass`, where the convention genuinely varies per store).
* **`--unmask` is required to read a password at all**, and it is passed. There is no mode in which
  Commander hands over a masked value SimpleVPN then unmasks; the unmasking is Commander's.
* **Nothing is cached, so every connect costs a fetch.** On the CLI channel that is a Python start-up.
  Service Mode is the answer, and it is why the transports are ordered as they are.

## What is fixture-tested

Keeper has no dedicated test file; its coverage lives in
`SimpleVPNTests/Credentials/SignInSourceTests.swift` — `keeperWithCommanderSignedInIsAFetchableSource`,
`keeperWithoutASessionIsOfferedWithTheSignInCommands`,
`theKeeperAppWithoutCommanderIsOfferedWithTheInstallCommand`, `keeperIsNeverBothASourceAndAPointer`,
and `everyKeeperErrorExplainsItself`. The provider's own paths are exercised through the injected
`KeeperChannel`, so the resolve path, the account filter, the no-password refusal and the local TOTP
computation all run with no Keeper anywhere on the machine. `KeeperRecordParser` and
`KeeperServiceMode.parse` are pure and covered against all three record shapes and both config key
spellings.

**Never run:** a real Commander, a real Keeper account, a real `whoami`, a real Service Mode daemon,
a real record, and a real Touch ID registration.
