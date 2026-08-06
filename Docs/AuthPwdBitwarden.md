# Bitwarden as a sign-in source

`SimpleVPN/Credentials/BitwardenProvider.swift` · settings in **Settings ▸ Sign-In Sources ▸
Bitwarden** · manual anchors `creds-bitwarden-*`

**Nobody has run this against a live Bitwarden vault.** Bitwarden was not installed on the machine
it was written on. Everything below the "Manual test recipe" heading is what a person with Bitwarden
should do to find out, and the recipe is written to be followed exactly, including the parts that are
expected to fail.

## The shape of it, and the one thing that decides everything

Bitwarden has two local channels, and SimpleVPN prefers the first **for a security reason, not a
speed one**:

| | What it is | What SimpleVPN needs from it |
|---|---|---|
| `bw serve` | Bitwarden's own local REST service, `127.0.0.1:8087` by default | one `GET`; the service holds the unlock, so SimpleVPN never handles a vault key |
| `bw` CLI | Bitwarden's command-line tool | a `BW_SESSION` key to read anything at all — which SimpleVPN never keeps |

**The `bw` CLI cannot read a vault without the key from an unlock.** That is not a policy of ours;
it is how the CLI works. It keeps its unlocked user key on disk encrypted with the session key
(`NodeEnvSecureStorageService` in `apps/cli/src/service-container/service-container.ts`, and
`init()` calls `setUserKeyInMemoryIfAutoUserKeySet` so that a `BW_SESSION` in the environment can
decrypt it). Consequences worth understanding before you test:

* `bw status`, run by SimpleVPN, reports **`locked`** whenever you are signed in — even while your
  own Terminal has an unlocked session. That session key belongs to your Terminal.
* So the state SimpleVPN can reach on the CLI alone is "signed in, locked", whose fix is
  `bw serve`. The service is the channel that actually fetches.
* `BW_SESSION` is a live key to everything in your vault. SimpleVPN **never persists it** — not in
  the keychain, not in `providerConfiguration`, not in a defaults key, not in a log line. When one
  exists at all it is held in `SingleUseCode`, read exactly once, and passed to the child process in
  its environment (never in argv — `ps` shows argv to every process on this Mac, and
  `bw --session <key>` would put a vault key there).

**Where the local service is addressed** is `Settings ▸ Sign-In Sources ▸ Bitwarden ▸ local service
address`, default `127.0.0.1:8087`. A non-loopback address is **refused, not used**: the service
asks nothing of whoever connects to it, so a request across a network would be a request for your
password sent to whatever answered. `bw serve --hostname all` exists; SimpleVPN still only talks to
this Mac.

**While the service runs, any program on this Mac can read your items from it.** Bitwarden's design.
The app's own copy says so, and the recipe below has you stop it.

Self-hosted Bitwarden and Vaultwarden are read through the same `bw` and are indistinguishable to
SimpleVPN — the `serverUrl` in a status reply is deliberately ignored rather than checked.

## Install locations

Per-vendor install paths and their sources live in `Docs/ToolDiscovery.md` (Bitwarden section).
Short version: `brew install bitwarden-cli` lands somewhere SimpleVPN will run from;
`npm install -g @bitwarden/cli` lands wherever npm's global prefix is, which SimpleVPN will *find*
but may decline to *run* — in which case the row says exactly that and offers the path to paste.

## Manual test recipe

You need: a Bitwarden account (hosted, self-hosted or Vaultwarden), a login item with a username and
password, and a VPN in SimpleVPN that signs in with a username and password.

### 0. Baseline — nothing installed

1. With no `bw` and no Bitwarden app, open a VPN's sign-in chooser.
   **Expect:** no Bitwarden row at all.
2. Install the Bitwarden **desktop app** only (`brew install --cask bitwarden`), reopen the chooser.
   **Expect:** a Bitwarden row saying its command-line tool isn't installed, with
   `brew install bitwarden-cli` shown and a link to Bitwarden's CLI page. **SimpleVPN must not offer
   to install anything.**

### 1. Installed outside the allow-list

1. `npm install -g @bitwarden/cli` with a Node from nvm, Bun or Volta — anywhere outside
   `/opt/homebrew/bin`, `/usr/local/bin`, `/opt/local/bin`, `/usr/bin`, `~/.local/bin` or
   `~/Library/Python/3.x/bin`.
2. Reopen the chooser.
   **Expect:** "installed, but not somewhere SimpleVPN will run it from", **naming the actual path**,
   with two ways out: paste that path into Settings, or install it with Homebrew.
   It must **not** say "not installed".
3. Paste the path into **Settings ▸ Sign-In Sources ▸ Bitwarden ▸ Bitwarden CLI location**.
   **Expect:** the row's validation says SimpleVPN will use it *because you chose it*, and the
   Bitwarden row stops complaining without an app restart.

### 2. Not signed in

1. `bw logout` (or start from a fresh install), then in SimpleVPN press **Check Again** on the
   chooser, or reopen it.
   **Expect:** "Bitwarden isn't signed in on this Mac", with `bw login` shown.
2. `bw login`.
   **Expect:** within ~15 seconds (the re-check interval) the row moves on to the *locked* state
   below, with no app restart.

### 3. Signed in, locked — the state most people will meet

1. Do **not** unlock. Reopen the chooser.
   **Expect:** "Bitwarden is signed in, but locked", with `bw unlock` and `bw serve` shown. It must
   **not** say you aren't signed in.
2. In Terminal: `export BW_SESSION=$(bw unlock --raw)` — your master password goes to **Bitwarden**,
   never to SimpleVPN.
3. Still not running `bw serve`, press **Check Again**.
   **Expect:** *still* locked, because that session belongs to your Terminal. This is the finding
   that shapes the whole feed; if it behaves differently, say so in the report — it would mean the
   CLI has gained a persistent unlock.

### 4. The local service — the path that should work

1. In the same Terminal: `bw serve` (leave it running).
2. Press **Check Again**.
   **Expect:** the Bitwarden row goes to **Ready to use**.
3. Point the VPN at an item: in the editor's Sign-In tab (or the first-connect card), set
   **Item name or ID** to the item's name. Leave the username empty.
4. Connect.
   **Expect:** username and password arrive from Bitwarden with nothing typed. If the VPN needs a
   verification code, **expect to type it** — `suppliesOTP` is deliberately `false` (see step 8).
5. Stop `bw serve` (Ctrl-C) and press **Check Again**.
   **Expect:** back to *locked*, and the connect panel offers to let you type your sign-in instead.

### 5. Wrong port, and an address that isn't this Mac

1. Restart the service on another port: `bw serve --port 9000`.
   **Expect:** SimpleVPN says *locked* (nothing is listening on 8087).
2. Set **local service address** to `127.0.0.1:9000`.
   **Expect:** Ready to use again.
3. Set it to `192.168.1.10:8087` (any address that is not this Mac).
   **Expect:** the field says the address isn't on this Mac and names 127.0.0.1 as the fix, and
   SimpleVPN **falls back to the default rather than using it**. Confirm with
   `sudo tcpdump -i any host 192.168.1.10` (or your own address) that **no request is sent**.
4. Set it to nonsense (`localhost`, `8087`, `http://127.0.0.1:8087`).
   **Expect:** "use the form host:port", a different sentence from the one above.
5. Clear the field.
   **Expect:** it reads "Not set, so SimpleVPN uses the usual address: 127.0.0.1:8087" — not
   "SimpleVPN hasn't found one".

### 6. Item addressing

With the service running and unlocked:

1. Item's **ID** (from Bitwarden's item view, or `bw list items | jq -r '.[0].id'`).
   **Expect:** works, exactly.
2. Item's **name**, unique.
   **Expect:** works.
3. A name that matches **several** items (make a second item with the same name).
   **Expect:** "N Bitwarden items match — paste the item's ID instead of its name, or set the
   username". It must **not** silently pick one, and must not print the other items' IDs.
4. Set **Username** to one of the two.
   **Expect:** the right one is used.
5. A name that matches **nothing**.
   **Expect:** "Bitwarden has no item matching …".
6. An item with a username but **no password**.
   **Expect:** "…has no password in it", not a silent empty sign-in.

### 7. Secrets discipline — the part that must be checked, not assumed

1. While a connect is in flight: `ps -Ao args | grep -i '[b]w '`.
   **Expect:** at most `bw ... list items --search <name>` or `bw get item <id>`; **never**
   `--session`, and never anything that looks like a key.
2. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` across a connect.
   **Expect:** `bitwarden item resolved for <profile>` and nothing else about the item — no username,
   no password, no code, no session key, no `serverUrl`.
3. `defaults read com.bragi0.SimpleVPN | grep -i -E 'bw_session|bitwarden'`.
   **Expect:** only `signin.bitwarden.endpoint` and `signin.tool.bw.path` / `signin.vendor.bitwarden
   .enabled` — an address, a path and a switch. **No key, no password.**
4. The VPN's stored source: it holds `kind`, `reference` (item name or ID) and `account`. Confirm
   there is no secret in `providerConfiguration` (`scutil --nc list` then the profile, or the app's
   diagnostic view).
5. Take a diagnostic report and search it for the item's password and for `BW_SESSION`.
   **Expect:** neither appears.

### 8. Verification codes

If the item carries a TOTP field, SimpleVPN computes the code **locally** from the seed with its own
RFC 6238 engine — `bw get totp` is deliberately not called (it answers "Premium status is required to
use this feature." for accounts without premium).

`CredentialSourceKind.bitwarden.suppliesOTP` is **false**: the connect panel still asks for a code.
That is a deliberate under-promise — the flag means "Connect works with nothing typed", and a broken
promise costs a failed sign-in and a consumed code.

**To clear it to `true`, someone has to report:** an item with a TOTP field, a VPN that requires a
code, a connect with the code field left empty, and a successful sign-in — twice, across a code
rollover. Until then it stays false.

### 9. MDM

1. Force `SignInSourcesForbidden = ["bitwarden"]`.
   **Expect:** no Bitwarden row anywhere — not in the chooser, not as a pointer — and the Settings
   switch visibly locked with a reason.
2. Force `SignInSourceToolPaths = {"bw": "/opt/homebrew/bin/bw"}`.
   **Expect:** the path row shows policy's value, read-only, and says who set it.
3. Force `signin.bitwarden.endpoint = "127.0.0.1:9000"`.
   **Expect:** the endpoint row shows that value, read-only, and SimpleVPN uses it.

## Known limitations, stated rather than discovered

* **`BITWARDENCLI_APPDATA_DIR`.** If you have relocated the CLI's data directory with that
  environment variable, SimpleVPN's child process will not see it: the child's environment is built
  from scratch (only `HOME`, `PATH`, `LANG`, `PYTHONUNBUFFERED`, and `BW_SESSION` when one exists),
  because inheriting an environment would let it choose what we run and where we read. `bw` will
  then look in its default location and report `unauthenticated`. Use `bw serve`, which is your own
  process and keeps your environment.
* **No sync.** SimpleVPN only reads. A password changed on another device may need `bw sync` before
  it appears here.
* **"Master password re-prompt" is not enforced by Bitwarden's own tool.** An item marked
  `reprompt` is handed over by `bw get item` regardless (there is no reprompt check in
  `apps/cli/src/commands/get.command.ts`), so an unlocked vault means an unlocked item even for one
  you expected to be asked about. That is Bitwarden's behaviour, not something SimpleVPN can add: we
  are a reader, and a prompt of ours would protect nothing that `bw` does not already release. If it
  matters, keep the service stopped until you need it.
* **An organization that hides passwords hides them from us too.** When the item's `viewPassword` is
  false Bitwarden nulls the password and the TOTP field before it leaves the tool, so SimpleVPN
  reports the item as having no password in it. That is accurate, if terse.
* **A `bw` we can see but not run, with the service running anyway.** If `bw` lives somewhere
  discovery cannot see at all (an absolute path outside `PATH`, e.g. `~/Downloads/bw`) *and* nothing
  Bitwarden is installed in `/Applications`, the row is not offered even though its service is
  answering. Set the tool path, or install `bw` where SimpleVPN looks.
* **Master-password unlock is not offered.** SimpleVPN never asks for a Bitwarden master password, so
  it cannot produce a session key itself. If a per-attempt session-key field is ever added to the
  connect panel it plugs into `BitwardenSessionSupplier` and nothing else changes.

## What is fixture-tested

`SimpleVPNTests/Credentials/BitwardenTests.swift` — every fixture's provenance is cited in that
file's header (Bitwarden's own `bitwarden/clients` sources and its CLI documentation). Covered:
unlocked / locked / not-signed-in, the service running and not running, a wrong port, a stranger
answering on the port, a non-loopback endpoint refused without a request being made, item-not-found,
several matches, an item with no password, `bw` outside the allow-list, the session key's
read-once-then-gone lifecycle, and the assertion that no argv and no error sentence can carry a
secret.
