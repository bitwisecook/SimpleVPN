# `pass` / `gopass` as a sign-in source

`SimpleVPN/Credentials/PasswordStoreReader.swift` · `PasswordStoreProvider.swift` ·
`PasswordStoreCopy.swift` · `PasswordStoreVaultAdapter` in the same provider file · settings in
**Settings ▸ Sign-In Sources ▸ pass / gopass** · manual anchors `creds-passwordstore-enabled`,
`creds-passwordstore-stores`, `creds-passwordstore-store-directory`,
`creds-passwordstore-username-field`, `creds-passwordstore-tool-path`

**This is the one source with a real end-to-end proof behind it, and it is still `.untested`.**
`FeatureMaturity` says `.vault(.passwordStore): .untested`, with the reason spelled out: the GPG
round trip **is** proven — a throwaway key and a throwaway store in `/tmp`, encrypted and read back
through the real `PasswordStoreReader`, in **both** pinentry modes — but no real store belonging to a
real person has ever been read, and nobody has connected a VPN with it. Those are different claims
and the registry keeps them apart.

**Not to be confused with Proton Pass** (`Docs/AuthPwdProtonPass.md`), whose tool is `pass-cli`.
Three entries sit next to each other in `ToolCatalog` — `pass`, `gopass`, `pass-cli` — precisely so
the difference is visible at the point where it could be got wrong, and only the third carries
`.protonPass`.

## What this actually is: a folder, read with `gpg`

The transport is `.file`, **and only `.file`**. A password store is a directory of GPG-encrypted
files and SimpleVPN reads them itself. There is no app to talk to, no socket, and no daemon — which
is why this source works for someone who has never installed `pass`.

**Neither `pass` nor `gopass` needs to be installed.** They are *detected* — knowing which one
somebody uses is worth having in a report — but they own **no vendor** in `ToolCatalog`, because
their absence blocks nothing and attributing a "missing tool" state to them would be wrong. The tool
that has to exist is **GnuPG**. That is why the row's install command is `brew install gnupg` and why
the tool-path field points at `gpg`: a row pointing at `pass` would let somebody carefully fix a path
that is never used.

The four reasons for decrypting with `gpg` rather than shelling to `pass show`, in order of weight
(`PasswordStoreReader.swift`'s header):

1. **`gpg` is far more likely to be there.** On the machine this was written on, `gpg` is installed
   and `pass` is not — the common case, because gpg arrives with a dozen other things and `pass` is a
   deliberate choice. Going through the CLI would make the feature unavailable to people whose store
   we can read perfectly well.
2. **The store layout is a documented, decade-stable format; a CLI's output is not.**
   `~/.password-store/<path>.gpg`, first line the password, `key: value` lines after. `pass show`'s
   formatting, colouring and extension behaviour are not a contract.
3. **`pass` is a shell script wrapping `gpg -d`.** Invoking it buys a shell, a `PATH`-dependent
   `getopt` and its own tempfile handling, in exchange for nothing we need.
4. **It keeps us away from `pass show -c`**, which puts the password on the pasteboard where every
   app on the Mac can read it. A VPN password must never go there, and the safest way not to call it
   is not to call `pass` at all.

Read-only, always: `--decrypt` and nothing else. It never writes to the store and **never runs git in
it**.

## The anti-hang guard, which is the important part

GPG asks for a passphrase through `gpg-agent`, which asks through a **pinentry**. On a Mac with no
GUI pinentry installed, that falls to a curses pinentry which cannot draw anywhere a windowed app can
see — so the process waits for input that can never arrive. **Forever, with no prompt and no error.**

That is not hypothetical. `pinentry-mac` is **absent** on the machine this was written on, which is
the default state for anyone who installed gpg without going looking for one.

So there are two modes, and both are bounded:

| Pinentry | Command | Deadline | Behaviour |
|---|---|---|---|
| a usable GUI one exists (`.graphical(program:)`) | `gpg --batch --yes --quiet --decrypt <file>` | **90 s** — a person may genuinely need a moment to type | the good path; can unlock a cold key |
| none usable (`.noneUsable`) | the same **plus `--pinentry-mode error`** | **12 s**, and irrelevant because gpg returns at once | fails *instantly* rather than trying to prompt — **and a passphrase already cached in the agent still works**, which is the common case for someone who has used their key this session |

`--pinentry-mode error` is the load-bearing flag. **`--batch` is never removed**: without it gpg may
try to interact on paths that have nothing to do with pinentry, and interaction is the one thing this
cannot survive. A deadline is present in *both* modes, because the whole point of the file is that no
path waits forever.

`PinentryProbe.detect` is deliberately **a file read and a `stat`, never an execution** — it runs on
the cheap availability path, and spawning there would make every settings refresh start processes. It
reads `~/.gnupg/gpg-agent.conf` for an explicit `pinentry-program`, then falls back to looking for
`pinentry-mac`, `pinentry-touchid`, `pinentry-qt` or `pinentry-gtk-2` in the execution allow-list. An
explicitly configured pinentry that **does not exist** is worse than none — gpg-agent then fails in a
way that reads like a broken keyring — so it only counts when the file is really there and
executable.

The one sentence the user gets names all three steps, because "install pinentry-mac" alone leaves
them with gpg still not using it:

> Your GPG key needs its passphrase, but there's no way to ask for it: no graphical pinentry is
> installed. Install one with "brew install pinentry-mac", add
> "pinentry-program /opt/homebrew/bin/pinentry-mac" to ~/.gnupg/gpg-agent.conf, then run
> "gpgconf --kill gpg-agent". Until then SimpleVPN can only read your store while your passphrase is
> still remembered by the GPG agent.

## Cardinality: `.multiple`, and it is instance-level

`LocalVaultVendor.passwordStore.cardinality` is `.multiple`, and the reason is a fact about the tool
rather than a convenience: **`PASSWORD_STORE_DIR` exists precisely so one person can keep several
stores.** A work one and a personal one is entirely ordinary. Each also carries its own username-field
convention, so they are configured separately, not merely located. The instance noun is **"store"**,
never "vault" — reserved, per `ONTOLOGY.md`, because that is what a `pass` store calls itself.

Three levels, kept apart:

| Level | What it is | Where it lives |
|---|---|---|
| 1 · transport | where `gpg` is on this Mac | app settings, one per Mac — the same `gpg` opens every store |
| 2 · store | which directory, plus which field name holds the username | app settings, **one or more**, each named |
| 3 · per VPN | which store + which entry (+ optional username) | that VPN's profile. No secrets, ever — not even a path |

A VPN remembers its store by an **opaque id**, not by its name or its path. And a profile naming a
store that no longer exists **fails rather than falling back**: `isResolved` is false and the fetch
throws `.notAStore`. Reading the wrong vault because a list changed is worse than failing to read at
all.

Both spellings of the tool are searched (`gpg` and `gpg2` — Homebrew's `gnupg` installs the first and
symlinks the second; some distributions ship only the latter), and both are registered in
`ToolCatalog` against `.passwordStore`. That registration is not cosmetic: `quickScan` asks
`toolFoundOutsideAllowList("gpg")` and `("gpg2")`, and a question about a tool the catalogue does not
carry can only ever answer nil — which once made this row's `.toolOutsideAllowList` branch
unreachable code.

## The layout is a convention, not a format — and the copy says so

`pass` guarantees only that an entry is GPG-encrypted text. That the first line is the password and
that `login:` holds the username are **habits** — near-universal habits, but habits. Two consequences
the copy is explicit about rather than hiding:

* **The first line is the password even when it looks like a `key: value` pair.** That is what every
  `pass` client does, and second-guessing it would silently return metadata as somebody's password.
* **The username comes from a convention**, so the field name is *configurable* rather than presented
  as a fact. `login`, `username`, `user`, `email` are tried in that order; a store that uses something
  else names it in **Settings ▸ Sign-In Sources ▸ pass / gopass ▸ Username Field**. If a sign-in comes
  back looking wrong, that is the first thing to check.

Parsing rules worth knowing before testing: only the **first** colon splits, so a URL in a value
survives; keys are lower-cased for matching; a key containing a space, or an empty value, is skipped;
**first wins**, like `pass`; and a `pass-otp`-style bare `otpauth://` line has no `key:` at all, so it
never reaches `fields` and is kept separately.

An entry name is a store-relative path without the `.gpg` (`vpn/work`). Absolute paths, `..` and `.`
components are refused outright — a reference that resolves to `/etc/…` is a bug worth making
impossible rather than a threat worth arguing about.

`.gpg-id` is what distinguishes **"you pointed at the wrong folder"** from **"your store is empty"**,
which need different sentences.

## Verification codes

Read from a `pass-otp`-style `otpauth://` URI, on its own line or as a field value, and the code is
computed **locally** with the app's own RFC 6238 engine — exactly as Bitwarden's is.

`CredentialSourceKind.passwordStore.suppliesOTP` is **`false`**, and the reason is one of the three
distinct ones in `Docs/CredentialSources.md`: not *unproven* and not *impossible*, but **unknowable in
advance**. `pass-otp` is an optional extension, so a code **may** be there — and "may" is not a
promise Connect can be built on, because whether a given entry carries a seed cannot be known until
the fetch has already happened. Promising it would be a claim about the user's data rather than about
`pass`. The code is still **used** when it is there.

## The four states, and the one action that clears each

`quickScan` is a pure filesystem question — a `stat` on the directory, a `stat` on `.gpg-id`, a
`locate` for gpg, and a file read for the pinentry. **No subprocess and no prompt.** The store's
directory comes from the **instance's own values** rather than from a second lookup, so the scan stays
nonisolated and cheap.

| State | What SimpleVPN says | The fix |
|---|---|---|
| `.notInstalled` — no gpg **and** no store configured | the row is not offered at all | `brew install gnupg` |
| `.blocked(.toolOutsideAllowList)` — discovery found `gpg`/`gpg2` somewhere execution won't run from | "GnuPG is installed somewhere SimpleVPN won't run it from" | set the full path to `gpg` in Settings, or install it with Homebrew |
| `.blocked(.toolMissing)` — a store **is** configured, gpg is not there | "GnuPG isn't installed", noting that `pass` itself is optional | `brew install gnupg` |
| `.blocked(.noVaultFile)` — gpg is there, no store chosen | "No password store chosen yet" | choose the folder — usually `~/.password-store` |
| `.blocked(.vaultFileMissing)` — the directory is gone | "That store folder isn't there any more" | point at where it is now |
| `.blocked(.vaultNotAPasswordStore)` — no `.gpg-id` in it | "That folder isn't a password store", naming `.gpg-id` and offering `pass init <your-gpg-key>` | choose the folder that has one |
| `.unchecked(.wouldPromptTheUser)` — everything present, **no GUI pinentry** | "Your store is ready to read. If GnuPG has forgotten your key's passphrase it will need to ask for it…" | optional: `brew install pinentry-mac` if you would rather always be asked |
| `.ready` | nothing to say | — |

Two of those deserve their reasoning stated:

**`.notInstalled` is not used when a store is configured.** A password store is a *folder*, so there
is no app whose absence proves the person does not use one. With a store configured, the honest
answer is "install GnuPG", not "you don't have this".

**The no-pinentry state is `.unchecked`, not `.blocked`.** A great many people have their passphrase
cached all day and this works perfectly for them, so it is offered with the caveat. And
`.wouldPromptTheUser` is the honest **ceiling**: the only way to find out whether the agent still
remembers the passphrase is to attempt a decrypt, and an uncached one raises GnuPG's own pinentry. A
dialog out of a two-second background refresh is exactly what teaches people to click through
dialogs, so it is not done. `deepScan` therefore returns the cheap answer **unchanged** — the same
conclusion the `.kdbx` adapter reaches for the same reason.

A multi-instance vendor's own row is the **best** of its stores, because the row answers "can this
vendor get me in at all". The per-store answers ride alongside it, so the pane, the chooser and a
report can each say which is which — a store on an unmounted volume must not hide the ready one.

## What is stored, and where — none of it secret

| Thing | Where | Secret? |
|---|---|---|
| each store: its name, its directory, its username-field name | `UserDefaults`, `signin.instances.passwordstore` | no — a name, a path, a field name |
| the single-store legacy keys `signin.passwordstore.directory`, `signin.passwordstore.username-field` | `UserDefaults` | no |
| `signin.tool.gpg.path` | `UserDefaults` | no — a path |
| `signin.vendor.passwordstore.enabled` | `UserDefaults` | no — a switch |
| `kind`, `reference` (the entry name), `account`, `instanceID` (opaque) | the VPN's profile | no — a relative path and a username |
| the GPG key's passphrase | **nowhere.** GnuPG's agent owns it, entirely | — |
| the decrypted entry | in memory for the connect | stdout is the secret; it is decoded and never logged, never quoted in an error, never returned in a diagnostic |

There is deliberately **no passphrase field and no Touch ID option on this row**, unlike the `.kdbx`
row. GnuPG owns the passphrase; offering to keep a copy would mean holding the key to the whole store
in order to save a prompt that GnuPG's own agent already caches.

## What it withholds

* **The GPG key's passphrase** — never seen, never stored, never prompted for. Every prompt is
  GnuPG's own pinentry.
* **Every other entry in the store.** One `--decrypt` of one file. There is no bulk read and no
  equivalent of `keepassxc-cli export`.
* **Everything in the entry that is not the password, the named username field, or an `otpauth://`
  URI.** Other `key: value` pairs are parsed but nothing else asks for them.
* **A promised verification code** — used when present, never promised.
* **Any write.** No writes to the store, and no `git`. Ever.
* **The pasteboard.** `pass show -c` exists and is simply never called; nothing here touches
  `NSPasteboard`.

## Failure modes, and the ambiguous one

| Case | Sentence names |
|---|---|
| `.gpgMissing` | GnuPG isn't installed where SimpleVPN can run it |
| `.notAStore` | no `.gpg-id` file in that folder |
| `.entryMissing(name)` | there's no entry called "…" in your password store |
| `.needsPassphraseButNoPinentry` | the three-step fix above |
| `.decryptFailed(detail)` | GnuPG's own words, scrubbed |
| `.timedOut` | "if a passphrase window is waiting somewhere, answer it and try again" |

One genuine ambiguity, and it is deliberate:

**In no-pinentry mode, "the agent has forgotten your passphrase" and "your passphrase is wrong" are
reported as the same thing.** `read(entry:)` sniffs gpg's stderr for `pinentry`, `no passphrase`,
`cancel` or `bad passphrase` and maps all four to `.needsPassphraseButNoPinentry`. That is
intentional: with `--pinentry-mode error` gpg cannot *have* been given a wrong passphrase — there was
no way to supply one — so the four strings all mean "it needed to ask and could not", and the fix is
the same sentence. The cost is that a genuinely corrupt key reports the pinentry advice.

A second, smaller one: **`.entryMissing` covers both "no such file" and "an unsafe name"**. An entry
reference containing `..` is refused by `file(forEntry:)` returning nil, which lands on the same case
as a missing file. There is nothing useful to say about the difference to somebody who typed a path.

## Manual test recipe

You need: GnuPG, a GPG key **with a passphrase** (the proof runs on a passphrase-less key precisely
because a test may never risk a prompt — so this is the part only a human can do), and a VPN in
SimpleVPN that signs in with a username and password.

### 0. Baseline — nothing installed, nothing configured

1. With no `gpg` and no store configured, open a VPN's sign-in chooser.
   **Expect:** no pass / gopass row at all.
2. `brew install gnupg`. Reopen the chooser.
   **Expect:** the row appears saying **"No password store chosen yet"**, offering the folder picker
   — **not** "GnuPG isn't installed", and **not** an instruction to install `pass`.

### 1. Making a store, and the two folder failures

1. `gpg --full-generate-key` (give it a passphrase), then
   `pass init <your-key-id>` if you have `pass` — or, without it,
   `mkdir -p ~/.password-store && echo <your-key-id> > ~/.password-store/.gpg-id`.
2. Point SimpleVPN at `~/.password-store`.
   **Expect:** the row goes to ready, or to the pinentry caveat (step 4) — **and which one it is
   tells you whether you have a GUI pinentry.** Write it down.
3. Now point it at a folder with **no** `.gpg-id` (`mkdir /tmp/notastore`).
   **Expect:** "That folder isn't a password store", naming `.gpg-id` and offering
   `pass init <your-gpg-key-id>`. It must **not** say the folder is missing.
4. Point it at a folder that does not exist at all.
   **Expect:** "That store folder isn't there any more" — a **different** sentence from step 3.
5. Rename `~/.password-store` while SimpleVPN is running, and press **Check Again**.
   **Expect:** it moves to the missing-folder state on its own, without a restart.

### 2. The tool path

1. Install gpg somewhere outside the allow-list — e.g. build it, or
   `cp $(which gpg) ~/bin/gpg` and remove the Homebrew one from the search set.
2. Reopen the chooser.
   **Expect:** "GnuPG is installed somewhere SimpleVPN won't run it from", naming the path, with two
   ways out. It must **not** say "not installed".
3. Paste the path into **Settings ▸ Sign-In Sources ▸ pass / gopass ▸ tool location**.
   **Expect:** the row's validation says SimpleVPN will use it *because you chose it*, and the row
   settles without a restart.
4. Set the path to something that is not executable.
   **Expect:** validation refuses it, and the automatic discovery is not broken by the bad value.

### 3. The pinentry guard — the most important section on this row

1. **Start from the default state:** make sure no GUI pinentry is installed
   (`ls /opt/homebrew/bin/pinentry*` should be empty) and `~/.gnupg/gpg-agent.conf` names none.
2. `gpgconf --kill gpg-agent` so nothing is cached. Reopen the chooser.
   **Expect:** the row is **offered** with the caveat note — "Your store is ready to read. If GnuPG
   has forgotten your key's passphrase…" — and **not** blocked.
3. Add an entry: `pass insert vpn/work` (or encrypt a file by hand), with a password on the first line
   and `login: yourname` on the second. Point the VPN at `vpn/work` and press Connect.
   **Expect:** **it fails within a couple of seconds**, with the three-step sentence naming
   `brew install pinentry-mac`, the `pinentry-program` line and `gpgconf --kill gpg-agent`.
   **It must not hang.** Time it — this is the whole reason the file exists, and a hang here is the
   worst possible outcome.
4. Now warm the agent from Terminal: `gpg --decrypt ~/.password-store/vpn/work.gpg > /dev/null` and
   type your passphrase there. Press Connect again **without** installing anything.
   **Expect:** **success.** A cached passphrase works in no-pinentry mode, and that is the case the
   caveat note is promising.
5. `gpgconf --kill gpg-agent` and connect again.
   **Expect:** back to the bounded failure from step 3.
6. Now `brew install pinentry-mac`, add
   `pinentry-program /opt/homebrew/bin/pinentry-mac` to `~/.gnupg/gpg-agent.conf`, and
   `gpgconf --kill gpg-agent`. Press **Check Again**.
   **Expect:** the row goes to plain **Ready to use** — the caveat note is gone.
7. Connect with a cold agent.
   **Expect:** **pinentry-mac's own window appears**, you type the passphrase there, and the connect
   proceeds. SimpleVPN never asks for it.
8. Do it again and **dismiss** the pinentry window.
   **Expect:** a bounded failure, well inside the 90-second deadline, saying GnuPG couldn't decrypt.
   **Not** a hang.
9. Finally, break it the way that reads like a broken keyring: point `pinentry-program` at a path that
   **does not exist** and `gpgconf --kill gpg-agent`. Press **Check Again**.
   **Expect:** back to the **no-pinentry caveat** — a configured pinentry that is not there must
   count as none, not as a working one.

### 4. Entry names and the convention

With a working pinentry or a warm agent:

1. Entry `vpn/work`.
   **Expect:** works.
2. Entry `vpn/work.gpg` (with the extension).
   **Expect:** fails with "There's no entry called …". The name is the path **without** `.gpg`.
3. Entry `../../etc/passwd`, and entry `/etc/passwd`.
   **Expect:** both refused with the no-entry sentence. Confirm with `ps` and `fs_usage` that **no
   `gpg` was spawned** and nothing outside the store was opened.
4. An entry whose **first line looks like metadata** — make one whose first line is
   `login: someone`.
   **Expect:** that whole line is taken as the **password**. That is correct behaviour and worth
   seeing once, because it is the convention's sharpest edge.
5. An entry with `URL: https://vpn.example.com/x` after the password.
   **Expect:** it parses — only the first colon splits.
6. An entry using `user:` instead of `login:`.
   **Expect:** the username is still found (conventional order).
7. An entry using `acct:` instead.
   **Expect:** **no username** — and then set **Username Field** to `acct` and confirm it is found.
8. Set the VPN's own **Account** field.
   **Expect:** it wins over whatever the entry says, because the person who typed it there meant it.

### 5. Two stores, and the failure that must not fall back

1. Make a second store: `mkdir -p ~/work-store && echo <key-id> > ~/work-store/.gpg-id`, and add an
   entry with a **different** password.
2. Add it in Settings as a second named store, and give it a different **Username Field**.
   **Expect:** two rows under **Your Stores**, each checked separately.
3. Move the *second* store aside. Look at the pane.
   **Expect:** the vendor row is still offered (best of the two), and the pane says **which** store is
   missing rather than averaging them.
4. Point a VPN at the missing store and connect.
   **Expect:** it **fails** — "That folder isn't a password store" / not-a-store — and does **not**
   read the other store. A silent fall-back to the wrong vault is the failure this is guarding
   against, so confirm the password you get is never the other store's.
5. Rename the store in Settings, and move its folder to a new path.
   **Expect:** the VPN keeps working — it holds an opaque id, not a name and not a path.
6. Remove a store that a VPN reads.
   **Expect:** SimpleVPN names the VPNs that read it **first**, and each of those then asks you to
   choose another rather than being silently pointed at somebody else's store.

### 6. Verification codes

1. `pass otp insert vpn/work` (or add a bare `otpauth://…` line by hand). Connect a VPN that needs a
   code, leaving the code field empty.
   **Expect:** Connect **asks** for the code — `suppliesOTP` is `false` here on purpose, because
   whether an entry has a seed is unknowable in advance.
2. If the sign-in nonetheless succeeds with the field empty, that is the code arriving. Confirm it
   twice across a 30-second rollover and report it.
3. Put the `otpauth://` URI as a **field value** (`totp: otpauth://…`) instead of a bare line.
   **Expect:** it is found either way.
4. Search a diagnostic report for `otpauth://` and for the base32 seed.
   **Expect:** neither appears.

### 7. Read-only and secrets discipline — checked, not assumed

1. Take a checksum of the whole store before and after a dozen connects:
   `find ~/.password-store -type f | sort | xargs md5`.
   **Expect:** identical. And `git -C ~/.password-store status` (if it is a git store)
   **Expect:** clean, with no new commits — we never run git.
2. While a connect is in flight: `ps -Ao args | grep '[g]pg'`.
   **Expect:** `gpg --batch --yes --quiet --decrypt <path>` — plus `--pinentry-mode error` in the
   no-pinentry mode — and **nothing else**. The **path** is in argv, which is fine; **no passphrase,
   ever**.
3. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` across a connect.
   **Expect:** nothing about the entry's contents — no password, no username, no code.
4. `defaults read com.bragi0.SimpleVPN | grep -i -E 'passwordstore|gpg'`.
   **Expect:** `signin.instances.passwordstore` (names, paths, field names),
   `signin.passwordstore.directory`, `signin.passwordstore.username-field`, `signin.tool.gpg.path`,
   `signin.vendor.passwordstore.enabled`. **No passphrase, no password.**
5. Check the pasteboard is untouched: copy a marker string, connect, then paste.
   **Expect:** your marker. Nothing here goes near the pasteboard, and confirming it is cheap.
6. Take a diagnostic report and search it for the entry's password and for your key's passphrase.
   **Expect:** neither appears.

### 8. MDM

1. Force `SignInSourcesForbidden = ["passwordstore"]`.
   **Expect:** no pass / gopass row anywhere, and the Settings switch locked with a reason.
2. Force `SignInSourceToolPaths = {"gpg": "/opt/homebrew/bin/gpg"}`.
   **Expect:** the path row shows policy's value, read-only, and says who set it.
3. Force the store directory through policy.
   **Expect:** the row shows that value read-only, and — the part worth verifying — the **fetch**
   uses it. Policy is written into the instance's values when it is applied, so reading the instance
   reads the policy; `quickScan` and the fetch must agree.

## Known limitations, stated rather than discovered

* **The layout is a convention.** Everything above about first lines and `login:` is habit, not
  format. A store that does something else needs the username field named, and a store whose first
  line is *not* the password cannot be read correctly by anything, including `pass` itself.
* **No entry browser.** The entry name is typed. Listing a store would mean walking somebody's whole
  directory tree, and while that is only filenames, it is a bigger read than one entry.
* **`gopass`'s extras are not modelled.** `gopass` supports things `pass` does not; SimpleVPN reads
  the common on-disk format both share, and a `gopass`-only feature that changes how a file is
  encrypted is out of scope.
* **`PASSWORD_STORE_DIR` in your environment is not consulted.** The store's directory is a setting,
  because the child process's environment is built from scratch rather than inherited. Set the
  directory in Settings; that is what the instance is for.
* **A cold agent in no-pinentry mode fails every time.** By design, and bounded. Installing
  `pinentry-mac` is the fix, and the row says so without nagging.
* **`.notAStore` cannot tell a wrong folder from a store whose `.gpg-id` was deleted.** Both need the
  same action.

## What is fixture-tested

`SimpleVPNTests/Credentials/PasswordStoreTests.swift` is deliberately two halves.

**The fixture tests always run**, over an injected process boundary (`StubDecrypter`,
`PasswordStoreFileProbe`), so they pass on a machine with no store, no key and no agent. They cover
the parser (first-line-is-the-password, first-colon-only, first-wins, the bare `otpauth://` line,
skipped keys), the path handling including the traversal refusals, all five `PasswordStoreState`
answers, every availability state, every error sentence, and — the one worth naming — an assertion
that the reader really **passes `allowPrompting: false`** when no pinentry is available rather than
merely being configured that way.

**The live test runs only when `gpg` is really installed**, and then it is a genuine end-to-end
proof: a throwaway keyring and a throwaway store in `/tmp`, a real entry encrypted to a real key, read
back through the real `PasswordStoreReader`, in **both** pinentry modes. Two details are load-bearing:
it uses `/tmp` rather than `NSTemporaryDirectory()` because gpg-agent's socket lives inside
`GNUPGHOME` and `sockaddr_un` caps a socket path at 104 bytes — the test host's temporary directory
alone can blow that, and gpg then fails with "File name too long" while looking like a broken keyring.
And the throwaway key has **no passphrase**, deliberately: nothing in a test run may ever be able to
raise a passphrase prompt, because a prompt nobody answers is a hang.

**Never done:** a real store belonging to a real person, a real key with a real passphrase, a real
pinentry window, and a VPN connected through any of it. That is exactly what §3 above is for.
