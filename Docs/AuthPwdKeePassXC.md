# KeePassXC as a sign-in source

`SimpleVPN/Credentials/KeePassXCProvider.swift` · `KeePassXCProtocol.swift` ·
`KeePassXCCrypto.swift` · `KeePassXCVaultAdapter` in `LocalVaultAdapters.swift` · settings in
**Settings ▸ Sign-In Sources ▸ KeePassXC** · manual anchors `creds-keepassxc-enabled`,
`creds-keepassxc-socket`

**Nobody has run this against a live KeePassXC.** KeePassXC is not installed on the machine it was
written on, and `FeatureMaturity` says `.vault(.keePassXC): .untested`. What *has* been proven is
unusually strong for an untested row: the whole protocol runs end-to-end in tests against a mock
KeePassXC serving the real wire format over a real unix socket, and the crypto underneath it is
pinned against reference vectors. What has never happened is a real KeePassXC answering. The recipe
below is written to be followed exactly, including the parts expected to fail.

**This row is separate from the KeePass `.kdbx` file row** (`Docs/AuthPwdKeePassFile.md`), and this
one is preferred wherever it works: a running KeePassXC owns its own unlock, asks the user to allow
SimpleVPN once, and never lets a database password near this app. The file row exists for what this
cannot reach — Strongbox, KeePassium, a closed KeePassXC, a database on a share.

## The channel: KeePassXC's own published browser protocol

The transport is `.appSocket`. SimpleVPN speaks the **keepassxc-browser** protocol — the same one
KeePassXC's own browser extensions use — over a unix-domain stream socket. There is no CLI in this
path: `keepassxc-cli` belongs to the file row, and this row needs no binary whatever.

The protocol in one breath: connect, swap Curve25519 public keys in the clear
(`change-public-keys`), then every further message is a JSON body sealed with `crypto_box` under a
fresh 24-byte nonce, riding inside a plaintext envelope `{action, message, nonce, clientID}`. **A
reply must arrive under the request's nonce + 1** — that increment is what ties an answer to its
question, and a mismatch is a hard `protocolError` rather than something to shrug at.

Framing is walked by brace depth (string- and escape-aware) rather than assumed: `QLocalSocket`
writes one JSON document per message, but `SOCK_STREAM` guarantees no boundaries, so a read may
deliver half a message or an unsolicited signal glued to the reply.
`KeePassXCProtocol.extractJSONObject` returns the first complete object plus the remainder.
KeePassXC's `database-locked` / `database-unlocked` broadcasts are recognised as signals and skipped
by anything waiting for a reply — and acted on by the one thing that wants them.

### Where the socket is

| Directory probed | Why |
|---|---|
| `$TMPDIR` | `QStandardPaths::TempLocation` on macOS, i.e. the per-user directory under `/var/folders` — where KeePassXC 2.7 actually listens |
| `confstr(_CS_DARWIN_USER_TEMP_DIR)` | the same directory, spelled the way a process with **no** `$TMPDIR` must ask for it — a `posix_spawn`ed process, or one launched from a shell that scrubbed the environment, has none |
| `~/Library/Application Support/KeePassXC` | where sandboxed and some packaged builds land |

Two names in each: `org.keepassxc.KeePassXC.BrowserServer`, and the pre-2.6 legacy `kpxc_server`.
Duplicates are collapsed, order preserved.

**The Linux `/run/user/<uid>` spellings are deliberately not probed.** They do not exist on macOS,
and carrying them would be a list of paths that can never match — the kind of dead code that reads
as thoroughness.

An absolute path set in **Settings ▸ Sign-In Sources ▸ KeePassXC ▸ socket** wins over discovery, for
someone whose KeePassXC listens somewhere the candidates do not cover — but only when the path
really **is** a socket (`S_IFSOCK`, checked with `stat`). A stale setting must not stop the automatic
path working.

**The socket is the authority for availability**, not Launch Services: a KeePassXC installed
somewhere macOS has not indexed still answers.

## The crypto is ours, and there is no libsodium in this app

`KeePassXCCrypto.swift` is an **original Swift implementation of NaCl `crypto_box`** — X25519 key
agreement, HSalsa20 key derivation, and XSalsa20-Poly1305 `secretbox`. About two hundred lines. No
libsodium is vendored and none is linked.

That was a decision with three closed doors behind it. CryptoKit has Curve25519 but **no** XSalsa20
and **no** standalone Poly1305 — its `ChaChaPoly` is the IETF ChaCha20 construction, a different
cipher. Vendoring libsodium for two primitives would drag a C build into the app target. The Go
archives already in the tree carry `x/crypto`'s copy, but reaching it would mean routing every
protocol message through a helper process. So the two primitives were written: Salsa20's core is four
operations in a loop, and Poly1305 is the well-trodden donna-32 arithmetic.

What keeps that honest is the testing, not the word count:

* Key agreement stays **CryptoKit's** `Curve25519.KeyAgreement`, which also rejects low-order
  results the way libsodium does. Only the derivation and the cipher are ours.
* `KeePassXCCryptoTests` pins both primitives end-to-end against vectors generated from
  `golang.org/x/crypto` — the reference NaCl port — plus the RFC 8439 Poly1305 vector.
* The protocol round-trip test's mock peer seals with the **same** `NaClBox` the client opens with,
  so agreement there would be circular on its own. It is not, because the vectors above pin
  `NaClBox` to an independent implementation first.
* `open` returns nil for anything that does not authenticate — wrong key, mismatched nonce, tampered
  byte — and the tag compare is constant-time, because an early-out would leak how much of a forged
  tag was right.

## How it authenticates: a pairing stored inside your database

`associate` registers a public **identification key** which KeePassXC stores **inside the database**,
under a name the user types into KeePassXC's own dialog. Presenting that pair — id plus key — later,
in `test-associate` and `get-logins`, **is** the whole authentication.

Which makes the pair a bearer credential, and that decides where it lives:
`KeePassXCAssociationStore` puts it in the data-protection keychain, in SimpleVPN's own access group,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, labelled "SimpleVPN ↔ KeePassXC pairing". One item
**per database hash**, because associations are per-database and a person may keep several. The
identification keypair's private half is never used after the `associate`, so only the public half is
kept.

Revocation is symmetric and works: delete the pairing inside KeePassXC and the next
`test-associate` returns code 10 or 11, which drops the stored item and pairs afresh.

## Is a fetch interactive?

Sometimes, and each case is KeePassXC's own dialog rather than one of ours:

* **First use with a given database** — KeePassXC's pairing dialog, where the user names the
  connection. 180-second deadline: that is dialog time.
* **A locked database** — the `get-databasehash` request carries `triggerUnlock`, which raises
  KeePassXC's own unlock (its Touch ID quick-unlock included) instead of failing. SimpleVPN then
  waits up to **60 seconds** for the `database-unlocked` broadcast and re-asks. Again, dialog time,
  not network time.
* **Per-entry access confirmation**, if the user has KeePassXC configured to ask.

**The database password never reaches SimpleVPN.** There is no field for it on this row and no code
path that could accept one.

Blocking socket I/O runs on a dedicated serial queue, never the Swift cooperative pool — an unlock
dialog can sit unanswered for minutes. Cancelling closes the socket, which unblocks the `recv`; only
the socket crosses into the cancellation handler, never the session's other state.

## Finding the entry: KeePassXC matches, we do not

The per-VPN reference is **an address**, not an entry path. A bare hostname is dressed as
`https://host` because KeePassXC's matcher works on URLs; a full URL is kept verbatim. Matching is
then **KeePassXC's own** — an entry matches when its URL field's host is the same site, base-domain
by default and configurable per entry in KeePassXC's Browser Integration settings. So an entry whose
URL says `https://vpn.example.com` is found for the reference `vpn.example.com`.

`account` is an optional username filter for when one address has several entries. With no account,
one match proceeds and **several is a genuine ambiguity** — `pickEntry` throws rather than choosing,
because silently picking one would sign in as somebody unintended. The error names at most four
matches as "name (login)".

The verification code arrives one of two ways: inline on the matched entry when KeePassXC's "include
TOTP in `get-logins`" setting is on, else one more sealed `get-totp` by the entry's uuid with a
30-second deadline. An entry with no code at all is fine — the caller falls back to the typed path.

`CredentialSourceKind.keePassXC.suppliesOTP` is **`true`**, one of only two sources for which it is.

## Cardinality: single

One running app, one browser-integration socket per login session — level 1 is the whole
configuration. **KeePassXC decides which of its open databases matches an entry; SimpleVPN never
names one.** That is why there is no instance list here even though a person may have several
databases open: the choice is not ours to express. Someone who does want to name a specific file
wants the `.kdbx` row instead, which is `.multiple` for exactly that reason.

## The four states, and the one action that clears each

`quickScan()` is a `stat` on each socket candidate. `deepScan` adds **nothing**, deliberately: the
socket either exists or it does not, and no subprocess could learn more.

| State | What SimpleVPN says | The fix |
|---|---|---|
| `.notInstalled` — no socket **and** no `org.keepassxc.keepassxc` bundle | the row is not offered at all | `brew install --cask keepassxc` (we never install it) |
| `.blocked(.integrationOff)` — the app is installed, no socket | "KeePassXC isn't running, or its browser integration is off", with the setting named | open KeePassXC with the database unlocked, and tick **Settings ▸ Browser Integration ▸ Enable browser integration** |
| `.ready` — a socket answered | nothing to say | — |

There is no `.unchecked` state and no `uncheckedNote`: a socket that exists is as much proof as a
cheap probe can offer, and everything past it is interactive by design.

**The installed-but-no-socket case is offered with its steps rather than hidden**, and that is a
deliberate choice: a hidden row is indistinguishable from an app we do not support, which would be a
lie about a vendor we do.

## What is stored, and where — none of it secret

| Thing | Where | Secret? |
|---|---|---|
| the association: the name you typed in KeePassXC + the identification **public** key | the data-protection keychain, one item per database hash, app-only, `…WhenUnlockedThisDeviceOnly` | a **bearer credential** — which is why it is in the keychain and nowhere else |
| the socket path override | `UserDefaults`, `creds.keepassxc.socket` | no — a path |
| `signin.vendor.keepassxc.enabled` | `UserDefaults` | no — a switch |
| `kind`, `reference` (the address to match), `account` | the VPN's profile | no — a hostname and a username |
| the database password | **nowhere.** KeePassXC holds it | — |
| the session keypair, the shared key, nonces | in memory, one connection's lifetime | never persisted |

## What it withholds

* **The database password**, absolutely — there is no path.
* **The identification keypair's private half**, which is discarded after the `associate`.
* **The TOTP seed.** `get-totp` returns a **code**; the seed is never asked for and never sent.
* **Every entry that does not match the address.** `get-logins` is a query, not a dump; there is no
  "list everything" call in this path and none is wanted.
* **Which database it came from.** SimpleVPN sees a hash, which is what the pairing is keyed on. Not
  a path, not a name.

## Failure modes, and the ones that are ambiguous

Wire error codes (KeePassXC's `BrowserAction.h`) are mapped to typed cases in
`KeePassXCError.fromWire`, so the prose a user reads never depends on KeePassXC's own message
strings.

| Case | Wire code | What it means |
|---|---|---|
| `.notRunning` | — | nothing to connect to |
| `.handshakeFailed` | — | the socket answered but the key exchange did not |
| `.databaseLocked` | 1 | locked, or still waiting on the unlock we triggered |
| `.accessDenied` | 6 | KeePassXC's access-confirmation dialog was dismissed |
| `.associationFailed` | 8, 9 | the pairing attempt was refused or cancelled |
| `.associationRevoked` | 10, 11 | KeePassXC no longer recognises our identification key |
| `.noLogins` | 15 | no entry whose **URL** matches |
| `.ambiguous` | — | several entries matched and nothing picks between them |
| `.timedOut`, `.protocolError`, `.serverError` | — | the socket went quiet; a structurally wrong reply; anything else |

Errors can arrive **plaintext on the envelope** (the failure happened before anything could be
encrypted) or **inside the sealed body** (the reply encrypted fine, the action failed). Both are
handled, in that order.

Three are genuinely ambiguous, and the copy says both halves rather than guessing:

1. **`.notRunning` cannot tell "KeePassXC is quit" from "browser integration is off".** Both are
   "no socket". The sentence names both, and so does the row's headline. This is the single most
   common state and it is irreducible from outside.
2. **`.associationFailed` and `.associationRevoked` overlap in practice.** Codes 8/9 mean the
   attempt failed; 10/11 mean the key is unknown. But a KeePassXC that considers a stale key a
   *failure* rather than a *revocation* would send 8 or 9 for what is really 10 — so
   `associationEnsured` treats **both** as "drop the stored pairing and pair afresh", and logs
   "stored association rejected — re-associating". Anything else surfaces.
3. **`.noLogins` is about the URL field, not about the entry.** An entry that plainly exists, with
   the right password, reports "no entry whose URL matches" when its URL field is empty. The
   sentence therefore says to add the address to the entry's URL field, which is the actual fix and
   not an obvious one.

## Manual test recipe

You need: KeePassXC (current release), a database you can unlock, an entry with a username, a
password and a TOTP field whose **URL field** holds your VPN's address, and a VPN in SimpleVPN that
signs in with a username and password.

### 0. Baseline — nothing installed

1. With no KeePassXC, open a VPN's sign-in chooser.
   **Expect:** no KeePassXC row at all. (The KeePass **file** row may still appear — different row,
   different doc.)
2. `brew install --cask keepassxc`, but do **not** launch it. Reopen the chooser.
   **Expect:** a KeePassXC row saying it isn't running or its browser integration is off, naming
   **Settings ▸ Browser Integration ▸ Enable browser integration**. It must **not** say KeePassXC is
   not installed.

### 1. Integration off — the commonest state

1. Launch KeePassXC, unlock the database, and leave browser integration **off**. Press **Check
   Again**.
   **Expect:** still the same row and the same sentence. This is the ambiguity above: quit and
   integration-off look identical, and both are covered by one message.
2. Tick **Enable browser integration**. Press **Check Again**.
   **Expect:** **Ready to use**, with no app restart.
3. Confirm the socket really is where we think:
   `ls -l "$TMPDIR/org.keepassxc.KeePassXC.BrowserServer"`.
   **Expect:** a socket (`s` in the mode bits). If it is somewhere else, **write down where** — that
   is the finding that would change `socketCandidates`.

### 2. The socket path setting

1. Set **Settings ▸ Sign-In Sources ▸ KeePassXC ▸ socket** to the path from step 1.3.
   **Expect:** Ready to use, unchanged.
2. Set it to a path that does not exist.
   **Expect:** **still** Ready to use — discovery takes over, because a stale setting must not break
   the automatic path.
3. Set it to a path that exists but is a **regular file** (`touch /tmp/notasocket`).
   **Expect:** still Ready to use. Only a real socket is honoured.
4. Set it to a relative path (`org.keepassxc…`).
   **Expect:** ignored — only absolute paths are read.
5. Clear it.
   **Expect:** Ready to use.

### 3. Pairing — the first real fetch

1. Point the VPN at the entry: in the editor's Sign-In tab, set the reference to the VPN's
   **address** (e.g. `vpn.example.com`), leave the account empty. Make sure the KeePassXC entry's
   **URL** field holds that address.
2. Connect.
   **Expect:** KeePassXC raises its **pairing dialog** asking you to name the connection. Name it.
   Then the username and password arrive with nothing typed, and if the VPN needs a verification
   code **that arrives too** — `suppliesOTP` is `true` here, so Connect should not have asked you
   for one.
3. Confirm the pairing landed: **Keychain Access**, search "SimpleVPN ↔ KeePassXC pairing".
   **Expect:** exactly one item. Look at it: it holds a name and a base64 **public** key. **No
   password.**
4. Connect again.
   **Expect:** **no dialog at all** — `test-associate` accepted the stored pairing.
5. In KeePassXC, **Settings ▸ Browser Integration ▸ Shared Encryption Keys** (the pairing list) —
   delete SimpleVPN's entry. Connect again.
   **Expect:** the pairing dialog comes back once, and the keychain item is replaced rather than
   duplicated. This is the code 10/11 path.

### 4. A locked database — the unlock hand-off

1. Lock the database in KeePassXC (leave the app running, integration on). Connect.
   **Expect:** **KeePassXC's own unlock** appears — its Touch ID quick-unlock if you have that
   configured. Answer it.
   **Expect:** the connect proceeds without you retrying anything: SimpleVPN waited for the
   `database-unlocked` broadcast and re-asked.
2. Do it again and **dismiss** the unlock instead.
   **Expect:** after about 60 seconds, "The KeePassXC database is locked. Unlock it in KeePassXC,
   then try again." — and the connect panel offers to let you type your sign-in instead. It must
   **not** hang and must not claim KeePassXC is not running.
3. Do it a third time and press **Cancel in SimpleVPN** while KeePassXC's unlock is up.
   **Expect:** the connect stops promptly. (Cancellation closes the socket, which unblocks the
   blocked `recv`.) KeePassXC's dialog may remain — that is KeePassXC's.

### 5. Entry matching — the traps

1. Reference = the exact address in the entry's URL field.
   **Expect:** works.
2. Reference = a **full URL** (`https://vpn.example.com/portal`).
   **Expect:** works, kept verbatim.
3. Empty the entry's **URL** field in KeePassXC and connect.
   **Expect:** "KeePassXC has no entry whose URL matches "vpn.example.com". Add the address to the
   entry's URL field in KeePassXC." Note that the entry exists and is perfectly good — this is the
   ambiguity worth understanding before it bites.
4. Make a **second** entry with the same URL and a different username. Connect with the account
   empty.
   **Expect:** "More than one KeePassXC entry matches (…)", naming at most four as "name (login)",
   and telling you to set the account. **No silent choice.**
5. Set **Account** to one of the two usernames.
   **Expect:** the right one is used.
6. Set Account to a username that matches **neither**.
   **Expect:** the no-entry sentence, not the ambiguity one.
7. An entry with a username but **no password**.
   **Expect:** the fetch returns a username and no password, and the connect panel asks for the
   password rather than signing in blank.

### 6. Verification codes

1. With a TOTP entry and a VPN that needs a code, leave the code field empty and connect.
   **Expect:** success with nothing typed.
2. In KeePassXC, turn **off** "include TOTP in `get-logins`" (Browser Integration settings) and
   connect again.
   **Expect:** still success — SimpleVPN falls back to a separate `get-totp` by uuid. **If this
   fails, say so:** it is the branch least likely to have been exercised.
3. Point the VPN at an entry with **no** TOTP field, on a VPN that does not need a code.
   **Expect:** username and password arrive normally. A missing code must not fail the fetch.
4. Search a diagnostic report for `otpauth://`.
   **Expect:** nothing — only codes cross this channel, never seeds.

### 7. Secrets discipline — checked, not assumed

1. `ps -Ao args | grep -i keepass` during a connect.
   **Expect:** KeePassXC's own process and **nothing of ours** — this row spawns no subprocess at
   all.
2. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` across a first
   connect.
   **Expect:** at most `associated with KeePassXC as <the name you typed>` and "stored association
   rejected — re-associating". No username, no password, no code, no database hash, no key.
3. `defaults read com.bragi0.SimpleVPN | grep -i keepassxc`.
   **Expect:** `creds.keepassxc.socket`'s defaults key and `signin.vendor.keepassxc.enabled` — a
   path and a switch. **No key, no password, no pairing.**
4. Take a diagnostic report and search it for the entry's password and for the base64 identification
   key.
   **Expect:** neither appears.
5. Check the network: `sudo tcpdump -i any port 443` across a connect that fetches.
   **Expect:** nothing attributable to this fetch. The channel is a unix socket; there is no server.

### 8. MDM

1. Force `SignInSourcesForbidden = ["keepassxc"]`.
   **Expect:** no KeePassXC row anywhere, and the Settings switch locked with a reason.
2. Force `creds.keepassxc.socket` to a path.
   **Expect:** the row shows policy's value, read-only, says who set it, and SimpleVPN uses it —
   subject to the same "only if it is really a socket" rule.

## Known limitations, stated rather than discovered

* **"Not running" and "integration off" are one state.** Irreducible from outside a socket check.
  Both halves are in the sentence.
* **Which database answered is KeePassXC's choice.** With several open, SimpleVPN cannot express a
  preference. Someone who needs to name a file wants `Docs/AuthPwdKeePassFile.md`.
* **No entry listing, and no browse.** Unlike 1Password there is no picker: the reference is an
  address, typed. `get-logins` is the only read, and adding a browse would mean asking KeePassXC to
  enumerate a database, which is not what this protocol is for.
* **The pairing is a bearer credential in your keychain.** Anything that can read SimpleVPN's
  keychain items can present it. That is the protocol's design, and it is why the item is
  app-only, this-device-only and not synced.
* **A KeePassXC too old for protocol v2** fails at the handshake with "KeePassXC refused the
  connection handshake". Per the house rule we describe the current release only; the fix is to
  update.
* **`accessDenied` (code 6) is not retried.** If per-entry confirmation is on and the prompt is
  dismissed, the connect fails with the sentence saying to choose Allow next time. Retrying
  automatically would mean re-raising a dialog somebody just refused.

## What is fixture-tested

`SimpleVPNTests/Credentials/KeePassXCProtocolTests.swift` pins the pieces that never see a socket
(envelope shapes, nonce discipline including the +1 rule, error-code mapping, stream framing with
split and glued messages, URL dressing, socket-candidate order) **and** runs the full round trip —
handshake → `get-databasehash` locked → `triggerUnlock` → the unlock signal → `associate` →
`test-associate` → `get-logins` → `get-totp` — against a mock KeePassXC serving the real wire format
over a real unix socket. `KeePassXCCryptoTests.swift` pins `NaClBox` against vectors generated from
`golang.org/x/crypto` plus RFC 8439's Poly1305 vector, which is what stops the round-trip test being
circular. `SignInSourceTests.swift` covers the three availability states and asserts every
`KeePassXCError` explains itself.

**Never run:** a real KeePassXC, a real pairing dialog, a real unlock, a real Touch ID quick-unlock,
and a real database. That is the whole of what the recipe above is for.
