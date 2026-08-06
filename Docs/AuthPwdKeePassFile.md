# Signing in from a KeePass `.kdbx` file

One adapter, three products. **KeePassXC**, **Strongbox** and **KeePassium** all store
their entries in a KeePass 2 database (`.kdbx`), and none of them needs a vendor API for
SimpleVPN to read one — the database is the API. So `LocalVaultVendor.keePassFile` is named
for the **format**, not for a brand, and it serves all three.

The existing **KeePassXC row is unchanged and stays preferred.** A running KeePassXC owns
its own unlock, asks the user to allow SimpleVPN once, and never lets a database password
near this app. Where that works, it is strictly better. This row is for what it cannot
reach: a Strongbox or KeePassium user, a closed KeePassXC, a database on a share with no
KeePass app installed at all.

## What SimpleVPN does, exactly

| Step | Who does it |
|---|---|
| Read the plaintext outer header (version, KDF, KDF seed) | SimpleVPN — `KeePassDatabaseFile.swift`, no crypto, bounded read |
| Derive the key, authenticate and decrypt the body, parse the XML | **`keepassxc-cli`** |
| Answer a security key's challenge as part of the unlock | **`keepassxc-cli`**, talking to the key itself |
| Answer that challenge for a *check* the user asked for | SimpleVPN — `YubiKeyChallengeResponse` via `ykman` |

**SimpleVPN contains no cryptography for your database.** The reason is in
`KeePassFileProvider.swift`'s header: writing a kdbx reader would mean writing AES-KDF,
Argon2d/Argon2id, HMAC-SHA-256 block authentication, AES-CBC/ChaCha20, gzip, an inner
random stream and the XML — a decryption path for somebody's entire password vault, with no
second implementation to differentially test against, and Argon2 is in neither CryptoKit
nor CommonCrypto. `keepassxc-cli` is the reference implementation, maintained by the people
who define the format, and it **ships inside the KeePassXC app** at
`/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli` (the Homebrew cask also symlinks
it into the Homebrew bin directory), so for most of this audience *the app being installed
already means the tool is available*.

**Read-only, always.** Every invocation is `show` or `search`. The allow-list of
subcommands is a constant with a test behind it: no `add`, no `edit`, no `import`, no
`db-create`, no `merge`. A corrupted vault is unrecoverable and it is not our file. Nor is
a KeePass 1 `.kdb` ever converted, even though the tool can — that is a one-way migration
of somebody's data.

## Where the database password goes

* **stdin, and nowhere else.** `LocalToolRunner.run(stdin:)`. Argv is world-readable
  through `ps`, so what rides argv is the database path, the key-file path, the entry path
  and a slot number — names, not secrets.
* **Nothing is kept, by default.** You type it once per run of SimpleVPN.
* **Optionally, the Touch ID keychain — and never the ordinary one.** In the ordinary
  keychain, macOS would release it to SimpleVPN silently whenever it asked, which would
  make this app a silent decryptor of everything you own. `.userPresence` means something
  has to happen at the keyboard first. That is the same bar KeePassXC and Strongbox apply
  to their own quick unlock.
* Never `providerConfiguration`, never a defaults key, never a log line, never an error
  string, never a diagnostic bundle.
* Kept per **database** (keyed by a SHA-256 of its path, so the path itself is not
  published in Keychain Access), not per VPN: five VPNs reading one database must not mean
  five copies of its password.

## Setting it up — a recipe per product

All three recipes need the same two things first:

```sh
brew install --cask keepassxc     # SimpleVPN never installs it for you
```

…then, in SimpleVPN, **Settings ▸ Sign-In Sources ▸ KeePass database file**: choose your
`.kdbx`, type its password, and (optionally) turn on *Remember the database password with
Touch ID*.

### More than one database

You can set up **as many databases as you like** — a work one and a personal one is the
ordinary case. Each is a named entry in **Your KeePass Databases**, with its own file, its own
key file and its own security-key slot, and each is checked on its own: the work database
being on a drive that isn't plugged in does not stop the personal one working, and the pane
says which is which rather than averaging them into one answer.

Three levels, kept apart deliberately (see `SimpleVPN/Credentials/SignInSourceInstances.swift`):

| Level | What it is | Where it lives |
|---|---|---|
| 1 · transport | Where `keepassxc-cli` is on this Mac | App settings, one per Mac — the same tool opens every database |
| 2 · database | Which `.kdbx`, plus its key file and slot | App settings, **one or more**, each named |
| 3 · per VPN | Which database + which entry (+ optional username) | That VPN's profile. No secrets, ever — not even a path |

A VPN remembers its database by an **opaque id**, not by its name or its path: rename the
database, or move the file, and the VPNs reading it keep working. Removing a database names the
VPNs that read it first, and each of those then asks you to choose another rather than being
silently pointed at somebody else's vault.

Per VPN, in the **Sign-In** tab, the question is asked as two numbered steps: **which database**,
then **which entry** in it. The entry is named by its **path in the database** — its groups and
its title, separated by slashes, e.g. `VPN/Work`.

A VPN set up before any of this existed keeps working untouched: the previous single-valued
settings become the first database (named after its own file), and a profile that names no
database reads that one.

### KeePassXC

1. In KeePassXC, **Database ▸ Database Settings** shows the file's path (it is also in the
   window title). Copy it, or use **Choose Database…** in SimpleVPN.
2. If the database has a key file, KeePassXC lists it under **Database Settings ▸ Security
   ▸ Database Credentials**. Set it in SimpleVPN's **KeePass key file**.
3. If the database uses a YubiKey challenge-response, the same panel shows which slot. Put
   `1` or `2` in **KeePass security key slot**, then press **Check My Security Key**.
4. **Prefer the KeePassXC row instead** if you keep the app running. It is a better answer:
   the app does the unlocking, so SimpleVPN never sees your database password.

### Strongbox

1. Strongbox ▸ the database's **⋯ ▸ Database Settings** (or **Preferences ▸ Databases**)
   shows the underlying file. For a local database it is a `.kdbx` you can point at
   directly. For one Strongbox keeps in iCloud, the file lives under
   `~/Library/Mobile Documents/` — SimpleVPN handles a not-yet-downloaded one as its own
   state and says so, rather than reporting a read error.
2. Strongbox's key file and YubiKey settings are in the same place; set them in SimpleVPN's
   corresponding rows.
3. Strongbox does not have to be running, and SimpleVPN does not talk to it at all.

### KeePassium

1. KeePassium ▸ the database list ▸ the database's **ⓘ** shows its file location.
   KeePassium on the Mac normally keeps databases in iCloud Drive or a chosen folder.
2. Key file and hardware-key settings appear on KeePassium's own unlock screen; mirror them
   in SimpleVPN.
3. KeePassium does not have to be running.

## Every "not working" state, and the one thing that fixes it

| State | What SimpleVPN says | The fix |
|---|---|---|
| Nothing KeePass on this Mac and no database chosen | the row is not offered at all | — (nothing to advertise) |
| `keepassxc-cli` not installed | "SimpleVPN needs KeePassXC's command-line tool" + the `brew` command | install KeePassXC |
| `keepassxc-cli` found somewhere we won't run from | names the exact path | paste it into **KeePassXC tool location**, or reinstall via Homebrew |
| No database chosen | "No KeePass database is chosen yet" | **Choose Database…** |
| Database moved / disk not mounted | "SimpleVPN can't find your KeePass database any more" | point at it again |
| Database not downloaded (iCloud placeholder) | its own state, *not* a read error | open the folder in the Finder and wait |
| macOS won't let us read it | its own state | allow SimpleVPN in **System Settings ▸ Privacy & Security ▸ Files and Folders**, or move the database |
| Not a `.kdbx` | "That file isn't a KeePass database SimpleVPN can read" | choose the `.kdbx` |
| A KeePass 1 `.kdb` | its own sentence, naming the conversion | convert it in KeePassXC (SimpleVPN never touches your file) |
| Newer KDBX than the tool reads | "newer than the KeePassXC on this Mac can read" | update KeePassXC |
| No database password held | "SimpleVPN needs your KeePass database's password" (`vaultLocked`) | type it in Settings |
| The database refused the last unlock | "Your KeePass database wouldn't open", listing every configured factor | correct the password, the key file, or the security key |
| Security key didn't answer | "Your security key didn't answer" | plug it in and touch it |
| No such entry | names the entry path | check the path — groups and title, slash-separated |
| Entry has no password | names the entry | put a password in it |

## macOS file permissions (TCC) — what is verified and what is not

The app is **not** sandboxed, and that does not exempt it. macOS protects `~/Desktop`,
`~/Documents`, `~/Downloads` and iCloud Drive from *every* app and asks once per app.

* **Verified here:** a file whose contents cannot be opened lets `stat` through and refuses
  `open` with `EACCES` (measured with `chmod 000`, which is the same syscall outcome). Left
  unhandled, that would be reported as an *empty or truncated database*. So
  `KeePassDatabaseFile.classify` calls `access(path, R_OK)` before reading and reports
  `.permissionDenied`, which becomes its own row state and its own sentence.
* **NOT verified here:** whether macOS's consent prompt appears, what it says, and whether
  choosing a file with `NSOpenPanel` suppresses it for a non-sandboxed app. That needs a
  human with a database in a protected folder and a build whose TCC state has not already
  been granted. **Manual check, still owed** — see below.
* The app declares no `NS*FolderUsageDescription` strings, so any prompt would carry
  macOS's own default wording. Adding one is a one-line change to `project.yml` once the
  behaviour above has been watched.

## Still owed to a human (nothing below has been done)

Nothing in this feature has been exercised against a real database: KeePassXC, Strongbox,
KeePassium and `keepassxc-cli` are all absent from the machine it was written on, and the
programme's standing rules forbid installing software to get one. The header parsing is
tested against **real KDBX3 and KDBX4 header bytes** built from KeePassXC's own source, and
every command line, output shape and error string is tested against strings quoted from
that source — but no unlock has ever run. Specifically:

1. `keepassxc-cli show --show-protected -a UserName -a Password <db> <entry>` with the
   password on stdin: confirm the two values come back one per line, values only.
2. An entry with an **empty username**: confirm the first line is empty rather than absent.
3. A **wrong password**: confirm stderr contains `Invalid credentials were provided`, and
   that it is not pushed past the runner's 200-character cap by a long database path.
4. A database needing a **key file** that is not supplied: confirm it also reports invalid
   credentials (this is the documented ambiguity — our message lists every factor).
5. A **YubiKey** database: confirm `--yubikey 2` unlocks, that a touch-required slot flashes
   and waits within our 60-second deadline, and that **only one touch** is needed.
6. **Check My Security Key** against the same database: confirm `ykman` returns 20 bytes for
   the header's KDF seed.
7. A **KDBX3** database as well as a KDBX4 one.
8. A database in **`~/Documents`** and one in **iCloud Drive**: confirm which TCC prompt (if
   any) appears, and whether choosing via **Choose Database…** avoids it.
9. A **not-yet-downloaded** iCloud database: confirm the `.icloud` placeholder is what is on
   disk and that our state matches.
10. Confirm `keepassxc-cli --version` is reported in the Settings pane's discovery list, and
    that the copy inside `/Applications/KeePassXC.app/Contents/MacOS/` is found.

## Not built, and why

* **Verification codes.** `keepassxc-cli show -t` prints an entry's current code, but its
  own `Show.cpp` **fails the whole run** when the entry has not got one — and there is no
  way to ask whether an entry has one without unlocking the database, which is the expensive
  part and may want a finger on a security key. Passing `-t` speculatively would turn every
  ordinary entry's fetch into a failed sign-in. So `suppliesOTP` is `false` and the code is
  typed. Doing better needs a per-VPN "this entry has a code" switch, which is a follow-up.
* **A connect-time password prompt.** The database password is entered in Settings and held
  for the run. A prompt at connect time is the obvious next step; it is not here because it
  is a new interaction surface rather than a missing line.
* **`keepassxc-cli export`.** One invocation would fetch every entry and let us search
  locally — and would pull every password in the vault into this process's memory. Rejected.
* **Writing anything.** Never.
