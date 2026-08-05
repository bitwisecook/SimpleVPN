# Finding a password manager's tool — the discovery map

SimpleVPN answers two different questions about a vendor's command-line tool, and keeping
them apart is the whole design.

| | **Execution** (`LocalToolRunner`) | **Discovery** (`ToolDiscovery`) |
|---|---|---|
| Question | *May we run this?* | *Where is it?* |
| `$PATH` | **never consulted** | consulted |
| World-writable directory | refused, even if the user names it | reported, and refused |
| Scope | a fixed allow-list of documented install directories | everything in this document |
| Runs anything | yes — that is the point | **never**, not even `--version` |

Execution is a **security control**: a user-writable `PATH` entry must not decide which binary
gets handed a request for a password. Nothing in the discovery half relaxes it — `ToolDiscovery`
asks `LocalToolRunner` whether a path is acceptable rather than re-deciding.

The **gap between them is the product.** "Bitwarden's `bw` isn't installed" is a lie when `bw`
is sitting in `~/.bun/bin`. The honest sentence names the path and the one-field fix, and it has
a state of its own: `LocalVaultBlock.toolOutsideAllowList`.

Two rules for the discovery half:

1. **Filesystem only.** `stat`, plus the occasional `Info.plist`. It never executes a binary to
   learn its version — doing that would hand a `PATH`-resolved binary exactly the execution the
   allow-list exists to deny. Versions are probed only for a path already inside the allow-list;
   everything else reports `version unknown` **with the reason**.
2. **Local and silent.** No network, no prompts, nothing written. It therefore defaults **on**
   (`creds.discovery`) — a detection feature that does not detect is inert. Putting the results
   in a *submitted* diagnostic report is a separate, per-submission opt-in.

---

## Per-vendor locations

Every path below comes from the vendor's own installation guide, its install script, or the
Homebrew formula/cask source that installs it. **Paths we could not confirm from a primary source
are listed as unconfirmed and are not searched as though they were documented** — a guessed path
presented as a real one sends people looking in the wrong place.

`$HOMEBREW_PREFIX` is `/opt/homebrew` on Apple silicon and `/usr/local` on Intel.

### Keeper Commander (`keeper`) — adapter built

| Install method | Path | Source |
|---|---|---|
| `pip3 install --user keepercommander` | `~/Library/Python/<X.Y>/bin/keeper` | <https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup/installation-on-mac> |
| virtual environment (Keeper's recommendation) | `<venv>/bin/keeper` — **unguessable by design** | same |
| `brew install keeper-commander` | `$HOMEBREW_PREFIX/bin/keeper` | <https://formulae.brew.sh/formula/keeper-commander> |
| Service Mode config | `~/.keeper/service_config.json` | <https://docs.keeper.io/en/keeperpam/commander-cli/service-mode-rest-api> |

- **Unconfirmed:** the standalone `.pkg`'s install path. Keeper documents the installer's
  filename and not where it puts anything, so SimpleVPN asserts no vendor path for it.
- **Unconfirmed:** Service Mode's port. There is **no default** — it is a required parameter.
  Do not document one.
- The virtual-environment case is exactly why the explicit-path setting exists.

### KeePassXC (`keepassxc-cli`) — adapter built (over the app's socket)

| Install method | Path | Source |
|---|---|---|
| any install — **inside the app bundle** | `/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli` | cask source: `binary "#{appdir}/KeePassXC.app/Contents/MacOS/keepassxc-cli"` — <https://github.com/Homebrew/homebrew-cask/blob/main/Casks/k/keepassxc.rb> |
| `brew install --cask keepassxc` | also symlinked to `$HOMEBREW_PREFIX/bin/keepassxc-cli` | same |
| browser-integration socket | `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer`, where `$TMPDIR` is the **Darwin per-user temp dir** from `confstr(_CS_DARWIN_USER_TEMP_DIR)` | `localServerPath()` in <https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserShared.cpp> |
| config | `~/Library/Application Support/keepassxc/keepassxc.ini` | `defaultConfigFiles()` in `src/core/Config.cpp` |

- **There is no `keepassxc-cli` formula** — cask only.
- The socket is **not** in a Group Container and **not** in `/tmp`. KeePassXC uses
  `_CS_DARWIN_USER_TEMP_DIR` deliberately so a `$TMPDIR` override cannot move it. The
  `/run/user/<uid>/…` spellings are Linux-only.
- This is the canonical **CLI-inside-an-app-bundle** case: "the app is installed" already means
  "the CLI is available", so a discovery map that misses that class is flatly wrong about a
  vendor we support.

### 1Password (`op`) — adapter built, but **not through `op`**

SimpleVPN talks to 1Password over its SDK's signed IPC to the running app. `op` is discovered and
version-reported for diagnostics only; there is no path for a user to set.

| Install method | Path | Source |
|---|---|---|
| standalone pkg / zip | `/usr/local/bin/op` — 1Password documents this unconditionally (an Intel-shaped path) | <https://www.1password.dev/cli/get-started/> |
| `brew install --cask 1password-cli` | `$HOMEBREW_PREFIX/bin/op` (cask ships a zip with `binary "op"`) | <https://github.com/Homebrew/homebrew-cask/blob/main/Casks/1/1password-cli.rb> |
| app | `/Applications/1Password.app`, bundle id `com.1password.1password` | <https://support.1password.com/deploy-1password/> |
| **bundled** SSH signing helper | `/Applications/1Password.app/Contents/MacOS/op-ssh-sign` | <https://www.1password.dev/ssh/git-commit-signing/> |
| SSH agent socket | `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` | <https://www.1password.dev/ssh/agent/compatibility/> |

- The app does **not** bundle `op`. It does bundle `op-ssh-sign` — a second documented
  in-bundle binary, and useful to know about even though we do not run it.
- **Documentation host moved:** `developer.1password.com/docs/…` 301s to `www.1password.dev/…`,
  and the new host 308s a trailing slash away. `VendorDocs` carries the post-redirect,
  no-trailing-slash form; see the comment there.
- **Unconfirmed:** the 1Password 7 bundle id, and the transport `op` ↔ app IPC uses.

### Bitwarden (`bw`) — no adapter yet

| Install method | Path | Source |
|---|---|---|
| `npm install -g @bitwarden/cli` | `$(npm prefix -g)/bin/bw` | <https://bitwarden.com/help/cli/> |
| `brew install bitwarden-cli` | `$HOMEBREW_PREFIX/bin/bw` (the GPL `oss` build) | <https://github.com/Homebrew/homebrew-core/blob/main/Formula/b/bitwarden-cli.rb> |
| standalone zip | **no destination documented** — "add the executable to your PATH" | <https://bitwarden.com/help/cli/> |
| `bw serve` | port **8087**, bound to `localhost` | <https://bitwarden.com/help/cli/> |
| CLI data | `~/Library/Application Support/Bitwarden CLI` (`BITWARDENCLI_APPDATA_DIR`) | <https://bitwarden.com/help/data-storage/> |

The standalone zip's "add it to your PATH" is precisely the case that produces
`toolOutsideAllowList`: it works for the user's shell and not for us, and the fix is one field.

### Dashlane (`dcli`), LastPass (`lpass`), Proton Pass (`pass-cli`), Passbolt, `pass`, `gopass`, Vault, `ykman`

| Tool | Install method | Path | Source |
|---|---|---|---|
| `dcli` | `brew install dashlane/tap/dashlane-cli` | `$HOMEBREW_PREFIX/bin/dcli` | <https://cli.dashlane.com/install> |
| `dcli` | manual binary | `/usr/local/bin/dcli` (documented verbatim, no Apple-silicon branch) | same |
| `lpass` | `brew install lastpass-cli` | `$HOMEBREW_PREFIX/bin/lpass` | <https://formulae.brew.sh/formula/lastpass-cli> |
| `lpass` | config | `$LPASS_HOME`, else XDG, else `~/.lpass` | <https://github.com/lastpass/lastpass-cli/blob/master/lpass.1.txt> |
| `pass-cli` | `brew install protonpass/tap/pass-cli` | `$HOMEBREW_PREFIX/bin/pass-cli` | <https://protonpass.github.io/pass-cli/get-started/installation/> |
| `pass-cli` | `install.sh` | prefers `~/.local/bin`, falls back to `/usr/local/bin` | <https://raw.githubusercontent.com/protonpass/pass-cli/main/install.sh> |
| `passbolt` | `brew install go-passbolt-cli` | `$HOMEBREW_PREFIX/bin/passbolt` — the **formula** is `go-passbolt-cli`, the **binary** is `passbolt` | <https://github.com/Homebrew/homebrew-core/blob/main/Formula/g/go-passbolt-cli.rb> |
| `pass` | `brew install pass` | `$HOMEBREW_PREFIX/bin/pass` | <https://formulae.brew.sh/formula/pass> |
| `pass` | `port install pass` | `/opt/local/bin/pass` | <https://ports.macports.org/port/pass/> |
| `pass` | store | `~/.password-store` | <https://www.passwordstore.org/> |
| `gopass` | `brew install gopass` | `$HOMEBREW_PREFIX/bin/gopass` | <https://formulae.brew.sh/formula/gopass> |
| `gopass` | `go install` | `$GOBIN/gopass`, default `~/go/bin/gopass` | <https://go.dev/ref/mod#go-install> |
| `vault` | `brew install hashicorp/tap/vault` | `$HOMEBREW_PREFIX/bin/vault` | <https://developer.hashicorp.com/vault/install> |
| `vault` | standalone zip | **no destination documented** | same |
| `ykman` | `brew install ykman` | `$HOMEBREW_PREFIX/bin/ykman` | <https://formulae.brew.sh/formula/ykman> |
| `ykman` | **inside the app bundle** | `/Applications/YubiKey Manager.app/Contents/MacOS/ykman` | <https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html> |

**Proton Pass's tool is `pass-cli`, not `pass`.** `pass` is password-store — a different product,
a different vault. Both are searched, separately.

**`ykman` is the second confirmed in-bundle CLI.** Yubico publishes the path verbatim. SimpleVPN
discovers it; what the app does with a YubiKey is not this document's subject.

- **Unconfirmed:** the binary name `go install` produces for the Passbolt CLI (`passbolt` vs
  `go-passbolt-cli`). Both names are searched.
- **Unconfirmed:** `dcli`'s config directory on macOS, and `ykman`'s.
- **No deprecation claim** is made about `lpass`: there is no formal notice, only a quiet
  release history.

### PKCS#11 modules — **not this map's job**

**`ToolDiscovery` deliberately does not search for PKCS#11 modules.**
`SimpleVPN/ControlPlane/PKCS11Discovery.swift` already does, and it answers a question this map
cannot: whether a module is merely *installed* or is *registered with p11-kit* — which is what
decides whether it can be loaded at all, since p11-kit only loads registered modules and RFC
7512's `module-path=` does not work (measured). Duplicating a shorter, dumber list here would give
two answers to one question.

**Take module paths from that file, not from this document.** Two corrections it records that a
plausible-sounding list would get wrong:

- **`~/.pkcs11_modules/` is not a p11-kit path.** It appears in a lot of prose and in none of
  p11-kit's own behaviour. The real registry directories were extracted from the installed
  `libp11-kit.0.dylib` and are listed in `PKCS11Discovery.registryDirectories`.
- **Installed ≠ loadable.** `PKCS11Module.registeredWithP11Kit` is the distinction, and the UI
  has to say which one it means.

A module is also a **loaded library, not an executed program**, so the allow-list reasoning in
this document does not transfer to it unchanged. That is a further reason to leave it where it is.

---

## Generic install directories

Each row is the location manager's **own** documentation.

| Manager | Directory | Source |
|---|---|---|
| Homebrew, Apple silicon | `/opt/homebrew/bin` | <https://docs.brew.sh/Installation> |
| Homebrew, Intel | `/usr/local/bin` | same |
| Homebrew, relocated | `$HOMEBREW_PREFIX/bin` (exported by `brew shellenv`) | <https://docs.brew.sh/FAQ> |
| Homebrew casks | `/Applications` (`--appdir`, `HOMEBREW_CASK_OPTS`) | <https://docs.brew.sh/Cask-Cookbook> |
| MacPorts | `/opt/local/bin` | <https://guide.macports.org/> |
| pipx | `$PIPX_BIN_DIR`, default `~/.local/bin`; `--global` → `/usr/local/bin` | <https://pipx.pypa.io/latest/how-to/configure-paths/> |
| `pip --user`, framework Python | `~/Library/Python/<X.Y>/bin` | <https://docs.python.org/3/library/site.html#site.USER_BASE> |
| npm global | `$prefix/bin` — "on most systems `/usr/local`" | <https://docs.npmjs.com/cli/v10/configuring-npm/folders> |
| nvm | `$NVM_DIR/versions/node/<version>/bin`, default `~/.nvm` | <https://github.com/nvm-sh/nvm> |
| bun | `~/.bun/bin` (`BUN_INSTALL`) | <https://bun.sh/docs/installation> |
| volta | `~/.volta/bin` (`VOLTA_HOME`) | <https://docs.volta.sh/advanced/installers> |
| pnpm | **`~/Library/pnpm/bin`** on macOS (`globalBinDir`) | <https://pnpm.io/settings/other#globalbindir> |
| yarn (classic) | `yarn config set prefix`; global modules `~/.config/yarn/global` | <https://classic.yarnpkg.com/en/docs/cli/global/> |
| Go | `$GOBIN`, else `$GOPATH/bin`, else `~/go/bin` | <https://go.dev/ref/mod#go-install> |
| Cargo | `$CARGO_HOME/bin`, default `~/.cargo/bin` | <https://doc.rust-lang.org/cargo/guide/cargo-home.html> |
| mise | `~/.local/share/mise/shims` | <https://mise.jdx.dev/dev-tools/shims.html> |
| asdf | `${ASDF_DATA_DIR:-$HOME/.asdf}/shims` | <https://asdf-vm.com/manage/configuration.html> |
| Nix, user profile | `~/.nix-profile/bin` | <https://nix.dev/manual/nix/2.34/package-management/profiles> |
| Nix, default profile | `/nix/var/nix/profiles/default/bin` | same |
| nix-darwin | `/run/current-system/sw/bin` | <https://nix-darwin.github.io/nix-darwin/manual/> |
| Setapp | `/Applications/Setapp` (admin), `~/Applications/Setapp` (standard user) | <https://support.setapp.com/hc/en-us/articles/360002037440> |
| Apps | user + Mac App Store → `/Applications`; Apple's built-ins → `/System/Applications` | <https://support.apple.com/guide/security/role-of-apple-file-system-seca6147599e/web> |

Notes:

- **pnpm's macOS default is `~/Library/pnpm/bin`**, not the Linux `~/.local/share/pnpm/bin`.
  Older releases put binaries directly in `PNPM_HOME`, so both are searched.
- **Unconfirmed:** `PNPM_HOME`'s own default value (pnpm documents `globalBinDir`'s, not
  `PNPM_HOME`'s); npm's prefix for a Homebrew node (npm's docs never mention Homebrew); the
  non-framework `pip --user` bin directory (derived from `site.USER_BASE`); Yarn Berry has no
  global-bin path at all — `yarn global` is deprecated.
- **Only the execution allow-list is security-relevant.** It is a much shorter list, in
  `LocalToolRunner.systemDirectories` + `userDirectories`, and everything above beyond it is
  informational.

---

## What a report says per tool

`DiscoveredTool` carries: found or not, **every** path with the class that put it there, which
one we would actually run, and the version or the reason it is unknown. Per path,
`ToolUsability` is one of:

| State | Meaning | Is it a problem? |
|---|---|---|
| `runnable` | inside the allow-list, or explicitly set by the user | no |
| `outsideAllowList` | a real executable in a safe directory we do not search | **no** — set it explicitly and it works. This is the sanctioned escape hatch. |
| `unsafeDirectory` | the directory is world-writable (or group-writable by a non-admin group) | **yes**, and it stays refused even when the user names the path: there, anyone on the Mac chooses what we execute |
| `notExecutable` | present, but not a regular executable file | yes |

---

## Manual test recipe (for someone who has one of these installed)

1. **Confirm the honest "found but not runnable" state.** Copy a tool somewhere off the
   allow-list and make sure the shell can see it:
   ```sh
   mkdir -p ~/.bun/bin && cp "$(command -v keeper)" ~/.bun/bin/
   ```
   SimpleVPN's chooser row must say *"Keeper Commander is installed, but not somewhere SimpleVPN
   will run it from"* and the banner must **name that path**. It must not say "isn't installed".
2. **Use the escape hatch.** Paste the path into **Settings ▸ Sign-In Sources ▸ Keeper Commander
   location**. The validation line must read *"SimpleVPN doesn't look in this folder on its own —
   it will use this one because you chose it"*, and the row must become usable with no restart.
3. **Confirm the refusal that stands.** `chmod 777` the containing directory. The same path must
   now report *"anyone using this Mac can replace files in that folder"* and must **not** run,
   even though it is explicitly set.
4. **Confirm value versus suggestion.** Clear the field. The detected path must appear as **grey
   placeholder** text, and a separate **"SimpleVPN found"** row must show it. With VoiceOver on,
   the field's value must be spoken as *"Not set. SimpleVPN uses the one it found: …"* — never as
   the bare path, which would be indistinguishable from a value you set.
5. **Confirm the master switch.** Turn **Look for password apps on this Mac** off. Every vendor
   row must disappear from the chooser, and no password app may be mentioned anywhere. Typing,
   the keychain and Apple Passwords must all still be offered.
