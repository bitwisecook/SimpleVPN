// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSources.swift
//  "How do you want to sign in?" — the plain-English list of sign-in sources
//  offered before the first connect, and the rules that decide which of them are
//  honestly on offer on THIS Mac.
//
//  Two classes of entry, and the difference between them is the whole point:
//
//   • FETCHABLE (`.fetches`) — SimpleVPN gets the sign-in itself: typing it, the
//     Apple keychain, Apple Passwords' AutoFill, or a password app we can really
//     talk to locally (1Password, KeePassXC, Keeper). Picking one changes what
//     happens when you connect.
//   • A POINTER (`.hint`) — a password app that IS installed but that nothing on
//     this Mac lets us read. Listing it still earns its place: it answers "where
//     IS my password?" for the person staring at an empty field. It can never be
//     picked, and its wording says why.
//
//  The vendor list is DELIBERATELY not hard-coded case by case. Each vendor
//  contributes (a) a live probe — `LocalVaultAdapter`, see LocalVaultAdapters
//  .swift — and (b) a block of copy in `LocalVaultCopy` below. Adding Bitwarden's
//  `bw` or LastPass's `lpass` later is one adapter plus one copy entry, not a new
//  branch in five switches. That shape exists because the first version of this
//  file DID hard-code "Keeper can't be read", which was simply wrong.
//
//  Everything in this file is pure data over injected facts, so every rule —
//  including "installed but the integration is switched off", "installed but not
//  signed in", and "an app we can't read never appears as one we can" — is
//  unit-testable with no 1Password, no KeePassXC, no Keeper and no /Applications.
//
//  Wording rules (AGENTS.md glossary, binding): "sign in" / "sign-in",
//  "verification code", "username" / "password". Never "credential store",
//  "provider", "vault integration" or a bare "OTP" in anything a user reads or
//  hears.
//

import Foundation
// For ASSettingsHelper only — opening the AutoFill pane. SimpleVPN ships no
// credential-provider extension of its own and this file asks AuthenticationServices
// nothing about one.
import AuthenticationServices

// MARK: - Vendors we can actually talk to

/// A password app SimpleVPN reaches over a LOCAL channel. Membership here is a
/// claim we must be able to back with a working fetch.
///
/// A VENDOR IS NOT A TRANSPORT — see `AuthTransport`. Keeping the two
/// separate is what lets one future file-backed adapter serve KeePassXC,
/// Strongbox and KeePassium (all three store the same KeePass `.kdbx`) instead
/// of three near-copies, and what lets Keeper's CLI and its local daemon be one
/// vendor with two ways in.
nonisolated enum LocalVaultVendor: String, CaseIterable, Sendable, Hashable {
    case onePassword
    case keePassXC
    case keeper
    case bitwarden
    /// Dashlane, reached through `dcli` — Dashlane's own command-line tool, and the
    /// only local read path Dashlane has (the desktop app exposes no socket, no
    /// daemon and no IPC). See DashlaneProvider, whose header explains the one flag
    /// the whole source turns on: `--output json`, so the password is printed to us
    /// instead of being copied to the pasteboard the way `dcli` does by default.
    case dashlane
    /// A KeePass `.kdbx` FILE, read directly — the `.file` transport, and the one
    /// entry here that is not a brand. It is deliberately not called "Strongbox" or
    /// "KeePassium": all three of those products plus KeePassXC store the same
    /// format, so the vendor is the FORMAT and one adapter serves everyone who uses
    /// it (see `KeePassFileProvider`). KeePassXC keeps its own row above, because a
    /// running app owning its own unlock is a better answer than a file on disk.
    case keePassFile
    /// A `pass` / `gopass` PASSWORD STORE — a directory of GPG-encrypted files.
    /// Like `.keePassFile` this is a FORMAT rather than a brand: `pass` and `gopass`
    /// share the same layout, and SimpleVPN reads it with `gpg` directly, so neither
    /// tool has to be installed for the source to work (see PasswordStoreReader).
    case passwordStore
    /// LastPass, through `lpass` — LastPass's own command-line tool, and the only
    /// local read path LastPass has. Reached over `.cli`, with the tool's own agent
    /// holding the vault key (see LastPassProvider). Listed LAST on purpose: it is
    /// the least capable of the sources SimpleVPN reads — it can never hand over a
    /// verification code — and its own copy says so rather than letting somebody
    /// find out at connect time.
    case lastPass
    /// PROTON PASS, through Proton's own command-line tool. A BRAND, unlike the two
    /// format entries above: it is one vendor, one account, one hosted service.
    ///
    /// NOT TO BE CONFUSED WITH `.passwordStore`, and the confusion is a real risk
    /// rather than a theoretical one — Proton's tool is called `pass-cli` and the
    /// unix password store's is called `pass`, discovery searches by binary name, and
    /// the two read completely different vaults. `ToolCatalog` keeps three separate
    /// entries (`pass`, `gopass`, `pass-cli`) and only `pass-cli` maps here; see
    /// ProtonPassProvider.swift's header for the rest of the separation.
    case protonPass
    /// A PASSBOLT SERVER, read through Passbolt's own `go-passbolt-cli`. The first
    /// vendor here whose level-2 instance is not a thing on disk: an instance is a
    /// SERVER — an https address plus that server's own OpenPGP sign-in
    /// configuration — so no `stat` can ever settle whether it can answer. See
    /// PassboltServer.swift, which states what that costs the availability model.
    case passbolt
}

// THE TRANSPORT AXIS MOVED. `AuthTransport` — the five channel shapes a
// vault is reached over — is now `AuthTransport` in `Shared/AuthKind.swift`, with
// the same five raw values plus the four shapes that were always there and never
// named: `.osKeychain`, `.osAutoFill`, `.agent` and `.hardware`. It sits beside the
// kind axis because the two are read together, and because the mechanisms that are
// not vaults (the SSH agent, a PKCS#11 token, a security key that types) need the
// same vocabulary as the ones that are.

/// Why a vendor that IS installed still can't answer. Each one has a fix the
/// user can carry out, which is why none of them is ever a hidden row — and why
/// none of them may read as permanent.
nonisolated enum LocalVaultBlock: String, Sendable, Equatable {
    /// The app is installed but not running (its channel is app-to-app).
    case appNotRunning
    /// Installed, but too old / missing the piece we talk to.
    case needsUpdate
    /// Installed and running, but the integration switch is off.
    case integrationOff
    /// The vendor's app is here, but the command-line tool or local daemon
    /// SimpleVPN reads through is not installed. WE NEVER INSTALL IT: we show the
    /// command and the vendor's page, and the user runs it.
    case toolMissing
    /// The tool is here but nobody has signed in to it (no live session).
    case notSignedIn
    /// SIGNED IN, BUT LOCKED. Deliberately not folded into `notSignedIn`: the fix is
    /// a different command and the sentence is a different sentence, and telling
    /// someone who is signed in that they are not is how a person concludes the app
    /// cannot see their vault at all. Bitwarden is the case that names it — its
    /// command-line tool reports `locked` for a signed-in user whenever the caller
    /// holds no session key, which SimpleVPN deliberately never keeps.
    case vaultLocked
    /// THE TOOL IS INSTALLED — we can see it — but not in a location SimpleVPN
    /// will execute from, and the user hasn't pointed at it explicitly.
    ///
    /// This state exists because the alternative is a lie. Execution resolves
    /// against an allow-list of documented install directories and never consults
    /// `PATH` (`LocalToolRunner`, and that is a security control). Discovery
    /// searches far wider (`ToolDiscovery`). When the two disagree — `bw` in
    /// `~/.bun/bin`, `keeper` in a virtualenv, anything reachable only through
    /// `PATH` — "not installed" is simply false, and the person reading it goes off
    /// to install a second copy of something they already have.
    ///
    /// The fix is one field: set the tool's path in Settings, which is the
    /// sanctioned way to use a tool we would otherwise decline to run. So this is
    /// an enablement state, not a failure.
    case toolOutsideAllowList
    /// EVERYTHING IS INSTALLED, EVERYTHING IS SIGNED IN, AND THE VENDOR'S PLAN DOES
    /// NOT INCLUDE THE PART SIMPLEVPN READS THROUGH.
    ///
    /// This is a state, not an error, and it is its own state because none of the
    /// others can be made to say it. Proton Pass is the case that names it: its
    /// command-line tool ships to everybody and is licensed to Pass Plus, Pass
    /// Family, Pass Professional and the Proton bundles, so somebody on a free plan
    /// can install it, watch it start, and still be refused — the tool prints "your
    /// account is not yet allowed to use our CLI" and logs itself back out.
    ///
    /// Folding that into `toolMissing` would tell them to install what they have;
    /// folding it into `notSignedIn` would send them round the sign-in loop for ever.
    /// Both are how a person concludes an app is broken when the answer is a
    /// subscription. The FIX is on the vendor's own account pages and there is no
    /// command to run, which is why the banner for this one carries a link and a
    /// sentence instead of an example.
    case planExcludesTool

    // MARK: The file-backed states
    //
    // A vendor reached through a FILE fails in ways a socket or a CLI cannot, and
    // every one of these would otherwise be reported as "wrong password" — which
    // sends somebody off to retype a password that was never the problem. They are
    // separate cases because each has exactly one different fix.

    /// No vault file has been chosen yet. An enablement state: one file picker.
    case noVaultFile
    /// The chosen file is not there any more. Moved, renamed, or on a volume that
    /// isn't mounted.
    case vaultFileMissing
    /// It lives in iCloud Drive (or another file provider) and the contents are not
    /// on this Mac yet. NOT an error and NOT a read failure — it fixes itself once
    /// the download finishes, and saying "couldn't read your database" about it
    /// would be actively misleading.
    case vaultFileNotDownloaded
    /// It is there and macOS will not let SimpleVPN read it. The app is NOT
    /// sandboxed, and this still happens: macOS protects Desktop, Documents,
    /// Downloads and iCloud Drive from every app and asks once per app. The fix is a
    /// permission, so it is its own state rather than a file problem.
    case vaultFileNotReadable
    /// It is there and it is not a KeePass 2 database.
    case vaultFileNotAKeePassDatabase
    /// A real KeePass database of a generation newer than the tool on this Mac can
    /// read. An update, not a credential problem.
    case vaultFileTooNew
    /// The chosen folder is not a password store: no `.gpg-id` in it. Its own case
    /// rather than reusing the KeePass one, whose name would be a lie, and rather
    /// than folding into "missing", because "you pointed at the wrong folder" and
    /// "the folder is gone" need different sentences.
    case vaultNotAPasswordStore
    // NOTE: there is deliberately NO "the database needs its password" case here.
    // That is `vaultLocked` above, which the Bitwarden adapter named first and which
    // describes this exactly: the vault is here and something has to unlock it. The
    // FIX differs per vendor (Bitwarden: unlock its own tool; a `.kdbx`: type the
    // database password in Settings), and the fix is per-vendor copy — so a second
    // case would have been the same state under two names.

    /// The vault refused the last unlock. Distinct from `vaultLocked` because "you
    /// haven't given me one" and "the one you gave me didn't work" are different
    /// sentences and only one of them is a correction.
    case vaultPasswordRejected

    /// THE VENDOR'S TOOL IS CONFIGURED TO PUT THE SECRET ON THE PASTEBOARD instead
    /// of handing it to us, so SimpleVPN declines to run it at all.
    ///
    /// A new case rather than a reuse, because every existing one would be a lie:
    /// nothing is missing, nothing is locked, nobody needs to sign in, and the
    /// vendor's integration switch is not off. What is true is that a fetch WOULD
    /// SUCCEED — at leaving a VPN password on the pasteboard for anything on this Mac
    /// to read — and that must never happen.
    ///
    /// LastPass is the vendor that named it. `lpass` expands `$LPASS_HOME/alias.show`
    /// into every `lpass show`, its own man page suggests putting `-c` there, and
    /// there is no `--no-clip` to undo it. So the file is read and the row says the
    /// one line to delete. It is an enablement state, not a failure: nothing is
    /// broken, and the fix is one edit the user makes.
    case toolDivertsSecretToClipboard
    /// NO SERVER HAS BEEN SET UP. The server-shaped equivalent of `noVaultFile`,
    /// and its own case rather than a reuse: `noVaultFile`'s whole vocabulary is a
    /// file that was chosen and can be re-chosen ("no database has been chosen
    /// yet", a Finder picker), and none of that is true of an address somebody
    /// types. Passbolt is the case that names it. An enablement state: one field.
    case noServerConfigured

    /// The states the enablement banner exists for: something to switch on,
    /// install, sign in to, or point at — as opposed to "your app isn't running"
    /// (not a setup problem) or "it's too old" (an update, not an enablement).
    var wantsEnablementBanner: Bool {
        // A switch rather than a chain of `==`: with a dozen cases, "did anyone
        // remember to add the new one" stops being answerable by reading, and an
        // exhaustive switch makes the compiler ask.
        switch self {
        case .toolMissing, .integrationOff, .notSignedIn, .toolOutsideAllowList,
             .vaultLocked, .noVaultFile, .vaultPasswordRejected:
            true
        // A BANNER, even though the fix is not on this Mac. It is exactly the state
        // whose banner earns its place: without one, the row says a true thing
        // ("Proton Pass can't answer") that leads somewhere useless, and the person
        // goes looking for a bug. With one, they read the word "plan" and stop.
        case .planExcludesTool:
            true
        // "You pointed at the wrong folder" IS something to fix, with an exact fix
        // (choose the folder with .gpg-id in it), so it earns a banner.
        case .vaultNotAPasswordStore:
            true
        // "Take the -c out of that one file" is as exact a fix as this app has, and
        // the banner is the only place it can be spelled out.
        // "Tell SimpleVPN your server's address" is the shortest enablement in the
        // whole list: one field, and the row works.
        case .toolDivertsSecretToClipboard, .noServerConfigured:
            true
        case .appNotRunning, .needsUpdate, .vaultFileMissing, .vaultFileNotDownloaded,
             .vaultFileNotReadable, .vaultFileNotAKeePassDatabase, .vaultFileTooNew:
            false
        }
    }
}

/// What a vendor can do right now. Ordered from useless to usable.
nonisolated enum LocalVaultAvailability: Sendable, Equatable {
    /// Not on this Mac at all — the row isn't offered.
    case notInstalled
    /// Here, but something must happen first. Offered WITH the fix.
    case blocked(LocalVaultBlock)
    /// Here, but the whole path has never been proven — AND THE CEILING SAYS WHY.
    ///
    /// The reason is not decoration. This case used to be bare, and it therefore said
    /// the same thing about two states that need opposite handling: 1Password's "the
    /// check is owed and picking the row pays it", and a Passbolt SERVER's "nothing
    /// short of a real sign-in could prove this, and a real sign-in is an
    /// authentication attempt against somebody else's machine, so it will never
    /// happen". The first is a to-do. The second is the honest ceiling, for ever — and
    /// a row promising "SimpleVPN checks this when you pick it" was making a promise
    /// nothing would keep.
    ///
    /// `AuthProbeCeiling.willBeProbed` is the distinction, and it is what tells "set
    /// up, deliberately not probed" from "probeable but unproven" without any caller
    /// matching on the vendor.
    case unchecked(AuthProbeCeiling)
    /// Proven working.
    case ready

    var isOffered: Bool { self != .notInstalled }
    var isReady: Bool { self == .ready }

    /// Useless to usable, as a number — so "the best of this vendor's vaults" is one
    /// `max` rather than a chain of `if`s in the gatherer. It exists because a
    /// multi-instance vendor's ROW has to be offered when ANY of its vaults can
    /// answer: one database being missing must not hide the one that is ready.
    var rank: Int {
        switch self {
        case .notInstalled: 0
        case .blocked: 1
        case .unchecked: 2
        case .ready: 3
        }
    }
}

// MARK: - Where the vendor's own documentation lives

/// THE link table. One place, auditable, so nobody has to grep view bodies to
/// find out what this app tells people to read — and so a dead link is one edit.
/// A link that 404s is worse than no link at all.
///
/// Every URL is the vendor's CURRENT documentation. We do not carry version
/// matrices for other people's software: our own example commands target the
/// latest release, and the vendor's page carries the history.
nonisolated enum VendorDocs {

    nonisolated struct Page: Sendable, Equatable, Hashable {
        var title: String
        var url: URL
    }

    private static func page(_ title: String, _ string: String) -> Page {
        // Force-unwrap-free: a malformed literal here would be a build-time
        // mistake, and a nil URL is preferable to a crash — the banner simply
        // shows its commands without a link.
        Page(title: title, url: URL(string: string) ?? URL(fileURLWithPath: "/"))
    }

    // 1Password. NOTE: SimpleVPN talks to 1Password through its SDK desktop-app
    // integration, NOT the `op` CLI (the CLI path was retired). The SDKs page is
    // therefore the one that matters for us; the CLI app-integration page is
    // included because it is where 1Password documents the sibling toggle, and
    // people who use `op` land there first.
    //
    // FINAL URLs ONLY — measured WITHOUT following redirects. "It resolves in a
    // browser" is not the bar: `curl -L` reports 200 for a chain of redirects, and
    // three entries in this table were passing that way. 1Password moved its
    // developer documentation off `developer.1password.com/docs/…` (301) and its new
    // host 308s a trailing slash away (`/sdks/` → `/sdks`); Keeper 307s the `/en/`
    // locale prefix off. A redirect works today and is somebody else's decision
    // tomorrow, so what ships is the address the server actually serves. Re-check
    // with:
    //   curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' <url>
    // and accept only a bare 200.
    static let onePasswordSDKs = page("1Password SDKs", "https://www.1password.dev/sdks")
    static let onePasswordCLIIntegration = page("1Password CLI app integration",
                                               "https://www.1password.dev/cli/app-integration")

    // Keeper Commander.
    static let keeperCommander = page("Keeper Commander",
                                      "https://docs.keeper.io/keeperpam/commander-cli/overview")
    static let keeperCommanderLogin = page(
        "Keeper Commander sign-in",
        "https://docs.keeper.io/keeperpam/commander-cli/commander-installation-setup/logging-in")
    static let keeperServiceMode = page(
        "Keeper Commander Service Mode",
        "https://docs.keeper.io/keeperpam/commander-cli/service-mode-rest-api")

    // KeePassXC.
    static let keePassXC = page("KeePassXC documentation", "https://keepassxc.org/docs/")
    /// The `keepassxc-cli` reference — the authority for what the tool the `.kdbx`
    /// file adapter runs can and cannot do. Its own man page, which is where its
    /// flags are defined.
    static let keePassXCCLI = page("keepassxc-cli reference",
                                   "https://keepassxc.org/docs/KeePassXC_UserGuide")
    /// The two other products that store the same format. Named because a Strongbox
    /// or KeePassium user arriving at this row has never heard of `keepassxc-cli` and
    /// needs to know why a KeePassXC tool is what reads their file.
    static let strongbox = page("Strongbox", "https://strongboxsafe.com")
    static let keePassium = page("KeePassium", "https://keepassium.com")

    // Bitwarden. The CLI page is the authority for installing `bw`, signing in,
    // unlocking and `bw serve`; the Vault Management API page is what documents the
    // local service's own requests. Both measured at a bare 200, no redirect.
    static let bitwardenCLI = page("Bitwarden CLI", "https://bitwarden.com/help/cli/")
    static let bitwardenVaultAPI = page("Bitwarden Vault Management API",
                                        "https://bitwarden.com/help/vault-management-api/")

    // Dashlane. The CLI's own documentation site is the authority for installing
    // `dcli`; the authentication page is where Dashlane documents registering a Mac,
    // saving the master password in the OS keychain, and the biometrics switch —
    // which are exactly the three things this app's Dashlane banners talk about.
    // Both measured at a bare 200, no redirect.
    static let dashlaneCLI = page("Dashlane CLI", "https://cli.dashlane.com/")
    static let dashlaneAuthentication = page("Dashlane CLI sign-in",
                                             "https://cli.dashlane.com/personal/authentication")

    // Proton Pass. The tool's own documentation site, which is where Proton
    // documents installing it, signing in, the session lock and the `pass://`
    // reference syntax. All four measured at a bare 200 with NO redirect followed —
    // note the trailing slashes, which this site requires: the same address without
    // one 301s (`/pass-cli` → `/pass-cli/`), and shipping the redirecting form is
    // exactly the mistake three earlier entries in this table made.
    //
    // The PLANS page is Proton's own support article and is the authority for the
    // one thing nobody can fix from this Mac — which plans include the tool. It is
    // on proton.me rather than the docs site because that is where Proton says it.
    static let protonPassCLI = page("Proton Pass CLI", "https://protonpass.github.io/pass-cli/")
    static let protonPassCLILogin = page("Proton Pass CLI sign-in",
                                        "https://protonpass.github.io/pass-cli/commands/login/")
    static let protonPassCLISession = page("Proton Pass CLI session lock",
                                          "https://protonpass.github.io/pass-cli/commands/session/")
    static let protonPassCLIReferences = page(
        "Proton Pass item references",
        "https://protonpass.github.io/pass-cli/commands/contents/secret-references/")
    static let protonPassPlans = page("Proton Pass plans",
                                      "https://proton.me/support/proton-pass-plans-explained")

    // Passbolt. The CLI's repository is the authority for its flags, its config
    // file and its own error text — everything SimpleVPN's argument building and
    // failure classification is derived from — and Passbolt's documentation site
    // is where somebody self-hosting starts. Both measured at a bare 200, no
    // redirect (`passbolt.com/docs` 301s to `/docs/`, so the slash is part of the
    // address that actually gets served).
    static let passboltCLI = page("Passbolt CLI", "https://github.com/passbolt/go-passbolt-cli")
    static let passbolt = page("Passbolt documentation", "https://www.passbolt.com/docs/")

    // Vendors on the seam but not yet implemented — listed here so the next
    // adapter's author has the same auditable table rather than a fresh guess.
    static let passwordStore = page("pass", "https://www.passwordstore.org/")
    static let gopass = page("gopass", "https://www.gopass.pw/")
    static let lastPassCLI = page("LastPass CLI", "https://github.com/lastpass/lastpass-cli")
    static let hashiCorpVaultCLI = page("HashiCorp Vault CLI",
                                        "https://developer.hashicorp.com/vault/docs/commands")

    /// Everything above, for the audit test.
    static let all: [Page] = [
        onePasswordSDKs, onePasswordCLIIntegration,
        keeperCommander, keeperCommanderLogin, keeperServiceMode,
        keePassXC, keePassXCCLI, strongbox, keePassium,
        bitwardenCLI, bitwardenVaultAPI,
        dashlaneCLI, dashlaneAuthentication,
        protonPassCLI, protonPassCLILogin, protonPassCLISession, protonPassCLIReferences,
        protonPassPlans,
        passboltCLI, passbolt,
        passwordStore, gopass, lastPassCLI, hashiCorpVaultCLI,
    ]
}

// MARK: - "You can turn this on" — the enablement banner's data

/// What to show when a vendor's app is here but the piece SimpleVPN needs isn't
/// switched on (or isn't installed). Data, not a view: the banner renders it, the
/// tests read it, and each new adapter supplies its own without touching the view.
///
/// SCOPE, deliberately narrow: ONE short example of our own — the minimal way to
/// get it working on the CURRENT release — plus a link to the vendor's own page,
/// which is the authority. No version matrices, no "on older versions the toggle
/// is called…", no alternate paths for superseded releases. Maintaining a
/// compatibility matrix for someone else's software is not this app's job.
nonisolated struct EnablementGuidance: Sendable, Equatable {
    /// One line: what turning this on gets the user. Not what is broken — the
    /// row's own headline already says that.
    var benefit: String
    /// Our short example. Copyable, in order, usually one or two lines. Works
    /// offline, which is exactly why a bare URL isn't enough on its own.
    var example: [Command] = []
    /// A single current-version line for an in-app toggle, when the gate is a
    /// setting rather than a command.
    var settingLocation: String?
    /// The vendor's own page, for everything this example doesn't cover.
    var doc: VendorDocs.Page

    nonisolated struct Command: Sendable, Equatable, Identifiable {
        var id: String { text }
        /// Exactly what to run. Copied verbatim.
        var text: String
        /// One short line saying what it does, for the eye and for VoiceOver.
        var caption: String
    }

    /// Everything in this banner as one spoken sentence, so a VoiceOver user gets
    /// the commands and the link as CONTENT — the house rule is that nothing may
    /// be hover-only, and a copy button whose payload is invisible is worse.
    var spokenSummary: String {
        var parts = [benefit]
        if let settingLocation { parts.append(settingLocation) }
        for command in example { parts.append("\(command.caption): \(command.text)") }
        parts.append("More in \(doc.title).")
        return parts.joined(separator: " ")
    }
}

// MARK: - Per-vendor copy (pure)

/// Everything a vendor row SAYS. Separate from the probe so wording can be
/// reviewed and tested without a vendor app anywhere near the machine.
nonisolated struct LocalVaultCopy: Sendable {
    var title: String
    var summary: String
    var explanation: String
    var symbol: String
    var storedKind: CredentialSourceKind
    /// The vendor's own page — the authority for anything our own short example
    /// doesn't cover, and the fallback link for guidance built at runtime.
    var primaryDoc: VendorDocs.Page
    /// The one command that installs this vendor's tool into a location SimpleVPN
    /// already searches. Latest release only, per the house rule. nil for a vendor
    /// with no tool to install (1Password's channel is the app's own IPC).
    var homebrewInstallCommand: String?
    /// Per-block headline and numbered steps. **bold** names a real thing on
    /// screen; `code` names something to type. Short: the banner's example and
    /// the vendor's own page carry the detail.
    var blocks: [LocalVaultBlock: (headline: String, steps: [String])]
    /// Per-block enablement guidance — our one short example plus the vendor's
    /// page. Only the blocks that are genuinely "you can turn this on".
    var guidance: [LocalVaultBlock: EnablementGuidance] = [:]
    /// Shown when the path is reachable but unproven.
    var uncheckedNote: String?

    func headline(for block: LocalVaultBlock) -> String {
        blocks[block]?.headline ?? "\(title) needs a moment of setup"
    }
    func steps(for block: LocalVaultBlock) -> [String] {
        blocks[block]?.steps ?? []
    }
    func guidance(for block: LocalVaultBlock) -> EnablementGuidance? {
        guidance[block]
    }

    /// The same, but able to name a path this Mac actually has.
    ///
    /// `.toolOutsideAllowList` is the one block whose advice is worthless without
    /// the specific path — "your tool is somewhere else" tells nobody anything,
    /// while "it's at /Users/you/.bun/bin/bw, set that as its path or reinstall it
    /// with Homebrew" is a two-second fix. So this block's guidance is BUILT rather
    /// than declared, and the static table carries only the headline.
    func guidance(for block: LocalVaultBlock, foundAt path: String?) -> EnablementGuidance? {
        guard block == .toolOutsideAllowList, let path else { return guidance(for: block) }
        return LocalVaultCopyBook.outsideAllowListGuidance(
            title: title, foundAt: path, installCommand: homebrewInstallCommand, doc: primaryDoc)
    }
}

nonisolated enum LocalVaultCopyBook {

    /// "It's installed, just not where we look." Built at runtime because it has
    /// to name THE path on THIS Mac — the whole value of the state is that it turns
    /// a dead end into a two-second fix, and a sentence without the path does not.
    ///
    /// Two ways out, in the order most people should take them: point SimpleVPN at
    /// the copy you already have (the sanctioned escape hatch), or install it
    /// somewhere we search anyway. Neither is presented as an error, because
    /// neither is one — nothing is broken, we are simply declining to guess which
    /// binary on `PATH` gets handed a request for a password.
    static func outsideAllowListGuidance(title: String, foundAt path: String,
                                        installCommand: String?,
                                        doc: VendorDocs.Page) -> EnablementGuidance {
        var example: [EnablementGuidance.Command] = [
            .init(text: path,
                  caption: "Paste this into Settings \u{25B8} Sign-In Sources as the tool\u{2019}s path"),
        ]
        if let installCommand {
            example.append(.init(text: installCommand,
                                 caption: "Or install it where SimpleVPN already looks"))
        }
        return EnablementGuidance(
            benefit: "\(title)\u{2019}s command-line tool is already on this Mac, at \(path). "
                + "SimpleVPN only runs programs from the folders package managers install into, so it "
                + "won\u{2019}t pick this one up on its own \u{2014} that check is what stops a stray "
                + "program in your search path from being handed a request for a password. Tell "
                + "SimpleVPN to use this copy and it can get your sign-in straight from \(title).",
            example: example,
            settingLocation: "In SimpleVPN: **Settings \u{25B8} Sign-In Sources**, then set "
                + "**\(title)**\u{2019}s tool path.",
            doc: doc)
    }

    static func copy(for vendor: LocalVaultVendor) -> LocalVaultCopy {
        switch vendor {
        case .onePassword: onePassword
        case .keePassXC: keePassXC
        case .keeper: keeper
        case .bitwarden: bitwarden
        // Lives in DashlaneCopy.swift, same reason as the two below.
        case .dashlane: dashlane
        // Lives in KeePassFileCopy.swift — one line here, so a new vendor's block of
        // copy never collides with another's in this file.
        case .keePassFile: keePassFile
        // Lives in PasswordStoreCopy.swift, same reason as KeePassFile's.
        case .passwordStore: passwordStore
        // Lives in LastPassCopy.swift, same reason again — and that file's header
        // carries the argument for why this row's copy sets lower expectations than
        // any other's without being unfair to the vendor.
        case .lastPass: lastPass
        // Lives in ProtonPassCopy.swift. NOT next to `passwordStore` by accident:
        // they are different vendors with adjacent tool names, and keeping their copy
        // in separate files is part of what stops one row describing the other's tool.
        case .protonPass: protonPass
        // Lives in PassboltCopy.swift, same reason again.
        case .passbolt: passbolt
        }
    }

    static let onePassword = LocalVaultCopy(
        title: "1Password",
        summary: "SimpleVPN asks the 1Password app for this VPN\u{2019}s sign-in when you connect.",
        explanation: "SimpleVPN asks the 1Password app for the item you point it at. 1Password does "
            + "the unlocking \u{2014} it asks you for Touch ID \u{2014} and your 1Password password "
            + "never reaches SimpleVPN. It can hand over the verification code too, so there is "
            + "usually nothing left to type.",
        symbol: "key.fill",
        storedKind: .onePassword,
        primaryDoc: VendorDocs.onePasswordSDKs,
        // No tool to install: 1Password is reached over its app's own signed IPC.
        homebrewInstallCommand: nil,
        blocks: [
            .appNotRunning: ("1Password isn\u{2019}t running",
                             ["Open **1Password** and sign in to it.",
                              "Come back here \u{2014} SimpleVPN will ask it for your sign-in."]),
            .needsUpdate: ("1Password needs updating on this Mac",
                           ["Update **1Password** to version 8 or later.",
                            "Come back here and pick 1Password again."]),
            .integrationOff: ("1Password needs one setting turned on", []),
        ],
        guidance: [
            .integrationOff: EnablementGuidance(
                benefit: "Turn this on and SimpleVPN can get this VPN\u{2019}s sign-in straight from "
                    + "1Password \u{2014} username, password and verification code \u{2014} with "
                    + "1Password doing the unlocking.",
                settingLocation: "In 1Password: **Settings \u{25B8} Developer**, then tick "
                    + "**\(UserFacingError.sdkIntegrationSetting)**.",
                doc: VendorDocs.onePasswordSDKs),
        ],
        uncheckedNote: "SimpleVPN checks with 1Password when you pick this. "
            + "1Password may ask you to allow it, once.")

    static let keePassXC = LocalVaultCopy(
        title: "KeePassXC",
        summary: "SimpleVPN asks the KeePassXC app for this VPN\u{2019}s sign-in when you connect.",
        explanation: "SimpleVPN asks the running KeePassXC app for the entry whose address matches "
            + "this VPN \u{2014} including its verification code, when the entry has one. KeePassXC "
            + "asks you to allow SimpleVPN the first time (give the connection a name), and raises "
            + "its own unlock if the database is locked. Your database password never reaches "
            + "SimpleVPN.",
        symbol: "key.horizontal.fill",
        storedKind: .keePassXC,
        primaryDoc: VendorDocs.keePassXC,
        // The cask installs the app AND symlinks keepassxc-cli into Homebrew's bin.
        homebrewInstallCommand: "brew install --cask keepassxc",
        blocks: [
            .integrationOff: ("KeePassXC isn\u{2019}t running, or its browser integration is off", []),
        ],
        guidance: [
            .integrationOff: EnablementGuidance(
                benefit: "Turn this on and SimpleVPN can get this VPN\u{2019}s sign-in from KeePassXC "
                    + "when you connect, including its verification code.",
                settingLocation: "In KeePassXC: **Settings \u{25B8} Browser Integration**, then tick "
                    + "**Enable browser integration** (with your database unlocked).",
                doc: VendorDocs.keePassXC),
        ],
        uncheckedNote: nil)

    /// Keeper is reached through **Keeper Commander**, Keeper's own MIT-licensed
    /// command-line tool — not through the Keeper app, which has no local API.
    /// So the row is offered when Commander is present, and the Keeper app on
    /// its own is a pointer (see `PasswordAppCatalog.pathToIntegration`).
    static let keeper = LocalVaultCopy(
        title: "Keeper",
        summary: "SimpleVPN asks Keeper Commander for this VPN\u{2019}s sign-in when you connect.",
        explanation: "SimpleVPN asks Keeper Commander \u{2014} Keeper\u{2019}s own command-line tool "
            + "\u{2014} for the record you point it at, and reads only that record\u{2019}s username "
            + "and password. Commander keeps your Keeper sign-in in this Mac\u{2019}s keychain, where "
            + "macOS protects it; SimpleVPN never sees your Keeper master password and never changes "
            + "Commander\u{2019}s own setup. If a verification code is required, you type that one "
            + "yourself.",
        symbol: "key.viewfinder",
        storedKind: .keeper,
        primaryDoc: VendorDocs.keeperCommander,
        homebrewInstallCommand: "brew install keeper-commander",
        blocks: [
            .toolMissing: ("Keeper Commander isn\u{2019}t installed on this Mac", []),
            .notSignedIn: ("Keeper Commander isn\u{2019}t signed in on this Mac", []),
            // Deliberately NOT "isn't installed": it demonstrably is, and we can
            // see where. Saying otherwise sends someone to install a second copy.
            .toolOutsideAllowList: (
                "Keeper Commander is installed, but not somewhere SimpleVPN will run it from", []),
        ],
        guidance: [
            // SimpleVPN never installs anything: the command is shown, and the
            // user runs it. Latest release only — Keeper's own page carries the
            // rest.
            .toolMissing: EnablementGuidance(
                benefit: "Install Keeper\u{2019}s own command-line tool and SimpleVPN can get this "
                    + "VPN\u{2019}s sign-in straight from Keeper when you connect.",
                example: [
                    .init(text: "pipx install keepercommander",
                          caption: "Install Keeper Commander (SimpleVPN never installs it for you)"),
                    .init(text: "keeper shell",
                          caption: "Sign in to Keeper once, in Terminal"),
                    .init(text: "this-device register; this-device persistent-login on",
                          caption: "Inside that shell: let SimpleVPN fetch without asking again"),
                ],
                doc: VendorDocs.keeperCommander),
            .notSignedIn: EnablementGuidance(
                benefit: "Sign Commander in once and SimpleVPN can get this VPN\u{2019}s sign-in from "
                    + "Keeper when you connect \u{2014} without asking you again.",
                example: [
                    .init(text: "keeper shell", caption: "Sign in to Keeper once, in Terminal"),
                    .init(text: "this-device register; this-device persistent-login on",
                          caption: "Inside that shell: keep the session for next time"),
                    .init(text: "biometric register",
                          caption: "Optional: unlock Keeper with Touch ID instead"),
                ],
                doc: VendorDocs.keeperCommanderLogin),
        ],
        uncheckedNote: "SimpleVPN checks Keeper Commander when you pick this.")

    /// Bitwarden is reached through Bitwarden's own command-line tool — and
    /// preferably through the LOCAL SERVICE that tool can start (`bw serve`), for a
    /// reason worth stating in the copy as well as in the code: the service holds
    /// the unlock, so SimpleVPN reads one item without ever handling the key that
    /// unlocks the vault. The command-line tool on its own cannot read anything
    /// without that key, and SimpleVPN never keeps one.
    ///
    /// Nothing here names bitwarden.com: a self-hosted Bitwarden and a Vaultwarden
    /// server work exactly the same way through the same tool.
    static let bitwarden = LocalVaultCopy(
        title: "Bitwarden",
        summary: "SimpleVPN asks Bitwarden for this VPN\u{2019}s sign-in when you connect.",
        explanation: "SimpleVPN reads one item from Bitwarden using Bitwarden\u{2019}s own "
            + "command-line tool. It works best with Bitwarden\u{2019}s local service running (you "
            + "unlock your vault once in Terminal and leave \u{201C}bw serve\u{201D} going): the "
            + "unlock stays in Bitwarden\u{2019}s own program, and SimpleVPN never sees your master "
            + "password or the key that unlocks your vault. Worth knowing: while that service is "
            + "running it asks nothing of whoever connects to it, so any program on this Mac can "
            + "read your items \u{2014} stop it when you are done. Your own server works the same "
            + "way as Bitwarden\u{2019}s. If a verification code is required, you type that one "
            + "yourself.",
        symbol: "shield.lefthalf.filled",
        storedKind: .bitwarden,
        primaryDoc: VendorDocs.bitwardenCLI,
        homebrewInstallCommand: "brew install bitwarden-cli",
        blocks: [
            .toolMissing: ("Bitwarden\u{2019}s command-line tool isn\u{2019}t installed on this Mac", []),
            .notSignedIn: ("Bitwarden isn\u{2019}t signed in on this Mac", []),
            .vaultLocked: ("Bitwarden is signed in, but locked", []),
            // Deliberately NOT "isn't installed": it demonstrably is, and we can
            // see where. Saying otherwise sends someone to install a second copy.
            .toolOutsideAllowList: (
                "Bitwarden\u{2019}s command-line tool is installed, but not somewhere SimpleVPN "
                + "will run it from", []),
        ],
        guidance: [
            // SimpleVPN never installs anything: the commands are shown, and the
            // user runs them. Latest release only — Bitwarden's own page carries
            // the rest.
            .toolMissing: EnablementGuidance(
                benefit: "Install Bitwarden\u{2019}s own command-line tool and SimpleVPN can get "
                    + "this VPN\u{2019}s sign-in straight from Bitwarden when you connect.",
                example: [
                    .init(text: "brew install bitwarden-cli",
                          caption: "Install Bitwarden\u{2019}s command-line tool "
                              + "(SimpleVPN never installs it for you)"),
                    .init(text: "bw login",
                          caption: "Sign in to Bitwarden once, in Terminal"),
                    .init(text: "export BW_SESSION=$(bw unlock --raw) && bw serve",
                          caption: "Unlock it and leave Bitwarden\u{2019}s local service running "
                              + "\u{2014} the key stays in your Terminal, never in SimpleVPN"),
                ],
                doc: VendorDocs.bitwardenCLI),
            .notSignedIn: EnablementGuidance(
                benefit: "Sign in to Bitwarden once, leave its local service running, and SimpleVPN "
                    + "can get this VPN\u{2019}s sign-in from Bitwarden when you connect.",
                example: [
                    .init(text: "bw login", caption: "Sign in to Bitwarden once, in Terminal"),
                    .init(text: "export BW_SESSION=$(bw unlock --raw)",
                          caption: "Unlock your vault \u{2014} the key stays in your Terminal"),
                    .init(text: "bw serve",
                          caption: "Start Bitwarden\u{2019}s own local service, which SimpleVPN "
                              + "reads your item from"),
                ],
                doc: VendorDocs.bitwardenCLI),
            .vaultLocked: EnablementGuidance(
                benefit: "Unlock your vault and leave Bitwarden\u{2019}s local service running, and "
                    + "SimpleVPN can get this VPN\u{2019}s sign-in from Bitwarden with nothing to "
                    + "type. Bitwarden asks for your master password, not SimpleVPN, and the key it "
                    + "gives back stays in your Terminal.",
                example: [
                    .init(text: "export BW_SESSION=$(bw unlock --raw)",
                          caption: "Unlock your vault in Terminal"),
                    .init(text: "bw serve",
                          caption: "Start Bitwarden\u{2019}s own local service, which holds the "
                              + "unlock so SimpleVPN never needs the key"),
                ],
                doc: VendorDocs.bitwardenVaultAPI),
        ],
        uncheckedNote: "SimpleVPN checks Bitwarden when you pick this.")
}

// MARK: - Identity

/// One offerable row. The pointer case carries a bundle id so several pointers
/// stay distinct without a second enum.
nonisolated enum SignInSourceID: Hashable, Sendable {
    case typeEachTime
    case saveInSimpleVPN
    case applePasswords
    case vault(LocalVaultVendor)
    case otherApp(bundleID: String)

    /// A stable string for accessibility identifiers and test addressing.
    var rawValue: String {
        switch self {
        case .typeEachTime: "type-each-time"
        case .saveInSimpleVPN: "save-in-simplevpn"
        case .applePasswords: "apple-passwords"
        case .vault(let vendor): vendor.rawValue
        case .otherApp(let bundleID): "other:\(bundleID)"
        }
    }
}

/// Which of the two classes a row belongs to. The visible wording, the symbol
/// and the spoken sentence all key off this — a pointer must never read like an
/// integration.
nonisolated enum SignInSourceRole: Sendable, Equatable {
    /// SimpleVPN gets the sign-in itself. Selectable.
    case fetches
    /// SimpleVPN cannot read this app. Not selectable — it says where to look.
    case hint
}

/// What a fetchable row can do right now.
nonisolated enum SignInSourceState: Sendable, Equatable {
    /// Works as soon as it is picked.
    case ready
    /// On offer, but something has to happen first — `headline` says what,
    /// `steps` say how.
    case needsSetup(headline: String, steps: [String])
    /// On offer; picking it runs a one-time check that may ask for approval.
    case unchecked(note: String)

    var isReady: Bool { self == .ready }
}

// MARK: - One row

nonisolated struct SignInSourceOption: Identifiable, Sendable, Equatable {
    var id: SignInSourceID
    var role: SignInSourceRole
    /// The row's name.
    var title: String
    /// The always-visible one-liner under the title.
    var summary: String
    /// The hover/help text — and, verbatim, the VoiceOver hint. A hover-only
    /// explanation is invisible to VoiceOver (house rule), so there is exactly
    /// ONE string and both surfaces read it.
    var explanation: String
    var symbol: String
    var state: SignInSourceState = .ready
    /// "You can turn this on": our one short example plus the vendor's own page.
    /// Present exactly when the row is blocked on something the user can install
    /// or switch on — never for a row that already works.
    var guidance: EnablementGuidance?
    /// Where picking this lands in the stored source. nil for pointers — which
    /// is also the structural guarantee that a pointer can never be picked.
    var storedKind: CredentialSourceKind?
    /// Picking this turns "remember my sign-in" on (the keychain row) or off
    /// (the type-it-each-time row). nil = leave that setting alone.
    var remembers: Bool?
    /// Pointer rows: the app to open.
    var appBundleID: String?
    /// Pointer rows: this app ships a macOS AutoFill extension, so it can fill
    /// the fields itself once switched on in System Settings. Detected from the
    /// app bundle, never assumed.
    var fillsThroughAutoFill = false
    /// The vendor whose settings a "Configure…" affordance on this row opens. nil
    /// for the rows that have nothing to configure (typing, the keychain, Apple
    /// Passwords) and for pointers.
    var configurableVendor: LocalVaultVendor?

    var isSelectable: Bool { role == .fetches }

    /// The sentence VoiceOver reads as the row's value: what this row can do, in
    /// words. Selection itself is spoken by the row's selected trait.
    var accessibilityStateValue: String {
        switch state {
        case .ready:
            role == .fetches ? "Ready to use" : "SimpleVPN can\u{2019}t read this app"
        case .needsSetup(let headline, _): headline
        case .unchecked(let note): note
        }
    }
}

// MARK: - The facts the rules turn on

/// Everything the list depends on, gathered by `SignInSourceAvailability` and
/// injectable wholesale by tests.
nonisolated struct SignInSourceFacts: Sendable, Equatable {
    /// Per-vendor live answer. A vendor missing from the dictionary is treated
    /// as `.notInstalled` — an unscanned Mac offers no vendor rows rather than
    /// offering broken ones.
    ///
    /// For a vendor that can have several vaults (`SourceCardinality.multiple`) this
    /// is the BEST of them: the row is offered when any one of them can answer.
    /// Which one is which is `vaultInstances`.
    var vaults: [LocalVaultVendor: LocalVaultAvailability] = [:]

    /// LEVEL 2's live answer, per configured instance. One database can be missing
    /// while another is ready, and the four-state model plus its enablement banners
    /// apply to each of them separately.
    var vaultInstances: [SourceInstanceID: LocalVaultAvailability] = [:]

    /// The instances themselves, as they were when this was gathered — so the
    /// chooser, the readiness check and a diagnostic report all name the same
    /// vaults without a second read of the defaults.
    var instances: [LocalVaultVendor: [SourceInstance]] = [:]

    /// This Mac can ask for a fingerprint (or Apple Watch, or the account
    /// password) — decides whether the keychain row promises one.
    var biometricsAvailable = false

    /// The profile allows saving the password at all (`auth-nocache` and the
    /// like say no). False drops the keychain row rather than offering a setting
    /// the engine will refuse.
    var allowsPasswordSave = true

    /// Password apps found installed that SimpleVPN has no way to read.
    var otherApps: [InstalledPasswordApp] = []

    /// Vendors the user (or their organization) has switched off in Settings.
    ///
    /// THE FILTER IS APPLIED IN `availability(_:)`, not at each call site, and that
    /// is the design: "disabled means not offered AND not hinted" is then true by
    /// construction for the chooser, the readiness check, the connect-time recovery
    /// notice and anything added later — rather than being three places somebody has
    /// to remember. `rawAvailability(_:)` is the single deliberate exception, for the
    /// Settings pane, which has to be able to say "installed, and you switched it
    /// off".
    var disabledVendors: Set<LocalVaultVendor> = []

    /// A vendor whose tool discovery FOUND but the execution allow-list won't run:
    /// the path, so the banner can name it. Keyed by vendor because that is what a
    /// row is; the tool it belongs to is in the discovery map.
    var toolsFoundOutsideAllowList: [LocalVaultVendor: String] = [:]

    func availability(_ vendor: LocalVaultVendor) -> LocalVaultAvailability {
        guard !disabledVendors.contains(vendor) else { return .notInstalled }
        return vaults[vendor] ?? .notInstalled
    }

    /// What was PROBED, ignoring the user's own switch. Only the Settings pane may
    /// use this — everywhere else, a switched-off vendor must be indistinguishable
    /// from an absent one.
    func rawAvailability(_ vendor: LocalVaultVendor) -> LocalVaultAvailability {
        vaults[vendor] ?? .notInstalled
    }

    /// ONE INSTANCE's live answer — the level-2 form of `availability(_:)`, and
    /// filtered by the vendor's switch for exactly the same reason: off means not
    /// offered anywhere.
    ///
    /// A single-instance vendor answers from the vendor row, because it has one
    /// thing to talk to and no list. A `nil` instance means the default one.
    func availability(_ vendor: LocalVaultVendor,
                      instance: SourceInstanceID?) -> LocalVaultAvailability {
        guard !disabledVendors.contains(vendor) else { return .notInstalled }
        return rawAvailability(vendor, instance: instance)
    }

    /// The same, past the switch. Settings-pane only, like `rawAvailability(_:)`.
    func rawAvailability(_ vendor: LocalVaultVendor,
                         instance: SourceInstanceID?) -> LocalVaultAvailability {
        guard vendor.cardinality.allowsSeveral else { return rawAvailability(vendor) }
        let resolved = instance ?? instances[vendor]?.first?.id
        guard let resolved else { return rawAvailability(vendor) }
        return vaultInstances[resolved] ?? rawAvailability(vendor)
    }

    func instances(for vendor: LocalVaultVendor) -> [SourceInstance] {
        instances[vendor] ?? []
    }

    func isEnabled(_ vendor: LocalVaultVendor) -> Bool { !disabledVendors.contains(vendor) }
}

/// A password app found on this Mac.
nonisolated struct InstalledPasswordApp: Identifiable, Sendable, Equatable {
    var id: String { bundleID }
    var bundleID: String
    /// The name to show. From our catalog, so it stays stable when a vendor
    /// renames a bundle on disk.
    var name: String
    /// The bundle ships an AutoFill password extension (an `.appex` whose
    /// extension point is the credential-provider one). Detected, not assumed.
    var shipsAutoFillExtension = false
}

// MARK: - The apps we point at rather than read

/// Password apps worth POINTING AT: installed here, and not (yet) something
/// SimpleVPN can read. They are offered as an answer to "where IS my password?",
/// which is a different and genuinely useful thing from "pick this".
///
/// Each carries WHY, because "we can't read it" and "we can't read it yet" are
/// different promises and the copy must not confuse them:
///   • `.officialCLI` — the vendor ships a command-line tool that reads ordinary
///     vault records (Bitwarden `bw`, Dashlane `dcli`, LastPass `lpass`, Proton
///     Pass's CLI). An adapter is a small addition, so the wording says "yet".
///   • `.keePassFormat` — Strongbox and KeePassium store KeePass `.kdbx`, the
///     same format SimpleVPN already reads through KeePassXC. One file-backed
///     adapter would serve all three (`AuthTransport.file`), so again:
///     "yet". Neither needs a vendor API.
///   • `.none` — no local read path exists at all (NordPass, Enpass, RoboForm).
///     Here the honest answer is copy and paste, with no hint of a CLI that
///     doesn't exist.
/// Keeper is the special one and stays special: its Commander CLI is BUILT, so
/// the Keeper app alone is a pointer that names the way in (`gatedVendor`).
///
/// Matching is by bundle-id PREFIX as well as exact id, the same technique as
/// `TailscaleConflict`: these vendors ship several distributions (direct
/// download, Mac App Store, Electron wrapper) under related ids, and a prefix
/// catches the ones we haven't seen without maintaining an exhaustive list.
nonisolated enum PasswordAppCatalog {

    /// Why an app is a pointer rather than a source. Not a UI string — the
    /// wording is derived from it, in one place.
    nonisolated enum LocalReadPath: Sendable, Equatable {
        /// Nothing local exists. Copy and paste is the whole answer.
        case none
        /// The vendor ships a CLI that reads ordinary records; no adapter yet.
        /// The payload is the tool's own name, so the copy can name it.
        case officialCLI(String)
        /// Stores KeePass `.kdbx` — the format we already read.
        case keePassFormat
    }

    nonisolated struct Entry: Sendable, Equatable {
        var name: String
        /// Bundle ids to look up directly (fast path — finds the app anywhere).
        var bundleIDs: [String]
        /// Prefixes to match when scanning the Applications folders.
        var prefixes: [String]
        /// Why this app is a pointer. Drives the wording, nothing else.
        var localReadPath: LocalReadPath = .none
    }

    /// Alphabetical: this is a "where to look" list, and ranking it would be
    /// claiming something about apps we can't even read.
    static let entries: [Entry] = [
        // Bitwarden's own CLI (and the local service it starts) IS built — see
        // `gatedVendor`. This entry only matters when neither is installed.
        .init(name: "Bitwarden", bundleIDs: ["com.bitwarden.desktop"], prefixes: ["com.bitwarden."],
              localReadPath: .officialCLI("bw")),
        // Dashlane's own CLI (`dcli`) IS built — see `gatedVendor`. This entry only
        // matters when `dcli` isn't installed, and it names the tool so the pointer
        // can say what would turn the app into a real source.
        .init(name: "Dashlane", bundleIDs: ["com.dashlane.Dashlane", "com.dashlane.dashlanephonefinal"],
              prefixes: ["com.dashlane."], localReadPath: .officialCLI("dcli")),
        // No local read path: no CLI, no documented socket, no file we can open.
        .init(name: "Enpass", bundleIDs: ["in.sinew.Enpass-Desktop", "in.sinew.Walletx"],
              prefixes: ["in.sinew."]),
        .init(name: "KeePassium", bundleIDs: ["com.keepassium.mac", "com.keepassium.ios"],
              prefixes: ["com.keepassium."], localReadPath: .keePassFormat),
        // Keeper's own CLI (Commander) IS built — see `gatedVendor`. This entry
        // only matters when Commander isn't installed.
        .init(name: "Keeper", bundleIDs: ["com.callpod.KeeperDesktop", "com.keepersecurity.KeeperDesktop"],
              prefixes: ["com.callpod.", "com.keepersecurity."],
              localReadPath: .officialCLI("keeper")),
        // LastPass's own CLI (`lpass`) IS built — see `gatedVendor`. This entry only
        // matters when `lpass` isn't installed.
        .init(name: "LastPass", bundleIDs: ["com.lastpass.LastPass", "com.lastpass.lastpassmacdesktop"],
              prefixes: ["com.lastpass."], localReadPath: .officialCLI("lpass")),
        .init(name: "NordPass", bundleIDs: ["com.nordpass.macos", "com.nordpass.desktop"],
              prefixes: ["com.nordpass."]),
        // Proton Pass's own CLI IS built — see `gatedVendor`. This entry only matters
        // when `pass-cli` isn't installed. The tool is named exactly, because "the
        // Proton Pass command-line tool" was true but unsearchable, and because the
        // one thing a reader must not conclude is that it is the `pass` they may
        // already have.
        .init(name: "Proton Pass", bundleIDs: ["me.proton.pass.electron", "ch.protonmail.pass"],
              prefixes: ["me.proton.pass", "ch.protonmail.pass"],
              localReadPath: .officialCLI("pass-cli")),
        .init(name: "RoboForm", bundleIDs: ["com.siber.roboform"], prefixes: ["com.siber.roboform"]),
        .init(name: "Strongbox", bundleIDs: ["com.markmcguill.strongbox.mac", "com.markmcguill.strongbox"],
              prefixes: ["com.markmcguill.strongbox"], localReadPath: .keePassFormat),
    ]

    static func entry(forBundleID id: String) -> Entry? {
        if let exact = entries.first(where: { $0.bundleIDs.contains(id) }) { return exact }
        return entries.first { entry in entry.prefixes.contains { id.hasPrefix($0) } }
    }

    static func localReadPath(forBundleID id: String) -> LocalReadPath {
        entry(forBundleID: id)?.localReadPath ?? .none
    }

    /// Which catalog name (if any) owns a bundle id. Exact ids first, then
    /// prefixes — an exact hit is the more specific answer.
    static func name(forBundleID id: String) -> String? { entry(forBundleID: id)?.name }

    /// Apps whose vault SimpleVPN reads through its app itself. Never pointers —
    /// that would be two rows for one app, one of them lying.
    static let integratedAppPrefixes = ["com.1password.", "com.agilebits.", "org.keepassxc."]

    /// Which vendor row an installed app belongs to, when the app alone isn't
    /// enough to make that row work. Keeper is the case that matters: the Keeper
    /// app has no local API, so the app on its own is a pointer — but Keeper
    /// Commander turns it into a real source, and saying so is the single most
    /// useful thing this row can do.
    ///
    /// Strongbox and KeePassium are the same shape as Keeper and were added for the
    /// same reason: neither app has a local API, but both keep their entries in a
    /// KeePass `.kdbx`, and SimpleVPN now reads that file directly
    /// (`LocalVaultVendor.keePassFile`). So the app on its own is a pointer, and the
    /// file row turns it into a real source — which is the single most useful thing
    /// that row can say to somebody who has never heard the words "KeePass format".
    static func gatedVendor(forBundleID id: String) -> LocalVaultVendor? {
        switch name(forBundleID: id) {
        case "Keeper": .keeper
        // Bitwarden is the same shape: the desktop app has nothing SimpleVPN can
        // talk to, and `bw` (with the local service it starts) is what turns the app
        // into a real source. So the app alone points at the way in rather than
        // appearing as a second, dead row.
        case "Bitwarden": .bitwarden
        // And Dashlane is the same shape again: the desktop app has no local API at
        // all, and `dcli` is the whole read path — so the app alone points at the way
        // in rather than appearing as a second, dead row.
        // LastPass is the same shape once more: the desktop app exposes nothing
        // locally, and `lpass` is what turns it into a real source. So the app points
        // at the way in rather than appearing as a second, dead row.
        case "Dashlane": .dashlane
        // LastPass is the same shape once more: its desktop app exposes nothing
        // locally, and `lpass` is what turns it into a real source. So the app points
        // at the way in rather than appearing as a second, dead row.
        case "LastPass": .lastPass
        // Proton Pass is the same shape again: the desktop app has no local API, and
        // Proton's own `pass-cli` is what turns it into a real source. So the app
        // alone points at the way in rather than appearing as a second, dead row.
        case "Proton Pass": .protonPass
        case "Strongbox", "KeePassium": .keePassFile
        default: nil
        }
    }

    static func isIntegratedApp(bundleID: String) -> Bool {
        integratedAppPrefixes.contains { bundleID.hasPrefix($0) }
    }
}

// MARK: - The list

nonisolated enum SignInSourceCatalog {

    /// The AutoFill pane every AutoFill sentence points at. One spelling, shared
    /// by the Apple Passwords row, every pointer and the footnote.
    static let autoFillSettingsPath = "System Settings \u{25B8} General \u{25B8} AutoFill & Passwords"

    /// Open that pane. `ASSettingsHelper.openCredentialProviderAppSettings()` is
    /// available to ANY app from macOS 14 — it is not restricted to apps that ship a
    /// credential provider — and it lands on the AutoFill pane directly.
    ///
    /// The written path STAYS: it is what a VoiceOver user hears and what someone
    /// reading over a shoulder follows, and a button whose destination is invisible is
    /// the hover-only failure in another costume. So both, always — the sentence names
    /// the place, the button saves the walk.
    static func openAutoFillSettings() {
        ASSettingsHelper.openCredentialProviderAppSettings()
    }

    // MARK: The two rows that always work

    /// Type it every time. Always available — a Mac with nothing installed still
    /// has a keyboard, and this row is what keeps the list from ever being a
    /// dead end.
    static func typeEachTime() -> SignInSourceOption {
        SignInSourceOption(
            id: .typeEachTime, role: .fetches,
            title: "Type it each time",
            summary: "Nothing is saved. You type your username and password every time you connect.",
            explanation: "Nothing is kept anywhere \u{2014} not by SimpleVPN, not on this Mac. Every "
                + "connect asks for your username and password again, and for your verification code "
                + "if this VPN uses one.",
            symbol: "keyboard",
            storedKind: .manual, remembers: false)
    }

    /// The keychain row. WHO holds the secret is the point of this wording:
    /// macOS does, we don't, and we can't read it back unless macOS agrees.
    static func saveInSimpleVPN(biometricsAvailable: Bool) -> SignInSourceOption {
        var explanation =
            "Your password goes straight into the Apple keychain \u{2014} the same place macOS keeps "
            + "your other passwords. macOS protects it, not SimpleVPN, and SimpleVPN never sees it "
            + "again after you save it: it asks macOS for it at connect time and keeps no copy of its "
            + "own. You can remove it whenever you like."
        if biometricsAvailable {
            explanation += " You can also ask for a fingerprint: with Touch ID protection on, macOS "
                + "won\u{2019}t release your sign-in until you give one \u{2014} or your Apple Watch, "
                + "or your Mac\u{2019}s password."
        }
        return SignInSourceOption(
            id: .saveInSimpleVPN, role: .fetches,
            title: "Save it securely in SimpleVPN",
            summary: biometricsAvailable
                ? "Kept in the Apple keychain, protected by macOS. Connect with a fingerprint \u{2014} or with nothing to type."
                : "Kept in the Apple keychain, protected by macOS. Connect with nothing to type.",
            explanation: explanation,
            symbol: "lock.shield",
            storedKind: .manual, remembers: true)
    }

    /// Apple Passwords — AN AUTOFILL ROW, NOT A PROVIDER, and the wording has to say
    /// so.
    ///
    /// This row USED to promise fetch-like behaviour ("macOS fills the username and
    /// password in for you"), and that promise was not ours to make. SimpleVPN cannot
    /// read what Safari and the Passwords app manage: those items live in the
    /// data-protection keychain under the `com.apple.cfnetwork` access group, which
    /// this app's entitlement does not contain, so they are unreachable by
    /// construction rather than merely missing (see ApplePasswordsProvider's header).
    /// What actually works is AUTOFILL — the key in the field — which is macOS's own
    /// affordance, driven by the user, needing no entitlement and no lookup from us.
    ///
    /// So the copy promises exactly that much and no more: click the key, and macOS
    /// decides what it can offer. It deliberately does NOT claim the menu will
    /// contain a match, because whether it does is macOS's business and nobody here
    /// has watched it happen in OUR fields. Until a human confirms that, the honest
    /// sentence is the modest one.
    ///
    /// Two further honesties the copy carries:
    ///  • Verification codes stay in Apple Passwords — it exposes none of them to
    ///    other apps, so the code is still typed (`suppliesOTP` is false, correctly).
    ///  • NOTHING IS SAVED INTO APPLE PASSWORDS by picking this. SimpleVPN has no way
    ///    to write there at all: the only public path needs associated domains plus a
    ///    file served by the VPN operator, and it is deprecated with no macOS
    ///    replacement. Saving is what the "Save it securely in SimpleVPN" row does,
    ///    into the Apple keychain, which is a different place and already says so.
    static func applePasswords() -> SignInSourceOption {
        SignInSourceOption(
            id: .applePasswords, role: .fetches,
            title: "Apple Passwords",
            summary: "Fill the fields yourself from Apple Passwords \u{2014} click the key in the "
                + "username or password field.",
            explanation: "This is macOS\u{2019}s own AutoFill, the same key you see in Safari: click it "
                + "in the username or password field and macOS offers whatever it can for this VPN. "
                + "SimpleVPN doesn\u{2019}t read Apple Passwords itself and can\u{2019}t \u{2014} macOS "
                + "keeps Safari\u{2019}s and the Passwords app\u{2019}s entries where other apps "
                + "can\u{2019}t reach them \u{2014} so what the menu offers is macOS\u{2019}s decision, "
                + "not ours. Verification codes stay in Apple Passwords whatever happens: it "
                + "doesn\u{2019}t hand those to other apps, so you type the code yourself. Picking "
                + "this saves nothing anywhere; if you want your sign-in remembered, use "
                + "\u{201C}Save it securely in SimpleVPN\u{201D}.",
            symbol: "person.badge.key.fill",
            storedKind: .applePasswords, remembers: nil)
    }

    // MARK: Vendor rows (one shape, every vendor)

    /// A vendor row, built from its copy plus its live availability. There is no
    /// per-vendor branch here on purpose: a new adapter is a copy entry and a
    /// probe, never another `if`.
    static func vaultOption(_ vendor: LocalVaultVendor,
                            availability: LocalVaultAvailability,
                            foundOutsideAllowList: String? = nil) -> SignInSourceOption? {
        guard availability.isOffered else { return nil }
        let copy = LocalVaultCopyBook.copy(for: vendor)
        var option = SignInSourceOption(
            id: .vault(vendor), role: .fetches,
            title: copy.title, summary: copy.summary, explanation: copy.explanation,
            symbol: copy.symbol,
            storedKind: copy.storedKind, remembers: nil,
            // Every vendor row is configurable — including the ready ones. Someone
            // who wants to switch a working vendor off, or move to a different copy
            // of its tool, should not have to go looking for where that lives.
            configurableVendor: vendor)
        switch availability {
        case .notInstalled:
            return nil
        case .blocked(let block):
            option.state = .needsSetup(headline: copy.headline(for: block),
                                       steps: copy.steps(for: block))
            option.guidance = copy.guidance(for: block, foundAt: foundOutsideAllowList)
        case .unchecked(let ceiling):
            // ALWAYS a note now, and that is a fix rather than tidying: a vendor with
            // no `uncheckedNote` of its own used to fall through with `state` left at
            // `.ready`, so an unproven row said "Ready to use" out loud — to the eye
            // and to VoiceOver. The ceiling's own sentence is the floor, and a vendor's
            // wording still wins where it has some, because it can be specific.
            option.state = .unchecked(note: copy.uncheckedNote ?? ceiling.fallbackNote)
        case .ready:
            break
        }
        return option
    }

    // MARK: Pointer rows

    /// One pointer per installed app we cannot read. The WORDING carries the
    /// distinction, not the styling: "SimpleVPN can't read [yet]", "open it",
    /// "paste". "Yet" is not decoration — for a vendor whose own tool we could
    /// adopt, telling someone the door is permanently shut would be false.
    static func pointer(to app: InstalledPasswordApp) -> SignInSourceOption {
        let path = PasswordAppCatalog.localReadPath(forBundleID: app.bundleID)
        let cannot = path == .none
            ? "SimpleVPN can\u{2019}t read \(app.name)"
            : "SimpleVPN can\u{2019}t read \(app.name) yet"
        let summary = app.shipsAutoFillExtension
            ? "\(cannot), but \(app.name) can fill the fields itself."
            : "\(cannot). Open it and copy your password across."

        var explanation = "Your sign-in may well be saved in \(app.name). "
        switch path {
        case .none:
            explanation += "Nothing on this Mac lets SimpleVPN read \(app.name)\u{2019}s entries, "
                + "so this isn\u{2019}t something to pick \u{2014} it is a reminder of where to look."
        case .officialCLI(let tool):
            explanation += "SimpleVPN doesn\u{2019}t read \(app.name) yet: \(app.name) ships its "
                + "own command-line tool (\(tool)) that could do it, and adding it is on the list. "
                + "Until then this is a reminder of where to look, not something to pick."
        case .keePassFormat:
            // NOT "on the list" any more: the file adapter is built. This row is now
            // only reached when the file row is NOT on offer — no `keepassxc-cli` and
            // no database chosen — so what it says is how to turn it on.
            explanation += "\(app.name) keeps its entries in a KeePass database, and SimpleVPN can "
                + "read one of those directly \u{2014} it just needs KeePassXC\u{2019}s command-line "
                + "tool on this Mac (\u{201C}brew install --cask keepassxc\u{201D}) and to be pointed "
                + "at the file. Then \u{201C}KeePass database file\u{201D} appears above as something "
                + "to pick. Until then, open \(app.name) and copy your password across."
        }

        if app.shipsAutoFillExtension {
            explanation += " \(app.name) does come with a macOS AutoFill extension: switch it on in "
                + "\(autoFillSettingsPath), then click the key in the username or password field and "
                + "\(app.name) fills them in. Otherwise open \(app.name), copy your password, and "
                + "paste it into the fields below."
        } else {
            explanation += " Open \(app.name), copy your username and password, and paste them into "
                + "the fields below."
        }
        return SignInSourceOption(
            id: .otherApp(bundleID: app.bundleID), role: .hint,
            title: app.name, summary: summary, explanation: explanation,
            symbol: app.shipsAutoFillExtension ? "rectangle.and.pencil.and.ellipsis" : "arrow.up.right.square",
            storedKind: nil, remembers: nil,
            appBundleID: app.bundleID,
            fillsThroughAutoFill: app.shipsAutoFillExtension)
    }

    // MARK: The whole list

    /// Every row to show, fetchable ones first. The order is deliberate: the two
    /// that always work lead, then this Mac's own apps, then the pointers.
    static func options(_ facts: SignInSourceFacts) -> [SignInSourceOption] {
        fetchable(facts) + pointers(facts)
    }

    static func fetchable(_ facts: SignInSourceFacts) -> [SignInSourceOption] {
        var out: [SignInSourceOption] = [typeEachTime()]
        if facts.allowsPasswordSave {
            out.append(saveInSimpleVPN(biometricsAvailable: facts.biometricsAvailable))
        }
        out.append(applePasswords())
        // Vendor order is the enum's order — stable, and one place to change.
        for vendor in LocalVaultVendor.allCases {
            if let option = vaultOption(
                vendor, availability: facts.availability(vendor),
                foundOutsideAllowList: facts.toolsFoundOutsideAllowList[vendor]) {
                out.append(option)
            }
        }
        return out
    }

    /// The pointer rows on their own (the chooser gives them their own heading).
    /// An app we DO read never appears here — nor does one whose gated vendor row
    /// is already on offer, which is what keeps Keeper from being both at once.
    ///
    /// …and nor does an app belonging to a vendor the user has SWITCHED OFF. That
    /// is the second half of "disabled means not offered and not hinted": without
    /// this filter, turning Keeper off would move it from the sources list to the
    /// "other password apps on this Mac" list, which is not off — it is the same
    /// app still being advertised, in a worse place.
    static func pointers(_ facts: SignInSourceFacts) -> [SignInSourceOption] {
        facts.otherApps
            .filter { !PasswordAppCatalog.isIntegratedApp(bundleID: $0.bundleID) }
            .filter { app in
                guard let vendor = PasswordAppCatalog.gatedVendor(forBundleID: app.bundleID)
                else { return true }
                guard facts.isEnabled(vendor) else { return false }
                return !facts.availability(vendor).isOffered
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            .map(pointer(to:))
    }

    /// The row a stored source maps back to, so a returning VPN can be shown as
    /// "this is how you sign in" without re-deriving the copy.
    static func option(for kind: CredentialSourceKind, remembers: Bool,
                       facts: SignInSourceFacts) -> SignInSourceOption? {
        if kind == .manual {
            return remembers ? saveInSimpleVPN(biometricsAvailable: facts.biometricsAvailable)
                             : typeEachTime()
        }
        return fetchable(facts).first { $0.storedKind == kind && $0.role == .fetches }
            ?? LocalVaultVendor.allCases
                .first { LocalVaultCopyBook.copy(for: $0).storedKind == kind }
                .flatMap { vaultOption($0, availability: .ready) }
    }

    // MARK: Headings and footnotes

    static let title = "How do you want to sign in?"
    static let subtitle = "Pick one \u{2014} you can change it whenever you like."
    static let fetchableHeading = "SimpleVPN gets your sign-in for you"
    static let pointerHeading = "Other password apps on this Mac"
    static let pointerCaption =
        "SimpleVPN can\u{2019}t read these. They\u{2019}re listed so you know where to look."
    /// Always shown, so someone whose password app we have never heard of still
    /// learns the one path that works whatever the vendor.
    static let autoFillFootnote =
        "Any password app you have switched on in " + autoFillSettingsPath
        + " can fill these fields: click the key in the username or password field to pick a saved sign-in."

    /// What VoiceOver says the moment a row is chosen. User-initiated, so it is
    /// spoken immediately — the click is the debounce.
    static func announcement(for option: SignInSourceOption) -> String {
        switch option.id {
        case .typeEachTime: "You\u{2019}ll type your sign-in each time."
        case .saveInSimpleVPN: "Your sign-in will be saved securely in SimpleVPN."
        case .applePasswords: "You\u{2019}ll sign in with Apple Passwords."
        case .vault(let vendor): "You\u{2019}ll sign in with \(LocalVaultCopyBook.copy(for: vendor).title)."
        case .otherApp: "\(option.title) can\u{2019}t be read by SimpleVPN."
        }
    }

    /// The container sentence for a pointer row — it holds a button, so it is a
    /// `.contain` element with an explicit label rather than a combined one.
    static func pointerAccessibilityLabel(_ option: SignInSourceOption) -> String {
        "\(option.title). \(option.summary)"
    }
}

// MARK: - First time versus every other time

/// The plain facts the first-run decision turns on. A pure value type: the
/// decision is testable without a keychain, a manager or a window.
nonisolated struct SignInFlowInputs: Sendable, Equatable {
    /// A sign-in already exists for this VPN: saved (or Touch ID-protected)
    /// credentials, or a manager item linked to it.
    var hasStoredSignIn = false
    /// This VPN has connected successfully at least once.
    var hasConnectedBefore = false
    /// The source this VPN is set to. Manual is always available.
    var chosenKind: CredentialSourceKind = .manual
    /// Whether that source can serve right now (its app installed / running /
    /// signed in, and something linked for it to fetch).
    var chosenSourceAvailable = true
    /// The user closed the setup card for this run.
    var dismissedForNow = false
    /// Nothing to collect at all (Tailscale, WireGuard, autologin, a proxy
    /// tunnel): no sign-in question exists, so none is asked.
    var collectsNothing = false
}

/// What the connect surface should do about sign-in.
nonisolated enum SignInFlowStep: Sendable, Equatable {
    /// Nothing to ask — this VPN signs itself in.
    case nothingToCollect
    /// First time: present the chooser so the user says how they want to sign in.
    case chooseHowToSignIn
    /// Returning: don't ask again. Connect through what was chosen.
    case connectStraightThrough
    /// The chosen source has gone away. Offer the way out explicitly instead of
    /// failing at connect time: type it once, or choose something else.
    case recoverUnavailableSource(CredentialSourceKind)
}

nonisolated enum SignInFlow {

    /// The ONE decision the first-connect card, the credential forms and the
    /// recovery notice all read. The order matters and IS the design:
    ///
    /// 1. Nothing to collect wins outright — asking would be nonsense.
    /// 2. A chosen-but-unavailable source wins over everything else: a dead
    ///    option must never be discovered as a connect failure.
    /// 3. Anything already set up (connected before, or a sign-in on file) is
    ///    NOT re-asked. That is the whole "returning" requirement.
    /// 4. A dismissed card stays dismissed for this run.
    /// 5. Otherwise it is the first time: ask.
    static func step(_ inputs: SignInFlowInputs) -> SignInFlowStep {
        if inputs.collectsNothing { return .nothingToCollect }
        if inputs.chosenKind != .manual, !inputs.chosenSourceAvailable {
            return .recoverUnavailableSource(inputs.chosenKind)
        }
        if inputs.hasConnectedBefore || inputs.hasStoredSignIn { return .connectStraightThrough }
        if inputs.dismissedForNow { return .connectStraightThrough }
        return .chooseHowToSignIn
    }

    /// Whether the chooser is on screen for these inputs.
    static func showsChooser(_ inputs: SignInFlowInputs) -> Bool {
        step(inputs) == .chooseHowToSignIn
    }

    // MARK: Recovery copy

    /// "Your password app isn't there" — one sentence per source, naming the app
    /// and what it means, never a status code.
    static func unavailableHeadline(_ kind: CredentialSourceKind) -> String {
        switch kind {
        case .onePassword:
            "1Password isn\u{2019}t available, so SimpleVPN can\u{2019}t get your sign-in from it."
        case .keePassXC:
            "KeePassXC isn\u{2019}t running (or its browser integration is off), so SimpleVPN can\u{2019}t get your sign-in from it."
        case .keeper:
            "Keeper Commander isn\u{2019}t available or isn\u{2019}t signed in, so SimpleVPN can\u{2019}t get your sign-in from Keeper."
        case .bitwarden:
            // Never "Bitwarden isn't available": the app may be right there. What is
            // missing is an unlocked vault SimpleVPN may read, and the fix is the
            // local service.
            "Bitwarden isn\u{2019}t unlocked for SimpleVPN, so it can\u{2019}t get your sign-in "
            + "from it. Run \u{201C}bw unlock\u{201D} and then \u{201C}bw serve\u{201D} in Terminal."
        case .dashlane:
            // Never "Dashlane isn't installed": the app and its tool may both be
            // right there. What is missing is a signed-in, unlocked Dashlane, and the
            // fix is one command that Dashlane — not SimpleVPN — asks the questions
            // for.
            "Dashlane isn\u{2019}t unlocked for SimpleVPN, so it can\u{2019}t get your sign-in "
            + "from it. Run \u{201C}dcli sync\u{201D} in Terminal and answer Dashlane\u{2019}s "
            + "questions."
        case .keePassFile:
            // Deliberately does NOT say "your database is missing": the same recovery
            // notice covers a moved file, a file still downloading, a password that
            // hasn't been typed this session and a tool that isn't installed. Naming
            // one of those would be wrong three times out of four; the settings pane
            // says which, in one sentence, right next to the fix.
            "SimpleVPN can\u{2019}t read your KeePass database file right now. Check it in "
            + "Settings \u{25B8} Sign-In Sources \u{2014} it will say which part is missing."
        case .applePasswords:
            // Not "Apple Passwords is unavailable" — it isn't, and SimpleVPN was never
            // reading it. What is missing is the server to match, and the way that
            // actually works is the key in the field.
            "SimpleVPN doesn\u{2019}t know which saved sign-in to look for. Click the key in the "
            + "username or password field and macOS will offer what it can."
        case .manual:
            "SimpleVPN can\u{2019}t get your sign-in."
        case .passwordStore:
            // Names GnuPG rather than "pass", because GnuPG is what we actually need
            // and telling someone to install pass would send them to do work that
            // changes nothing.
            // Names the source, as every other recovery sentence does — and names
            // GnuPG as the thing that might be missing, because telling someone to
            // install `pass` would send them to do work that changes nothing.
            "SimpleVPN can\u{2019}t read your pass / gopass store right now \u{2014} GnuPG "
            + "isn\u{2019}t available, or the store folder isn\u{2019}t where it expected. "
            + "Check it in Settings \u{25B8} Sign-In Sources, which will say which."
        case .lastPass:
            // Names the source, as every other recovery sentence does, and names the
            // two things it is nearly always: nobody has signed the tool in, or its
            // hour is up. No command here — this string is rendered as plain text, so
            // a `code` span would show its backticks, and the settings pane gives the
            // exact command next to the state it belongs to.
            "SimpleVPN can\u{2019}t read your LastPass sign-in right now \u{2014} "
            + "LastPass\u{2019}s own tool isn\u{2019}t signed in, or it has forgotten your master "
            + "password. Check it in Settings \u{25B8} Sign-In Sources, which will say which and "
            + "give you the one command that fixes it."
        case .protonPass:
            // Names the source (every recovery sentence does) and names the PLAN,
            // because "sign in again" is the wrong advice for the one person this
            // sentence cannot help: a free-plan account is refused at sign-in and left
            // signed out, so it lands here looking identical to a lapsed session.
            // The settings pane says which; this says both are possible.
            "SimpleVPN can\u{2019}t read Proton Pass right now \u{2014} its command-line tool "
            + "isn\u{2019}t signed in, its session is locked, or your Proton plan doesn\u{2019}t "
            + "include the tool. Check it in Settings \u{25B8} Sign-In Sources, which will say which."
        case .passbolt:
            // Names the source, as every recovery sentence must, and deliberately
            // does NOT guess which of the four things is missing: the program, the
            // server address, the program's own setup for that server, or its
            // passphrase. Naming one would be wrong three times in four, and the
            // settings pane says which in one sentence right beside the fix.
            "SimpleVPN can\u{2019}t read your Passbolt server right now. Check it in "
            + "Settings \u{25B8} Sign-In Sources \u{2014} it will say which part is missing."
        }
    }

    /// The way out, always both halves: connect now, or change the setup.
    static let recoveryLine =
        "Type your sign-in once to connect now, or choose another way to sign in."
}
