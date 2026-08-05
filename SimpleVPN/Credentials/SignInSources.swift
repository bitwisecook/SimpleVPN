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

// MARK: - Vendors we can actually talk to

/// A password app SimpleVPN reaches over a LOCAL channel. Membership here is a
/// claim we must be able to back with a working fetch.
///
/// A VENDOR IS NOT A TRANSPORT — see `LocalVaultTransport`. Keeping the two
/// separate is what lets one future file-backed adapter serve KeePassXC,
/// Strongbox and KeePassium (all three store the same KeePass `.kdbx`) instead
/// of three near-copies, and what lets Keeper's CLI and its local daemon be one
/// vendor with two ways in.
nonisolated enum LocalVaultVendor: String, CaseIterable, Sendable, Hashable {
    case onePassword
    case keePassXC
    case keeper
}

/// HOW a vendor is reached. Deliberately separate from the vendor, and named in
/// each adapter, because the shape of the channel — not the brand — is what
/// decides how detection, session liveness and failure behave:
///
///  • `.signedIPC` — a vendor library doing app-to-app IPC (1Password's SDK).
///    Detection = the library is on disk AND the app is running.
///  • `.appSocket` — a unix socket the running app listens on (KeePassXC's
///    browser protocol). Detection = the socket exists. Nothing to spawn.
///  • `.cli` — the vendor's own command-line tool (Keeper Commander today;
///    Bitwarden's `bw`, Dashlane's `dcli`, LastPass's `lpass`, Proton Pass's CLI,
///    Passbolt's `go-passbolt-cli`, and `pass`/`gopass` are all this shape).
///    Detection = the tool is on disk; liveness = a session probe; failures come
///    back on stderr and must be scrubbed (see LocalToolRunner).
///  • `.localDaemon` — a loopback HTTP/REST server the vendor's tool starts
///    (Keeper's Service Mode; Bitwarden's `bw serve` on 127.0.0.1:8087 is the
///    same shape). Cheaper per fetch than spawning, so an adapter that has both
///    prefers this and falls back to `.cli`.
///  • `.file` — a vault FILE read directly, no vendor process at all. Not built:
///    it is how Strongbox and KeePassium would be served, since both store
///    KeePass `.kdbx` — the same format KeePassXC does. One adapter, three
///    vendors, and the existing KeePassXC socket path stays exactly as it is
///    (a running app with a live socket is a better answer than a file on disk,
///    because the app owns the unlock).
nonisolated enum LocalVaultTransport: String, CaseIterable, Sendable, Hashable {
    case signedIPC
    case appSocket
    case cli
    case localDaemon
    case file
}

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

    /// The two states the enablement banner exists for: something to switch on or
    /// install, as opposed to "your app isn't running" (which is not a setup
    /// problem) or "it's too old" (which is an update, not an enablement).
    var wantsEnablementBanner: Bool {
        self == .toolMissing || self == .integrationOff || self == .notSignedIn
    }
}

/// What a vendor can do right now. Ordered from useless to usable.
nonisolated enum LocalVaultAvailability: Sendable, Equatable {
    /// Not on this Mac at all — the row isn't offered.
    case notInstalled
    /// Here, but something must happen first. Offered WITH the fix.
    case blocked(LocalVaultBlock)
    /// Here and reachable, but we have never proven the whole path. Offered;
    /// picking it runs the one-time check.
    case unchecked
    /// Proven working.
    case ready

    var isOffered: Bool { self != .notInstalled }
    var isReady: Bool { self == .ready }
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
    static let onePasswordSDKs = page("1Password SDKs", "https://developer.1password.com/docs/sdks/")
    static let onePasswordCLIIntegration = page("1Password CLI app integration",
                                               "https://developer.1password.com/docs/cli/app-integration/")

    // Keeper Commander.
    static let keeperCommander = page("Keeper Commander",
                                      "https://docs.keeper.io/en/keeperpam/commander-cli/overview")
    static let keeperCommanderLogin = page(
        "Keeper Commander sign-in",
        "https://docs.keeper.io/keeperpam/commander-cli/commander-installation-setup/logging-in")
    static let keeperServiceMode = page(
        "Keeper Commander Service Mode",
        "https://docs.keeper.io/keeperpam/commander-cli/service-mode-rest-api")

    // KeePassXC.
    static let keePassXC = page("KeePassXC documentation", "https://keepassxc.org/docs/")

    // Vendors on the seam but not yet implemented — listed here so the next
    // adapter's author has the same auditable table rather than a fresh guess.
    static let bitwardenCLI = page("Bitwarden CLI", "https://bitwarden.com/help/cli/")
    static let dashlaneCLI = page("Dashlane CLI", "https://cli.dashlane.com/")
    static let protonPassCLI = page("Proton Pass CLI", "https://protonpass.github.io/pass-cli/")
    static let passboltCLI = page("Passbolt CLI", "https://github.com/passbolt/go-passbolt-cli")
    static let passwordStore = page("pass", "https://www.passwordstore.org/")
    static let gopass = page("gopass", "https://www.gopass.pw/")
    static let lastPassCLI = page("LastPass CLI", "https://github.com/lastpass/lastpass-cli")
    static let hashiCorpVaultCLI = page("HashiCorp Vault CLI",
                                        "https://developer.hashicorp.com/vault/docs/commands")

    /// Everything above, for the audit test.
    static let all: [Page] = [
        onePasswordSDKs, onePasswordCLIIntegration,
        keeperCommander, keeperCommanderLogin, keeperServiceMode,
        keePassXC,
        bitwardenCLI, dashlaneCLI, protonPassCLI, passboltCLI,
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
}

nonisolated enum LocalVaultCopyBook {

    static func copy(for vendor: LocalVaultVendor) -> LocalVaultCopy {
        switch vendor {
        case .onePassword: onePassword
        case .keePassXC: keePassXC
        case .keeper: keeper
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
        blocks: [
            .toolMissing: ("Keeper Commander isn\u{2019}t installed on this Mac", []),
            .notSignedIn: ("Keeper Commander isn\u{2019}t signed in on this Mac", []),
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
    var vaults: [LocalVaultVendor: LocalVaultAvailability] = [:]

    /// This Mac can ask for a fingerprint (or Apple Watch, or the account
    /// password) — decides whether the keychain row promises one.
    var biometricsAvailable = false

    /// The profile allows saving the password at all (`auth-nocache` and the
    /// like say no). False drops the keychain row rather than offering a setting
    /// the engine will refuse.
    var allowsPasswordSave = true

    /// Password apps found installed that SimpleVPN has no way to read.
    var otherApps: [InstalledPasswordApp] = []

    func availability(_ vendor: LocalVaultVendor) -> LocalVaultAvailability {
        vaults[vendor] ?? .notInstalled
    }
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
///     adapter would serve all three (`LocalVaultTransport.file`), so again:
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
        .init(name: "Bitwarden", bundleIDs: ["com.bitwarden.desktop"], prefixes: ["com.bitwarden."],
              localReadPath: .officialCLI("bw")),
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
        .init(name: "LastPass", bundleIDs: ["com.lastpass.LastPass", "com.lastpass.lastpassmacdesktop"],
              prefixes: ["com.lastpass."], localReadPath: .officialCLI("lpass")),
        .init(name: "NordPass", bundleIDs: ["com.nordpass.macos", "com.nordpass.desktop"],
              prefixes: ["com.nordpass."]),
        .init(name: "Proton Pass", bundleIDs: ["me.proton.pass.electron", "ch.protonmail.pass"],
              prefixes: ["me.proton.pass", "ch.protonmail.pass"],
              localReadPath: .officialCLI("the Proton Pass command-line tool")),
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
    static func gatedVendor(forBundleID id: String) -> LocalVaultVendor? {
        name(forBundleID: id) == "Keeper" ? .keeper : nil
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

    /// Apple Passwords. Available on every Mac this app runs on; what varies is
    /// only whether a matching sign-in has been saved, which the user can see
    /// for themselves in the field's own AutoFill menu.
    static func applePasswords() -> SignInSourceOption {
        SignInSourceOption(
            id: .applePasswords, role: .fetches,
            title: "Apple Passwords",
            summary: "Use a sign-in you have already saved in Apple Passwords.",
            explanation: "macOS fills the username and password in for you, using the same AutoFill "
                + "you get in Safari \u{2014} click the key in either field to pick the saved sign-in. "
                + "macOS asks your permission the first time. Verification codes stay in Apple "
                + "Passwords: it doesn\u{2019}t hand those to other apps, so you would still type the "
                + "code yourself.",
            symbol: "person.badge.key.fill",
            storedKind: .applePasswords, remembers: nil)
    }

    // MARK: Vendor rows (one shape, every vendor)

    /// A vendor row, built from its copy plus its live availability. There is no
    /// per-vendor branch here on purpose: a new adapter is a copy entry and a
    /// probe, never another `if`.
    static func vaultOption(_ vendor: LocalVaultVendor,
                            availability: LocalVaultAvailability) -> SignInSourceOption? {
        guard availability.isOffered else { return nil }
        let copy = LocalVaultCopyBook.copy(for: vendor)
        var option = SignInSourceOption(
            id: .vault(vendor), role: .fetches,
            title: copy.title, summary: copy.summary, explanation: copy.explanation,
            symbol: copy.symbol,
            storedKind: copy.storedKind, remembers: nil)
        switch availability {
        case .notInstalled:
            return nil
        case .blocked(let block):
            option.state = .needsSetup(headline: copy.headline(for: block),
                                       steps: copy.steps(for: block))
            option.guidance = copy.guidance(for: block)
        case .unchecked:
            if let note = copy.uncheckedNote { option.state = .unchecked(note: note) }
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
            explanation += "\(app.name) keeps its entries in a KeePass database \u{2014} the same "
                + "format SimpleVPN already reads through KeePassXC \u{2014} so reading it "
                + "directly is on the list. Until then this is a reminder of where to look, not "
                + "something to pick."
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
            if let option = vaultOption(vendor, availability: facts.availability(vendor)) {
                out.append(option)
            }
        }
        return out
    }

    /// The pointer rows on their own (the chooser gives them their own heading).
    /// An app we DO read never appears here — nor does one whose gated vendor row
    /// is already on offer, which is what keeps Keeper from being both at once.
    static func pointers(_ facts: SignInSourceFacts) -> [SignInSourceOption] {
        facts.otherApps
            .filter { !PasswordAppCatalog.isIntegratedApp(bundleID: $0.bundleID) }
            .filter { app in
                guard let vendor = PasswordAppCatalog.gatedVendor(forBundleID: app.bundleID)
                else { return true }
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
        case .applePasswords:
            "SimpleVPN doesn\u{2019}t know which saved sign-in to use from Apple Passwords."
        case .manual:
            "SimpleVPN can\u{2019}t get your sign-in."
        }
    }

    /// The way out, always both halves: connect now, or change the setup.
    static let recoveryLine =
        "Type your sign-in once to connect now, or choose another way to sign in."
}
