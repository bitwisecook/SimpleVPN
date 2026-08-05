// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceSettings.swift
//  The per-vendor configuration surface: which password apps SimpleVPN may use at
//  all, and the paths and endpoints each one actually needs.
//
//  FOUR THINGS THIS FILE IS RESPONSIBLE FOR, and each is a decision rather than
//  an implementation detail:
//
//   1. ENABLE / DISABLE IS ONE SWITCH WITH NO HALF STATE. A disabled vendor is
//      not offered in the chooser AND not hinted at as "another password app on
//      this Mac" — because a switch that hides a row but keeps advertising the
//      app is not off. That is structural, not remembered: `SignInSourceFacts
//      .availability(_:)` answers `.notInstalled` for a disabled vendor, so every
//      caller — chooser, readiness, connect-time recovery — is filtered by
//      construction. The pane reads `rawAvailability(_:)` instead, which is the
//      only place allowed to see through the filter.
//
//   2. FIELDS ARE PER VENDOR, NOT A UNIFORM BLOB. 1Password needs no path at all
//      (its channel is signed app-to-app IPC); KeePassXC needs a socket; Keeper
//      needs a binary. Showing all three to all three would be three wrong
//      questions per vendor.
//
//   3. A DETECTED PATH IS A SUGGESTION, NEVER A VALUE. See
//      `VendorFieldPresentation` — this project has already shipped the bug where
//      an example string became a field's TITLE (and so its VoiceOver name, and so
//      apparently its value); 26 sites were fixed for it. A pre-filled guess makes
//      that failure much more attractive, so the value/suggestion distinction is a
//      pure, tested function here rather than a habit in a view.
//
//   4. AN EXPLICIT PATH IS THE SANCTIONED ESCAPE HATCH, NOT AN ERROR. Discovery
//      finds tools in places the execution allow-list will not search
//      (`~/.bun/bin`, an nvm version directory, a `PATH` entry). Pointing at one
//      deliberately is exactly how such a tool is meant to be used, so validation
//      says "SimpleVPN will run this because you chose it" and not "wrong". What
//      is still refused, explicit or not, is a world-writable directory: there,
//      anyone on the Mac decides what we execute, which is the entire reason the
//      check exists.
//
//  MDM: an administrator can allow or forbid vendors, pin paths, and switch
//  discovery off. Pinned and forbidden rows are VISIBLY locked and never silently
//  revert — a control that snaps back with no explanation reads as a bug in this
//  app rather than as policy. See Docs/MDM.md.
//
//  Nothing in this file has a UI dependency: the pane renders it, the tests read
//  it, and it works with no vendor installed anywhere.
//

import Foundation
import os

// MARK: - Vendor identity for settings

nonisolated extension LocalVaultVendor {
    /// The stable slug used in setting ids, defaults keys, manual anchors and MDM
    /// payloads. Fixed forever once shipped — like every other setting id in this
    /// app, it is the CLI/MDM/manual contract, so a display-name change must never
    /// move it.
    var settingSlug: String {
        switch self {
        case .onePassword: "onepassword"
        case .keePassXC: "keepassxc"
        case .keeper: "keeper"
        case .bitwarden: "bitwarden"
        case .dashlane: "dashlane"
        // Named for the FORMAT, not for a brand — see `LocalVaultVendor
        // .keePassFile`. Fixed forever: it is the MDM, CLI and manual-anchor
        // contract, and it must not become "strongbox" the day Strongbox is
        // mentioned on screen.
        case .keePassFile: "keepassfile"
        case .passwordStore: "passwordstore"
        case .lastPass: "lastpass"
        // "protonpass", never "pass" or "passcli": the slug is the MDM, CLI and
        // manual-anchor contract, and it must never be confusable with the
        // `passwordstore` slug above — an administrator's payload naming the wrong one
        // would allow or forbid the wrong vendor.
        case .protonPass: "protonpass"
        case .passbolt: "passbolt"
        }
    }

    /// The vendor's name in a sentence. One source (the copy book) so the pane and
    /// the chooser can never call the same vendor two things.
    var displayTitle: String { LocalVaultCopyBook.copy(for: self).title }

    static func vendor(withSlug slug: String) -> LocalVaultVendor? {
        allCases.first { $0.settingSlug == slug }
    }
}

// MARK: - What a vendor needs configured

/// The KIND of thing a field holds. Validation and the keyboard-free "Reset to
/// Detected" behaviour both key off this, so a new field type is one case here
/// rather than a branch in the view.
nonisolated enum VendorConfigFieldKind: Sendable, Equatable {
    /// An absolute path to a program. Validated against the same rules the
    /// execution side applies, and reported against the same allow-list.
    case toolBinary(tool: String)
    /// A unix-domain socket the vendor's running app listens on.
    case unixSocket
    /// `host:port` for a loopback daemon the vendor's own tool starts.
    case daemonEndpoint
    /// A vault file on disk (a KeePass `.kdbx`, say). WIRED: the `.kdbx` adapter's
    /// database path is this.
    case vaultFile(extensions: [String])
    /// A KEY FILE — a second factor for a vault, whose CONTENTS are a secret we
    /// never read (the vendor's own tool does) but whose PATH is not.
    ///
    /// Deliberately not `vaultFile`: it validates the same way but it is a
    /// different question with different copy, and one field kind rendering as two
    /// rows both called "database file" is how a user ends up putting their key file
    /// where their database goes. Any extension (or none) is legitimate — KeePassXC
    /// writes `.keyx`, older releases wrote `.key`, and a hand-made one is often a
    /// plain file with no extension at all — so this case carries no extension list
    /// to filter by, on purpose.
    case keyFile
    /// A security key's challenge-response SLOT. Not a path: a small number, 1 or 2.
    ///
    /// EMPTY MEANS NONE, and that is the design rather than an omission: a database
    /// that needs a security key is told apart from one that doesn't by whether this
    /// has a number in it. A separate "use a security key" switch would be a second
    /// place for the same fact to live, and the two would fall out of step.
    case securityKeySlot
    /// A PKCS#11 module (a `.so`/`.dylib`, loaded rather than executed).
    case pkcs11Module
    /// A DIRECTORY holding a whole store, rather than one file — a `pass` /
    /// `gopass` password store, whose entries are files inside it.
    ///
    /// Deliberately not `vaultFile`: it validates differently (a directory that
    /// must contain `.gpg-id`, not a file with an extension), and the "choose"
    /// affordance has to offer a folder rather than a document.
    case storeDirectory
    /// A FIELD NAME inside an entry, not a path — e.g. which line of a `pass`
    /// entry holds the username. Free text with no filesystem meaning at all, so
    /// it must never be validated or pre-filled as though it were a path.
    case entryFieldName(suggestions: [String])
    /// A SERVER'S ADDRESS. `https://passbolt.example.com` — the first field kind
    /// here that names something not on this Mac.
    ///
    /// Deliberately not `daemonEndpoint`: that is a `host:port` on loopback and is
    /// REFUSED when it is anywhere else, which is the exact opposite of what this
    /// one wants. And deliberately not free text: `https` only, no userinfo, no
    /// query — see `PassboltServerLocation.validate`, which is the one definition.
    case serverURL
    /// THE VENDOR TOOL'S OWN CONFIG FILE, for one instance. Its CONTENTS are the
    /// vendor's secrets, which we never read and never write; its PATH is not a
    /// secret.
    ///
    /// A separate kind from `vaultFile` because it is a different question with
    /// different copy — and because the check worth running on it is not "is this a
    /// database" but "can anybody else on this Mac read it", which is a sentence
    /// the other kinds have no use for.
    case toolConfigFile

    // NOTE on `daemonEndpoint` and `pkcs11Module`: no shipped field declares them
    // yet. They are here because the adapters that need them are already designed —
    // Bitwarden's `bw serve` is a loopback endpoint — and each one's validation and
    // its setting copy are written and tested. Their presence is what makes adding
    // either a one-row declaration instead of another branch in every switch. A
    // field is only DECLARED when something reads it, which is why neither appears
    // on screen: a setting nothing consults is worse than a missing one, because
    // someone will configure it and then wonder why their VPN still fails.

    /// The tool whose discovery result pre-fills this field, if any.
    var detectionTool: String? {
        if case .toolBinary(let tool) = self { return tool }
        return nil
    }
}

/// One configurable thing, bound to its setting id (and therefore to its manual
/// anchor, its search entry and its MDM address).
nonisolated struct VendorConfigField: Sendable, Equatable, Identifiable {
    /// The stable setting id — `creds.keeper.tool-path`. Also the manual anchor
    /// (dots → dashes) and what MDM and the CLI address.
    var settingID: String
    /// The password app this belongs to, or nil for a tool that is not a password
    /// app but still needs a path.
    ///
    /// `ykman` is the case: the security-key feed resolves it through
    /// `LocalToolRunner` with the very same `signin.tool.ykman.path` override this
    /// pane writes. It gets a row HERE rather than a second override of its own,
    /// because "where is that tool" should be answered in one place — and a user who
    /// has already been shown that field for Keeper should not have to discover a
    /// different mechanism for the next tool.
    var vendor: LocalVaultVendor?
    /// What to call the owner in a sentence.
    var ownerTitle: String
    var kind: VendorConfigFieldKind
    /// Where the value is persisted.
    var defaultsKey: String
    /// An EXAMPLE. It is shown as a `prompt:` placeholder and nowhere else — never
    /// as the field's title, never as its value, never as its VoiceOver name.
    var example: String
    /// What SimpleVPN uses when this field is EMPTY, for a field whose empty state
    /// is a working state rather than a gap. Only the vendor's own documented
    /// default belongs here — never a guess of ours, and never a detection (that is
    /// `detected(for:)`, which is measured on this Mac).
    ///
    /// `bw serve`'s 127.0.0.1:8087 is the case: nothing on disk can be found to
    /// discover it, so "not set, and SimpleVPN hasn't found one" would be both true
    /// and useless. Absent for every other field, which keeps their wording exactly
    /// as it was.
    var emptyMeansDefault: String? = nil

    var id: String { settingID }
}

// MARK: - The declaration table

/// Every vendor's configurable surface, declared once.
///
/// Deliberately SHORT. A setting that nothing reads is worse than a missing one:
/// it invites someone to configure a path that changes nothing and then wonder why
/// their VPN still fails. So a field appears here only when some code path
/// genuinely consults it — Keeper's binary (`LocalToolRunner.userConfiguredPath`)
/// and KeePassXC's socket (`KeePassXCProtocol.discoverSocket`). 1Password needs
/// nothing but its switch, because its channel is the app's own signed IPC and
/// there is no path to get wrong.
nonisolated enum SignInSourceSettings {

    // MARK: Defaults keys

    /// The path key `LocalToolRunner.userConfiguredPath` already reads. Sharing it
    /// is the point: the pane writes the key the runner resolves, so there is one
    /// notion of "the path the user set" rather than a settings copy that has to be
    /// kept in step.
    static func toolPathKey(_ tool: String) -> String { "signin.tool.\(tool).path" }
    static func vendorEnabledKey(_ vendor: LocalVaultVendor) -> String {
        "signin.vendor.\(vendor.settingSlug).enabled"
    }
    static let keePassXCSocketKey = "signin.keepassxc.socket"
    /// Bitwarden's local-service address. The key `BitwardenSettings` reads, for the
    /// same reason the tool-path key is shared with `LocalToolRunner`: one notion of
    /// "what the user set", not a settings copy to keep in step.
    static let bitwardenEndpointKey = BitwardenSettings.endpointKey
    /// The `.kdbx` adapter's three settings. Paths and a slot number — never the
    /// database password, which is not a setting and never goes near `UserDefaults`
    /// (KeePassUnlock.swift).
    static let keePassDatabaseKey = "signin.keepassfile.database"
    static let keePassKeyFileKey = "signin.keepassfile.keyfile"

    /// `pass` / `gopass`, both INSTANCE level: someone with a work store and a
    /// personal one has two of each of these, not one shared pair.
    static let passwordStoreDirectoryKey = "signin.passwordstore.directory"
    static let passwordStoreUsernameFieldKey = "signin.passwordstore.username-field"

    /// Passbolt, both INSTANCE level: one server is one address plus one config
    /// file, and somebody with a company server and a personal one has two of
    /// each. Neither holds a secret — an address and a path.
    static let passboltServerKey = "signin.passbolt.server"
    static let passboltConfigFileKey = "signin.passbolt.config-file"
    static let keePassSecurityKeySlotKey = "signin.keepassfile.securitykey-slot"
    /// The master switch for the whole local scan. Default ON — the scan is
    /// filesystem-only, needs no macOS permission, and every sign-in source
    /// feature is inert without it. Off means SimpleVPN never looks for a password
    /// manager at all.
    static let discoveryEnabledKey = "signin.discovery.enabled"

    // MARK: Setting ids

    static func enabledSettingID(_ vendor: LocalVaultVendor) -> String {
        "creds.\(vendor.settingSlug).enabled"
    }
    /// The LEVEL-2 LIST control for a vendor that can have several vaults — the
    /// add/rename/remove/choose row. A real user-facing control, so it is a real
    /// spec with a real manual anchor, addressable by MDM and the CLI like every
    /// other. Only declared for a vendor whose cardinality is `.multiple`: a spec
    /// for a list that cannot have two entries in it would be a question with no
    /// answer.
    static func instanceListSettingID(_ vendor: LocalVaultVendor) -> String {
        "creds.\(vendor.settingSlug).\(vendor.instanceNounPlural)"
    }
    static let discoverySettingID = "creds.discovery"
    /// The two `.kdbx` controls that are not fields: a secret to type, and whether
    /// macOS should remember it. They are real user-facing controls, so per AGENTS.md
    /// they are real specs with real manual anchors — but neither is a path, and
    /// neither is stored where `VendorConfigField` stores things (one is nowhere at
    /// all, the other is a keychain item's existence).
    static let keePassPasswordSettingID = "creds.keepassfile.database-password"
    static let keePassRememberPasswordSettingID = "creds.keepassfile.remember-password"
    /// Passbolt's two, and the same shape for the same reason: a secret to type and
    /// whether macOS should remember it. Neither is stored where a `VendorConfigField`
    /// is stored — one is in memory, the other IS a keychain item's existence — which
    /// is exactly why neither can be a field.
    static let passboltPassphraseSettingID = "creds.passbolt.passphrase"
    static let passboltRememberPassphraseSettingID = "creds.passbolt.remember-passphrase"

    // MARK: Fields

    static func fields(for vendor: LocalVaultVendor) -> [VendorConfigField] {
        switch vendor {
        case .onePassword:
            // Nothing: 1Password is reached over its own SDK's signed IPC to the
            // running app. There is no socket to point at and no binary to find,
            // so there is no field to get wrong.
            []
        case .keePassXC:
            [VendorConfigField(
                settingID: "creds.keepassxc.socket",
                vendor: .keePassXC,
                ownerTitle: LocalVaultVendor.keePassXC.displayTitle,
                kind: .unixSocket,
                defaultsKey: keePassXCSocketKey,
                example: "/var/folders/\u{2026}/T/org.keepassxc.KeePassXC.BrowserServer")]
        case .keeper:
            [VendorConfigField(
                settingID: "creds.keeper.tool-path",
                vendor: .keeper,
                ownerTitle: LocalVaultVendor.keeper.displayTitle,
                kind: .toolBinary(tool: "keeper"),
                defaultsKey: toolPathKey("keeper"),
                example: "/opt/homebrew/bin/keeper")]
        case .bitwarden:
            // TWO fields, because Bitwarden genuinely has two ways in and they are
            // read by two different code paths: the binary (`BitwardenCLIClient
            // .locate`, through `LocalToolRunner`) and the local service's address
            // (`BitwardenSettings.configuredEndpoint`). Neither is a setting nothing
            // consults.
            [VendorConfigField(
                settingID: "creds.bitwarden.tool-path",
                vendor: .bitwarden,
                ownerTitle: LocalVaultVendor.bitwarden.displayTitle,
                kind: .toolBinary(tool: "bw"),
                defaultsKey: toolPathKey("bw"),
                example: "/opt/homebrew/bin/bw"),
             VendorConfigField(
                settingID: "creds.bitwarden.daemon-endpoint",
                vendor: .bitwarden,
                ownerTitle: LocalVaultVendor.bitwarden.displayTitle,
                kind: .daemonEndpoint,
                defaultsKey: bitwardenEndpointKey,
                // Bitwarden's own documented default for `bw serve`. An EXAMPLE,
                // shown as a placeholder — never as the value, so "not set" and
                // "set to the default" stay distinguishable — and also, honestly,
                // what SimpleVPN falls back to when the field is empty.
                example: LoopbackEndpoint.bitwardenDefault.settingValue,
                emptyMeansDefault: LoopbackEndpoint.bitwardenDefault.settingValue)]
        case .dashlane:
            // ONE row, and only one, because Dashlane has exactly one thing that can
            // be got wrong on this Mac: where `dcli` is. Everything else about
            // reaching Dashlane — which account, whether the master password is kept
            // in the keychain, whether a fingerprint is required, whether the vault
            // auto-syncs — is `dcli`'s OWN configuration, set with `dcli configure`
            // and stored in Dashlane's own database. Mirroring any of it here would
            // create a second place for the same fact to live, and the two would fall
            // out of step the first time somebody used Terminal.
            //
            // TRANSPORT LEVEL (level 1), and correctly so: it says how we reach the
            // vendor at all, not which vault we read. Dashlane has one vault per
            // signed-in Mac, so there is no level-2 field to declare.
            [VendorConfigField(
                settingID: "creds.dashlane.tool-path",
                vendor: .dashlane,
                ownerTitle: LocalVaultVendor.dashlane.displayTitle,
                kind: .toolBinary(tool: "dcli"),
                defaultsKey: toolPathKey("dcli"),
                example: "/opt/homebrew/bin/dcli")]
        case .keePassFile:
            // Three rows, in the order somebody sets them up: the database, then
            // the two things that some databases additionally need. No tool-path row
            // — `keepassxc-cli`'s is the standalone one below, because the tool is
            // KeePassXC's and is shared with that vendor's row rather than belonging
            // to a file format.
            [VendorConfigField(
                settingID: "creds.keepassfile.database",
                vendor: .keePassFile,
                ownerTitle: LocalVaultVendor.keePassFile.displayTitle,
                kind: .vaultFile(extensions: ["kdbx"]),
                defaultsKey: keePassDatabaseKey,
                example: "/Users/you/Documents/Passwords.kdbx"),
             VendorConfigField(
                settingID: "creds.keepassfile.key-file",
                vendor: .keePassFile,
                ownerTitle: LocalVaultVendor.keePassFile.displayTitle,
                kind: .keyFile,
                defaultsKey: keePassKeyFileKey,
                example: "/Users/you/Documents/Passwords.keyx"),
             VendorConfigField(
                settingID: "creds.keepassfile.security-key-slot",
                vendor: .keePassFile,
                ownerTitle: LocalVaultVendor.keePassFile.displayTitle,
                kind: .securityKeySlot,
                defaultsKey: keePassSecurityKeySlotKey,
                example: "2"),
             // The tool that does the opening. It belongs to THIS row rather than to
             // the KeePassXC row above, and `ToolCatalog` says the same: the
             // KeePassXC row talks to the running app over a socket and needs no
             // binary at all, while this row cannot work without one. Somebody whose
             // copy lives somewhere SimpleVPN won't run from needs a field to point
             // at it, and this is it.
             VendorConfigField(
                settingID: "creds.keepassfile.tool-path",
                vendor: .keePassFile,
                ownerTitle: LocalVaultVendor.keePassFile.displayTitle,
                kind: .toolBinary(tool: "keepassxc-cli"),
                defaultsKey: toolPathKey("keepassxc-cli"),
                example: "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli")]
        case .passwordStore:
            // Two instance-level rows and one transport-level row, and the split is
            // exactly the three-level model: WHICH store (and how its entries are
            // written) belongs to the store, while WHERE gpg lives belongs to the Mac.
            //
            // `gpg` and not `pass`: SimpleVPN decrypts the store itself, so the tool
            // that has to exist is GnuPG. A row pointing at `pass` would let somebody
            // carefully fix a path that is never used.
            [VendorConfigField(
                settingID: "creds.passwordstore.store-directory",
                vendor: .passwordStore,
                ownerTitle: LocalVaultVendor.passwordStore.displayTitle,
                kind: .storeDirectory,
                defaultsKey: passwordStoreDirectoryKey,
                example: "/Users/you/.password-store"),
             VendorConfigField(
                settingID: "creds.passwordstore.username-field",
                vendor: .passwordStore,
                ownerTitle: LocalVaultVendor.passwordStore.displayTitle,
                kind: .entryFieldName(suggestions: PasswordStoreEntry.conventionalUsernameKeys),
                defaultsKey: passwordStoreUsernameFieldKey,
                example: "login"),
             VendorConfigField(
                settingID: "creds.passwordstore.tool-path",
                vendor: .passwordStore,
                ownerTitle: LocalVaultVendor.passwordStore.displayTitle,
                kind: .toolBinary(tool: "gpg"),
                defaultsKey: toolPathKey("gpg"),
                example: "/opt/homebrew/bin/gpg")]
        case .lastPass:
            // ONE field, and only one, because there is exactly one thing about
            // LastPass that can be configured and read: where `lpass` is. It is
            // TRANSPORT level — how SimpleVPN reaches the one `lpass` on this Mac.
            //
            // What is deliberately NOT a field, and why: LastPass's cache directory.
            // It looks instance-shaped ("which vault"), but `lpass` keeps ONE
            // signed-in account, so the vendor is single-instance and a level-2 field
            // cannot exist for it — and putting a "which vault" question at level 1
            // would be exactly the conflation the three-level model exists to fix.
            // SimpleVPN therefore pins `LPASS_HOME` to the directory it probes
            // (`$HOME/.lpass`, which is what the tool itself resolves given a built
            // environment), so the files checked and the process run can never
            // disagree. Somebody who keeps their cache elsewhere is reported as not
            // signed in — a coherent state with a real fix, never a wrong-vault read.
            [VendorConfigField(
                settingID: "creds.lastpass.tool-path",
                vendor: .lastPass,
                ownerTitle: LocalVaultVendor.lastPass.displayTitle,
                kind: .toolBinary(tool: "lpass"),
                defaultsKey: toolPathKey("lpass"),
                example: "/opt/homebrew/bin/lpass")]
        case .protonPass:
            // ONE row, at level 1, and that is the whole configuration surface. Proton
            // Pass is single-instance (`SourceCardinality` — one session, no
            // `--config`), so there is no level-2 field to declare; which vault and
            // which item a VPN reads is level 3 and lives in the profile as the
            // `pass://` reference, which is not a settings field at all.
            //
            // `pass-cli`, and never `pass`: the tool name is what discovery searches
            // by, and a row here pointing at `pass` would let somebody carefully set
            // the path of the unix password store's tool and wonder why Proton Pass
            // still failed.
            [VendorConfigField(
                settingID: "creds.protonpass.tool-path",
                vendor: .protonPass,
                ownerTitle: LocalVaultVendor.protonPass.displayTitle,
                kind: .toolBinary(tool: ProtonPassCLIChannel.toolName),
                defaultsKey: toolPathKey(ProtonPassCLIChannel.toolName),
                // Proton's own installer prefers ~/.local/bin; the example names the
                // Homebrew tap's location because that is the command the banner shows.
                example: "/opt/homebrew/bin/pass-cli")]
        case .passbolt:
            // Two instance-level rows and one transport-level row, and the split is
            // exactly the three-level model: WHICH server (its address, and which of
            // Passbolt's own config files holds that server's key) belongs to the
            // server; WHERE the `passbolt` program lives belongs to the Mac.
            //
            // THERE IS DELIBERATELY NO PASSPHRASE ROW, AND NO "SKIP CERTIFICATE
            // CHECK" ROW. The first because SimpleVPN keeps no Passbolt secret —
            // Passbolt's own program owns the passphrase, in its own 0600 file. The
            // second because certificate verification is not a preference: the tool
            // has a flag for it, SimpleVPN never passes it, and a switch like that
            // ends up on across an estate.
            [VendorConfigField(
                settingID: "creds.passbolt.server",
                vendor: .passbolt,
                ownerTitle: LocalVaultVendor.passbolt.displayTitle,
                kind: .serverURL,
                defaultsKey: passboltServerKey,
                example: "https://passbolt.example.com"),
             VendorConfigField(
                settingID: "creds.passbolt.config-file",
                vendor: .passbolt,
                ownerTitle: LocalVaultVendor.passbolt.displayTitle,
                kind: .toolConfigFile,
                defaultsKey: passboltConfigFileKey,
                example: PassboltServerLocation.defaultConfigFile(),
                // Empty is a WORKING state, not a gap: with no `--config` the tool
                // reads its own default file, which is where `passbolt configure`
                // writes. Only somebody with a second server needs a second file.
                emptyMeansDefault: PassboltServerLocation.defaultConfigFile()),
             VendorConfigField(
                settingID: "creds.passbolt.tool-path",
                vendor: .passbolt,
                ownerTitle: LocalVaultVendor.passbolt.displayTitle,
                kind: .toolBinary(tool: "passbolt"),
                defaultsKey: toolPathKey("passbolt"),
                example: "/opt/homebrew/bin/passbolt")]
        }
    }

    /// Tool paths that belong to no password app. ONE place for "where is that
    /// tool", rather than a fresh mechanism per feed: the security-key feed already
    /// resolves `ykman` through `LocalToolRunner` and the same
    /// `signin.tool.ykman.path` key this row writes, so surfacing it here costs one
    /// declaration and saves a second settings surface.
    static let standaloneToolFields: [VendorConfigField] = [
        VendorConfigField(
            settingID: "creds.ykman.tool-path",
            vendor: nil,
            ownerTitle: "YubiKey Manager",
            kind: .toolBinary(tool: "ykman"),
            defaultsKey: toolPathKey("ykman"),
            example: "/opt/homebrew/bin/ykman"),
    ]

    static var allFields: [VendorConfigField] {
        LocalVaultVendor.allCases.flatMap { fields(for: $0) } + standaloneToolFields
    }

}

// MARK: - MDM

/// Organization policy for sign-in sources. Read from FORCED managed preferences
/// only (`objectIsForced`), the same mechanism `ManagedPolicy` uses, so a user's
/// own same-named local default is never mistaken for policy.
///
/// Keys (all optional; absent = the user is free):
///   `SignInSourcesAllowed`    — array of vendor slugs. Present ⇒ ONLY these.
///   `SignInSourcesForbidden`  — array of vendor slugs, always denied.
///   `SignInSourceToolPaths`   — dictionary of tool name → absolute path, pinned.
///   `DisableCredentialToolDiscovery` — Boolean; the local scan is switched off.
/// `LockConfiguration` (an existing `ManagedPolicy` key) additionally makes the
/// whole pane read-only.
nonisolated enum ManagedSignInSourcePolicy {

    static let allowedKey = "SignInSourcesAllowed"
    static let forbiddenKey = "SignInSourcesForbidden"
    static let pinnedPathsKey = "SignInSourceToolPaths"
    static let disableDiscoveryKey = "DisableCredentialToolDiscovery"

    /// Every key an administrator can force. The level-2 ones (pinned instance
    /// lists, and forbidding additions) are declared in SignInSourceInstances.swift
    /// beside the type they configure, and joined here so `isManaged` and the
    /// summary stay total.
    static let allKeys = [allowedKey, forbiddenKey, pinnedPathsKey, disableDiscoveryKey]
        + instancePolicyKeys

    private static func forcedArray(_ key: String, _ store: UserDefaults) -> [String]? {
        guard store.objectIsForced(forKey: key) else { return nil }
        return store.stringArray(forKey: key)
    }

    /// The allow-list, or nil when the administrator hasn't set one.
    static func allowed(_ store: UserDefaults = .standard) -> Set<LocalVaultVendor>? {
        guard let slugs = forcedArray(allowedKey, store) else { return nil }
        return Set(slugs.compactMap { LocalVaultVendor.vendor(withSlug: $0) })
    }

    static func forbidden(_ store: UserDefaults = .standard) -> Set<LocalVaultVendor> {
        Set((forcedArray(forbiddenKey, store) ?? []).compactMap { LocalVaultVendor.vendor(withSlug: $0) })
    }

    /// Tool paths pinned by policy. Only absolute paths are honoured — a relative
    /// one would be resolved by whatever the child process felt like, which is the
    /// exact thing the execution rules exist to prevent.
    static func pinnedPaths(_ store: UserDefaults = .standard) -> [String: String] {
        guard store.objectIsForced(forKey: pinnedPathsKey),
              let raw = store.dictionary(forKey: pinnedPathsKey) else { return [:] }
        var out: [String: String] = [:]
        for (tool, value) in raw {
            guard let path = value as? String, path.hasPrefix("/") else { continue }
            out[tool] = path
        }
        return out
    }

    static func discoveryForbidden(_ store: UserDefaults = .standard) -> Bool {
        store.objectIsForced(forKey: disableDiscoveryKey) && store.bool(forKey: disableDiscoveryKey)
    }

    /// A vendor's availability under policy, or nil when policy says nothing.
    /// Deliberately three-valued: "forced on" is different from "not mentioned",
    /// because a forced-on vendor's switch must be locked ON rather than merely
    /// left alone.
    static func decision(for vendor: LocalVaultVendor,
                         store: UserDefaults = .standard) -> Bool? {
        if forbidden(store).contains(vendor) { return false }
        if let allowed = allowed(store) { return allowed.contains(vendor) }
        return nil
    }

    static func isManaged(_ store: UserDefaults = .standard) -> Bool {
        allKeys.contains { store.objectIsForced(forKey: $0) }
    }

    /// Plain-language summary for the pane's "Managed by Your Organization"
    /// block. Says what is enforced, never a key name.
    static func activeSummary(_ store: UserDefaults = .standard) -> [String] {
        var out: [String] = []
        if let allowed = allowed(store) {
            out.append(allowed.isEmpty
                ? "No password apps may be used for signing in."
                : "Only these password apps may be used: "
                  + allowed.map(\.displayTitle).sorted().joined(separator: ", ") + ".")
        }
        let forbidden = forbidden(store)
        if !forbidden.isEmpty {
            out.append("These password apps aren\u{2019}t allowed: "
                       + forbidden.map(\.displayTitle).sorted().joined(separator: ", ") + ".")
        }
        for (tool, path) in pinnedPaths(store).sorted(by: { $0.key < $1.key }) {
            out.append("The path for \(ToolCatalog.tool(named: tool)?.title ?? tool) is set to \(path).")
        }
        if discoveryForbidden(store) {
            out.append("SimpleVPN doesn\u{2019}t look for password apps on this Mac.")
        }
        // Level 2: which vaults are set up for you, and whether you may add more.
        out += instanceSummary(store)
        return out
    }
}

// MARK: - Validation

/// What is true about a field's current value. Ordered from "nothing to say" to
/// "this will not work".
nonisolated enum VendorFieldValidation: Sendable, Equatable {
    /// Nothing set. `detected` is what SimpleVPN will use instead — which may be
    /// nothing at all, and saying so is the honest answer.
    case notSet(detected: String?)
    /// Nothing set, and there is nothing to detect — but the vendor documents a
    /// default, and that is what SimpleVPN will use. An endpoint is the case:
    /// `bw serve` listens on 127.0.0.1:8087 unless told otherwise, so "not set" is
    /// a working state rather than a gap, and saying "SimpleVPN hasn't found one"
    /// about an address nobody can find by looking would be nonsense.
    case notSetUsingDefault(String)
    /// Set and good, inside the locations SimpleVPN searches anyway.
    case ok
    /// Set, good, and OUTSIDE those locations. Not a problem: this is the
    /// sanctioned way to use a tool installed somewhere we don't search.
    case sanctioned
    case notAbsolute
    case missing
    case notExecutable
    /// Refused whatever the user says, and the one case where an explicit path is
    /// not enough.
    case unsafeDirectory
    case notASocket
    case badEndpoint
    /// A well-formed `host:port` that is NOT on this Mac. A fault, and one worth its
    /// own sentence: a local service with no authentication of its own must never be
    /// addressed across a network, and "use 127.0.0.1" is the whole fix.
    case notLoopback
    /// A path that points at a folder (or anything else that isn't a plain file)
    /// where a file is wanted. Its own case because "there's nothing there" and
    /// "that's a folder" send somebody to different places.
    case notAFile
    /// The file is there and it is not a KeePass database SimpleVPN can read. The
    /// sentence comes from the classifier, so this case carries it.
    case notAReadableDatabase(String)
    /// A security-key slot that isn't 1 or 2.
    case badSecurityKeySlot
    /// A well-formed address that is not one SimpleVPN will talk to. The clause
    /// says which of the four things is wrong (no address, not a web address, not
    /// https, credentials or a query in it) — see `PassboltServerLocation.validate`.
    case badServerAddress(String)
    /// The file is FINE and SimpleVPN will use it — but another account on this Mac
    /// can read it, and it holds a private key. NOT a fault: refusing to read
    /// somebody's own file because its permissions are loose would break a working
    /// setup to make a point. It is a statement, with the one command that fixes it.
    case readableByOthers

    /// Whether this state stops the field working. `sanctioned` and `notSet`
    /// don't — they are statements, not faults.
    var isProblem: Bool {
        switch self {
        // `readableByOthers` sits with the non-problems on purpose: the setting
        // works, and the sentence is advice rather than a correction.
        case .notSet, .notSetUsingDefault, .ok, .sanctioned, .readableByOthers: false
        case .notAbsolute, .missing, .notExecutable, .unsafeDirectory, .notASocket,
             .badEndpoint, .notLoopback, .notAFile, .notAReadableDatabase,
             .badSecurityKeySlot, .badServerAddress: true
        }
    }

    /// The sentence shown beside the field AND spoken as part of its value. One
    /// string for both, because a visible-only validation state is invisible to
    /// VoiceOver (Docs/Accessibility.md rule 5).
    var sentence: String {
        switch self {
        case .notSet(let detected):
            if let detected {
                "Not set. SimpleVPN uses the one it found: \(detected)"
            } else {
                "Not set, and SimpleVPN hasn\u{2019}t found one. Type a full path to use this."
            }
        case .notSetUsingDefault(let fallback):
            // "the usual one" rather than "the usual address": this case started as
            // a loopback endpoint and now also covers a vendor tool's own default
            // config file, and a sentence that names the WRONG kind of thing is
            // worse than a slightly vaguer one. The fallback itself is shown.
            "Not set, so SimpleVPN uses the usual one: \(fallback)"
        case .ok:
            "Ready to use."
        case .sanctioned:
            "SimpleVPN doesn\u{2019}t look in this folder on its own \u{2014} it will use this one "
            + "because you chose it."
        case .notAbsolute:
            "Problem: type the whole path, starting with a slash."
        case .missing:
            "Problem: there\u{2019}s nothing at that path."
        case .notExecutable:
            "Problem: that isn\u{2019}t a program SimpleVPN can run."
        case .unsafeDirectory:
            "Problem: anyone using this Mac can replace files in that folder, so SimpleVPN "
            + "won\u{2019}t run it. Move the program somewhere only you can write to."
        case .notASocket:
            "Problem: there\u{2019}s no connection point at that path. It appears while the app "
            + "is running."
        case .badEndpoint:
            "Problem: use the form host:port, for example 127.0.0.1:8087."
        case .notLoopback:
            "Problem: that address isn\u{2019}t on this Mac, and SimpleVPN only talks to this "
            + "one. Use 127.0.0.1 (or localhost) with the port the service is on."
        case .notAFile:
            "Problem: that\u{2019}s not a file. Pick the file itself, not the folder it is in."
        case .notAReadableDatabase(let why):
            "Problem: \(why)"
        case .badSecurityKeySlot:
            "Problem: a security key has two slots \u{2014} type 1 or 2, or leave this empty if your "
            + "database doesn\u{2019}t use one."
        case .badServerAddress(let why):
            "Problem: \(why). Use the address you open in your browser, starting with https."
        case .readableByOthers:
            // Advice, not a fault, and it names the command because "tighten the
            // permissions" is not something most people can act on.
            "Ready to use \u{2014} but other accounts on this Mac can read that file, and it holds "
            + "your private key. Run \u{201C}chmod 600\u{201D} on it to keep it to yourself."
        }
    }

    /// The label role the visible error announces — "Problem:" is already in the
    /// sentence for the faults, so this is the SF Symbol half only.
    var symbolName: String? {
        switch self {
        case .notSet, .notSetUsingDefault: nil
        case .ok: "checkmark.circle.fill"
        case .sanctioned: "hand.raised.circle.fill"
        // Its own symbol, because it is neither a tick nor a warning triangle: it
        // works, and there is something worth doing about it.
        case .readableByOthers: "eye.trianglebadge.exclamationmark.fill"
        case .notAbsolute, .missing, .notExecutable, .unsafeDirectory, .notASocket, .badEndpoint,
             .notLoopback, .notAFile, .notAReadableDatabase, .badSecurityKeySlot,
             .badServerAddress:
            "exclamationmark.triangle.fill"
        }
    }
}

// MARK: - Value versus suggestion — the landmine, made testable

/// EXACTLY what a field renders and what VoiceOver reads, derived once so no view
/// can get it wrong.
///
/// THE BUG THIS TYPE EXISTS TO PREVENT: `TextField("~/.bun/bin/bw", text: $x)`
/// passes the example as the field's TITLE. `LabeledContent` then renders titles
/// as visible content, so the example appears where the value goes and VoiceOver
/// announces it as the field's NAME. This project shipped that once, in 26 places.
/// A detected path makes it far worse than an example would: the user cannot tell
/// whether the path in front of them is a setting they made or a guess we made,
/// and "reset to detected" then has no meaning.
///
/// So the contract, and the tests assert every clause of it:
///   • `value` is what the binding holds. When nothing is set it is EMPTY. A
///     detected path is NEVER written into it.
///   • `prompt` is placeholder text — the detected path when there is one, else
///     the example. It renders grey and is not the value.
///   • the field's accessibility LABEL is always the setting's name (from its
///     spec), never the example and never the detected path.
///   • `accessibilityValue` states which of the two the user is looking at, in
///     words, because grey-versus-black is not available to a screen reader.
nonisolated struct VendorFieldPresentation: Sendable, Equatable {
    /// The committed value. Empty means nothing is set.
    var value: String
    /// Placeholder only. Never content.
    var prompt: String
    /// Spoken as the field's value.
    var accessibilityValue: String
    /// Whether the user has genuinely committed a value.
    var isSet: Bool
    /// What SimpleVPN would use right now — the set value, else the detection.
    var effectivePath: String?
    var validation: VendorFieldValidation
    /// Pinned by MDM: the value is policy's, and the row is read-only.
    var isLockedByPolicy: Bool

    /// Whether "Reset to Detected" can do anything: there is a detection, and it
    /// isn't already what the field holds.
    var canResetToDetected: Bool {
        guard !isLockedByPolicy, let detected = detectedPath else { return false }
        return value != detected
    }
    /// The detection behind the suggestion, kept so the reset button has something
    /// to write and the pane can show it as its own labelled row.
    var detectedPath: String?

    static func make(field: VendorConfigField,
                     setValue: String,
                     detected: String?,
                     pinned: String?,
                     validate: (String) -> VendorFieldValidation) -> VendorFieldPresentation {
        // Policy wins outright and is shown AS the value: pinning a path and then
        // displaying the user's stale one would be the silent-revert failure this
        // is meant to avoid.
        if let pinned {
            return VendorFieldPresentation(
                value: pinned,
                prompt: field.example,
                accessibilityValue: "\(pinned). Set by your organization. \(validate(pinned).sentence)",
                isSet: true,
                effectivePath: pinned,
                validation: validate(pinned),
                isLockedByPolicy: true,
                detectedPath: detected)
        }
        let trimmed = setValue.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            // Empty is a gap for a path (SimpleVPN uses what it found, or nothing)
            // and a WORKING STATE for a field the vendor documents a default for.
            // Both say which, in words, because a screen reader gets no other clue.
            let validation = field.emptyMeansDefault.map(VendorFieldValidation.notSetUsingDefault)
                ?? .notSet(detected: detected)
            return VendorFieldPresentation(
                value: "",
                // The suggestion lives HERE — in the placeholder — and nowhere
                // else. This is the whole distinction.
                prompt: detected ?? field.example,
                accessibilityValue: validation.sentence,
                isSet: false,
                effectivePath: detected ?? field.emptyMeansDefault,
                validation: validation,
                isLockedByPolicy: false,
                detectedPath: detected)
        }
        let validation = validate(trimmed)
        return VendorFieldPresentation(
            value: trimmed,
            prompt: field.example,
            accessibilityValue: "\(trimmed). \(validation.sentence)",
            isSet: true,
            effectivePath: trimmed,
            validation: validation,
            isLockedByPolicy: false,
            detectedPath: detected)
    }
}

// MARK: - The store

/// The live per-vendor configuration: reads and writes the defaults, applies MDM,
/// and answers validation from the discovery map.
///
/// `@Observable` so the pane redraws when a path is typed, and the chooser's
/// filtering follows an enable/disable without a restart.
@MainActor
@Observable
final class SignInSourceSettingsStore {

    static let shared = SignInSourceSettingsStore()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "sign-in-settings")

    private let store: UserDefaults
    /// Bumped on every write so `@Observable` readers (the pane's validation, the
    /// chooser's filter) recompute. The values themselves live in `UserDefaults`,
    /// which Observation cannot see into.
    private(set) var revision = 0

    /// LEVEL 2 — the named vaults, one or more per vendor (SignInSourceInstances
    /// .swift). A separate object because it is a separate level: this class owns
    /// "how we reach a vendor" (level 1) and the validation every level shares.
    let instanceStore: SourceInstanceStore

    init(store: UserDefaults = .standard) {
        self.store = store
        self.instanceStore = SourceInstanceStore(store: store)
        // The single-valued settings become instance #1, once. Done HERE rather
        // than lazily in a getter: a getter that writes defaults and bumps a
        // revision mid-render is how a SwiftUI update loop starts.
        instanceStore.migrateIfNeeded()
    }

    // MARK: The master switch

    /// Whether SimpleVPN looks for password managers on this Mac at all.
    ///
    /// DEFAULT ON, and the reason is worth stating: the scan is filesystem-only,
    /// needs no macOS permission, sends nothing anywhere and is what makes every
    /// sign-in source work — off, the feature is inert. Its results going into a
    /// SUBMITTED diagnostic report is a separate, per-submission opt-in.
    /// Off is nonetheless offered, and honoured absolutely: no scan, no vendor
    /// rows beyond the ones that need no detection, no inventory.
    var discoveryEnabled: Bool {
        _ = revision      // see `value(for:)` — Observation can't watch UserDefaults
        if ManagedSignInSourcePolicy.discoveryForbidden(store) { return false }
        return store.object(forKey: SignInSourceSettings.discoveryEnabledKey) as? Bool ?? true
    }

    var discoveryLockedByPolicy: Bool {
        ManagedSignInSourcePolicy.discoveryForbidden(store) || ManagedPolicy.lockConfiguration
    }

    func setDiscoveryEnabled(_ on: Bool) {
        guard !discoveryLockedByPolicy else { return }
        store.set(on, forKey: SignInSourceSettings.discoveryEnabledKey)
        ToolDiscovery.invalidateCache()
        revision += 1
    }

    // MARK: Enable / disable

    /// Whether this vendor may be used. Policy first, then the user's own choice,
    /// default on.
    func isEnabled(_ vendor: LocalVaultVendor) -> Bool {
        _ = revision      // see `value(for:)` — Observation can't watch UserDefaults
        if let forced = ManagedSignInSourcePolicy.decision(for: vendor, store: store) { return forced }
        return store.object(forKey: SignInSourceSettings.vendorEnabledKey(vendor)) as? Bool ?? true
    }

    /// Why this row can't be changed here, or nil when it can. The sentence goes
    /// to `.help` and to `accessibilityValue` together — a dead control that
    /// doesn't say why is the failure Docs/Accessibility.md rule 5 forbids.
    func lockReason(_ vendor: LocalVaultVendor) -> String? {
        if ManagedSignInSourcePolicy.decision(for: vendor, store: store) != nil {
            return "Your organization decides whether \(vendor.displayTitle) can be used."
        }
        if ManagedPolicy.lockConfiguration {
            return "Your organization has locked SimpleVPN\u{2019}s settings."
        }
        return nil
    }

    func setEnabled(_ on: Bool, for vendor: LocalVaultVendor) {
        guard lockReason(vendor) == nil else { return }
        store.set(on, forKey: SignInSourceSettings.vendorEnabledKey(vendor))
        revision += 1
    }

    /// Vendors that are switched off, in the shape `SignInSourceFacts` filters by.
    var disabledVendors: Set<LocalVaultVendor> {
        Set(LocalVaultVendor.allCases.filter { !isEnabled($0) })
    }

    // MARK: Field values

    func value(for field: VendorConfigField) -> String {
        // Touch `revision` so Observation registers a dependency. The values live in
        // `UserDefaults`, which Observation cannot see into — without this, typing a
        // path would update the field's own editing state and leave the validation
        // line, the reset button and the vendor's row showing the previous answer.
        _ = revision
        return store.string(forKey: field.defaultsKey) ?? ""
    }

    func pinnedValue(for field: VendorConfigField) -> String? {
        if let tool = field.kind.detectionTool,
           let pinned = ManagedSignInSourcePolicy.pinnedPaths(store)[tool] { return pinned }
        // A field an administrator has FORCED as a managed preference is policy's
        // too. This is the only way a non-path field can be pinned — the endpoint
        // row's case — and without it the pane would show the user's stale value
        // while SimpleVPN used the forced one, which is the silent-revert failure
        // this file exists to avoid.
        guard store.objectIsForced(forKey: field.defaultsKey),
              let forced = store.string(forKey: field.defaultsKey), !forced.isEmpty
        else { return nil }
        return forced
    }

    func setValue(_ raw: String, for field: VendorConfigField) {
        // A LEVEL-2 FIELD BELONGS TO ONE VAULT, never to the vendor as a whole, so a
        // write that names no vault lands on the default one (creating it if this is
        // the first database somebody has chosen) rather than on the old
        // single-valued key. Without this redirect a caller could write a path that
        // nothing reads — see SignInSourceInstances.swift.
        if field.level == .instance, field.vendor != nil {
            setValue(raw, for: field, instance: nil)
            return
        }
        guard pinnedValue(for: field) == nil, !ManagedPolicy.lockConfiguration else { return }
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            store.removeObject(forKey: field.defaultsKey)
        } else {
            store.set(trimmed, forKey: field.defaultsKey)
        }
        // The next validation must reflect what was just typed, not a cached scan.
        ToolDiscovery.invalidateCache()
        revision += 1
    }

    /// What discovery suggests for this field, or nil. Honours the master switch:
    /// with the scan off there is no suggestion to make, and pretending otherwise
    /// would be a scan by another name.
    func detected(for field: VendorConfigField) -> String? {
        guard discoveryEnabled else { return nil }
        switch field.kind {
        case .toolBinary(let tool):
            guard let entry = ToolDiscovery.cachedMap()[tool] else { return nil }
            return entry.suggestedPath
        case .unixSocket:
            return KeePassXCProtocol.discoverSocket()
        case .vaultFile, .keyFile:
            // DELIBERATELY NO GUESS. A `.kdbx` lives wherever its owner put it, and
            // sweeping the home directory for one would mean reading somebody's file
            // tree to find their password database — a search nobody asked for, to
            // produce a suggestion that is as likely to be the wrong database as the
            // right one. The field's placeholder shows the SHAPE of an answer instead.
            return nil
        case .storeDirectory:
            // ~/.password-store is `pass`'s own default and the overwhelmingly common
            // answer, so unlike a .kdbx there IS a sane suggestion — and offering it
            // reads no file tree: it is one fixed path, not a search.
            return PasswordStoreLocation.default().directory
        case .entryFieldName:
            // Not a path and not discoverable: which line holds a username is a fact
            // about how its owner writes their entries. The conventional names are
            // offered as suggestions in the field itself, not as a detected value.
            return nil
        case .serverURL:
            // NO GUESS, ever. There is nothing on this Mac that names somebody's
            // Passbolt server except the tool's own config file — and reading a
            // value out of that file to pre-fill a field would mean holding its
            // contents, which this source's whole design says we do not do. The
            // placeholder shows the SHAPE of an answer instead.
            return nil
        case .toolConfigFile:
            // The tool's own default file, but only when it is really there: a
            // suggestion pointing at a path that does not exist is worse than none,
            // because it reads as "SimpleVPN found this".
            let path = PassboltServerLocation.defaultConfigFile()
            var isDirectory: ObjCBool = false
            let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            return exists && !isDirectory.boolValue ? path : nil
        case .securityKeySlot, .daemonEndpoint, .pkcs11Module:
            return nil
        }
    }

    /// Write the detection into the field, so a user who has broken it can get
    /// back without editing text.
    func resetToDetected(_ field: VendorConfigField) {
        guard let detected = detected(for: field) else { return }
        setValue(detected, for: field)
    }

    /// Clear the field back to "let SimpleVPN decide".
    func clear(_ field: VendorConfigField) {
        setValue("", for: field)
    }

    // MARK: Validation

    func validate(_ raw: String, field: VendorConfigField) -> VendorFieldValidation {
        let path = raw.trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty else {
            // An endpoint cannot be "found" by looking at the filesystem, but the
            // vendor documents where its service listens, and that is what SimpleVPN
            // uses when this is empty (a test ties the field's declared default to
            // `BitwardenSettings.configuredEndpoint` so the two cannot drift).
            if let fallback = field.emptyMeansDefault { return .notSetUsingDefault(fallback) }
            return .notSet(detected: detected(for: field))
        }
        // An endpoint is `host:port`, not a path — it is checked before the
        // absolute-path rule rather than being told to start with a slash. Shape
        // first, then WHERE: a well-formed address somewhere else on the network is
        // a different mistake from a malformed one, and gets its own sentence.
        if case .daemonEndpoint = field.kind {
            guard let endpoint = LoopbackEndpoint(parsing: path) else { return .badEndpoint }
            return endpoint.isLoopback ? .ok : .notLoopback
        }
        // A SERVER'S ADDRESS is not a path either. Checked before the absolute-path
        // rule, and against the one definition in `PassboltServerLocation` so the
        // pane and the reader can never disagree about what SimpleVPN will talk to.
        if case .serverURL = field.kind {
            if let why = PassboltServerLocation.validate(path) { return .badServerAddress(why) }
            return .ok
        }
        // A slot number is not a path either, and telling somebody to start it with a
        // slash would be nonsense.
        if case .securityKeySlot = field.kind {
            guard let number = Int(path), YubiKeySlot(rawValue: number) != nil else {
                return .badSecurityKeySlot
            }
            return .ok
        }
        guard path.hasPrefix("/") else { return .notAbsolute }
        var st = stat()
        guard stat(path, &st) == 0 else {
            // A `.kdbx` in iCloud Drive that hasn't come down yet is NOT missing, and
            // it is the one "problem" here that fixes itself. Saying "there's nothing
            // at that path" would send somebody looking for a file that is fine.
            if case .vaultFile = field.kind,
               KeePassDatabaseFile.hasICloudPlaceholder(for: path) {
                return .notAReadableDatabase(
                    "that database hasn\u{2019}t been downloaded to this Mac yet. Open its folder in "
                    + "the Finder and wait for it to finish \u{2014} nothing else needs changing.")
            }
            return .missing
        }
        switch field.kind {
        case .unixSocket:
            return (st.st_mode & S_IFMT) == S_IFSOCK ? .ok : .notASocket
        case .daemonEndpoint, .securityKeySlot, .serverURL:
            return .ok               // handled above
        case .toolConfigFile:
            // A file, and one only its owner should be able to read: it holds an
            // OpenPGP private key and possibly its passphrase. Loose permissions do
            // NOT stop SimpleVPN using it — that would break a working setup to make
            // a point — but they earn a sentence with the fix in it.
            guard (st.st_mode & S_IFMT) == S_IFREG else { return .notAFile }
            return (st.st_mode & (S_IRGRP | S_IROTH)) != 0 ? .readableByOthers : .ok
        case .entryFieldName:
            return .ok               // free text; not a path, so nothing on disk to check
        case .storeDirectory:
            // A store must be a DIRECTORY containing `.gpg-id`. Both halves matter:
            // pointing at a file, and pointing at a folder that merely looks like a
            // store, fail in ways that would otherwise surface as a decryption error.
            guard (st.st_mode & S_IFMT) == S_IFDIR else { return .notAFile }
            let gpgID = (path as NSString).appendingPathComponent(".gpg-id")
            guard FileManager.default.fileExists(atPath: gpgID) else {
                return .notAReadableDatabase(
                    "that folder isn\u{2019}t a password store \u{2014} there\u{2019}s no .gpg-id "
                    + "file in it. Choose the folder that has one, usually ~/.password-store.")
            }
            return .ok
        case .vaultFile:
            // The one field in this pane whose CONTENTS are checked, because the four
            // ways a chosen file can be the wrong file all look identical from a
            // failed unlock. This reads the plaintext outer header only — no
            // decryption, no password, and a bounded prefix of the file.
            guard (st.st_mode & S_IFMT) == S_IFREG else { return .notAFile }
            switch KeePassDatabaseFile.classify(path: path) {
            case .readable:
                return .ok
            case .notDownloaded:
                return .notAReadableDatabase(
                    "that database hasn\u{2019}t been downloaded to this Mac yet. Open its folder in "
                    + "the Finder and wait for it to finish \u{2014} nothing else needs changing.")
            case .permissionDenied:
                // The app is not sandboxed and this STILL happens: macOS protects
                // Desktop, Documents, Downloads and iCloud Drive from every app and
                // asks once per app. Reported as its own sentence, because "there's
                // nothing there" would send somebody looking for a file that is fine.
                return .notAReadableDatabase(
                    "macOS won\u{2019}t let SimpleVPN read that file. Allow SimpleVPN in System "
                    + "Settings \u{25B8} Privacy & Security \u{25B8} Files and Folders, or keep your "
                    + "database somewhere macOS doesn\u{2019}t protect.")
            case .notADatabase(_, let reason):
                return .notAReadableDatabase(reason.sentence)
            case .tooNew(_, let version):
                return .notAReadableDatabase(
                    "that database is version \(version.displayName), which is newer than the "
                    + "KeePassXC on this Mac can read. Update KeePassXC.")
            case .missing:
                return .missing
            case .notConfigured:
                return .notSet(detected: nil)
            }
        case .keyFile:
            return (st.st_mode & S_IFMT) == S_IFREG ? .ok : .notAFile
        case .pkcs11Module:
            return (st.st_mode & S_IFMT) == S_IFREG ? .ok : .missing
        case .toolBinary:
            guard (st.st_mode & S_IFMT) == S_IFREG,
                  FileManager.default.isExecutableFile(atPath: path) else { return .notExecutable }
            // The one rule an explicit path cannot buy its way past.
            guard LocalToolRunner.isSafeExecutable(atPath: path) else { return .unsafeDirectory }
            let parent = (path as NSString).deletingLastPathComponent
            let searched = Set(LocalToolRunner.searchDirectories())
            return searched.contains(parent) ? .ok : .sanctioned
        }
    }

    /// Everything the pane needs for one field, in one value.
    func presentation(for field: VendorConfigField) -> VendorFieldPresentation {
        VendorFieldPresentation.make(
            field: field,
            setValue: value(for: field),
            detected: detected(for: field),
            pinned: pinnedValue(for: field),
            validate: { self.validate($0, field: field) })
    }

}
