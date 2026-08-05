// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialSourceSettingDescriptors.swift
//  The `creds.*` setting catalog: the sign-in-source pane's controls, declared the
//  same way every engine's options are, so they get the same treatment for free —
//  app-wide search finds them, the manual has a section per id, the help button
//  beside each row lands somewhere real, and MDM and the CLI can address them.
//
//  WHY THESE ARE SPECS AND NOT JUST SWITCHES IN A VIEW. AGENTS.md is explicit:
//  every user-facing control gets a spec, including the ones that look like
//  plumbing. An unspec'd control is invisible to SettingsSearch, unaddressable by
//  the CLI and MDM, and has no manual anchor behind its help button. "Which
//  password managers may SimpleVPN use, and where are their tools" is exactly the
//  kind of setting someone will go looking for by name.
//
//  THE CATALOG IS GENERATED, not hand-listed: one enabled switch per
//  `LocalVaultVendor`, plus whatever fields that vendor declares in
//  `SignInSourceSettings.fields(for:)`. So adding a vendor adds its settings
//  automatically — and `ManualAnchorParityTests` then FAILS until the manual has a
//  section for each, which is the pressure that keeps documentation from lagging a
//  release behind.
//
//  Group: every one of these is **Sign-In** in the canonical taxonomy. They are
//  about how you identify yourself, which is that group's definition.
//

import Foundation

@MainActor
enum CredentialSourceSettings {

    /// The master switch for the local scan.
    static let discovery = EngineSettingSpec(
        id: SignInSourceSettings.discoverySettingID,
        name: "Look for password apps on this Mac",
        summary: "Lets SimpleVPN find the password apps and command-line tools you already have, so it "
            + "can offer them and tell you where they are. It only reads this Mac \u{2014} nothing is "
            + "sent anywhere, and nothing is installed or changed. Off means SimpleVPN never looks.",
        group: .signIn,
        default: true)

    /// One switch per vendor, in the vendor enum's order.
    static let vendorSwitches: [EngineSettingSpec] = LocalVaultVendor.allCases.map { vendor in
        EngineSettingSpec(
            id: SignInSourceSettings.enabledSettingID(vendor),
            name: "Use \(vendor.displayTitle)",
            summary: "Offer \(vendor.displayTitle) as a way to sign in to your VPNs. Off means "
                + "SimpleVPN neither offers it nor mentions it \u{2014} even if it is installed.",
            group: .signIn,
            default: true)
    }

    /// THE LEVEL-2 LIST, for a vendor that can genuinely have several vaults.
    /// Declared per vendor from `SourceCardinality`, so a singular vendor never
    /// grows a list control it has no use for — and so the multi-instance vendor's
    /// list is searchable, documented and MDM-addressable like everything else.
    static let instanceLists: [EngineSettingSpec] = LocalVaultVendor.allCases
        .filter { $0.cardinality.allowsSeveral }
        .map { vendor in
            EngineSettingSpec(
                id: SignInSourceSettings.instanceListSettingID(vendor),
                name: "Your \(vendor.displayTitle) \(vendor.instanceNounPlural)",
                summary: "The \(vendor.instanceNounPlural) SimpleVPN can read, each with a name you "
                    + "choose. Set up as many as you like \u{2014} a work one and a personal one, say "
                    + "\u{2014} then pick which one a VPN uses when you set its sign-in up. Each is "
                    + "checked on its own, so one being away doesn\u{2019}t stop the others working.",
                group: .signIn,
                default: "")
        }

    /// One row per declared per-vendor field. The names and summaries live here
    /// rather than in `VendorConfigField` so all setting copy is reviewable in one
    /// place, next to every other engine's.
    static let fieldSpecs: [EngineSettingSpec] = SignInSourceSettings.allFields.map { field in
        switch field.kind {
        case .toolBinary(let tool):
            EngineSettingSpec(
                id: field.settingID,
                name: "\(ToolCatalog.tool(named: tool)?.title ?? tool) location",
                summary: "Where \(vendorTitle(field)) \u{2019}s command-line tool is on this Mac. Leave "
                    + "it empty and SimpleVPN uses the one it found. Set it when your copy is somewhere "
                    + "SimpleVPN doesn\u{2019}t look on its own \u{2014} that is what this is for.",
                group: .signIn,
                default: "")
        case .storeDirectory:
            EngineSettingSpec(
                id: field.settingID,
                name: "Password store folder",
                summary: "The folder holding your password store \u{2014} usually ~/.password-store. "
                    + "SimpleVPN reads one entry out of it when you connect, and never writes to it. "
                    + "A store has a .gpg-id file in it; if the folder you pick doesn\u{2019}t, "
                    + "SimpleVPN will say so rather than fail later with a decryption error.",
                group: .signIn,
                default: "")
        case .entryFieldName(let suggestions):
            EngineSettingSpec(
                id: field.settingID,
                name: "Username line in an entry",
                summary: "Which line of an entry holds the username. By convention it is one of "
                    + suggestions.joined(separator: ", ")
                    + " \u{2014} SimpleVPN tries those in order, so leave this empty unless you use a "
                    + "different name. This is a convention rather than part of the format, which is "
                    + "why it is yours to set.",
                group: .signIn,
                default: "")
        case .unixSocket:
            EngineSettingSpec(
                id: field.settingID,
                name: "\(vendorTitle(field)) connection point",
                summary: "The connection \(vendorTitle(field)) opens while it is running, which "
                    + "SimpleVPN talks to. Leave it empty and SimpleVPN finds it. Set it only if you "
                    + "have moved it.",
                group: .signIn,
                default: "")
        case .daemonEndpoint:
            EngineSettingSpec(
                id: field.settingID,
                name: "\(vendorTitle(field)) local service address",
                summary: "The address and port of \(vendorTitle(field))\u{2019}s own local service on "
                    + "this Mac, in the form host:port.",
                group: .signIn,
                default: "")
        case .vaultFile:
            EngineSettingSpec(
                id: field.settingID,
                name: "KeePass database file",
                summary: "The KeePass database (.kdbx) SimpleVPN reads your sign-in out of. The same "
                    + "file whichever app looks after it \u{2014} KeePassXC, Strongbox or KeePassium. "
                    + "SimpleVPN only ever reads it.",
                group: .signIn,
                default: "")
        case .keyFile:
            EngineSettingSpec(
                id: field.settingID,
                name: "KeePass key file",
                summary: "The key file your database needs as well as its password, if it has one. "
                    + "Leave it empty when it hasn\u{2019}t.",
                group: .signIn,
                default: "")
        case .securityKeySlot:
            EngineSettingSpec(
                id: field.settingID,
                name: "KeePass security key slot",
                summary: "Which slot on your security key answers for this database \u{2014} 1 or 2. "
                    + "Leave it empty when your database doesn\u{2019}t use a security key.",
                group: .signIn,
                default: "")
        case .pkcs11Module:
            EngineSettingSpec(
                id: field.settingID,
                name: "\(vendorTitle(field)) security module",
                summary: "The security module (PKCS#11) SimpleVPN should load for "
                    + "\(vendorTitle(field)).",
                group: .signIn,
                default: "")
        }
    }

    private static func vendorTitle(_ field: VendorConfigField) -> String {
        field.ownerTitle
    }

    /// Controls a vendor needs that are NOT paths, and so are not
    /// `VendorConfigField`s. Declared per vendor, spliced in after that vendor's
    /// fields, so the pane, app-wide search, the manual-anchor gate and MDM all see
    /// them exactly as they see everything else.
    ///
    /// The `.kdbx` row is the first to need any: a database password (a secret to
    /// type, kept nowhere by default) and whether macOS should remember it behind
    /// Touch ID. Neither lives in `UserDefaults` — the password lives in memory or
    /// in the keychain, and the toggle IS the keychain item's existence — which is
    /// exactly why they cannot be fields.
    static func extraSpecs(for vendor: LocalVaultVendor) -> [EngineSettingSpec] {
        switch vendor {
        // A password store needs no extra spec: GnuPG owns the passphrase entirely, so
        // there is nothing for SimpleVPN to hold, prompt for, or remember behind Touch
        // ID — which is the whole reason this source has no secret of its own.
        // Dashlane needs none either, and for the same reason as a password store: the
        // Dashlane password goes to Dashlane's own tool, which keeps what it needs in
        // this Mac's keychain and decides for itself whether to ask for a fingerprint.
        // There is nothing here for SimpleVPN to hold or prompt for.
        case .onePassword, .keePassXC, .keeper, .bitwarden, .dashlane, .passwordStore:
            []
        case .keePassFile:
            [EngineSettingSpec(
                id: SignInSourceSettings.keePassPasswordSettingID,
                name: "KeePass database password",
                summary: "The password that opens your KeePass database. SimpleVPN keeps it only until "
                    + "it quits, unless you ask macOS to remember it. It is never written to a "
                    + "settings file and never appears in a log.",
                group: .signIn,
                default: ""),
             EngineSettingSpec(
                id: SignInSourceSettings.keePassRememberPasswordSettingID,
                name: "Remember the database password with Touch ID",
                summary: "Lets macOS keep your database password and release it only when you give a "
                    + "fingerprint, your Apple Watch, or this Mac\u{2019}s password. Off means you type "
                    + "it once each time you open SimpleVPN.",
                group: .signIn,
                default: false)]
        }
    }

    /// Declaration order: the master switch, then each vendor's switch followed by
    /// its own fields — the order the pane renders, so search results and the
    /// screen agree.
    static let catalog: EngineSettingCatalog = {
        var specs: [EngineSettingSpec] = [discovery]
        let fieldsByID = Dictionary(fieldSpecs.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for vendor in LocalVaultVendor.allCases {
            if let toggle = vendorSwitches.first(where: {
                $0.id == SignInSourceSettings.enabledSettingID(vendor)
            }) {
                specs.append(toggle)
            }
            // Level 1 first (how SimpleVPN reaches this vendor at all), then the
            // level-2 list, then the fields ONE of those vaults holds — the order
            // somebody sets it up in, and the order the pane renders.
            for field in SignInSourceSettings.transportFields(for: vendor) {
                if let spec = fieldsByID[field.settingID] { specs.append(spec) }
            }
            if let list = instanceLists.first(where: {
                $0.id == SignInSourceSettings.instanceListSettingID(vendor)
            }) {
                specs.append(list)
            }
            for field in SignInSourceSettings.instanceFields(for: vendor) {
                if let spec = fieldsByID[field.settingID] { specs.append(spec) }
            }
            specs += extraSpecs(for: vendor)
        }
        // Tool paths belonging to no password app (ykman) come last, in their own
        // section on screen.
        for field in SignInSourceSettings.standaloneToolFields {
            if let spec = fieldsByID[field.settingID] { specs.append(spec) }
        }
        return EngineSettingCatalog(specs)
    }()

    static var all: [EngineSettingSpec] { catalog.all }

    /// The vendor a `creds.*` id belongs to, when one does. Used to open the pane
    /// scrolled to the right vendor from a chooser row's "Configure…".
    static func vendor(forSettingID id: String) -> LocalVaultVendor? {
        LocalVaultVendor.allCases.first { vendor in
            id == SignInSourceSettings.enabledSettingID(vendor)
                || id == SignInSourceSettings.instanceListSettingID(vendor)
                || SignInSourceSettings.fields(for: vendor).contains { $0.settingID == id }
                || extraSpecs(for: vendor).contains { $0.id == id }
        }
    }
}
