// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceInstances.swift
//  THE THREE LEVELS OF SIGN-IN CONFIGURATION, as three named types rather than
//  three conventions. The distinction is the user's own:
//
//      "we need to be careful to separate configuring talking to the auth source
//       in general, and then selecting the auth source and entry per vpn"
//
//   1. TRANSPORT — `SourceTransportConfig`. How SimpleVPN reaches a vendor AT ALL:
//      a binary path, a socket, a loopback endpoint, and the vendor's own on/off
//      switch. Per Mac, exactly ONE per vendor, because there is one `bw` on this
//      Mac and one KeePassXC browser socket in this login session. Lives in the
//      app's settings.
//
//   2. SOURCE INSTANCE — `SourceInstance`. WHICH thing we talk to: which `.kdbx`
//      file, with its key file and its security-key slot. Per Mac, one OR MORE per
//      vendor, because a person legitimately has a work database and a personal
//      one. Each instance is separately named, separately configured, separately
//      probed, and separately reported.
//
//   3. PER-VPN SELECTION — `SignInSourceSelection`. Which INSTANCE plus which
//      ENTRY inside it, and nothing else. Stored in the profile, and never a
//      secret — the level-3 carrier on disk is `CredentialSource`, whose blob a
//      test greps for exactly that reason.
//
//  THE CONFLATION THIS FIXES. Level 2 used to sit in level 1's single-valued app
//  defaults (`signin.keepassfile.database`, one key file, one slot). That is right
//  for exactly one database and wrong the moment somebody has two — and level 3
//  stored `{kind, reference, account}` with no instance id, so a profile could not
//  say WHICH database it meant. Both are now expressible, and the migration below
//  turns the old shape into instance #1 without losing anything.
//
//  WHY VENDORS DECLARE CARDINALITY (`SourceCardinality`). Forcing an instance list
//  on a genuinely singular vendor is as wrong as hard-coding singularity where a
//  vendor allows several: the first gives somebody a list with one meaningless row
//  in it, the second is the bug being fixed here. So each vendor states which it
//  is, with its reason, in `LocalVaultVendor.cardinality`.
//
//  NOTHING HERE IS A SECRET. An instance holds paths, a slot number and a name.
//  The database password is not an instance field and never will be — it lives in
//  memory or the Touch ID keychain (KeePassUnlock.swift), never in `UserDefaults`
//  and never in a profile.
//

import Foundation
import os

// MARK: - Level 1 / 2 / 3, named

/// WHICH LEVEL a setting belongs to. The rule that decides it is short: anything
/// that identifies *how we reach a vendor* is `.transport`, anything that
/// identifies *which vault* is `.instance`, anything that identifies *which entry*
/// is `.perVPN`.
nonisolated enum SignInConfigLevel: String, Sendable, CaseIterable, Equatable {
    /// Level 1 — per Mac, one per vendor. App settings.
    case transport
    /// Level 2 — per Mac, one or more per vendor. App settings.
    case instance
    /// Level 3 — per VPN. The profile.
    case perVPN

    /// The section heading for this level, in the settings pane and the chooser.
    var title: String {
        switch self {
        case .transport: "How SimpleVPN reaches it"
        case .instance: "Which one SimpleVPN reads"
        case .perVPN: "What this VPN uses"
        }
    }

    /// One plain sentence saying what belongs here, so a person can tell why a
    /// field is on one screen rather than another.
    var summary: String {
        switch self {
        case .transport:
            "Set once for this Mac: where the program is, and how SimpleVPN talks to it."
        case .instance:
            "You can set up more than one, and give each a name. Each is checked on its own."
        case .perVPN:
            "Chosen per VPN: which one to read, and which entry inside it."
        }
    }
}

/// How many level-2 instances a vendor can have. Declared per vendor, with a
/// reason, in `LocalVaultVendor.cardinality`.
nonisolated enum SourceCardinality: String, Sendable, Equatable {
    /// Exactly one thing to talk to, so there is no list and no instance id worth
    /// storing. Level 1 is the whole configuration.
    case single
    /// One or more, each separately named, configured and probed.
    case multiple

    var allowsSeveral: Bool { self == .multiple }
}

nonisolated extension LocalVaultVendor {

    /// WHETHER THIS VENDOR CAN HAVE SEVERAL INSTANCES — decided per vendor, from
    /// what the vendor actually allows through the channel SimpleVPN uses:
    ///
    ///  • `.onePassword` — MULTIPLE, and this one was `.single` until the distinction
    ///    between an ACCOUNT and a VAULT was drawn properly. The old reasoning was
    ///    that accounts and vaults "are 1Password's own namespace and are already
    ///    addressed PER VPN", and half of that was right: a VAULT is *scope*, it is
    ///    not configured at all, and `Docs/Onboarding.md` says why (we ride
    ///    1Password's own search rather than enumerating, which is what keeps the
    ///    first run prompt-free). An ACCOUNT is not scope. It is *which 1Password we
    ///    are talking to at all*, a person can have a personal one and a work tenant
    ///    signed in at the same moment, and — decisively — it CANNOT BE DISCOVERED:
    ///    the desktop integration rejects an account it can't match, the empty string
    ///    included, and nothing in the SDK hands out a list of the ones the app is
    ///    signed into. So it is a thing the user tells us, once per account, app-wide,
    ///    which is the definition of a level-2 connection.
    ///
    ///    It was already stored app-wide, as one string, by `OnePasswordAccountMemory`
    ///    — a hand-rolled singleton connection sitting beside the general mechanism
    ///    built for exactly this. Sharing that defaults key is what makes migration
    ///    free: the remembered account becomes connection #1.
    ///  • `.keePassXC` — SINGLE. One running app, one browser-integration socket
    ///    per login session (level 1). The app decides which of its open databases
    ///    matches an entry; SimpleVPN never names one.
    ///  • `.keeper` — SINGLE. Keeper Commander keeps one configuration and one
    ///    persistent-login session on this Mac, and SimpleVPN passes no `--config`
    ///    (see KeeperProvider — Keeper's own documentation warns that sharing a
    ///    config revokes sessions). So there is one Commander to talk to.
    ///  • `.bitwarden` — SINGLE. `bw` has one signed-in account and one data
    ///    directory at a time, and `bw serve` is one loopback address (level 1).
    ///  • `.dashlane` — SINGLE, and this one is settled by reading `dcli` rather than
    ///    by preference. It keeps ONE SQLite database, at a path with no variable in
    ///    it (`~/Library/Application Support/dashlane-cli/userdata.db`, built from
    ///    `HOME` in `src/modules/database/connect.ts`); `dcli status` reads its device
    ///    row as `SELECT * FROM device LIMIT 1`; the local key is one OS-keychain
    ///    entry under the service name `dashlane-cli`; and no command in
    ///    `src/commands` takes a `--config`, `--profile` or `--account` option. So
    ///    there is exactly one signed-in Dashlane account to talk to on this Mac —
    ///    the same shape as `bw`. Forcing an instance list on it would produce a page
    ///    of rows with nothing in them, and Dashlane's own spaces (personal versus a
    ///    business space) are addressed inside the vault, i.e. at level 3.
    ///  • `.keePassFile` — MULTIPLE, and it is the case that named the problem: a
    ///    `.kdbx` is a FILE, with its own key file and its own security-key slot,
    ///    and "work" and "personal" databases are entirely ordinary.
    ///  • `.lastPass` — SINGLE, and verified rather than assumed. `lpass` keeps ONE
    ///    signed-in account per configuration directory: `agent_save` writes a single
    ///    `username` value (`agent.c`), `cmd_status` reads that one value back, and
    ///    `login` overwrites it — so there is no shape in which two LastPass accounts
    ///    are signed in at once. A second account would mean a second `LPASS_HOME`,
    ///    and SimpleVPN pins that to the directory it probes so the tool it runs and
    ///    the files it looked at can never disagree (see LastPassProvider). Same
    ///    answer as Bitwarden's, for the same structural reason.
    ///  • `.protonPass` — SINGLE, and the reason is a fact about the tool rather than
    ///    a simplification. `pass-cli` holds ONE session: one session file
    ///    (`<data dir>/proton-pass-cli/.session/session.json`), one signed-in account,
    ///    and no `--config`, `--account` or `--profile` flag anywhere in its command
    ///    surface — `pass-cli logout` is how you change accounts. A Proton account CAN
    ///    hold several vaults, and a person may have a work one and a personal one,
    ///    but a vault is named INSIDE the item reference (`pass://Work/GR Lab`), which
    ///    is level 3 where it belongs. An instance list here would be a list of rows
    ///    with no fields in them — exactly the mistake `SourceCardinality` exists to
    ///    prevent, in the other direction from `.keePassFile`'s.
    var cardinality: SourceCardinality {
        switch self {
        case .keePassXC, .keeper, .bitwarden, .dashlane, .lastPass, .protonPass:
            .single
        // MULTIPLE, for the same reason as a .kdbx and then some: PASSWORD_STORE_DIR
        // exists precisely so one person can keep several stores, and "work" and
        // "personal" stores are entirely ordinary. Each also carries its own username
        // field convention, so they are configured separately, not just located.
        // MULTIPLE, and the first one that is not a file: a Passbolt instance is a
        // SERVER. `go-passbolt-cli`'s own config holds exactly ONE serverAddress,
        // one key and one passphrase (internal/cmd/root.go), so a second server
        // needs a second config file and `--config` — which is precisely a
        // per-instance setting, not a per-Mac one. A company Passbolt and a
        // self-hosted personal one, with different keys, is entirely ordinary.
        // MULTIPLE, and the only one whose instance is neither a file nor a server but
        // an ACCOUNT — see the note above.
        case .keePassFile, .passwordStore, .passbolt, .onePassword: .multiple
        }
    }

    /// What one instance IS, in a sentence's worth of words ("database"). Used in
    /// every button, heading and spoken label, so a multi-instance vendor never
    /// says the word "instance" at a user.
    var instanceNoun: String {
        switch self {
        case .keePassFile: "database"
        case .passwordStore: "store"
        // Not "vault" and not "instance": what somebody sets up here IS a server,
        // that is the word Passbolt itself uses, and calling it a vault would hide
        // the one fact that matters — it is somewhere else, over a network.
        case .passbolt: "server"
        // NOT "vault", and the difference is the whole point of 1Password being
        // `.multiple`: what somebody sets up here is an ACCOUNT — the thing named at
        // the top of 1Password's sidebar — and calling it a vault would ask them for
        // the wrong string. Their vaults are inside it, and SimpleVPN does not ask
        // about those at all.
        case .onePassword: "account"
        case .keePassXC, .keeper, .bitwarden, .dashlane, .lastPass, .protonPass:
            "vault"
        }
    }

    var instanceNounPlural: String {
        switch self {
        case .keePassFile: "databases"
        case .passwordStore: "stores"
        case .passbolt: "servers"
        case .onePassword: "accounts"
        case .keePassXC, .keeper, .bitwarden, .dashlane, .lastPass, .protonPass:
            "vaults"
        }
    }

    /// Title case, for a section heading ("Your Databases").
    var instanceSectionTitle: String { "Your \(instanceNounPlural.capitalized)" }

    /// What removing an instance does NOT touch, in the vendor's own terms. It
    /// used to be one sentence about "the file", which was true of every
    /// multi-instance vendor until one of them stopped being a file: telling
    /// somebody their SERVER "is left exactly as it is" reads as though SimpleVPN
    /// could have changed a server, which is a much worse implication than the
    /// vagueness it was avoiding.
    var instanceRemovalReassurance: String {
        switch self {
        case .keePassFile: "the file itself is left exactly as it is"
        case .passwordStore: "the folder itself is left exactly as it is"
        case .passbolt:
            "nothing on the server changes, and Passbolt\u{2019}s own setup is left alone"
        // Says ACCOUNT, and says the one thing somebody removing it will worry about:
        // SimpleVPN is forgetting a name it was told, not signing anybody out.
        case .onePassword:
            "nothing in 1Password changes and you stay signed in to it"
        case .keePassXC, .keeper, .bitwarden, .dashlane, .lastPass, .protonPass:
            "nothing in the vault itself changes"
        }
    }
}

// MARK: - An instance's identity

/// A STABLE, OPAQUE id for one level-2 instance.
///
/// Deliberately NOT a path. A path is not an identity: moving a database, renaming
/// it, or having it arrive on a different volume changes the path while the vault
/// is the same vault — and a profile keyed on the path would then silently point at
/// nothing (or, worse, at whatever else now sits there). So the id is generated
/// once, stored, and never derived from anything the user can change.
nonisolated struct SourceInstanceID: Hashable, Sendable, Codable, Identifiable {
    let rawValue: String
    var id: String { rawValue }

    init(rawValue: String) { self.rawValue = rawValue }

    /// A fresh id. Lowercase hex-and-dashes only, so it is safe inside a defaults
    /// key and inside an accessibility identifier.
    static func fresh() -> SourceInstanceID {
        SourceInstanceID(rawValue: UUID().uuidString.lowercased())
    }

    init(from decoder: any Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }
    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// An id is well-formed when it can appear in a defaults key without changing
    /// its meaning: no dots (the key separator), no whitespace, not empty.
    var isWellFormed: Bool {
        !rawValue.isEmpty && !rawValue.contains(".")
            && !rawValue.contains(where: \.isWhitespace)
    }
}

/// LEVEL 2 — one configured thing SimpleVPN can read: which `.kdbx`, with its key
/// file and its slot. Named by the user, identified by an opaque id, and holding
/// nothing secret.
nonisolated struct SourceInstance: Identifiable, Sendable, Equatable {
    var id: SourceInstanceID
    var vendor: LocalVaultVendor
    /// What the user calls it ("Work", "Personal"). Never empty — `named(_:)` falls
    /// back rather than shipping a nameless row.
    var name: String
    /// The instance-level field values, keyed by `VendorConfigField.instanceKey`
    /// ("database", "key-file", "security-key-slot"). Paths and a slot number: no
    /// secrets, ever.
    var values: [String: String] = [:]

    func value(for field: VendorConfigField) -> String {
        values[field.instanceKey] ?? ""
    }

    /// The name, guaranteed to be something a person can read.
    static func displayName(_ raw: String, vendor: LocalVaultVendor, index: Int) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "\(vendor.instanceNoun.capitalized) \(index + 1)" : trimmed
    }
}

/// The persisted form of the instance LIST: id and name only. The values live in
/// their own defaults keys, one per (instance, field), so everything the existing
/// per-field machinery does — MDM pinning through `objectIsForced`, validation,
/// the value-versus-suggestion rule — keeps working per instance with no second
/// mechanism.
nonisolated struct SourceInstanceRecord: Codable, Sendable, Equatable {
    var id: SourceInstanceID
    var name: String
}

// MARK: - Level 1, as a value

/// LEVEL 1 — everything about reaching ONE vendor on THIS Mac. A value rather than
/// a screenful of scattered reads, so "what is this Mac's Bitwarden setup" is one
/// thing that can be printed, tested and reported.
nonisolated struct SourceTransportConfig: Sendable, Equatable {
    var vendor: LocalVaultVendor
    /// The vendor's own switch — level 1, because it says whether we talk to this
    /// vendor at all.
    var isEnabled: Bool
    /// The level-1 fields and what they are set to. Paths and endpoints; never a
    /// secret.
    var values: [String: String] = [:]

    var level: SignInConfigLevel { .transport }
}

// MARK: - Level 3, as a value

/// LEVEL 3 — what ONE VPN's profile says about signing in: which source, which
/// instance of it, which entry, and optionally which login inside that entry.
///
/// NO SECRETS, and that is structural rather than remembered: there is no field
/// here one could be put in. `CredentialSource` is the on-disk carrier (it also
/// holds 1Password's vault and field map, which are that vendor's own level-3
/// details); this is the three-level view of it.
nonisolated struct SignInSourceSelection: Sendable, Equatable {
    var kind: CredentialSourceKind = .manual
    /// WHICH instance. nil means "the one SimpleVPN set up" — the default instance,
    /// which after migration is the database the single-valued settings named. It
    /// is not "any of them": see `SourceInstanceResolution`.
    var instance: SourceInstanceID?
    /// WHICH entry inside it. A name, a path, a UID or an address, per vendor.
    var entry: String = ""
    /// Which login, when one entry could serve several. Optional everywhere.
    var account: String = ""

    var level: SignInConfigLevel { .perVPN }
}

nonisolated extension CredentialSource {
    /// The three-level view of this profile's stored source.
    var selection: SignInSourceSelection {
        get {
            SignInSourceSelection(
                kind: kind,
                instance: instanceID.isEmpty ? nil : SourceInstanceID(rawValue: instanceID),
                entry: reference,
                account: account)
        }
        set {
            kind = newValue.kind
            instanceID = newValue.instance?.rawValue ?? ""
            reference = newValue.entry
            account = newValue.account
        }
    }
}

// MARK: - Where a field sits

nonisolated extension VendorConfigFieldKind {
    /// WHICH LEVEL this kind of field belongs to, derived once here rather than
    /// decided per declaration: a socket, a binary and an endpoint are all "how we
    /// reach the vendor", while a vault file, its key file and its slot are all
    /// "which vault". A new field kind has to answer this, because the switch is
    /// exhaustive.
    var level: SignInConfigLevel {
        switch self {
        case .toolBinary, .unixSocket, .daemonEndpoint, .pkcs11Module: .transport
        // A store's directory and the field name to read inside its entries are both
        // "which vault, and how it is laid out" — the same level as a .kdbx path,
        // and both legitimately differ between a work store and a personal one.
        //
        // A SERVER'S ADDRESS is level 2 for the same reason and it is worth being
        // explicit, because "an address" sounds transport-shaped: the address is
        // WHICH Passbolt, not how SimpleVPN reaches Passbolt at all — the latter is
        // the `passbolt` binary, which is one per Mac. And a vendor tool's own
        // config FILE is level 2 whenever it holds one server's sign-in setup,
        // which `go-passbolt-cli`'s does: two servers means two files.
        //
        // AN ACCOUNT IDENTIFIER is level 2 as well, and it is the case that forced
        // the distinction to be stated rather than assumed: it sounds
        // transport-shaped ("how do we reach 1Password?") and is not. There is one
        // 1Password app on this Mac and one signed IPC channel to it — that is
        // level 1, and it has no fields at all. WHICH ACCOUNT is which sign-in of the
        // user's we are asking, and a person may have a personal one and a work
        // tenant signed in at once.
        case .vaultFile, .keyFile, .securityKeySlot, .storeDirectory, .entryFieldName,
             .serverURL, .toolConfigFile, .accountIdentifier: .instance
        }
    }
}

nonisolated extension VendorConfigField {
    var level: SignInConfigLevel { kind.level }

    /// The short, stable key this field's value is stored under INSIDE an instance
    /// — the last component of the setting id (`creds.keepassfile.database` →
    /// `database`). Part of the on-disk contract, like the setting id itself.
    var instanceKey: String {
        settingID.split(separator: ".").last.map(String.init) ?? settingID
    }
}

// MARK: - Storage keys

nonisolated extension SignInSourceSettings {

    /// The instance LIST for a vendor. Its presence is also what says migration
    /// has already run for that vendor.
    static func instanceListKey(_ vendor: LocalVaultVendor) -> String {
        "signin.instances.\(vendor.settingSlug)"
    }

    /// One instance's one field. Deliberately per-field rather than a blob, so MDM
    /// pinning, validation and the value-versus-suggestion presentation all work
    /// per instance through the machinery that already exists.
    static func instanceValueKey(_ vendor: LocalVaultVendor,
                                 _ instance: SourceInstanceID,
                                 _ field: VendorConfigField) -> String {
        "signin.instance.\(vendor.settingSlug).\(instance.rawValue).\(field.instanceKey)"
    }

    /// The level-1 fields for a vendor.
    static func transportFields(for vendor: LocalVaultVendor) -> [VendorConfigField] {
        fields(for: vendor).filter { $0.level == .transport }
    }

    /// The level-2 fields for a vendor — the ones an instance holds a value for.
    static func instanceFields(for vendor: LocalVaultVendor) -> [VendorConfigField] {
        fields(for: vendor).filter { $0.level == .instance }
    }
}

// MARK: - Migration: the single-valued shape becomes instance #1

/// Turning the OLD on-disk shape into the new one, as pure functions so the whole
/// thing is testable from a fixture of what is really on disk today.
///
/// LOSSLESS, and in one direction only: the legacy keys are READ and left exactly
/// where they are. Deleting them would throw away the one thing an administrator's
/// existing MDM payload pins (`signin.keepassfile.database`), and a downgrade to
/// the previous build would then find nothing.
nonisolated enum SourceInstanceMigration {

    /// The instances implied by the legacy single-valued settings for a vendor:
    /// one instance when anything was set, none when nothing was.
    ///
    /// `legacy` is keyed by the field's `instanceKey`, which is exactly what the
    /// caller reads out of the legacy defaults keys.
    static func migrate(vendor: LocalVaultVendor,
                        legacy: [String: String],
                        id: SourceInstanceID = .fresh()) -> [SourceInstance] {
        let values = legacy.compactMapValues { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty ? nil : trimmed
        }
        guard !values.isEmpty else { return [] }
        return [SourceInstance(id: id, vendor: vendor,
                              name: defaultName(vendor: vendor, values: values),
                              values: values)]
    }

    /// A NAME somebody will recognise, taken from the file they chose rather than
    /// invented: "Passwords.kdbx" becomes "Passwords". A path is not a name, so the
    /// directory is dropped; a vendor with no file-shaped field falls back to its
    /// own title.
    static func defaultName(vendor: LocalVaultVendor, values: [String: String]) -> String {
        for field in SignInSourceSettings.instanceFields(for: vendor) {
            guard case .vaultFile = field.kind,
                  let path = values[field.instanceKey], !path.isEmpty else { continue }
            let base = (path as NSString).lastPathComponent
            let stem = (base as NSString).deletingPathExtension
            if !stem.isEmpty { return stem }
        }
        return vendor.displayTitle
    }

    /// The name to offer for a NEW instance: the vendor's noun and the next number,
    /// so adding one is never blocked on thinking of a name.
    static func suggestedName(vendor: LocalVaultVendor, existing: [SourceInstance]) -> String {
        var index = existing.count + 1
        let taken = Set(existing.map { $0.name.lowercased() })
        while taken.contains("\(vendor.instanceNoun) \(index)".lowercased()) { index += 1 }
        return "\(vendor.instanceNoun.capitalized) \(index)"
    }
}

/// What a profile's instance id resolves to. Four answers, and the two unhappy
/// ones are separate because they are different sentences with different fixes —
/// and because "pick another one for them" is exactly the silent-wrong-vault
/// behaviour this whole change exists to prevent.
nonisolated enum SourceInstanceResolution: Sendable, Equatable {
    /// A single-instance vendor: level 1 is the whole answer, there is nothing to
    /// choose and nothing to get wrong.
    case sole
    /// This is the one.
    case resolved(SourceInstance)
    /// A multi-instance vendor with nothing set up yet. An enablement state: one
    /// file picker away from working.
    case noneConfigured
    /// The profile names an instance that is not there any more (removed, or a
    /// profile copied from another Mac). NOT silently replaced.
    case chosenIsGone(SourceInstanceID)

    var instance: SourceInstance? {
        if case .resolved(let instance) = self { return instance }
        return nil
    }

    var isUsable: Bool {
        switch self {
        case .sole, .resolved: true
        case .noneConfigured, .chosenIsGone: false
        }
    }
}

nonisolated extension SourceInstanceResolution {

    /// The sentence shown and spoken. Names the vendor's own noun, never the word
    /// "instance".
    func sentence(vendor: LocalVaultVendor) -> String {
        switch self {
        case .sole:
            "SimpleVPN talks to \(vendor.displayTitle) itself \u{2014} there is only one."
        case .resolved(let instance):
            "Using \u{201C}\(instance.name)\u{201D}."
        case .noneConfigured:
            "No \(vendor.instanceNoun) is set up yet. Choose one in Settings \u{25B8} "
            + "Sign-In Sources."
        case .chosenIsGone:
            "The \(vendor.instanceNoun) this VPN used isn\u{2019}t set up any more. Choose "
            + "which one to use."
        }
    }
}

nonisolated enum SourceInstanceResolver {

    /// WHICH instance a selection means. The rules, in order, and each one is a
    /// decision:
    ///
    ///  1. A single-instance vendor is `.sole`. There is nothing to name.
    ///  2. Nothing configured is `.noneConfigured` — "choose a database", not a
    ///     crash and not a guess.
    ///  3. A named instance that exists wins.
    ///  4. A named instance that does NOT exist is `.chosenIsGone`. It is never
    ///     quietly replaced by another one: reading the wrong person's vault
    ///     because a list changed order is the worst outcome available here.
    ///  5. No name at all means the DEFAULT instance — the first in the list, which
    ///     is the one migration created out of the old single-valued settings. That
    ///     is what makes every existing profile keep working without being
    ///     rewritten, and adding a second database later appends rather than
    ///     displacing it.
    static func resolve(_ selection: SignInSourceSelection,
                        vendor: LocalVaultVendor,
                        instances: [SourceInstance]) -> SourceInstanceResolution {
        guard vendor.cardinality.allowsSeveral else { return .sole }
        guard !instances.isEmpty else { return .noneConfigured }
        guard let wanted = selection.instance else {
            return .resolved(instances[0])
        }
        guard let found = instances.first(where: { $0.id == wanted }) else {
            return .chosenIsGone(wanted)
        }
        return .resolved(found)
    }

    /// The same, given only an id — for the settings pane and the availability
    /// gatherer, which have no profile in hand.
    static func resolve(id: SourceInstanceID?, vendor: LocalVaultVendor,
                        instances: [SourceInstance]) -> SourceInstanceResolution {
        resolve(SignInSourceSelection(kind: .manual, instance: id), vendor: vendor,
                instances: instances)
    }
}

// MARK: - The store for level 2

/// The live instance lists: read, written, migrated, and MDM-pinned.
///
/// Its own object rather than more methods on `SignInSourceSettingsStore`, because
/// the three levels are three things — and because that store's own job (level 1
/// plus validation) was already right and did not need rewriting.
@MainActor
@Observable
final class SourceInstanceStore {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "sign-in-settings")

    private let store: UserDefaults

    /// Bumped on every change, so `@Observable` readers recompute — the values live
    /// in `UserDefaults`, which Observation cannot see into. Same device as
    /// `SignInSourceSettingsStore.revision`, for the same reason.
    private(set) var revision = 0

    init(store: UserDefaults) {
        self.store = store
    }

    // MARK: Reading

    /// Every instance for a vendor, in a STABLE order — the first is the default,
    /// and migration's instance is always first, which is what keeps existing
    /// profiles pointing where they always pointed.
    func instances(for vendor: LocalVaultVendor) -> [SourceInstance] {
        _ = revision
        guard vendor.cardinality.allowsSeveral else { return [] }
        if let pinned = ManagedSignInSourcePolicy.pinnedInstances(vendor, store) { return pinned }
        return records(for: vendor).enumerated().map { index, record in
            SourceInstance(id: record.id, vendor: vendor,
                           name: SourceInstance.displayName(record.name, vendor: vendor,
                                                            index: index),
                           values: values(vendor: vendor, instance: record.id))
        }
    }

    /// The default instance: the first, or nil when nothing is set up.
    func defaultInstance(for vendor: LocalVaultVendor) -> SourceInstance? {
        instances(for: vendor).first
    }

    func instance(_ id: SourceInstanceID?, for vendor: LocalVaultVendor) -> SourceInstance? {
        let all = instances(for: vendor)
        guard let id else { return all.first }
        return all.first { $0.id == id }
    }

    func resolve(_ id: SourceInstanceID?, for vendor: LocalVaultVendor)
        -> SourceInstanceResolution {
        SourceInstanceResolver.resolve(id: id, vendor: vendor,
                                      instances: instances(for: vendor))
    }

    func resolve(_ selection: SignInSourceSelection, for vendor: LocalVaultVendor)
        -> SourceInstanceResolution {
        SourceInstanceResolver.resolve(selection, vendor: vendor,
                                      instances: instances(for: vendor))
    }

    /// One instance's one field, as stored. Never a suggestion — that is
    /// `VendorFieldPresentation`'s job.
    func value(vendor: LocalVaultVendor, instance: SourceInstanceID,
               field: VendorConfigField) -> String {
        _ = revision
        if let pinned = pinnedValue(vendor: vendor, instance: instance, field: field) {
            return pinned
        }
        return store.string(forKey: SignInSourceSettings.instanceValueKey(vendor, instance, field))
            ?? ""
    }

    /// A value an administrator has pinned for this instance's field.
    ///
    /// TWO shapes are honoured, and the second is what keeps existing payloads
    /// working: the per-instance key, and — for the DEFAULT instance only — the
    /// legacy single-valued key an administrator may already be forcing
    /// (`signin.keepassfile.database`). Level 1's `pinnedPaths` covers tool paths;
    /// this covers level 2.
    func pinnedValue(vendor: LocalVaultVendor, instance: SourceInstanceID,
                     field: VendorConfigField) -> String? {
        let key = SignInSourceSettings.instanceValueKey(vendor, instance, field)
        if store.objectIsForced(forKey: key), let forced = store.string(forKey: key),
           !forced.isEmpty {
            return forced
        }
        if ManagedSignInSourcePolicy.pinnedInstances(vendor, store) != nil {
            // The whole list is policy's, so its values are too — and they are not
            // in defaults at all.
            return instances(for: vendor).first { $0.id == instance }?.values[field.instanceKey]
        }
        guard records(for: vendor).first?.id == instance,
              store.objectIsForced(forKey: field.defaultsKey),
              let legacy = store.string(forKey: field.defaultsKey), !legacy.isEmpty
        else { return nil }
        return legacy
    }

    private func values(vendor: LocalVaultVendor,
                        instance: SourceInstanceID) -> [String: String] {
        var out: [String: String] = [:]
        for field in SignInSourceSettings.instanceFields(for: vendor) {
            let key = SignInSourceSettings.instanceValueKey(vendor, instance, field)
            if let pinned = pinnedValue(vendor: vendor, instance: instance, field: field) {
                out[field.instanceKey] = pinned
            } else if let value = store.string(forKey: key), !value.isEmpty {
                out[field.instanceKey] = value
            }
        }
        return out
    }

    // MARK: Writing

    /// Whether the user may add another, and why not when they may not. MDM can
    /// forbid it outright — a managed Mac's list of vaults may be exactly the list
    /// the administrator shipped.
    func addLockReason(_ vendor: LocalVaultVendor) -> String? {
        guard vendor.cardinality.allowsSeveral else {
            return "There is only one \(vendor.instanceNoun) to set up for "
                + "\(vendor.displayTitle)."
        }
        if ManagedSignInSourcePolicy.pinnedInstances(vendor, store) != nil {
            return "Your organization decides which \(vendor.instanceNounPlural) SimpleVPN uses."
        }
        if ManagedSignInSourcePolicy.addingInstancesForbidden(store) {
            return "Your organization doesn\u{2019}t allow adding \(vendor.instanceNounPlural)."
        }
        if ManagedPolicy.lockConfiguration {
            return "Your organization has locked SimpleVPN\u{2019}s settings."
        }
        return nil
    }

    /// Whether this list can be changed at all (rename, remove, or edit a field).
    func editLockReason(_ vendor: LocalVaultVendor) -> String? {
        if ManagedSignInSourcePolicy.pinnedInstances(vendor, store) != nil {
            return "Your organization decides which \(vendor.instanceNounPlural) SimpleVPN uses."
        }
        if ManagedPolicy.lockConfiguration {
            return "Your organization has locked SimpleVPN\u{2019}s settings."
        }
        return nil
    }

    /// Add one, named. Returns nil when policy forbids it — the caller shows
    /// `addLockReason` rather than a control that does nothing.
    @discardableResult
    func add(named rawName: String, for vendor: LocalVaultVendor) -> SourceInstance? {
        guard addLockReason(vendor) == nil else { return nil }
        var list = records(for: vendor)
        let id = SourceInstanceID.fresh()
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? SourceInstanceMigration.suggestedName(vendor: vendor,
                                                    existing: instances(for: vendor))
            : rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        list.append(SourceInstanceRecord(id: id, name: name))
        write(list, for: vendor)
        Self.log.log("added a sign-in source instance for \(vendor.rawValue, privacy: .public)")
        return SourceInstance(id: id, vendor: vendor, name: name)
    }

    func rename(_ id: SourceInstanceID, to rawName: String, for vendor: LocalVaultVendor) {
        guard editLockReason(vendor) == nil else { return }
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        var list = records(for: vendor)
        guard let index = list.firstIndex(where: { $0.id == id }) else { return }
        list[index].name = name
        write(list, for: vendor)
    }

    /// Remove one, and its values with it. The CALLER is responsible for warning
    /// about the VPNs that still name it — see `SignInSourceSteps.removalWarning`.
    func remove(_ id: SourceInstanceID, for vendor: LocalVaultVendor) {
        guard editLockReason(vendor) == nil else { return }
        var list = records(for: vendor)
        guard let index = list.firstIndex(where: { $0.id == id }) else { return }
        list.remove(at: index)
        for field in SignInSourceSettings.instanceFields(for: vendor) {
            store.removeObject(forKey: SignInSourceSettings.instanceValueKey(vendor, id, field))
        }
        write(list, for: vendor)
    }

    func setValue(_ raw: String, vendor: LocalVaultVendor, instance: SourceInstanceID,
                  field: VendorConfigField) {
        guard editLockReason(vendor) == nil,
              pinnedValue(vendor: vendor, instance: instance, field: field) == nil else { return }
        let key = SignInSourceSettings.instanceValueKey(vendor, instance, field)
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            store.removeObject(forKey: key)
        } else {
            store.set(trimmed, forKey: key)
        }
        revision += 1
    }

    /// The instance a level-2 write lands on when the caller has not named one:
    /// the default, created if the list is empty. That is what makes "point
    /// SimpleVPN at my database" work for somebody who has never seen an instance
    /// list — the first database they choose IS the first instance.
    func instanceForImplicitWrite(_ vendor: LocalVaultVendor) -> SourceInstance? {
        if let existing = defaultInstance(for: vendor) { return existing }
        return add(named: "", for: vendor)
    }

    // MARK: Migration

    /// Turn the legacy single-valued settings into instance #1, once per vendor.
    ///
    /// Called from `SignInSourceSettingsStore.init` — deliberately not lazily from
    /// a getter, because a getter that writes defaults and bumps a revision while a
    /// view is rendering is how a SwiftUI update loop starts.
    func migrateIfNeeded() {
        for vendor in LocalVaultVendor.allCases where vendor.cardinality.allowsSeveral {
            let listKey = SignInSourceSettings.instanceListKey(vendor)
            guard store.object(forKey: listKey) == nil else { continue }
            var legacy: [String: String] = [:]
            for field in SignInSourceSettings.instanceFields(for: vendor) {
                if let value = store.string(forKey: field.defaultsKey) {
                    legacy[field.instanceKey] = value
                }
            }
            let migrated = SourceInstanceMigration.migrate(vendor: vendor, legacy: legacy)
            for instance in migrated {
                for field in SignInSourceSettings.instanceFields(for: vendor) {
                    guard let value = instance.values[field.instanceKey] else { continue }
                    store.set(value, forKey: SignInSourceSettings.instanceValueKey(
                        vendor, instance.id, field))
                }
            }
            // Written even when it is empty: the key's presence is what says this
            // vendor has been migrated, so a Mac with nothing configured does not
            // re-scan the legacy keys on every launch (and does not resurrect a
            // value the user has since cleared).
            write(migrated.map { SourceInstanceRecord(id: $0.id, name: $0.name) }, for: vendor)
            if !migrated.isEmpty {
                Self.log.log("""
                    migrated \(vendor.rawValue, privacy: .public) settings into \
                    \(migrated.count, privacy: .public) named \
                    \(vendor.instanceNounPlural, privacy: .public)
                    """)
            }
        }
    }

    // MARK: The list, on disk

    private func records(for vendor: LocalVaultVendor) -> [SourceInstanceRecord] {
        guard let data = store.data(forKey: SignInSourceSettings.instanceListKey(vendor)),
              let list = try? JSONDecoder().decode([SourceInstanceRecord].self, from: data)
        else { return [] }
        // Anything malformed is dropped rather than allowed to name a defaults key.
        return list.filter { $0.id.isWellFormed }
    }

    private func write(_ list: [SourceInstanceRecord], for vendor: LocalVaultVendor) {
        guard let data = try? JSONEncoder().encode(list) else { return }
        store.set(data, forKey: SignInSourceSettings.instanceListKey(vendor))
        revision += 1
    }
}

// MARK: - The settings store, per level

extension SignInSourceSettingsStore {

    /// LEVEL 1 for one vendor, as a value.
    func transportConfig(for vendor: LocalVaultVendor) -> SourceTransportConfig {
        var values: [String: String] = [:]
        for field in SignInSourceSettings.transportFields(for: vendor) {
            let shown = presentation(for: field)
            if let effective = shown.effectivePath { values[field.instanceKey] = effective }
        }
        return SourceTransportConfig(vendor: vendor, isEnabled: isEnabled(vendor), values: values)
    }

    /// LEVEL 2 for one vendor.
    func instances(for vendor: LocalVaultVendor) -> [SourceInstance] {
        instanceStore.instances(for: vendor)
    }

    func instance(_ id: SourceInstanceID?, for vendor: LocalVaultVendor) -> SourceInstance? {
        instanceStore.instance(id, for: vendor)
    }

    /// What one instance's field renders as — the same value-versus-suggestion
    /// contract as a level-1 field, per instance, so the landmine cannot come back
    /// through this door.
    ///
    /// With no instance named, a level-2 field falls back to reading its LEGACY
    /// single-valued key. That is the honest answer for the one moment it can happen:
    /// before migration has run there is no instance to name, and the value on disk
    /// is exactly where that read looks.
    func presentation(for field: VendorConfigField,
                      instance: SourceInstance?) -> VendorFieldPresentation {
        guard field.level == .instance, let vendor = field.vendor, let instance else {
            return presentation(for: field)
        }
        return VendorFieldPresentation.make(
            field: field,
            setValue: instanceStore.value(vendor: vendor, instance: instance.id, field: field),
            // No guesses at level 2, ever: finding somebody's password database
            // would mean reading their file tree to work out where they keep their
            // passwords, and a guess is as likely to be the wrong vault as the
            // right one.
            detected: nil,
            pinned: instanceStore.pinnedValue(vendor: vendor, instance: instance.id, field: field),
            validate: { self.validate($0, field: field) })
    }

    func setValue(_ raw: String, for field: VendorConfigField, instance: SourceInstance?) {
        guard field.level == .instance, let vendor = field.vendor else {
            setValue(raw, for: field)
            return
        }
        guard let target = instance ?? instanceStore.instanceForImplicitWrite(vendor) else { return }
        instanceStore.setValue(raw, vendor: vendor, instance: target.id, field: field)
    }
}

// MARK: - MDM at level 2

nonisolated extension ManagedSignInSourcePolicy {

    /// `SignInSourceForbidAddingInstances` — Boolean. The user may use what is
    /// there and may not add more.
    static let forbidAddingInstancesKey = "SignInSourceForbidAddingInstances"
    /// `SignInSourceInstances` — dictionary of vendor slug → array of
    /// `{ name, <field key>: <value>, … }`. Present for a vendor ⇒ THAT vendor's
    /// list is policy's: read-only, and nothing may be added to it.
    static let pinnedInstancesKey = "SignInSourceInstances"

    static let instancePolicyKeys = [forbidAddingInstancesKey, pinnedInstancesKey]

    static func addingInstancesForbidden(_ store: UserDefaults = .standard) -> Bool {
        store.objectIsForced(forKey: forbidAddingInstancesKey)
            && store.bool(forKey: forbidAddingInstancesKey)
    }

    /// The instances an administrator has pinned for a vendor, or nil when policy
    /// says nothing about it.
    ///
    /// The id is DERIVED from the administrator's ordering (`managed-1`, …) rather
    /// than generated, so it is the same id on every Mac in the fleet — which is
    /// what lets one profile, shipped to everybody, name the same vault everywhere.
    static func pinnedInstances(_ vendor: LocalVaultVendor,
                                _ store: UserDefaults = .standard) -> [SourceInstance]? {
        guard store.objectIsForced(forKey: pinnedInstancesKey),
              let raw = store.dictionary(forKey: pinnedInstancesKey),
              let list = raw[vendor.settingSlug] as? [[String: Any]] else { return nil }
        let fieldKeys = Set(SignInSourceSettings.instanceFields(for: vendor).map(\.instanceKey))
        return list.enumerated().map { index, entry in
            var values: [String: String] = [:]
            for (key, value) in entry where fieldKeys.contains(key) {
                if let string = value as? String, !string.isEmpty { values[key] = string }
            }
            let name = (entry["name"] as? String) ?? ""
            return SourceInstance(
                id: SourceInstanceID(rawValue: "managed-\(index + 1)"),
                vendor: vendor,
                name: SourceInstance.displayName(name, vendor: vendor, index: index),
                values: values)
        }
    }

    /// The level-2 half of the "Managed by Your Organization" block, in plain
    /// language and never a key name.
    static func instanceSummary(_ store: UserDefaults = .standard) -> [String] {
        var out: [String] = []
        for vendor in LocalVaultVendor.allCases {
            guard let pinned = pinnedInstances(vendor, store) else { continue }
            out.append(pinned.isEmpty
                ? "No \(vendor.instanceNounPlural) are set up for \(vendor.displayTitle)."
                : "The \(vendor.instanceNounPlural) for \(vendor.displayTitle) are set for you: "
                  + pinned.map(\.name).joined(separator: ", ") + ".")
        }
        if addingInstancesForbidden(store) {
            out.append("You can\u{2019}t add more places for SimpleVPN to read a sign-in from.")
        }
        return out
    }
}

// MARK: - The two-step reading, as copy

/// The words the per-VPN chooser uses to make "which vault, then which entry" a
/// TWO-STEP question rather than one flat list — and the warning shown before an
/// instance some VPNs still use is removed.
///
/// Copy rather than a view, so the step numbering, the spoken labels and the
/// warning are testable with nothing on screen. Glossary: "sign in" / "sign-in",
/// never "credential", never "instance".
nonisolated enum SignInSourceSteps {

    static let count = 2

    /// "Step 1 of 2" — which one of the vendor's vaults.
    static func stepOneTitle(vendor: LocalVaultVendor) -> String {
        "Step 1 of \(count): which \(vendor.instanceNoun)"
    }

    static func stepOneSummary(vendor: LocalVaultVendor) -> String {
        "You can set up more than one \(vendor.instanceNoun) in Settings \u{25B8} Sign-In "
        + "Sources. This VPN reads the one you pick here."
    }

    /// "Step 2 of 2" — which entry inside the one just picked. Names it, so the two
    /// steps read as one sentence rather than two unrelated fields.
    static func stepTwoTitle(vendor: LocalVaultVendor, instanceName: String?) -> String {
        guard let instanceName, !instanceName.isEmpty else {
            return "Step 2 of \(count): which entry"
        }
        return "Step 2 of \(count): which entry in \u{201C}\(instanceName)\u{201D}"
    }

    static func stepTwoSummary(vendor: LocalVaultVendor) -> String {
        switch vendor {
        case .keePassFile:
            "An entry\u{2019}s path is its groups and its title, separated by slashes "
            + "\u{2014} for example VPN/Work."
        case .passwordStore:
            // Names the layout, because a store's entry name IS its path inside the
            // folder — the same shape as a .kdbx entry path, but arrived at from a
            // filesystem rather than from groups, and worth saying so once.
            "An entry\u{2019}s name is its path inside the store, without the .gpg "
            + "\u{2014} for example vpn/work."
        case .dashlane:
            // Names the two shapes Dashlane's own filters take, because "any entry whose
            // address or title matches" is a genuinely different rule from the exact-name
            // matching every other vendor here uses, and someone who does not know that
            // will wonder why two entries matched.
            "Dashlane matches an entry\u{2019}s address or its title \u{2014} for example "
            + "vpn.example.com, or title=My VPN to be exact."
        case .lastPass:
            // The name has to match EXACTLY — SimpleVPN passes neither of the tool's
            // loose-matching options, because a substring match can read a different
            // entry. So the sentence has to say "including its folders", or somebody will
            // type "GR Lab" for an entry that lives in Work/VPN.
            "An entry\u{2019}s name has to match exactly, including its folders \u{2014} for "
            + "example Work/VPN/GR Lab. Its numeric id works too."
        case .protonPass:
            // Says BOTH halves, because Proton Pass addresses a vault and an item in
            // one string and a bare title is refused rather than guessed at.
            "An item is named by its vault and its title, separated by a slash "
            + "\u{2014} for example Work/GR Lab. Proton\u{2019}s own identifiers work too."
        case .passbolt:
            // States the trade-off in the one place somebody is choosing, exactly as
            // the kdbx row states it for entry paths: the identifier is stable and
            // never ambiguous, the name is readable and neither.
            "Paste the resource\u{2019}s identifier \u{2014} the long code in the web address when "
            + "you open it in Passbolt. That never changes when somebody renames or moves it. A "
            + "name works too, but only while it stays unique and unchanged."
        case .onePassword, .keePassXC, .keeper, .bitwarden:
            "Which entry SimpleVPN reads this VPN\u{2019}s sign-in from."
        }
    }

    /// Spoken as the step's own value, so a VoiceOver user hears WHICH step they
    /// are on and what it is waiting for — the visual numbering is not available to
    /// them.
    static func spokenStep(_ step: Int, of vendor: LocalVaultVendor,
                           chosen: String?) -> String {
        let what = step == 1 ? vendor.instanceNoun : "entry"
        guard let chosen, !chosen.isEmpty else {
            return "Step \(step) of \(count). No \(what) chosen yet."
        }
        return "Step \(step) of \(count). \(chosen)."
    }

    /// The warning before removing one. NAMES the VPNs that still use it: a
    /// silently orphaned profile fails at connect time, days later, with no clue
    /// that a setting somewhere else caused it.
    static func removalWarning(vendor: LocalVaultVendor, name: String,
                               usedBy profiles: [String]) -> String {
        let head = "Remove \u{201C}\(name)\u{201D}? SimpleVPN forgets where that "
            + "\(vendor.instanceNoun) is \u{2014} \(vendor.instanceRemovalReassurance)."
        guard !profiles.isEmpty else { return head }
        let list = profiles.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        let named = list.count == 1
            ? "\u{201C}\(list[0])\u{201D} uses it"
            : list.map { "\u{201C}\($0)\u{201D}" }.joined(separator: ", ") + " use it"
        return head + " \(named), and will ask you to choose another \(vendor.instanceNoun) "
            + "before connecting."
    }
}
