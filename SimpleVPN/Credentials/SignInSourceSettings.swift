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
    /// A vault file on disk (a KeePass `.kdbx`, say).
    case vaultFile(extensions: [String])
    /// A PKCS#11 module (a `.so`/`.dylib`, loaded rather than executed).
    case pkcs11Module

    // NOTE on the last three: no shipped field declares them yet. They are here
    // because the two adapters that need them are already designed — Bitwarden's
    // `bw serve` is a loopback endpoint and the kdbx adapter is a file — and each
    // one's validation and its setting copy are written and tested. Their presence
    // is what makes adding either a one-row declaration instead of a fourth branch
    // in every switch. A field is only DECLARED when something reads it, which is
    // why none of them appears on screen: a setting nothing consults is worse than
    // a missing one, because someone will configure it and then wonder why their
    // VPN still fails.

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
    /// The master switch for the whole local scan. Default ON — the scan is
    /// filesystem-only, needs no macOS permission, and every sign-in source
    /// feature is inert without it. Off means SimpleVPN never looks for a password
    /// manager at all.
    static let discoveryEnabledKey = "signin.discovery.enabled"

    // MARK: Setting ids

    static func enabledSettingID(_ vendor: LocalVaultVendor) -> String {
        "creds.\(vendor.settingSlug).enabled"
    }
    static let discoverySettingID = "creds.discovery"

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

    static let allKeys = [allowedKey, forbiddenKey, pinnedPathsKey, disableDiscoveryKey]

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

    /// Whether this state stops the field working. `sanctioned` and `notSet`
    /// don't — they are statements, not faults.
    var isProblem: Bool {
        switch self {
        case .notSet, .ok, .sanctioned: false
        case .notAbsolute, .missing, .notExecutable, .unsafeDirectory, .notASocket, .badEndpoint: true
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
        }
    }

    /// The label role the visible error announces — "Problem:" is already in the
    /// sentence for the faults, so this is the SF Symbol half only.
    var symbolName: String? {
        switch self {
        case .notSet: nil
        case .ok: "checkmark.circle.fill"
        case .sanctioned: "hand.raised.circle.fill"
        default: "exclamationmark.triangle.fill"
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
            let validation = VendorFieldValidation.notSet(detected: detected)
            return VendorFieldPresentation(
                value: "",
                // The suggestion lives HERE — in the placeholder — and nowhere
                // else. This is the whole distinction.
                prompt: detected ?? field.example,
                accessibilityValue: validation.sentence,
                isSet: false,
                effectivePath: detected,
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

    init(store: UserDefaults = .standard) {
        self.store = store
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
        guard let tool = field.kind.detectionTool else { return nil }
        return ManagedSignInSourcePolicy.pinnedPaths(store)[tool]
    }

    func setValue(_ raw: String, for field: VendorConfigField) {
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
        case .daemonEndpoint, .vaultFile, .pkcs11Module:
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
        guard !path.isEmpty else { return .notSet(detected: detected(for: field)) }
        // An endpoint is `host:port`, not a path — it is checked before the
        // absolute-path rule rather than being told to start with a slash.
        if case .daemonEndpoint = field.kind {
            let parts = path.split(separator: ":")
            guard parts.count == 2, !parts[0].isEmpty,
                  let port = Int(parts[1]), (1...65535).contains(port) else { return .badEndpoint }
            return .ok
        }
        guard path.hasPrefix("/") else { return .notAbsolute }
        var st = stat()
        guard stat(path, &st) == 0 else { return .missing }
        switch field.kind {
        case .unixSocket:
            return (st.st_mode & S_IFMT) == S_IFSOCK ? .ok : .notASocket
        case .daemonEndpoint:
            return .ok               // handled above
        case .vaultFile, .pkcs11Module:
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
