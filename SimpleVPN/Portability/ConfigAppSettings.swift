// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigAppSettings.swift
//  THE list of app-wide settings the export carries, and the only place that says
//  which preference key each one lives in.
//
//  WHY A DECLARED LIST rather than "write out the whole preference domain". Two
//  reasons, and both are about a file that leaves the Mac:
//   • A preference domain also holds window frames, one-shot "have you seen this
//     yet" flags, Sparkle's update bookkeeping and whatever a future feature
//     caches there. None of that is a SETTING, and a file full of it cannot be
//     read by a person — which is the whole point of this format.
//   • Import must not trust the file. A declared list means an imported document
//     can only reach settings somebody deliberately made reachable; a domain dump
//     would let a hand-edited file write ANY key in SimpleVPN's preferences,
//     including the four `ManagedPolicy` keys an administrator sets.
//
//  THE ID is a registered setting id where the app has one (`vm.detect`,
//  `creds.discovery`), and otherwise an `app.*` id coined here. Those `app.*` ids
//  are NOT descriptor ids — the Settings window's own toggles predate the
//  descriptor registry and have no manual anchors of their own — so they are
//  spelled out in this table and checked by `ConfigFormatTests`. What they are
//  never keyed by is the display name: "Show the Dock icon" is the label, and a
//  label is free to be reworded.
//

import Foundation

@MainActor
enum ConfigAppSettings {

    nonisolated enum Kind: Sendable, Equatable {
        case boolean(Bool)          // with its default
        case text(String)
        case number(Int)
        /// A `Codable` value persisted as JSON `Data` (the app-wide browser
        /// choice). Carried as a nested map, so the file stays readable.
        case json
    }

    nonisolated struct Entry: Sendable {
        let id: String
        /// The macOS preference key. The one place it is written down twice — here
        /// and at the `@AppStorage` that reads it — which is why the constants are
        /// shared rather than re-typed.
        let key: String
        /// What the import diff calls it. A DISPLAY name: it appears in a sentence
        /// a person reads, never as a key.
        let name: String
        let kind: Kind
        /// False for a setting an imported file must not be able to turn on.
        /// Location is the only one today: macOS asks for that permission exactly
        /// when the user flips the switch themselves, and a file that could flip it
        /// would turn "opt in" into "opt in on somebody else's behalf".
        var importable = true
    }

    static var all: [Entry] {
        var out: [Entry] = [
            .init(id: "app.details-pane", key: inspectorDefaultsKey,
                  name: "Open the live-details pane by default", kind: .boolean(false)),
            .init(id: "app.browser", key: BrowserDefaults.preferenceKey,
                  name: "Browser used for signing in", kind: .json),
            .init(id: "app.server-speed-checks", key: endpointProbeDefaultsKey,
                  name: "Check how quick each server is", kind: .boolean(true)),
            .init(id: "app.dock-icon", key: dockIconDefaultsKey,
                  name: "Show the Dock icon", kind: .boolean(true)),
            .init(id: "app.menu-bar-icon", key: menuBarIconDefaultsKey,
                  name: "Show the menu-bar icon", kind: .boolean(true)),
            .init(id: "app.menu-bar-graph", key: menuBarGraphDefaultsKey,
                  name: "Show traffic graph next to the icon", kind: .boolean(false)),
            // Sparkle's own key. Written here because it is a switch in SimpleVPN's
            // Settings window and a person moving to a new Mac means it too;
            // Sparkle reads its preference domain, so setting it is enough.
            .init(id: "app.automatic-updates", key: "SUEnableAutomaticChecks",
                  name: "Check for updates automatically", kind: .boolean(true)),
            .init(id: "app.public-address-lookup", key: publicIPLookupDefaultsKey,
                  name: "Look up my public address", kind: .boolean(true)),
            .init(id: "app.public-address-service", key: publicIPProviderDefaultsKey,
                  name: "Lookup service", kind: .text("ipify")),
            .init(id: "app.public-address-url-v4", key: publicIPCustomV4DefaultsKey,
                  name: "IPv4 lookup URL", kind: .text("")),
            .init(id: "app.public-address-url-v6", key: publicIPCustomV6DefaultsKey,
                  name: "IPv6 lookup URL", kind: .text("")),
            .init(id: "app.location", key: LocationAuthority.enabledKey,
                  name: "Use this Mac\u{2019}s location", kind: .boolean(false), importable: false),
            .init(id: VirtualizationSettings.detect.id, key: VirtualizationSettings.detectDefaultsKey,
                  name: VirtualizationSettings.detect.name, kind: .boolean(true)),
            .init(id: VirtualizationSettings.warnOnConnect.id,
                  key: VirtualizationSettings.warnOnConnectDefaultsKey,
                  name: VirtualizationSettings.warnOnConnect.name, kind: .boolean(true)),
            .init(id: SignInSourceSettings.discoverySettingID,
                  key: SignInSourceSettings.discoveryEnabledKey,
                  name: CredentialSourceSettings.discovery.name, kind: .boolean(true)),
        ]
        // One switch per password app, GENERATED from the vendor list — so a vendor
        // added next year is carried by the export without anyone editing this file,
        // which is the same reason its settings catalog is generated.
        for vendor in LocalVaultVendor.allCases {
            out.append(.init(id: SignInSourceSettings.enabledSettingID(vendor),
                             key: SignInSourceSettings.vendorEnabledKey(vendor),
                             name: "Use \(vendor.displayTitle)", kind: .boolean(true)))
        }
        return out
    }

    static func entry(id: String) -> Entry? { all.first { $0.id == id } }

    // MARK: Reading

    /// The EFFECTIVE value, default included. A file that only listed the settings
    /// somebody had touched would be a worse description of the Mac and a much
    /// worse diff: "this file would change nothing" has to be answerable.
    static func read(_ e: Entry, from store: UserDefaults = .standard) -> ConfigValue? {
        switch e.kind {
        case .boolean(let fallback):
            return .bool(store.object(forKey: e.key) == nil ? fallback : store.bool(forKey: e.key))
        case .text(let fallback):
            return .string(store.string(forKey: e.key) ?? fallback)
        case .number(let fallback):
            return .int(store.object(forKey: e.key) == nil ? fallback : store.integer(forKey: e.key))
        case .json:
            guard let data = store.data(forKey: e.key),
                  let any = try? JSONSerialization.jsonObject(with: data) else { return nil }
            return ConfigJSON.value(any)
        }
    }

    static func snapshot(from store: UserDefaults = .standard) -> [ConfigSnapshot.AppSetting] {
        all.compactMap { e in
            read(e, from: store).map { ConfigSnapshot.AppSetting(id: e.id, value: $0) }
        }
    }

    // MARK: Writing

    /// Why an imported value cannot be applied, or nil when it can. Type-checked
    /// against the declared kind: a file saying `app.dock-icon: "sometimes"` is
    /// refused rather than coerced to a truth value.
    static func refusal(applying value: ConfigValue, to e: Entry,
                        store: UserDefaults = .standard) -> String? {
        if !e.importable {
            return "\u{201C}\(e.name)\u{201D} is left as it is \u{2014} macOS only asks for that "
                + "permission when you turn it on yourself."
        }
        if store.objectIsForced(forKey: e.key) {
            return "\u{201C}\(e.name)\u{201D} is set by your organization and can\u{2019}t be changed."
        }
        switch e.kind {
        case .boolean: return value.boolValue == nil ? typeRefusal(e, "on or off") : nil
        case .text: return value.stringValue == nil ? typeRefusal(e, "some text") : nil
        case .number: return value.intValue == nil ? typeRefusal(e, "a number") : nil
        case .json: return value.mapValue == nil ? typeRefusal(e, "a group of settings") : nil
        }
    }

    private static func typeRefusal(_ e: Entry, _ expected: String) -> String {
        "\u{201C}\(e.name)\u{201D} in the file isn\u{2019}t \(expected), so it was left as it is."
    }

    /// Apply one setting. Returns false when nothing was written — callers have
    /// already asked `refusal(applying:to:)`, so a false here means the value
    /// could not be encoded at all.
    @discardableResult
    static func write(_ value: ConfigValue, to e: Entry, store: UserDefaults = .standard) -> Bool {
        switch e.kind {
        case .boolean:
            guard let b = value.boolValue else { return false }
            store.set(b, forKey: e.key)
        case .text:
            guard let s = value.stringValue else { return false }
            store.set(s, forKey: e.key)
        case .number:
            guard let i = value.intValue else { return false }
            store.set(i, forKey: e.key)
        case .json:
            guard let m = value.mapValue,
                  let data = try? JSONSerialization.data(withJSONObject: m.jsonRepresentation) else { return false }
            store.set(data, forKey: e.key)
        }
        return true
    }
}

nonisolated extension ConfigMap {
    /// The map as a `JSONSerialization` object, for the settings persisted as a
    /// JSON blob.
    var jsonRepresentation: [String: Any] {
        Dictionary(entries.map { ($0.key, $0.value.jsonObject) }, uniquingKeysWith: { _, last in last })
    }
}
