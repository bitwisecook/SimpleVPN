// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EngineSettings.swift
//  Shared, engine-agnostic settings scaffolding so every VPN engine (WireGuard,
//  SSH, OpenConnect SSL-VPNs, native IKEv2/IPsec) gets the same treatment the
//  OpenVPN options pane has: one spec per option (stable id, name, short
//  user-focused summary, manual anchor), rendered as a labelled control with the
//  summary and a "Learn more" deep-link into the bundled HTML manual. Each engine
//  declares a spec table; its form composes rows from it. The manual anchor is
//  the spec id with dots→dashes, matching Resources/Manual/manual.html.
//

import SwiftUI

/// One configurable option's presentation metadata (not its value — engines
/// bind values via their own concrete config structs).
struct EngineSettingSpec: Identifiable, Sendable {
    let id: String        // e.g. "wg.mtu" — also the manual anchor (dots→dashes)
    let name: String
    let summary: String
    var manualAnchor: String { id.replacingOccurrences(of: ".", with: "-") }
}

/// A spec table keyed by id, with a terse literal builder.
struct EngineSettingCatalog: Sendable {
    private let byID: [String: EngineSettingSpec]
    init(_ specs: [EngineSettingSpec]) {
        byID = Dictionary(uniqueKeysWithValues: specs.map { ($0.id, $0) })
    }
    /// Force-unwrap: a missing id is a programming error caught immediately in dev.
    subscript(_ id: String) -> EngineSettingSpec { byID[id]! }
}

/// A labelled row: the engine supplies the control; this adds the bold-on-change
/// label, the plain-English summary, and the manual deep-link — identical in feel
/// to the OpenVPN options rows.
struct EngineSettingRow<Control: View>: View {
    let spec: EngineSettingSpec
    var changed: Bool = false
    @ViewBuilder let control: Control

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 8) {
                control
                    .frame(maxWidth: .infinity, alignment: .leading)
                ManualLink(anchor: spec.manualAnchor, settingName: spec.name)
            }
            Text(spec.summary)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 6)
        .help(spec.summary)
    }

    /// The row's control label, bold when the value differs from the default.
    func label() -> some View { Text(spec.name).bold(changed) }
}

/// Convenience: a plain label for a spec (bold when changed), matching SettingLabel.
struct EngineSettingLabel: View {
    let spec: EngineSettingSpec
    var changed = false
    var body: some View { Text(spec.name).bold(changed) }
}
