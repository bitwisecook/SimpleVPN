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
    /// Canonical taxonomy group (AGENTS.md "Config surfaces"). Optional because
    /// some catalogs' forms are laid out by hand; a catalog that declares groups
    /// (SSHSettings) can be section-checked by tests and future searches.
    var group: SettingGroup? = nil
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
    /// Non-nil disables the control and says why — the reason replaces the
    /// summary and rides `.help` + the control's `accessibilityValue`, the
    /// same dead-control contract the OpenVPN form's SettingRow follows.
    var disabledReason: String? = nil
    @ViewBuilder let control: Control

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 8) {
                // NOTE for callers: a bare TextField whose title is an example
                // value ("https://vpn.example.com") makes that example its
                // VoiceOver name — wrap fields in LabeledContent { … } label: {
                // EngineSettingLabel(spec:) } (the WireGuard pattern) or add
                // .accessibilityLabel(spec.name) to the field.
                if let reason = disabledReason {
                    control
                        .disabled(true)
                        .accessibilityValue("unavailable — \(reason)")
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    control
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                ManualLink(anchor: spec.manualAnchor, settingName: spec.name)
            }
            Text(disabledReason ?? spec.summary)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 6)
        .help(disabledReason ?? spec.summary)
        // Group the control with its summary so the explanation is the element
        // VoiceOver reaches next, matching SettingRow in the OpenVPN form.
        .accessibilityElement(children: .contain)
    }

    /// The row's control label, bold when the value differs from the default.
    func label() -> some View { Text(spec.name).bold(changed) }
}

/// Convenience: a plain label for a spec (bold when changed), matching SettingLabel.
struct EngineSettingLabel: View {
    let spec: EngineSettingSpec
    var changed = false
    var body: some View {
        Text(spec.name).bold(changed)
            // Bold weight is invisible to VoiceOver — say the state too.
            .accessibilityLabel(changed ? "\(spec.name), changed from default" : spec.name)
    }
}
