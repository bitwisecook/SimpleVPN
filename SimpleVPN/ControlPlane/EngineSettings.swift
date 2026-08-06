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

    /// Ids of the settings a reader of THIS one needs to know about — rendered as
    /// the "Related settings" links in the help popover.
    ///
    /// Computed from `SettingRelations`, not stored per spec, and deliberately:
    /// relations are symmetric, and a stored list makes symmetry something every
    /// declaration has to remember (get it wrong once and the link works one way
    /// and dead-ends the other). The map declares cliques; both directions fall
    /// out. See SettingRelations.swift's header.
    var related: [String] { SettingRelations.related[id] ?? [] }

    /// The engine/OS default, type-erased behind its own comparison. "Changed"
    /// used to be hand-wired at every call site (`changed: !draft.acceptRoutes`,
    /// `changed: draft.useExitNode`, …) — thirty-odd derivations, several of them
    /// INVERTED, for one question the spec can answer once. Declare the default
    /// here and `isChanged(_:)` computes it.
    private let changedCheck: (@Sendable (Any) -> Bool)?

    /// Whether this spec declares a default at all (the contract tests check that
    /// every spec whose form asks for "changed" has one).
    var declaresDefault: Bool { changedCheck != nil }

    /// Whether `value` differs from the declared default. False when no default
    /// is declared — never a guess. Generic (not `Any`) so an Optional value
    /// isn't silently coerced at the call site.
    func isChanged(_ value: some Equatable & Sendable) -> Bool { changedCheck?(value) ?? false }

    init(id: String, name: String, summary: String, group: SettingGroup? = nil) {
        self.id = id
        self.name = name
        self.summary = summary
        self.group = group
        self.changedCheck = nil
    }

    /// The preferred form: declare the value this setting rests at, and every row
    /// gets its bold-when-changed state from one place.
    init<V: Equatable & Sendable>(id: String, name: String, summary: String,
                                  group: SettingGroup? = nil, default defaultValue: V) {
        self.id = id
        self.name = name
        self.summary = summary
        self.group = group
        self.changedCheck = { value in
            // A mismatched type is a programming error at the call site, but a
            // wrong BOLD is not worth a crash — answer "unchanged".
            guard let typed = value as? V else { return false }
            return typed != defaultValue
        }
    }
}

/// A spec table keyed by id, with a terse literal builder.
struct EngineSettingCatalog: Sendable {
    private let byID: [String: EngineSettingSpec]
    /// Declaration order — what a catalog's form renders, and what tests walk to
    /// hold every id to the contract (a name, a summary, a real manual anchor).
    let all: [EngineSettingSpec]
    init(_ specs: [EngineSettingSpec]) {
        all = specs
        byID = Dictionary(uniqueKeysWithValues: specs.map { ($0.id, $0) })
    }
    /// Force-unwrap: a missing id is a programming error caught immediately in dev.
    subscript(_ id: String) -> EngineSettingSpec { byID[id]! }
}

/// A labelled row: the engine supplies the control; this adds the bold-on-change
/// label, the plain-English summary, and the manual deep-link — identical in feel
/// to the OpenVPN options rows.
///
/// THE LAYOUT IS NOT HERE any more. It is `SettingRowLayout`
/// (UI/Components/SettingValueRow.swift), shared with the OpenVPN options form's
/// `SettingRow`, so the two cannot drift again — and so the red required-field
/// marking landed in both at once. What stays here is the only part that could never
/// merge: where "changed" comes from.
struct EngineSettingRow<Control: View>: View {
    let spec: EngineSettingSpec
    var changed: Bool = false
    /// Non-nil disables the control and says why — the reason replaces the
    /// summary and rides `.help` + the control's `accessibilityValue`, the
    /// same dead-control contract the OpenVPN form's SettingRow follows.
    var disabledReason: String? = nil
    @ViewBuilder let control: Control

    var body: some View {
        // NOTE for callers: the control must be a value in the VALUE column —
        // `SettingValueField`, `SettingPicker`, a `Toggle`, or your own
        // `LabeledContent`. A bare `TextField` or `Picker` is neither right-aligned
        // nor correctly named to VoiceOver; see SettingValueRow.swift's header.
        SettingRowLayout(setting: spec, disabledReason: disabledReason) {
            control
        }
    }

    /// The row's control label, bold when the value differs from the default.
    func label() -> some View { Text(spec.name).bold(changed) }
}

extension EngineSettingRow {
    /// The preferred form: hand the row the CURRENT value and let the spec's
    /// declared default decide whether it counts as changed. One derivation, in
    /// the catalog, instead of a hand-written (and sometimes inverted) predicate
    /// at each of thirty-odd call sites.
    init(spec: EngineSettingSpec, value: some Equatable & Sendable,
         disabledReason: String? = nil,
         @ViewBuilder control: () -> Control) {
        self.init(spec: spec, changed: spec.isChanged(value),
                  disabledReason: disabledReason, control: control)
    }
}

/// Convenience: a plain label for a spec (bold when changed, red when the connect
/// path is waiting on it), matching `SettingLabel`. Both render `SettingNameLabel`,
/// which is the one definition of what a setting's name looks like and sounds like.
struct EngineSettingLabel: View {
    let spec: EngineSettingSpec
    var changed = false

    init(spec: EngineSettingSpec, changed: Bool = false) {
        self.spec = spec
        self.changed = changed
    }

    /// Value-driven form: the spec's declared default decides "changed".
    init(spec: EngineSettingSpec, value: some Equatable & Sendable) {
        self.spec = spec
        self.changed = spec.isChanged(value)
    }

    var body: some View {
        SettingNameLabel(settingID: spec.id, name: spec.name, changed: changed)
    }
}
