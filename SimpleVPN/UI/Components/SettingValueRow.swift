// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingValueRow.swift
//  THE value column. One definition of "a setting's value is on the right", and
//  the controls that put it there.
//
//  WHY THIS FILE EXISTS. "All setting values should be right-aligned" was reported
//  twice — the second time as "again with values not right aligned" — because the
//  answer was spread across five near-identical private helpers, one per editor:
//  `WireGuardView.textField`/`monoField`/`listField`, `SSHNetworkTunnelView`,
//  `TailscaleView` and `ProxyTunnelView`'s `labeledField`, and
//  `SubprocessTunnelView.row`. Five copies of one layout is why it drifted: a fix
//  landed in whichever copy the reporter happened to be looking at. All five now
//  forward here, so there is one place to be right and no way to be inconsistent.
//
//  THE THREE RULES THIS FILE ENFORCES:
//
//   1. A VALUE IS TRAILING (`settingValue()`). `LabeledContent` puts its label
//      leading and its content trailing, which is the macOS grouped-form idiom and
//      what every value here rides.
//
//   2. A PICKER IS NOT EXEMPT (`SettingPicker`). A bare `Picker` sizes to
//      label-plus-popup and is NOT greedy, so the shared row's
//      `.frame(maxWidth: .infinity, alignment: .leading)` pinned that whole pair to
//      the left — ~30 rows whose value sat on the left while every text row's sat on
//      the right. Wrapping it in `LabeledContent` with `.labelsHidden()` is what
//      moves the popup into the value column. `SettingAlignmentTests` holds every
//      editor to it.
//
//   3. AN EXAMPLE IS A `prompt:`, NEVER A TITLE. A `TextField`'s first argument is
//      its TITLE; inside `LabeledContent` SwiftUI DRAWS that title next to the
//      value, so an example rendered as though it were the value — and VoiceOver
//      announced it as the field's NAME. Twenty-six sites were fixed for exactly
//      this once already. Every field here passes `""` and a real `prompt:`.
//
//  Required-ness (the red highlight) lives here too, in `SettingNeeds` — see its
//  own doc comment for why it is derived and never declared.
//

import SwiftUI

// MARK: - The value column

nonisolated enum SettingValueMetrics {
    /// How wide a value may get before it stops growing. Matches the OpenVPN
    /// options form, which had this number inline and was the only form that did.
    static let maxWidth: CGFloat = 260
}

extension View {
    /// A setting's VALUE, in the value column: right-aligned, capped, and pushed to
    /// the trailing edge. The one definition — see this file's header.
    func settingValue(maxWidth: CGFloat = SettingValueMetrics.maxWidth) -> some View {
        self
            .multilineTextAlignment(.trailing)
            .frame(maxWidth: maxWidth, alignment: .trailing)
            .frame(maxWidth: .infinity, alignment: .trailing)
    }
}

// MARK: - What must be filled in, and why

/// The settings the connect path says are missing, keyed by the field at fault.
///
/// DERIVED, NEVER DECLARED. The user asked for required fields in red and for the
/// answer to live "in one spot only"; the hazard is two answers — the connect list
/// saying one field is missing while the editor reddens another. So this carries
/// exactly what `ConnectNeed.settingID` already names (`SubprocessTunnelReadiness`,
/// `NativeVPNReadiness`, and each packet-tunnel editor's own single validator
/// chain). There is deliberately no hand-maintained list of "required settings"
/// anywhere: a field is required because the thing that refuses to connect said so.
///
/// Colour is never the only signal (`Docs/Accessibility.md`): the row renders the
/// sentence as text and the control's accessibility value says it too.
nonisolated struct SettingNeeds: Equatable, Sendable {
    /// setting id → what is missing and what clears it, in the user's words.
    var byID: [String: String] = [:]

    init(byID: [String: String] = [:]) { self.byID = byID }

    /// Why this setting is holding the connection up, or nil.
    func reason(_ settingID: String) -> String? { byID[settingID] }

    var isEmpty: Bool { byID.isEmpty }
}

private struct SettingNeedsKey: EnvironmentKey {
    static let defaultValue = SettingNeeds()
}

extension EnvironmentValues {
    /// Published by an editor, read by every row in it.
    var settingNeeds: SettingNeeds {
        get { self[SettingNeedsKey.self] }
        set { self[SettingNeedsKey.self] = newValue }
    }
}

extension View {
    /// Publish what this editor's readiness answer says is missing, so the rows at
    /// fault mark themselves. One line per editor; nothing per row.
    func settingNeeds(_ needs: SettingNeeds) -> some View {
        environment(\.settingNeeds, needs)
    }
}

// MARK: - Live save

/// "Store what the editor holds now."
///
/// WHY THERE IS NO SAVE BUTTON. The confirming ✓ was reported as doing nothing —
/// and it half was: it saved without dismissing, and its "Saved" state reused the
/// SAME `checkmark` glyph as "Save", so in an icon-only toolbar a successful save
/// was invisible to a sighted user while VoiceOver heard "Saved". The resolution the
/// user arrived at is "maybe everything is just live save and close", and the app was
/// already halfway there: Custom Routing commits on `onDisappear`, and switching
/// profiles in the sidebar saved as it went.
///
/// WHY LIVE SAVE IS SAFE HERE, when System Settings ▸ Network needs an explicit
/// Apply: an edit updates the STORED profile and nothing else. The running tunnel
/// keeps the settings it started with until it is reconnected. The hazard of
/// live-applying network configuration is applying it NOW, and this does not.
///
/// THE THREE RULES THAT MAKE IT SAFE RATHER THAN SLOPPY:
///
///  1. ON BLUR OR SUBMIT, NEVER PER KEYSTROKE. `SettingRowLayout` already owns a
///     `@FocusState` for every row's control (the reveal needed one), so "the user
///     has left this field" is knowable in ONE place — without it, `vpn.f5.c` gets
///     persisted on the way to `vpn.f5.com`.
///  2. AND ON CLOSE. Each editor calls it from `onDisappear`, which covers closing
///     the window and switching profiles in the sidebar. Typing is never discarded.
///  3. VALIDATE BEFORE COMMITTING. Each editor's `commit` is gated on its own single
///     validator chain, so a malformed value is HELD in the editor and not stored.
///     Storage is live; VALIDITY is surfaced separately — by the red need caption
///     above, by each row's amber problem caption, and by `ConnectListing`, which
///     already lists an unfinished profile with Connect disabled and a reason.
struct SettingCommit {
    /// Nil until an editor publishes one, so a row outside an editor is inert.
    var action: (@MainActor () -> Void)?

    @MainActor func callAsFunction() { action?() }
}

private struct SettingCommitKey: EnvironmentKey {
    static let defaultValue = SettingCommit()
}

extension EnvironmentValues {
    var settingCommit: SettingCommit {
        get { self[SettingCommitKey.self] }
        set { self[SettingCommitKey.self] = newValue }
    }
}

extension View {
    /// THE live-save contract for one editor, in one line: commit when a field loses
    /// focus, when a field is submitted, and when the editor goes away (closing the
    /// window, or switching profiles in the sidebar).
    ///
    /// Applied at the editor's outermost view so the environment reaches the rows on
    /// every tab and the `onDisappear` covers the whole editor. `action` must be
    /// IDEMPOTENT — all three paths can fire for one edit — and must refuse to store
    /// an invalid draft rather than rewriting it.
    func savesSettingsLive(_ action: @MainActor @escaping () -> Void) -> some View {
        environment(\.settingCommit, SettingCommit(action: action))
            .onSubmit(of: .text, action)
            .onDisappear(perform: action)
    }
}

/// The red "this has to be filled in" caption. TEXT plus colour plus (on the
/// control) an accessibility value — three channels, because colour alone is not a
/// signal (`Docs/Accessibility.md`).
struct SettingNeedLabel: View {
    let reason: String

    var body: some View {
        Label(reason, systemImage: "exclamationmark.circle.fill")
            .font(.callout)
            .foregroundStyle(.red)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            // "Needed" rather than a bare read-out: the colour says urgency to a
            // sighted user and this says it to everyone else.
            .accessibilityLabel("Needed: \(reason)")
    }
}

// MARK: - The one row layout

/// The row body every setting row in the app draws: the control and its "?" on one
/// line, the plain-English summary under it, the red need caption when the connect
/// path is waiting on this field, and any caveats.
///
/// `EngineSettingRow` (every engine's catalog) and the OpenVPN options form's
/// `SettingRow` (the keypath-bound descriptor registry) are both thin wrappers over
/// this — they differ only in where "changed" and "availability" come from, which is
/// exactly the part that could never merge. The LAYOUT is not that part, and having
/// it twice is how the two drifted (`.padding(.vertical, 6)` was restored to one of
/// them and not the other more than once).
struct SettingRowLayout<Control: View, Caveat: View>: View {
    let setting: any SearchableSetting
    /// Non-nil disables the control and says why — the reason replaces the summary
    /// and rides `.help` plus the control's `accessibilityValue`.
    var disabledReason: String?
    @ViewBuilder let control: Control
    @ViewBuilder let caveat: Caveat

    @Environment(\.settingNeeds) private var needs
    @Environment(\.settingCommit) private var commit
    /// Keyboard focus for a search/related-link reveal — and, since live save, the
    /// one place "the user has left this field" is knowable. Here rather than at each
    /// call site, so one edit gives every row in seven editors a jump target and a
    /// blur commit.
    @FocusState private var controlFocused: Bool

    init(setting: any SearchableSetting, disabledReason: String? = nil,
         @ViewBuilder control: () -> Control,
         @ViewBuilder caveat: () -> Caveat) {
        self.setting = setting
        self.disabledReason = disabledReason
        self.control = control()
        self.caveat = caveat()
    }

    /// Why the connect path is waiting on this field, or nil. A DISABLED row is
    /// never marked required: a control the user cannot reach is not something they
    /// have failed to fill in.
    private var needReason: String? {
        disabledReason == nil ? needs.reason(setting.id) : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Control and "?" share the top line, so every help button lines up in
            // one column with every row's value.
            HStack(alignment: .center, spacing: 8) {
                control
                    .disabled(disabledReason != nil)
                    // A dead control says why in all three channels: the visible
                    // summary below, the tooltip, and its own accessibility value.
                    // A required-and-empty one says that instead.
                    .accessibilityValue(spokenState ?? "")
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .settingRevealFocus(setting.id, focused: $controlFocused)
                ManualLink(setting: setting)
            }
            Text(disabledReason ?? setting.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let needReason { SettingNeedLabel(reason: needReason) }
            caveat
        }
        // Grouped-form rows with a stacked summary need extra air.
        .padding(.vertical, 6)
        .help(disabledReason ?? needReason ?? setting.summary)
        // Identity for the scroll, the pulse and VoiceOver focus. INSIDE the shared
        // row, so adding search to an editor is one line in that editor rather than
        // an `.id()` on every row it renders.
        .settingReveal(setting.id)
        // Group the control with its summary so the explanation is the element
        // VoiceOver reaches next.
        .accessibilityElement(children: .contain)
        // LIVE SAVE, on the ONE transition that means "I've finished with this
        // field". Not `onChange(of: value)` — that is per keystroke, which is how a
        // half-typed server address gets stored (see `SettingCommit`).
        .onChange(of: controlFocused) { wasFocused, isFocused in
            if wasFocused && !isFocused { commit() }
        }
    }

    /// What the control's accessibility value says about its own state, or nil when
    /// there is nothing to add (the control's real value then speaks for itself).
    private var spokenState: String? {
        if let disabledReason { return "unavailable \u{2014} \(disabledReason)" }
        if let needReason { return "needed \u{2014} \(needReason)" }
        return nil
    }
}

extension SettingRowLayout where Caveat == EmptyView {
    init(setting: any SearchableSetting, disabledReason: String? = nil,
         @ViewBuilder control: () -> Control) {
        self.init(setting: setting, disabledReason: disabledReason,
                  control: control, caveat: { EmptyView() })
    }
}

// MARK: - The one label

/// A setting's name, bold while it differs from the default (the Xcode
/// build-settings idiom), red while the connect path is waiting on it.
///
/// `SettingLabel` (OpenVPN descriptors) and `EngineSettingLabel` (every other
/// catalog) both render this, so the two can't disagree about weight, colour or
/// what VoiceOver hears.
struct SettingNameLabel: View {
    let settingID: String
    let name: String
    var changed = false

    @Environment(\.settingNeeds) private var needs

    var body: some View {
        let needed = needs.reason(settingID) != nil
        Text(name)
            .bold(changed)
            // The red is a hint, not the message: `SettingNeedLabel` carries the
            // words, right under the row.
            .foregroundStyle(needed ? AnyShapeStyle(.red) : AnyShapeStyle(.primary))
            // Bold weight and colour are both invisible to VoiceOver — say them.
            .accessibilityLabel(spoken(needed: needed))
    }

    private func spoken(needed: Bool) -> String {
        var out = name
        if changed { out += ", changed from default" }
        if needed { out += ", needs a value" }
        return out
    }
}

// MARK: - The one text/secure value field

/// A setting's text value: `LabeledContent` with the name leading and a trailing,
/// right-aligned field. THE text row — the five per-editor copies forward here.
///
/// The title is always empty and the example always rides `prompt:` (rule 3 in this
/// file's header).
struct SettingValueField: View {
    let spec: EngineSettingSpec
    @Binding var text: String
    /// The example, shown only while the field is empty.
    var prompt: String
    /// What is wrong with the value, said on the field's own accessibility value
    /// (`Docs/Accessibility.md`: validation rides the value).
    var problem: String?
    /// A secret: never rendered, so never a plain field.
    var secure = false
    /// Monospaced, for keys, fingerprints and paths where character-level reading
    /// is the point.
    var mono = false
    /// What VoiceOver calls it, when that is not the spec's own name (e.g. "SSH
    /// password" for a row the spec calls "Password").
    var spokenName: String?
    /// Whether the value differs from the spec's declared default. Passed explicitly
    /// only when the stored value isn't this String (a comma-joined list, a number
    /// held as text).
    var changed: Bool?
    /// Anything else the field's own accessibility value has to carry — a
    /// non-blocking warning, or an informational note the row also shows as a
    /// caption. It rides the VALUE rather than a hint because that is where
    /// `Docs/Accessibility.md` puts state.
    var extraSpoken: String?

    var body: some View {
        LabeledContent {
            field
                .font(mono ? .callout.monospaced() : nil)
                .settingValue()
                .autocorrectionDisabled()
                .accessibilityLabel(spokenName ?? spec.name)
                .accessibilityValue(spokenValue)
        } label: {
            SettingNameLabel(settingID: spec.id, name: spec.name,
                             changed: changed ?? spec.isChanged(text))
        }
    }

    @ViewBuilder private var field: some View {
        if secure {
            // A secret's own value must never be read back out loud, so the
            // accessibility value carries only the problem.
            SecureField("", text: $text, prompt: Text(prompt))
        } else {
            TextField("", text: $text, prompt: Text(prompt))
        }
    }

    private var spokenValue: String {
        // A secret's own value is never read back out loud.
        let base = secure ? "" : text
        return [base, problem.map { "Problem: \($0)" }, extraSpoken]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: ". ")
    }
}

extension SettingValueField {
    /// The comma-separated-list form: one field over a `[String]`, which is how
    /// every editor already presents addresses, routes, resolvers and search
    /// domains. "Changed" comes from the LIST against the spec's declared default,
    /// not from the joined string — a `[String]` spec's default is `[]`, and asking
    /// it about a String always answered "unchanged".
    init(spec: EngineSettingSpec, list: Binding<[String]>, prompt: String,
         problem: String? = nil, mono: Bool = false, spokenName: String? = nil) {
        self.init(spec: spec,
                  text: Binding(
                    get: { list.wrappedValue.joined(separator: ", ") },
                    set: { joined in
                        list.wrappedValue = joined
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                    }),
                  prompt: prompt, problem: problem, secure: false, mono: mono,
                  spokenName: spokenName, changed: spec.isChanged(list.wrappedValue))
    }
}

// MARK: - The one picker

/// A setting's picker, laid out like every other value: name leading, popup in the
/// value column. See rule 2 in this file's header for why a bare `Picker` cannot be
/// left alone, and `SettingAlignmentTests` for the check that keeps it that way.
///
/// The initialiser mirrors `Picker(selection:content:label:)` exactly, so adopting
/// it at a call site is one word.
/// `Value` is only `Hashable` — deliberately NOT `Sendable`. Three of the OpenVPN
/// form's selections are main-actor-isolated nested enums, and requiring `Sendable`
/// here refused them ("main actor-isolated conformance … cannot satisfy conformance
/// requirement for a 'Sendable' type parameter"). Nothing in this view crosses an
/// isolation boundary, so the requirement bought nothing.
struct SettingPicker<Value: Hashable, Content: View, Label: View>: View {
    @Binding var selection: Value
    @ViewBuilder let content: Content
    @ViewBuilder let label: Label

    init(selection: Binding<Value>,
         @ViewBuilder content: () -> Content,
         @ViewBuilder label: () -> Label) {
        self._selection = selection
        self.content = content()
        self.label = label()
    }

    var body: some View {
        LabeledContent {
            Picker(selection: $selection) { content } label: { EmptyView() }
                .labelsHidden()
                .frame(maxWidth: .infinity, alignment: .trailing)
        } label: {
            label
        }
    }
}

// MARK: - The one problem caption

/// One amber caption for a field's problem, or nothing. Was written out four times
/// (`problemLabel`, `fieldProblem`, and twice inline) with three different symbols.
struct SettingProblemLabel: View {
    let problem: String?

    init(_ problem: String?) { self.problem = problem }

    var body: some View {
        if let problem {
            Label(problem, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Problem: \(problem)")
        }
    }
}
