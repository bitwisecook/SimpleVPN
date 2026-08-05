// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourcesSettings.swift
//  Settings ▸ Sign-In Sources: which password apps SimpleVPN may use, and where
//  each one's tool is on this Mac.
//
//  THE ONE THING THIS FILE MUST NOT GET WRONG. A detected path is a SUGGESTION.
//  This project already shipped the bug once — `TextField("example", text:)` passes
//  the string as the field's TITLE, `LabeledContent` renders titles as visible
//  content, so the example appeared where the value goes and VoiceOver read it out
//  as the field's NAME. Twenty-six sites were fixed for it.
//
//  A pre-filled guess makes that failure far more attractive and far more harmful:
//  if a detected path can appear as a value, nobody can tell whether the path in
//  front of them is a setting they made or a guess we made — and "Reset to
//  Detected" stops meaning anything. So:
//
//    • every field is `LabeledContent { TextField("", text:, prompt:) } label: {
//      EngineSettingLabel(spec:) }`. The title argument is EMPTY, always. The name
//      comes from the spec, which is also what search finds and what the manual
//      documents.
//    • the suggestion lives in `prompt:` — placeholder only — and in its own
//      "SimpleVPN found" row, which is a LabeledContent whose value is plainly
//      labelled as a detection.
//    • what a screen reader hears is `presentation.accessibilityValue`, which SAYS
//      which of the two it is ("Not set. SimpleVPN uses the one it found: …" versus
//      the path itself followed by its validation). Grey-versus-black is not
//      available to VoiceOver, so the distinction is carried in words.
//
//  `VendorFieldPresentation` derives all of that, so the rule is a tested function
//  rather than a habit in a view (SignInSourceSettingsTests).
//
//  Everything else here follows the house patterns: `EngineSettingRow` for the
//  label/summary/manual-link/reveal treatment, a plain-language line under every
//  control, the canonical Sign-In group, a "Managed by Your Organization" block
//  when policy is in force, and no hover-only content anywhere.
//

import SwiftUI
import AppKit

struct SignInSourcesSettings: View {

    @State private var settings = SignInSourceSettingsStore.shared
    @State private var sources = SignInSourceAvailability.shared
    /// Which vendor a "Configure…" click asked for, so the pane can put the
    /// keyboard on that vendor's switch rather than leaving it wherever it was.
    @FocusState private var focusedVendor: LocalVaultVendor?
    /// Which "where it was found" lists are open. Per tool, so opening one doesn't
    /// open them all.
    @State private var expandedTools: Set<String> = []
    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    private var specs: EngineSettingCatalog { CredentialSourceSettings.catalog }

    var body: some View {
        Form {
            Section("Finding Your Password Apps") {
                let spec = specs[SignInSourceSettings.discoverySettingID]
                EngineSettingRow(
                    spec: spec,
                    changed: spec.isChanged(settings.discoveryEnabled),
                    disabledReason: settings.discoveryLockedByPolicy
                        ? "Your organization decides this." : nil
                ) {
                    Toggle(isOn: Binding(
                        get: { settings.discoveryEnabled },
                        set: { settings.setDiscoveryEnabled($0) })) {
                            EngineSettingLabel(spec: spec, value: settings.discoveryEnabled)
                        }
                }
                if !settings.discoveryEnabled {
                    Label("SimpleVPN isn\u{2019}t looking. You can still type your sign-in, save it in "
                          + "the Apple keychain, or use Apple Passwords.",
                          systemImage: "eye.slash")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            ForEach(LocalVaultVendor.allCases, id: \.self) { vendor in
                vendorSection(vendor)
            }

            // Tools that are not password apps but still need a path. Here rather
            // than in a surface of their own: the security-key feed resolves `ykman`
            // through the same `signin.tool.<name>.path` override this row writes, so
            // one pane answers "where is that tool" for everything.
            if !SignInSourceSettings.standaloneToolFields.isEmpty {
                Section("Other Tools") {
                    ForEach(SignInSourceSettings.standaloneToolFields) { field in
                        fieldRows(field)
                        ForEach(discoveries(for: field)) { found in
                            discoveryDisclosure(found)
                        }
                    }
                    Text("SimpleVPN uses these when a VPN\u{2019}s sign-in needs them. The same rules "
                         + "apply: leave a path empty and SimpleVPN uses the one it found, or set it "
                         + "when your copy is somewhere SimpleVPN doesn\u{2019}t look on its own.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if ManagedSignInSourcePolicy.isManaged() || ManagedPolicy.lockConfiguration {
                Section("Managed by Your Organization") {
                    ForEach(ManagedSignInSourcePolicy.activeSummary(), id: \.self) { line in
                        Label(line, systemImage: "lock.fill")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if ManagedPolicy.lockConfiguration {
                        Label("SimpleVPN\u{2019}s settings are locked.", systemImage: "lock.fill")
                            .font(.callout)
                    }
                    Text("These are enforced by your organization\u{2019}s device management and "
                         + "can\u{2019}t be changed here.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            sources.refresh()
            followRoute()
        }
        .onChange(of: router?.appSettingsGeneration ?? 0) { followRoute() }
        .task { await sources.deepScan() }
    }

    /// The discovery map this pane draws from. `sources.discoveries` is the observable
    /// mirror the deep pass fills in (and where measured versions land); before it has
    /// run, the cache is the same answer without them. One map either way — a second
    /// scan of its own would be a different answer on the same screen.
    private var map: [String: DiscoveredTool] {
        guard settings.discoveryEnabled else { return [:] }
        let published = sources.discoveries
        return published.isEmpty ? ToolDiscovery.cachedMap() : published
    }

    private func discoveries(for vendor: LocalVaultVendor) -> [DiscoveredTool] {
        ToolCatalog.tools(for: vendor).compactMap { map[$0.name] }
    }

    /// What discovery found for one field's tool, so the "where it was found" list
    /// works for a standalone tool exactly as it does for a vendor's.
    private func discoveries(for field: VendorConfigField) -> [DiscoveredTool] {
        guard let tool = field.kind.detectionTool, let found = map[tool] else { return [] }
        return [found]
    }

    /// A route that named a vendor puts the keyboard on that vendor's switch. Arriving
    /// from "Configure… " on a chooser row and then having to hunt for the vendor
    /// would make the affordance a signpost rather than a shortcut.
    private func followRoute() {
        guard let id = router?.appSettingsRoute?.settingID,
              let vendor = CredentialSourceSettings.vendor(forSettingID: id) else { return }
        focusedVendor = vendor
        AccessibilityAnnouncer.sayNow("\(vendor.displayTitle) settings.")
    }

    // MARK: One vendor

    @ViewBuilder private func vendorSection(_ vendor: LocalVaultVendor) -> some View {
        let copy = LocalVaultCopyBook.copy(for: vendor)
        let spec = specs[SignInSourceSettings.enabledSettingID(vendor)]
        let enabled = settings.isEnabled(vendor)
        let lock = settings.lockReason(vendor)
        Section(copy.title) {
            EngineSettingRow(spec: spec, changed: spec.isChanged(enabled),
                             disabledReason: lock) {
                Toggle(isOn: Binding(get: { enabled },
                                     set: { settings.setEnabled($0, for: vendor) })) {
                    EngineSettingLabel(spec: spec, value: enabled)
                }
            }
            .focused($focusedVendor, equals: vendor)

            // What this Mac actually has. Shown whether or not the vendor is on,
            // because "installed, and you turned it off" is a fact someone looking
            // at this pane needs — it is the one place allowed to see past the
            // switch (`rawAvailability`).
            stateRow(vendor, enabled: enabled)

            // MATURITY IS A DIFFERENT AXIS FROM THE ROW ABOVE, and the two must not
            // be read as one. `stateRow` answers "what does this Mac have right
            // now" — a live probe that changes when the user installs something.
            // This answers "has the code that talks to it ever been proven" — a
            // constant that changes only when somebody reports a result. “Ready to
            // use” and “Untested” together is not a contradiction; it is the normal
            // state of a freshly written adapter. Nothing here consults the probe,
            // and the claim lives one line deep in the maturity registry.
            if let notice = MaturityNotice.forSignInSource(id: .vault(vendor),
                                                           title: copy.title) {
                MaturityBanner(notice: notice,
                               request: .init(kind: nil, profileID: nil,
                                              reason: .untestedSource))
            }

            if enabled {
                ForEach(SignInSourceSettings.fields(for: vendor)) { field in
                    fieldRows(field)
                }
                // From `sources.discoveries` — the observable mirror of the ONE
                // discovery map, so the version this pane prints is the version the
                // banners and any report see, and it appears here as soon as the deep
                // pass has measured it.
                ForEach(discoveries(for: vendor)) { found in
                    discoveryDisclosure(found)
                }
            }
        }
    }

    /// The vendor's live state in words. Never a status code, and never only a
    /// colour: the label's text carries it, so VoiceOver gets the same sentence.
    @ViewBuilder private func stateRow(_ vendor: LocalVaultVendor, enabled: Bool) -> some View {
        let availability = sources.facts.rawAvailability(vendor)
        let copy = LocalVaultCopyBook.copy(for: vendor)
        let sentence: String = {
            guard enabled else {
                return availability == .notInstalled
                    ? "Switched off. Nothing for it was found on this Mac either."
                    : "Switched off, so SimpleVPN neither offers it nor mentions it."
            }
            switch availability {
            case .notInstalled: return "Not found on this Mac."
            case .ready: return "Ready to use."
            case .unchecked: return copy.uncheckedNote ?? "SimpleVPN checks this when you pick it."
            case .blocked(let block): return copy.headline(for: block)
            }
        }()
        let symbol: String = {
            guard enabled else { return "circle.slash" }
            switch availability {
            case .ready: return "checkmark.circle.fill"
            case .notInstalled: return "questionmark.circle"
            case .unchecked: return "clock"
            case .blocked: return "exclamationmark.triangle.fill"
            }
        }()
        LabeledContent("On this Mac") {
            Label(sentence, systemImage: symbol)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(copy.title) on this Mac")
        .accessibilityValue(sentence)
    }

    // MARK: One field — the value/suggestion distinction, made visible AND audible

    @ViewBuilder private func fieldRows(_ field: VendorConfigField) -> some View {
        let spec = specs[field.settingID]
        let shown = settings.presentation(for: field)
        EngineSettingRow(
            spec: spec,
            changed: spec.isChanged(shown.value),
            disabledReason: shown.isLockedByPolicy
                ? "Your organization has set this path."
                : (ManagedPolicy.lockConfiguration ? "Your organization has locked SimpleVPN\u{2019}s settings." : nil)
        ) {
            LabeledContent {
                // The title argument is EMPTY. The name comes from the spec's
                // label; the example or detection is `prompt:` and nothing else.
                TextField("", text: Binding(
                    get: { shown.value },
                    set: { settings.setValue($0, for: field) }),
                          prompt: Text(shown.prompt))
                    .autocorrectionDisabled()
                    .textContentType(nil)
                    .accessibilityLabel(spec.name)
                    // What is spoken SAYS whether this is a value or a suggestion —
                    // the visual grey placeholder cannot.
                    .accessibilityValue(shown.accessibilityValue)
                    .accessibilityIdentifier("creds-field-\(field.settingID)")
            } label: {
                EngineSettingLabel(spec: spec, value: shown.value)
            }
        }
        validationRow(shown, field: field)
    }

    /// The validation sentence, plus the detection as its own labelled row, plus
    /// the two keyboard-reachable ways back — so a user who has broken a path never
    /// has to retype one.
    @ViewBuilder private func validationRow(_ shown: VendorFieldPresentation,
                                           field: VendorConfigField) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if let symbol = shown.validation.symbolName {
                Label(shown.validation.sentence, systemImage: symbol)
                    .font(.callout)
                    .foregroundStyle(shown.validation.isProblem ? .orange
                                     : (shown.validation == .sanctioned ? .primary : .secondary))
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text(shown.validation.sentence)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let detected = shown.detectedPath {
                // A SEPARATE row, explicitly labelled as a detection. This is the
                // other half of the value/suggestion distinction: the suggestion has
                // its own place on screen, so it is never mistaken for the setting.
                LabeledContent("SimpleVPN found") {
                    Text(detected)
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("SimpleVPN found this one on your Mac")
                .accessibilityValue(detected)
            }
            if !shown.isLockedByPolicy {
                HStack(spacing: 8) {
                    Button("Use What SimpleVPN Found") { settings.resetToDetected(field) }
                        .disabled(!shown.canResetToDetected)
                        .help(shown.canResetToDetected
                              ? "Put the path SimpleVPN found into this field"
                              : (shown.detectedPath == nil
                                 ? "SimpleVPN hasn\u{2019}t found one to use"
                                 : "That is already what this is set to"))
                        .accessibilityValue(shown.canResetToDetected ? ""
                            : "unavailable \u{2014} \(shown.detectedPath == nil ? "nothing was found" : "already set to it")")
                    Button("Clear") { settings.clear(field) }
                        .disabled(!shown.isSet)
                        .help(shown.isSet
                              ? "Empty this field and let SimpleVPN decide"
                              : "Nothing is set, so there is nothing to clear")
                        .accessibilityValue(shown.isSet ? "" : "unavailable \u{2014} nothing is set")
                    Spacer(minLength: 0)
                }
                .controlSize(.small)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Everywhere a tool was found

    /// The discovery map for one tool: EVERY path, what put it there, and whether
    /// SimpleVPN would run it — collapsed by default, because most people never
    /// need it and the one person debugging needs all of it.
    ///
    /// This is where the discovery/execution split becomes visible: a row can say
    /// "found here, and SimpleVPN won't run it from here", which is the truth the
    /// bare word "installed" cannot express.
    @ViewBuilder private func discoveryDisclosure(_ found: DiscoveredTool) -> some View {
        let title = ToolCatalog.tool(named: found.tool)?.title ?? found.tool
        let open = expandedTools.contains(found.tool)
        VStack(alignment: .leading, spacing: 6) {
            // A Button, not a DisclosureGroup: the whole row is then the hit target,
            // Tab reaches it and Space activates it. (`CollapsibleSettingsSection`
            // is the house idiom for collapsing a canonical GROUP and is keyed to
            // one — this is a detail list inside a vendor's section, which is a
            // different thing, so it is not that component's job.)
            Button {
                if open { expandedTools.remove(found.tool) } else { expandedTools.insert(found.tool) }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption).foregroundStyle(.secondary)
                        .accessibilityHidden(true)      // state rides the button's value
                    Text(found.isFound
                         ? "Where SimpleVPN found \(title) (\(found.paths.count))"
                         : "\(title) wasn\u{2019}t found")
                        .font(.callout)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(found.isFound
                                ? "Where SimpleVPN found \(title), \(found.paths.count) places"
                                : "\(title) wasn\u{2019}t found")
            .accessibilityValue(open ? "showing" : "hidden")
            .accessibilityHint("Lists every place \(title) was found, and whether SimpleVPN will "
                               + "run it from there.")
            if open {
                detail(found, title: title)
                    .padding(.leading, 16)
            }
        }
        .accessibilityElement(children: .contain)
    }

    /// One tool's every hit, each stating in WORDS whether SimpleVPN will run it from
    /// there. This is where the discovery/execution split becomes visible, and the
    /// wording is the point: "found here, and SimpleVPN won't run it from here" is a
    /// truth the bare word "installed" cannot express.
    @ViewBuilder private func detail(_ found: DiscoveredTool, title: String) -> some View {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(found.paths) { hit in
                    Label(hit.explanation,
                          systemImage: hit.usability.isRunnableNow ? "checkmark.circle.fill"
                            : (hit.usability == .outsideAllowList ? "hand.raised.circle.fill"
                               : "exclamationmark.triangle.fill"))
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(hit.explanation)
                }
                if found.paths.isEmpty {
                    Text("SimpleVPN didn\u{2019}t find \(title) anywhere on this Mac.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                LabeledContent("Version", value: found.version.displayValue)
                    .font(.callout)
                if case .unknown(let why) = found.version {
                    Text("SimpleVPN hasn\u{2019}t asked \u{2014} \(why). It only ever runs a program "
                         + "from a folder it trusts, so it won\u{2019}t start one just to read a "
                         + "version number.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
