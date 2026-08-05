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
import UniformTypeIdentifiers

struct SignInSourcesSettings: View {

    @State private var settings = SignInSourceSettingsStore.shared
    @State private var sources = SignInSourceAvailability.shared
    /// Which vendor a "Configure…" click asked for, so the pane can put the
    /// keyboard on that vendor's switch rather than leaving it wherever it was.
    @FocusState private var focusedVendor: LocalVaultVendor?
    /// Which "where it was found" lists are open. Per tool, so opening one doesn't
    /// open them all.
    @State private var expandedTools: Set<String> = []
    /// The KeePass database password being typed. Never committed to `UserDefaults`
    /// and never stored here beyond the keystroke: pressing Use hands it to
    /// `KDBXMasterPasswordStore` and empties this.
    @State private var typedDatabasePassword = ""
    @State private var securityKeyCheck: KDBXSecurityKeyCheckResult?
    @State private var checkingSecurityKey = false
    @State private var databasePasswordStore = KDBXMasterPasswordStore.shared
    /// Which vault this PANE is editing, per vendor. Nothing to do with which one a
    /// VPN reads — that is level 3, in the profile.
    @State private var editingInstance: [LocalVaultVendor: SourceInstanceID] = [:]
    /// The add / rename / remove asks. Each is an alert rather than an inline field:
    /// naming a thing and destroying one both deserve a deliberate confirmation, and
    /// the removal one has to be able to NAME the VPNs that would be orphaned.
    @State private var addingTo: LocalVaultVendor?
    @State private var newInstanceName = ""
    @State private var renaming: SourceInstance?
    @State private var renameText = ""
    @State private var removing: SourceInstance?
    @Environment(SettingsRouter.self) private var router: SettingsRouter?
    /// Optional: present in the app, absent in previews. Used ONLY to name the VPNs
    /// that would be left without a vault — without it the warning still appears, it
    /// just cannot list them.
    @Environment(VPNController.self) private var vpn: VPNController?

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
        .alert("Add a \(addingTo?.instanceNoun ?? "vault")",
               isPresented: Binding(get: { addingTo != nil },
                                    set: { if !$0 { addingTo = nil } })) {
            TextField("", text: $newInstanceName,
                      prompt: Text(verbatim: addingTo.map { "\($0.instanceNoun.capitalized) 2" }
                                   ?? "Name"))
                .accessibilityLabel("Name")
            Button("Add") { commitAdd() }
            Button("Cancel", role: .cancel) { addingTo = nil }
        } message: {
            Text("Give it a name you will recognise \u{2014} \u{201C}Work\u{201D} or "
                 + "\u{201C}Personal\u{201D}, say. You point SimpleVPN at its file next.")
        }
        .alert("Rename \u{201C}\(renaming?.name ?? "")\u{201D}",
               isPresented: Binding(get: { renaming != nil },
                                    set: { if !$0 { renaming = nil } })) {
            TextField("", text: $renameText).accessibilityLabel("Name")
            Button("Rename") { commitRename() }
            Button("Cancel", role: .cancel) { renaming = nil }
        } message: {
            Text("Only the name changes. Every VPN that reads it keeps working \u{2014} they "
                 + "remember it by an identity of its own, not by its name or its path.")
        }
        .alert("Remove \u{201C}\(removing?.name ?? "")\u{201D}?",
               isPresented: Binding(get: { removing != nil },
                                    set: { if !$0 { removing = nil } })) {
            Button("Remove", role: .destructive) { commitRemove() }
            Button("Cancel", role: .cancel) { removing = nil }
        } message: {
            // NAMES the VPNs that still use it. A silently orphaned profile fails at
            // connect time, days later, with nothing to connect it to a setting
            // changed here.
            Text(removalWarning)
        }
    }

    // MARK: Adding, renaming and removing a vault

    private func commitAdd() {
        guard let vendor = addingTo else { return }
        let added = settings.instanceStore.add(named: newInstanceName, for: vendor)
        addingTo = nil
        newInstanceName = ""
        guard let added else { return }
        editingInstance[vendor] = added.id
        sources.refresh()
        AccessibilityAnnouncer.sayNow(
            "Added \(added.name). Point SimpleVPN at its file below.")
    }

    private func commitRename() {
        guard let instance = renaming else { return }
        settings.instanceStore.rename(instance.id, to: renameText, for: instance.vendor)
        renaming = nil
        sources.refresh()
        AccessibilityAnnouncer.sayNow("Renamed.")
    }

    private func commitRemove() {
        guard let instance = removing else { return }
        settings.instanceStore.remove(instance.id, for: instance.vendor)
        if editingInstance[instance.vendor] == instance.id {
            editingInstance[instance.vendor] = nil
        }
        removing = nil
        sources.refresh()
        AccessibilityAnnouncer.sayNow(
            "Removed \(instance.name). SimpleVPN has forgotten where it was; the file itself is "
            + "untouched.")
    }

    /// The removal warning, naming the VPNs that read this vault. Built from the
    /// profiles' own stored sources, so it cannot claim a VPN uses one it doesn't.
    private var removalWarning: String {
        guard let instance = removing else { return "" }
        return SignInSourceSteps.removalWarning(
            vendor: instance.vendor, name: instance.name,
            usedBy: profilesUsing(instance))
    }

    /// Which VPNs name this vault. A profile with no instance id at all counts as
    /// using the DEFAULT one, because that is exactly what it resolves to — so
    /// removing the migrated vault warns about every VPN that was set up before
    /// instances existed, which is the whole point.
    private func profilesUsing(_ instance: SourceInstance) -> [String] {
        guard let vpn else { return [] }
        let all = settings.instances(for: instance.vendor)
        return vpn.profiles.compactMap { profile in
            let source = vpn.credentialSource(for: profile.id)
            guard LocalVaultRegistry.adapter(for: source.kind)?.vendor == instance.vendor
            else { return nil }
            let resolution = SourceInstanceResolver.resolve(
                source.selection, vendor: instance.vendor, instances: all)
            return resolution.instance?.id == instance.id ? profile.name : nil
        }
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
                // LEVEL 1 — how SimpleVPN reaches this vendor at all. Per Mac, one
                // per vendor: one `keepassxc-cli`, whichever database it opens.
                ForEach(SignInSourceSettings.transportFields(for: vendor)) { field in
                    fieldRows(field)
                }
                // LEVEL 2 — WHICH vault, one or more. A vendor that declares itself
                // singular gets neither the list nor the fields, because it has
                // exactly one thing to talk to and a one-row list would be a
                // question with no answer.
                if vendor.cardinality.allowsSeveral {
                    instanceRows(vendor)
                    let chosen = chosenInstance(vendor)
                    if let chosen {
                        ForEach(SignInSourceSettings.instanceFields(for: vendor)) { field in
                            fieldRows(field, instance: chosen)
                        }
                    }
                    // Controls that are not paths. Only the `.kdbx` row has any today
                    // (a password to type and whether macOS remembers it), and they are
                    // here rather than in the generic field loop because neither is
                    // stored where a field is stored — one is in memory, the other IS a
                    // keychain item's existence. Per DATABASE, not per VPN: five VPNs
                    // reading one database must not mean five copies of its password.
                    if vendor == .keePassFile {
                        keePassUnlockRows(locked: lock != nil, instance: chosen)
                    }
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

    // MARK: Level 2 — the named vaults

    /// Which vault this pane is editing, per vendor. A choice about the SCREEN, not
    /// about any VPN: which one a VPN reads is level 3 and lives in its profile.
    private func chosenInstance(_ vendor: LocalVaultVendor) -> SourceInstance? {
        let list = settings.instances(for: vendor)
        if let wanted = editingInstance[vendor], let found = list.first(where: { $0.id == wanted }) {
            return found
        }
        return list.first
    }

    /// The list itself: one row per vault, each with ITS OWN state sentence, plus
    /// add / rename / remove. This is where "one database can be missing while
    /// another is ready" becomes visible — the vendor's own row above answers "can
    /// this vendor get me in at all", which is a different question.
    @ViewBuilder private func instanceRows(_ vendor: LocalVaultVendor) -> some View {
        let spec = specs[SignInSourceSettings.instanceListSettingID(vendor)]
        let list = settings.instances(for: vendor)
        let chosen = chosenInstance(vendor)
        let editLock = settings.instanceStore.editLockReason(vendor)
        let addLock = settings.instanceStore.addLockReason(vendor)
        EngineSettingRow(
            spec: spec,
            // "Changed" for a list means more than the one you started with.
            changed: list.count > 1,
            disabledReason: editLock
        ) {
            VStack(alignment: .leading, spacing: 6) {
                if list.isEmpty {
                    Label("No \(vendor.instanceNounPlural) yet. Add one, then point SimpleVPN at "
                          + "its file.", systemImage: "plus.circle")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(list) { instance in
                        instanceRow(vendor, instance, isChosen: instance.id == chosen?.id,
                                    locked: editLock != nil)
                    }
                }
                HStack(spacing: 8) {
                    Button("Add \(vendor.instanceNoun.capitalized)\u{2026}") {
                        addingTo = vendor
                        newInstanceName = SourceInstanceMigration.suggestedName(
                            vendor: vendor, existing: list)
                    }
                    .disabled(addLock != nil)
                    .help(addLock ?? "Set up another \(vendor.instanceNoun) with a name of "
                          + "its own")
                    .accessibilityValue(addLock.map { "unavailable \u{2014} \($0)" } ?? "")
                    .accessibilityIdentifier("creds-add-instance-\(vendor.settingSlug)")
                    Button("Rename\u{2026}") {
                        guard let chosen else { return }
                        renaming = chosen
                        renameText = chosen.name
                    }
                    .disabled(chosen == nil || editLock != nil)
                    .help(editLock ?? "Change what this \(vendor.instanceNoun) is called")
                    Button("Remove") {
                        guard let chosen else { return }
                        removing = chosen
                    }
                    .disabled(chosen == nil || editLock != nil)
                    .help(editLock ?? "Forget where this \(vendor.instanceNoun) is. The file "
                          + "itself is left as it is.")
                    Spacer(minLength: 0)
                }
                .controlSize(.small)
            }
        }
    }

    /// One vault: pick it to edit, and read what it can do right now.
    @ViewBuilder private func instanceRow(_ vendor: LocalVaultVendor, _ instance: SourceInstance,
                                         isChosen: Bool, locked: Bool) -> some View {
        let availability = sources.facts.rawAvailability(vendor, instance: instance.id)
        let copy = LocalVaultCopyBook.copy(for: vendor)
        let sentence: String = {
            switch availability {
            case .ready: return "Ready to use."
            case .notInstalled: return "Nothing found for it on this Mac."
            case .unchecked: return copy.uncheckedNote ?? "SimpleVPN checks this when you pick it."
            case .blocked(let block): return copy.headline(for: block)
            }
        }()
        Button {
            editingInstance[vendor] = instance.id
            AccessibilityAnnouncer.sayNow("\(instance.name). \(sentence)")
        } label: {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: isChosen ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(isChosen ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
                    .accessibilityHidden(true)      // selection rides the row's trait
                VStack(alignment: .leading, spacing: 1) {
                    Text(instance.name)
                        .font(.callout.weight(isChosen ? .semibold : .regular))
                    // Colour is never the only carrier: the sentence says it, and a
                    // symbol differs as well.
                    Label(sentence, systemImage: availability.isReady
                          ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(availability.isReady ? Color.secondary : Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(locked)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(instance.name)
        .accessibilityValue(sentence)
        .accessibilityHint("Shows this \(vendor.instanceNoun)\u{2019}s own file, key file and "
                           + "security-key slot below.")
        .accessibilityAddTraits(isChosen ? [.isButton, .isSelected] : .isButton)
        .accessibilityIdentifier("creds-instance-\(vendor.settingSlug)-\(instance.id.rawValue)")
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

    // MARK: The KeePass database's unlock — a secret, and where it may live

    /// The three controls that open a `.kdbx`: its password, whether macOS should
    /// remember it, and a way to check a security key BEFORE a connect depends on it.
    ///
    /// The password is the only secret this pane has ever held, so:
    ///  • it is a `SecureField`, and the title argument is EMPTY like every other
    ///    field here — the name comes from the spec (the placeholder landmine);
    ///  • what is typed is handed straight to `KDBXMasterPasswordStore` and this
    ///    view's copy is emptied, so it does not sit in SwiftUI state for the life
    ///    of the window;
    ///  • it is never written to `UserDefaults`. The only place it can be persisted
    ///    at all is the Touch ID keychain, by the toggle below it, and off is the
    ///    default.
    @ViewBuilder private func keePassUnlockRows(locked: Bool,
                                               instance: SourceInstance?) -> some View {
        let configuration = KeePassFileConfiguration.current(store: settings,
                                                            instance: instance?.id)
        let path = configuration.databasePath
        let hasDatabase = !path.trimmingCharacters(in: .whitespaces).isEmpty
        let passwordSpec = specs[SignInSourceSettings.keePassPasswordSettingID]
        let rememberSpec = specs[SignInSourceSettings.keePassRememberPasswordSettingID]
        let remembered = hasDatabase && databasePasswordStore.isRemembered(database: path)

        EngineSettingRow(
            spec: passwordSpec, changed: false,
            disabledReason: locked ? "Your organization has locked SimpleVPN\u{2019}s settings."
                : (hasDatabase ? nil : "Choose your KeePass database first.")
        ) {
            LabeledContent {
                HStack(spacing: 6) {
                    SecureField("", text: $typedDatabasePassword,
                                prompt: Text("Your database\u{2019}s password"))
                        .onSubmit { commitDatabasePassword(path: path, remember: remembered) }
                        .accessibilityLabel(passwordSpec.name)
                        // Never the value, and never a length: what is spoken is what
                        // SimpleVPN is holding, which is the thing a user needs to know.
                        .accessibilityValue(databasePasswordStore.heldDescription(database: path))
                        .accessibilityIdentifier("creds-field-keepassfile-password")
                    Button("Use") { commitDatabasePassword(path: path, remember: remembered) }
                        .disabled(typedDatabasePassword.isEmpty || !hasDatabase || locked)
                        .help(typedDatabasePassword.isEmpty
                              ? "Type your database\u{2019}s password first"
                              : "Let SimpleVPN open your database with this")
                        .accessibilityValue(typedDatabasePassword.isEmpty
                                            ? "unavailable \u{2014} nothing typed" : "")
                }
                .controlSize(.small)
            } label: {
                EngineSettingLabel(spec: passwordSpec, value: "")
            }
        }

        Label(databasePasswordStore.heldDescription(database: path),
              systemImage: remembered ? "touchid"
                : (databasePasswordStore.isHeldForThisRun(database: path)
                   ? "clock" : "keyboard"))
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("What SimpleVPN is holding")
            .accessibilityValue(databasePasswordStore.heldDescription(database: path))

        EngineSettingRow(
            spec: rememberSpec, changed: rememberSpec.isChanged(remembered),
            disabledReason: locked ? "Your organization has locked SimpleVPN\u{2019}s settings."
                : (databasePasswordStore.canRemember
                   ? (hasDatabase ? nil : "Choose your KeePass database first.")
                   : "This Mac can\u{2019}t ask for a fingerprint, an Apple Watch or your password.")
        ) {
            Toggle(isOn: Binding(
                get: { remembered },
                set: { on in setRememberDatabasePassword(on, path: path) })) {
                    EngineSettingLabel(spec: rememberSpec, value: remembered)
                }
        }

        if !remembered, databasePasswordStore.isHeldForThisRun(database: path) {
            Text("Turning this on remembers what SimpleVPN is holding now. macOS won\u{2019}t hand it "
                 + "back without a fingerprint, your Apple Watch, or this Mac\u{2019}s password.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }

        if databasePasswordStore.isHeldForThisRun(database: path) || remembered {
            Button("Forget This Database\u{2019}s Password") {
                databasePasswordStore.forgetThisRun(database: path)
                databasePasswordStore.forgetRemembered(database: path)
                KeePassFileUnlockMemory.shared.clear(database: path)
                sources.refresh()
                AccessibilityAnnouncer.sayNow("Database password forgotten.")
            }
            .controlSize(.small)
            .disabled(locked)
            .help("Drop it from this run and from the keychain")
        }

        // The security-key check. Offered only when a slot is set, because that is
        // what says this database uses one at all — and it is a BUTTON rather than
        // something that happens on its own, because it may ask for a finger.
        if let slot = configuration.slot, hasDatabase {
            Button(checkingSecurityKey ? "Touch Your Security Key\u{2026}"
                                       : "Check My Security Key") {
                Task { await runSecurityKeyCheck(path: path, slot: slot,
                                                 serial: configuration.serial) }
            }
            .controlSize(.small)
            .disabled(checkingSecurityKey)
            .help("Ask your key to answer this database\u{2019}s challenge, once")
            .accessibilityValue(checkingSecurityKey
                                ? "waiting for you to touch your security key" : "")
            .accessibilityHint("Sends this database\u{2019}s own challenge to \(slot.displayName) and "
                               + "says whether your key answered. It doesn\u{2019}t open the database.")
            if let securityKeyCheck {
                Label(securityKeyCheck.sentence,
                      systemImage: securityKeyCheck.succeeded ? "checkmark.circle.fill"
                                                              : "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(securityKeyCheck.succeeded ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("Security key check")
                    .accessibilityValue(securityKeyCheck.sentence)
            }
        }
    }

    private func commitDatabasePassword(path: String, remember: Bool) {
        guard !typedDatabasePassword.isEmpty, !path.isEmpty else { return }
        let password = KDBXPassword(typedDatabasePassword)
        // Emptied immediately: the secret belongs in the store, not in a view's state
        // for as long as the window is open.
        typedDatabasePassword = ""
        if remember {
            try? databasePasswordStore.remember(password, database: path)
        } else {
            databasePasswordStore.holdForThisRun(password, database: path)
        }
        // A new password retires "the database refused the last attempt": the row must
        // go back to offering a try rather than repeating an accusation.
        KeePassFileUnlockMemory.shared.clear(database: path)
        sources.refresh()
        AccessibilityAnnouncer.sayNow(databasePasswordStore.heldDescription(database: path))
    }

    private func setRememberDatabasePassword(_ on: Bool, path: String) {
        guard !path.isEmpty else { return }
        if on {
            // Only possible when something is held: there is nothing to remember
            // otherwise, and the row says so rather than silently doing nothing.
            Task {
                guard let held = try? await databasePasswordStore.password(
                    database: path, reason: "remember your KeePass database\u{2019}s password")
                else {
                    AccessibilityAnnouncer.sayNow(
                        "Type your database\u{2019}s password first, then turn this on.")
                    return
                }
                try? databasePasswordStore.remember(held, database: path)
                sources.refresh()
                AccessibilityAnnouncer.sayNow("Remembered behind Touch ID.")
            }
        } else {
            databasePasswordStore.forgetRemembered(database: path)
            sources.refresh()
            AccessibilityAnnouncer.sayNow("No longer remembered.")
        }
    }

    private func runSecurityKeyCheck(path: String, slot: YubiKeySlot, serial: String) async {
        checkingSecurityKey = true
        defer { checkingSecurityKey = false }
        securityKeyCheck = nil
        AccessibilityAnnouncer.sayNow("Touch your security key now.")
        guard let facts = KeePassDatabaseFile.classify(path: path).facts else {
            securityKeyCheck = .noChallengeAvailable
            AccessibilityAnnouncer.sayNow(KDBXSecurityKeyCheckResult.noChallengeAvailable.sentence)
            return
        }
        let result = await KeePassSecurityKeyCheck.run(
            facts: facts, slot: slot, serial: serial.isEmpty ? nil : serial)
        securityKeyCheck = result
        AccessibilityAnnouncer.sayNow(result.sentence)
    }

    // MARK: One field — the value/suggestion distinction, made visible AND audible

    /// `instance` is the level-2 vault whose value this row edits, and is nil for a
    /// level-1 field (a tool path, a socket, an endpoint) — which is per Mac and
    /// belongs to no single vault.
    @ViewBuilder private func fieldRows(_ field: VendorConfigField,
                                        instance: SourceInstance? = nil) -> some View {
        let spec = specs[field.settingID]
        let shown = settings.presentation(for: field, instance: instance)
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
                    set: { settings.setValue($0, for: field, instance: instance) }),
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
        validationRow(shown, field: field, instance: instance)
    }

    /// The validation sentence, plus the detection as its own labelled row, plus
    /// the two keyboard-reachable ways back — so a user who has broken a path never
    /// has to retype one.
    @ViewBuilder private func validationRow(_ shown: VendorFieldPresentation,
                                           field: VendorConfigField,
                                           instance: SourceInstance? = nil) -> some View {
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
                    // A file-shaped field gets a picker as well as the text box. Not
                    // instead of it: a typed path must always work (it is what MDM
                    // pins, what a script sets and what someone reading over a
                    // shoulder can follow), and a picker that was the ONLY way in
                    // would make an iCloud path impossible to paste. Both, always.
                    if let prompt = filePickerPrompt(field.kind) {
                        Button(prompt.buttonTitle) {
                            chooseFile(for: field, prompt: prompt, instance: instance)
                        }
                            .help(prompt.help)
                    }
                    Button("Use What SimpleVPN Found") { settings.resetToDetected(field) }
                        .disabled(!shown.canResetToDetected)
                        .help(shown.canResetToDetected
                              ? "Put the path SimpleVPN found into this field"
                              : (shown.detectedPath == nil
                                 ? "SimpleVPN hasn\u{2019}t found one to use"
                                 : "That is already what this is set to"))
                        .accessibilityValue(shown.canResetToDetected ? ""
                            : "unavailable \u{2014} \(shown.detectedPath == nil ? "nothing was found" : "already set to it")")
                    Button("Clear") { settings.setValue("", for: field, instance: instance) }
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

    // MARK: Picking a file rather than typing its path

    /// What a file picker for this field kind should say, or nil for a field that
    /// isn't a file.
    private func filePickerPrompt(_ kind: VendorConfigFieldKind)
        -> (buttonTitle: String, help: String, extensions: [String])? {
        switch kind {
        case .vaultFile(let extensions):
            ("Choose Database\u{2026}",
             "Pick your KeePass database in the Finder instead of typing its path",
             extensions)
        case .keyFile:
            // Deliberately no extension filter: KeePassXC writes `.keyx`, older
            // releases wrote `.key`, and a hand-made key file often has no extension
            // at all. Filtering would hide the very file somebody was told to pick.
            ("Choose Key File\u{2026}",
             "Pick your key file in the Finder instead of typing its path", [])
        case .toolBinary, .unixSocket, .daemonEndpoint, .securityKeySlot, .pkcs11Module:
            nil
        }
    }

    /// An `NSOpenPanel`, which is also how the path gets there for a file inside a
    /// container the app has no standing access to: the app is not sandboxed, so this
    /// is a convenience rather than a permission grant — but a user-chosen path is
    /// also the thing macOS's own privacy controls treat most kindly.
    private func chooseFile(for field: VendorConfigField,
                            prompt: (buttonTitle: String, help: String, extensions: [String]),
                            instance: SourceInstance? = nil) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = prompt.help
        panel.prompt = "Use"
        // Placeholders for a file kept in iCloud Drive must be selectable: choosing
        // one is exactly how somebody points at a database that hasn't come down yet,
        // and the state row then explains that it is on its way.
        panel.canDownloadUbiquitousContents = true
        if !prompt.extensions.isEmpty {
            panel.allowedContentTypes = prompt.extensions.compactMap {
                UTType(filenameExtension: $0)
            }
            // …and never ONLY those types: a database with a non-standard extension is
            // legitimate and must still be choosable.
            panel.allowsOtherFileTypes = true
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        settings.setValue(url.path, for: field, instance: instance)
        AccessibilityAnnouncer.sayNow("Chose \(url.lastPathComponent).")
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
