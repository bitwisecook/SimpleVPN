// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FirstConnectSetupCard.swift
//  First-connect hand-holding for the detail column. An imported config
//  describes the TRANSPORT, not the sign-in, so until a VPN has connected
//  successfully once this card asks the two questions that otherwise ambush
//  people at connect time — one-time code? and where does the sign-in live? —
//  including the 1Password drag-in. ConnectionDetailView decides when it shows.
//
//  The "where does your sign-in live?" half used to be a four-item menu listing
//  every manager whether or not it was installed. It is now
//  `SignInSourceChooser`: the same question, but only over the sources that
//  really exist on this Mac, with a plain sentence each, and with the password
//  apps we CANNOT read listed separately as pointers rather than hidden (that
//  list is the answer to "where is my password?", which is the question someone
//  staring at an empty field is actually asking).
//
//  This card is deliberately the ONE first-run surface — extended, not joined by
//  a competitor. It already appears exactly when the flow needs a chooser (no
//  successful connect yet), it already owns the OTP question the chooser's
//  wording refers to, and it already hosts the per-source detail (the 1Password
//  drag-in well, Apple Passwords' system picker, and the address a KeePassXC
//  lookup or Keeper record matches).
//  A second sheet or window would have to duplicate all of that and then argue
//  with this card about which of them was showing.
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// First-connect hand-holding. An imported config describes the TRANSPORT, not
/// the sign-in — so until this VPN has connected successfully once, the main
/// window itself asks the two questions that otherwise ambush people at connect
/// time: "do you also enter a one-time code?" and "where does your sign-in
/// live?" — with the password-manager choice (and its drag-in) right here, no
/// trip to Manage VPNs. Disappears forever after the first proven connect.
struct FirstConnectSetupCard: View {   // was private — internal for the file split
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    /// The profile's own verdict on saving a password (`auth-nocache` says no) —
    /// passed in rather than re-derived, so the card and the form below it can
    /// never disagree about whether the keychain row is on offer.
    var allowsPasswordSave = true
    /// This same surface is also used by Change… after a connection has
    /// succeeded.  Keeping one configuration view prevents a second, taller
    /// source chooser from drifting away from the first-connect experience.
    var isFirstConnection = true
    @Binding var dismissed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.liveVisualPolicy) private var liveVisuals
    @State private var apServer = ""
    /// A multi-selection drag, waiting to be narrowed to the one item this VPN
    /// signs in with. Empty = nothing pending.
    @State private var choices: [OnePasswordDrop] = []
    @State private var onePasswordDrops = OnePasswordDropCollector()
    /// The 1Password setup check — run when 1Password is CHOSEN here, never on
    /// appear, and skipped once the integration has been proven to work.
    @State private var preflight = OnePasswordPreflightModel()
    @State private var isOnePasswordDropTargeted = false
    @State private var onePasswordDropError: String?
    @State private var onePasswordItems: [OnePasswordNative.OPItemInVault] = []
    @State private var loadingOnePasswordItems = false
    @State private var showOnePasswordBrowser = false
    @State private var onePasswordBrowseError: String?
    /// The selected entry's field list, loaded only after the person explicitly
    /// asks SimpleVPN to use that entry.  It powers the same mapping sheet as
    /// Manage VPNs, rather than inventing a smaller first-run-only mapper.
    @State private var opFields: [OnePasswordProvider.OPField] = []
    @State private var opItemTitle = ""
    /// A momentary, non-secret description of the linked 1Password entry.  It
    /// lets the person see what will be supplied without turning the app into
    /// another password store.
    @State private var opInspection: OnePasswordProvider.EntryInspection?
    @State private var loadingOPFields = false
    @State private var showFieldMap = false
    /// What this Mac can actually offer. Shared app-wide so one set of probes
    /// serves every surface.
    @State private var sources = SignInSourceAvailability.shared
    @State private var signInSettings = SignInSourceSettingsStore.shared
    @Environment(SettingsRouter.self) private var settingsRouter: SettingsRouter?

    private var auth: VPNAuthConfig { vpn.authConfig(for: profile.id) }
    private var source: CredentialSource { vpn.credentialSource(for: profile.id) }
    private var facts: SignInSourceFacts { sources.facts(allowsPasswordSave: allowsPasswordSave) }
    /// The row that matches what this VPN is set to right now.
    private var selectedID: SignInSourceID? {
        switch source.kind {
        case .manual: vpn.remembersPassword(for: profile.id) ? .saveInSimpleVPN : .typeEachTime
        case .applePasswords: .applePasswords
        default: LocalVaultRegistry.adapter(for: source.kind).map { .vault($0.vendor) }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(isFirstConnection ? "Before your first connect" : "Set up your sign-in",
                      systemImage: isFirstConnection ? "hand.wave" : "person.badge.key")
                    .font(.callout.weight(.semibold))
                Spacer()
                Button { dismissed = true } label: {
                    Image(systemName: "xmark").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                    .buttonStyle(.borderless)
                    .help(isFirstConnection
                          ? "Hide until next launch — this card comes back until a connect succeeds"
                          : "Close sign-in setup")
                    .accessibilityLabel(isFirstConnection ? "Hide setup card" : "Close sign-in setup")
            }
            Text(isFirstConnection
                 ? "The configuration file says how to reach \(profile.name) — but not how you sign in. Choose where the sign-in comes from, then check whether it needs a verification code."
                 : "Choose where \(profile.name)'s sign-in comes from, then check whether it needs a verification code.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                GridRow {
                    Text("Where your sign-in comes from")
                        .foregroundStyle(.secondary)
                        .gridColumnAlignment(.trailing)
                    SignInSourcePicker(
                        options: SignInSourceCatalog.options(facts),
                        selection: selectedID,
                        onChoose: choose)
                }
            }
            .frame(maxWidth: 520, alignment: .leading)

            switch source.kind {
            case .manual:
                EmptyView()   // the credential form directly below IS the answer
            case .onePassword:
                onePasswordConfiguration
            case .applePasswords:
                VStack(alignment: .leading, spacing: 8) {
                    ApplePasswordsPickerButton(onPick: useApplePassword)
                    Text("macOS owns this searchable picker and its authorization. SimpleVPN receives only the one username and password you choose, for this connection.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            case .keePassXC:
                // Same one-field shape as Apple Passwords: KeePassXC finds the
                // entry by matching this address against each entry's URL field.
                HStack {
                    TextField("Address the KeePassXC entry's URL matches", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveKeePassXC)
                    Button("Use") { saveKeePassXC() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.server : source.reference
                }
                Text("The first connect asks KeePassXC to pair \u{2014} give the connection a name (\u{201C}SimpleVPN\u{201D}) when it asks.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .keeper:
                // Keeper names a RECORD, not an address: Commander takes the
                // record's title, its UID, or its folder path.
                HStack {
                    TextField("Keeper record name, UID, or folder path", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveKeeper)
                    Button("Use") { saveKeeper() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("SimpleVPN asks Keeper Commander for just this record. It never changes Commander\u{2019}s own setup.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .bitwarden:
                // Bitwarden names an ITEM: its own ID, or anything its search matches.
                HStack {
                    TextField("Bitwarden item name or ID", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveBitwarden)
                    Button("Use") { saveBitwarden() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("SimpleVPN reads just this item. Leave \u{201C}bw serve\u{201D} running and Bitwarden keeps the unlock \u{2014} SimpleVPN never sees the key that unlocks your vault.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .dashlane:
                // Dashlane matches an ADDRESS or a TITLE, so the field's prompt names
                // both — and the profile's server is the better pre-fill, because a
                // Dashlane entry for a VPN almost always carries its address.
                HStack {
                    TextField("Dashlane entry\u{2019}s address or title", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveDashlane)
                    Button("Use") { saveDashlane() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.server : source.reference
                }
                Text("SimpleVPN asks Dashlane to print just this entry, never to copy it \u{2014} your password never lands on the clipboard.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .keePassFile:
                // TWO QUESTIONS, in order, even in this small card: WHICH database
                // (you may have a work one and a personal one) and WHICH entry in it.
                // The step numbering is what stops the second field reading as the
                // whole answer.
                keePassFileDatabaseStep
                // A `.kdbx` entry is named by its PATH in the database — its groups
                // and its title, separated by slashes. Not an address: the file has no
                // URL matching of its own, which is the one place this row differs
                // from the KeePassXC row above it.
                Text(SignInSourceSteps.stepTwoTitle(vendor: .keePassFile,
                                                    instanceName: keePassFileDatabaseName))
                    .font(.caption.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                HStack {
                    TextField("Entry path in your database, for example VPN/Work", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveKeePassFile)
                        .accessibilityLabel(SignInSourceSteps.stepTwoTitle(
                            vendor: .keePassFile, instanceName: keePassFileDatabaseName))
                        .accessibilityValue(SignInSourceSteps.spokenStep(
                            2, of: .keePassFile,
                            chosen: apServer.isEmpty ? nil : apServer))
                    Button("Use") { saveKeePassFile() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("Your databases, and their passwords, are set up in Settings \u{25B8} Sign-In Sources; this VPN just says which of them to read. SimpleVPN only ever reads your database.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .passwordStore:
                // One question in this compact card: which entry. WHICH store is a
                // settings-level choice (and most people have exactly one), so it is
                // pointed at rather than asked here — the editor's Sign-In tab shows
                // the full two-step store-then-entry picker for anyone with several.
                Text(SignInSourceSteps.stepTwoSummary(vendor: .passwordStore))
                    .font(.caption.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                HStack {
                    TextField("Entry", text: $apServer,
                              prompt: Text("Entry name in your store, for example vpn/work"))
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(savePasswordStore)
                        .accessibilityLabel("Entry name in your password store")
                        .accessibilityValue(apServer.isEmpty
                            ? "Not set. For example, vpn slash work."
                            : apServer)
                    Button("Save", action: savePasswordStore)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("Your store folder is set up in Settings \u{25B8} Sign-In Sources; this VPN just says which entry to read. SimpleVPN reads your store with GnuPG and never writes to it.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .lastPass:
                // ONE question, and the prompt has to carry the whole shape of an
                // answer: `lpass` matches names EXACTLY, so an entry inside folders
                // needs its folders typed. Getting that wrong reads as "LastPass
                // doesn't have my password", which is the wrong conclusion entirely.
                HStack {
                    TextField("Entry", text: $apServer,
                              prompt: Text(verbatim: "Work/VPN/GR Lab"))
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveLastPass)
                        .accessibilityLabel("LastPass entry name or id")
                        .accessibilityValue(apServer.isEmpty
                            ? "Not set. The name has to match exactly, including its folders \u{2014} for example Work slash VPN slash GR Lab."
                            : apServer)
                    Button("Save", action: saveLastPass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("SimpleVPN reads just this entry with LastPass\u{2019}s own command-line tool, and reads only its username and password. You type the verification code yourself \u{2014} LastPass\u{2019}s tool has no way to give one.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .protonPass:
                // ONE field, and it holds BOTH halves of the address — the vault and
                // the item. Not two fields: Proton's own reference syntax is one
                // string, and splitting it here would mean re-joining it to store it
                // and re-splitting it to show it.
                HStack {
                    TextField("Item", text: $apServer,
                              prompt: Text("Vault and item, for example Work/GR Lab"))
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveProtonPass)
                        .accessibilityLabel("Proton Pass vault and item")
                        .accessibilityValue(apServer.isEmpty
                            ? "Not set. For example, Work slash GR Lab."
                            : apServer)
                    Button("Save", action: saveProtonPass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.name : source.reference
                }
                Text("Name the vault as well as the item. Proton\u{2019}s own identifiers work here too and keep working when things are renamed. SimpleVPN reads just this item with Proton\u{2019}s command-line tool and never changes your vaults.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .passbolt:
                // One question here too: which resource. WHICH server is a
                // settings-level choice, and the editor's Sign-In tab has the full
                // two-step server-then-resource picker for anyone with several.
                //
                // The prompt asks for the IDENTIFIER rather than the name, because the
                // profile's name is a poor guess here: this card pre-fills the VPN's
                // own name for every other source, and a Passbolt resource is far more
                // often named something else. So it starts EMPTY.
                Text(SignInSourceSteps.stepTwoSummary(vendor: .passbolt))
                    .font(.caption.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                HStack {
                    TextField("Resource", text: $apServer,
                              prompt: Text("The resource\u{2019}s identifier, or its name"))
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(savePassbolt)
                        .accessibilityLabel("Resource identifier or name in Passbolt")
                        .accessibilityValue(apServer.isEmpty
                            ? "Not set. Paste the identifier from the web address when you open it in Passbolt, or type its name."
                            : apServer)
                    Button("Save", action: savePassbolt)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear { apServer = source.reference }
                Text("Your server is set up in Settings \u{25B8} Sign-In Sources; this VPN just says which resource to read. Your OpenPGP key and its passphrase stay with Passbolt\u{2019}s own program \u{2014} SimpleVPN never sees either, and only ever reads.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // The same optional verification-code choice appears for every
            // sign-in source.  A linked 1Password entry may prefill it, but it
            // remains visible and editable until this VPN has connected once.
            VerificationCodeConfiguration(required: otpRequirement,
                                          passwordTemplate: otpTemplate,
                                          requiredByServer: vpn.hasStaticChallenge(profile.id))
        }
        .padding(14)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
        // A container (it is full of controls), and it carries its own sentence: the
        // card was an UNNAMED AX group, which is precisely the shape SimpleVPNUITests'
        // audit excuses as framework chrome — so the biggest first-run surface in the
        // app had no name and no gate could say so. Names the VPN it is about, because
        // a listener arriving here needs to know which one is being set up.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(isFirstConnection
                            ? "Before your first connect to \(profile.name)"
                            : "Set up the sign-in for \(profile.name)")
        // Gather only the prompt-free facts as the card appears.  A password
        // manager's deep check can launch its helper and therefore show that
        // manager's approval UI; it belongs to an explicit recheck, not to
        // merely opening the VPN window.
        .onAppear { sources.refresh() }
        // Deliberately no task keyed on the linked 1Password item. A drop only
        // records coordinates; the ordinary Connect action is the first read,
        // so it is also the only Touch ID approval needed to get online.
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                sources.refresh()
            }
        }
        .sheet(isPresented: $showFieldMap) {
            OnePasswordFieldMapSheet(itemTitle: opItemTitle, fields: opFields,
                                     roles: applicableOnePasswordRoles, mapping: sourceFieldMap)
        }
    }

    private var otpRequirement: Binding<Bool> {
        Binding(get: { vpn.requiresOTP(for: profile.id) }, set: { on in
            guard !vpn.hasStaticChallenge(profile.id) else { return }
            var auth = vpn.authConfig(for: profile.id)
            auth.requiresOTP = on
            Task { try? await vpn.setAuthConfig(auth, for: profile.id) }
        })
    }

    private var otpTemplate: Binding<String> {
        Binding(get: { vpn.authConfig(for: profile.id).passwordTemplate }, set: { template in
            var auth = vpn.authConfig(for: profile.id)
            auth.passwordTemplate = template
            Task { try? await vpn.setAuthConfig(auth, for: profile.id) }
        })
    }

    private var sourceFieldMap: Binding<[String: String]> {
        Binding(get: { source.fieldMap }, set: { map in
            var updated = source
            updated.fieldMap = map
            Task { try? await vpn.setCredentialSource(updated, for: profile.id) }
        })
    }

    private var applicableOnePasswordRoles: [AuthKind] {
        var roles: [AuthKind] = [.username, .password]
        if vpn.requiresOTP(for: profile.id) { roles.append(.otp) }
        return roles
    }

    private var onePasswordEntryPreview: some View {
        Group {
            if loadingOPFields && opInspection == nil {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Checking the linked 1Password entry…")
                }
                .font(.callout).foregroundStyle(.secondary)
            } else if let inspection = opInspection {
                VStack(alignment: .leading, spacing: 8) {
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                        if let username = inspection.username, !username.isEmpty {
                            linkedCredentialRow(label: fieldLabel(for: .username, in: inspection),
                                                value: username, symbol: "person", sensitive: false)
                        }
                        if inspection.hasPassword {
                            linkedCredentialRow(label: fieldLabel(for: .password, in: inspection),
                                                value: "••••••••", symbol: "lock", sensitive: true)
                        }
                        if inspection.hasVerificationCode {
                            linkedCredentialRow(label: fieldLabel(for: .otp, in: inspection),
                                                value: "••••••", symbol: "clock.arrow.circlepath",
                                                sensitive: true, trailing: { OnePasswordVerificationCountdown() })
                        }
                    }
                    .font(.callout)
                    .frame(maxWidth: 460, alignment: .leading)

                    HStack(spacing: 8) {
                        Button("Change Fields…") { loadOnePasswordFields(showMapping: true) }
                            .disabled(loadingOPFields)
                        Text("1Password supplies these values when you connect.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(10)
                .background(.background.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
            } else {
                HStack(spacing: 8) {
                    Button("Choose Fields…") { loadOnePasswordFields(showMapping: true) }
                        .disabled(source.reference.trimmingCharacters(in: .whitespaces).isEmpty || loadingOPFields)
                    Text(source.reference.trimmingCharacters(in: .whitespaces).isEmpty
                         ? "Link a 1Password item first."
                         : "Linked. 1Password will identify the sign-in fields when you click Connect.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private func linkedCredentialRow<Trailing: View>(label: String, value: String, symbol: String,
                                                     sensitive: Bool, @ViewBuilder trailing: () -> Trailing) -> some View {
        GridRow {
            Label(label, systemImage: symbol)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            HStack(spacing: 8) {
                TextField("", text: .constant(value))
                    .textFieldStyle(.roundedBorder)
                    .font(sensitive ? .body.monospacedDigit() : .body)
                    .disabled(true)
                    .accessibilityLabel(label)
                    .accessibilityValue(sensitive ? "Saved in 1Password" : value)
                trailing()
            }
            .frame(maxWidth: 360, alignment: .leading)
        }
    }

    private func linkedCredentialRow(label: String, value: String, symbol: String,
                                     sensitive: Bool) -> some View {
        linkedCredentialRow(label: label, value: value, symbol: symbol, sensitive: sensitive) { EmptyView() }
    }

    private func fieldLabel(for role: AuthKind, in inspection: OnePasswordProvider.EntryInspection) -> String {
        guard let id = source.fieldMap[role.rawValue] ?? inspection.fieldMap[role.rawValue],
              let field = inspection.fields.first(where: { $0.id == id }) else {
            return role.title
        }
        return field.label
    }

    private func loadOnePasswordFields(showMapping: Bool) {
        guard !loadingOPFields else { return }
        loadingOPFields = true
        let selection = source
        Task {
            defer { loadingOPFields = false }
            do {
                let account = OnePasswordAccountMemory.effectiveAccount(for: selection)
                let item = try await OnePasswordProvider.inspectEntry(
                    itemReference: selection.reference, vault: selection.vault, account: account)
                opItemTitle = item.title
                opFields = item.fields
                opInspection = item
                // This successful, explicitly requested item inspection proves
                // the integration too.  Do not make a follow-up vault-list call
                // merely to set the same app-level fact.
                OnePasswordPreflight.markVerified()
                preflight.note(.ready(vaults: []))
                // Entries linked by an earlier build may predate automatic
                // mapping. Repair them as soon as the person opens this card,
                // using only the entry they already selected.
                // Persist everything learned from this one inspection together.
                // Saving the map and then the vault from two copies of `selection`
                // used to let the second write put the empty old map back, making
                // Connect guess field names and issue another 1Password request.
                var updated = selection
                var sourceChanged = false
                if updated.fieldMap.isEmpty, !item.fieldMap.isEmpty {
                    updated.fieldMap = item.fieldMap
                    sourceChanged = true
                }
                if updated.vault.trimmingCharacters(in: .whitespaces).isEmpty,
                   !item.vaultID.trimmingCharacters(in: .whitespaces).isEmpty {
                    updated.vault = item.vaultID
                    sourceChanged = true
                }
                if sourceChanged {
                    try? await vpn.setCredentialSource(updated, for: profile.id)
                }
                if item.hasVerificationCode, !vpn.hasStaticChallenge(profile.id) {
                    var auth = vpn.authConfig(for: profile.id)
                    if !auth.requiresOTP {
                        auth.requiresOTP = true
                        try? await vpn.setAuthConfig(auth, for: profile.id)
                    }
                }
                if showMapping { self.showFieldMap = true }
            } catch {
                OnePasswordPreflight.noteFailure(error)
                vpn.lastError = "Couldn’t read this 1Password entry: \(error.localizedDescription)"
            }
        }
    }

    private var onePasswordAccounts: [SourceInstance] {
        signInSettings.instances(for: .onePassword)
    }

    private var selectedOnePasswordAccountID: SourceInstanceID? {
        source.selection.instance ?? onePasswordAccounts.first?.id
    }

    private var hasSelectedOnePasswordAccount: Bool {
        let configured = OnePasswordAccountMemory.connectionAccount(
            selectedOnePasswordAccountID, store: signInSettings)
        return !configured.isEmpty
            || !source.account.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private var onePasswordConnected: Bool {
        if preflight.state?.isReady == true { return true }
        return sources.facts.rawAvailability(.onePassword).isReady
    }

    private var onePasswordConnectionButtonLabel: String {
        let hasConnectedBefore = OnePasswordPreflight.isVerified()
            || sources.facts.rawAvailability(.onePassword).isAnswered
        if preflight.checking { return hasConnectedBefore ? "Reconnecting…" : "Connecting…" }
        return hasConnectedBefore ? "Reconnect to 1Password" : "Connect to 1Password"
    }

    @ViewBuilder private var onePasswordConfiguration: some View {
        VStack(alignment: .leading, spacing: 8) {
            OnePasswordSetupCard(model: preflight, compact: true, asksForAccount: false,
                                 showsCheckAgain: false,
                                 onAccount: { useAccount($0) },
                                 onCheckAgain: { recheckOnePassword() })

            if onePasswordAccounts.isEmpty {
                Button("Set Up 1Password Accounts…") { openOnePasswordAccountSettings() }
                    .buttonStyle(.glass)
                Text("Drop an item below to set up its account automatically, or add a named account to browse 1Password first.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Picker("1Password account", selection: Binding(
                    get: { selectedOnePasswordAccountID },
                    set: { chooseOnePasswordAccount($0) })) {
                        ForEach(onePasswordAccounts) { account in
                            Text(account.name).tag(Optional(account.id))
                        }
                    }
                    .frame(maxWidth: 360, alignment: .leading)
                    .accessibilityHint("Chooses which named 1Password account this VPN uses. Internal account identifiers are not shown.")
            }

            // The well is available before authorization and before an account
            // has been named. A 1Password row drag already carries the account,
            // vault and item coordinates needed to finish this non-secret link.
            onePasswordWell
            if let onePasswordDropError {
                Text(onePasswordDropError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if !source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                onePasswordEntryPreview
            }

            if !onePasswordConnected {
                Button(onePasswordConnectionButtonLabel) { recheckOnePassword() }
                    .buttonStyle(.glassProminent)
                    .disabled(preflight.checking || !hasSelectedOnePasswordAccount)
                Text(source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                     ? "Connect only if you want to browse before dropping an item. 1Password may ask you to approve SimpleVPN."
                     : "The item is linked. 1Password will ask for Touch ID when you click this VPN's Connect button.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if hasSelectedOnePasswordAccount {
                Button {
                    showOnePasswordBrowser = true
                    Task { await loadOnePasswordItems() }
                } label: {
                    Label("Browse 1Password…", systemImage: "magnifyingglass")
                }
                .buttonStyle(.glass)
                .disabled(loadingOnePasswordItems)
                .accessibilityHint("Selects a complete 1Password item without dragging it.")
                .popover(isPresented: $showOnePasswordBrowser) {
                    OnePasswordBrowsePopover(
                        searchPrompt: "Search items",
                        rows: onePasswordItems.map {
                            OnePasswordBrowseRow(
                                id: $0.id,
                                title: $0.title,
                                subtitle: [$0.vaultTitle, $0.category]
                                    .filter { !$0.isEmpty }.joined(separator: " · "))
                        },
                        loading: loadingOnePasswordItems,
                        status: onePasswordBrowseError,
                        onPick: { row in chooseOnePasswordItem(row.id) },
                        onRefresh: { Task { await loadOnePasswordItems() } })
                }
            }
        }
    }

    private func chooseOnePasswordAccount(_ id: SourceInstanceID?) {
        var updated = source
        updated.instanceID = id?.rawValue ?? ""
        // The named connection owns the internal account identifier. Keeping a
        // second copy on the VPN would let a hidden UUID override the picker.
        updated.account = ""
        Task { try? await vpn.setCredentialSource(updated, for: profile.id) }
    }

    private func openOnePasswordAccountSettings() {
        settingsRouter?.go(to: SignInSourceSettings.instanceListSettingID(.onePassword))
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        AccessibilityAnnouncer.sayNow("Opening 1Password account settings.")
    }

    /// The drag-in target: deliberately quiet at rest, with one animated down
    /// arrow to make the next action obvious without a bright, permanent callout.
    private var onePasswordWell: some View {
        let linked = !source.reference.isEmpty
        return VStack(spacing: 10) {
            Image(systemName: linked ? "checkmark.circle.fill"
                                     : isOnePasswordDropTargeted
                                        ? "arrow.down.circle.fill" : "arrow.down.circle")
                .font(.system(size: 30))
            Text(linked ? "Linked to \(linkedName) — drag another item to change"
                        : isOnePasswordDropTargeted
                            ? "Release to use this 1Password item"
                            : "Or drag the item from 1Password here")
                .font(.headline)
        }
            .foregroundStyle((linked || isOnePasswordDropTargeted)
                             ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
            .frame(maxWidth: .infinity, minHeight: 110)
            .contentShape(Rectangle())
            .background {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(isOnePasswordDropTargeted
                          ? Color.accentColor.opacity(0.16)
                          : Color.secondary.opacity(0.08))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(isOnePasswordDropTargeted ? Color.accentColor : Color.secondary,
                                  style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .allowsHitTesting(false)
            }
            // Match the proven standalone probe: the visible well owns exactly
            // one destination. Do not hoist this onto the conditional setup
            // container, where controls, transitions and unrelated drop
            // destinations complicate AppKit's target negotiation.
            .onDrop(of: OnePasswordDropItem.acceptedContentTypes,
                    isTargeted: $isOnePasswordDropTargeted,
                    perform: acceptOnePasswordDrop)
            .onChange(of: isOnePasswordDropTargeted) { _, targeted in
                OnePasswordDropItem.logTargeting(targeted)
            }
            // One element with the well's own words; the drag itself has no
            // keyboard path, so say where the keyboard-operable one lives.
            .accessibilityElement(children: .combine)
            .accessibilityHint("Drag the item from 1Password, or use Browse 1Password to select it without dragging.")
            .popover(isPresented: Binding(get: { !choices.isEmpty },
                                          set: { if !$0 { choices = [] } })) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Which item is this VPN\u{2019}s sign-in?").font(.callout.weight(.semibold))
                    ForEach(Array(choices.enumerated()), id: \.element.id) { index, drop in
                        Button(drop.displayName(position: index + 1)) { link(drop) }
                            .buttonStyle(.link)
                    }
                }
                .padding(12)
                .frame(minWidth: 220)
            }
    }

    /// The same small SwiftUI boundary used by OnePasswordProbe. Everything
    /// after acceptance is domain work and must not influence hit testing.
    private func acceptOnePasswordDrop(_ providers: [NSItemProvider]) -> Bool {
        guard OnePasswordDropItem.canAccept(providers) else { return false }
        let snapshot = OnePasswordDropItem.activeDragSnapshot()
        Task {
            guard let drops = await onePasswordDrops.collect(
                providers, dragSnapshot: snapshot
            ) else { return }
            receiveOnePasswordDrops(drops)
        }
        return true
    }

    private func receiveOnePasswordDrops(_ drops: [OnePasswordDrop]) {
        onePasswordDropError = nil
        guard let first = drops.first else {
            onePasswordDropError = "SimpleVPN couldn’t read that item. Drag its row from 1Password, or use Browse 1Password."
            return
        }
        if drops.count > 1 {
            choices = drops
        } else {
            link(first)
        }
    }

    private func loadOnePasswordItems() async {
        guard !loadingOnePasswordItems else { return }
        loadingOnePasswordItems = true
        onePasswordBrowseError = nil
        defer { loadingOnePasswordItems = false }
        do {
            let account = OnePasswordAccountMemory.effectiveAccount(for: source,
                                                                     store: signInSettings)
            onePasswordItems = try await OnePasswordNative.listItemsAcrossVaults(account: account)
            if onePasswordItems.isEmpty {
                onePasswordBrowseError = "1Password didn’t show SimpleVPN any items."
            }
        } catch {
            onePasswordItems = []
            onePasswordBrowseError = error.localizedDescription
        }
    }

    private func chooseOnePasswordItem(_ rowID: String) {
        guard let item = onePasswordItems.first(where: { $0.id == rowID }) else { return }
        showOnePasswordBrowser = false
        let account = OnePasswordAccountMemory.effectiveAccount(for: source,
                                                                 store: signInSettings)
        link(OnePasswordDrop(reference: item.itemID,
                             vault: item.vaultID,
                             account: account,
                             title: item.title))
    }

    /// Apply a chosen row. Two things are stored, not one: WHERE the sign-in
    /// comes from, and whether it is remembered — "type it each time" and "save
    /// it securely in SimpleVPN" are the same source with opposite answers to the
    /// second question, and a chooser that set only the first would silently
    /// leave a saved password behind when someone picked "type it each time".
    private func choose(_ option: SignInSourceOption) {
        guard let kind = option.storedKind else { return }   // pointers aren't choices
        var s = source
        s.kind = kind
        var a = auth
        if let remembers = option.remembers { a.rememberCredentials = remembers }
        Task {
            try? await vpn.setCredentialSource(s, for: profile.id)
            if a != auth { try? await vpn.setAuthConfig(a, for: profile.id) }
            // Picking "type it each time" means it: whatever was saved for this
            // VPN goes, rather than quietly still being there.
            if option.id == .typeEachTime { vpn.forgetSavedSignIn(id: profile.id) }
        }
        // Selecting 1Password and dropping an item do not inspect it. The
        // ordinary Connect action is the explicit first need, and one approved
        // response both identifies the fields and supplies this connection.
    }

    /// "Check Again" on a row that is waiting on something. THE ANSWER IS SPOKEN AND
    /// SHOWN, which is the point: somebody who has just gone into 1Password's or
    /// Keeper's own settings and come back wants a straight yes or no, not a row that
    /// may have quietly updated while they were looking away.
    ///
    /// It re-probes EVERY vendor rather than one, because `deepScanAll` is the only
    /// pass there is and it already skips the vendors the user has switched off — and
    /// because the thing somebody just enabled is frequently not the row they pressed
    /// (installing `keepassxc-cli` settles the KeePass-file row, not the KeePassXC
    /// one). The scan is sequential on purpose: two vendor approval dialogs at once is
    /// a mess.
    private func recheck(_ vendor: LocalVaultVendor) {
        let before = sources.facts.availability(vendor)
        Task {
            // 1Password's own preflight is the more specific check, and it is the one
            // that clears its "the integration is off" state — so a re-check of that
            // row pays for it as well.
            if vendor == .onePassword { recheckOnePassword() }
            await sources.deepScan(force: true)
            sources.refresh()
            let after = sources.facts.availability(vendor)
            let title = LocalVaultCopyBook.copy(for: vendor).title
            // A straight answer either way. "Nothing changed" is a real answer and is
            // more use than silence, which reads as "the button did nothing".
            AccessibilityAnnouncer.sayNow(
                after == .ready ? "\(title) is ready to use now."
                    : after == before ? "\(title) still isn\u{2019}t ready. Nothing has changed yet."
                    : "\(title): \(after.spokenChange)")
        }
    }

    /// A pointer row's button: open the app the user's password is probably in.
    /// This changes no setting — the row is a signpost, and the wording says so.
    private func open(_ option: SignInSourceOption) {
        guard let bundleID = option.appBundleID,
              let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
        AccessibilityAnnouncer.sayNow("Opening \(option.title). Copy your password, then paste it below.")
    }

    /// The fallback integration check, used only before an item is linked.  A
    /// linked item is re-inspected instead, because that one approved request
    /// answers both "does 1Password work?" and "which fields will this VPN use?".
    private func checkOnePassword(force: Bool) {
        let account = OnePasswordAccountMemory.effectiveAccount(for: source,
                                                                 store: signInSettings)
        Task {
            if force { await preflight.check(account: account) }
            else { await preflight.checkIfNeeded(account: account) }
            sources.refresh()
        }
    }

    private func recheckOnePassword() {
        if source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            checkOnePassword(force: true)
        } else {
            loadOnePasswordFields(showMapping: false)
        }
    }

    /// The account name typed into the card's prompt: kept for this VPN, and
    /// checked straight away so the answer lands where the question was asked.
    private func useAccount(_ name: String) {
        var s = source
        s.account = name
        Task {
            try? await vpn.setCredentialSource(s, for: profile.id)
            // A name is only remembered app-wide once it has actually worked —
            // the check itself does that.
            await preflight.check(account: name)
        }
    }

    /// A dragged item is linked by its 1Password id — exact, and immune to
    /// renaming, but not something to read back at anyone.
    private var linkedName: String {
        OnePasswordDrop.looksLikeItemID(source.reference)
            ? "your 1Password item"
            : "\u{201C}\(source.reference)\u{201D}"
    }

    /// Point this VPN's sign-in at a dropped item. The 1Password payload carries
    /// account and vault UUIDs as well as the item's, which is what keeps this
    /// card a one-drag setup — 1Password won't answer without knowing which
    /// account to ask.
    private func link(_ dropped: OnePasswordDrop) {
        choices = []
        Task {
            do {
                try await vpn.linkOnePasswordEntry(dropped, for: profile.id)
            } catch {
                vpn.lastError = "Couldn’t link the 1Password entry: \(error.localizedDescription)"
            }
        }
    }

    private func useApplePassword(_ selection: ApplePasswordSelection) {
        var credentials = vpn.transientCredentials(for: profile.id)
        credentials.username = selection.username
        credentials.password = selection.password
        vpn.setTransientCredentials(credentials, for: profile.id)

        // A picker result also settles the source's non-secret service hint so
        // the setup card does not ask the same question again. The password is
        // deliberately absent from this persisted source value.
        var updated = source
        updated.kind = .applePasswords
        updated.reference = profile.server
        Task { try? await vpn.setCredentialSource(updated, for: profile.id) }
    }

    private func savePasswordStore() {
        var s = source
        s.kind = .passwordStore
        // The entry NAME, which is its path inside the store without the `.gpg`.
        // Trimmed only — never lower-cased or otherwise normalised, because a store's
        // entries are files and the filesystem's case is the user's business.
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveProtonPass() {
        var s = source
        s.kind = .protonPass
        // The whole reference — vault and item — exactly as typed. Trimmed only: a
        // Proton Pass title may legitimately contain spaces in the middle and its
        // identifiers are case-sensitive base64, so nothing else may be normalised.
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func savePassbolt() {
        var s = source
        s.kind = .passbolt
        // Trimmed only. Never lower-cased: a resource NAME is the user's text, and
        // an identifier is hex whose case does not matter — normalising either
        // would be a change SimpleVPN has no business making.
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveKeePassXC() {
        var s = source
        s.kind = .keePassXC
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveKeeper() {
        var s = source
        s.kind = .keeper
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveBitwarden() {
        var s = source
        s.kind = .bitwarden
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveDashlane() {
        var s = source
        s.kind = .dashlane
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveKeePassFile() {
        var s = source
        s.kind = .keePassFile
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveLastPass() {
        var s = source
        s.kind = .lastPass
        // The entry's name, or its full path including groups, or its numeric id.
        // Trimmed only: `lpass` matches names EXACTLY (SimpleVPN passes neither of its
        // loose-matching options), so changing the case here would stop it matching.
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    // MARK: Step one — which database

    private var keePassFileDatabases: [SourceInstance] {
        SignInSourceSettingsStore.shared.instances(for: .keePassFile)
    }

    private var keePassFileDatabaseName: String? {
        SourceInstanceResolver.resolve(id: source.selection.instance, vendor: .keePassFile,
                                      instances: keePassFileDatabases).instance?.name
    }

    /// Only shown when there is genuinely a choice: one database (the ordinary case,
    /// and what somebody who has just migrated has) needs no picker, and none at all
    /// is a setup state the source's own row already explains.
    @ViewBuilder private var keePassFileDatabaseStep: some View {
        let databases = keePassFileDatabases
        if databases.count > 1 {
            Text(SignInSourceSteps.stepOneTitle(vendor: .keePassFile))
                .font(.caption.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Picker(SignInSourceSteps.stepOneTitle(vendor: .keePassFile),
                   selection: Binding(
                    get: { source.selection.instance ?? databases.first?.id },
                    set: { chooseKeePassFileDatabase($0) })) {
                ForEach(databases) { database in
                    Text(database.name).tag(Optional(database.id))
                }
            }
            .labelsHidden()
            .accessibilityLabel(SignInSourceSteps.stepOneTitle(vendor: .keePassFile))
            .accessibilityValue(SignInSourceSteps.spokenStep(1, of: .keePassFile,
                                                            chosen: keePassFileDatabaseName))
            .accessibilityHint("Chooses which of your KeePass databases this VPN reads.")
        }
    }

    private func chooseKeePassFileDatabase(_ id: SourceInstanceID?) {
        var s = source
        s.kind = .keePassFile
        s.instanceID = id?.rawValue ?? ""
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
        if let name = keePassFileDatabases.first(where: { $0.id == id })?.name {
            AccessibilityAnnouncer.sayNow("Reading \(name).")
        }
    }
}
