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
//  drag-in well, the address a KeePassXC/Keeper/Apple Passwords lookup matches).
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
    @Binding var dismissed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Marching-ants phase for the drop well (pure Shape drawing — safe).
    @State private var dashPhase: CGFloat = 0
    @State private var apServer = ""
    /// A multi-selection drag, waiting to be narrowed to the one item this VPN
    /// signs in with. Empty = nothing pending.
    @State private var choices: [OnePasswordDrop] = []
    /// The 1Password setup check — run when 1Password is CHOSEN here, never on
    /// appear, and skipped once the integration has been proven to work.
    @State private var preflight = OnePasswordPreflightModel()
    /// Collapses the several deliveries macOS makes of one drag into one apply.
    @State private var drops = OnePasswordDropCollector()
    /// What this Mac can actually offer. Shared app-wide so one set of probes
    /// serves every surface.
    @State private var sources = SignInSourceAvailability.shared

    private var auth: VPNAuthConfig { vpn.authConfig(for: profile.id) }
    private var source: CredentialSource { vpn.credentialSource(for: profile.id) }
    private var facts: SignInSourceFacts { sources.facts(allowsPasswordSave: allowsPasswordSave) }
    /// The row that matches what this VPN is set to right now.
    private var selectedID: SignInSourceID? {
        switch source.kind {
        case .manual: auth.rememberCredentials ? .saveInSimpleVPN : .typeEachTime
        case .applePasswords: .applePasswords
        default: LocalVaultRegistry.adapter(for: source.kind).map { .vault($0.vendor) }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Before your first connect", systemImage: "hand.wave")
                    .font(.callout.weight(.semibold))
                Spacer()
                Button { dismissed = true } label: {
                    Image(systemName: "xmark").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                    .buttonStyle(.borderless)
                    .help("Hide until next launch — this card comes back until a connect succeeds")
                    .accessibilityLabel("Hide setup card")
            }
            Text("The configuration file says how to reach \(profile.name) — but not how you sign in. Two quick questions:")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle(isOn: otpBinding) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("I also enter a verification code")
                    Text("A short code from an authenticator app, a key fob, or a text message.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)

            SignInSourceChooser(
                options: SignInSourceCatalog.options(facts),
                selection: selectedID,
                onChoose: { choose($0) },
                onOpenApp: { open($0) },
                compact: true)

            switch source.kind {
            case .manual:
                EmptyView()   // the credential form directly below IS the answer
            case .onePassword:
                // Same walkthrough as the editor, in the smaller type this card
                // uses — with the account asked for here, since this card has no
                // Account field of its own to point at.
                OnePasswordSetupCard(model: preflight, compact: true, asksForAccount: true,
                                     onAccount: { useAccount($0) },
                                     onCheckAgain: { checkOnePassword(force: true) })
                onePasswordWell
                Text("Dragging the item itself fills in everything SimpleVPN needs. Dragging one of its fields fills in less.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .applePasswords:
                HStack {
                    TextField("Website or server the password is saved for", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveApplePasswords)
                    Button("Use") { saveApplePasswords() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.server : source.reference
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
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
        // Cheap facts on appear, then the paid-for ones once. The poll is what
        // makes a 1Password someone quits (or a KeePassXC they launch) show up
        // in the list without the window being reopened.
        .onAppear { sources.refresh() }
        .task { await sources.deepScan() }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                sources.refresh()
                // Following an enablement banner must flip the row without a
                // restart; the throttle inside keeps this cheap.
                await sources.recheckIfDue()
            }
        }
    }

    /// The drag-in target, with a quiet "things can be dropped here" rhythm:
    /// slowly marching dashes and an occasional key wiggle (both suppressed
    /// under Reduce Motion, and both stop once an item is linked).
    private var onePasswordWell: some View {
        let linked = !source.reference.isEmpty
        return RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5], dashPhase: dashPhase))
            .foregroundStyle(linked ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
            .frame(height: 52)
            .overlay {
                Label(linked ? "Linked to \(linkedName) — drag another item to change"
                             : "Drag the item from 1Password here",
                      systemImage: linked ? "checkmark.circle.fill" : "key.fill")
                    .font(.callout)
                    .foregroundStyle(linked ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 4)),
                                  isActive: !reduceMotion && !linked)
            }
            .contentShape(Rectangle())
            // One element with the well's own words; the drag itself has no
            // keyboard path, so say where the keyboard-operable one lives.
            .accessibilityElement(children: .combine)
            .accessibilityHint("Dragging isn't required — you can also link the item under this VPN in Manage VPNs.")
            // 1Password's own drag payload first (it names account, vault AND
            // item), then a link, then op://, then the bare title — see
            // OnePasswordDropItem.
            .onDrop(of: OnePasswordDropItem.acceptedContentTypes, isTargeted: nil) { providers, _ in
                guard OnePasswordDropItem.canAccept(providers) else { return false }
                Task {
                    // Through the collector: macOS delivers one drag more than
                    // once, and applying each delivery turned a single dropped
                    // item into a "which one?" chooser.
                    guard let dropped = await drops.collect(providers),
                          let first = dropped.first else { return }
                    // A VPN signs in with one item; several were dragged, so ask.
                    if dropped.count > 1 { choices = dropped; return }
                    link(first)
                }
                return true
            }
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
            .task(id: linked) {
                guard !reduceMotion, !linked else { return }
                dashPhase = 0
                withAnimation(.linear(duration: 1.8).repeatForever(autoreverses: false)) {
                    dashPhase = -10   // one full dash+gap cycle → seamless march
                }
            }
    }

    private var otpBinding: Binding<Bool> {
        Binding(get: { auth.requiresOTP },
                set: { on in
                    var a = auth
                    a.requiresOTP = on
                    Task { try? await vpn.setAuthConfig(a, for: profile.id) }
                })
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
        // Choosing 1Password is the first genuine need for a 1Password lookup —
        // and the only moment this card is allowed to raise its approval prompt.
        if kind == .onePassword { checkOnePassword(force: false) }
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

    /// The setup check. `force` is the Check Again button, which re-checks even
    /// a verified integration — the way back from "it worked yesterday".
    private func checkOnePassword(force: Bool) {
        let account = OnePasswordAccountMemory.effectiveAccount(profile: source.account)
        Task {
            if force { await preflight.check(account: account) }
            else { await preflight.checkIfNeeded(account: account) }
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
        var s = source
        s.kind = .onePassword
        s.reference = dropped.reference
        if !dropped.vault.isEmpty { s.vault = dropped.vault }
        if !dropped.account.isEmpty {
            s.account = dropped.account
            // The dragged item names its account, and the SDK takes that UUID as
            // readily as the sidebar name — so one drag answers "which account?"
            // for every other VPN too.
            OnePasswordAccountMemory.seed(dropped.account)
        }
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveApplePasswords() {
        var s = source
        s.kind = .applePasswords
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
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
