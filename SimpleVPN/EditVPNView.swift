// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EditVPNView.swift
//  Edit sheet for a single VPN entry, tabbed:
//   • General        — name, logo, labels
//   • Credentials    — username/password (adapts to the profile: hidden for
//                      autologin, username locked when the profile pins it)
//   • Options        — per-VPN OpenVPN engine overrides (OpenVPNOptionsForm)
//   • Certificates   — certificate/key wells with rich parsed cards
//   • Configuration  — the raw .ovpn text (source of truth)
//  The profile is re-evaluated with the real engine parser as the text changes,
//  so tabs adapt live (private-key password field, autologin, server list, …).
//

import SwiftUI
import CoreGraphics

struct EditVPNView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore
    let profileID: String
    /// true when hosted as the Manage window's detail pane (no sheet chrome:
    /// flexible size, Revert instead of Cancel, Save doesn't dismiss).
    var embedded = false

    @Environment(\.dismiss) private var dismiss
    @Environment(ProfileEvaluator.self) private var evaluator
    @State private var name = ""
    @State private var ovpn = ""
    @State private var username = ""
    @State private var password = ""
    @State private var remember = true
    @State private var logo: CGImage?
    @State private var showLogoImporter = false
    @State private var loaded = false
    @State private var saving = false
    @State private var saveError: String?
    /// Brief "Saved" confirmation for the embedded editor, which stays open.
    @State private var savedTick = false

    // Snapshots of the persisted config as loaded, so we can tell whether the user
    // has diverged from it. If a Doctor fix / undo / other editor changes the
    // persisted config while this editor is open AND the user hasn't edited that
    // field group, we quietly reload — instead of letting a later Save clobber the
    // external change with a stale draft.
    @State private var loadedOverrides = OpenVPNOverrides()
    @State private var loadedOVPN = ""

    // Engine options draft + keychain-bound secrets
    @State private var draft = OpenVPNOverrides()
    @State private var proxyPassword = ""
    @State private var privateKeyPassword = ""

    // Authentication shape (OTP requirement + template)
    @State private var requiresOTP = false
    @State private var passwordTemplate = VPNAuthConfig.defaultTemplate
    @State private var otpAdvancedExpanded = false

    // Credential source (manual / 1Password / Apple Passwords)
    @State private var credentialKind: CredentialSourceKind = .manual
    @State private var sourceReference = ""
    @State private var sourceAccount = ""
    @State private var sourceTest: SourceTestState = .idle

    // 1Password field mapping (which item field feeds which auth role)
    @State private var fieldMap: [String: String] = [:]
    @State private var opFields: [OnePasswordProvider.OPField] = []
    @State private var opItemTitle = ""
    @State private var showFieldMap = false
    @State private var loadingOPFields = false
    @State private var opFieldError: String?

    private enum SourceTestState: Equatable {
        case idle, testing, ok(String), failed(String)
    }

    private var evaluation: ProfileEvaluation? {
        ovpn.isEmpty ? nil : evaluator.evaluation(for: ovpn)
    }

    var body: some View {
        NavigationStack {
            TabView {
                generalTab
                    .tabItem { Label("General", systemImage: "info.circle") }
                credentialsTab
                    .tabItem { Label("Credentials", systemImage: "person.badge.key") }
                OpenVPNOptionsForm(draft: $draft,
                                   proxyPassword: $proxyPassword,
                                   privateKeyPassword: $privateKeyPassword,
                                   evaluation: evaluation)
                    .disabled(ManagedPolicy.lockConfiguration)
                    .tabItem { Label("Options", systemImage: "slider.horizontal.3") }
                CertificatesTab(ovpn: $ovpn, evaluation: evaluation)
                    .disabled(ManagedPolicy.lockConfiguration)
                    .tabItem { Label("Certificates", systemImage: "checkmark.seal") }
                configurationTab
                    .disabled(ManagedPolicy.lockConfiguration)
                    .tabItem { Label("Configuration", systemImage: "doc.text") }
            }
            // Clear the toolbar's scroll-edge shadow band — without this the
            // segmented tab strip sits flush under the title bar and the edge
            // effect overlays its top pixels.
            .padding(.top, 10)
            .navigationTitle(embedded ? name : "Edit VPN")
            .task { load() }
            // Reload from the persisted config when it changes underneath us
            // (Doctor fix, undo, another editor) — but only for a field group the
            // user hasn't touched, so in-progress edits are never lost.
            .onChange(of: vpn.overrides(for: profileID)) { _, new in
                if draft == loadedOverrides { draft = new }
                loadedOverrides = new
            }
            .onChange(of: vpn.ovpnText(id: profileID) ?? "") { _, new in
                if ovpn == loadedOVPN { ovpn = new }
                loadedOVPN = new
            }
            .alert("Couldn’t save changes", isPresented: Binding(
                get: { saveError != nil }, set: { if !$0 { saveError = nil } })) {
                Button("OK") { saveError = nil }
            } message: { Text(saveError ?? "") }
            .fileImporter(isPresented: $showLogoImporter, allowedContentTypes: [.image], onCompletion: importLogo)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if embedded {
                        Button("Revert") { loaded = false; load() }
                    } else {
                        Button("Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) { saveButton }
            }
            .safeAreaInset(edge: .bottom) {
                if ManagedPolicy.lockConfiguration {
                    Label("Connection settings are managed by your organization and can't be changed here.",
                          systemImage: "lock.fill")
                        .font(.callout).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10).background(.quaternary.opacity(0.5))
                } else if let eval = evaluation, eval.error {
                    EvaluationErrorBanner(message: eval.message)
                } else if vpn.hasPendingSettings(id: profileID) {
                    PendingSettingsNotice(vpn: vpn, profileID: profileID)
                }
            }
        }
        .frame(minWidth: embedded ? 520 : 600,
               idealWidth: 620,
               minHeight: embedded ? 500 : 680,
               idealHeight: 700)
        .disabled(saving)
        .sheet(isPresented: $showFieldMap) {
            OnePasswordFieldMapSheet(itemTitle: opItemTitle, fields: opFields,
                                     roles: applicableRoles, mapping: $fieldMap)
        }
    }

    // MARK: Tabs

    private var generalTab: some View {
        Form {
            Section("Name") { TextField("Name", text: $name) }

            Section("Logo") {
                HStack(spacing: 14) {
                    LogoWell(image: logo, pick: { showLogoImporter = true }, drop: { importLogoFile($0) })
                    VStack(alignment: .leading, spacing: 6) {
                        Button("Choose Image…") { showLogoImporter = true }
                        if logo != nil { Button("Remove", role: .destructive) { LogoStore.delete(profileID); logo = nil } }
                    }
                }
            }

            Section("Labels") {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(labels.labels) { l in
                            LabelChip(label: l, on: labels.isAssigned(l, to: profileID)) { labels.toggle(l, for: profileID) }
                        }
                    }.padding(.vertical, 2)
                }
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private var credentialsTab: some View {
        Form {
            if evaluation?.autologin == true {
                Section {
                    Label("This VPN signs in automatically — no username or password is needed.",
                          systemImage: "person.fill.checkmark")
                        .foregroundStyle(.secondary)
                }
            } else {
                credentialSourceSection

                if credentialKind == .manual {
                    Section("Credentials") {
                        TextField("Username", text: $username)
                            .textContentType(.username)
                            .disabled(usernameLocked)
                        if usernameLocked {
                            Text("This configuration only works with the username above.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        SecureField("Password", text: $password).textContentType(.password)
                        if evaluation?.allowPasswordSave ?? true {
                            Toggle("Remember password", isOn: $remember)
                        } else {
                            Label("This VPN's administrator doesn't allow saving the password.",
                                  systemImage: "key.slash")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }
                }

                Section("One-Time Passcode") {
                    Toggle("Requires a one-time passcode (OTP)", isOn: $requiresOTP)
                        .onChange(of: requiresOTP) { _, on in
                            if on { promptForOTPFieldIfNeeded() }
                        }
                    Text("Each connection asks for a fresh code from your authenticator. Quick connect from the menu bar opens the window so the code can be typed.")
                        .font(.callout).foregroundStyle(.secondary)

                    if requiresOTP {
                        managedOTPSourceRow
                        DisclosureGroup(isExpanded: $otpAdvancedExpanded) {
                            TextField("Password template", text: $passwordTemplate,
                                      prompt: Text(verbatim: VPNAuthConfig.defaultTemplate))
                                .font(.body.monospaced())
                                .autocorrectionDisabled()
                                .padding(.top, 4)
                            Text("How the sign-in password is assembled from your password and the code. \u{201C}{password}{otp}\u{201D} sends them joined together — what most OTP-enabled servers (LinOTP, privacyIDEA) expect.")
                                .font(.callout).foregroundStyle(.secondary)
                            if !templateValid {
                                Label("The template must contain {otp} — the default will be used instead.",
                                      systemImage: "exclamationmark.triangle.fill")
                                    .font(.callout).foregroundStyle(.orange)
                            }
                        } label: {
                            // The whole row toggles, not just the chevron.
                            Text("Advanced")
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    withAnimation(.snappy) { otpAdvancedExpanded.toggle() }
                                }
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var templateValid: Bool {
        let t = passwordTemplate.trimmingCharacters(in: .whitespaces)
        return t.isEmpty || t.contains("{otp}")
    }

    /// Where the code actually comes from, stated in the OTP section itself.
    ///
    /// Turning OTP on while credentials come from 1Password used to say nothing at all:
    /// the app quietly fell back to the item's *standard* one-time-code field, so anyone
    /// keeping their code in a custom field only found out at connect time, as a failed
    /// sign-in with no explanation. The mapping belongs next to the toggle that needs it.
    @ViewBuilder private var managedOTPSourceRow: some View {
        if credentialKind == .onePassword {
            let mapped = fieldMap["otp"].flatMap { id -> String? in
                id.isEmpty ? nil : (opFields.first { $0.id == id }?.label ?? id)
            }
            let noItemYet = sourceReference.trimmingCharacters(in: .whitespaces).isEmpty

            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: mapped == nil ? "questionmark.circle.fill" : "arrow.right.circle")
                    .foregroundStyle(mapped == nil ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                VStack(alignment: .leading, spacing: 2) {
                    if let mapped {
                        Text("Code comes from the \u{201C}\(mapped)\u{201D} field in 1Password")
                            .font(.callout)
                    } else if noItemYet {
                        Text("Choose a 1Password item below, then pick the field holding the code.")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Which 1Password field holds the code?").font(.callout)
                        Text("Until you pick one, SimpleVPN tries the item's standard one-time-code field.")
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 8)
                if !noItemYet {
                    Button(mapped == nil ? "Choose Field\u{2026}" : "Change\u{2026}") {
                        Task { await loadOPFieldsAndShowSheet() }
                    }
                    .disabled(OnePasswordProvider.cliPath == nil || loadingOPFields)
                }
            }
        }
    }

    /// Flipping OTP on is exactly when to ask which 1Password field carries the code —
    /// the user is already thinking about it, and the alternative is finding out at
    /// connect time. Only auto-opens when we can genuinely populate the sheet; otherwise
    /// `managedOTPSourceRow` carries the ask until an item has been chosen.
    private func promptForOTPFieldIfNeeded() {
        guard requiresOTP, credentialKind == .onePassword,
              (fieldMap["otp"] ?? "").isEmpty,
              !sourceReference.trimmingCharacters(in: .whitespaces).isEmpty,
              OnePasswordProvider.cliPath != nil,
              !loadingOPFields, !showFieldMap
        else { return }
        Task { await loadOPFieldsAndShowSheet() }
    }

    // MARK: Credential source

    @ViewBuilder private var credentialSourceSection: some View {
        Section("Credential Source") {
            Picker("Get credentials from", selection: $credentialKind) {
                ForEach(CredentialSourceKind.allCases, id: \.self) { kind in
                    Label(kind.displayName, systemImage: kind.systemImage).tag(kind)
                }
            }
            .onChange(of: credentialKind) {
                sourceTest = .idle
                // Arriving at 1Password with OTP already on needs the same ask.
                promptForOTPFieldIfNeeded()
            }

            switch credentialKind {
            case .manual:
                EmptyView()
            case .onePassword:
                onePasswordSource
            case .applePasswords:
                TextField("Website or server", text: $sourceReference,
                          prompt: Text(verbatim: evaluation?.remoteHost ?? "vpn.example.com"))
                    .autocorrectionDisabled()
                TextField("Account (optional)", text: $sourceAccount)
                    .autocorrectionDisabled()
                Text("SimpleVPN reads the saved username and password for this server from Apple Passwords. macOS asks your permission the first time. One-time codes aren't read — enter those below if required.")
                    .font(.callout).foregroundStyle(.secondary)
                sourceTestRow
            }
        }
    }

    /// 1Password source: reference/vault fields, a drop well for dragging an item
    /// straight in from 1Password, and the field-role mapping.
    @ViewBuilder private var onePasswordSource: some View {
        if OnePasswordProvider.cliPath == nil {
            Label("The 1Password command-line tool (op) isn't installed. Install it, then enable Developer ▸ CLI in the 1Password app.",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
        }
        TextField("Item name or link", text: $sourceReference, prompt: Text("GR Lab VPN"))
            .autocorrectionDisabled()
        TextField("Vault (optional)", text: $sourceAccount)
            .autocorrectionDisabled()

        // Drop well — drag an item from the 1Password app onto here.
        onePasswordDropWell

        // Field-role mapping summary + editor.
        if !fieldMap.isEmpty {
            ForEach(mappedRoleSummary, id: \.self) { line in
                Label(line, systemImage: "arrow.right.circle").font(.callout).foregroundStyle(.secondary)
            }
        }
        HStack {
            Button(fieldMap.isEmpty ? "Choose Fields…" : "Change Fields…") {
                Task { await loadOPFieldsAndShowSheet() }
            }
            .disabled(sourceReference.trimmingCharacters(in: .whitespaces).isEmpty
                      || OnePasswordProvider.cliPath == nil || loadingOPFields)
            if loadingOPFields { ProgressView().controlSize(.small) }
            if let err = opFieldError {
                Label(err, systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.callout).lineLimit(2)
            }
            Spacer()
        }

        Text("SimpleVPN reads the mapped fields through 1Password. If you don't map them, it uses the item's standard username, password and one-time-code fields. 1Password handles unlock (Touch ID); the vault password never reaches SimpleVPN.")
            .font(.callout).foregroundStyle(.secondary)
        sourceTestRow
    }

    private var onePasswordDropWell: some View {
        RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5]))
            .foregroundStyle(.tertiary)
            .frame(height: 52)
            .overlay {
                Label(opItemTitle.isEmpty ? "Drag a 1Password item here" : "Item: \(opItemTitle)",
                      systemImage: "square.and.arrow.down")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .dropDestination(for: String.self) { items, _ in
                guard let raw = items.first else { return false }
                return handleOnePasswordDrop(raw)
            }
            .contentShape(Rectangle())
    }

    /// A 1Password drag delivers text: a secret reference (op://vault/item/field),
    /// a deep link (onepassword://…?i=item&v=vault), or a plain item name/UUID.
    /// Extract a reference + vault, then load the item's fields for mapping.
    private func handleOnePasswordDrop(_ raw: String) -> Bool {
        guard let (ref, vault) = Self.parseOnePasswordDrop(raw) else { return false }
        sourceReference = ref
        if !vault.isEmpty { sourceAccount = vault }
        Task { await loadOPFieldsAndShowSheet() }
        return true
    }

    static func parseOnePasswordDrop(_ raw: String) -> (reference: String, vault: String)? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.hasPrefix("op://") {
            // op://<vault>/<item>[/<section>/<field>] — keep vault + item.
            let parts = s.dropFirst("op://".count).split(separator: "/").map(String.init)
            if parts.count >= 2 { return (parts[1], parts[0]) }
            if parts.count == 1 { return (parts[0], "") }
            return nil
        }
        if s.hasPrefix("onepassword://"), let comps = URLComponents(string: s) {
            let q = comps.queryItems ?? []
            let item = q.first { $0.name == "i" || $0.name == "item" }?.value
            let vault = q.first { $0.name == "v" || $0.name == "vault" }?.value ?? ""
            if let item, !item.isEmpty { return (item, vault) }
            return nil
        }
        // Plain text: the item's name or UUID. First line only.
        let firstLine = s.split(whereSeparator: \.isNewline).first.map(String.init) ?? s
        return (firstLine, "")
    }

    /// The auth roles this VPN uses — the sheet renders exactly these.
    private var applicableRoles: [CredentialRole] {
        CredentialRole.forOpenVPN(evaluation: evaluation, requiresOTP: requiresOTP)
    }

    private func loadOPFieldsAndShowSheet() async {
        opFieldError = nil
        loadingOPFields = true
        defer { loadingOPFields = false }
        do {
            let (title, fields) = try await OnePasswordProvider.listFields(
                itemReference: sourceReference, vault: sourceAccount)
            opItemTitle = title
            opFields = fields
            // Seed only the roles this VPN uses, from the item's field purposes/types.
            let roles = Set(applicableRoles)
            if roles.contains(.username), fieldMap["username"] == nil,
               let f = fields.first(where: { $0.purpose == "USERNAME" }) { fieldMap["username"] = f.id }
            if roles.contains(.password), fieldMap["password"] == nil,
               let f = fields.first(where: { $0.purpose == "PASSWORD" }) { fieldMap["password"] = f.id }
            if roles.contains(.otp), fieldMap["otp"] == nil,
               let f = fields.first(where: { $0.isOTP }) { fieldMap["otp"] = f.id }
            showFieldMap = true
        } catch {
            opFieldError = error.localizedDescription
        }
    }

    /// Human summary of the current role→field mapping ("Username → email"),
    /// limited to the roles this VPN actually uses.
    private var mappedRoleSummary: [String] {
        applicableRoles.compactMap { role in
            guard let fieldID = fieldMap[role.id], !fieldID.isEmpty else { return nil }
            let label = opFields.first { $0.id == fieldID }?.label ?? fieldID
            return "\(role.title) → \(label)"
        }
    }

    @ViewBuilder private var sourceTestRow: some View {
        HStack {
            Button("Test") { Task { await testSource() } }
                .disabled(sourceReference.trimmingCharacters(in: .whitespaces).isEmpty || sourceTest == .testing)
            switch sourceTest {
            case .idle: EmptyView()
            case .testing: ProgressView().controlSize(.small)
            case .ok(let who):
                Label(who, systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.callout)
            case .failed(let msg):
                Label(msg, systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.callout)
                    .lineLimit(3)
            }
            Spacer()
        }
    }

    private func testSource() async {
        sourceTest = .testing
        // Persist the current source first so the controller builds the right provider.
        await saveCredentialSource()
        guard let provider = vpn.managerProvider(for: profileID) else { sourceTest = .idle; return }
        do {
            let raw = try await provider.resolve(profile: profileID, fields: [.username, .password, .otp])
            let user = raw.username.map { "as \($0)" } ?? "found"
            let hasOTP = (raw.otp?.isEmpty == false) ? " · one-time code available" : ""
            sourceTest = raw.password?.isEmpty == false
                ? .ok("Found \(user)\(hasOTP)")
                : .failed("Item found but has no password.")
        } catch {
            sourceTest = .failed(error.localizedDescription)
        }
    }

    private func saveCredentialSource() async {
        var source = CredentialSource()
        source.kind = credentialKind
        source.reference = sourceReference.trimmingCharacters(in: .whitespaces)
        source.account = sourceAccount.trimmingCharacters(in: .whitespaces)
        // Field mapping only applies to 1Password; drop it otherwise.
        source.fieldMap = credentialKind == .onePassword ? fieldMap : [:]
        try? await vpn.setCredentialSource(source, for: profileID)
    }

    private var usernameLocked: Bool {
        !(evaluation?.userlockedUsername.isEmpty ?? true)
    }

    private var configurationTab: some View {
        Form {
            Section("Configuration (.ovpn)") {
                TextEditor(text: $ovpn)
                    .font(.callout.monospaced())
                    .frame(minHeight: 320)
            }
        }
        .formStyle(.grouped)
    }

    /// Why Save can't be pressed — surfaced in a tooltip, because a dead button with
    /// no explanation is indistinguishable from a broken app (and the config banner at
    /// the bottom is easy to miss).
    /// Deliberately does NOT include a configuration parse error. A config that won't
    /// connect yet must still be savable — an imported .conf that references cert
    /// FILES (`ca /etc/openvpn/ca.crt`) fails the engine's eval because we only hold
    /// the text, and refusing to save it meant you couldn't save a half-fixed config
    /// either. The error still blocks connecting, and the banner still explains it.
    private var saveDisabledReason: String? {
        if saving { return "Saving…" }
        if name.isEmpty { return "Give this VPN a name first." }
        return nil
    }

    /// Shown on the Save button when the config saves fine but won't connect yet.
    private var saveWarning: String? {
        evaluation?.error == true
            ? "Saved settings will be kept, but this VPN won't connect until the configuration problem below is fixed."
            : nil
    }

    private var saveButton: some View {
        Button { Task { await save() } } label: {
            // Embedded (the Manage pane) doesn't close on save, so success has to be
            // visible somehow — otherwise Save looks like it did nothing.
            if savedTick {
                Label("Saved", systemImage: "checkmark")
            } else {
                Text("Save")
            }
        }
        .buttonStyle(.glassProminent)
        .disabled(saveDisabledReason != nil)
        .help(saveDisabledReason ?? (embedded ? "Save changes to this VPN" : "Save and close"))
        .animation(.snappy(duration: 0.2), value: savedTick)
    }

    // MARK: Load / save

    private func load() {
        guard !loaded else { return }
        loaded = true
        name = vpn.profiles.first { $0.id == profileID }?.name ?? ""
        ovpn = vpn.ovpnText(id: profileID) ?? ""
        loadedOVPN = ovpn
        logo = LogoStore.load(profileID)
        // Shared credential state: whatever was typed in the main window or the
        // menu bar shows here too (falls back to the keychain, then empty).
        let creds = vpn.transientCredentials(for: profileID)
        username = creds.username
        password = creds.password
        if let locked = evaluation?.userlockedUsername, !locked.isEmpty { username = locked }
        draft = vpn.overrides(for: profileID)
        loadedOverrides = draft
        let secrets = KeychainCredentialStore.loadProfileSecrets(profile: profileID)
        proxyPassword = secrets?.proxyPassword ?? ""
        privateKeyPassword = secrets?.privateKeyPassword ?? ""
        let auth = vpn.authConfig(for: profileID)
        requiresOTP = auth.requiresOTP
        passwordTemplate = auth.passwordTemplate
        remember = auth.rememberCredentials
        let source = vpn.credentialSource(for: profileID)
        credentialKind = source.kind
        sourceReference = source.reference
        sourceAccount = source.account
        fieldMap = source.fieldMap
    }

    private func save() async {
        saving = true; defer { saving = false }
        if !name.isEmpty { try? await vpn.rename(id: profileID, to: name) }

        // Configuration/overrides/auth are what MDM LockConfiguration governs — skip
        // them under the lock (rather than calling and swallowing the thrown error),
        // and surface any real failure instead of dismissing as if it saved.
        if !ManagedPolicy.lockConfiguration {
            let server = evaluation?.remoteHostOrNil ?? name
            var auth = VPNAuthConfig()
            auth.requiresOTP = requiresOTP
            auth.passwordTemplate = passwordTemplate.trimmingCharacters(in: .whitespaces).isEmpty
                ? VPNAuthConfig.defaultTemplate : passwordTemplate
            auth.rememberCredentials = remember
            do {
                try await vpn.updateOVPN(id: profileID, ovpn: ovpn, server: server)
                try await vpn.setOverrides(draft, for: profileID)
                try await vpn.setAuthConfig(auth, for: profileID)
                loadedOVPN = ovpn; loadedOverrides = draft   // snapshots now match persisted
            } catch {
                saveError = error.localizedDescription
                return   // don't dismiss — the change didn't persist
            }
        }

        await saveCredentialSource()

        // Push into the shared credential state so the main window and menu bar
        // immediately see what was typed here.
        var live = vpn.transientCredentials(for: profileID)
        live.username = username
        live.password = password
        vpn.transientCreds[profileID] = live

        // The profile's allow-password-save (auth-nocache) always wins over the toggle.
        let mayRemember = evaluation?.allowPasswordSave ?? true
        if mayRemember && remember && !username.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: profileID, .init(username: username, password: password))
        } else if !remember || !mayRemember {
            KeychainCredentialStore.deleteCredentials(profile: profileID)
        }
        try? KeychainCredentialStore.saveProfileSecrets(profile: profileID, .init(
            proxyPassword: proxyPassword.isEmpty ? nil : proxyPassword,
            privateKeyPassword: privateKeyPassword.isEmpty ? nil : privateKeyPassword))
        if embedded {
            savedTick = true
            // Long enough to SEE the tick, then done means done: close. (dismiss()
            // closes the standalone editor, or the containing Manage window.)
            Task { try? await Task.sleep(for: .seconds(0.7)); dismiss() }
        } else {
            dismiss()
        }
    }

    private func importLogo(_ result: Result<URL, Error>) { if case let .success(u) = result { importLogoFile(u) } }
    private func importLogoFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if LogoStore.save(fromFile: url, id: profileID) { logo = LogoStore.load(profileID) }
        else { vpn.lastError = "Could not read image" }
    }
}

// MARK: - Shared notices

/// "Your saved settings differ from what this session started with."
/// Shown wherever the user can see a connected VPN whose options just changed.
struct PendingSettingsNotice: View {
    @Bindable var vpn: VPNController
    let profileID: String
    @State private var reconnecting = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(.tint)
            Text("Settings changes take effect on reconnect.")
            Spacer(minLength: 8)
            Button("Reconnect") {
                reconnecting = true
                Task { await vpn.reconnect(id: profileID); reconnecting = false }
            }
            .disabled(reconnecting)
        }
        .font(.callout)
        .padding(10)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .padding([.horizontal, .bottom], 12)
        .accessibilityElement(children: .combine)
    }
}

/// The profile text doesn't parse — shown while editing, and save is blocked.
struct EvaluationErrorBanner: View {
    let message: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(message.isEmpty ? "This configuration can't be read." : message)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.callout)
        .padding(10)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .padding([.horizontal, .bottom], 12)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Configuration error: \(message)")
    }
}
