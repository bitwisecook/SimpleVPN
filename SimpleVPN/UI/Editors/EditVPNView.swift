// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EditVPNView.swift
//  Edit sheet for a single VPN entry, tabbed (tab order follows the canonical
//  group order, AGENTS.md "Config surfaces": Connection → Sign-In → …):
//   • General        — name, logo, labels
//   • Servers        — endpoints (the Connection story)
//   • Sign-In        — credentials + credential sources (adapts to the profile:
//                      hidden for autologin, username locked when pinned)
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
    /// Called after a successful embedded save. `dismiss()` is a no-op in a
    /// split-view detail, so the parent (Manage VPNs) decides what "done"
    /// means — e.g. close the window when it holds only this one VPN.
    var onSaved: (() -> Void)? = nil

    @Environment(\.dismiss) private var dismiss
    @Environment(ProfileEvaluator.self) private var evaluator

    /// Which tab is showing. A binding, so the cross-links below (Sign-In →
    /// Options ▸ Sign-In, Certificates → the private-key password, Traffic ↔
    /// Custom Routing) and app-wide search can select one.
    @State private var tab: SettingsTab = .general
    /// The editor's search catalog — the OpenVPN engine options AND the Custom
    /// Routing tab, so one field finds everything this editor holds and a hit on
    /// the other tab selects it. Owned HERE rather than inside
    /// OpenVPNOptionsForm, which is what confined search to that one form.
    @State private var search = SettingsSearch(surfaces: [.openVPN, .customRouting],
                                               kind: .openVPN)

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
    // Optional interface controls (VPNUIPrefs) — advanced surfaces are per-VPN opt-in.
    @State private var allowPause = false
    @State private var showConnectionManager = false
    /// Authenticator (TOTP) setup key destined for the Touch ID-locked item.
    /// Loaded EMPTY even when one is stored (reading it back would cost a
    /// fingerprint prompt just to open the editor); saving a non-empty value
    /// replaces the stored secret, leaving it empty keeps whatever is there.
    @State private var totpSecretInput = ""
    @State private var passwordTemplate = VPNAuthConfig.defaultTemplate
    @State private var otpAdvancedExpanded = false

    // Custom Routing draft (Mediators/CustomRouting.swift) — owned here (not inside
    // CustomRoutingTabView) so the toolbar Save button can commit it even while the
    // tab never disappears; see CustomRoutingTabView.swift's header comment.
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    // Credential source (manual / 1Password / Apple Passwords)
    @State private var credentialKind: CredentialSourceKind = .manual
    @State private var sourceReference = ""
    /// 1Password: which account to ask. Apple Passwords: which saved login.
    @State private var sourceAccount = ""
    /// 1Password only — a vault is a drawer inside an account, so it gets its
    /// own field; sharing one with `sourceAccount` is what left every 1Password
    /// fetch asking for an account nobody had ever been able to enter.
    @State private var sourceVault = ""
    @State private var sourceTest: SourceTestState = .idle

    // 1Password field mapping (which item field feeds which auth role)
    @State private var fieldMap: [String: String] = [:]
    @State private var opFields: [OnePasswordProvider.OPField] = []
    @State private var opItemTitle = ""
    @State private var showFieldMap = false
    @State private var loadingOPFields = false
    @State private var opFieldError: String?
    /// Whether a 1Password app with SDK support is installed (prompt-free
    /// probe via the bundled helper). Starts optimistic so the warning never
    /// flashes while the probe is in flight.
    @State private var opAvailable = true
    /// The setup check behind the walkthrough card. Runs ONLY when 1Password is
    /// newly chosen here (or Check Again is clicked) — never on open, which for
    /// an already-configured VPN would be an unasked-for lookup.
    @State private var opPreflight = OnePasswordPreflightModel()
    /// Collapses the several deliveries macOS makes of one drag into one apply.
    @State private var opDrops = OnePasswordDropCollector()
    /// Whether KeePassXC's browser-integration socket is there to talk to
    /// (prompt-free stat, no connection). Same optimistic start as
    /// `opAvailable`, and for the same reason.
    @State private var kpAvailable = true
    /// Whether Keeper Commander is present AND has a live session. Same
    /// optimistic start as the two above: proving it costs a subprocess, and a
    /// warning that flashes while the probe runs is worse than none.
    @State private var keeperAvailable = true

    // 1Password browsing (vault/item pickers). Every list is fetched ONLY on an
    // explicit click: the first one can raise 1Password's authorization prompt,
    // and this app never makes a lookup the user didn't ask for.
    @State private var opVaults: [OnePasswordNative.OPVaultOverview] = []
    @State private var opItems: [OnePasswordNative.OPItemInVault] = []
    /// Which vault `opItems` was loaded from ("" = every vault) — changing vault
    /// invalidates it, so the picker can never offer one drawer's contents under
    /// another's name.
    @State private var opItemsVault = ""
    /// Whether `opItemsVault` describes a list we actually hold; an empty vault
    /// is a real scope ("all of them"), so it can't double as "nothing loaded".
    @State private var opItemsLoaded = false
    @State private var loadingOPVaults = false
    @State private var loadingOPItems = false
    @State private var opBrowseError: String?
    @State private var showItemBrowser = false
    @State private var showVaultBrowser = false
    @State private var dropTargeted = false
    /// A multi-selection drag: several items arrived and a VPN uses one, so the
    /// choice is offered rather than guessed. Empty = nothing pending.
    @State private var droppedChoices: [OnePasswordDrop] = []
    @State private var showDropChooser = false
    /// A lookup reached 1Password and was told it doesn't know the account.
    /// Deliberately NOT an error: the drop/pick worked, only the account name
    /// is missing, so it shows as a nudge at the Account field.
    @State private var opNeedsAccount = false

    private enum SourceTestState: Equatable {
        case idle, testing, ok(String), failed(String)
    }

    private var evaluation: ProfileEvaluation? {
        ovpn.isEmpty ? nil : evaluator.evaluation(for: ovpn)
    }

    /// The profile signs in with its certificate alone — no username, password or
    /// code exists to collect, and none may be SAVED either (see `save()`).
    private var isAutologin: Bool { evaluation?.autologin == true }

    /// The `static-challenge` prompt this profile declares, or nil. When present
    /// the server demands a code on every connect whatever the toggle says
    /// (`VPNController.effectiveAuthConfig`), so the toggle is pinned on.
    private var staticChallenge: String? {
        guard let text = evaluation?.staticChallenge, !text.isEmpty else { return nil }
        return text
    }

    /// Why the verification-code toggle can't be turned off, or nil.
    private var otpPinnedReason: String? {
        staticChallenge == nil ? nil
            : "This VPN's configuration asks the server for a code itself (static-challenge), so a code is always required."
    }

    /// The OTP requirement IN EFFECT — the toggle, or forced on by the profile's
    /// own static challenge. Everything that depends on "does this VPN need a
    /// code" reads this, not the raw toggle state.
    private var otpRequired: Bool { staticChallenge != nil || requiresOTP }

    /// Why the password template can't be edited, or nil. A static challenge
    /// sends the code as the engine's own challenge response (SCRV1 framing), so
    /// the `{password}{otp}` assembly never runs — see `VPNController.connect`.
    private var templateInertReason: String? {
        guard staticChallenge != nil else { return nil }
        return "This VPN sends the code separately from the password (SCRV1), so the password isn't assembled from a template."
    }

    var body: some View {
        NavigationStack {
            TabView(selection: $tab) {
                generalTab
                    .tag(SettingsTab.general)
                    .tabItem { Label("General", systemImage: "info.circle") }
                // Saves as it goes (see EndpointsEditor) — no draft to reconcile
                // with this sheet's Save button.
                EndpointsEditor(vpn: vpn, profileID: profileID)
                    .tag(SettingsTab.servers)
                    .tabItem { Label("Servers", systemImage: "mappin.and.ellipse") }
                credentialsTab
                    .tag(SettingsTab.signIn)
                    .tabItem { Label("Sign-In", systemImage: "person.badge.key") }
                optionsTab
                    .tag(SettingsTab.options)
                    .tabItem { Label("Options", systemImage: "slider.horizontal.3") }
                CertificatesTab(ovpn: $ovpn, evaluation: evaluation)
                    .disabled(ManagedPolicy.lockConfiguration)
                    .tag(SettingsTab.certificates)
                    .tabItem { Label("Certificates", systemImage: "checkmark.seal") }
                configurationTab
                    .disabled(ManagedPolicy.lockConfiguration)
                    .tag(SettingsTab.configuration)
                    .tabItem { Label("Configuration", systemImage: "doc.text") }
                customRoutingTab
                    .tag(SettingsTab.customRouting)
                    .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
            }
            // Publishes `search` to every row, follows a reveal across tabs, and
            // serves incoming SettingsRoutes (UI/Components/SettingsEditorShell.swift).
            .settingsEditor(search: search, tab: $tab,
                            surfaces: [.openVPN, .customRouting], profileID: profileID)
            // Clear the toolbar's scroll-edge shadow band — without this the
            // segmented tab strip sits flush under the title bar and the edge
            // effect overlays its top pixels.
            .padding(.top, 10)
            .navigationTitle(embedded ? name : "Edit VPN")
            .task {
                load()
                kpAvailable = KeePassXCProvider.probe()
                opAvailable = await OnePasswordNative.probe()
                // A live Keeper session is the only thing worth warning about:
                // Commander missing entirely is covered by the row's own copy.
                if KeeperCommanderChannel.isInstalled() {
                    keeperAvailable = await KeeperCommanderChannel.hasLiveSession()
                }
                // Prompt-free, so this much can be said without anyone asking:
                // no 1Password on this Mac is a setup state, not a failure.
                if !opAvailable { opPreflight.note(.notInstalled) }
            }
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
                Button("OK", role: .cancel) { saveError = nil }
            } message: { Text(saveError ?? "") }
            .fileImporter(isPresented: $showLogoImporter, allowedContentTypes: [.image], onCompletion: importLogo)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if embedded {
                        Button("Revert") { loaded = false; load() }
                    } else {
                        Button("Cancel") { dismiss() }
                            .keyboardShortcut(.cancelAction)
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
                } else if let advice = evaluation?.pkcs11Advice {
                    // Before the generic parse error: the engine rejects a pkcs11
                    // profile as "unsupported options", which says nothing about the
                    // smartcard the user is holding.
                    EvaluationErrorBanner(message: advice)
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

    /// Extracted (like `customRoutingTab` below) because SwiftUI type-checks a
    /// `TabView`'s whole builder as ONE expression: adding the selection binding
    /// and the tags pushed the seven-tab body past what the compiler will do in
    /// reasonable time.
    private var optionsTab: some View {
        OpenVPNOptionsForm(draft: $draft,
                           proxyPassword: $proxyPassword,
                           privateKeyPassword: $privateKeyPassword,
                           evaluation: evaluation)
            .disabled(ManagedPolicy.lockConfiguration)
    }

    private var customRoutingTab: some View {
        Form {
            CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                 proxyAuthUsername: $crProxyAuthUsername,
                                 proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .revealsSettings()
        // Routes, DNS and the proxy (including a proxy sign-in that goes to the
        // keychain) ARE connection settings, so a managed lock covers them — the
        // other five editors' Custom Routing tabs already carried this and this
        // one didn't. `commitCustomRouting`/`setCustomRouting` refuse under the
        // lock too: the UI is never the only enforcement point.
        .disabled(ManagedPolicy.lockConfiguration)
    }

    private var generalTab: some View {
        Form {
            // The name is purely what YOU call this VPN — the addresses it
            // connects to live on the Servers tab, so renaming never changes
            // the connection and changing server never renames the VPN.
            Section("Name") {
                TextField("Name", text: $name, prompt: Text("Work, Home, Mum's house…"))
                Text("Just a name for you. The addresses this VPN connects to are on the Servers tab.")
                    .font(.callout).foregroundStyle(.secondary)
            }

            Section("Logo") {
                HStack(spacing: 14) {
                    LogoWell(image: logo, pick: { showLogoImporter = true }, drop: { importLogoFile($0) })
                    VStack(alignment: .leading, spacing: 6) {
                        Button("Choose Image…") { showLogoImporter = true }
                        if logo != nil {
                            Button("Remove", role: .destructive) { LogoStore.delete(profileID); logo = nil }
                                .accessibilityLabel("Remove logo")
                        }
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

            // Advanced controls are per-VPN opt-in so the default interface stays
            // simple — most people only ever connect and disconnect.
            Section("Optional Controls") {
                Toggle("Show a Pause button", isOn: $allowPause)
                Text("Pause keeps the VPN signed in but sends traffic outside it (using your normal connection) until you resume.")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("Show the Connection Manager", isOn: $showConnectionManager)
                Text("An advanced panel on the connection page with health checks and connection toggles.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private var credentialsTab: some View {
        Form {
            // Three sign-in settings live on the OPTIONS tab, because they are
            // engine overrides: keep retrying after a failed sign-in, server
            // session tokens, and the private key's password. Someone looking for
            // them on the tab called "Sign-In" could not find them — so this tab
            // now says where they are and takes you there.
            Section {
                SettingJumpLink(title: "Keep retrying after a failed sign-in",
                                settingID: "openvpn.retry-on-auth-failed")
                SettingJumpLink(title: "Use server session tokens",
                                settingID: "openvpn.autologin-sessions")
                SettingJumpLink(title: "Private Key Password",
                                settingID: "openvpn.private-key-password")
            } header: {
                Text("Also in Options \u{25B8} Sign-In")
            } footer: {
                Text("These three are engine options, so they live on the Options tab. Choosing one opens it there.")
            }
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
                        // AppKit-backed AutoFill fields (SwiftUI's
                        // .textContentType is a no-op on macOS): the key-icon
                        // suggestions from Apple Passwords and any enabled
                        // credential provider work here, same as the connect
                        // form. LabeledContent supplies the label a bare
                        // representable lacks in a Form row.
                        LabeledContent("Username") {
                            AutoFillField(kind: .username, placeholder: "Username",
                                          text: $username)
                        }
                        .disabled(usernameLocked)
                        if usernameLocked {
                            Text("This configuration only works with the username above.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        LabeledContent("Password") {
                            AutoFillField(kind: .password, placeholder: "Password",
                                          text: $password)
                        }
                        if evaluation?.allowPasswordSave ?? true {
                            Toggle("Remember password", isOn: $remember)
                        } else {
                            Label("This VPN's administrator doesn't allow saving the password.",
                                  systemImage: "key.slash")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }

                    if evaluation?.allowPasswordSave ?? true {
                        Section("Touch ID") {
                            Toggle("Protect the sign-in with Touch ID", isOn: protectBinding)
                            Text("The saved username and password move into a fingerprint-locked keychain item; connecting asks for Touch ID (or your Apple Watch, or the account password) to release them.")
                                .font(.callout).foregroundStyle(.secondary)
                            if otpRequired && vpn.authConfig(for: profileID).protectWithBiometrics {
                                // Stays a SecureField, not an AutoFillField: a
                                // TOTP ENROLLMENT SEED has no NSTextContentType
                                // (.oneTimeCode means a current 6-digit code),
                                // so AutoFill could only ever offer the wrong
                                // thing here.
                                SecureField("Authenticator setup key (otpauth:// link or secret)",
                                            text: $totpSecretInput)
                                    .autocorrectionDisabled()
                                    .accessibilityLabel("Authenticator setup key")
                                    // The invalid-key warning is the FIELD's
                                    // problem — it rides the value, not just
                                    // orange text further down.
                                    .accessibilityValue(totpSecretInput.isEmpty ? "not set"
                                        : (TOTPConfiguration.canonicalStorageString(from: totpSecretInput) == nil
                                           ? "set, but it doesn't look like a valid setup key" : "set"))
                                Text("Paste the setup key your authenticator was enrolled with and the fingerprint covers the verification code too — no more typing codes. Saved only inside the Touch ID-locked item.")
                                    .font(.callout).foregroundStyle(.secondary)
                                if !totpSecretInput.isEmpty && TOTPConfiguration.canonicalStorageString(from: totpSecretInput) == nil {
                                    Label("That doesn't look like a valid setup key (otpauth:// link or base32 secret).",
                                          systemImage: "exclamationmark.triangle.fill")
                                        .font(.callout).foregroundStyle(.orange)
                                        .accessibilityLabel("Problem: that doesn't look like a valid setup key")
                                }
                            }
                        }
                    }
                }

                Section("Verification Code") {
                    // Pinned ON by a profile-declared static challenge: the server
                    // asks for the code whatever this says, so the control that
                    // can't change anything is dead — and says why.
                    Toggle("Requires a verification code (OTP)",
                           isOn: otpPinnedReason == nil ? $requiresOTP : .constant(true))
                        .disabled(otpPinnedReason != nil)
                        .help(otpPinnedReason
                              ?? "Ask for a fresh code from your authenticator each time this VPN connects.")
                        .accessibilityValue(otpPinnedReason.map { "on, unavailable — \($0)" }
                                            ?? (requiresOTP ? "on" : "off"))
                        .onChange(of: requiresOTP) { _, on in
                            if on { promptForOTPFieldIfNeeded() }
                        }
                    if let reason = otpPinnedReason {
                        Text(reason)
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Each connection asks for a fresh code from your authenticator. Quick connect from the menu bar opens the window so the code can be typed.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    // What the server will actually put on screen — it comes from
                    // the profile, and until now nothing showed it anywhere.
                    if let prompt = staticChallenge {
                        Label("The server's prompt: \u{201C}\(prompt)\u{201D}\(staticChallengeEchoNote)",
                              systemImage: "text.bubble")
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    if otpRequired {
                        managedOTPSourceRow
                        DisclosureGroup(isExpanded: $otpAdvancedExpanded) {
                            TextField("Password template", text: $passwordTemplate,
                                      prompt: Text(verbatim: VPNAuthConfig.defaultTemplate))
                                .font(.body.monospaced())
                                .autocorrectionDisabled()
                                .padding(.top, 4)
                                .disabled(templateInertReason != nil)
                                .help(templateInertReason
                                      ?? "How the sign-in password is assembled from your password and the code.")
                                .accessibilityValue(templateInertReason.map { "unavailable — \($0)" }
                                    ?? (templateValid ? passwordTemplate
                                        : "\(passwordTemplate). Problem: the template must contain {otp}"))
                            if let reason = templateInertReason {
                                Text(reason)
                                    .font(.callout).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            } else {
                                Text("How the sign-in password is assembled from your password and the verification code. \u{201C}{password}{otp}\u{201D} sends them joined together — what most OTP-enabled servers (LinOTP, privacyIDEA) expect.")
                                    .font(.callout).foregroundStyle(.secondary)
                                if !templateValid {
                                    Label("The template must contain {otp} — the default will be used instead.",
                                          systemImage: "exclamationmark.triangle.fill")
                                        .font(.callout).foregroundStyle(.orange)
                                        .accessibilityLabel("Problem: the template must contain {otp} — the default will be used instead.")
                                }
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

    /// Whether the profile asks for the code to be echoed as it's typed — worth
    /// saying, because it changes what the connect form looks like.
    private var staticChallengeEchoNote: String {
        (evaluation?.staticChallengeEcho ?? false) ? " (shown as you type)" : ""
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
                    .accessibilityHidden(true)   // the text states the same thing
                VStack(alignment: .leading, spacing: 2) {
                    if let mapped {
                        Text("Verification code comes from the \u{201C}\(mapped)\u{201D} field in 1Password")
                            .font(.callout)
                    } else if noItemYet {
                        Text("Choose a 1Password item below, then pick the field holding the code.")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Which 1Password field holds the code?").font(.callout)
                        Text("Until you pick one, SimpleVPN tries the field 1Password marks as a one-time password.")
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .accessibilityElement(children: .combine)
                Spacer(minLength: 8)
                if !noItemYet {
                    Button(mapped == nil ? "Choose Field\u{2026}" : "Change\u{2026}") {
                        Task { await loadOPFieldsAndShowSheet() }
                    }
                    .disabled(!opAvailable || loadingOPFields)
                    // "Change…" alone answers nothing — change WHAT?
                    .accessibilityLabel(mapped == nil ? "Choose the 1Password field holding the code"
                                                      : "Change the 1Password field holding the code")
                }
            }
        } else if credentialKind == .keePassXC {
            // No mapping to configure: KeePassXC computes the code from the
            // matched entry's own TOTP settings — worth saying, so nobody goes
            // hunting for a field picker that doesn't exist.
            Label("KeePassXC supplies the verification code from the matched entry's TOTP, when it has one.",
                  systemImage: "arrow.right.circle")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    /// Flipping OTP on is exactly when to ask which 1Password field carries the code —
    /// the user is already thinking about it, and the alternative is finding out at
    /// connect time. Only auto-opens when we can genuinely populate the sheet; otherwise
    /// `managedOTPSourceRow` carries the ask until an item has been chosen.
    private func promptForOTPFieldIfNeeded() {
        guard otpRequired, credentialKind == .onePassword,
              (fieldMap["otp"] ?? "").isEmpty,
              !sourceReference.trimmingCharacters(in: .whitespaces).isEmpty,
              opAvailable,
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
            .onChange(of: credentialKind) { _, kind in
                sourceTest = .idle
                prefillRememberedAccount()
                // Choosing 1Password is the first genuine need for a 1Password
                // lookup — the one moment this app is allowed to raise its
                // approval prompt. Skipped once the integration has been proven.
                if kind == .onePassword { runOnePasswordPreflight(force: false) }
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
                Text("SimpleVPN reads the saved username and password for this server from Apple Passwords. macOS asks your permission the first time. Verification codes aren't read — enter those below if required.")
                    .font(.callout).foregroundStyle(.secondary)
                sourceTestRow
            case .keePassXC:
                TextField("Website or server", text: $sourceReference,
                          prompt: Text(verbatim: evaluation?.remoteHost ?? "vpn.example.com"))
                    .autocorrectionDisabled()
                TextField("Account (optional \u{2014} only needed if several entries match)",
                          text: $sourceAccount)
                    .autocorrectionDisabled()
                if !kpAvailable {
                    Label("KeePassXC isn't running (or its browser integration is off). Open KeePassXC and turn on Settings \u{25B8} Browser Integration \u{25B8} \u{201C}Enable browser integration\u{201D}.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("SimpleVPN asks the KeePassXC app for the entry whose URL matches this address — including its verification code, when the entry has one. The first request asks you to pair (name it \u{201C}SimpleVPN\u{201D}), and a locked database raises KeePassXC's own unlock.")
                    .font(.callout).foregroundStyle(.secondary)
                sourceTestRow
            case .keeper:
                // Keeper names a RECORD, not an address: Keeper Commander takes
                // the record's title, its UID, or its folder path.
                TextField("Record name, UID, or folder path", text: $sourceReference,
                          prompt: Text(verbatim: "Work/VPN/GR Lab"))
                    .autocorrectionDisabled()
                TextField("Username (optional \u{2014} only to confirm the right record)",
                          text: $sourceAccount)
                    .autocorrectionDisabled()
                if !keeperAvailable {
                    Label("Keeper Commander isn\u{2019}t signed in on this Mac. In Terminal, run \u{201C}keeper shell\u{201D} and sign in once, then \u{201C}this-device register\u{201D} and \u{201C}this-device persistent-login on\u{201D}.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("SimpleVPN asks Keeper Commander \u{2014} Keeper\u{2019}s own command-line tool \u{2014} for just this record, and reads only its username and password. Commander keeps your Keeper sign-in in this Mac\u{2019}s keychain, where macOS protects it; SimpleVPN never sees your Keeper master password and never changes Commander\u{2019}s own setup. If a verification code is required, type it below.")
                    .font(.callout).foregroundStyle(.secondary)
                sourceTestRow
            }
        }
    }

    /// 1Password source: reference/vault fields, a drop well for dragging an item
    /// straight in from 1Password, and the field-role mapping.
    @ViewBuilder private var onePasswordSource: some View {
        // Says which of the setup steps is actually missing, and offers the
        // button that fixes it — the old static warning said all of them at
        // once, whether or not any of it was true. The account state is left to
        // the nudge beside the Account field below: one ask, in one place.
        OnePasswordSetupCard(model: opPreflight,
                             onCheckAgain: { runOnePasswordPreflight(force: true) })
        // Typing stays the base: the pickers need 1Password running, approved
        // and reachable, and none of that is true offline or before the first
        // approval — so a typed item/vault must always be enough on its own.
        HStack(spacing: 6) {
            TextField("Item name or link", text: $sourceReference, prompt: Text("GR Lab VPN"))
                .autocorrectionDisabled()
            opItemBrowseButton
        }
        // A dragged item is linked by its 1Password id, which is exact but says
        // nothing to a human — so the readable name is stated beside it.
        if !opItemTitle.isEmpty, opItemTitle != sourceReference.trimmingCharacters(in: .whitespaces) {
            Text("This is \u{201C}\(opItemTitle)\u{201D} \u{2014} linked by its 1Password id, so renaming it won\u{2019}t break this VPN.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        HStack(spacing: 6) {
            TextField("Vault (optional)", text: $sourceVault)
                .autocorrectionDisabled()
            opVaultBrowseButton
        }
        TextField("Account (optional \u{2014} only needed if you have more than one)",
                  text: $sourceAccount)
            .autocorrectionDisabled()
            // Enter re-runs the lookup that was waiting on this name, so filling
            // it in finishes the job instead of just sitting there.
            .onSubmit {
                guard opNeedsAccount else { return }
                Task { await loadOPFieldsAndShowSheet() }
            }
        Text("The name at the top of 1Password\u{2019}s sidebar. SimpleVPN remembers it for your other VPNs.")
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        opBrowseStatus

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
                      || !opAvailable || loadingOPFields)
            if loadingOPFields {
                ProgressView().controlSize(.small)
                    .accessibilityLabel("Asking 1Password")
            }
            if let err = opFieldError {
                Label(err, systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.callout).lineLimit(2)
                    .accessibilityLabel("Error: \(err)")
            }
            Spacer()
        }

        Text("SimpleVPN reads the mapped fields through 1Password. If you don't map them, it uses the item's standard username, password and one-time password fields. 1Password handles unlock (Touch ID); the vault password never reaches SimpleVPN.")
            .font(.callout).foregroundStyle(.secondary)
        sourceTestRow
    }

    /// Item browse. A labelled button, not a bare ⟳ icon: testing put someone in
    /// front of the icons who then reported there was no way to search for an
    /// item at all. Clicking fetches (1Password may ask for approval the first
    /// time) and opens a search box over the results — never fetched on its own.
    private var opItemBrowseButton: some View {
        Button {
            showItemBrowser = true
            if !opItemsLoaded || opItemsVault != itemBrowseScope {
                Task { await loadOPItems() }
            }
        } label: {
            Label("Browse\u{2026}", systemImage: "magnifyingglass")
        }
        .buttonStyle(.bordered)
        .disabled(!opAvailable)
        .accessibilityLabel("Browse 1Password items")
        .help(itemBrowseScope.isEmpty
              ? "Search the items in your 1Password vaults"
              : "Search the items in \u{201C}\(itemBrowseScope)\u{201D}")
        .popover(isPresented: $showItemBrowser) {
            OnePasswordBrowsePopover(
                searchPrompt: "Search items",
                rows: opItems.map {
                    OnePasswordBrowseRow(
                        id: $0.id, title: $0.title,
                        subtitle: [$0.vaultTitle, $0.category]
                            .filter { !$0.isEmpty }.joined(separator: " \u{00B7} "))
                },
                loading: loadingOPItems,
                status: opBrowseError,
                needsAccount: opNeedsAccount,
                onAccount: { name in
                    sourceAccount = name
                    Task { await loadOPItems() }
                },
                onPick: { row in
                    guard let item = opItems.first(where: { $0.id == row.id }) else { return }
                    showItemBrowser = false
                    chooseOPItem(item)
                },
                onRefresh: { Task { await loadOPItems() } })
        }
    }

    /// Which vault the item browser is showing — "" means every vault, which is
    /// a real answer here even though 1Password itself only lists one at a time.
    private var itemBrowseScope: String {
        sourceVault.trimmingCharacters(in: .whitespaces)
    }

    /// Vault browse — same shape as the item one.
    private var opVaultBrowseButton: some View {
        Button {
            showVaultBrowser = true
            if opVaults.isEmpty { Task { await loadOPVaults() } }
        } label: {
            Label("Browse\u{2026}", systemImage: "magnifyingglass")
        }
        .buttonStyle(.bordered)
        .disabled(!opAvailable)
        .accessibilityLabel("Browse 1Password vaults")
        .help("Search the vaults in your 1Password account")
        .popover(isPresented: $showVaultBrowser) {
            OnePasswordBrowsePopover(
                searchPrompt: "Search vaults",
                rows: opVaults.map { OnePasswordBrowseRow(id: $0.id, title: $0.title) },
                loading: loadingOPVaults,
                status: opBrowseError,
                needsAccount: opNeedsAccount,
                onAccount: { name in
                    sourceAccount = name
                    Task { await loadOPVaults() }
                },
                onPick: { row in
                    guard let vault = opVaults.first(where: { $0.id == row.id }) else { return }
                    showVaultBrowser = false
                    chooseOPVault(vault)
                },
                onRefresh: { Task { await loadOPVaults() } })
        }
    }

    /// One shared line for everything the pickers and the drop well can say.
    /// A missing account is a nudge, not a failure — the drop/pick itself
    /// worked, and calling it an error sent people looking for the wrong bug.
    @ViewBuilder private var opBrowseStatus: some View {
        if opNeedsAccount {
            Label(accountNudgeText, systemImage: "person.crop.circle.badge.questionmark")
                .font(.callout).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        } else if let err = opBrowseError {
            Label(err, systemImage: "xmark.circle.fill")
                .font(.callout).foregroundStyle(.red).lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Error: \(err)")
        }
    }

    private var accountNudgeText: String { OnePasswordPreflight.accountNudge }

    /// The setup check, from the two actions allowed to start one: choosing
    /// 1Password as this VPN's source, and clicking Check Again. `force` is the
    /// button — it re-checks even when the integration is already verified,
    /// which is the only way back from "it worked yesterday".
    private func runOnePasswordPreflight(force: Bool) {
        Task {
            let state = force
                ? await opPreflight.check(account: sourceAccount)
                : await opPreflight.checkIfNeeded(account: sourceAccount)
            switch state {
            case .ready(let vaults):
                // The check already paid for this list; the vault picker would
                // otherwise ask 1Password for it a second time.
                if !vaults.isEmpty, opVaults.isEmpty { opVaults = vaults }
                opNeedsAccount = false
            case .needsAccount:
                // The integration works — only the name is missing, which the
                // nudge beside the Account field already asks for.
                opNeedsAccount = true
            default:
                break
            }
        }
    }

    /// A blank 1Password account starts from the one that has worked before: it
    /// names WHO to ask, which is a property of the person, not of a VPN. Only
    /// ever fills a blank — a name typed here is an explicit choice and wins.
    private func prefillRememberedAccount() {
        guard credentialKind == .onePassword,
              sourceAccount.trimmingCharacters(in: .whitespaces).isEmpty else { return }
        sourceAccount = OnePasswordAccountMemory.remembered()
    }

    /// Run a 1Password lookup on the account this VPN names, and — when the only
    /// thing wrong is that 1Password doesn't know that account — retry ONCE with
    /// the name that has worked before. The retry rides a lookup the user
    /// already asked for, so it adds no unasked-for traffic, and it turns the
    /// commonest failure ("which account?" on every new VPN) into a non-event.
    /// A name that works is remembered for every other VPN.
    private func withAccountFallback<T>(_ body: (String) async throws -> T) async throws -> T {
        let typed = sourceAccount.trimmingCharacters(in: .whitespaces)
        do {
            let result = try await body(typed)
            OnePasswordAccountMemory.remember(typed)
            return result
        } catch let error as OnePasswordNativeError where isMissingAccount(error) {
            guard let fallback = OnePasswordAccountMemory.retryAccount(after: typed) else {
                throw error
            }
            let result = try await body(fallback)
            sourceAccount = fallback
            return result
        }
    }

    private func loadOPVaults() async {
        opBrowseError = nil
        loadingOPVaults = true
        defer { loadingOPVaults = false }
        do {
            opVaults = try await withAccountFallback {
                try await OnePasswordNative.listVaults(account: $0)
            }
            opNeedsAccount = false
            if opVaults.isEmpty {
                opBrowseError = "That 1Password account has no vaults SimpleVPN can see."
            }
        } catch {
            noteBrowseFailure(error)
        }
    }

    /// Items for the browser. With a vault named, that vault's items; without
    /// one, everything across every vault — the SDK still asks one vault at a
    /// time, but the person searching gets a single list.
    private func loadOPItems() async {
        let vault = itemBrowseScope
        opBrowseError = nil
        loadingOPItems = true
        defer { loadingOPItems = false }
        do {
            opItems = try await withAccountFallback { account in
                if vault.isEmpty {
                    return try await OnePasswordNative.listItemsAcrossVaults(account: account)
                }
                // Lookup rather than list even for one vault: it reports the
                // vault's real id AND title, where the plain list only knows
                // the scope string the user typed (which may be either).
                // Falls back to the list on an archive predating the endpoint.
                if let matches = try? await OnePasswordNative.lookup(
                    query: "", vault: vault, account: account) {
                    return matches.map {
                        OnePasswordNative.OPItemInVault(
                            itemID: $0.itemID, title: $0.title, category: $0.category,
                            vaultID: $0.vaultID, vaultTitle: $0.vaultTitle)
                    }
                }
                return try await OnePasswordNative.listItems(vault: vault, account: account)
                    .map {
                        OnePasswordNative.OPItemInVault(
                            itemID: $0.id, title: $0.title, category: $0.category,
                            vaultID: vault, vaultTitle: vault)
                    }
            }
            opItemsVault = vault
            opItemsLoaded = true
            opNeedsAccount = false
            if opItems.isEmpty {
                opBrowseError = vault.isEmpty
                    ? "1Password didn\u{2019}t show SimpleVPN any items."
                    : "There are no items in \u{201C}\(vault)\u{201D}."
            }
        } catch {
            opItems = []
            opItemsLoaded = false
            noteBrowseFailure(error)
        }
    }

    private func chooseOPVault(_ vault: OnePasswordNative.OPVaultOverview) {
        // The TITLE, not the UUID: it's what the user reads in 1Password, and
        // the helper accepts either.
        sourceVault = vault.title
        // Items belong to the vault they were listed from.
        opItems = []
        opItemsLoaded = false
        opItemsVault = ""
        opBrowseError = nil
        sourceTest = .idle
    }

    private func chooseOPItem(_ item: OnePasswordNative.OPItemInVault) {
        sourceReference = item.title
        opItemTitle = item.title
        // Picking from the everything list also answers "which vault?" — it was
        // listed from one, so there's nothing to guess.
        if itemBrowseScope.isEmpty, !item.vaultTitle.isEmpty { sourceVault = item.vaultTitle }
        opBrowseError = nil
        sourceTest = .idle
        // Straight on to "which field is which" — the pick is explicit, the
        // authorization has just been granted, and this is what finishes setup.
        Task { await loadOPFieldsAndShowSheet() }
    }

    /// Turn a lookup failure into one short line — or, for a missing account,
    /// into the nudge. Classified rather than raw so an account problem says
    /// "account name" instead of blaming the item.
    private func noteBrowseFailure(_ error: Error) {
        if let native = error as? OnePasswordNativeError {
            switch native {
            case .accountNotFound:
                opNeedsAccount = true
                opBrowseError = nil
                return
            case .userCancelled:
                opBrowseError = "1Password is waiting for your approval \u{2014} click Browse again after approving."
                return
            default:
                break
            }
        }
        opBrowseError = UserFacingError.classify(error).title
    }

    @ViewBuilder private var onePasswordDropWell: some View {
        RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5]))
            .foregroundStyle(dropTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            .frame(height: 52)
            .overlay {
                Label(opItemTitle.isEmpty ? "Drag a 1Password item here" : "Item: \(opItemTitle)",
                      systemImage: "square.and.arrow.down")
                    .font(.callout).foregroundStyle(.secondary)
            }
            // Four flavours, read by NSItemProvider rather than Transferable:
            // the one that matters (1Password's own payload) travels under
            // Chromium's private type identifier, which isn't a UTType on a Mac
            // and so can only be asked for by name. See OnePasswordDropItem.
            .onDrop(of: OnePasswordDropItem.acceptedContentTypes, isTargeted: $dropTargeted) {
                providers, _ in
                guard OnePasswordDropItem.canAccept(providers) else { return false }
                // Through the collector: macOS delivers one drag more than
                // once, and applying each delivery turned a single dropped item
                // into a "which one?" chooser.
                Task { if let drops = await opDrops.collect(providers) { applyDrops(drops) } }
                return true
            }
            .contentShape(Rectangle())
            // The CertDropWell rule: a drop area names itself, states its value
            // and names its keyboard alternative.
            .accessibilityLabel("1Password item drop area, \(opItemTitle.isEmpty ? "empty" : "item: \(opItemTitle)"). Use the Browse buttons or type a reference as an alternative.")
            .popover(isPresented: $showDropChooser) {
                dropChooser
            }
        // Says what a drag really does — the old well implied it did everything,
        // and for a FIELD drag (op://, no account) it doesn't.
        Text("Dragging an item straight from 1Password fills in everything. Dragging one of its fields fills in less \u{2014} Browse, or type your account name once, covers the rest.")
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Several items were dragged at once. A VPN signs in with exactly one, so
    /// the choice is asked rather than guessed — and never treated as an error.
    @ViewBuilder private var dropChooser: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Which item is this VPN\u{2019}s sign-in?").font(.callout.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            ForEach(Array(droppedChoices.enumerated()), id: \.element.id) { index, drop in
                Button(drop.displayName(position: index + 1)) {
                    showDropChooser = false
                    apply(drop)
                }
                .buttonStyle(.link)
            }
        }
        .padding(12)
        .frame(minWidth: 220)
    }

    /// A 1Password drag delivers its own payload (account + vault + item, for
    /// each item dragged), a secret reference (op://vault/item/field), a link
    /// (onepassword://…?a=account&v=vault&i=item, or the same query on a
    /// start.1password.com share URL), or a plain item title. Whatever it
    /// carried is applied to the fields FIRST and unconditionally: the follow-up
    /// field lookup can still fail (1Password locked, approval dismissed) and
    /// that must never throw away a drop that was itself perfectly good.
    private func applyDrops(_ drops: [OnePasswordDrop]) {
        guard let first = drops.first else { return }
        guard drops.count == 1 else {
            droppedChoices = drops
            showDropChooser = true
            return
        }
        apply(first)
    }

    private func apply(_ dropped: OnePasswordDrop) {
        sourceReference = dropped.reference
        // Never clear a typed value with an absent one — a field drag names no
        // account, and the account already there may be the right one.
        if !dropped.vault.isEmpty { sourceVault = dropped.vault }
        if !dropped.account.isEmpty {
            sourceAccount = dropped.account
            // A dragged item names the account it came from, and the SDK takes
            // that UUID as readily as the sidebar name — so one drag answers
            // "which account?" for every other VPN too.
            OnePasswordAccountMemory.seed(dropped.account)
        }
        opItemTitle = dropped.title.isEmpty ? dropped.reference : dropped.title
        droppedChoices = []
        // The listed items no longer describe this vault.
        opItems = []
        opItemsLoaded = false
        sourceTest = .idle
        Task { await loadOPFieldsAndShowSheet() }
    }

    /// Pure string parsing, no view state — `nonisolated` so the drop pipeline
    /// (which deliberately runs off the main actor) can call it directly.
    nonisolated static func parseOnePasswordDrop(_ raw: String)
        -> (reference: String, vault: String, account: String)? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.hasPrefix("op://") {
            // op://<vault>/<item>[/<section>/<field>] — keep vault + item. A
            // secret reference never names the account.
            let parts = s.dropFirst("op://".count).split(separator: "/").map(String.init)
            if parts.count >= 2 { return (parts[1], parts[0], "") }
            if parts.count == 1 { return (parts[0], "", "") }
            return nil
        }
        // Deep link and share link carry the same query: a=<account UUID>,
        // v=<vault UUID>, i=<item UUID>. The account UUID is as good as the
        // sidebar name to the SDK, and it's the one thing users can't guess.
        if s.hasPrefix("onepassword://")
            || (s.hasPrefix("https://") && s.contains("1password.com/open")),
           let comps = URLComponents(string: s) {
            let q = comps.queryItems ?? []
            func param(_ names: Set<String>) -> String {
                q.first { names.contains($0.name) }?.value ?? ""
            }
            let item = param(["i", "item"])
            guard !item.isEmpty else { return nil }
            return (item, param(["v", "vault"]), param(["a", "account"]))
        }
        // Plain text: the item's name or UUID. First line only.
        let firstLine = s.split(whereSeparator: \.isNewline).first.map(String.init) ?? s
        return (firstLine, "", "")
    }

    /// The auth roles this VPN uses — the sheet renders exactly these.
    private var applicableRoles: [CredentialRole] {
        CredentialRole.forOpenVPN(evaluation: evaluation, requiresOTP: otpRequired)
    }

    private func loadOPFieldsAndShowSheet() async {
        opFieldError = nil
        opBrowseError = nil
        loadingOPFields = true
        defer { loadingOPFields = false }
        do {
            let (title, vaultID, fields) = try await withAccountFallback { account in
                try await OnePasswordProvider.listFields(
                    itemReference: sourceReference, vault: sourceVault, account: account)
            }
            opItemTitle = title
            opFields = fields
            opNeedsAccount = false
            await backfillVault(from: vaultID)
            // Seed only the roles this VPN uses, from the item's field purposes/types.
            let roles = Set(applicableRoles)
            if roles.contains(.username), fieldMap["username"] == nil,
               let f = fields.first(where: { $0.purpose == "USERNAME" }) { fieldMap["username"] = f.id }
            if roles.contains(.password), fieldMap["password"] == nil,
               let f = fields.first(where: { $0.purpose == "PASSWORD" }) { fieldMap["password"] = f.id }
            if roles.contains(.otp), fieldMap["otp"] == nil,
               let f = fields.first(where: { $0.isOTP }) { fieldMap["otp"] = f.id }
            showFieldMap = true
        } catch let error as OnePasswordNativeError where isMissingAccount(error) {
            // The drop/pick was fine; only the account name is missing. Say so
            // gently at the Account field instead of reporting a failure the
            // user would go looking for in the wrong place.
            opNeedsAccount = true
        } catch {
            opFieldError = error.localizedDescription
        }
    }

    /// After a successful read the item's home vault is known truth, so an empty
    /// Vault field is filled in silently. Only the readable NAME is written: a
    /// UUID in a field labelled "Vault" tells the user nothing, and leaving it
    /// blank still works (the whole-item read searches every vault). Rides the
    /// authorization the successful read just used.
    private func backfillVault(from vaultID: String) async {
        let id = vaultID.trimmingCharacters(in: .whitespaces)
        let current = sourceVault.trimmingCharacters(in: .whitespaces)
        // Fill a blank — or swap the id a drag left behind for the name it turns
        // out to mean. Anything the user typed themselves is left alone.
        guard !id.isEmpty, current.isEmpty || current == id else { return }
        if opVaults.isEmpty {
            opVaults = (try? await OnePasswordNative.listVaults(
                account: OnePasswordAccountMemory.effectiveAccount(profile: sourceAccount))) ?? []
        }
        if let title = OnePasswordNative.vaultTitle(forID: vaultID, in: opVaults) {
            sourceVault = title
        }
    }

    private func isMissingAccount(_ error: OnePasswordNativeError) -> Bool {
        if case .accountNotFound = error { return true }
        return false
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
                .accessibilityLabel("Test the credential source")
                // The outcome is this button's answer — a focused Test button
                // reports its own result.
                .accessibilityValue(sourceTestAXValue)
            switch sourceTest {
            case .idle: EmptyView()
            case .testing:
                ProgressView().controlSize(.small)
                    .accessibilityLabel("Testing")
            case .ok(let who):
                Label(who, systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.callout)
            case .failed(let msg):
                Label(msg, systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.callout)
                    .lineLimit(3)
                    .accessibilityLabel("Error: \(msg)")
            }
            Spacer()
        }
    }

    private var sourceTestAXValue: String {
        switch sourceTest {
        case .idle: ""
        case .testing: "testing"
        case .ok(let who): who
        case .failed(let msg): "failed: \(msg)"
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
            let hasOTP = (raw.otp?.isEmpty == false) ? " · verification code available" : ""
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
        // Vault and field mapping only apply to 1Password; drop them otherwise.
        source.vault = credentialKind == .onePassword
            ? sourceVault.trimmingCharacters(in: .whitespaces) : ""
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
        .help(saveDisabledReason ?? saveWarning ?? (embedded ? "Save changes to this VPN" : "Save and close"))
        // The reason a dead Save is dead (or the saves-but-won't-connect
        // warning) must reach VoiceOver, not just the hover tooltip.
        .accessibilityValue(saveDisabledReason ?? saveWarning ?? "")
        .animation(.snappy(duration: 0.2), value: savedTick)
        // The embedded editor doesn't close on save; the tick is its only
        // confirmation — say it too.
        .onChange(of: savedTick) { _, ticked in
            if ticked { AccessibilityAnnouncer.sayNow("Saved") }
        }
    }

    /// Touch ID protection toggle. The migration sources the secret from the
    /// shared credential state, so what's typed in THIS form is pushed there
    /// first — otherwise a fresh entry wouldn't be seen.
    private var protectBinding: Binding<Bool> {
        Binding(get: { vpn.authConfig(for: profileID).protectWithBiometrics },
                set: { on in
                    var live = vpn.transientCredentials(for: profileID)
                    if !username.isEmpty { live.username = username }
                    if !password.isEmpty { live.password = password }
                    vpn.transientCreds[profileID] = live
                    let totp = totpSecretInput.isEmpty ? nil
                        : TOTPConfiguration.canonicalStorageString(from: totpSecretInput)
                    Task {
                        do { try await vpn.setBiometricProtection(on, for: profileID, totpSecret: totp) }
                        catch is CancellationError {}
                        catch { saveError = error.localizedDescription }
                    }
                })
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
        sourceVault = source.vault
        prefillRememberedAccount()
        fieldMap = source.fieldMap
        let prefs = vpn.uiPrefs(for: profileID)
        allowPause = prefs.allowPause
        showConnectionManager = prefs.showConnectionManager
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
    }

    private func save() async {
        saving = true; defer { saving = false }
        if !name.isEmpty { try? await vpn.rename(id: profileID, to: name) }

        // Configuration/overrides/auth are what MDM LockConfiguration governs — skip
        // them under the lock (rather than calling and swallowing the thrown error),
        // and surface any real failure instead of dismissing as if it saved.
        if !ManagedPolicy.lockConfiguration {
            let server = evaluation?.remoteHostOrNil ?? name
            // Start from the CURRENT auth config, not a fresh one — a fresh
            // VPNAuthConfig() silently wiped fields this form doesn't edit
            // (biometricProtection: saving the editor turned Touch ID off).
            var auth = vpn.authConfig(for: profileID)
            auth.requiresOTP = requiresOTP
            auth.passwordTemplate = passwordTemplate.trimmingCharacters(in: .whitespaces).isEmpty
                ? VPNAuthConfig.defaultTemplate : passwordTemplate
            auth.rememberCredentials = remember
            // The PROFILE has the last word on the auth shape: an autologin
            // profile stores no OTP requirement and no template (this form
            // replaces the whole credential UI for one, so the state written
            // above is whatever the profile used to need), and a declared static
            // challenge stores the requirement the server will impose anyway.
            auth = VPNAuthConfig.resolved(auth, autologin: isAutologin,
                                          staticChallenge: staticChallenge != nil)
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

        // A newly-entered authenticator secret goes into the Touch ID item
        // (one fingerprint prompt — changing what the fingerprint guards
        // should cost one). Empty input means "keep what's stored".
        if vpn.authConfig(for: profileID).protectWithBiometrics, !totpSecretInput.isEmpty,
           let canonical = TOTPConfiguration.canonicalStorageString(from: totpSecretInput) {
            do {
                try await vpn.updateProtectedTOTP(id: profileID, secret: canonical)
                totpSecretInput = ""
            } catch is CancellationError {
            } catch {
                saveError = error.localizedDescription
                return
            }
        }

        // Interface preferences aren't configuration — they persist even under
        // an MDM configuration lock (they only show/hide optional controls).
        var prefs = VPNUIPrefs()
        prefs.allowPause = allowPause
        prefs.showConnectionManager = showConnectionManager
        await vpn.setUIPrefs(prefs, for: profileID)

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
        customRouting = await commitCustomRouting(vpn, profileID: profileID, profile: customRouting,
                                                  proxyAuthUsername: crProxyAuthUsername,
                                                  proxyAuthPassword: crProxyAuthPassword)
        if embedded {
            savedTick = true
            // Long enough to SEE the tick, then done. dismiss() is a no-op in a
            // split-view detail, so ALSO tell the parent — it closes the window
            // when this is the only VPN.
            Task { try? await Task.sleep(for: .seconds(0.7)); dismiss(); onSaved?() }
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
            // Icon + sentence combine; the button must stay individually
            // activatable — a whole-row .combine swallowed it.
            HStack(spacing: 10) {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text("Settings changes take effect on reconnect.")
            }
            .accessibilityElement(children: .combine)
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
