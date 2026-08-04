// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNView.swift
//  Editor + control for the OS-native personal VPN kinds (IKEv2, IPsec). macOS
//  runs these itself via NEVPNManager — one at a time (singleton). L2TP has no
//  programmatic API, so it's offered as a downloadable configuration profile.
//

import SwiftUI
import NetworkExtension

struct NativeVPNView: View {
    let vpn: VPNController
    @Bindable var manager: NativeVPNManager
    @State var draft: NativeVPNConfig
    /// IKEv2: the password or PSK, whichever mode is active. IPsec: the XAuth
    /// password (optional — the group secret alone is sometimes enough).
    @State private var secret = ""
    /// IPsec only: the group shared secret (PSK). Kept separate from `secret`
    /// because IPsec, unlike IKEv2, can need both at once.
    @State private var sharedSecret = ""
    /// L2TP only: the PPP (user) password. A third slot for the same reason —
    /// L2TP needs the IPSec shared secret AND a user password at once, and the
    /// exported .mobileconfig carries them in different payload dictionaries.
    @State private var pppPassword = ""
    @State private var loaded = false
    /// The saved-confirmation affordance every editor's primary action now has —
    /// three of six used to save with no visible acknowledgement at all.
    @State private var savedTick = false
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    /// Which tab is showing. A binding, so a related-settings link or a search
    /// hit on the other tab can select it — no TabView in the app could be
    /// selected in code before this.
    @State private var tab: SettingsTab = .settings
    /// This editor's search catalog: its own surface plus Custom Routing, which
    /// is its second tab — one field finds everything this editor shows.
    /// `kind` starts at IKEv2 and follows the Protocol picker; all three native
    /// kinds share the one surface, so this only affects which of them a related
    /// link is offered for.
    @State private var search = SettingsSearch(surfaces: [.native, .customRouting],
                                               kind: .ikev2)

    private var isActive: Bool {
        manager.activeConfigID == draft.id &&
        (manager.status == .connected || manager.status == .connecting || manager.status == .reasserting)
    }

    /// nil once every field the active auth mode needs is filled in;
    /// otherwise a short caption naming what's missing, for both the Connect
    /// button's disabled state and a visible reason (never just a dead button).
    private var missingFieldCaption: String? {
        // Was `.isEmpty` only: a typo'd server reached NEVPNManager and came
        // back as an opaque IKE timeout.
        if let p = draft.serverProblem { return p }
        switch draft.kind {
        case .ipsec:
            if sharedSecret.isEmpty { return "Enter the shared secret (PSK) to connect." }
        case .ikev2:
            if draft.usesSharedSecret {
                if secret.isEmpty { return "Enter the shared secret (PSK) to connect." }
            } else {
                if draft.username.isEmpty { return "Enter a username to connect." }
                if secret.isEmpty { return "Enter a password to connect." }
            }
        default: break
        }
        return nil
    }

    /// The OTHER native config currently occupying macOS's single personal-VPN
    /// slot, if any — connecting this one replaces it, so Connect names it.
    private var activeOtherNativeName: String? {
        guard let activeID = manager.activeConfigID, activeID != draft.id,
              manager.status == .connected || manager.status == .connecting
                || manager.status == .reasserting
        else { return nil }
        let name = manager.configs.first { $0.id == activeID }?.name
            .trimmingCharacters(in: .whitespaces) ?? ""
        return name.isEmpty ? "the other native VPN" : name
    }

    private var replacesActiveVPNCaption: String? {
        activeOtherNativeName.map { "Will disconnect \($0) first." }
    }

    private var connectHelp: String {
        [replacesActiveVPNCaption, missingFieldCaption ?? "Push this configuration into macOS and connect."]
            .compactMap { $0 }.joined(separator: " ")
    }

    /// Why this server address won't work, or nil. Shown inline AND used by both
    /// gates — a bad address used to surface only as an opaque IKE timeout.
    private var serverProblem: String? {
        draft.server.isEmpty ? nil : draft.serverProblem
    }

    /// Why Save is unavailable, in the user's language, or nil.
    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = draft.serverProblem { return p }
        return nil
    }

    /// The config surface: the canonical five groups, in order (AGENTS.md
    /// "Config surfaces") — Connection → Sign-In → Traffic → Security → Advanced.
    private var configForm: some View {
        Form {
            SettingsSearchSection(search: search)
            Section("Connection") {
                TextField("Name", text: $draft.name)
                EngineSettingRow(spec: Self.specs["native.protocol"], value: draft.kind) {
                    Picker(selection: $draft.kind) {
                        Text("IKEv2").tag(VPNKind.ikev2)
                        Text("IPsec (IKEv1)").tag(VPNKind.ipsec)
                        Text("L2TP / IPsec").tag(VPNKind.l2tp)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.protocol"], value: draft.kind)
                    }
                    .onChange(of: draft.kind) {
                        // IPsec has no certificate path (no identity picker/import
                        // exists), so it's always the shared-secret mode — keep
                        // the model honest even though connect() no longer trusts
                        // this flag for IPsec either.
                        if draft.kind == .ipsec { draft.usesSharedSecret = true }
                    }
                }
                EngineSettingRow(spec: Self.specs["native.server"], value: draft.server) {
                    LabeledContent {
                        TextField("vpn.example.com", text: $draft.server)
                            .multilineTextAlignment(.trailing)
                            .autocorrectionDisabled()
                            // The title is an EXAMPLE — the spec name is the name.
                            .accessibilityLabel(Self.specs["native.server"].name)
                            // Validation rides the field's value (Docs/Accessibility.md).
                            .accessibilityValue(serverProblem.map { "\(draft.server). Problem: \($0)" } ?? draft.server)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.server"], value: draft.server)
                    }
                }
                if let p = serverProblem {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(p)")
                }
                if draft.kind == .ipsec {
                    EngineSettingRow(spec: Self.specs["native.group"], value: draft.groupOrRealm) {
                        LabeledContent {
                            TextField("optional", text: $draft.groupOrRealm)
                                .multilineTextAlignment(.trailing)
                                .autocorrectionDisabled()
                                .accessibilityLabel(Self.specs["native.group"].name)
                        } label: {
                            EngineSettingLabel(spec: Self.specs["native.group"], value: draft.groupOrRealm)
                        }
                    }
                }
                if draft.kind != .l2tp {
                    // The rule installed is a bare NEOnDemandRuleConnect() — no
                    // SSID, domain or interface conditions exist anywhere in this
                    // app, so say what it really does rather than let "on demand"
                    // imply a condition list the user could have set.
                    EngineSettingRow(spec: Self.specs["native.on-demand"], value: draft.onDemand) {
                        Toggle(isOn: $draft.onDemand) {
                            EngineSettingLabel(spec: Self.specs["native.on-demand"], value: draft.onDemand)
                        }
                        .accessibilityValue(draft.onDemand
                            ? "on — reconnects whenever any app opens a network connection, on every network"
                            : "off")
                    }
                    // Lifecycle sibling of Connect on Demand — both answer "when
                    // is this VPN up", so they live together (it was in Advanced).
                    EngineSettingRow(spec: Self.specs["native.disconnect-sleep"],
                                     value: draft.disconnectOnSleep) {
                        Toggle(isOn: $draft.disconnectOnSleep) {
                            EngineSettingLabel(spec: Self.specs["native.disconnect-sleep"],
                                               value: draft.disconnectOnSleep)
                        }
                    }
                }
            }

            if draft.kind == .l2tp {
                l2tpSection
            } else {
                authSection
                trafficSection
                securitySection
                advancedSection
                controlSection
            }
        }
        .formStyle(.grouped)
        .revealsSettings()
        .disabled(ManagedPolicy.lockConfiguration)
    }

    var body: some View {
        // Custom Routing is its own TAB in every editor (AGENTS.md "Config
        // surfaces") — appending it as sections put a second, differently-shaped
        // config surface inside the run of canonical groups.
        TabView(selection: $tab) {
            configForm
                .tag(SettingsTab.settings)
                .tabItem { Label("Settings", systemImage: "slider.horizontal.3") }
            Form {
                CustomRoutingTabView(vpn: vpn, profileID: draft.id, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword,
                                    kind: draft.kind)
            }
            .formStyle(.grouped)
            .revealsSettings()
            .disabled(ManagedPolicy.lockConfiguration)
            .tag(SettingsTab.customRouting)
            .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
        }
        // Which rows this draft gates OUT (most of the surface swaps on the
        // Protocol picker), so a search hit or a related link naming one says so
        // instead of jumping nowhere (SettingVisibility). Inner, so the shell's
        // route consumption can't read a stale table.
        .onAppear { search.visibility = SettingVisibility.native(draft) }
        .onChange(of: SettingVisibility.native(draft)) { _, new in search.visibility = new }
        .settingsEditor(search: search, tab: $tab,
                        surfaces: [.native, .customRouting], profileID: draft.id)
        .onChange(of: draft.kind) { search.kind = draft.kind }
        .padding(.top, 10)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button { save() } label: {
                    savedTick ? Label("Saved", systemImage: "checkmark")
                              : Label("Save", systemImage: "checkmark")
                }
                    .buttonStyle(.glassProminent)   // primary action — one idiom in every editor
                    .disabled(saveDisabledReason != nil)
                    // A dead Save must say why — hover AND VoiceOver.
                    .help(saveDisabledReason ?? "Save changes to this VPN")
                    .accessibilityValue(saveDisabledReason.map { "unavailable — \($0)" } ?? "")
            }
        }
    }

    @ViewBuilder private var authSection: some View {
        Section {
            if draft.kind == .ipsec {
                // No certificate/identity path exists (no picker, no import),
                // so IPsec always authenticates with a shared secret — the
                // Cisco-style group PSK, optionally paired with an XAuth
                // username/password (exactly what a .pcf import produces).
                EngineSettingRow(spec: Self.specs["native.shared-secret"], value: sharedSecret) {
                    LabeledContent {
                        SecureField("group PSK", text: $sharedSecret)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel(Self.specs["native.shared-secret"].name)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.shared-secret"], value: sharedSecret)
                    }
                }
                // There was no way to say "no XAuth": a username left behind by
                // an import kept extended authentication on with nothing to send.
                EngineSettingRow(spec: Self.specs["native.xauth"], value: draft.usesXAuth) {
                    Toggle(isOn: xauthBinding) {
                        EngineSettingLabel(spec: Self.specs["native.xauth"], value: draft.usesXAuth)
                    }
                }
                let xauthOff: String? = draft.usesXAuth ? nil
                    : "Turn on \u{201C}Also sign in with a username and password (XAuth)\u{201D} to use these."
                EngineSettingRow(spec: Self.specs["native.username"], value: draft.username,
                                 disabledReason: xauthOff) {
                    LabeledContent {
                        TextField("username", text: $draft.username).textContentType(.username)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel("XAuth username")
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.username"], value: draft.username)
                    }
                }
                EngineSettingRow(spec: Self.specs["native.xauth-password"], value: secret,
                                 disabledReason: xauthOff) {
                    LabeledContent {
                        SecureField("password", text: $secret)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel("XAuth password")
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.xauth-password"], value: secret)
                    }
                }
            } else {
                EngineSettingRow(spec: Self.specs["native.auth-method"], value: draft.usesSharedSecret) {
                    Toggle(isOn: $draft.usesSharedSecret) {
                        EngineSettingLabel(spec: Self.specs["native.auth-method"],
                                           value: draft.usesSharedSecret)
                    }
                }
                if !draft.usesSharedSecret {
                    EngineSettingRow(spec: Self.specs["native.username"], value: draft.username) {
                        LabeledContent {
                            TextField("username", text: $draft.username).textContentType(.username)
                                .multilineTextAlignment(.trailing)
                                .accessibilityLabel(Self.specs["native.username"].name)
                        } label: {
                            EngineSettingLabel(spec: Self.specs["native.username"], value: draft.username)
                        }
                    }
                }
                // One control, two subjects: `secret` carries the PSK or the
                // password depending on the toggle above, and they are mutually
                // exclusive — so it renders under whichever spec applies.
                let secretSpec = Self.specs[draft.usesSharedSecret ? "native.shared-secret" : "native.password"]
                EngineSettingRow(spec: secretSpec, value: secret) {
                    LabeledContent {
                        SecureField(draft.usesSharedSecret ? "shared secret" : "password", text: $secret)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel(secretSpec.name)
                    } label: {
                        EngineSettingLabel(spec: secretSpec, value: secret)
                    }
                }
            }
        } header: {
            Text("Sign-In")
        } footer: {
            if draft.kind == .ipsec {
                Text("Certificate authentication isn't supported in this build — IPsec always uses a shared secret.")
            }
        }
    }

    /// The XAuth answer. `nil` in the model means "never asked", which reads as
    /// the old behaviour (on when a username exists) — writing through it records
    /// the explicit choice, so the answer stops depending on a leftover username.
    private var xauthBinding: Binding<Bool> {
        Binding(get: { draft.usesXAuth }, set: { draft.xauth = $0 })
    }

    @ViewBuilder private var trafficSection: some View {
        Section("Traffic") {
            // "Changed" is the SPEC's business now — this row's twin below used to
            // hand-write an inverted predicate, and two rows disagreeing about
            // which way "changed" runs is exactly what that produces.
            EngineSettingRow(spec: Self.specs["native.include-all"], value: draft.includeAllNetworks) {
                Toggle(isOn: $draft.includeAllNetworks) {
                    EngineSettingLabel(spec: Self.specs["native.include-all"], value: draft.includeAllNetworks)
                }
            }
            if draft.includeAllNetworks {
                EngineSettingRow(spec: Self.specs["native.exclude-local"], value: draft.excludeLocalNetworks) {
                    Toggle(isOn: $draft.excludeLocalNetworks) {
                        EngineSettingLabel(spec: Self.specs["native.exclude-local"], value: draft.excludeLocalNetworks)
                    }
                }
            }
            // macOS runs these itself, so what finally got installed is visible
            // only in the routing table — which is exactly what Routes shows.
            TrafficCrossLinks()
        }
    }

    /// Verifying the SERVER and the channel. Everything macOS exposes here is
    /// IKEv2-only, so for IPsec the whole group is OMITTED rather than shown empty
    /// (the canonical-taxonomy rule).
    @ViewBuilder private var securitySection: some View {
        if draft.kind == .ikev2 {
            Section("Security") {
                // The remote identifier is the identity macOS demands the server's
                // certificate present — a check on the SERVER, which is why it is
                // here and not beside the address it verifies.
                EngineSettingRow(spec: Self.specs["native.remote-id"], value: draft.remoteID) {
                    LabeledContent {
                        TextField("defaults to the server address", text: $draft.remoteID)
                            .multilineTextAlignment(.trailing)
                            .autocorrectionDisabled()
                            .accessibilityLabel(Self.specs["native.remote-id"].name)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["native.remote-id"], value: draft.remoteID)
                    }
                }
                ikev2CryptoRows
            }
        }
    }

    @ViewBuilder private var ikev2CryptoRows: some View {
        Group {
            enumRow("native.encryption", $draft.ikeEncryption, [
                ("", "Automatic"), ("aes256gcm", "AES-256-GCM"), ("aes128gcm", "AES-128-GCM"),
                ("aes256", "AES-256-CBC"), ("aes128", "AES-128-CBC"), ("chacha20poly1305", "ChaCha20-Poly1305")])
            enumRow("native.integrity", $draft.ikeIntegrity, [
                ("", "Automatic"), ("sha256", "SHA2-256"), ("sha384", "SHA2-384"), ("sha512", "SHA2-512")])
            enumRow("native.dh-group", $draft.ikeDHGroup, [
                ("", "Automatic"), ("14", "Group 14 (2048-bit)"), ("15", "Group 15 (3072-bit)"),
                ("16", "Group 16 (4096-bit)"), ("19", "Group 19 (P-256)"), ("20", "Group 20 (P-384)"),
                ("21", "Group 21 (P-521)"), ("31", "Group 31 (Curve25519)")])
            EngineSettingRow(spec: Self.specs["native.pfs"], value: draft.enablePFS) {
                Toggle(isOn: $draft.enablePFS) {
                    EngineSettingLabel(spec: Self.specs["native.pfs"], value: draft.enablePFS)
                }
            }
            // Apple's API has no "enable PFS" bit: PFS is whether the data channel
            // gets its OWN Diffie-Hellman group, and it borrows the picker's. On
            // Automatic there is nothing to borrow, so the code picks Group 14 —
            // a real choice the picker doesn't show, hence a caveat.
            if draft.enablePFS && draft.ikeDHGroup.isEmpty {
                SettingCaveat("With the Diffie-Hellman Group above on Automatic, the data channel rekeys with Group 14 (2048-bit) — Automatic can't be honoured for it. Choose a group above to use that one instead.")
            }
            // The model has always applied this to BOTH security associations —
            // there was simply no control for it anywhere, so an imported value
            // (or one set by a future MDM key) could not be seen or changed.
            EngineSettingRow(spec: Self.specs["native.ike-lifetime"], value: draft.ikeLifetimeMinutes) {
                ValidatedNumberField(
                    label: { EngineSettingLabel(spec: Self.specs["native.ike-lifetime"],
                                                value: draft.ikeLifetimeMinutes) },
                    prompt: "60",
                    value: $draft.ikeLifetimeMinutes,
                    range: NativeVPNConfig.ikeLifetimeRange,
                    invalidMessage: "Enter a lifetime between 10 and 1440 minutes. Leave empty to keep macOS's own (60 minutes, or 30 for the data channel).")
            }
        }
    }

    /// Advanced is IKEv2-only content, so it is OMITTED for IPsec rather than
    /// shown empty (the canonical-taxonomy rule). Collapsed by default, through
    /// the shared component every editor now uses.
    @ViewBuilder private var advancedSection: some View {
        if draft.kind == .ikev2 {
            CollapsibleSettingsSection(group: .advanced, changedCount: advancedChangedCount) {
                // "Automatic", not "Default": "" now genuinely leaves the OS
                // value untouched (it used to be applied as .medium, so the
                // picker's first option named a state it didn't produce).
                enumRow("native.dpd", $draft.deadPeerDetection, [
                    ("", "Automatic"), ("none", "Off"), ("low", "Low"), ("medium", "Medium"), ("high", "High")])
                EngineSettingRow(spec: Self.specs["native.mobike"], value: draft.disableMOBIKE) {
                    Toggle(isOn: $draft.disableMOBIKE) {
                        EngineSettingLabel(spec: Self.specs["native.mobike"], value: draft.disableMOBIKE)
                    }
                }
            }
        }
    }

    /// The badge count for Advanced — computed from the specs' own declared
    /// defaults, so it can never disagree with the rows' bold labels.
    private var advancedChangedCount: Int {
        [Self.specs["native.dpd"].isChanged(draft.deadPeerDetection),
         Self.specs["native.mobike"].isChanged(draft.disableMOBIKE)].count { $0 }
    }

    /// The catalog now lives in `ControlPlane/NativeVPNSettingDescriptors.swift`
    /// so app-wide search can reach it (a catalog private to a View can only be
    /// searched by that View). This alias keeps the form's ~40 call sites reading
    /// `Self.specs["native.…"]`.
    static var specs: EngineSettingCatalog { NativeVPNSettings.catalog }

    private func enumRow(_ id: String, _ binding: Binding<String>, _ options: [(String, String)]) -> some View {
        EngineSettingRow(spec: Self.specs[id], value: binding.wrappedValue) {
            Picker(selection: binding) {
                ForEach(options, id: \.0) { Text($0.1).tag($0.0) }
            } label: { EngineSettingLabel(spec: Self.specs[id], value: binding.wrappedValue) }
        }
    }

    @ViewBuilder private var controlSection: some View {
        Section {
            if manager.needsEntitlement {
                Label("Native VPN needs the Personal VPN capability on this build's signing profile. Everything else works; ask to have it provisioned.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
                // Not a substitute for the capability — but the pane where an
                // already-installed native VPN can be seen and connected by hand
                // is where someone hitting this needs to go, and it was unnamed.
                SystemSettingsLink(title: "Open Network \u{25B8} VPN to see and connect native VPNs on this Mac",
                                   pane: .networkVPN, systemImage: "network",
                                   accessibilityLabel: "Open Network, VPN, to see and connect native VPNs on this Mac")
            }
            HStack {
                nativeStatus
                Spacer()
                if isActive {
                    Button("Disconnect") { manager.disconnect() }.buttonStyle(.bordered).tint(.red)
                } else {
                    Button("Connect") {
                        save()
                        let proxy = nativeProxySettings()
                        Task { await manager.connect(draft, secret: secret, sharedSecret: sharedSecret, proxy: proxy) }
                    }
                        .buttonStyle(.glassProminent)   // primary "go" — consistent with OpenVPN Connect
                        .disabled(missingFieldCaption != nil)
                        // macOS keeps ONE app-managed personal VPN, so connecting
                        // here tears down whichever native VPN is up. The footer
                        // said so generically; the button names the casualty.
                        .help(connectHelp)
                        .accessibilityValue([replacesActiveVPNCaption, missingFieldCaption]
                                                .compactMap { $0 }.joined(separator: " "))
                }
            }
            if !isActive, let caption = missingFieldCaption {
                Text(caption).font(.caption).foregroundStyle(.secondary)
            }
            if !isActive, let caption = replacesActiveVPNCaption {
                Text(caption).font(.caption).foregroundStyle(.secondary)
            }
            if let err = manager.lastError {
                Label(err, systemImage: "xmark.circle.fill")
                    .font(.callout).foregroundStyle(.red)
                    .accessibilityLabel("Error: \(err)")
            }
            Text("macOS runs one app-managed personal VPN at a time — connecting this one replaces any other native VPN this app started.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var nativeStatus: some View {
        switch manager.status {
        case .connected where isActive: Label("Connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .connecting where isActive:
            HStack(spacing: 6) { ProgressView().controlSize(.small).accessibilityHidden(true); Text("Connecting…") }
                .accessibilityElement(children: .combine)
        default: Label("Disconnected", systemImage: "circle").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var l2tpSection: some View {
        Section("Sign-In") {
            // The same three concepts as the other kinds, so the same three specs
            // — one name per concept, one manual anchor, one search hit.
            EngineSettingRow(spec: Self.specs["native.username"], value: draft.username) {
                LabeledContent {
                    TextField("username", text: $draft.username).textContentType(.username)
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel(Self.specs["native.username"].name)
                } label: {
                    EngineSettingLabel(spec: Self.specs["native.username"], value: draft.username)
                }
            }
            // L2TP needs BOTH: a user password for PPP and the IPSec shared
            // secret. There was no password field at all, so every exported
            // profile wrote AuthName with no AuthPassword and prompted at connect.
            EngineSettingRow(spec: Self.specs["native.password"], value: pppPassword) {
                LabeledContent {
                    SecureField("password", text: $pppPassword)
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel("L2TP password")
                } label: {
                    EngineSettingLabel(spec: Self.specs["native.password"], value: pppPassword)
                }
            }
            Text("Written into the exported profile as well, so connecting doesn't ask again. Clear it to remove both.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            EngineSettingRow(spec: Self.specs["native.shared-secret"], value: secret) {
                LabeledContent {
                    SecureField("shared secret", text: $secret)
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel("L2TP shared secret")
                } label: {
                    EngineSettingLabel(spec: Self.specs["native.shared-secret"], value: secret)
                }
            }
        }
        Section {
            Button("Export Configuration Profile…") { exportMobileconfig() }
                .disabled(l2tpExportDisabledReason != nil)
                // A dead export must say why on the control, not only in the footer.
                .help(l2tpExportDisabledReason
                      ?? "Write a .mobileconfig you double-click to install this VPN in System Settings.")
                .accessibilityValue(l2tpExportDisabledReason.map { "unavailable — \($0)" } ?? "")
        } header: {
            Text("Configuration Profile")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("macOS has no programmatic L2TP API for apps. SimpleVPN writes a standard .mobileconfig you double-click to install; it then appears in System Settings ▸ VPN.")
                // Both destinations named in this footer are one click away, and
                // were prose: the pane where a just-installed profile is approved,
                // and the pane where the options an L2TP profile CAN'T carry have
                // to be set by hand.
                SystemSettingsLink(title: "Open Privacy & Security \u{25B8} Profiles to approve an installed profile",
                                   pane: .profiles,
                                   accessibilityLabel: "Open Privacy and Security, Profiles, to approve an installed profile")
                SystemSettingsLink(title: "Open Network \u{25B8} VPN to set the options a profile can\u{2019}t carry",
                                   pane: .networkVPN, systemImage: "network",
                                   accessibilityLabel: "Open Network, VPN, to set the options a profile cannot carry")
                // Switching to L2TP doesn't just hide the crypto/DPD/MOBIKE/PFS,
                // traffic and on-demand rows — the exported profile carries none
                // of them either, so anything configured under IKEv2/IPsec is
                // silently dropped. That has to be stated where it happens.
                Label("Only the fields above are exported. Encryption, integrity, Diffie-Hellman group, key lifetime, dead peer detection, MOBIKE, Perfect Forward Secrecy, Send All Traffic, local network access, disconnect on sleep, Connect on demand and Custom Routing are NOT part of an L2TP configuration profile — anything you set for IKEv2 or IPsec is kept, but not used here. Configure those in System Settings after installing, if the profile needs them.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                if let reason = l2tpExportDisabledReason {
                    Text(reason)
                }
            }
        }
    }

    /// Why the L2TP export is unavailable, in the user's language, or nil.
    private var l2tpExportDisabledReason: String? {
        if let p = draft.serverProblem { return p }
        if secret.isEmpty { return "Enter the shared secret before exporting — the profile needs it to configure IPSec." }
        return nil
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        search.kind = draft.kind
        if draft.kind == .ipsec { draft.usesSharedSecret = true }   // no cert path — always PSK
        // ALL THREE ROWS, whatever the kind. The Protocol picker changes which
        // fields are on screen but not which secrets this profile owns, and
        // `save()` writes what these variables hold — so loading only the current
        // kind's secret meant switching Protocol and saving wrote an empty value
        // over the other kind's. (`NativeVPNSecrets.plan` no longer deletes a row
        // the saved kind doesn't own either; both halves of that bug are fixed.)
        let base = KeychainCredentialStore.loadCredentials(profile: NativeVPNSecrets.baseProfile(draft.id))
        secret = base?.password ?? ""
        pppPassword = KeychainCredentialStore.loadCredentials(
            profile: NativeVPNSecrets.pppPasswordProfile(draft.id))?.password ?? ""
        customRouting = vpn.customRouting(for: draft.id)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: draft.id)
        if let group = KeychainCredentialStore.loadCredentials(profile: NativeVPNSecrets.groupPSKProfile(draft.id)) {
            sharedSecret = group.password
        } else if draft.kind == .ipsec, !secret.isEmpty {
            // Backward compat: earlier builds (and the Cisco .pcf importer,
            // ManageVPNsView.importCiscoText) stored the IPsec group PSK in
            // this same base slot, with no separate XAuth password field to
            // conflict with. Migrate it into the new shared-secret field so
            // existing saved configs keep working without re-entry.
            sharedSecret = secret
            secret = ""
        }
    }

    /// The user's Custom Routing proxy as the native VPN's `NEProxySettings` — for these
    /// kinds the app is the applier, at connect (NEVPNManager carries the proxy in the
    /// VPN configuration; the OS applies it while the tunnel is up). The sign-in comes
    /// from the keychain-backed fields (the CURRENT draft, not a possibly-racing
    /// keychain read — Connect calls save() the same instant); the stored config only
    /// ever carries the ref.
    private func nativeProxySettings() -> NEProxySettings? {
        customRouting.proxy.nativeApplyRequest(
            username: crProxyAuthUsername.isEmpty ? nil : crProxyAuthUsername,
            password: crProxyAuthPassword.isEmpty ? nil : crProxyAuthPassword)?
            .makeNEProxySettings()
    }

    private func save() {
        if draft.kind == .ipsec { draft.usesSharedSecret = true }
        manager.save(draft)
        // Emptying a secret field REMOVES the stored secret (SubprocessTunnelView's
        // rule for every one of its secrets): writing only when non-empty left the
        // previous password in the keychain, so the next Connect still signed in
        // with a password the user believed they had deleted.
        NativeVPNSecrets.apply(
            NativeVPNSecrets.plan(kind: draft.kind, secret: secret, sharedSecret: sharedSecret,
                                  pppPassword: pppPassword, xauth: draft.usesXAuth),
            id: draft.id, username: draft.username)
        // save() is synchronous (called inline from several button actions, incl.
        // Export), so the commit runs in the background — harmless since it's
        // idempotent and CustomRoutingTabView's own onDisappear covers "left before
        // this finished" too.
        let id = draft.id
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            customRouting = await commitCustomRouting(vpn, profileID: id, profile: toCommit,
                                                      proxyAuthUsername: user, proxyAuthPassword: pass)
        }
        // Acknowledge the save on the button, the way Tailscale/Proxy Tunnel and
        // the OpenVPN editor do — a Save that changes nothing on screen reads as
        // a Save that didn't happen.
        savedTick = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            savedTick = false
        }
    }

    private func exportMobileconfig() {
        save()
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(draft.name).mobileconfig"
        panel.allowedContentTypes = [.init(filenameExtension: "mobileconfig") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? NativeVPNProfile.l2tpMobileconfig(draft, secret: secret, pppPassword: pppPassword)
            .write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Minimal, valid L2TP-over-IPsec .mobileconfig generator (PPP + IPSec payload).
enum NativeVPNProfile {
    /// Escapes the five XML-significant characters. Every interpolated string
    /// below is attacker/user-controlled (profile name, username, server) —
    /// unescaped, a name like `Foo</string><key>Bad`  would break out of its
    /// element and corrupt (or inject into) the generated plist. The base64
    /// secret needs no escaping (its alphabet is `[A-Za-z0-9+/=]`).
    private static func xmlEscaped(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
         .replacingOccurrences(of: "'", with: "&apos;")
    }

    /// `pppPassword` is the L2TP user (PPP) password. It rides `PPP.AuthPassword`
    /// — the generator wrote `AuthName` with no password at all, so EVERY
    /// exported profile prompted at connect, which reads as a broken export.
    /// Emitted ONLY when set: an empty `AuthPassword` is an empty-password
    /// attempt, not "ask me".
    static func l2tpMobileconfig(_ c: NativeVPNConfig, secret: String,
                                 pppPassword: String = "") -> String {
        let uuid = UUID().uuidString
        let payloadUUID = UUID().uuidString
        let name = xmlEscaped(c.name)
        let username = xmlEscaped(c.username)
        let server = xmlEscaped(c.server)
        // User-controlled text (unlike the base64 shared secret), so it goes
        // through the same escaping as every other interpolation here.
        let authPassword = pppPassword.isEmpty ? ""
            : "\n      <key>AuthPassword</key><string>\(xmlEscaped(pppPassword))</string>"
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>PayloadDisplayName</key><string>\(name)</string>
          <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.\(uuid)</string>
          <key>PayloadType</key><string>Configuration</string>
          <key>PayloadUUID</key><string>\(uuid)</string>
          <key>PayloadVersion</key><integer>1</integer>
          <key>PayloadContent</key><array><dict>
            <key>PayloadType</key><string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.vpn.\(payloadUUID)</string>
            <key>PayloadUUID</key><string>\(payloadUUID)</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>UserDefinedName</key><string>\(name)</string>
            <key>VPNType</key><string>L2TP</string>
            <key>PPP</key><dict>
              <key>AuthName</key><string>\(username)</string>\(authPassword)
              <key>CommRemoteAddress</key><string>\(server)</string>
            </dict>
            <key>IPSec</key><dict>
              <key>AuthenticationMethod</key><string>SharedSecret</string>
              <key>SharedSecret</key><data>\(Data(secret.utf8).base64EncodedString())</data>
            </dict>
          </dict></array>
        </dict></plist>
        """
    }
}
