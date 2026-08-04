// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNOptionsForm.swift
//  The per-VPN OpenVPN engine options form (the "Options" tab of the VPN editor).
//  Rows are driven by the descriptor registry (OpenVPNSettingDescriptors): names,
//  summaries, availability rules, manual anchors, and overridden-state all come
//  from there. Controls edit a draft OpenVPNOverrides; nil = engine default.
//
//  Conventions:
//   • Every value control rests at the engine default; setting it back to the
//     default stores nil (the round-trip contract).
//   • Overridden rows show a bold label and offer "Reset to Default" in the
//     context menu; section headers count their overrides.
//   • Rows the profile makes meaningless are hidden; rows another choice makes
//     unavailable are disabled with the reason shown.
//   • Groups follow the canonical taxonomy (AGENTS.md "Config surfaces"):
//     Connection → Sign-In → Traffic → Security → Advanced. Prominence follows
//     a survey of ~460 published real-world .ovpn files: protocol/port/server
//     are what users actually flip (every provider documents "switch to TCP
//     443 if blocked"), so Connection leads; Security and Advanced are
//     collapsed until they contain overrides, and the proxy fields (absent
//     from every surveyed file) hide behind their enabling toggle.
//

import SwiftUI

struct OpenVPNOptionsForm: View {
    @Binding var draft: OpenVPNOverrides
    /// Engine secrets live in the keychain, never in the overrides blob — the
    /// editor owns these strings and persists them on save.
    @Binding var proxyPassword: String
    @Binding var privateKeyPassword: String
    let evaluation: ProfileEvaluation?

    @Environment(PolicyStore.self) private var policyStore
    @State private var search = SettingsSearch()
    @State private var cipherStringsExpanded = false

    private var context: SettingsContext {
        SettingsContext(evaluation: evaluation, draft: draft, policy: policyStore.policy)
    }

    var body: some View {
        ScrollViewReader { proxy in
            Form {
                searchSection
                connectionSection
                signInSection
                trafficSection
                securitySection
                advancedSection
                resetSection
            }
            .formStyle(.grouped)
            .environment(search)
            .onAppear {
                proxyOn = draft.proxyHost != nil
                cipherStringsExpanded = draft.tlsCipherList != nil || draft.tlsCiphersuitesList != nil
            }
            .onChange(of: draft.proxyHost != nil) { _, hasHost in
                if hasHost { proxyOn = true }   // draft loaded/replaced externally
            }
            .onChange(of: search.revealGeneration) {
                guard let id = search.revealTargetID else { return }
                // Open any container hiding the target, let it expand, then scroll.
                if id.hasPrefix("openvpn.proxy-") { proxyOn = true }
                if id == "openvpn.tls-cipher-list" || id == "openvpn.tls-ciphersuites" {
                    cipherStringsExpanded = true
                }
                Task { @MainActor in
                    try? await Task.sleep(for: .milliseconds(80))
                    withAnimation { proxy.scrollTo(id, anchor: .center) }
                    // The reveal is a scroll + a colour wash — imperceptible to
                    // VoiceOver. Say where we landed.
                    if let d = OpenVPNSettings.byID[id] {
                        AccessibilityAnnouncer.sayNow("Showing \(d.name), in \(d.group.title)")
                    }
                }
            }
        }
    }

    // MARK: Search

    @ViewBuilder private var searchSection: some View {
        Section {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                TextField("Search settings", text: $search.query)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .onSubmit { if let first = search.matches.first { search.reveal(first) } }
                if !search.query.isEmpty {
                    Button { search.query = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Clear search")
                }
            }
            ForEach(search.matches) { d in
                Button { search.reveal(d) } label: {
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            Text(d.name)
                            Text("· \(d.group.title)").foregroundStyle(.secondary).font(.callout)
                        }
                        Text(d.summary).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityHint("Jump to this setting")
            }
            if !search.query.trimmingCharacters(in: .whitespaces).isEmpty,
               search.query.trimmingCharacters(in: .whitespaces).count >= 2,
               search.matches.isEmpty {
                Text("No settings match \u{201C}\(search.query)\u{201D}")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Connection

    @ViewBuilder private var connectionSection: some View {
        SettingsSection(group: .connection, draft: draft) {
            SettingRow(id: "openvpn.server", draft: $draft, context: context) {
                if let eval = evaluation, !eval.serverList.isEmpty {
                    Picker(selection: optionalString(\.server)) {
                        Text(defaultLabel(eval.remoteHostOrNil)).tag(String?.none)
                        ForEach(eval.serverList, id: \.server) { entry in
                            Text(entry.friendlyName.isEmpty ? entry.server : entry.friendlyName)
                                .tag(String?.some(entry.server))
                        }
                    } label: { SettingLabel(id: "openvpn.server", draft: draft) }
                } else {
                    LabeledContent {
                        TextField(evaluation?.remoteHostOrNil ?? "server address",
                                  text: emptyAsNil(\.server))
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                    } label: { SettingLabel(id: "openvpn.server", draft: draft) }
                }
            }

            SettingRow(id: "openvpn.port", draft: $draft, context: context) {
                ValidatedNumberField(
                    label: { SettingLabel(id: "openvpn.port", draft: draft) },
                    prompt: evaluation?.remotePortOrNil.map(String.init) ?? "port",
                    value: $draft.port,
                    range: OpenVPNOverrides.portRange,
                    invalidMessage: "Enter a port between 1 and 65535.")
            }

            SettingRow(id: "openvpn.protocol", draft: $draft, context: context) {
                protocolPicker
            } caveat: {
                if draft.proto == .udp && context.proxyConfigured {
                    SettingCaveat("Proxies only carry TCP. UDP won't work while a proxy is configured.")
                }
            }

            SettingRow(id: "openvpn.ip-version", draft: $draft, context: context) {
                Picker(selection: $draft.ipVersion) {
                    Text("Automatic").tag(OpenVPNOverrides.IPVersion?.none)
                    Text("IPv4 only").tag(OpenVPNOverrides.IPVersion?.some(.v4))
                    Text("IPv6 only").tag(OpenVPNOverrides.IPVersion?.some(.v6))
                } label: { SettingLabel(id: "openvpn.ip-version", draft: draft) }
            }

            SettingRow(id: "openvpn.connect-timeout", draft: $draft, context: context) {
                connTimeoutPicker
            }

            SettingRow(id: "openvpn.tun-persist", draft: $draft, context: context) {
                settingToggle("openvpn.tun-persist", \.tunPersist,
                              default: OpenVPNOverrides.EngineDefaults.tunPersist)
            }

            proxyRows
        }
    }

    private var protocolPicker: some View {
        // Never silently rewrite a stored choice: UDP stays listed while selected,
        // with the caveat above explaining why it won't be used.
        let udpUnavailable = context.proxyConfigured && draft.proto != .udp
        return Picker(selection: $draft.proto) {
            Text(defaultLabel(evaluation?.remoteProtoDisplay)).tag(OpenVPNOverrides.TransportProto?.none)
            Text("Adaptive").tag(OpenVPNOverrides.TransportProto?.some(.adaptive))
            if !udpUnavailable {
                Text("UDP").tag(OpenVPNOverrides.TransportProto?.some(.udp))
            }
            Text("TCP").tag(OpenVPNOverrides.TransportProto?.some(.tcp))
        } label: { SettingLabel(id: "openvpn.protocol", draft: draft) }
    }

    private var connTimeoutPicker: some View {
        let choices: [(Int?, String)] = [
            (nil, "Keep trying forever"),
            (15, "15 seconds"), (30, "30 seconds"),
            (60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"),
        ]
        let known = choices.compactMap(\.0)
        return Picker(selection: $draft.connTimeout) {
            ForEach(choices, id: \.0) { value, title in
                Text(value == nil ? "\(title) (default)" : title).tag(value)
            }
            if let current = draft.connTimeout, !known.contains(current) {
                Text("Custom (\(current) seconds)").tag(Int?.some(current))
            }
        } label: { SettingLabel(id: "openvpn.connect-timeout", draft: draft) }
    }

    // MARK: Sign-In

    @ViewBuilder private var signInSection: some View {
        SettingsSection(group: .signIn, draft: draft) {
            SettingRow(id: "openvpn.retry-on-auth-failed", draft: $draft, context: context) {
                settingToggle("openvpn.retry-on-auth-failed", \.retryOnAuthFailed,
                              default: OpenVPNOverrides.EngineDefaults.retryOnAuthFailed)
            }
            SettingRow(id: "openvpn.autologin-sessions", draft: $draft, context: context) {
                settingToggle("openvpn.autologin-sessions", \.autologinSessions,
                              default: OpenVPNOverrides.EngineDefaults.autologinSessions)
            }
            if evaluation?.privateKeyPasswordRequired == true {
                LabeledContent {
                    SecureField("required", text: $privateKeyPassword)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                } label: {
                    Text("Private Key Password")
                }
                Text("This configuration's private key is protected by a password. It is stored in your Keychain.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Traffic

    @ViewBuilder private var trafficSection: some View {
        SettingsSection(group: .traffic, draft: draft) {
            SettingRow(id: "openvpn.local-lan", draft: $draft, context: context) {
                settingToggle("openvpn.local-lan", \.allowLocalLanAccess,
                              default: OpenVPNOverrides.EngineDefaults.allowLocalLanAccess)
            }
            SettingRow(id: "openvpn.unused-families", draft: $draft, context: context) {
                Picker(selection: $draft.allowUnusedAddrFamilies) {
                    Text("Default — let the server decide").tag(OpenVPNOverrides.AddrFamilyPolicy?.none)
                    Text("Allowed outside the VPN").tag(OpenVPNOverrides.AddrFamilyPolicy?.some(.allow))
                    Text("Blocked").tag(OpenVPNOverrides.AddrFamilyPolicy?.some(.block))
                } label: { SettingLabel(id: "openvpn.unused-families", draft: draft) }
            }
            SettingRow(id: "openvpn.google-dns-fallback", draft: $draft, context: context) {
                settingToggle("openvpn.google-dns-fallback", \.googleDnsFallback,
                              default: OpenVPNOverrides.EngineDefaults.googleDnsFallback)
            }
        }
    }

    // MARK: Security (collapsed — rarely touched per the real-world survey)

    @ViewBuilder private var securitySection: some View {
        CollapsibleSettingsSection(group: .security, draft: draft) {
            SettingRow(id: "openvpn.tls-version-min", draft: $draft, context: context) {
                Picker(selection: $draft.tlsVersionMin) {
                    Text("Default").tag(OpenVPNOverrides.TLSVersionMin?.none)
                    Text("TLS 1.3").tag(OpenVPNOverrides.TLSVersionMin?.some(.tls1_3))
                    Text("TLS 1.2").tag(OpenVPNOverrides.TLSVersionMin?.some(.tls1_2))
                    Text("No minimum").tag(OpenVPNOverrides.TLSVersionMin?.some(.disabled))
                } label: { SettingLabel(id: "openvpn.tls-version-min", draft: draft) }
            } caveat: {
                if draft.tlsVersionMin == .disabled {
                    SettingCaveat("Weakens security — only for very old servers.")
                }
            }

            certProfileRow

            SettingRow(id: "openvpn.compression", draft: $draft, context: context) {
                Picker(selection: $draft.compression) {
                    Text("Off — recommended (default)").tag(OpenVPNOverrides.Compression?.none)
                    Text("Downloads only").tag(OpenVPNOverrides.Compression?.some(.asym))
                    Text("Full").tag(OpenVPNOverrides.Compression?.some(.yes))
                } label: { SettingLabel(id: "openvpn.compression", draft: draft) }
            } caveat: {
                if draft.compression == .yes {
                    SettingCaveat("Compression can let attackers steal secrets sent through the VPN (VORACLE attack).")
                }
                if evaluation?.requestsCompression == true {
                    Text("This VPN's configuration file asks for compression itself.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            SettingRow(id: "openvpn.legacy-algorithms", draft: $draft, context: context) {
                settingToggle("openvpn.legacy-algorithms", \.enableLegacyAlgorithms,
                              default: OpenVPNOverrides.EngineDefaults.enableLegacyAlgorithms)
            } caveat: {
                if draft.enableLegacyAlgorithms == true {
                    SettingCaveat("Outdated ciphers weaken this VPN's security.")
                }
            }

            SettingRow(id: "openvpn.non-preferred-ciphers", draft: $draft, context: context) {
                settingToggle("openvpn.non-preferred-ciphers", \.enableNonPreferredDCAlgorithms,
                              default: OpenVPNOverrides.EngineDefaults.enableNonPreferredDCAlgorithms)
            }

            DisclosureGroup(isExpanded: $cipherStringsExpanded) {
                SettingRow(id: "openvpn.tls-cipher-list", draft: $draft, context: context) {
                    cipherField("openvpn.tls-cipher-list", \.tlsCipherList)
                }
                SettingRow(id: "openvpn.tls-ciphersuites", draft: $draft, context: context) {
                    cipherField("openvpn.tls-ciphersuites", \.tlsCiphersuitesList)
                }
                Text("Leave empty unless a server administrator gave you an exact string to paste.")
                    .font(.callout).foregroundStyle(.secondary)
            } label: {
                Text("Custom TLS Cipher Strings")
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                    .onTapGesture { withAnimation(.snappy) { cipherStringsExpanded.toggle() } }
            }
        }
    }

    /// tlsCertProfile decomposes into a base choice plus "only as a default"
    /// (legacy-default / preferred-default; Suite B has no default form).
    @ViewBuilder private var certProfileRow: some View {
        SettingRow(id: "openvpn.tls-cert-profile", draft: $draft, context: context) {
            Picker(selection: certProfileBase) {
                Text("Default").tag(CertBase?.none)
                Text("Modern — 2048-bit RSA, SHA-256 or better").tag(CertBase?.some(.preferred))
                Text("Legacy — allows weak certificates").tag(CertBase?.some(.legacy))
                Text("Suite B").tag(CertBase?.some(.suiteb))
            } label: { SettingLabel(id: "openvpn.tls-cert-profile", draft: draft) }
        } caveat: {
            if certProfileBase.wrappedValue == .legacy {
                SettingCaveat("Weak certificates (1024-bit RSA, SHA-1) are accepted.")
            }
        }
        if let base = certProfileBase.wrappedValue, base != .suiteb {
            Toggle("Only if the configuration file doesn't specify", isOn: certProfileOnlyDefault)
                .padding(.leading, 16)
                // The indentation ties this to Certificate Strictness for the
                // eye; VoiceOver needs the subject in words.
                .accessibilityLabel("Apply the certificate strictness only if the configuration file doesn't specify one")
        }
    }

    private enum CertBase { case legacy, preferred, suiteb }

    private var certProfileBase: Binding<CertBase?> {
        Binding(
            get: {
                switch draft.tlsCertProfile {
                case .legacy, .legacyDefault: .legacy
                case .preferred, .preferredDefault: .preferred
                case .suiteb: .suiteb
                case nil: nil
                }
            },
            set: { base in
                let onlyDefault = certProfileOnlyDefault.wrappedValue
                switch base {
                case nil: draft.tlsCertProfile = nil
                case .legacy: draft.tlsCertProfile = onlyDefault ? .legacyDefault : .legacy
                case .preferred: draft.tlsCertProfile = onlyDefault ? .preferredDefault : .preferred
                case .suiteb: draft.tlsCertProfile = .suiteb
                }
            })
    }

    private var certProfileOnlyDefault: Binding<Bool> {
        Binding(
            get: { draft.tlsCertProfile == .legacyDefault || draft.tlsCertProfile == .preferredDefault },
            set: { only in
                switch draft.tlsCertProfile {
                case .legacy, .legacyDefault: draft.tlsCertProfile = only ? .legacyDefault : .legacy
                case .preferred, .preferredDefault: draft.tlsCertProfile = only ? .preferredDefault : .preferred
                default: break
                }
            })
    }

    // MARK: Connection — proxy rows (no surveyed real-world profile shipped a
    // proxy, but corporate egress networks are exactly where a Mac user gets
    // stuck, so the fields live one toggle away inside Connection)

    @ViewBuilder private var proxyRows: some View {
        if ManagedPolicy.lockProxySettings {
            SettingCaveat("Proxy settings are managed by your organization and can't be changed.")
        }
        Group {
            Toggle("Connect through an HTTP proxy", isOn: proxyEnabled)

            if proxyOn {
                SettingRow(id: "openvpn.proxy-host", draft: $draft, context: context) {
                    LabeledContent {
                        TextField("proxy.example.com", text: emptyAsNil(\.proxyHost))
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                    } label: { SettingLabel(id: "openvpn.proxy-host", draft: draft) }
                }
                SettingRow(id: "openvpn.proxy-port", draft: $draft, context: context) {
                    ValidatedNumberField(
                        label: { SettingLabel(id: "openvpn.proxy-port", draft: draft) },
                        prompt: "8080",
                        value: $draft.proxyPort,
                        range: OpenVPNOverrides.portRange,
                        invalidMessage: "Enter a port between 1 and 65535.")
                }
                SettingRow(id: "openvpn.proxy-username", draft: $draft, context: context) {
                    LabeledContent {
                        TextField("optional", text: emptyAsNil(\.proxyUsername))
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                    } label: { SettingLabel(id: "openvpn.proxy-username", draft: draft) }
                }
                LabeledContent {
                    SecureField("optional", text: $proxyPassword)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                        .disabled(!context.proxyHasUsername)
                        // A dead field must say why.
                        .help(context.proxyHasUsername ? "" : "Enter a proxy username first")
                        .accessibilityValue(context.proxyHasUsername ? "" : "unavailable — enter a proxy username first")
                } label: {
                    Text("Proxy Password")
                }
                SettingRow(id: "openvpn.proxy-cleartext-auth", draft: $draft, context: context) {
                    settingToggle("openvpn.proxy-cleartext-auth", \.proxyAllowCleartextAuth,
                                  default: OpenVPNOverrides.EngineDefaults.proxyAllowCleartextAuth)
                }
                Text("Proxies carry TCP only. While a proxy is configured, UDP can't be used.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .disabled(ManagedPolicy.lockProxySettings)
    }

    /// Sub-form visibility is deliberately NOT derived from the host value:
    /// clearing the host field mid-edit must not collapse the fields under the
    /// user's cursor. Local state opens it; turning it off clears everything.
    @State private var proxyOn = false

    private var proxyEnabled: Binding<Bool> {
        Binding(
            get: { proxyOn },
            set: { on in
                proxyOn = on
                if !on {
                    draft.proxyHost = nil
                    draft.proxyPort = nil
                    draft.proxyUsername = nil
                    draft.proxyAllowCleartextAuth = nil
                    proxyPassword = ""
                }
            })
    }

    // MARK: Advanced

    @ViewBuilder private var advancedSection: some View {
        CollapsibleSettingsSection(group: .advanced, draft: draft) {
                SettingRow(id: "openvpn.ssl-debug", draft: $draft, context: context) {
                    Picker(selection: $draft.sslDebugLevel) {
                        Text("Off (default)").tag(Int?.none)
                        Text("Basic").tag(Int?.some(1))
                        Text("Detailed").tag(Int?.some(3))
                        Text("Everything").tag(Int?.some(9))
                        if let v = draft.sslDebugLevel, ![1, 3, 9].contains(v) {
                            Text("Custom (\(v))").tag(Int?.some(v))
                        }
                    } label: { SettingLabel(id: "openvpn.ssl-debug", draft: draft) }
                }
                SettingRow(id: "openvpn.synchronous-dns", draft: $draft, context: context) {
                    settingToggle("openvpn.synchronous-dns", \.synchronousDnsLookup,
                                  default: OpenVPNOverrides.EngineDefaults.synchronousDnsLookup)
                }
                SettingRow(id: "openvpn.no-client-cert", draft: $draft, context: context) {
                    settingToggle("openvpn.no-client-cert", \.disableClientCert,
                                  default: OpenVPNOverrides.EngineDefaults.disableClientCert)
                }
                SettingRow(id: "openvpn.key-direction", draft: $draft, context: context) {
                    Picker(selection: $draft.defaultKeyDirection) {
                        Text("Bidirectional (default)").tag(Int?.none)
                        Text("0").tag(Int?.some(0))
                        Text("1").tag(Int?.some(1))
                    } label: { SettingLabel(id: "openvpn.key-direction", draft: draft) }
                }
        } footer: {
            Text("Only change these if support asks you to.")
        }
    }

    // MARK: Reset

    @State private var confirmingReset = false

    @ViewBuilder private var resetSection: some View {
        Section {
            Button("Reset All to Defaults", role: .destructive) { confirmingReset = true }
                .disabled(draft.isEmpty && proxyPassword.isEmpty && privateKeyPassword.isEmpty)
                .confirmationDialog("Reset all OpenVPN options to their defaults?",
                                    isPresented: $confirmingReset, titleVisibility: .visible) {
                    Button("Reset All", role: .destructive) {
                        draft = OpenVPNOverrides()
                        proxyPassword = ""
                        privateKeyPassword = ""
                    }
                } message: {
                    Text("Every option returns to the engine's default. The configuration file itself is not changed.")
                }
        }
    }

    // MARK: Binding helpers

    /// Toggle over an optional Bool: rests at the engine default; choosing the
    /// default stores nil immediately, so the bold "overridden" state and the
    /// stored blob always agree.
    private func settingToggle(_ id: String,
                               _ keyPath: WritableKeyPath<OpenVPNOverrides, Bool?>,
                               default engineDefault: Bool) -> some View {
        Toggle(isOn: Binding(
            get: { draft[keyPath: keyPath] ?? engineDefault },
            set: { draft[keyPath: keyPath] = ($0 == engineDefault) ? nil : $0 }
        )) {
            SettingLabel(id: id, draft: draft)
        }
    }

    /// String field binding where an empty (or whitespace) string means nil.
    private func emptyAsNil(_ keyPath: WritableKeyPath<OpenVPNOverrides, String?>) -> Binding<String> {
        Binding(
            get: { draft[keyPath: keyPath] ?? "" },
            set: {
                let t = $0.trimmingCharacters(in: .whitespacesAndNewlines)
                draft[keyPath: keyPath] = t.isEmpty ? nil : $0
            })
    }

    private func optionalString(_ keyPath: WritableKeyPath<OpenVPNOverrides, String?>) -> Binding<String?> {
        Binding(get: { draft[keyPath: keyPath] }, set: { draft[keyPath: keyPath] = $0 })
    }

    private func cipherField(_ id: String,
                             _ keyPath: WritableKeyPath<OpenVPNOverrides, String?>) -> some View {
        LabeledContent {
            TextField("", text: emptyAsNil(keyPath))
                .font(.callout.monospaced())
                .autocorrectionDisabled()
                .multilineTextAlignment(.trailing)
        } label: { SettingLabel(id: id, draft: draft) }
    }

    private func defaultLabel(_ resolved: String?) -> String {
        resolved.map { "Default (\($0))" } ?? "Default"
    }
}

// MARK: - Row & section building blocks

/// A section for one setting group: header shows the title and a change count.
private struct SettingsSection<Content: View, Footer: View>: View {
    let group: SettingGroup
    let draft: OpenVPNOverrides
    @ViewBuilder let content: Content
    @ViewBuilder let footer: Footer

    init(group: SettingGroup, draft: OpenVPNOverrides,
         @ViewBuilder content: () -> Content,
         @ViewBuilder footer: () -> Footer) {
        self.group = group
        self.draft = draft
        self.content = content()
        self.footer = footer()
    }

    var body: some View {
        Section {
            content
        } header: {
            HStack {
                Text(group.title)
                ChangeCountBadge(count: OpenVPNSettings.overriddenCount(in: group, for: draft))
            }
        } footer: {
            footer.font(.callout).foregroundStyle(.secondary)
        }
    }
}

extension SettingsSection where Footer == EmptyView {
    init(group: SettingGroup, draft: OpenVPNOverrides, @ViewBuilder content: () -> Content) {
        self.init(group: group, draft: draft, content: content, footer: { EmptyView() })
    }
}

/// A collapsed-by-default group (Security, Advanced — the areas the real-world
/// survey shows are rarely touched). Opens automatically when it already
/// contains overrides, so nothing the user changed is ever hidden.
private struct CollapsibleSettingsSection<Content: View, Footer: View>: View {
    let group: SettingGroup
    let draft: OpenVPNOverrides
    @ViewBuilder let content: Content
    @ViewBuilder let footer: Footer
    @State private var expanded: Bool
    @Environment(SettingsSearch.self) private var search: SettingsSearch?

    init(group: SettingGroup, draft: OpenVPNOverrides,
         @ViewBuilder content: () -> Content,
         @ViewBuilder footer: () -> Footer) {
        self.group = group
        self.draft = draft
        self.content = content()
        self.footer = footer()
        _expanded = State(initialValue: OpenVPNSettings.overriddenCount(in: group, for: draft) > 0)
    }

    var body: some View {
        Section {
            DisclosureGroup(isExpanded: $expanded) {
                content
                    .padding(.top, 4)
            } label: {
                HStack {
                    Text(group.title)
                    ChangeCountBadge(count: OpenVPNSettings.overriddenCount(in: group, for: draft))
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 4)
                .contentShape(Rectangle())
                .onTapGesture { withAnimation(.snappy) { expanded.toggle() } }
            }
        } footer: {
            footer.font(.callout).foregroundStyle(.secondary)
        }
        .onChange(of: search?.revealGeneration ?? 0) {
            // A search hit inside this group must never land on a closed disclosure.
            if search?.revealGroup == group { expanded = true }
        }
    }
}

extension CollapsibleSettingsSection where Footer == EmptyView {
    init(group: SettingGroup, draft: OpenVPNOverrides, @ViewBuilder content: () -> Content) {
        self.init(group: group, draft: draft, content: content, footer: { EmptyView() })
    }
}

/// One setting row: applies availability (hidden/disabled + reason), renders the
/// control, the plain-English summary with a manual deep link, any caveats, and
/// a "Reset to Default" context menu when overridden.
extension SettingRow where Caveat == EmptyView {
    init(id: String, draft: Binding<OpenVPNOverrides>, context: SettingsContext,
         @ViewBuilder control: () -> Control) {
        self.init(id: id, draft: draft, context: context, control: control, caveat: { EmptyView() })
    }
}

private struct SettingRow<Control: View, Caveat: View>: View {
    let id: String
    @Binding var draft: OpenVPNOverrides
    let context: SettingsContext
    @ViewBuilder let control: Control
    @ViewBuilder let caveat: Caveat
    @Environment(SettingsSearch.self) private var search: SettingsSearch?

    init(id: String, draft: Binding<OpenVPNOverrides>, context: SettingsContext,
         @ViewBuilder control: () -> Control,
         @ViewBuilder caveat: () -> Caveat) {
        self.id = id
        self._draft = draft
        self.context = context
        self.control = control()
        self.caveat = caveat()
    }

    private var descriptor: SettingDescriptor { OpenVPNSettings.byID[id]! }
    private var highlighted: Bool { search?.highlightedID == id }

    var body: some View {
        switch descriptor.availability(in: context) {
        case .hidden:
            EmptyView()
        case .disabled(let reason):
            rowBody(disabledReason: reason)
        case .available:
            rowBody(disabledReason: nil)
        }
    }

    @ViewBuilder private func rowBody(disabledReason: String?) -> some View {
        VStack(alignment: .leading, spacing: 6) {   // match EngineSettingRow
            // Control and the help button share the top line, so every "?" lines up
            // in one column with each row's value/control.
            HStack(alignment: .center, spacing: 8) {
                control
                    .disabled(disabledReason != nil)
                    .frame(maxWidth: .infinity, alignment: .leading)
                ManualLink(anchor: descriptor.manualAnchor, settingName: descriptor.name)
            }
            Text(disabledReason ?? descriptor.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            caveat
        }
        .padding(.vertical, 6)   // grouped-form rows with stacked summary need extra air
        .help(descriptor.summary)
        .id(id)
        .listRowBackground(highlighted ? Color.accentColor.opacity(0.16) : nil)
        .contextMenu {
            Button("Reset to Default") { descriptor.reset(&draft) }
                .disabled(!descriptor.isSet(draft))
        }
        .accessibilityElement(children: .contain)
    }
}

/// A setting's label, bold while overridden (the Xcode build-settings idiom).
struct SettingLabel: View {
    let id: String
    let draft: OpenVPNOverrides

    var body: some View {
        let d = OpenVPNSettings.byID[id]!
        Text(d.name).bold(d.isSet(draft))
            // Bold weight is invisible to VoiceOver — say the state too.
            .accessibilityLabel(d.isSet(draft) ? "\(d.name), changed from default" : d.name)
    }
}

/// Amber warning caption for risky choices — a value the user should see, not decoration.
struct SettingCaveat: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(.orange)
            .accessibilityLabel("Warning: \(text)")
    }
}

/// Small "n changed" badge for section headers; hidden at zero.
struct ChangeCountBadge: View {
    let count: Int
    var body: some View {
        if count > 0 {
            Text("\(count) changed")
                .font(.footnote.weight(.medium))
                .padding(.horizontal, 7).padding(.vertical, 1)
                .background(.tint.opacity(0.15), in: Capsule())
                .foregroundStyle(.tint)
                .accessibilityLabel("\(count) settings changed in this group")
        }
    }
}

/// "Learn more" deep link into the bundled manual.
struct ManualLink: View {
    let anchor: String
    let settingName: String
    @Environment(ManualRouter.self) private var router: ManualRouter?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            router?.navigate(to: anchor)
            openWindow(id: "manual")
        } label: {
            Image(systemName: "questionmark.circle")
        }
        .buttonStyle(.borderless)
        .help("Learn more about \u{201C}\(settingName)\u{201D} in the manual")
        .accessibilityLabel("Learn more about \(settingName)")
    }
}

/// Numeric text field over an optional Int with range validation: empty = default
/// (nil), out-of-range shows an inline error and stores nothing.
private struct ValidatedNumberField<Label: View>: View {
    @ViewBuilder let label: Label
    let prompt: String
    @Binding var value: Int?
    let range: ClosedRange<Int>
    let invalidMessage: String

    @State private var text = ""
    @State private var invalid = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent {
                TextField(prompt, text: $text)
                    .multilineTextAlignment(.trailing)
                    .frame(maxWidth: 120).frame(maxWidth: .infinity, alignment: .trailing)
                    .onChange(of: text) { _, newValue in commit(newValue) }
                    .onChange(of: value) { _, newValue in
                        // External change (Reset to Default / Reset All): resync.
                        let shown = Int(text.trimmingCharacters(in: .whitespaces))
                        if newValue != shown { text = newValue.map(String.init) ?? ""; invalid = false }
                    }
                    .onAppear { text = value.map(String.init) ?? "" }
            } label: { label }
            if invalid {
                Text(invalidMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityLabel("Error: \(invalidMessage)")
            }
        }
    }

    private func commit(_ newValue: String) {
        let trimmed = newValue.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            value = nil; invalid = false
        } else if let n = Int(trimmed), range.contains(n) {
            value = n; invalid = false
        } else {
            invalid = true   // keep the last good stored value
        }
    }
}
