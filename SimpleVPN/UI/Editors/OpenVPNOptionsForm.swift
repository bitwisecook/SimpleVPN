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
    /// The search model is the HOST's (EditVPNView), not this form's: its catalog
    /// spans the Options tab AND the Custom Routing tab, so one field finds both
    /// and the host switches tabs for a hit on the other one. Owning it here is
    /// what confined search to this single form in the first place.
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @State private var cipherStringsExpanded = false

    private var context: SettingsContext {
        SettingsContext(evaluation: evaluation, draft: draft, policy: policyStore.policy)
    }

    var body: some View {
        Form {
            if let search { SettingsSearchSection(search: search) }
            connectionSection
            signInSection
            trafficSection
            securitySection
            advancedSection
            resetSection
        }
        .formStyle(.grouped)
        // The ScrollViewReader + scroll + announcement are one shared modifier
        // now (UI/Components/SettingReveal.swift), so every editor gets them.
        .revealsSettings()
        .onAppear {
            proxyOn = draft.proxyHost != nil
            cipherStringsExpanded = draft.tlsCipherList != nil || draft.tlsCiphersuitesList != nil
        }
        .onChange(of: draft.proxyHost != nil) { _, hasHost in
            if hasHost { proxyOn = true }   // draft loaded/replaced externally
        }
        // UNHIDE the target before the shared scroll runs: a row behind a toggle
        // or a disclosure isn't in the hierarchy for scrollTo to find. Both of
        // these are pure VIEW state (the proxy sub-form's master toggle mirrors
        // `draft.proxyHost != nil`; the cipher disclosure holds nothing), which is
        // the only kind of gate a reveal may flip — see `SettingRevealUnhide`.
        // Shared modifier now, so it also fires for a CROSS-TAB reveal, where this
        // form is created after the generation changed.
        .unhidesRevealTarget { id in
            if id.hasPrefix("openvpn.proxy-") { proxyOn = true }
            if id == "openvpn.tls-cipher-list" || id == "openvpn.tls-ciphersuites" {
                cipherStringsExpanded = true
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
                // `usesUDP`, not `draft.proto == .udp`: "Default (UDP)" is the
                // commonest way to be on UDP and a proxy can't carry that either.
                if context.usesUDP && context.proxyConfigured {
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

    /// The fixed choices, plus a real "Custom…" case. A read-only
    /// "Custom (n seconds)" row could DISPLAY an in-range value that arrived from
    /// MDM, the CLI or an older blob but gave no way to edit it — the picker was a
    /// dead end for every value it didn't list.
    private static let connTimeoutChoices: [(Int?, String)] = [
        (nil, "Keep trying forever"),
        (15, "15 seconds"), (30, "30 seconds"),
        (60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"),
    ]

    @ViewBuilder private var connTimeoutPicker: some View {
        let known = Self.connTimeoutChoices.compactMap(\.0)
        let isCustom = connTimeoutCustom || draft.connTimeout.map { !known.contains($0) } ?? false
        VStack(alignment: .leading, spacing: 6) {
            Picker(selection: connTimeoutSelection(known: known)) {
                ForEach(Self.connTimeoutChoices, id: \.0) { value, title in
                    Text(value == nil ? "\(title) (default)" : title).tag(CustomChoice.preset(value))
                }
                Text("Custom…").tag(CustomChoice.custom)
            } label: { SettingLabel(id: "openvpn.connect-timeout", draft: draft) }
            if isCustom {
                ValidatedNumberField(
                    label: { Text("Seconds").foregroundStyle(.secondary) },
                    prompt: "seconds",
                    value: $draft.connTimeout,
                    range: OpenVPNOverrides.connTimeoutRange,
                    invalidMessage: "Enter a number of seconds between 0 and 86400 — 0 keeps trying forever.")
                    .padding(.leading, 16)
            }
        }
    }

    /// A picker selection that can say "one of the listed values" or "let me type
    /// one" without either state being able to erase the other's value.
    private enum CustomChoice: Hashable {
        case preset(Int?)
        case custom
    }

    @State private var connTimeoutCustom = false
    @State private var sslDebugCustom = false

    private func connTimeoutSelection(known: [Int]) -> Binding<CustomChoice> {
        Binding(
            get: {
                if connTimeoutCustom { return .custom }
                if let v = draft.connTimeout, !known.contains(v) { return .custom }
                return .preset(draft.connTimeout)
            },
            set: { choice in
                switch choice {
                case .custom:
                    connTimeoutCustom = true
                case .preset(let value):
                    connTimeoutCustom = false
                    draft.connTimeout = value
                }
            })
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
            SettingRow(id: "openvpn.private-key-password", draft: $draft, context: context) {
                LabeledContent {
                    SecureField("required", text: $privateKeyPassword)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                } label: {
                    SettingLabel(id: "openvpn.private-key-password", draft: draft)
                }
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
            } caveat: {
                // It reaches the engine, but the engine only reads it under two
                // conditions at once — so on its own, on a split tunnel or with a
                // server that pushes DNS, turning it on does nothing at all.
                if draft.googleDnsFallback == true {
                    SettingCaveat("Only used when BOTH are true: this VPN carries all your traffic, and the server sends no DNS servers of its own. Otherwise this does nothing.")
                }
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
                    // The engine's own "no" is the SAME state as leaving this
                    // unset (ovpncli.cpp only calls parse_compression_mode for a
                    // non-empty mode, and ProtoContextCompressionOptions starts at
                    // COMPRESS_NO), so it isn't offered as a second way to say
                    // "off". It stays LISTED while stored, though — a value that
                    // arrived from MDM, the CLI or an older blob must never leave
                    // the picker blank (the Protocol row's rule).
                    if draft.compression == .no {
                        Text("Off — never compress").tag(OpenVPNOverrides.Compression?.some(.no))
                    }
                    Text("Downloads only").tag(OpenVPNOverrides.Compression?.some(.asym))
                    Text("Full").tag(OpenVPNOverrides.Compression?.some(.yes))
                } label: { SettingLabel(id: "openvpn.compression", draft: draft) }
            } caveat: {
                if draft.compression == .yes {
                    SettingCaveat("Compression can let attackers steal secrets sent through the VPN (VORACLE attack).")
                }
                // "…asks for compression itself" used to stop there, which read as
                // a warning the user had to act on. The engine refuses to compress
                // unless this row says otherwise, so say what actually happens.
                if evaluation?.requestsCompression == true {
                    Text(draft.compression == nil || draft.compression == .no
                         ? "This VPN's configuration file asks for compression itself. It is still not used: the engine only accepts the framing, and compresses nothing, unless you choose otherwise here."
                         : "This VPN's configuration file asks for compression itself, and your choice above is what the engine uses.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
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
                // The two strings govern DIFFERENT halves of TLS and neither can
                // do the other's job: OpenSSL takes this one through
                // SSL_CTX_set_cipher_list, which only names TLS 1.2-and-below
                // suites, so with a 1.3 minimum it is applied and then never
                // matters. It still reaches the engine, so this is a caveat, not
                // a dead control — drop the minimum back to TLS 1.2 and it bites.
                SettingRow(id: "openvpn.tls-cipher-list", draft: $draft, context: context) {
                    cipherField("openvpn.tls-cipher-list", \.tlsCipherList)
                } caveat: {
                    if draft.tlsVersionMin == .tls1_3, (draft.tlsCipherList ?? "").isEmpty == false {
                        SettingCaveat("This list only names TLS 1.2-and-below ciphers, and Minimum TLS Version is TLS 1.3 — so nothing here can be chosen. Use \u{201C}TLS 1.3 ciphersuites\u{201D} below instead.")
                    }
                }
                SettingRow(id: "openvpn.tls-ciphersuites", draft: $draft, context: context) {
                    cipherField("openvpn.tls-ciphersuites", \.tlsCiphersuitesList)
                } caveat: {
                    if (draft.tlsCiphersuitesList ?? "").isEmpty == false {
                        Text("Applies to TLS 1.3 only — TLS 1.2 and below take their suites from the list above.")
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
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
            SettingRow(id: "openvpn.proxy-enabled", draft: $draft, context: context) {
                Toggle(isOn: proxyEnabled) {
                    SettingLabel(id: "openvpn.proxy-enabled", draft: draft)
                }
            }

            if proxyOn {
                SettingRow(id: "openvpn.proxy-host", draft: $draft, context: context) {
                    LabeledContent {
                        TextField("proxy.example.com", text: emptyAsNil(\.proxyHost))
                            .autocorrectionDisabled()
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                    } label: { SettingLabel(id: "openvpn.proxy-host", draft: draft) }
                } caveat: {
                    // The other half of the Protocol row's caveat: a proxy is set
                    // AND the connection is on UDP, so the proxy will never be
                    // used. Said on both rows, because either one is where the
                    // user is looking when they make the pair impossible.
                    if context.usesUDP {
                        SettingCaveat("This VPN connects over UDP, which a proxy can't carry — set Protocol above to TCP (or Adaptive) or the proxy is never used.")
                    }
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
                // The descriptor carries the "enter a username first" rule now, so
                // the dead-field reason comes from the same place as every other
                // row's (SettingRow applies it to all three channels).
                SettingRow(id: "openvpn.proxy-password", draft: $draft, context: context) {
                    LabeledContent {
                        SecureField("optional", text: $proxyPassword)
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: 260).frame(maxWidth: .infinity, alignment: .trailing)
                    } label: {
                        SettingLabel(id: "openvpn.proxy-password", draft: draft)
                    }
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
                    sslDebugPicker
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

    /// Same shape as the connection timeout: named levels plus a typed value, so
    /// any level in the engine's 0–9 range can be both shown AND set.
    @ViewBuilder private var sslDebugPicker: some View {
        let known = [1, 3, 9]
        let isCustom = sslDebugCustom || draft.sslDebugLevel.map { !known.contains($0) } ?? false
        VStack(alignment: .leading, spacing: 6) {
            Picker(selection: Binding<CustomChoice>(
                get: {
                    if sslDebugCustom { return .custom }
                    if let v = draft.sslDebugLevel, !known.contains(v) { return .custom }
                    return .preset(draft.sslDebugLevel)
                },
                set: { choice in
                    switch choice {
                    case .custom: sslDebugCustom = true
                    case .preset(let value): sslDebugCustom = false; draft.sslDebugLevel = value
                    }
                })) {
                Text("Off (default)").tag(CustomChoice.preset(Int?.none))
                Text("Basic").tag(CustomChoice.preset(Int?.some(1)))
                Text("Detailed").tag(CustomChoice.preset(Int?.some(3)))
                Text("Everything").tag(CustomChoice.preset(Int?.some(9)))
                Text("Custom…").tag(CustomChoice.custom)
            } label: { SettingLabel(id: "openvpn.ssl-debug", draft: draft) }
            if isCustom {
                ValidatedNumberField(
                    label: { Text("Level").foregroundStyle(.secondary) },
                    prompt: "0–9",
                    value: $draft.sslDebugLevel,
                    range: OpenVPNOverrides.sslDebugLevelRange,
                    invalidMessage: "Enter a level between 0 and 9 — 0 is off, 9 is everything.")
                    .padding(.leading, 16)
            }
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

// CollapsibleSettingsSection — the collapsed-by-default group with the whole-row
// hit target, the "n changed" badge and the search-reveal hook — grew up here and
// now lives in UI/Components/CollapsibleSettingsSection.swift so every editor
// uses the same one. This overlay keeps the OpenVPN form's call sites reading in
// terms of its draft rather than a hand-computed count.
extension CollapsibleSettingsSection where Footer == EmptyView {
    init(group: SettingGroup, draft: OpenVPNOverrides, @ViewBuilder content: () -> Content) {
        self.init(group: group,
                  changedCount: OpenVPNSettings.overriddenCount(in: group, for: draft),
                  content: content)
    }
}

extension CollapsibleSettingsSection {
    init(group: SettingGroup, draft: OpenVPNOverrides,
         @ViewBuilder content: () -> Content,
         @ViewBuilder footer: () -> Footer) {
        self.init(group: group,
                  changedCount: OpenVPNSettings.overriddenCount(in: group, for: draft),
                  content: content, footer: footer)
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
    /// Keyboard focus for a search/related-link reveal — same contract as
    /// EngineSettingRow's (UI/Components/SettingReveal.swift).
    @FocusState private var controlFocused: Bool

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
                // A dead control says why in all three channels, exactly like
                // EngineSettingRow: the visible summary, the tooltip, and the
                // control's own accessibilityValue.
                if let reason = disabledReason {
                    control
                        .disabled(true)
                        .accessibilityValue("unavailable — \(reason)")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .settingRevealFocus(id, focused: $controlFocused)
                } else {
                    control
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .settingRevealFocus(id, focused: $controlFocused)
                }
                ManualLink(setting: descriptor)
            }
            Text(disabledReason ?? descriptor.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            caveat
        }
        .padding(.vertical, 6)   // grouped-form rows with stacked summary need extra air
        .help(disabledReason ?? descriptor.summary)
        // The `.id` + highlight pair used to be written out here, which is why
        // only this form could be searched. It is one shared modifier now — and
        // the highlight is an animated PULSE plus keyboard/VoiceOver focus
        // (UI/Components/SettingReveal.swift), not a static colour wash.
        .settingReveal(id)
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

// ManualLink — the "?" beside every row — is now a POPOVER (name, summary,
// related-settings links, "Open the manual") and lives in
// UI/Components/ManualLink.swift, shared by all six editors.

// ValidatedNumberField — the shared range-validating numeric control — now lives
// in UI/Components/ValidatedNumberField.swift so every editor uses the same one.
