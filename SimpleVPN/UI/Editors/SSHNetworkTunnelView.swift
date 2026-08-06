// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetworkTunnelView.swift
//  Create / edit an SSH Network Tunnel: a utun with routes, every connection
//  carried over one SSH session. Not the SSH editor (that one is a local SOCKS
//  port or named forwards) and not the Proxy Tunnel editor (no sign-in, no host
//  key) — the same five canonical groups, its own catalog.
//
//  Copy rule for this form: plain words. "netstack", "direct-tcpip",
//  "socketpair" and "5-tuple" do not appear; they become "the tunnel", "a
//  connection". The unavoidable jargon is what the user was given by whoever runs
//  the server — a fingerprint, a KexAlgorithms list — and that is exactly the
//  text they will paste.
//
//  TWO THINGS THIS FORM MUST SAY OUT LOUD, because neither is discoverable:
//    • only TCP crosses (SSH has no datagram channel), so QUIC is refused;
//    • SSH agent and Kerberos sign-in cannot work from a system service, so they
//      are shown as unavailable WITH THE REASON rather than quietly omitted.
//

import SwiftUI

struct SSHNetworkTunnelView: View {
    let vpn: VPNController
    let profileID: String

    @State private var draft = SSHNetworkTunnelConfig()
    @State private var name = ""
    @State private var password = ""
    @State private var privateKeyPEM = ""
    @State private var certificatePEM = ""
    @State private var portText = ""
    @State private var includedText = ""
    @State private var excludedText = ""
    @State private var dnsText = ""
    @State private var searchDomainsText = ""
    @State private var loaded = false
    @State private var saving = false
    @State private var checkingHostKey = false
    @State private var hostKeyReport: VPNController.SSHNetHostKeyReport?
    @State private var status: SSHNetworkTunnelStatus?
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    @State private var tab: SettingsTab = .settings
    @State private var search = SettingsSearch(surfaces: [.sshNetworkTunnel, .customRouting],
                                               kind: .sshNetworkTunnel)

    /// The config surface: the canonical groups, in order (AGENTS.md "Config
    /// surfaces"). This engine has content for all five.
    private var configForm: some View {
        Form {
            SettingsSearchSection(search: search)

            Section("Connection") {
                TextField("Name", text: $name)
                EngineSettingRow(spec: Self.specs["sshnet.server"], value: draft.server) {
                    labeledField(Self.specs["sshnet.server"], $draft.server,
                                 prompt: "gateway.example.com", problem: serverProblem)
                }
                if let problem = serverProblem {
                    fieldProblem(problem)
                }
                EngineSettingRow(spec: Self.specs["sshnet.port"], value: draft.port) {
                    labeledField(Self.specs["sshnet.port"], $portText,
                                 prompt: "22", problem: portProblem)
                }
                if let problem = portProblem { fieldProblem(problem) }
            }

            Section("Sign-In") {
                EngineSettingRow(spec: Self.specs["sshnet.username"], value: draft.username) {
                    labeledField(Self.specs["sshnet.username"], $draft.username,
                                 prompt: NSUserName(), accessibilityLabel: "SSH username")
                }
                EngineSettingRow(spec: Self.specs["sshnet.auth-method"], value: draft.authMethod) {
                    SettingPicker(selection: $draft.authMethod) {
                        ForEach(SSHNetworkTunnelConfig.AuthMethod.allCases, id: \.self) {
                            Text($0.displayName).tag($0)
                        }
                    } label: {
                        EngineSettingLabel(spec: Self.specs["sshnet.auth-method"],
                                           value: draft.authMethod)
                    }
                }
                Text(draft.authMethod.summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // ABSENT WITH THE REASON, not silently missing: everyone who uses
                // SSH expects an agent option, and its absence without explanation
                // reads as a bug rather than a constraint.
                SettingCaveat(SSHNetworkTunnelConfig.unavailableMethodReason)

                EngineSettingRow(spec: Self.specs["sshnet.password"], value: !password.isEmpty) {
                    LabeledContent {
                        SecureField(draft.authMethod == .password ? "password" : "key passphrase",
                                    text: $password)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel(draft.authMethod == .password
                                                ? "SSH password" : "Private key passphrase")
                    } label: {
                        EngineSettingLabel(spec: Self.specs["sshnet.password"], value: !password.isEmpty)
                    }
                }
                if draft.needsPrivateKey {
                    EngineSettingRow(spec: Self.specs["sshnet.private-key"],
                                     value: !privateKeyPEM.isEmpty) {
                        LabeledContent {
                            SecureField("", text: $privateKeyPEM, prompt: Text("-----BEGIN OPENSSH PRIVATE KEY-----"))
                                .multilineTextAlignment(.trailing)
                                .accessibilityLabel("SSH private key")
                        } label: {
                            EngineSettingLabel(spec: Self.specs["sshnet.private-key"],
                                               value: !privateKeyPEM.isEmpty)
                        }
                    }
                }
                if draft.needsCertificate {
                    EngineSettingRow(spec: Self.specs["sshnet.certificate"],
                                     value: !certificatePEM.isEmpty) {
                        LabeledContent {
                            SecureField("", text: $certificatePEM, prompt: Text("ssh-ed25519-cert-v01@openssh.com AAAA…"))
                                .multilineTextAlignment(.trailing)
                                .accessibilityLabel("SSH certificate")
                        } label: {
                            EngineSettingLabel(spec: Self.specs["sshnet.certificate"],
                                               value: !certificatePEM.isEmpty)
                        }
                    }
                }
                Label("Saved in your Keychain, and only ever handed to the tunnel in memory.",
                      systemImage: "lock")
                    .font(.callout).foregroundStyle(.secondary)
            }

            Section("Traffic") {
                EngineSettingRow(spec: Self.specs["sshnet.send-all-traffic"],
                                 value: draft.includeDefaultRoute) {
                    Toggle(isOn: $draft.includeDefaultRoute) {
                        EngineSettingLabel(spec: Self.specs["sshnet.send-all-traffic"],
                                           value: draft.includeDefaultRoute)
                    }
                }
                if !draft.includeDefaultRoute {
                    EngineSettingRow(spec: Self.specs["sshnet.routes"], value: includedText) {
                        labeledField(Self.specs["sshnet.routes"], $includedText,
                                     prompt: "10.0.0.0/8, 192.168.1.0/24", problem: includedProblem)
                    }
                    if let p = includedProblem { fieldProblem(p) }
                }
                EngineSettingRow(spec: Self.specs["sshnet.excluded-routes"], value: excludedText) {
                    labeledField(Self.specs["sshnet.excluded-routes"], $excludedText,
                                 prompt: "10.0.0.0/8", problem: excludedProblem)
                }
                if let p = excludedProblem { fieldProblem(p) }
                if let w = overlapWarning { SettingCaveat(w) }

                EngineSettingRow(spec: Self.specs["sshnet.local-lan"],
                                 value: draft.allowLocalNetworkAccess) {
                    Toggle(isOn: $draft.allowLocalNetworkAccess) {
                        EngineSettingLabel(spec: Self.specs["sshnet.local-lan"],
                                           value: draft.allowLocalNetworkAccess)
                    }
                }
                // ON means traffic leaves the tunnel, so the row says what leaves
                // rather than describing the mechanism.
                if draft.allowLocalNetworkAccess { SettingCaveat(Self.localNetworkCaveat) }

                EngineSettingRow(spec: Self.specs["sshnet.dns"], value: dnsText) {
                    labeledField(Self.specs["sshnet.dns"], $dnsText, prompt: "1.1.1.1, 8.8.8.8",
                                 problem: dnsProblem)
                }
                if let p = dnsProblem { fieldProblem(p) }

                EngineSettingRow(spec: Self.specs["sshnet.search-domains"], value: searchDomainsText) {
                    labeledField(Self.specs["sshnet.search-domains"], $searchDomainsText,
                                 prompt: "corp.example, example.com", problem: searchDomainsProblem)
                }
                if let p = searchDomainsProblem { fieldProblem(p) }

                EngineSettingRow(spec: Self.specs["sshnet.far-side-dns"],
                                 value: draft.useFarSideResolver) {
                    Toggle(isOn: $draft.useFarSideResolver) {
                        EngineSettingLabel(spec: Self.specs["sshnet.far-side-dns"],
                                           value: draft.useFarSideResolver)
                    }
                }
                if draft.useFarSideResolver {
                    EngineSettingRow(spec: Self.specs["sshnet.far-side-resolver"],
                                     value: draft.farSideResolver) {
                        labeledField(Self.specs["sshnet.far-side-resolver"], $draft.farSideResolver,
                                     prompt: SSHNetworkTunnelConfig.defaultFarSideResolver,
                                     problem: farSideProblem)
                    }
                    if let p = farSideProblem { fieldProblem(p) }
                    if let w = draft.sentinelReachabilityWarning { SettingCaveat(w) }
                }
                if let w = draft.dnsWarning { SettingCaveat(w) }

                // ONE MTU control across every engine that has one.
                EngineSettingRow(spec: Self.specs["sshnet.mtu"], value: draft.mtu) {
                    RequiredMTUField(
                        label: { EngineSettingLabel(spec: Self.specs["sshnet.mtu"], value: draft.mtu) },
                        value: $draft.mtu,
                        range: SSHNetworkTunnelConfig.mtuRange,
                        engineDefault: SSHNetworkTunnelStartConfig.defaultMTU,
                        invalidMessage: "Enter an MTU between \(SSHNetworkTunnelConfig.mtuRange.lowerBound) and \(SSHNetworkTunnelConfig.mtuRange.upperBound). Leave empty for the standard \(SSHNetworkTunnelStartConfig.defaultMTU).")
                }
                // The one limitation nobody would guess, at the point where they
                // are deciding what to send through this tunnel.
                SettingCaveat(SSHNetworkTunnelConfig.udpCaveat)
                TrafficCrossLinks(gatewayNote: gatewayNote)
            }

            Section("Security") {
                EngineSettingRow(spec: Self.specs["sshnet.host-key-policy"],
                                 value: draft.hostKeyPolicy) {
                    SettingPicker(selection: $draft.hostKeyPolicy) {
                        ForEach(SSHNetworkTunnelConfig.HostKeyPolicy.allCases, id: \.self) {
                            Text($0.displayName).tag($0)
                        }
                    } label: {
                        EngineSettingLabel(spec: Self.specs["sshnet.host-key-policy"],
                                           value: draft.hostKeyPolicy)
                    }
                }
                EngineSettingRow(spec: Self.specs["sshnet.pinned-host-key"],
                                 value: draft.pinnedHostKeySHA256) {
                    labeledField(Self.specs["sshnet.pinned-host-key"], $draft.pinnedHostKeySHA256,
                                 prompt: "SHA256:…", problem: pinProblem)
                }
                if let p = pinProblem { fieldProblem(p) }
                // TRUST IS AN ACTION SOMEONE TAKES. The tunnel itself cannot ask
                // (it runs as a system service with no UI and no access to
                // known_hosts), so this button is where trust-on-first-use
                // actually happens: it fetches the key, shows it, and records it.
                Button {
                    Task { await checkAndTrust() }
                } label: {
                    if checkingHostKey {
                        Text("Checking\u{2026}")
                    } else {
                        Label("Check and Trust This Server", systemImage: "checkmark.shield")
                    }
                }
                .disabled(checkingHostKey || draft.serverProblem != nil)
                .help(draft.serverProblem
                      ?? "Connect to the server, show its identity key, and record it as the one this tunnel accepts")
                .accessibilityValue(draft.serverProblem ?? "")
                if let report = hostKeyReport {
                    Label(report.message,
                          systemImage: report.trusted ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(report.trusted ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel(report.trusted
                                            ? "Host key: \(report.message)"
                                            : "Problem: \(report.message)")
                }
                EngineSettingRow(spec: Self.specs["sshnet.key-exchange"], value: draft.keyExchange) {
                    labeledField(Self.specs["sshnet.key-exchange"], $draft.keyExchange,
                                 prompt: "curve25519-sha256,\u{2026}")
                }
            }

            CollapsibleSettingsSection(group: .advanced, changedCount: advancedChangedCount) {
                EngineSettingRow(spec: Self.specs["sshnet.keepalive"], value: draft.keepaliveSeconds) {
                    LabeledContent {
                        TextField("", value: $draft.keepaliveSeconds, format: .number, prompt: Text("30"))
                            .multilineTextAlignment(.trailing)
                            .frame(width: 70)
                            .accessibilityLabel("Keepalive seconds")
                    } label: {
                        EngineSettingLabel(spec: Self.specs["sshnet.keepalive"],
                                           value: draft.keepaliveSeconds)
                    }
                }
            }

            // Live status, AFTER the canonical config groups — it is not one of
            // them, so it must not interrupt their run.
            if let status, status.netstack.isRunning {
                liveSection(status)
            }
        }
        .formStyle(.grouped)
        .revealsSettings()
        .disabled(ManagedPolicy.lockConfiguration)
    }

    var body: some View {
        TabView(selection: $tab) {
            configForm
                .tag(SettingsTab.settings)
                .tabItem { Label("Settings", systemImage: "slider.horizontal.3") }
            Form {
                CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword)
            }
            .formStyle(.grouped)
            .revealsSettings()
            .disabled(ManagedPolicy.lockConfiguration)
            .tag(SettingsTab.customRouting)
            .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
        }
        .onAppear { search.visibility = SettingVisibility.sshNetworkTunnel(draft) }
        .onChange(of: SettingVisibility.sshNetworkTunnel(draft)) { _, new in search.visibility = new }
        .settingsEditor(search: search, tab: $tab,
                        surfaces: [.sshNetworkTunnel, .customRouting], profileID: profileID,
                        kind: .sshNetworkTunnel)
        .padding(.top, 10)
        .navigationTitle(name.isEmpty ? "SSH Network Tunnel" : name)
        .task { loadOnce() }
        .task(id: profileID) { await pollStatus() }
        // LIVE SAVE — no confirming button in any editor now. See `SettingCommit`.
        .savesSettingsLive { Task { await save() } }
        // RED ON THE FIELD THAT IS HOLDING THE CONNECTION UP, from the connect gate
        // itself (`SSHNetworkTunnelConfig.connectFault`) rather than a second list of
        // "required" ids — see `SettingNeeds`.
        .settingNeeds(needs)
        .safeAreaInset(edge: .bottom) {
            if ManagedPolicy.lockConfiguration {
                Label("Connection settings are managed by your organization and can't be changed here.",
                      systemImage: "lock.fill")
                    .font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10).background(.quaternary.opacity(0.5))
            }
        }
    }

    // MARK: Live status

    @ViewBuilder private func liveSection(_ status: SSHNetworkTunnelStatus) -> some View {
        Section("Right Now") {
            // The session's own health FIRST: while it is down the tunnel's routes
            // stay in place and traffic is refused rather than escaping, so "not
            // connected right now" is the single most important fact on screen.
            LabeledContent("SSH connection",
                           value: status.sessionUp ? "Connected" : "Reconnecting\u{2026}")
            LabeledContent("Open connections", value: "\(status.activeChannels)")
            LabeledContent("Connections total", value: "\(status.openedFlows)")
            if status.refusedFlows > 0 {
                LabeledContent("Refused", value: "\(status.refusedFlows)")
            }
            if status.netstack.dnsQueries > 0 {
                LabeledContent("DNS lookups", value: "\(status.netstack.dnsQueries)")
            }
            if status.netstack.udpRefused > 0 {
                LabeledContent("UDP refused (can't be carried)", value: "\(status.netstack.udpRefused)")
            }
            if status.reconnects > 0 {
                LabeledContent("Reconnects", value: "\(status.reconnects)")
            }
            let problem = status.lastSessionError.isEmpty
                ? status.netstack.lastError : status.lastSessionError
            if !problem.isEmpty {
                Label(problem, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.orange)
            }
        }
    }

    // MARK: State

    private var serverProblem: String? {
        draft.server.isEmpty ? nil : SSHNetworkTunnelConfig.serverProblem(draft.server)
    }
    private var portProblem: String? {
        let t = portText.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        guard let p = Int(t) else { return "A port is a number — 22 for a standard SSH server." }
        return SSHNetworkTunnelConfig.portRange.contains(p)
            ? nil : "\(p) isn't a valid port — use 1 to 65535."
    }
    private var includedProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(includedText)
        return list.isEmpty ? nil : SSHNetworkTunnelConfig.routesProblem(list)
    }
    private var excludedProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(excludedText)
        return list.isEmpty ? nil : SSHNetworkTunnelConfig.routesProblem(list)
    }
    private var dnsProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(dnsText)
        return list.isEmpty ? nil : SSHNetworkTunnelConfig.dnsServersProblem(list)
    }
    private var searchDomainsProblem: String? {
        DNSSearchDomains.problem(list: ProxyTunnelConfig.splitRoutes(searchDomainsText))
    }
    /// What ON actually does, in the one sentence that matters: the consequence,
    /// not the mechanism (ONTOLOGY.md, "Writing help text").
    private static let localNetworkCaveat =
        "Traffic to the network you're on \u{2014} and to the addresses devices use to find each other "
        + "\u{2014} leaves your Mac outside the tunnel, where anyone on that network can see it. "
        + "Everything else still goes through the tunnel."
    private var farSideProblem: String? {
        draft.useFarSideResolver
            ? SSHNetworkTunnelConfig.farSideResolverProblem(draft.farSideResolver) : nil
    }
    /// A pin is only a problem once something is typed — and it MUST be, for the
    /// pinned policy.
    private var pinProblem: String? {
        if draft.pinnedHostKeySHA256.trimmingCharacters(in: .whitespaces).isEmpty {
            return draft.hostKeyPolicy == .pinned
                ? "This tunnel accepts only a pinned key, so a fingerprint is required."
                : nil
        }
        return SSHNetworkTunnelConfig.pinProblem(draft.pinnedHostKeySHA256)
    }
    private var overlapWarning: String? {
        guard includedProblem == nil, excludedProblem == nil else { return nil }
        return SSHNetworkTunnelConfig.routeOverlapWarning(
            included: ProxyTunnelConfig.splitRoutes(includedText),
            excluded: ProxyTunnelConfig.splitRoutes(excludedText))
    }

    private var advancedChangedCount: Int {
        Self.specs["sshnet.keepalive"].isChanged(draft.keepaliveSeconds) ? 1 : 0
    }

    private var saveDisabledReason: String? {
        if saving { return "Saving…" }
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if draft.server.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter the SSH server address." }
        if let p = serverProblem { return p }
        if let p = portProblem { return p }
        if draft.username.trimmingCharacters(in: .whitespaces).isEmpty {
            return "Enter the login name to use on the server."
        }
        if !draft.includeDefaultRoute, ProxyTunnelConfig.splitRoutes(includedText).isEmpty {
            return "Add a network to route through the tunnel, or turn on \u{201C}Send All Traffic\u{201D}."
        }
        if let p = includedProblem { return p }
        if let p = excludedProblem { return p }
        if let p = dnsProblem { return p }
        if let p = searchDomainsProblem { return p }
        if let p = farSideProblem { return p }
        if let p = pinProblem { return p }
        return nil
    }

    /// Which row has to be filled in before this VPN can connect, and why — straight
    /// off `SSHNetworkTunnelConfig.connectFault`, which is the same gate
    /// `VPNController+SSHNetworkTunnel.connect` throws on. Asked of a draft carrying
    /// the editor's OWN text fields (they are only folded into `draft` on save), so a
    /// field the user has just typed into counts as filled in.
    private var needs: SettingNeeds {
        var probe = draft
        probe.port = Int(portText) ?? (portText.isEmpty ? 0 : -1)
        probe.includedRoutes = ProxyTunnelConfig.splitRoutes(includedText)
        probe.excludedRoutes = ProxyTunnelConfig.splitRoutes(excludedText)
        probe.dnsServers = ProxyTunnelConfig.splitRoutes(dnsText)
        probe.searchDomains = ProxyTunnelConfig.splitRoutes(searchDomainsText)
        guard let fault = probe.connectFault, let id = fault.settingID else { return SettingNeeds() }
        return SettingNeeds(byID: [id: fault.sentence])
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        draft = vpn.sshNetworkTunnelConfig(for: profileID)
        name = vpn.displayName(for: profileID)
        portText = draft.port > 0 ? String(draft.port) : ""
        let secrets = vpn.sshNetworkTunnelSecrets(for: profileID)
        password = secrets.password
        privateKeyPEM = secrets.privateKeyPEM
        certificatePEM = secrets.certificatePEM
        includedText = draft.includedRoutes.joined(separator: ", ")
        excludedText = draft.excludedRoutes.joined(separator: ", ")
        dnsText = draft.dnsServers.joined(separator: ", ")
        searchDomainsText = draft.searchDomains.joined(separator: ", ")
        status = vpn.sshNetworkTunnelStatuses[profileID]
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
    }

    private func pollStatus() async {
        while !Task.isCancelled {
            if vpn.profiles.first(where: { $0.id == profileID })?.status == .connected {
                status = await vpn.refreshSSHNetworkTunnelStatus(id: profileID)
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func checkAndTrust() async {
        checkingHostKey = true
        defer { checkingHostKey = false }
        // Save first: the check dials what is SAVED, and checking a server the
        // user has typed but not saved would trust the wrong machine.
        await save()
        let report = await vpn.checkAndTrustSSHNetworkTunnelHostKey(id: profileID)
        hostKeyReport = report
        if report.trusted {
            draft = vpn.sshNetworkTunnelConfig(for: profileID)
        }
    }

    /// Store what the editor holds. Called on field blur, on submit, and on close
    /// (`savesSettingsLive`) — never from a button, because there isn't one.
    /// Idempotent and validity-gated: an invalid draft is HELD here, not rewritten
    /// and not stored.
    private func save() async {
        guard !ManagedPolicy.lockConfiguration else { return }
        guard saveDisabledReason == nil else { return }
        saving = true
        defer { saving = false }
        draft.port = Int(portText.trimmingCharacters(in: .whitespaces)) ?? 0
        draft.includedRoutes = ProxyTunnelConfig.splitRoutes(includedText)
        draft.excludedRoutes = ProxyTunnelConfig.splitRoutes(excludedText)
        draft.dnsServers = ProxyTunnelConfig.splitRoutes(dnsText)
        draft.searchDomains = ProxyTunnelConfig.splitRoutes(searchDomainsText)
        // normalized() on every save path (the OpenVPNOverrides rule).
        draft = draft.normalized()
        do {
            try await vpn.rename(id: profileID, to: name)
            try await vpn.setSSHNetworkTunnelConfig(draft, for: profileID)
            vpn.setSSHNetworkTunnelSecrets(password: password,
                                           privateKeyPEM: draft.needsPrivateKey ? privateKeyPEM : "",
                                           certificatePEM: draft.needsCertificate ? certificatePEM : "",
                                           for: profileID)
            customRouting = await commitCustomRouting(vpn, profileID: profileID, profile: customRouting,
                                                      proxyAuthUsername: crProxyAuthUsername,
                                                      proxyAuthPassword: crProxyAuthPassword)
            // No "Saved" transient: it reused the SAME `checkmark` glyph as "Save"
            // in an icon-only toolbar, so a successful save was invisible to a
            // sighted user while VoiceOver heard "Saved". Deleting the button
            // deleted the bug.
        } catch {
            vpn.report(error, profile: profileID)
        }
    }

    private var gatewayNote: String? {
        guard vpn.profiles.first(where: { $0.id == profileID })?.status == .connected else { return nil }
        return vpn.gatewayRole(for: profileID) == .full
            ? "Right now this VPN carries ALL traffic \u{2014} it owns the default route."
            : "Right now this VPN carries only the networks above \u{2014} something else owns the default route."
    }

    // MARK: Manual-linked specs (anchors: sshnet.x → #sshnet-x in manual.html)

    static var specs: EngineSettingCatalog { SSHNetSettings.catalog }

    @ViewBuilder private func fieldProblem(_ text: String) -> some View {
        SettingProblemLabel(text)
    }

    /// The house text-field idiom — one of the five copies of it that now forward to
    /// the shared `SettingValueField` (UI/Components/SettingValueRow.swift).
    private func labeledField(_ spec: EngineSettingSpec, _ binding: Binding<String>,
                              prompt: String, problem: String? = nil,
                              accessibilityLabel: String? = nil) -> some View {
        SettingValueField(spec: spec, text: binding, prompt: prompt, problem: problem,
                          spokenName: accessibilityLabel)
    }
}
