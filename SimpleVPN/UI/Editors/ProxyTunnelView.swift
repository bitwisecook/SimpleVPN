// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelView.swift
//  Create / edit a Proxy Tunnel. One engine, three schemes: the preset picker
//  chooses SOCKS5 / HTTP CONNECT / HTTPS CONNECT, which is only the scheme of
//  the upstream URL. The tunnel presents a utun with routes and dials every flow
//  through that proxy in-process (tun2socks).
//
//  Copy rule for this form: plain words. "tun2socks", "netstack", "CONNECT
//  method" and "5-tuple" do not appear; they become "proxy tunnel", "the proxy",
//  and "connection". The one place jargon is unavoidable — the scheme names in
//  the picker — is exactly what the user copied from their proxy's docs.
//

import SwiftUI

struct ProxyTunnelView: View {
    let vpn: VPNController
    let profileID: String

    @State private var draft = ProxyTunnelConfig()
    @State private var name = ""
    @State private var preset: ProxyTunnelConfig.Preset = .socks5
    @State private var address = ""          // host or host:port (scheme is the preset)
    @State private var username = ""
    @State private var password = ""
    @State private var includedText = ""
    @State private var excludedText = ""
    @State private var dnsText = ""
    @State private var loaded = false
    @State private var saving = false
    @State private var savedTick = false
    @State private var status: ProxyTunnelStatus?
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $name)
                Picker("Kind", selection: $preset) {
                    ForEach(ProxyTunnelConfig.Preset.allCases, id: \.self) {
                        Text($0.displayName).tag($0)
                    }
                }
                Text(preset.summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                EngineSettingRow(spec: Self.specs["px.address"], changed: !address.isEmpty) {
                    TextField("proxy.example.com:\(preset.defaultPort)", text: $address)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        // The title is an EXAMPLE address — the spec name is the name.
                        .accessibilityLabel(Self.specs["px.address"].name)
                        .accessibilityValue(upstreamProblem.map { "\(address). Problem: \($0)" } ?? address)
                }
                if let problem = upstreamProblem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(problem)")
                }
            }

            Section("Sign-In") {
                EngineSettingRow(spec: Self.specs["px.requires-auth"], changed: draft.requiresAuth) {
                    Toggle(isOn: $draft.requiresAuth) {
                        Text("This proxy needs a username and password").bold(draft.requiresAuth)
                    }
                }
                if draft.requiresAuth {
                    EngineSettingRow(spec: Self.specs["px.username"], changed: !username.isEmpty) {
                        TextField("Username", text: $username)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            // Several editors show credential pairs — say whose.
                            .accessibilityLabel("Proxy username")
                    }
                    EngineSettingRow(spec: Self.specs["px.password"], changed: !password.isEmpty) {
                        SecureField("Password", text: $password)
                            .textFieldStyle(.roundedBorder)
                            .accessibilityLabel("Proxy password")
                    }
                    Label("Saved in your Keychain, and only ever handed to the proxy in memory.",
                          systemImage: "lock")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            Section("What Goes Through the Proxy") {
                EngineSettingRow(spec: Self.specs["px.default-route"], changed: !draft.includeDefaultRoute) {
                    Toggle(isOn: $draft.includeDefaultRoute) {
                        Text("Send all traffic through the proxy").bold(!draft.includeDefaultRoute)
                    }
                }
                if !draft.includeDefaultRoute {
                    EngineSettingRow(spec: Self.specs["px.included"], changed: !includedText.isEmpty) {
                        TextField("10.0.0.0/8, 192.168.1.0/24", text: $includedText)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .accessibilityLabel(Self.specs["px.included"].name)
                            .accessibilityValue(includedProblem.map { "\(includedText). Problem: \($0)" } ?? includedText)
                    }
                    if let p = includedProblem {
                        Label(p, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                            .accessibilityLabel("Problem: \(p)")
                    }
                }
                EngineSettingRow(spec: Self.specs["px.excluded"], changed: !excludedText.isEmpty) {
                    TextField("Networks to keep OUT of the proxy", text: $excludedText)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .accessibilityLabel(Self.specs["px.excluded"].name)
                        .accessibilityValue(excludedProblem.map { "\(excludedText). Problem: \($0)" } ?? excludedText)
                }
                if let p = excludedProblem {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(p)")
                }
            }

            Section("Advanced") {
                EngineSettingRow(spec: Self.specs["px.dns"], changed: !dnsText.isEmpty) {
                    TextField("1.1.1.1, 8.8.8.8", text: $dnsText)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .accessibilityLabel(Self.specs["px.dns"].name)
                }
                EngineSettingRow(spec: Self.specs["px.mtu"], changed: draft.mtu != ProxyTunnelStartConfig.defaultMTU) {
                    Stepper("MTU: \(draft.mtu)", value: $draft.mtu, in: 576...1500, step: 4)
                        .accessibilityLabel("MTU")
                        .accessibilityValue("\(draft.mtu)")
                }
            }

            if let status, status.isRunning {
                liveSection(status)
            }

            CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                proxyAuthUsername: $crProxyAuthUsername,
                                proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(name.isEmpty ? "Proxy Tunnel" : name)
        .task { loadOnce() }
        .task(id: profileID) { await pollStatus() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button { Task { await save() } } label: {
                    savedTick ? Label("Saved", systemImage: "checkmark") : Label("Save", systemImage: "checkmark")
                }
                .buttonStyle(.glassProminent)
                .disabled(saveDisabledReason != nil)
                .help(saveDisabledReason ?? "Save changes to this VPN")
                .accessibilityValue(saveDisabledReason ?? "")
            }
        }
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

    @ViewBuilder private func liveSection(_ status: ProxyTunnelStatus) -> some View {
        Section("Right Now") {
            LabeledContent("Active connections", value: "\(status.activeFlows)")
            LabeledContent("Connections total", value: "\(status.totalFlows)")
            if status.failedFlows > 0 {
                LabeledContent("Couldn't connect", value: "\(status.failedFlows)")
            }
            if status.dnsQueries > 0 {
                LabeledContent("DNS lookups", value: "\(status.dnsQueries)")
            }
            if !status.lastError.isEmpty {
                Label(status.lastError, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.orange)
            }
        }
    }

    // MARK: State

    private var upstreamProblem: String? {
        address.isEmpty ? nil : ProxyTunnelConfig.upstreamProblem(composedUpstream)
    }
    private var includedProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(includedText)
        return list.isEmpty ? nil : ProxyTunnelConfig.routesProblem(list)
    }
    private var excludedProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(excludedText)
        return list.isEmpty ? nil : ProxyTunnelConfig.routesProblem(list)
    }

    /// The upstream URL assembled from the preset scheme and the address field.
    private var composedUpstream: String {
        let a = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !a.isEmpty else { return "" }
        // Accept a full URL pasted into the address field; otherwise prefix the
        // preset's scheme.
        if a.contains("://") { return a }
        return "\(preset.scheme)://\(a)"
    }

    private var saveDisabledReason: String? {
        if saving { return "Saving…" }
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if address.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter the proxy address." }
        if let p = upstreamProblem { return p }
        if !draft.includeDefaultRoute, ProxyTunnelConfig.splitRoutes(includedText).isEmpty {
            return "Add a network to route through the proxy, or turn on \u{201C}Send all traffic\u{201D}."
        }
        if let p = includedProblem { return p }
        if let p = excludedProblem { return p }
        return nil
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        draft = vpn.proxyTunnelConfig(for: profileID)
        name = vpn.displayName(for: profileID)
        preset = draft.preset ?? .socks5
        // Address = host[:port] from the saved upstream (scheme lives in preset).
        if let comps = URLComponents(string: draft.upstream), let host = comps.host {
            address = comps.port.map { "\(host):\($0)" } ?? host
        } else {
            address = ""
        }
        let creds = vpn.proxyTunnelCredentials(for: profileID)
        username = creds.username
        password = creds.password
        includedText = draft.includedRoutes.joined(separator: ", ")
        excludedText = draft.excludedRoutes.joined(separator: ", ")
        dnsText = draft.dnsServers.joined(separator: ", ")
        status = vpn.proxyTunnelStatuses[profileID]
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
    }

    private func pollStatus() async {
        while !Task.isCancelled {
            if vpn.profiles.first(where: { $0.id == profileID })?.status == .connected {
                status = await vpn.refreshProxyTunnelStatus(id: profileID)
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        draft.upstream = composedUpstream
        draft.includedRoutes = ProxyTunnelConfig.splitRoutes(includedText)
        draft.excludedRoutes = ProxyTunnelConfig.splitRoutes(excludedText)
        draft.dnsServers = ProxyTunnelConfig.splitRoutes(dnsText)
        do {
            try await vpn.rename(id: profileID, to: name)
            try await vpn.setProxyTunnelConfig(draft, for: profileID)
            // Credentials only when the proxy needs them; clearing the toggle
            // clears the stored secret so it does not linger.
            if draft.requiresAuth {
                vpn.setProxyTunnelCredentials(username: username, password: password, for: profileID)
            } else {
                vpn.setProxyTunnelCredentials(username: "", password: "", for: profileID)
            }
            customRouting = await commitCustomRouting(vpn, profileID: profileID, profile: customRouting,
                                                      proxyAuthUsername: crProxyAuthUsername,
                                                      proxyAuthPassword: crProxyAuthPassword)
            savedTick = true
            try? await Task.sleep(for: .seconds(2))
            savedTick = false
        } catch {
            vpn.report(error, profile: profileID)
        }
    }

    // MARK: Manual-linked specs (anchors: px.x → #px-x in manual.html)

    static let specs = EngineSettingCatalog([
        .init(id: "px.address", name: "Proxy Address",
              summary: "The proxy that carries your traffic, as host or host:port. Pick the kind above to match your proxy (SOCKS5 or HTTP CONNECT)."),
        .init(id: "px.requires-auth", name: "Requires Sign-In",
              summary: "Turn on if your proxy asks for a username and password. Leave off for an open proxy."),
        .init(id: "px.username", name: "Username",
              summary: "The username your proxy expects."),
        .init(id: "px.password", name: "Password",
              summary: "The password your proxy expects. Stored in your Keychain, handed to the proxy only in memory."),
        .init(id: "px.default-route", name: "Send All Traffic",
              summary: "Route everything on this Mac through the proxy. Turn off to send only specific networks through it and leave the rest direct."),
        .init(id: "px.included", name: "Networks Through the Proxy",
              summary: "When not sending all traffic, these networks (as CIDRs) go through the proxy and nothing else does."),
        .init(id: "px.excluded", name: "Networks Kept Direct",
              summary: "Networks to send straight out, never through the proxy — even when \u{201C}Send all traffic\u{201D} is on."),
        .init(id: "px.dns", name: "DNS Servers",
              summary: "Name servers to use while connected. Lookups to them go through the proxy too, so they don't leak. Leave empty to keep your Mac's own DNS."),
        .init(id: "px.mtu", name: "MTU",
              summary: "The tunnel's maximum packet size. 1500 suits almost everything; lower it only if a network in the path needs smaller packets."),
    ])
}
