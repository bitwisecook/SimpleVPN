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

    /// Which tab is showing. A binding, so a related-settings link or a search
    /// hit on the other tab can select it — no TabView in the app could be
    /// selected in code before this.
    @State private var tab: SettingsTab = .settings
    /// This editor's search catalog: its own surface plus Custom Routing, which
    /// is its second tab — one field finds everything this editor shows.
    @State private var search = SettingsSearch(surfaces: [.proxyTunnel, .customRouting],
                                               kind: .proxyTunnel)

    /// The config surface: the canonical groups, in order (AGENTS.md "Config
    /// surfaces"). Security and Advanced have no content for this engine.
    private var configForm: some View {
        Form {
            SettingsSearchSection(search: search)
            Section("Connection") {
                TextField("Name", text: $name)
                EngineSettingRow(spec: Self.specs["px.kind"], value: preset) {
                    Picker(selection: $preset) {
                        ForEach(ProxyTunnelConfig.Preset.allCases, id: \.self) {
                            Text($0.displayName).tag($0)
                        }
                    } label: {
                        EngineSettingLabel(spec: Self.specs["px.kind"], value: preset)
                    }
                }
                Text(preset.summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                EngineSettingRow(spec: Self.specs["px.address"], value: address) {
                    labeledField(Self.specs["px.address"], $address,
                                 prompt: "proxy.example.com:\(preset.defaultPort)",
                                 problem: upstreamProblem)
                        // A pasted full URL wins over the Kind picker in
                        // `composedUpstream`, so it must DRIVE the picker too —
                        // otherwise the picker sits there naming a scheme the
                        // tunnel isn't using.
                        .onChange(of: address) { _, new in
                            if let implied = ProxyTunnelConfig.Preset.implied(byAddress: new) {
                                preset = implied
                            }
                        }
                }
                if let problem = upstreamProblem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(problem)")
                }
            }

            Section("Sign-In") {
                // The Toggle's label is the SPEC's name. It used to carry its own
                // string while the row rendered the spec name, so one setting had
                // two names — search found one, the screen showed the other.
                EngineSettingRow(spec: Self.specs["px.requires-auth"], value: draft.requiresAuth) {
                    Toggle(isOn: $draft.requiresAuth) {
                        EngineSettingLabel(spec: Self.specs["px.requires-auth"], value: draft.requiresAuth)
                    }
                }
                if draft.requiresAuth {
                    EngineSettingRow(spec: Self.specs["px.username"], value: username) {
                        // Several editors show credential pairs — say whose.
                        labeledField(Self.specs["px.username"], $username, prompt: "username",
                                     accessibilityLabel: "Proxy username")
                    }
                    EngineSettingRow(spec: Self.specs["px.password"], value: password) {
                        LabeledContent {
                            // prompt:, not a title — inside LabeledContent a title
                            // renders as visible text beside the value.
                            SecureField("", text: $password, prompt: Text("password"))
                                .multilineTextAlignment(.trailing)
                                .accessibilityLabel("Proxy password")
                        } label: {
                            EngineSettingLabel(spec: Self.specs["px.password"], value: password)
                        }
                    }
                    Label("Saved in your Keychain, and only ever handed to the proxy in memory.",
                          systemImage: "lock")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            Section("Traffic") {
                EngineSettingRow(spec: Self.specs["px.default-route"], value: draft.includeDefaultRoute) {
                    Toggle(isOn: $draft.includeDefaultRoute) {
                        EngineSettingLabel(spec: Self.specs["px.default-route"],
                                           value: draft.includeDefaultRoute)
                    }
                }
                if !draft.includeDefaultRoute {
                    EngineSettingRow(spec: Self.specs["px.included"], value: includedText) {
                        labeledField(Self.specs["px.included"], $includedText,
                                     prompt: "10.0.0.0/8, 192.168.1.0/24",
                                     problem: includedProblem)
                    }
                    if let p = includedProblem {
                        Label(p, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                            .accessibilityLabel("Problem: \(p)")
                    }
                }
                EngineSettingRow(spec: Self.specs["px.excluded"], value: excludedText) {
                    labeledField(Self.specs["px.excluded"], $excludedText,
                                 prompt: "10.0.0.0/8", problem: excludedProblem)
                }
                if let p = excludedProblem {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(p)")
                }
                // Non-blocking: an exclusion that swallows part of an inclusion
                // is legal and does something — just rarely what was meant.
                if let w = overlapWarning {
                    SettingCaveat(w)
                }
                // …and with a split tunnel, an exclusion outside every included
                // network has nothing to take out.
                if let w = excludedRedundantWarning {
                    SettingCaveat(w)
                }
                EngineSettingRow(spec: Self.specs["px.dns"], value: dnsText) {
                    // A bad resolver is the FIELD's problem — NE just drops it,
                    // and DNS stops with nothing said anywhere.
                    labeledField(Self.specs["px.dns"], $dnsText, prompt: "1.1.1.1, 8.8.8.8",
                                 problem: dnsProblem)
                }
                if let p = dnsProblem {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(p)")
                }
                // A resolver an exclusion carves out still gets used — just
                // directly, outside the proxy. The one DNS hazard this tunnel
                // really has (a resolver outside the included routes is already
                // handled: ProxyTunnelNetworkSettings routes each one in).
                if let w = dnsExcludedWarning {
                    SettingCaveat(w)
                }
                // ONE MTU control across every engine that has one (see
                // UI/Components/MTUField.swift). This was a `Stepper(step: 4)`
                // over a 925-wide range — thirty clicks from 1500 to 1380, with
                // no way to type the number at all.
                EngineSettingRow(spec: Self.specs["px.mtu"], value: draft.mtu) {
                    RequiredMTUField(
                        label: { EngineSettingLabel(spec: Self.specs["px.mtu"], value: draft.mtu) },
                        value: $draft.mtu,
                        range: ProxyTunnelConfig.mtuRange,
                        engineDefault: ProxyTunnelStartConfig.defaultMTU,
                        invalidMessage: "Enter an MTU between \(ProxyTunnelConfig.mtuRange.lowerBound) and \(ProxyTunnelConfig.mtuRange.upperBound). Leave empty for the standard \(ProxyTunnelStartConfig.defaultMTU).")
                }
                TrafficCrossLinks(gatewayNote: gatewayNote)
            }

            // Live status, AFTER the canonical config groups — it is not one of
            // them, so it must not interrupt their run.
            if let status, status.isRunning {
                liveSection(status)
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
        // Which rows this draft gates OUT, so a search hit or a related link
        // naming one says so instead of jumping nowhere (SettingVisibility).
        // Inner, so the shell's route consumption can't read a stale table.
        .onAppear { search.visibility = SettingVisibility.proxyTunnel(draft) }
        .onChange(of: SettingVisibility.proxyTunnel(draft)) { _, new in search.visibility = new }
        .settingsEditor(search: search, tab: $tab,
                        surfaces: [.proxyTunnel, .customRouting], profileID: profileID,
                        kind: .proxyTunnel)
        .padding(.top, 10)
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
    /// A resolver is an ADDRESS, never a prefix — see `dnsServerProblem`.
    private var dnsProblem: String? {
        let list = ProxyTunnelConfig.splitRoutes(dnsText)
        return list.isEmpty ? nil : ProxyTunnelConfig.dnsServersProblem(list)
    }
    /// Non-blocking, and only once both lists parse.
    private var overlapWarning: String? {
        guard includedProblem == nil, excludedProblem == nil else { return nil }
        return ProxyTunnelConfig.routeOverlapWarning(
            included: ProxyTunnelConfig.splitRoutes(includedText),
            excluded: ProxyTunnelConfig.splitRoutes(excludedText))
    }
    /// Non-blocking: exclusions with nothing to exclude under a split tunnel.
    private var excludedRedundantWarning: String? {
        guard includedProblem == nil, excludedProblem == nil else { return nil }
        return ProxyTunnelConfig.excludedRedundantWarning(
            includeDefaultRoute: draft.includeDefaultRoute,
            included: ProxyTunnelConfig.splitRoutes(includedText),
            excluded: ProxyTunnelConfig.splitRoutes(excludedText))
    }
    /// Non-blocking: an advertised resolver an exclusion sends back out direct.
    private var dnsExcludedWarning: String? {
        guard dnsProblem == nil, excludedProblem == nil else { return nil }
        return ProxyTunnelConfig.dnsExcludedWarning(
            dnsServers: ProxyTunnelConfig.splitRoutes(dnsText),
            excluded: ProxyTunnelConfig.splitRoutes(excludedText))
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
        if let p = dnsProblem { return p }
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
        // normalized() on every save path (the OpenVPNOverrides rule).
        draft = draft.normalized()
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

    /// Whether this VPN is carrying everything right now — the question the
    /// Traffic group answers only in theory. nil when it isn't connected.
    private var gatewayNote: String? {
        guard vpn.profiles.first(where: { $0.id == profileID })?.status == .connected else { return nil }
        return vpn.gatewayRole(for: profileID) == .full
            ? "Right now this VPN carries ALL traffic \u{2014} it owns the default route."
            : "Right now this VPN carries only the networks above \u{2014} something else owns the default route."
    }

    // MARK: Manual-linked specs (anchors: px.x → #px-x in manual.html)

    /// The catalog now lives in `ControlPlane/ProxyTunnelSettingDescriptors.swift`
    /// so app-wide search can reach it; this alias keeps the form's call sites
    /// reading `Self.specs["px.…"]`.
    static var specs: EngineSettingCatalog { ProxyTunnelSettings.catalog }

    /// The house text-field idiom (`LabeledContent` + trailing plain field), so a
    /// text row looks the same here as in the OpenVPN, WireGuard, SSH and
    /// OpenConnect editors — this form used full-width `.roundedBorder` fields.
    private func labeledField(_ spec: EngineSettingSpec, _ binding: Binding<String>,
                              prompt: String, problem: String? = nil,
                              accessibilityLabel: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding)
                .multilineTextAlignment(.trailing)
                .autocorrectionDisabled()
                // The title is an EXAMPLE value — the spec name is the name.
                .accessibilityLabel(accessibilityLabel ?? spec.name)
                .accessibilityValue(problem.map { "\(binding.wrappedValue). Problem: \($0)" }
                                    ?? binding.wrappedValue)
        } label: {
            EngineSettingLabel(spec: spec, value: binding.wrappedValue)
        }
    }
}
