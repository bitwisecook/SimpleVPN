// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleView.swift
//  Create / edit a Tailscale or Headscale VPN. One engine, two presets: the
//  preset picker only decides whether the control-server field is shown, since
//  Headscale IS Tailscale pointed at a server you run yourself.
//
//  Copy rule for this form: no jargon. "Tailnet", "MagicDNS", "subnet router"
//  and "node" do not appear — they become "your network", "machine names",
//  "networks other machines share" and "machine". The words the user will meet
//  in the Tailscale admin console are given once, in the manual, not here.
//

import SwiftUI

struct TailscaleView: View {
    let vpn: VPNController
    let profileID: String

    @State private var draft = TailscaleConfig()
    @State private var name = ""
    @State private var authKey = ""
    @State private var advertiseText = ""
    @State private var loaded = false
    @State private var saving = false
    @State private var savedTick = false
    @State private var status: TailscaleStatus?
    @State private var prefsError: String?
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    var body: some View {
        Form {
            // Canonical group order (AGENTS.md "Config surfaces"):
            // Connection → Sign-In → Traffic → Advanced (no Security content).
            Section("Connection") {
                TextField("Name", text: $name)
                Picker("Service", selection: $draft.preset) {
                    ForEach(TailscaleConfig.Preset.allCases, id: \.self) {
                        Text($0.displayName).tag($0)
                    }
                }
                Text(draft.preset.summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                // Headscale only: Tailscale's own service has one address and
                // asking for it would just be a way to get it wrong.
                if draft.preset == .headscale {
                    EngineSettingRow(spec: Self.specs["ts.control-url"],
                                     changed: !draft.controlURL.isEmpty) {
                        TextField("https://vpn.example.com", text: $draft.controlURL)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            // The title is an EXAMPLE — the spec name is the name.
                            .accessibilityLabel(Self.specs["ts.control-url"].name)
                            // A malformed address is the FIELD's problem.
                            .accessibilityValue(draft.controlURL.isEmpty ? ""
                                : (draft.controlURLProblem.map { "\(draft.controlURL). Problem: \($0)" } ?? draft.controlURL))
                    }
                    if let problem = draft.controlURLProblem, !draft.controlURL.isEmpty {
                        Label(problem, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                            .accessibilityLabel("Problem: \(problem)")
                    }
                }

                EngineSettingRow(spec: Self.specs["ts.hostname"], changed: !draft.hostname.isEmpty) {
                    TextField(VPNController.defaultTailscaleHostname(), text: $draft.hostname)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .accessibilityLabel(Self.specs["ts.hostname"].name)
                }
            }

            Section("Sign-In") {
                EngineSettingRow(spec: Self.specs["ts.auth-key"], changed: !authKey.isEmpty) {
                    SecureField("Leave empty to sign in with a browser", text: $authKey)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel(Self.specs["ts.auth-key"].name)
                        .accessibilityValue(authKey.isEmpty ? "not set — sign in with a browser" : "set")
                }
                if authKey.isEmpty {
                    Label("SimpleVPN will open a sign-in page the first time you connect. After that this Mac stays signed in.",
                          systemImage: "safari")
                        .font(.callout).foregroundStyle(.secondary)
                    // Which browser opens that sign-in page. Defaults to your default
                    // browser because Tailscale's login often needs passkeys or a
                    // password manager living there; the in-app window is also offered.
                    BrowserPicker(selection: $draft.signInBrowser,
                                  systemDefaultLabel: "Default browser (\(BrowserCatalog.osDefaultName))")
                }
                signInStatusRow
            }

            Section("Traffic") {
                EngineSettingRow(spec: Self.specs["ts.accept-routes"], changed: !draft.acceptRoutes) {
                    Toggle(isOn: $draft.acceptRoutes) { Text("Use networks other machines share").bold(!draft.acceptRoutes) }
                }
                EngineSettingRow(spec: Self.specs["ts.accept-dns"], changed: !draft.acceptDNS) {
                    Toggle(isOn: $draft.acceptDNS) { Text("Use this network's DNS").bold(!draft.acceptDNS) }
                }
                EngineSettingRow(spec: Self.specs["ts.exit-node"], changed: draft.useExitNode) {
                    Toggle(isOn: $draft.useExitNode) { Text("Send all internet traffic through another machine").bold(draft.useExitNode) }
                }
                if draft.useExitNode {
                    exitNodePicker
                    Toggle("Allow local network access (printers, files)", isOn: $draft.exitNodeAllowLANAccess)
                }
            }

            Section("Advanced") {
                EngineSettingRow(spec: Self.specs["ts.advertise-routes"], changed: !advertiseText.isEmpty) {
                    TextField("192.168.1.0/24, 10.0.0.0/8", text: $advertiseText)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .accessibilityLabel(Self.specs["ts.advertise-routes"].name)
                        .accessibilityValue(advertiseProblem.map { "\(advertiseText). Problem: \($0)" } ?? advertiseText)
                }
                if let problem = advertiseProblem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(problem)")
                }
            }

            if let status, status.backendState == .running {
                networkSection(status)
            }

            CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                proxyAuthUsername: $crProxyAuthUsername,
                                proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(name.isEmpty ? "Tailscale" : name)
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
            } else if let prefsError {
                Label(prefsError, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10).background(.quaternary.opacity(0.5))
            }
        }
    }

    // MARK: Rows

    @ViewBuilder private var signInStatusRow: some View {
        if let status {
            let state = status.backendState
            HStack(spacing: 6) {
                // Icon + text read as ONE sentence; the button stays separate.
                HStack(spacing: 6) {
                    Image(systemName: state.isConnected ? "checkmark.circle.fill"
                            : (state.needsUserAction ? "person.crop.circle.badge.questionmark" : "clock"))
                        .foregroundStyle(state.isConnected ? .green : (state.needsUserAction ? .orange : .secondary))
                        .accessibilityHidden(true)
                    Text(state.displayText).font(.callout).foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                if state == .needsLogin {
                    Spacer()
                    // The engine's login URL, in the default browser (the SSO
                    // window is OpenConnect's loopback flow, not this one).
                    // Disabled until the engine has issued a URL to open.
                    Button("Open Sign-In…") { vpn.openTailscaleSignIn(id: profileID) }
                        .disabled(vpn.tailscaleSignInURL[profileID] == nil)
                        // A dead button must say why.
                        .help(vpn.tailscaleSignInURL[profileID] == nil
                              ? "Connect first — the sign-in page's address comes from the connection attempt."
                              : "Open the sign-in page in your browser")
                }
            }
        }
    }

    @ViewBuilder private var exitNodePicker: some View {
        let nodes = status?.exitNodes ?? []
        if nodes.isEmpty {
            // Honest empty state: the list can only be known from a live
            // session, so say so instead of showing an empty menu.
            Label(status == nil
                  ? "Connect once to see which machines can carry your traffic."
                  : "No machine on this network is offering to carry internet traffic yet.",
                  systemImage: "info.circle")
                .font(.callout).foregroundStyle(.secondary)
            TextField("Machine address (100.x.y.z)", text: $draft.exitNode)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .accessibilityLabel("Exit machine address")
        } else {
            Picker("Machine", selection: $draft.exitNode) {
                Text("Choose…").tag("")
                ForEach(nodes) { node in
                    Text(node.pickerLabel + (node.online ? "" : " (offline)")).tag(node.id)
                }
            }
        }
    }

    @ViewBuilder private func networkSection(_ status: TailscaleStatus) -> some View {
        Section("This Network") {
            LabeledContent("This Mac's address", value: status.primaryIPv4.isEmpty ? "—" : status.primaryIPv4)
            if !status.selfDNSName.isEmpty {
                LabeledContent("This Mac's name", value: status.selfDNSName)
            }
            LabeledContent("Machines", value: "\(status.peersOnline) of \(status.peerCount) online")
            if !status.exitNodeName.isEmpty {
                LabeledContent("Internet traffic via", value: status.exitNodeName)
            }
            ForEach(status.health, id: \.self) { warning in
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.orange)
            }
        }
    }

    // MARK: State

    private var advertiseProblem: String? {
        let list = TailscaleConfig.splitRoutes(advertiseText)
        return list.isEmpty ? nil : TailscaleConfig.routesProblem(list)
    }

    private var saveDisabledReason: String? {
        if saving { return "Saving…" }
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = draft.controlURLProblem { return p }
        if let p = advertiseProblem { return p }
        return nil
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        draft = vpn.tailscaleConfig(for: profileID)
        name = vpn.displayName(for: profileID)
        authKey = vpn.tailscaleAuthKey(for: profileID)
        advertiseText = draft.advertiseRoutes.joined(separator: ", ")
        status = vpn.tailscaleStatuses[profileID]
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
    }

    /// Live status while this editor is open: the exit-node list and the
    /// sign-in state only exist inside a running session.
    private func pollStatus() async {
        while !Task.isCancelled {
            if vpn.profiles.first(where: { $0.id == profileID })?.status == .connected {
                status = await vpn.refreshTailscaleStatus(id: profileID)
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        draft.advertiseRoutes = TailscaleConfig.splitRoutes(advertiseText)
        do {
            try await vpn.rename(id: profileID, to: name)
            try await vpn.setTailscaleConfig(draft, for: profileID)
            vpn.setTailscaleAuthKey(authKey, for: profileID)
            // A running session shouldn't need a reconnect just to change which
            // machine carries the traffic — push what the engine can take live.
            if vpn.profiles.first(where: { $0.id == profileID })?.status == .connected {
                let patch = TailscalePrefsPatch(
                    acceptRoutes: draft.acceptRoutes, acceptDNS: draft.acceptDNS,
                    useExitNode: draft.useExitNode, exitNode: draft.exitNode,
                    exitNodeAllowLANAccess: draft.exitNodeAllowLANAccess,
                    advertiseRoutes: draft.advertiseRoutes)
                prefsError = await vpn.pushTailscalePrefs(patch, id: profileID)
            } else {
                prefsError = nil
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

    // MARK: Manual-linked specs (anchors: ts.x → #ts-x in manual.html)

    static let specs = EngineSettingCatalog([
        .init(id: "ts.control-url", name: "Server Address",
              summary: "The web address of your own Tailscale-compatible server (Headscale). Must start with https://."),
        .init(id: "ts.hostname", name: "Name on the Network",
              summary: "What this Mac is called to the other machines on your network. Defaults to your Mac's name."),
        .init(id: "ts.auth-key", name: "Setup Key",
              summary: "An optional key from your network's admin page that signs this Mac in without a browser. Leave empty and you'll sign in the usual way, once."),
        .init(id: "ts.accept-routes", name: "Use Shared Networks",
              summary: "Some machines share the office or home network they sit on. With this on, those networks are reachable through this VPN too."),
        .init(id: "ts.accept-dns", name: "Use This Network's DNS",
              summary: "Lets you reach the other machines by name instead of by address, and uses the DNS servers your network specifies."),
        .init(id: "ts.exit-node", name: "Send Internet Traffic Elsewhere",
              summary: "Route everything — not just traffic to your own machines — through another machine on the network, the way a traditional VPN would."),
        .init(id: "ts.advertise-routes", name: "Share Networks From This Mac",
              summary: "Offer the networks this Mac can reach (like your home LAN) to the other machines. They still have to be approved on the admin page."),
    ])
}
