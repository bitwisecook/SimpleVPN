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

    /// The config surface: the canonical groups, in order (AGENTS.md "Config
    /// surfaces"). Security and Advanced have no content for this engine and are
    /// omitted; the live "This Network" status is NOT a config group and lives
    /// outside this form (it used to sit between Advanced and Custom Routing,
    /// i.e. inside the run of config groups).
    private var configForm: some View {
        Form {
            Section("Connection") {
                TextField("Name", text: $name)
                EngineSettingRow(spec: Self.specs["ts.preset"], value: draft.preset) {
                    Picker(selection: $draft.preset) {
                        ForEach(TailscaleConfig.Preset.allCases, id: \.self) {
                            Text($0.displayName).tag($0)
                        }
                    } label: {
                        EngineSettingLabel(spec: Self.specs["ts.preset"], value: draft.preset)
                    }
                }
                Text(draft.preset.summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                // Headscale only: Tailscale's own service has one address and
                // asking for it would just be a way to get it wrong.
                if draft.preset == .headscale {
                    EngineSettingRow(spec: Self.specs["ts.control-url"], value: draft.controlURL) {
                        labeledField(Self.specs["ts.control-url"], $draft.controlURL,
                                     prompt: "https://vpn.example.com",
                                     // A malformed address is the FIELD's problem.
                                     problem: draft.controlURL.isEmpty ? nil : draft.controlURLProblem)
                    }
                    if let problem = draft.controlURLProblem, !draft.controlURL.isEmpty {
                        Label(problem, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                            .accessibilityLabel("Problem: \(problem)")
                    }
                }

                EngineSettingRow(spec: Self.specs["ts.hostname"], value: draft.hostname) {
                    labeledField(Self.specs["ts.hostname"], $draft.hostname,
                                 prompt: VPNController.defaultTailscaleHostname(),
                                 problem: hostnameWarning)
                }
                // Non-blocking: the name is legal, it just won't survive intact.
                if let w = hostnameWarning { SettingCaveat(w) }
            }

            Section("Sign-In") {
                EngineSettingRow(spec: Self.specs["ts.auth-key"], value: authKey) {
                    LabeledContent {
                        SecureField("empty = sign in with a browser", text: $authKey)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel(Self.specs["ts.auth-key"].name)
                            .accessibilityValue(authKey.isEmpty ? "not set — sign in with a browser"
                                                : (authKeyWarning.map { "set. \($0)" } ?? "set"))
                    } label: {
                        EngineSettingLabel(spec: Self.specs["ts.auth-key"], value: authKey)
                    }
                }
                // Non-blocking: Headscale's keys legitimately look different.
                if let w = authKeyWarning { SettingCaveat(w) }
                if !authKey.isEmpty {
                    // The converse of the browser story below, which is correctly
                    // hidden here — but hiding it said nothing about WHY, and a
                    // key that turns out to be wrong then fails with no hint that
                    // no sign-in page was ever going to appear.
                    Label("This Mac signs in with the key — no sign-in page opens, and no browser is involved. Clear the key to sign in with a browser instead.",
                          systemImage: "key.fill")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
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
                // The Toggle's label is the SPEC's name. It used to carry its own
                // string ("Use networks other machines share") while the row above
                // rendered the spec name ("Use Shared Networks"), so one setting
                // had two names: search found one, the screen showed the other.
                EngineSettingRow(spec: Self.specs["ts.accept-routes"], value: draft.acceptRoutes) {
                    Toggle(isOn: $draft.acceptRoutes) {
                        EngineSettingLabel(spec: Self.specs["ts.accept-routes"], value: draft.acceptRoutes)
                    }
                }
                // Both toggles reach the engine and do exactly what they say — but
                // paired with an exit machine each leaves a hole worth naming.
                if !draft.acceptRoutes && draft.useExitNode {
                    SettingCaveat("With shared networks off, only your internet traffic goes through the other machine. The office or home networks other machines share stay unreachable.")
                }
                EngineSettingRow(spec: Self.specs["ts.accept-dns"], value: draft.acceptDNS) {
                    Toggle(isOn: $draft.acceptDNS) {
                        EngineSettingLabel(spec: Self.specs["ts.accept-dns"], value: draft.acceptDNS)
                    }
                }
                if !draft.acceptDNS && draft.useExitNode {
                    SettingCaveat("Your traffic goes through the other machine but your name lookups don't — they keep using this Mac's own DNS servers, which reveals every site you visit to whoever runs them. Turn this network's DNS on to send lookups through the machine carrying your traffic.")
                }
                EngineSettingRow(spec: Self.specs["ts.exit-node"], value: draft.useExitNode) {
                    Toggle(isOn: $draft.useExitNode) {
                        EngineSettingLabel(spec: Self.specs["ts.exit-node"], value: draft.useExitNode)
                    }
                }
                if draft.useExitNode {
                    exitNodePicker
                    // On with nothing chosen is a tunnel that carries traffic
                    // nowhere — say so here, and block Save and Connect.
                    if let p = draft.exitNodeSelectionProblem {
                        Label(p, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                            .accessibilityLabel("Problem: \(p)")
                    }
                    EngineSettingRow(spec: Self.specs["ts.exit-node-lan"],
                                     value: draft.exitNodeAllowLANAccess) {
                        Toggle(isOn: $draft.exitNodeAllowLANAccess) {
                            EngineSettingLabel(spec: Self.specs["ts.exit-node-lan"],
                                               value: draft.exitNodeAllowLANAccess)
                        }
                    }
                }
                EngineSettingRow(spec: Self.specs["ts.advertise-routes"], value: advertiseText) {
                    labeledField(Self.specs["ts.advertise-routes"], $advertiseText,
                                 prompt: "192.168.1.0/24, 10.0.0.0/8",
                                 problem: advertiseProblem)
                }
                if let problem = advertiseProblem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(problem)")
                }
            }

            // Live status, AFTER the canonical config groups. It used to sit
            // between Advanced and Custom Routing — inside the config run — where
            // a read-only status block reads as another group of settings.
            if let status, status.backendState == .running {
                networkSection(status)
            }
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
    }

    var body: some View {
        // Custom Routing is its own TAB in every editor (AGENTS.md "Config
        // surfaces") — appending it as sections put a second, differently-shaped
        // config surface inside the run of canonical groups.
        TabView {
            configForm
                .tabItem { Label("Settings", systemImage: "slider.horizontal.3") }
            Form {
                CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword)
            }
            .formStyle(.grouped)
            .disabled(ManagedPolicy.lockConfiguration)
            .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
        }
        .padding(.top, 10)
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
        let spec = Self.specs["ts.exit-node-machine"]
        if nodes.isEmpty {
            // Honest empty state: the list can only be known from a live
            // session, so say so instead of showing an empty menu.
            Label(status == nil
                  ? "Connect once to see which machines can carry your traffic."
                  : "No machine on this network is offering to carry internet traffic yet.",
                  systemImage: "info.circle")
                .font(.callout).foregroundStyle(.secondary)
            EngineSettingRow(spec: spec, value: draft.exitNode) {
                labeledField(spec, $draft.exitNode, prompt: "100.x.y.z",
                             // Validation rides the field's value (Docs/Accessibility.md).
                             problem: TailscaleConfig.exitNodeProblem(draft.exitNode))
            }
        } else {
            EngineSettingRow(spec: spec, value: draft.exitNode) {
                Picker(selection: $draft.exitNode) {
                    Text("Choose…").tag("")
                    ForEach(nodes) { node in
                        Text(node.pickerLabel + (node.online ? "" : " (offline)")).tag(node.id)
                    }
                } label: {
                    EngineSettingLabel(spec: spec, value: draft.exitNode)
                }
            }
        }
    }

    /// The house text-field idiom: `LabeledContent` with a trailing plain field,
    /// as used by the OpenVPN, WireGuard, SSH and OpenConnect editors. This form
    /// used `.roundedBorder` full-width fields, so the same control looked
    /// different depending on which editor you happened to open.
    private func labeledField(_ spec: EngineSettingSpec, _ binding: Binding<String>,
                              prompt: String, problem: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding)
                .multilineTextAlignment(.trailing)
                .autocorrectionDisabled()
                // The title is an EXAMPLE value — the spec name is the name.
                .accessibilityLabel(spec.name)
                .accessibilityValue(problem.map { "\(binding.wrappedValue). Problem: \($0)" }
                                    ?? binding.wrappedValue)
        } label: {
            EngineSettingLabel(spec: spec, value: binding.wrappedValue)
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

    /// Non-blocking nudges (the name is legal; the key may be a Headscale one).
    private var hostnameWarning: String? { TailscaleConfig.hostnameWarning(draft.hostname) }
    private var authKeyWarning: String? {
        TailscaleConfig.authKeyWarning(authKey, preset: draft.preset)
    }

    private var saveDisabledReason: String? {
        if saving { return "Saving…" }
        if name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = draft.controlURLProblem { return p }
        // Ungated before: saving this produced a tunnel that silently sent
        // traffic nowhere.
        if let p = draft.exitNodeSelectionProblem { return p }
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
        // normalized() on every save path (the OpenVPNOverrides rule).
        draft = draft.normalized()
        do {
            try await vpn.rename(id: profileID, to: name)
            try await vpn.setTailscaleConfig(draft, for: profileID)
            vpn.setTailscaleAuthKey(authKey, for: profileID)
            // A running session shouldn't need a reconnect just to change which
            // machine carries the traffic — push what the engine can take live.
            if vpn.profiles.first(where: { $0.id == profileID })?.status == .connected {
                // Same symmetry the start payload keeps (TailscaleStartConfig):
                // no exit machine ⇒ no exit node id and no LAN carve-out.
                let patch = TailscalePrefsPatch(
                    acceptRoutes: draft.acceptRoutes, acceptDNS: draft.acceptDNS,
                    useExitNode: draft.useExitNode,
                    exitNode: draft.useExitNode ? draft.exitNode : "",
                    exitNodeAllowLANAccess: draft.useExitNode && draft.exitNodeAllowLANAccess,
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

    /// In canonical group order (AGENTS.md "Config surfaces"). There is no
    /// Security content and — with Share Networks moved to Traffic, where a
    /// decision about which networks this Mac carries belongs — no Advanced
    /// content either, so both groups are OMITTED rather than shown empty.
    static let specs = EngineSettingCatalog([

        // MARK: Connection

        .init(id: "ts.preset", name: "Service",
              summary: "Tailscale's own coordination service, or a Headscale server you run yourself. It is the same engine either way — this only decides whether you're asked for a server address.",
              group: .connection, default: TailscaleConfig.Preset.tailscale),
        .init(id: "ts.control-url", name: "Server Address",
              summary: "The web address of your own Tailscale-compatible server (Headscale). Must start with https://.",
              group: .connection, default: ""),
        .init(id: "ts.hostname", name: "Name on the Network",
              summary: "What this Mac is called to the other machines on your network. Defaults to your Mac's name.",
              group: .connection, default: ""),

        // MARK: Sign-In

        .init(id: "ts.auth-key", name: "Setup Key",
              summary: "An optional key from your network's admin page that signs this Mac in without a browser. Leave empty and you'll sign in the usual way, once.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "ts.accept-routes", name: "Use Shared Networks",
              summary: "Some machines share the office or home network they sit on. With this on, those networks are reachable through this VPN too.",
              group: .traffic, default: true),
        .init(id: "ts.accept-dns", name: "Use This Network's DNS",
              summary: "Lets you reach the other machines by name instead of by address, and uses the DNS servers your network specifies.",
              group: .traffic, default: true),
        .init(id: "ts.exit-node", name: "Send Internet Traffic Elsewhere",
              summary: "Route everything — not just traffic to your own machines — through another machine on the network, the way a traditional VPN would.",
              group: .traffic, default: false),
        .init(id: "ts.exit-node-machine", name: "Machine",
              summary: "Which machine on your network carries your internet traffic. It has to be offering to, and be approved on the admin page — SimpleVPN can only list the ones that are while connected.",
              group: .traffic, default: ""),
        .init(id: "ts.exit-node-lan", name: "Allow Local Network Access",
              summary: "While your internet traffic goes through another machine, keep the network you are physically on — printers, file shares — directly reachable.",
              group: .traffic, default: true),
        // Sharing the networks this Mac can reach is a decision about which
        // traffic this tunnel carries, so it sits with the other traffic
        // decisions rather than alone under an "Advanced" heading.
        .init(id: "ts.advertise-routes", name: "Share Networks From This Mac",
              summary: "Offer the networks this Mac can reach (like your home LAN) to the other machines. They still have to be approved on the admin page.",
              group: .traffic, default: ""),
    ])
}
