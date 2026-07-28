// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionView.swift
//  Main window — connection only. Startup flow (per Apple HIG onboarding guidance):
//   1. extension not activated → activation prompt + instructions
//   2. no VPNs configured → import / add prompt
//   3. otherwise → sidebar of VPNs + connection detail (status, connect/disconnect,
//      OTP entry, and the throughput graph once M6 lands).
//  VPN management (create/import/edit/remove/export) lives in its own window.
//

import SwiftUI
import UniformTypeIdentifiers

struct ConnectionView: View {
    @Bindable var vpn: VPNController
    @Bindable var ext: ExtensionController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow
    @State private var showImporter = false

    var body: some View {
        content
            .navigationTitle("SimpleVPN")
            .task { await vpn.loadAll(); await ext.activate() }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [UI.ovpnType, .data, .plainText],
                          onCompletion: importConfig)
            .alert("Error", isPresented: .constant(vpn.lastError != nil)) {
                Button("OK") { vpn.lastError = nil }
            } message: { Text(vpn.lastError ?? "") }
    }

    @ViewBuilder private var content: some View {
        if !ext.isActivated {
            ActivationPrompt(ext: ext)
        } else if vpn.profiles.isEmpty {
            EmptyVPNsPrompt(importAction: { showImporter = true }, manageAction: { openWindow(id: "manage") })
        } else {
            splitView
        }
    }

    private var splitView: some View {
        NavigationSplitView {
            List(selection: $vpn.selectedID) {
                Section("VPNs") {
                    ForEach(vpn.profiles) { p in
                        VPNRow(profile: p, labelDefs: labels.labels(for: p.id)).tag(p.id)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .toolbar {
                ToolbarItem {
                    Button { openWindow(id: "manage") } label: { Image(systemName: "slider.horizontal.3") }
                        .help("Manage VPNs")
                }
            }
        } detail: {
            if let p = vpn.selected {
                ConnectionDetailView(vpn: vpn, profile: p).id(p.id)
            } else {
                ContentUnavailableView("Select a VPN", systemImage: "network")
            }
        }
        .navigationSubtitle("app \(UI.appVersion) · ext \(vpn.extensionVersion)")
    }

    private func importConfig(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            vpn.lastError = "Could not read \(url.lastPathComponent)"; return
        }
        let name = url.deletingPathExtension().lastPathComponent
        let server = UI.parseRemote(text) ?? name
        Task { do { try await vpn.importProfile(name: name, ovpn: text, server: server) } catch { vpn.lastError = error.localizedDescription } }
    }
}

// MARK: - Startup states

private struct ActivationPrompt: View {
    @Bindable var ext: ExtensionController
    @Environment(\.openURL) private var openURL
    var body: some View {
        ContentUnavailableView {
            Label("System Extension Required", systemImage: "puzzlepiece.extension")
        } description: {
            VStack(spacing: 8) {
                Text("SimpleVPN runs tunnels in a system extension. Activate it, then approve it in System Settings if prompted.")
                Text(ext.status).font(.callout).foregroundStyle(.secondary)
            }
        } actions: {
            Button("Activate Extension") { Task { await ext.activate() } }
                .buttonStyle(.borderedProminent)
            if ext.needsApproval {
                Button("Open Login Items & Extensions") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                        openURL(url)
                    }
                }
            }
        }
    }
}

private struct EmptyVPNsPrompt: View {
    let importAction: () -> Void
    let manageAction: () -> Void
    var body: some View {
        ContentUnavailableView {
            Label("No VPNs Configured", systemImage: "network.slash")
        } description: {
            Text("Import an OpenVPN configuration, or add a new VPN to get started.")
        } actions: {
            Button("Import .ovpn…", action: importAction).buttonStyle(.borderedProminent)
            Button("Add VPN…", action: manageAction)
        }
    }
}

// MARK: - Connection detail (connection only)

private struct ConnectionDetailView: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @State private var username = ""
    @State private var password = ""
    @State private var otp = ""
    @State private var remember = true
    @State private var busy = false
    @State private var loaded = false
    @State private var monitor = ThroughputMonitor()

    private var canConnect: Bool {
        !username.trimmingCharacters(in: .whitespaces).isEmpty && !password.isEmpty
    }

    var body: some View {
        VStack(spacing: 20) {
            header
            Divider()
            if UI.isActive(profile.status) {
                connectedBody
            } else {
                credentialForm
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(minWidth: 440)
        .navigationTitle(profile.name)
        .disabled(busy)
        .task { loadOnce() }
        .task(id: profile.status == .connected) {
            if profile.status == .connected { monitor.start(profile: profile.id) }
            else { monitor.stop() }
        }
        .onDisappear { monitor.stop() }
    }

    // Connect/disconnect lives here, in the header, local to this VPN — not a global button.
    private var header: some View {
        HStack(spacing: 14) {
            LogoBadge(id: profile.id, status: profile.status)
                .scaleEffect(1.6).frame(width: 40, height: 40)
            VStack(alignment: .leading) {
                Text(profile.name).font(.title2).bold()
                if !profile.server.isEmpty { Text(profile.server).foregroundStyle(.secondary) }
            }
            Spacer()
            connectControl
        }
    }

    @ViewBuilder private var connectControl: some View {
        switch profile.status {
        case .connected, .reasserting:
            Button("Disconnect") { vpn.disconnect(id: profile.id) }
                .buttonStyle(.bordered).controlSize(.large).tint(.red)
        case .connecting, .disconnecting:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(VPNController.statusText(profile.status)).foregroundStyle(.secondary)
            }
        default:   // disconnected / invalid
            connectButton
        }
    }

    @ViewBuilder private var connectButton: some View {
        if #available(macOS 26, *) {
            Button("Connect") { Task { await connect() } }
                .buttonStyle(.glassProminent).controlSize(.large).disabled(!canConnect)
        } else {
            Button("Connect") { Task { await connect() } }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(!canConnect)
        }
    }

    @ViewBuilder private var connectedBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            ThroughputReadout(inRate: monitor.inRate, outRate: monitor.outRate)
            ThroughputGraph(samples: monitor.samples, scaleMax: monitor.scaleMax)
            Divider()
            ConnectionInfoPanel(stats: monitor.latest, clientLabel: profile.server)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // Inline credentials so you can connect straight from here (Remember saves them).
    private var credentialForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Username").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    TextField("Username", text: $username).textContentType(.username)
                }
                GridRow {
                    Text("Password").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    SecureField("Password", text: $password).textContentType(.password)
                }
                GridRow {
                    Text("OTP").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    TextField("One-time passcode (if required)", text: $otp)
                        .textContentType(.oneTimeCode)
                        .onSubmit { if canConnect { Task { await connect() } } }
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 380)

            Toggle("Remember username & password", isOn: $remember)
                .toggleStyle(.checkbox)

            Text("Credentials are stored in your Keychain. Manage this VPN in the Manage VPNs window.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        if let c = vpn.savedCredentials(id: profile.id) {
            username = c.username; password = c.password; remember = true
        }
    }

    private func connect() async {
        busy = true; defer { busy = false }
        let provider = ManualCredentialProvider(username: username, password: password, otp: otp)
        do {
            try await vpn.connect(id: profile.id, using: provider, request: .usernamePasswordOTP, remember: remember)
            otp = ""   // one-time only
        } catch { vpn.lastError = error.localizedDescription }
    }
}
