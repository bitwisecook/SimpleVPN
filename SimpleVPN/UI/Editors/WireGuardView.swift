// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardView.swift
//  Import / edit / export a WireGuard configuration. In-app tunnelling needs the
//  WireGuardKit engine linked into the packet-tunnel provider (dispatched by
//  vpnType alongside OpenVPN); until that engine build lands, Export hands a
//  valid .conf to the official WireGuard app. The private key is kept in the
//  keychain, never shown or exported through providerConfiguration.
//

import SwiftUI
import UniformTypeIdentifiers

struct WireGuardView: View {
    let vpn: VPNController
    @Bindable var store: WireGuardStore
    @State var draft: WireGuardConfig

    @State private var loaded = false
    @State private var showImporter = false
    @State private var pasteText = ""
    @State private var showPaste = false
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""
    /// Write-only entry: a private key typed/pasted here replaces the stored
    /// one on Save, but the field itself never shows the value already in the
    /// keychain — the same "set it, never reveal it" convention as any
    /// password field.
    @State private var newPrivateKey = ""

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.name)
                HStack {
                    Button("Import .conf…") { showImporter = true }
                    Button("Paste Configuration…") { pasteText = ""; showPaste = true }
                }
            }

            Section("Interface") {
                EngineSettingRow(spec: Self.specs["wg.address"], changed: !draft.addresses.isEmpty) {
                    listField(Self.specs["wg.address"], $draft.addresses, prompt: "10.0.0.2/32")
                }
                EngineSettingRow(spec: Self.specs["wg.dns"], changed: !draft.dns.isEmpty) {
                    listField(Self.specs["wg.dns"], $draft.dns, prompt: "1.1.1.1")
                }
                EngineSettingRow(spec: Self.specs["wg.mtu"], changed: draft.mtu != nil) {
                    intField(Self.specs["wg.mtu"], $draft.mtu, prompt: "1420")
                }
                EngineSettingRow(spec: Self.specs["wg.listen-port"], changed: draft.listenPort != nil) {
                    intField(Self.specs["wg.listen-port"], $draft.listenPort, prompt: "auto")
                }
                EngineSettingRow(spec: Self.specs["wg.table"], changed: !draft.table.isEmpty) {
                    textField(Self.specs["wg.table"], $draft.table, prompt: "auto")
                }
                EngineSettingRow(spec: Self.specs["wg.fwmark"], changed: !draft.fwMark.isEmpty) {
                    textField(Self.specs["wg.fwmark"], $draft.fwMark, prompt: "off")
                }
                LabeledContent("Private key") {
                    Text(draft.privateKey.isEmpty && newPrivateKey.isEmpty
                         ? "not set" : "•••••• (in Keychain)")
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Set / Replace Key") {
                    SecureField("paste base64 private key", text: $newPrivateKey)
                        .font(.callout.monospaced())
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                }
            }

            Section("Peer") {
                EngineSettingRow(spec: Self.specs["wg.public-key"], changed: !draft.peerPublicKey.isEmpty) {
                    monoField(Self.specs["wg.public-key"], $draft.peerPublicKey, prompt: "base64 public key")
                }
                EngineSettingRow(spec: Self.specs["wg.endpoint"], changed: !draft.endpoint.isEmpty) {
                    textField(Self.specs["wg.endpoint"], $draft.endpoint, prompt: "host:51820")
                }
                EngineSettingRow(spec: Self.specs["wg.allowed-ips"], changed: !draft.allowedIPs.isEmpty) {
                    listField(Self.specs["wg.allowed-ips"], $draft.allowedIPs, prompt: "0.0.0.0/0")
                }
                EngineSettingRow(spec: Self.specs["wg.preshared-key"], changed: !draft.presharedKey.isEmpty) {
                    monoField(Self.specs["wg.preshared-key"], $draft.presharedKey, prompt: "optional base64")
                }
                EngineSettingRow(spec: Self.specs["wg.keepalive"], changed: draft.persistentKeepalive != nil) {
                    intField(Self.specs["wg.keepalive"], $draft.persistentKeepalive, prompt: "off")
                }
                if draft.isFullTunnel {
                    Label("Full tunnel — all traffic routes through this peer.", systemImage: "globe")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            Section {
                HStack {
                    Label("In-app WireGuard tunnelling isn't in this build yet — the WireGuard engine is the remaining piece.",
                          systemImage: "wrench.and.screwdriver")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Button("Export .conf…") { export() }
                    .disabled(draft.peerPublicKey.isEmpty || !hasPrivateKey)
            } footer: {
                Text(hasPrivateKey
                     ? "Export produces a standard wg-quick file you can use with the official WireGuard app today."
                     : "Set a private key above before exporting — wg-quick refuses a config without one.")
            }

            CustomRoutingTabView(vpn: vpn, profileID: draft.id, profile: $customRouting,
                                proxyAuthUsername: $crProxyAuthUsername,
                                proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { Button("Save") { save() }.disabled(draft.name.isEmpty) }
        }
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: [UTType(filenameExtension: "conf") ?? .data, .data, .plainText]) { result in
            if case let .success(url) = result { importConf(url) }
        }
        .sheet(isPresented: $showPaste) {
            VStack(spacing: 12) {
                Text("Paste WireGuard configuration").font(.headline)
                TextEditor(text: $pasteText).font(.callout.monospaced()).frame(width: 460, height: 260)
                    .border(.quaternary)
                HStack {
                    Button("Cancel") { showPaste = false }
                    Spacer()
                    Button("Import") { applyParsed(pasteText); showPaste = false }
                        .buttonStyle(.glassProminent).disabled(pasteText.isEmpty)
                }
            }
            .padding()
        }
    }

    // MARK: Spec catalog + typed field helpers

    static let specs = EngineSettingCatalog([
        .init(id: "wg.address", name: "Addresses",
              summary: "The in-tunnel IP address(es) this device is assigned, with prefix (e.g. 10.0.0.2/32). From your provider."),
        .init(id: "wg.dns", name: "DNS Servers",
              summary: "DNS servers to use while connected. Often points inside the tunnel so private names resolve."),
        .init(id: "wg.mtu", name: "MTU",
              summary: "Largest packet size on the tunnel. Leave empty to auto-detect; lower it (e.g. 1380) if some sites hang."),
        .init(id: "wg.listen-port", name: "Listen Port",
              summary: "UDP port WireGuard listens on locally. Leave empty to let the system pick one."),
        .init(id: "wg.table", name: "Routing Table",
              summary: "“auto” installs routes for the allowed IPs; “off” installs none (you manage routing yourself)."),
        .init(id: "wg.fwmark", name: "Firewall Mark",
              summary: "A firewall mark placed on the tunnel's own packets, for advanced policy routing. Rarely needed."),
        .init(id: "wg.public-key", name: "Peer Public Key",
              summary: "The server peer's public key (base64). Identifies and encrypts to the server. From your provider."),
        .init(id: "wg.endpoint", name: "Endpoint",
              summary: "The server's public address and port, host:port (e.g. vpn.example.com:51820)."),
        .init(id: "wg.allowed-ips", name: "Allowed IPs",
              summary: "Which destinations go through this peer. 0.0.0.0/0, ::/0 sends everything (full tunnel); specific subnets make it split."),
        .init(id: "wg.preshared-key", name: "Pre-shared Key",
              summary: "Optional extra symmetric key (base64) added on top for post-quantum resistance. Only if your provider gives you one."),
        .init(id: "wg.keepalive", name: "Persistent Keepalive",
              summary: "Seconds between keepalive packets to hold the tunnel open through NAT/firewalls. 25 is typical behind NAT; empty = off."),
    ])

    private func textField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String) -> some View {
        LabeledContent { TextField(prompt, text: binding).multilineTextAlignment(.trailing).autocorrectionDisabled() }
            label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }
    private func monoField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String) -> some View {
        LabeledContent { TextField(prompt, text: binding).font(.callout.monospaced()).multilineTextAlignment(.trailing).autocorrectionDisabled() }
            label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }
    private func intField(_ spec: EngineSettingSpec, _ binding: Binding<Int?>, prompt: String) -> some View {
        LabeledContent { TextField(prompt, value: binding, format: .number.grouping(.never)).multilineTextAlignment(.trailing).frame(maxWidth: 140) }
            label: { EngineSettingLabel(spec: spec, changed: binding.wrappedValue != nil) }
    }
    private func listField(_ spec: EngineSettingSpec, _ binding: Binding<[String]>, prompt: String) -> some View {
        LabeledContent {
            TextField(prompt, text: Binding(
                get: { binding.wrappedValue.joined(separator: ", ") },
                set: { binding.wrappedValue = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
                .multilineTextAlignment(.trailing).autocorrectionDisabled()
        } label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }

    /// Whether a private key is available for export — either already in the
    /// keychain (loaded into `draft` below) or freshly typed and not yet saved.
    private var hasPrivateKey: Bool { !draft.privateKey.isEmpty || !newPrivateKey.isEmpty }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        draft = draft.withSecretsFromKeychain()
        customRouting = vpn.customRouting(for: draft.id)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: draft.id)
    }

    private func importConf(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        applyParsed(text, name: url.deletingPathExtension().lastPathComponent)
    }

    private func applyParsed(_ text: String, name: String? = nil) {
        let parsed = WireGuardConfig.parse(text, name: name ?? draft.name)
        var next = parsed
        next.id = draft.id                       // keep identity
        if name == nil { next.name = draft.name }
        draft = next
    }

    private func save() {
        if !newPrivateKey.isEmpty {
            draft.privateKey = newPrivateKey
            newPrivateKey = ""
        }
        // store.save() moves the private/preshared key into the keychain and
        // persists only a redacted copy — the same move on every save path.
        store.save(draft)
        // Fire-and-forget: save() is called synchronously from a plain Button
        // action; commitCustomRouting is idempotent, and CustomRoutingTabView's
        // own onDisappear covers the case where the view closes before this lands.
        let id = draft.id
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            customRouting = await commitCustomRouting(vpn, profileID: id, profile: toCommit,
                                                      proxyAuthUsername: user, proxyAuthPassword: pass)
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(draft.name).conf"
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var toExport = draft
        if !newPrivateKey.isEmpty { toExport.privateKey = newPrivateKey }
        try? toExport.serialize().write(to: url, atomically: true, encoding: .utf8)
    }
}
