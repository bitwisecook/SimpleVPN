// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardView.swift
//  Import / edit / export a WireGuard configuration. A WireGuard VPN is an
//  ordinary packet-tunnel profile (the wireguard-go engine runs in-process in
//  the extension — VPNController+WireGuard.swift owns the settings blob and
//  connect flow); this editor is a structured view over the wg-quick fields.
//  The private key is kept in the keychain, never shown, and never persisted
//  through providerConfiguration.
//

import SwiftUI
import UniformTypeIdentifiers

struct WireGuardView: View {
    let vpn: VPNController
    let profileID: String
    @State private var draft = WireGuardConfig()

    @State private var loaded = false
    @State private var showImporter = false
    @State private var pasteText = ""
    @State private var showPaste = false
    @FocusState private var pasteFocused: Bool
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""
    /// Write-only entry: a private key typed/pasted here replaces the stored
    /// one on Save, but the field itself never shows the value already in the
    /// keychain — the same "set it, never reveal it" convention as any
    /// password field.
    @State private var newPrivateKey = ""
    /// Same write-only entry for the pre-shared key. It IS key material — a
    /// symmetric secret kept in the keychain (WireGuard's post-quantum extra) —
    /// so it gets the private key's treatment exactly: the row says whether one
    /// is stored, and the value is never rendered.
    @State private var newPresharedKey = ""
    /// Set by "Remove": clears the stored pre-shared key on Save. A write-only
    /// field can only ever REPLACE a secret, and this one is optional — without
    /// this a user could never take it off again (and clearing must really
    /// clear, not leave the old key in the keychain and in use).
    @State private var removePresharedKey = false

    var body: some View {
        Form {
            // Canonical group order (AGENTS.md "Config surfaces"):
            // Connection → Sign-In → Traffic → Advanced (keys ARE WireGuard's
            // sign-in, so they group there; the wg-quick Interface/Peer split
            // survives only in the .conf round-trip, not in the form).
            Section("Connection") {
                TextField("Name", text: $draft.name)
                HStack {
                    Button("Import .conf…") { showImporter = true }
                    Button("Paste Configuration…") { pasteText = ""; showPaste = true }
                }
                EngineSettingRow(spec: Self.specs["wg.endpoint"], changed: !draft.endpoint.isEmpty) {
                    textField(Self.specs["wg.endpoint"], $draft.endpoint, prompt: "host:51820",
                              problem: endpointProblem)
                }
                problemLabel(endpointProblem)
                EngineSettingRow(spec: Self.specs["wg.listen-port"], changed: draft.listenPort != nil) {
                    ValidatedNumberField(
                        label: { EngineSettingLabel(spec: Self.specs["wg.listen-port"], changed: draft.listenPort != nil) },
                        prompt: "auto",
                        value: $draft.listenPort,
                        range: WireGuardConfig.listenPortRange,
                        invalidMessage: "Enter a port between 0 and 65535 — 0 lets the system choose one.")
                }
                if let port = draft.listenPort, WireGuardConfig.privilegedPortRange.contains(port) {
                    SettingCaveat("Ports below 1024 are reserved for system services, so \(port) can collide with something already on this Mac — and few networks forward it. WireGuard's own port is 51820; leave this empty to let the system choose.")
                }
            }

            Section("Sign-In") {
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
                        .accessibilityLabel("Set or replace the private key")
                        // Validation rides the field's value (Docs/Accessibility.md).
                        .accessibilityValue(privateKeyProblem.map { "Problem: \($0)" } ?? "")
                }
                problemLabel(privateKeyProblem)
                EngineSettingRow(spec: Self.specs["wg.public-key"], changed: !draft.peerPublicKey.isEmpty) {
                    monoField(Self.specs["wg.public-key"], $draft.peerPublicKey, prompt: "base64 public key",
                              problem: publicKeyProblem)
                }
                problemLabel(publicKeyProblem)
                EngineSettingRow(spec: Self.specs["wg.preshared-key"], changed: hasPresharedKey) {
                    presharedKeyRows
                }
                problemLabel(presharedKeyProblem)
            }

            Section("Traffic") {
                EngineSettingRow(spec: Self.specs["wg.address"], changed: !draft.addresses.isEmpty) {
                    listField(Self.specs["wg.address"], $draft.addresses, prompt: "10.0.0.2/32",
                              problem: addressProblem)
                }
                problemLabel(addressProblem)
                EngineSettingRow(spec: Self.specs["wg.allowed-ips"], changed: !draft.allowedIPs.isEmpty) {
                    listField(Self.specs["wg.allowed-ips"], $draft.allowedIPs, prompt: "0.0.0.0/0",
                              problem: allowedIPsProblem)
                }
                problemLabel(allowedIPsProblem)
                if draft.isFullTunnel {
                    Label("Full tunnel — all traffic routes through this peer.", systemImage: "globe")
                        .font(.callout).foregroundStyle(.secondary)
                }
                EngineSettingRow(spec: Self.specs["wg.dns"], changed: !draft.dns.isEmpty) {
                    listField(Self.specs["wg.dns"], $draft.dns, prompt: "1.1.1.1")
                }
                EngineSettingRow(spec: Self.specs["wg.mtu"], changed: draft.mtu != nil) {
                    ValidatedNumberField(
                        label: { EngineSettingLabel(spec: Self.specs["wg.mtu"], changed: draft.mtu != nil) },
                        prompt: "1420",
                        value: $draft.mtu,
                        range: WireGuardConfig.mtuRange,
                        invalidMessage: "Enter an MTU between 1280 and 1500. Below 1280 the tunnel can't carry IPv6 at all, and the engine would silently drop packets.")
                }
                EngineSettingRow(spec: Self.specs["wg.table"], changed: !draft.table.isEmpty) {
                    textField(Self.specs["wg.table"], $draft.table, prompt: "auto",
                              help: Self.exportOnlyHelp)
                }
            }

            Section("Advanced") {
                EngineSettingRow(spec: Self.specs["wg.keepalive"], changed: draft.persistentKeepalive != nil) {
                    ValidatedNumberField(
                        label: { EngineSettingLabel(spec: Self.specs["wg.keepalive"], changed: draft.persistentKeepalive != nil) },
                        prompt: "off",
                        value: $draft.persistentKeepalive,
                        range: WireGuardConfig.keepaliveRange,
                        invalidMessage: "Enter a number of seconds between 0 and 65535 — 0 turns keepalives off, 25 is typical behind NAT.")
                }
                EngineSettingRow(spec: Self.specs["wg.fwmark"], changed: !draft.fwMark.isEmpty) {
                    textField(Self.specs["wg.fwmark"], $draft.fwMark, prompt: "off",
                              help: Self.exportOnlyHelp)
                }
            }

            Section {
                Button("Export .conf…") { export() }
                    .disabled(draft.peerPublicKey.isEmpty || !hasPrivateKey)
            } footer: {
                Text(hasPrivateKey
                     ? "Export produces a standard wg-quick file for use with other WireGuard clients."
                     : "Set a private key above before exporting — wg-quick refuses a config without one.")
            }

            CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                proxyAuthUsername: $crProxyAuthUsername,
                                proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
                    .disabled(saveDisabledReason != nil)
                    // A dead Save must say why — hover AND VoiceOver (house rule).
                    .help(saveDisabledReason ?? "Save changes to this VPN")
                    .accessibilityValue(saveDisabledReason.map { "unavailable — \($0)" } ?? "")
            }
        }
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: [UTType(filenameExtension: "conf") ?? .data, .data, .plainText]) { result in
            if case let .success(url) = result { importConf(url) }
        }
        .sheet(isPresented: $showPaste) { pasteSheet }
    }

    /// The paste sheet: focus lands in the editor so a keyboard user can ⌘V at
    /// once, ESC cancels, and Import is the default action (Return only fires
    /// it once focus leaves the editor — inside it, Return types a newline).
    private var pasteSheet: some View {
        VStack(spacing: 12) {
            Text("Paste WireGuard configuration").font(.headline)
            TextEditor(text: $pasteText).font(.callout.monospaced()).frame(width: 460, height: 260)
                .border(.quaternary)
                .focused($pasteFocused)
                .accessibilityLabel("WireGuard configuration text")
            HStack {
                Button("Cancel") { showPaste = false }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import") { applyParsed(pasteText); showPaste = false }
                    .buttonStyle(.glassProminent).disabled(pasteText.isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .onAppear { pasteFocused = true }
    }

    // MARK: Pre-shared key (write-only, like the private key)

    /// Status + write-only entry for the pre-shared key. Never a plain
    /// TextField: rendering it would put a live symmetric key on screen (and in
    /// any screenshot) for a value nobody needs to read back.
    @ViewBuilder private var presharedKeyRows: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent {
                HStack(spacing: 8) {
                    Text(presharedKeyStatus).foregroundStyle(.secondary)
                    if !draft.presharedKey.isEmpty, !removePresharedKey {
                        Button("Remove") { removePresharedKey = true; newPresharedKey = "" }
                            .controlSize(.small)
                            .accessibilityLabel("Remove pre-shared key")
                    }
                }
            } label: {
                EngineSettingLabel(spec: Self.specs["wg.preshared-key"], changed: hasPresharedKey)
            }
            LabeledContent("Set / Replace Key") {
                SecureField("paste base64 pre-shared key", text: $newPresharedKey)
                    .font(.callout.monospaced())
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Set or replace the pre-shared key")
                    // Validation rides the field's value (Docs/Accessibility.md).
                    .accessibilityValue(presharedKeyProblem.map { "Problem: \($0)" } ?? "")
                    // Typing a replacement cancels a pending removal — the last
                    // thing the user did is the thing that happens.
                    .onChange(of: newPresharedKey) {
                        if !newPresharedKey.isEmpty { removePresharedKey = false }
                    }
            }
        }
    }

    /// Whether a pre-shared key will be in use after Save.
    private var hasPresharedKey: Bool {
        !newPresharedKey.isEmpty || (!draft.presharedKey.isEmpty && !removePresharedKey)
    }

    private var presharedKeyStatus: String {
        if !newPresharedKey.isEmpty { return "•••••• (saved on Save)" }
        if removePresharedKey { return "removed on Save" }
        return draft.presharedKey.isEmpty ? "not set" : "•••••• (in Keychain)"
    }

    // MARK: Inline problems (the editor is where a bad value must surface)
    //
    // `Shared/WireGuardConfig.swift` carries the tested validators — the same
    // ones the connect gate and the Go engine's parseRoutes agree on. Every one
    // of them is shown against its own row, so a misconfiguration is a caption
    // under the field rather than a failed connect ten seconds later.

    private var endpointProblem: String? {
        draft.endpoint.isEmpty ? nil : WireGuardConfig.endpointProblem(draft.endpoint)
    }
    private var publicKeyProblem: String? {
        WireGuardConfig.keyProblem(draft.peerPublicKey)
    }
    /// Validates what the user TYPES. The stored key is never read back into the
    /// UI (write-only field), so there is nothing else here to check.
    private var privateKeyProblem: String? {
        WireGuardConfig.keyProblem(newPrivateKey)
    }
    private var presharedKeyProblem: String? {
        WireGuardConfig.keyProblem(newPresharedKey)
    }
    /// Interface addresses, NOT routes: `10.0.0.2/24` is a valid tunnel address,
    /// so the host-bit check that belongs on Allowed IPs must not run here.
    private var addressProblem: String? {
        draft.addresses.isEmpty ? nil : WireGuardConfig.addressesProblem(draft.addresses)
    }
    private var allowedIPsProblem: String? {
        draft.allowedIPs.isEmpty ? nil : WireGuardConfig.routesProblem(draft.allowedIPs)
    }

    /// Why Save is unavailable, in the user's language, or nil when it can go.
    /// Was gated on an empty name alone, which let every validator above be
    /// written straight into providerConfiguration.
    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = endpointProblem { return p }
        if let p = publicKeyProblem { return p }
        if let p = privateKeyProblem { return p }
        if let p = presharedKeyProblem { return p }
        if let p = addressProblem { return p }
        if let p = allowedIPsProblem { return p }
        return nil
    }

    /// One amber caption for a field's problem, or nothing. Same shape as the
    /// control-URL problem in TailscaleView.
    @ViewBuilder private func problemLabel(_ problem: String?) -> some View {
        if let problem {
            Label(problem, systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
                .accessibilityLabel("Problem: \(problem)")
        }
    }

    // MARK: Spec catalog + typed field helpers

    static let specs = EngineSettingCatalog([
        .init(id: "wg.address", name: "Addresses",
              summary: "The in-tunnel IP address(es) this device is assigned, with prefix (e.g. 10.0.0.2/32). From your provider."),
        .init(id: "wg.dns", name: "DNS Servers",
              summary: "DNS servers to use while connected. Often points inside the tunnel so private names resolve."),
        .init(id: "wg.mtu", name: "MTU",
              summary: "Largest packet size on the tunnel, 1280–1500. Leave empty for the standard 1420; lower it (e.g. 1380) if some sites hang."),
        .init(id: "wg.listen-port", name: "Listen Port",
              summary: "UDP port WireGuard listens on locally, 0–65535. Leave empty (or 0) to let the system pick one."),
        .init(id: "wg.table", name: "Routing Table",
              summary: "“auto” installs routes for the allowed IPs; “off” installs none (you manage routing yourself). Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it."),
        .init(id: "wg.fwmark", name: "Firewall Mark",
              summary: "A firewall mark placed on the tunnel's own packets, for advanced policy routing. Rarely needed. Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it."),
        .init(id: "wg.public-key", name: "Peer Public Key",
              summary: "The server peer's public key (base64). Identifies and encrypts to the server. From your provider."),
        .init(id: "wg.endpoint", name: "Server Address",
              summary: "The server's public address and port, host:port (e.g. vpn.example.com:51820) — the Endpoint line of a wg-quick file."),
        .init(id: "wg.allowed-ips", name: "Allowed IPs",
              summary: "Which destinations go through this peer. 0.0.0.0/0, ::/0 sends everything (full tunnel); specific subnets make it split."),
        .init(id: "wg.preshared-key", name: "Pre-shared Key",
              summary: "Optional extra symmetric key (base64) added on top for post-quantum resistance. Only if your provider gives you one."),
        .init(id: "wg.keepalive", name: "Persistent Keepalive",
              summary: "Seconds between keepalive packets to hold the tunnel open through NAT/firewalls, 0–65535. 25 is typical behind NAT; empty or 0 = off."),
    ])

    /// `wg.table` and `wg.fwmark` never reach our engine — `WireGuardStartConfig`
    /// has no such fields — so they only round-trip into an exported .conf. Said
    /// on the row rather than left to look effective.
    static let exportOnlyHelp =
        "Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it."

    private func textField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String,
                           problem: String? = nil, help: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding).multilineTextAlignment(.trailing).autocorrectionDisabled()
                // The title is an EXAMPLE value — the spec name is the name.
                .accessibilityLabel(spec.name)
                // Validation rides the field's value (Docs/Accessibility.md).
                .accessibilityValue(problem.map { "\(binding.wrappedValue). Problem: \($0)" } ?? binding.wrappedValue)
                .help(help ?? spec.summary)
        } label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }
    private func monoField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String,
                           problem: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding).font(.callout.monospaced()).multilineTextAlignment(.trailing).autocorrectionDisabled()
                .accessibilityLabel(spec.name)
                .accessibilityValue(problem.map { "Problem: \($0)" } ?? "")
        } label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }
    private func listField(_ spec: EngineSettingSpec, _ binding: Binding<[String]>, prompt: String,
                           problem: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: Binding(
                get: { binding.wrappedValue.joined(separator: ", ") },
                set: { binding.wrappedValue = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
                .multilineTextAlignment(.trailing).autocorrectionDisabled()
                .accessibilityLabel(spec.name)
                .accessibilityValue(problem.map { "\(binding.wrappedValue.joined(separator: ", ")). Problem: \($0)" }
                                    ?? binding.wrappedValue.joined(separator: ", "))
        } label: { EngineSettingLabel(spec: spec, changed: !binding.wrappedValue.isEmpty) }
    }

    /// Whether a private key is available for export — either already in the
    /// keychain (loaded into `draft` below) or freshly typed and not yet saved.
    private var hasPrivateKey: Bool { !draft.privateKey.isEmpty || !newPrivateKey.isEmpty }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        // The persisted blob is redacted; the keys come back from the keychain
        // (the "wg.<id>" item VPNController+WireGuard maintains) so the export
        // works and the private-key row can say "set".
        draft = vpn.wireGuardConfig(for: profileID).withSecretsFromKeychain()
        if draft.name.isEmpty { draft.name = vpn.displayName(for: profileID) }
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
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
        next.id = profileID                      // keep identity
        if name == nil { next.name = draft.name }
        draft = next
    }

    private func save() {
        if !newPrivateKey.isEmpty {
            draft.privateKey = newPrivateKey
            newPrivateKey = ""
        }
        // Same for the pre-shared key, plus the explicit removal: an emptied
        // value is passed on (not nil), so clearing really clears the keychain
        // item instead of leaving the old key stored and still in use.
        if !newPresharedKey.isEmpty {
            draft.presharedKey = newPresharedKey
            newPresharedKey = ""
        } else if removePresharedKey {
            draft.presharedKey = ""
        }
        removePresharedKey = false
        // The keys go to the keychain; only a redacted copy is persisted —
        // the same move on every save path. The private key is nil (leave
        // alone) unless something set it: typing in the write-only field, or
        // an import that carried one.
        vpn.setWireGuardSecrets(privateKey: draft.privateKey.isEmpty ? nil : draft.privateKey,
                                presharedKey: draft.presharedKey,
                                for: profileID)
        // Fire-and-forget: save() is called synchronously from a plain Button
        // action; both persists are idempotent, and CustomRoutingTabView's own
        // onDisappear covers the case where the view closes before this lands.
        let toSave = draft
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            do { try await vpn.setWireGuardConfig(toSave, for: profileID) }
            catch { vpn.lastError = error.localizedDescription }
            customRouting = await commitCustomRouting(vpn, profileID: profileID, profile: toCommit,
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
        // Export what Save would store — including an unsaved replacement or
        // removal of the pre-shared key.
        if !newPresharedKey.isEmpty { toExport.presharedKey = newPresharedKey }
        else if removePresharedKey { toExport.presharedKey = "" }
        try? toExport.serialize().write(to: url, atomically: true, encoding: .utf8)
    }
}
