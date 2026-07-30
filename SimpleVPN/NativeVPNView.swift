// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNView.swift
//  Editor + control for the OS-native personal VPN kinds (IKEv2, IPsec). macOS
//  runs these itself via NEVPNManager — one at a time (singleton). L2TP has no
//  programmatic API, so it's offered as a downloadable configuration profile.
//

import SwiftUI
import NetworkExtension

struct NativeVPNView: View {
    @Bindable var manager: NativeVPNManager
    @State var draft: NativeVPNConfig
    @State private var secret = ""
    @State private var loaded = false

    private var isActive: Bool {
        manager.activeConfigID == draft.id &&
        (manager.status == .connected || manager.status == .connecting || manager.status == .reasserting)
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.name)
                Picker("Protocol", selection: $draft.kind) {
                    Text("IKEv2").tag(VPNKind.ikev2)
                    Text("IPsec (IKEv1)").tag(VPNKind.ipsec)
                    Text("L2TP / IPsec").tag(VPNKind.l2tp)
                }
            }

            if draft.kind == .l2tp {
                l2tpSection
            } else {
                serverSection
                authSection
                if draft.kind == .ikev2 { ikev2AdvancedSection }
                routingSection
                controlSection
            }
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
                    .disabled(draft.name.isEmpty || draft.server.isEmpty)
            }
        }
    }

    @ViewBuilder private var serverSection: some View {
        Section("Server") {
            TextField("Server address", text: $draft.server, prompt: Text("vpn.example.com")).autocorrectionDisabled()
            if draft.kind == .ikev2 {
                TextField("Remote identifier (optional)", text: $draft.remoteID,
                          prompt: Text("defaults to the server address"))
            }
            if draft.kind == .ipsec {
                TextField("Group / local identifier (optional)", text: $draft.groupOrRealm)
            }
        }
    }

    @ViewBuilder private var authSection: some View {
        Section("Authentication") {
            Toggle("Use a shared secret (PSK)", isOn: $draft.usesSharedSecret)
            if !draft.usesSharedSecret {
                TextField("Username", text: $draft.username).textContentType(.username)
            }
            SecureField(draft.usesSharedSecret ? "Shared secret" : "Password", text: $secret)
            Toggle("Connect on demand", isOn: $draft.onDemand)
        }
    }

    @ViewBuilder private var routingSection: some View {
        Section("Routing") {
            EngineSettingRow(spec: Self.specs["native.include-all"], changed: draft.includeAllNetworks) {
                Toggle(isOn: $draft.includeAllNetworks) { EngineSettingLabel(spec: Self.specs["native.include-all"], changed: draft.includeAllNetworks) }
            }
            if draft.includeAllNetworks {
                EngineSettingRow(spec: Self.specs["native.exclude-local"], changed: !draft.excludeLocalNetworks) {
                    Toggle(isOn: $draft.excludeLocalNetworks) { EngineSettingLabel(spec: Self.specs["native.exclude-local"], changed: !draft.excludeLocalNetworks) }
                }
            }
            EngineSettingRow(spec: Self.specs["native.disconnect-sleep"], changed: draft.disconnectOnSleep) {
                Toggle(isOn: $draft.disconnectOnSleep) { EngineSettingLabel(spec: Self.specs["native.disconnect-sleep"], changed: draft.disconnectOnSleep) }
            }
        }
    }

    @ViewBuilder private var ikev2AdvancedSection: some View {
        Section {
            DisclosureGroup("Advanced (IKEv2)") {
                enumRow("native.encryption", $draft.ikeEncryption, [
                    ("", "Automatic"), ("aes256gcm", "AES-256-GCM"), ("aes128gcm", "AES-128-GCM"),
                    ("aes256", "AES-256-CBC"), ("aes128", "AES-128-CBC"), ("chacha20poly1305", "ChaCha20-Poly1305")])
                enumRow("native.integrity", $draft.ikeIntegrity, [
                    ("", "Automatic"), ("sha256", "SHA2-256"), ("sha384", "SHA2-384"), ("sha512", "SHA2-512")])
                enumRow("native.dh-group", $draft.ikeDHGroup, [
                    ("", "Automatic"), ("14", "Group 14 (2048-bit)"), ("15", "Group 15 (3072-bit)"),
                    ("16", "Group 16 (4096-bit)"), ("19", "Group 19 (P-256)"), ("20", "Group 20 (P-384)"),
                    ("21", "Group 21 (P-521)"), ("31", "Group 31 (Curve25519)")])
                enumRow("native.dpd", $draft.deadPeerDetection, [
                    ("", "Default"), ("none", "Off"), ("low", "Low"), ("medium", "Medium"), ("high", "High")])
                EngineSettingRow(spec: Self.specs["native.pfs"], changed: draft.enablePFS) {
                    Toggle(isOn: $draft.enablePFS) { EngineSettingLabel(spec: Self.specs["native.pfs"], changed: draft.enablePFS) }
                }
                EngineSettingRow(spec: Self.specs["native.mobike"], changed: draft.disableMOBIKE) {
                    Toggle(isOn: $draft.disableMOBIKE) { EngineSettingLabel(spec: Self.specs["native.mobike"], changed: draft.disableMOBIKE) }
                }
            }
        }
    }

    static let specs = EngineSettingCatalog([
        .init(id: "native.encryption", name: "Encryption",
              summary: "The cipher for the IKE/child security associations. Leave Automatic unless your admin specifies one; AES-256-GCM is a strong modern default."),
        .init(id: "native.integrity", name: "Integrity / PRF",
              summary: "The hash protecting message integrity. Automatic is fine for most servers."),
        .init(id: "native.dh-group", name: "Diffie-Hellman Group",
              summary: "The key-exchange group. Higher numbers are stronger; 19–21 are elliptic-curve. Must match what the server offers."),
        .init(id: "native.dpd", name: "Dead Peer Detection",
              summary: "How aggressively to probe whether the server is still there, to notice a dropped tunnel. Higher = faster detection, more chatter."),
        .init(id: "native.pfs", name: "Perfect Forward Secrecy",
              summary: "Rekey the data channel with a fresh key exchange so a stolen key can't decrypt past traffic. Enable if the server requires it."),
        .init(id: "native.mobike", name: "Disable MOBIKE",
              summary: "MOBIKE lets the tunnel survive network changes (Wi-Fi ↔ Ethernet). Only disable it if a picky server misbehaves with it on."),
        .init(id: "native.include-all", name: "Send All Traffic",
              summary: "Route everything through the VPN (full tunnel). Off means only the server's routes go through it."),
        .init(id: "native.exclude-local", name: "Allow Local Network",
              summary: "While sending all traffic through the VPN, still let your local network (printers, file shares) stay reachable."),
        .init(id: "native.disconnect-sleep", name: "Disconnect on Sleep",
              summary: "Drop the VPN when the Mac sleeps instead of resuming it on wake. Off keeps it up across sleep."),
    ])

    private func enumRow(_ id: String, _ binding: Binding<String>, _ options: [(String, String)]) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty) {
            Picker(selection: binding) {
                ForEach(options, id: \.0) { Text($0.1).tag($0.0) }
            } label: { EngineSettingLabel(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty) }
        }
    }

    @ViewBuilder private var controlSection: some View {
        Section {
            if manager.needsEntitlement {
                Label("Native VPN needs the Personal VPN capability on this build's signing profile. Everything else works; ask to have it provisioned.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
            }
            HStack {
                nativeStatus
                Spacer()
                if isActive {
                    Button("Disconnect") { manager.disconnect() }.buttonStyle(.bordered).tint(.red)
                } else {
                    Button("Connect") { save(); Task { await manager.connect(draft, secret: secret) } }
                        .buttonStyle(.glassProminent)   // primary "go" — consistent with OpenVPN Connect
                        .disabled(draft.server.isEmpty)
                }
            }
            if let err = manager.lastError {
                Text(err).font(.callout).foregroundStyle(.red)
            }
            Text("macOS runs one app-managed personal VPN at a time — connecting this one replaces any other native VPN this app started.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var nativeStatus: some View {
        switch manager.status {
        case .connected where isActive: Label("Connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .connecting where isActive: HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Connecting…") }
        default: Label("Disconnected", systemImage: "circle").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var l2tpSection: some View {
        Section("Server") {
            TextField("Server address", text: $draft.server).autocorrectionDisabled()
            TextField("Username", text: $draft.username).textContentType(.username)
            SecureField("Shared secret", text: $secret)
        }
        Section {
            Button("Export Configuration Profile…") { exportMobileconfig() }
                .disabled(draft.server.isEmpty)
        } footer: {
            Text("macOS has no programmatic L2TP API for apps. SimpleVPN writes a standard .mobileconfig you double-click to install; it then appears in System Settings ▸ VPN.")
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        secret = KeychainCredentialStore.loadCredentials(profile: "native.\(draft.id)")?.password ?? ""
    }

    private func save() {
        manager.save(draft)
        if !secret.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "native.\(draft.id)",
                                                         .init(username: draft.username, password: secret))
        }
    }

    private func exportMobileconfig() {
        save()
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(draft.name).mobileconfig"
        panel.allowedContentTypes = [.init(filenameExtension: "mobileconfig") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? NativeVPNProfile.l2tpMobileconfig(draft, secret: secret).write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Minimal, valid L2TP-over-IPsec .mobileconfig generator (PPP + IPSec payload).
enum NativeVPNProfile {
    static func l2tpMobileconfig(_ c: NativeVPNConfig, secret: String) -> String {
        let uuid = UUID().uuidString
        let payloadUUID = UUID().uuidString
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>PayloadDisplayName</key><string>\(c.name)</string>
          <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.\(uuid)</string>
          <key>PayloadType</key><string>Configuration</string>
          <key>PayloadUUID</key><string>\(uuid)</string>
          <key>PayloadVersion</key><integer>1</integer>
          <key>PayloadContent</key><array><dict>
            <key>PayloadType</key><string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.vpn.\(payloadUUID)</string>
            <key>PayloadUUID</key><string>\(payloadUUID)</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>UserDefinedName</key><string>\(c.name)</string>
            <key>VPNType</key><string>L2TP</string>
            <key>PPP</key><dict>
              <key>AuthName</key><string>\(c.username)</string>
              <key>CommRemoteAddress</key><string>\(c.server)</string>
            </dict>
            <key>IPSec</key><dict>
              <key>AuthenticationMethod</key><string>SharedSecret</string>
              <key>SharedSecret</key><data>\(Data(secret.utf8).base64EncodedString())</data>
            </dict>
          </dict></array>
        </dict></plist>
        """
    }
}
