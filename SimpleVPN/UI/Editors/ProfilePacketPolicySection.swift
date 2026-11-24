// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

struct ProfilePacketPolicySection: View {
    let vpn: VPNController
    let source: String?
    let adapter: String?
    let save: (String?) async throws -> Void
    @State private var editing = false

    private var spec: EngineSettingSpec { CustomRoutingSettings.catalog["cr.packet-events"] }

    var body: some View {
        Section {
            EngineSettingRow(spec: spec, value: source ?? "",
                             disabledReason: adapter == nil && source == nil ? "Traffic event handlers require a built-in packet tunnel or the built-in SSH forwarding engine." : nil) {
                LabeledContent {
                    Button(source == nil ? "Add Handlers…" : "Edit Handlers…") { editing = true }
                        .accessibilityLabel(source == nil ? "Add traffic event handlers" : "Edit traffic event handlers")
                } label: { EngineSettingLabel(spec: spec, value: source ?? "") }
            }
        }
        .sheet(isPresented: $editing) {
            ProfilePacketPolicyEditor(vpn: vpn, original: source, adapter: adapter, save: save)
        }
    }
}

private struct ProfilePacketPolicyEditor: View {
    @Environment(\.dismiss) private var dismiss
    let original: String?
    let vpn: VPNController
    let adapter: String?
    let save: (String?) async throws -> Void
    @State private var draft: String
    @State private var saving = false
    @State private var diagnostic: String?

    init(vpn: VPNController, original: String?, adapter: String?, save: @escaping (String?) async throws -> Void) {
        self.vpn = vpn
        self.original = original
        self.adapter = adapter
        self.save = save
        _draft = State(initialValue: original ?? "")
    }

    private var source: String? { draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : draft }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Traffic Event Handlers").font(.headline)
            Text(adapter == "ssh-openssh-reverse" ? "This mode uses explicit profile options and ignores ssh_config. It checks each reverse delivery after OpenSSH opens the channel and before dialing the local service."
                 : adapter?.hasPrefix("ssh-") == true
                 ? "Check each request to open an SSH forwarding channel. Saved handlers take effect at the next connection."
                 : adapter == nil ? ProfilePacketPolicy.unsupported : "Check packets carried by this VPN. Saved handlers take effect at the next connection.")
                .fixedSize(horizontal: false, vertical: true)
            if draft.isEmpty && adapter != nil {
                ConfigSourceLabel(text: adapter == "ssh-libssh" || adapter == "ssh-openssh"
                                  ? "on permit: ssh.forward_open { if ssh.port == 25 { drop(); } }"
                                  : adapter == "ssh-openssh-reverse" ? "on permit: ssh.reverse_delivery { if ssh.port == 25 { drop(); } }"
                                  : "on observe: ip.packet { count(); }", format: .routingEvents)
            }
            if let adapter {
                RoutingSourceEditor(vpn: vpn, text: $draft, adapter: adapter, accessibilityLabel: "Traffic event handler code")
                    .frame(minWidth: 380, minHeight: 150)
            } else {
                ConfigurationSourceText(text: $draft, format: .routingEvents, accessibilityLabel: "Traffic event handler code")
                    .frame(minWidth: 380, minHeight: 150)
            }
            if source == nil && original != nil { Text("Saving removes the handlers from this VPN.") }
            if let diagnostic {
                Label(diagnostic, systemImage: "exclamationmark.triangle")
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    let submitted = source
                    saving = true
                    Task {
                        defer { saving = false }
                        do { try await save(submitted); dismiss() }
                        catch { diagnostic = error.localizedDescription }
                    }
                }
                .keyboardShortcut("s", modifiers: .command)
                .disabled(source == original || (source != nil && adapter == nil))
            }
        }
        .padding(20)
        .frame(idealWidth: adapter == nil ? 560 : 720, idealHeight: adapter == nil ? 335 : 620)
        .disabled(saving)
        .interactiveDismissDisabled(saving)
    }
}
