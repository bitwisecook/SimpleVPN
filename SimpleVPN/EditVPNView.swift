// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EditVPNView.swift
//  Liquid Glass edit sheet for a single VPN entry: name, logo, labels, credentials,
//  and the raw .ovpn. Presented from the management window for add/edit.
//

import SwiftUI
import CoreGraphics

struct EditVPNView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore
    let profileID: String

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var ovpn = ""
    @State private var username = ""
    @State private var password = ""
    @State private var remember = true
    @State private var logo: CGImage?
    @State private var showLogoImporter = false
    @State private var loaded = false
    @State private var saving = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") { TextField("Name", text: $name) }

                Section("Logo") {
                    HStack(spacing: 14) {
                        LogoWell(image: logo, pick: { showLogoImporter = true }, drop: { importLogoFile($0) })
                        VStack(alignment: .leading, spacing: 6) {
                            Button("Choose Image…") { showLogoImporter = true }
                            if logo != nil { Button("Remove", role: .destructive) { LogoStore.delete(profileID); logo = nil } }
                        }
                    }
                }

                Section("Labels") {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(labels.labels) { l in
                                LabelChip(label: l, on: labels.isAssigned(l, to: profileID)) { labels.toggle(l, for: profileID) }
                            }
                        }.padding(.vertical, 2)
                    }
                }

                Section("Credentials") {
                    TextField("Username", text: $username).textContentType(.username)
                    SecureField("Password", text: $password).textContentType(.password)
                    Toggle("Remember password", isOn: $remember)
                }

                Section("Configuration (.ovpn)") {
                    TextEditor(text: $ovpn)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 140)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Edit VPN")
            .task { load() }
            .fileImporter(isPresented: $showLogoImporter, allowedContentTypes: [.image], onCompletion: importLogo)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { saveButton }
            }
        }
        .frame(width: 480, height: 620)
        .disabled(saving)
    }

    @ViewBuilder private var saveButton: some View {
        if #available(macOS 26, *) {
            Button("Save") { Task { await save() } }.buttonStyle(.glassProminent).disabled(name.isEmpty)
        } else {
            Button("Save") { Task { await save() } }.buttonStyle(.borderedProminent).disabled(name.isEmpty)
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        name = vpn.profiles.first { $0.id == profileID }?.name ?? ""
        ovpn = vpn.ovpnText(id: profileID) ?? ""
        logo = LogoStore.load(profileID)
        if let c = vpn.savedCredentials(id: profileID) { username = c.username; password = c.password }
    }

    private func save() async {
        saving = true; defer { saving = false }
        if !name.isEmpty { try? await vpn.rename(id: profileID, to: name) }
        let server = UI.parseRemote(ovpn) ?? name
        try? await vpn.updateOVPN(id: profileID, ovpn: ovpn, server: server)
        if remember && !username.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: profileID, .init(username: username, password: password))
        } else if !remember {
            KeychainCredentialStore.deleteCredentials(profile: profileID)
        }
        dismiss()
    }

    private func importLogo(_ result: Result<URL, Error>) { if case let .success(u) = result { importLogoFile(u) } }
    private func importLogoFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if LogoStore.save(fromFile: url, id: profileID) { logo = LogoStore.load(profileID) }
        else { vpn.lastError = "Could not read image" }
    }
}
