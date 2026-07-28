// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ManageVPNsView.swift
//  Dedicated VPN-management window: create / import / edit / remove / export.
//  Uses the standard macOS list-management idiom (+ menu, − / Edit toolbar, context menu).
//

import SwiftUI
import UniformTypeIdentifiers

struct ManageVPNsView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore

    @State private var selection: String?
    @State private var showImporter = false
    @State private var editing: EditTarget?
    @State private var exportDoc: OVPNDocument?
    @State private var exportName = "config"
    @State private var showExporter = false

    struct EditTarget: Identifiable { let id: String }

    var body: some View {
        List(selection: $selection) {
            ForEach(vpn.profiles) { p in
                VPNRow(profile: p, labelDefs: labels.labels(for: p.id))
                    .tag(p.id)
                    .contextMenu {
                        Button("Edit…") { editing = .init(id: p.id) }
                        Button("Export .ovpn…") { export(p) }
                        Button("Remove", role: .destructive) { Task { try? await vpn.remove(id: p.id) } }
                    }
            }
        }
        .frame(minWidth: 520, minHeight: 380)
        .navigationTitle("Manage VPNs")
        .overlay {
            if vpn.profiles.isEmpty {
                ContentUnavailableView("No VPNs", systemImage: "network.slash",
                                       description: Text("Use + to import a configuration or add a new VPN."))
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    Button("Import .ovpn…") { showImporter = true }
                    Button("New Empty VPN") { Task { await newEmpty() } }
                } label: { Image(systemName: "plus") }
                    .help("Add a VPN")
                Button { if let id = selection { editing = .init(id: id) } } label: { Image(systemName: "pencil") }
                    .disabled(selection == nil).help("Edit")
                Button { if let id = selection { Task { try? await vpn.remove(id: id) } } } label: { Image(systemName: "minus") }
                    .disabled(selection == nil).help("Remove")
            }
        }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [UI.ovpnType, .data, .plainText], onCompletion: importConfig)
        .fileExporter(isPresented: $showExporter, document: exportDoc, contentType: UI.ovpnType, defaultFilename: exportName + ".ovpn") { _ in }
        .sheet(item: $editing) { t in EditVPNView(vpn: vpn, labels: labels, profileID: t.id) }
        .task { await vpn.loadAll() }
    }

    private func importConfig(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { vpn.lastError = "Could not read \(url.lastPathComponent)"; return }
        let name = url.deletingPathExtension().lastPathComponent
        let server = UI.parseRemote(text) ?? name
        Task {
            do { let id = try await vpn.importProfile(name: name, ovpn: text, server: server); editing = .init(id: id) }
            catch { vpn.lastError = error.localizedDescription }
        }
    }

    private func newEmpty() async {
        do { let id = try await vpn.importProfile(name: "New VPN", ovpn: "", server: ""); editing = .init(id: id) }
        catch { vpn.lastError = error.localizedDescription }
    }

    private func export(_ p: VPNController.Profile) {
        guard let text = vpn.ovpnText(id: p.id) else { vpn.lastError = "No configuration to export"; return }
        exportDoc = OVPNDocument(text: text); exportName = p.name; showExporter = true
    }
}
