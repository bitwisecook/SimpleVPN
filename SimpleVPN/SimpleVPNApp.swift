// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SimpleVPNApp.swift
//  Three surfaces per the Apple HIG:
//   • main window  — connection only (ConnectionView)
//   • Manage VPNs  — dedicated management pane (ManageVPNsView)
//   • Settings     — ⌘, / SimpleVPN ▸ Settings, global config (SettingsView)
//  Plus a window-style menu-bar extra for quick connect/disconnect.
//

import SwiftUI
import AppKit

@main
struct SimpleVPNApp: App {
    @State private var vpn = VPNController()
    @State private var labels = LabelStore()
    @State private var ext = ExtensionController()

    var body: some Scene {
        WindowGroup("SimpleVPN", id: "main") {
            ConnectionView(vpn: vpn, ext: ext, labels: labels)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}   // no document "New"
            VPNCommands(vpn: vpn)
        }

        Window("Manage VPNs", id: "manage") {
            ManageVPNsView(vpn: vpn, labels: labels)
        }
        .defaultSize(width: 560, height: 420)

        Settings {
            SettingsView(ext: ext, labels: labels)
        }

        MenuBarExtra("SimpleVPN", systemImage: vpn.menuBarSymbol) {
            MenuBarView(vpn: vpn, labels: labels)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Menu-bar commands: a VPN menu with Manage… (⌘M-adjacent) and Disconnect (⇧⌘K).
private struct VPNCommands: Commands {
    @Bindable var vpn: VPNController
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandMenu("VPN") {
            Button("Manage VPNs…") { openWindow(id: "manage") }
                .keyboardShortcut("m", modifiers: [.command, .shift])
            Divider()
            Button("Disconnect") { if let id = vpn.selectedID { vpn.disconnect(id: id) } }
                .keyboardShortcut("k", modifiers: [.command, .shift])
                .disabled(!(vpn.selected.map { UI.isActive($0.status) } ?? false))
        }
    }
}

/// Window-style menu-bar surface: a row per VPN (logo left only if *any* VPN has a logo,
/// labels right, connect/disconnect trailing), then Disconnect-all / open / manage / Quit.
private struct MenuBarView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow

    private var anyLogo: Bool { vpn.profiles.contains { LogoStore.exists($0.id) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("SimpleVPN").font(.headline).padding(.horizontal, 10).padding(.top, 8).padding(.bottom, 4)

            if vpn.profiles.isEmpty {
                Text("No VPNs configured")
                    .foregroundStyle(.secondary).font(.callout)
                    .padding(.horizontal, 10).padding(.vertical, 4)
            } else {
                ForEach(vpn.profiles) { row($0) }
            }

            Divider().padding(.vertical, 4)

            if vpn.anyConnected {
                menuButton("Disconnect All", systemImage: "xmark.shield") {
                    for p in vpn.profiles where UI.isActive(p.status) { vpn.disconnect(id: p.id) }
                }
            }
            menuButton("Open SimpleVPN", systemImage: "macwindow") { openWindow(id: "main") }
            menuButton("Manage VPNs…", systemImage: "slider.horizontal.3") { openWindow(id: "manage") }

            Divider().padding(.vertical, 4)

            menuButton("Quit SimpleVPN", systemImage: "power") { NSApplication.shared.terminate(nil) }
        }
        .padding(.bottom, 8)
        .frame(width: 300)
    }

    @ViewBuilder private func row(_ p: VPNController.Profile) -> some View {
        HStack(spacing: 8) {
            if anyLogo { LogoBadge(id: p.id, status: p.status) }
            else { Circle().fill(UI.color(p.status)).frame(width: 8, height: 8) }
            Text(p.name).lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 6)
            ForEach(labels.labels(for: p.id)) { LabelPill(label: $0) }
            trailingControl(p)
        }
        .padding(.horizontal, 10).padding(.vertical, 3)
    }

    @ViewBuilder private func trailingControl(_ p: VPNController.Profile) -> some View {
        if UI.isActive(p.status) {
            Button { vpn.disconnect(id: p.id) } label: { Image(systemName: "stop.circle.fill") }
                .buttonStyle(.borderless).help("Disconnect")
        } else {
            Button { vpn.selectedID = p.id; openWindow(id: "main") } label: { Image(systemName: "arrow.right.circle") }
                .buttonStyle(.borderless).help("Connect…")
        }
    }

    private func menuButton(_ title: String, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage).frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10).padding(.vertical, 3)
        .contentShape(Rectangle())
    }
}
