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
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var vpn = VPNController()
    @State private var labels = LabelStore()
    @State private var ext = ExtensionController()
    @State private var evaluator = ProfileEvaluator()
    @State private var policy = PolicyStore()
    @State private var manualRouter = ManualRouter()
    @State private var publicIP = PublicIPMonitor()
    @State private var endpointLocator = EndpointLocator()
    @State private var topology = TopologyMonitor()
    @State private var compositions = CompositionStore()
    @State private var tunnels = SubprocessTunnelStore()
    @State private var tunnelManager = SubprocessTunnelManager()
    @State private var nativeVPN = NativeVPNManager()
    @State private var wireguard = WireGuardStore()
    @State private var reachability = ReachabilityMonitor()
    /// One derivation of "what is this connection doing", shared by every surface.
    @State private var linkState: LinkStateMonitor

    init() {
        // First thing: make an AppKit exception crash nameable (the .ips drops the
        // reason string, so without this a display-cycle crash is undiagnosable).
        CrashDiagnostics.install()
        // linkState derives from the two stores, so it's built once here rather than
        // re-derived per surface (which is how the old per-view copies drifted).
        let vpn = VPNController()
        let reach = ReachabilityMonitor()
        _vpn = State(initialValue: vpn)
        _reachability = State(initialValue: reach)
        _linkState = State(initialValue: LinkStateMonitor(vpn: vpn, reach: reach))
    }

    var body: some Scene {
        WindowGroup("SimpleVPN", id: "main") {
            ConnectionView(vpn: vpn, ext: ext, labels: labels)
                .environment(evaluator)
                .environment(policy)
                .environment(manualRouter)
                .environment(publicIP)
                .environment(endpointLocator)
                .environment(topology)
                .environment(compositions)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
                .onChange(of: appDelegate.openBuffer.generation) {
                    // Finder double-click / Dock drop → the shared import pipeline.
                    vpn.handleImport(of: appDelegate.openBuffer.take())
                }
                .task {
                    // Home (pre-VPN) vs egress (while connected) hinges on this.
                    PublicIPMonitor.isVPNActive = { [weak vpn] in vpn?.anyConnected ?? false }
                    publicIP.startMonitoring()          // launch + every ~5 min
                    // Wire the no-save (auth-nocache) policy at launch, before ANY
                    // surface — including the menu bar — can connect or persist
                    // credentials. Previously this was set lazily on the first
                    // main-window Connect, so menu-bar credential entry could save a
                    // password the profile forbids saving.
                    vpn.allowsPasswordSaveEvaluator = { [weak vpn, weak evaluator] id in
                        guard let vpn, let evaluator, let text = vpn.ovpnText(id: id) else { return true }
                        return evaluator.evaluation(for: text).allowPasswordSave
                    }
                }
                .task { GeoIP.warm() }                 // parse the ~10 MB DB off-main
        }
        .commands {
            CommandGroup(replacing: .newItem) {}   // no document "New"
            VPNCommands(vpn: vpn)
            DiagnosticsCommands(vpn: vpn, tunnels: tunnels)
        }

        Window("About SimpleVPN", id: "about") {
            // Injected so "Report an Issue" can quote the extension version and the
            // configured VPN *types* (counts only — see IssueReport).
            AboutView()
                .environment(vpn)
                .environment(tunnels)
                .environment(nativeVPN)
                .environment(wireguard)
        }
        .windowResizability(.contentSize)

        Window("VPN Sign-In", id: "sso") {
            SSOAuthWindowView()
        }
        .defaultSize(width: 520, height: 680)
        .windowResizability(.contentSize)

        Window("Routes", id: "routes") {
            RouteGraphView(vpn: vpn)
                .environment(topology)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
        }
        .defaultSize(width: 1000, height: 700)

        Window("Network Tools", id: "tools") {
            NetworkToolsView(vpn: vpn)
                .environment(publicIP)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
                .environment(topology)
        }
        .defaultSize(width: 680, height: 680)

        Window("Manage VPNs", id: "manage") {
            ManageVPNsView(vpn: vpn, labels: labels)
                .environment(evaluator)
                .environment(policy)
                .environment(manualRouter)
                .environment(compositions)
                .environment(tunnels)
                .environment(tunnelManager)
                .environment(nativeVPN)
                .environment(wireguard)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
        }
        .defaultSize(width: 560, height: 420)

        Window("SimpleVPN Help", id: "manual") {
            ManualWindow()
                .environment(manualRouter)
        }
        .defaultSize(width: 720, height: 640)

        Settings {
            SettingsView(ext: ext, labels: labels)
                .environment(publicIP)
        }

        MenuBarExtra {
            MenuBarView(vpn: vpn, labels: labels)
                .environment(publicIP)
                .environment(endpointLocator)
                .environment(topology)
                .environment(compositions)
                .environment(tunnels)
                .environment(tunnelManager)
                .environment(nativeVPN)
                .environment(wireguard)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
        } label: {
            MenuBarLabel(vpn: vpn, reachability: reachability,
                         tunnelManager: tunnelManager, nativeVPN: nativeVPN)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Receives Finder/Dock file-open events (the .ovpn document type) and buffers
/// them for the main window to import; brings the app forward so the outcome
/// is visible. Also owns two launch safety nets (see below).
final class AppDelegate: NSObject, NSApplicationDelegate, ObservableObject {

    @Observable
    final class FileOpenBuffer {
        private(set) var generation = 0
        private var urls: [URL] = []
        func add(_ new: [URL]) { urls.append(contentsOf: new); generation += 1 }
        func take() -> [URL] { defer { urls.removeAll() }; return urls }
    }

    let openBuffer = FileOpenBuffer()

    func application(_ application: NSApplication, open urls: [URL]) {
        // simplevpn-sso:// URLs are SAML sign-in hand-offs for the in-app webview;
        // everything else is a .ovpn file open for the import pipeline.
        let sso = urls.filter { $0.scheme == "simplevpn-sso" }
        for u in sso { handleSSO(u) }
        let files = urls.filter { $0.scheme != "simplevpn-sso" }
        if !files.isEmpty { openBuffer.add(files) }
        NSApp.activate()
    }

    private func handleSSO(_ url: URL) {
        // simplevpn-sso://auth?u=<base64url of the real sign-in URL>
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let u = comps.queryItems?.first(where: { $0.name == "u" })?.value,
              let data = Data(base64URLEncoded: u),
              let s = String(data: data, encoding: .utf8),
              let target = URL(string: s) else { return }
        Task { @MainActor in SSOAuthModel.shared.request(target) }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Invalid launch (e.g. run straight from a DMG/quarantine → App Translocation):
        // the system extension and keychain group can't work from a randomized path.
        // Tell the user plainly and quit normally instead of misbehaving.
        if Bundle.main.bundlePath.contains("/AppTranslocation/") {
            let alert = NSAlert()
            alert.messageText = "Move SimpleVPN to Applications"
            alert.informativeText = "SimpleVPN is running from a temporary location and can't manage VPNs from here. Move SimpleVPN.app to the Applications folder and open it again."
            alert.alertStyle = .critical
            alert.addButton(withTitle: "Quit")
            alert.runModal()
            NSApp.terminate(nil)
            return
        }

        // Window-restoration safety net: macOS restores windows onto the display they
        // were last on. If that display identifier no longer exists ("invalid display
        // identifier" in SkyLight), the window is technically visible but appears
        // nowhere. Sweep restored windows and pull any screenless one back on-screen.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            for window in NSApp.windows
            where window.styleMask.contains(.titled) && window.isVisible && window.screen == nil {
                window.center()
                window.makeKeyAndOrderFront(nil)
            }
        }
    }
}

/// Menu-bar commands: a VPN menu with Manage… (⌘M-adjacent) and Disconnect (⇧⌘K).
private struct VPNCommands: Commands {
    @Bindable var vpn: VPNController
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About SimpleVPN") { openWindow(id: "about") }
        }
        CommandMenu("VPN") {
            Button("Import Configuration…") {
                openWindow(id: "main")
                vpn.importRequested = true       // ConnectionView presents the file panel
            }
            .keyboardShortcut("o", modifiers: [.command])
            Button("Manage VPNs…") { openWindow(id: "manage") }
                .keyboardShortcut("m", modifiers: [.command, .shift])
            Button("Network Tools…") { openWindow(id: "tools") }
                .keyboardShortcut("t", modifiers: [.command, .shift])
            Button("Routes…") { openWindow(id: "routes") }
                .keyboardShortcut("r", modifiers: [.command, .shift])
            Divider()
            Button("Disconnect") { if let id = vpn.selectedID { vpn.disconnect(id: id) } }
                .keyboardShortcut("k", modifiers: [.command, .shift])
                .disabled(!(vpn.selected.map { UI.isActive($0.status) } ?? false))
        }
    }
}

// MenuBarView / MenuBarLabel live in MenuBarView.swift.
