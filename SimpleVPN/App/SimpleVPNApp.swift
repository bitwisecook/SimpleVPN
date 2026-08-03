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
import Sparkle

/// Settings keys: which of the app's two icons exist. Both default ON. The
/// Settings pane guards against turning both off (an invisible app).
let dockIconDefaultsKey = "ui.dockIcon"
let menuBarIconDefaultsKey = "ui.menuBarIcon"

/// Read a BOOL default that should be true when the key was never written
/// (UserDefaults.bool(forKey:) alone defaults to false).
func defaultsBool(_ key: String, initially: Bool) -> Bool {
    UserDefaults.standard.object(forKey: key) == nil ? initially : UserDefaults.standard.bool(forKey: key)
}

@main
struct SimpleVPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var vpn = VPNController()
    @State private var control: ControlPlaneDispatcher
    /// The CLI's socket (ControlServer): hosts the SAME dispatcher out-of-process.
    private let controlServer = ControlServer()
    @State private var labels = LabelStore()
    @State private var ext = ExtensionController()
    @State private var evaluator = ProfileEvaluator()
    @State private var policy = PolicyStore()
    @State private var manualRouter = ManualRouter()
    @State private var publicIP = PublicIPMonitor()
    @State private var endpointLocator = EndpointLocator()
    /// Endpoint speed measurements, shared so every server list agrees (and so a
    /// server is measured once, not once per surface).
    @State private var endpointProbes = EndpointProbeStore()
    @State private var topology = TopologyMonitor()
    @State private var compositions = CompositionStore()
    @State private var tunnels = SubprocessTunnelStore()
    @State private var tunnelManager = SubprocessTunnelManager()
    @State private var nativeVPN = NativeVPNManager()
    @State private var wireguard = WireGuardStore()
    @State private var reachability = ReachabilityMonitor()
    /// One derivation of "what is this connection doing", shared by every surface.
    @State private var linkState: LinkStateMonitor
    /// Sparkle. Automatic checks are OFF via Info.plist (SUEnableAutomaticChecks)
    /// until the Settings toggle turns them on, so starting the updater here
    /// neither phones out nor prompts — it only enables the manual menu check.
    private let updaterController = SPUStandardUpdaterController(
        startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
    /// Captured ONCE at launch: the menu-bar scene is included (or not) for
    /// the process lifetime. The obvious MenuBarExtra(isInserted:) API loops
    /// SwiftUI's menu builder on macOS 26 — makeMainMenu rebuilds forever, a
    /// permanent beachball at launch — so the toggle applies on next start
    /// instead (Settings says so). Do not "fix" this back to isInserted
    /// without profiling a launch.
    private let menuBarIconAtLaunch = defaultsBool(menuBarIconDefaultsKey, initially: true)

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
        // The control plane's one entry (UI, CLI, intents, future Tcl all route
        // through it) — built here so every surface shares the same instance.
        let dispatcher = ControlPlaneDispatcher(vpn: vpn)
        _control = State(initialValue: dispatcher)
        VPNIntentSupport.register(dispatcher)   // Shortcuts route through the same entry
    }

    var body: some Scene {
        WindowGroup("SimpleVPN", id: "main") {
            ConnectionView(vpn: vpn, ext: ext, labels: labels)
                .opensSSOWindow()
                .environment(control)
                .environment(evaluator)
                .environment(policy)
                .environment(manualRouter)
                .environment(publicIP)
                .environment(endpointLocator)
                .environment(endpointProbes)
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
                    // "Engaged", not "connected": the tunnel owns the default
                    // route before it says it is up.
                    PublicIPMonitor.isVPNActive = { [weak vpn] in vpn?.anyEngaged ?? false }
                    // No VPN is speed-checked through its own tunnel.
                    endpointProbes.isProfileEngaged = { [weak vpn] id in
                        vpn?.isEngaged(id: id) ?? false
                    }
                    publicIP.startMonitoring()          // launch + every ~5 min
                    controlServer.start(dispatcher: control)   // the CLI's socket
                    vpn.routes.startMonitoring()        // PF_ROUTE default-route drift watch
                    vpn.dns.startMonitoring()           // SCDynamicStore DNS drift watch
                    vpn.proxies.startMonitoring()       // SCDynamicStore proxy drift watch
                    appDelegate.quitHandler = { reply in handleQuit(reply) }
                    // Wire the no-save (auth-nocache) policy at launch, before ANY
                    // surface — including the menu bar — can connect or persist
                    // credentials. Previously this was set lazily on the first
                    // main-window Connect, so menu-bar credential entry could save a
                    // password the profile forbids saving.
                    vpn.allowsPasswordSaveEvaluator = { [weak vpn, weak evaluator] id in
                        guard let vpn, let evaluator, let text = vpn.ovpnText(id: id) else { return true }
                        return evaluator.evaluation(for: text).allowPasswordSave
                    }
                    // Same wiring for the full evaluation: the connect flow
                    // branches on autologin and static-challenge (see
                    // VPNController.profileEvaluationProvider).
                    vpn.profileEvaluationProvider = { [weak vpn, weak evaluator] id in
                        guard let vpn, let evaluator, let text = vpn.ovpnText(id: id) else { return nil }
                        return evaluator.evaluation(for: text)
                    }
                    // The shared import pipeline (main-window drop/Import, Finder
                    // open) sniffs a config's real kind before assuming OpenVPN;
                    // anything else routes here to the same stores ManageVPNsView's
                    // own importer already uses, so a WireGuard/Cisco file dropped
                    // on the main window no longer fails with an OpenVPN-only error.
                    vpn.otherEngineImportHandler = { [weak wireguard, weak tunnels, weak nativeVPN] kind, text, name in
                        switch kind {
                        case .wireGuard:
                            guard let wireguard else { return .invalid(reason: "WireGuard isn't available right now.") }
                            let c = WireGuardConfig.parse(text, name: name)
                            wireguard.save(c)
                            return .imported(profileID: c.id, name: c.name)
                        case .cisco:
                            guard let tunnels, let nativeVPN else {
                                return .invalid(reason: "Import isn't available right now.")
                            }
                            switch CiscoImport.parse(text, name: name) {
                            case .anyConnect(let configs):
                                for c in configs { tunnels.save(c) }
                                guard let first = configs.first else {
                                    return .invalid(reason: "That file isn't a recognisable Cisco AnyConnect profile.")
                                }
                                return .imported(profileID: first.id, name: first.name)
                            case .pcf(let config, let secret, _):
                                nativeVPN.save(config)
                                if let secret {
                                    try? KeychainCredentialStore.saveCredentials(
                                        profile: "native.\(config.id)",
                                        .init(username: config.username, password: secret))
                                }
                                return .imported(profileID: config.id, name: config.name)
                            case .unrecognized:
                                return .invalid(reason: "That file isn't a recognisable Cisco .pcf or AnyConnect XML profile.")
                            }
                        case .openVPN:
                            return .invalid(reason: "")   // unreachable — routeNonOpenVPN filters this out
                        }
                    }
                }
                .task { GeoIP.warm() }                 // parse the ~10 MB DB off-main
        }
        .commands {
            CommandGroup(replacing: .newItem) {}   // no document "New"
            VPNCommands(vpn: vpn, updater: updaterController)
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
        .commandsRemoved()

        Window("VPN Sign-In", id: "sso") {
            SSOAuthWindowView()
        }
        .defaultSize(width: 520, height: 680)
        .windowResizability(.contentSize)
        .commandsRemoved()

        Window("Routes", id: "routes") {
            RouteGraphView(vpn: vpn)
                .environment(topology)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
        }
        .defaultSize(width: 1000, height: 700)
        .commandsRemoved()

        Window("Network Tools", id: "tools") {
            NetworkToolsView(vpn: vpn)
                .environment(publicIP)
                .environment(reachability)
                .environment(linkState)
                .environment(ext)
                .environment(topology)
                // The staged check reads a saved VPN's own certificates, keys
                // and host-key settings, which live in these four stores.
                .environment(evaluator)
                .environment(tunnels)
                .environment(nativeVPN)
                .environment(wireguard)
        }
        .defaultSize(width: 680, height: 680)
        .commandsRemoved()

        Window("Manage VPNs", id: "manage") {
            ManageVPNsView(vpn: vpn, labels: labels)
                .opensSSOWindow()
                .environment(evaluator)
                .environment(endpointLocator)
                .environment(endpointProbes)
                .environment(publicIP)
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
        .commandsRemoved()

        Window("SimpleVPN Help", id: "manual") {
            ManualWindow()
                .environment(manualRouter)
        }
        .defaultSize(width: 720, height: 640)
        .commandsRemoved()

        Settings {
            SettingsView(ext: ext, labels: labels, updater: updaterController.updater)
                .environment(publicIP)
                .environment(endpointProbes)
        }

        menuBarScene
    }

    /// Included per the LAUNCH-TIME setting only, via a CONSTANT isInserted
    /// binding. Two dead ends first: a live @AppStorage binding sends macOS 26's
    /// menu builder into an infinite makeMainMenu loop (permanent beachball),
    /// and SceneBuilder has no `if` at all ("failed to produce diagnostic").
    /// A .constant binding gives the menu builder nothing reactive to cycle on.
    private var menuBarScene: some Scene {
        MenuBarExtra(isInserted: .constant(menuBarIconAtLaunch)) {
            MenuBarView(vpn: vpn, labels: labels)
                .environment(publicIP)
                .environment(endpointLocator)
                .environment(endpointProbes)
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
                // Menu-bar-only usage may never open the main window, so the
                // label (alive whenever the icon is) wires the quit gate too —
                // and watches for SSO sign-ins for the same reason.
                .task { appDelegate.quitHandler = { reply in handleQuit(reply) } }
                .opensSSOWindow()
        }
        .menuBarExtraStyle(.window)
    }

    /// The quit gate (see AppDelegate.applicationShouldTerminate): a tunnel
    /// lives in the system extension and would outlive the app, so quitting
    /// ALWAYS disconnects first — after a confirmation when apps demonstrably
    /// have live TCP connections riding the VPN (matched by their sockets'
    /// local address == the tunnel's in-tunnel address; named for humans).
    private func handleQuit(_ reply: @escaping (Bool) -> Void) {
        let active = vpn.profiles.filter { UI.isActive($0.status) }
        let nativeActive = nativeVPN.status == .connected || nativeVPN.status == .connecting
        guard !active.isEmpty || tunnelManager.hasActive || nativeActive else {
            reply(true); return
        }

        var tunnelAddrs: Set<String> = []
        for p in active {
            guard let s = reachability.stats(for: p.id) ?? TunnelStatsStore.read(profile: p.id) else { continue }
            if !s.tunnelIPv4.isEmpty { tunnelAddrs.insert(s.tunnelIPv4) }
            if let v6 = s.tunnelIPv6, !v6.isEmpty { tunnelAddrs.insert(v6) }
        }
        let apps = AppConnectionInspector.appsUsingTunnel(tunnelAddresses: tunnelAddrs)

        // Explicitly Void-returning: the reply is delivered from inside the task,
        // and quitting outlives it, so there is nothing to await or cancel.
        let disconnectAndGo: () -> Void = {
            Task {
                await vpn.disconnectAllAndWait()
                for id in tunnelManager.activeIDs { tunnelManager.disconnect(id) }
                if nativeActive { nativeVPN.disconnect() }
                reply(true)
            }
        }
        guard !apps.isEmpty else { disconnectAndGo(); return }

        let vpnName = active.count == 1 ? active[0].name : "your VPNs"
        let lines = apps.map {
            $0.connections > 1 ? "\u{2022}  \($0.name) (\($0.connections) connections)"
                               : "\u{2022}  \($0.name)"
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Quit and disconnect \(vpnName)?"
        alert.informativeText = "These apps are using the VPN right now:\n\n"
            + lines.joined(separator: "\n")
            + "\n\nQuitting disconnects the VPN, so whatever they\u{2019}re doing through it may be interrupted."
        alert.addButton(withTitle: "Disconnect and Quit")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate()
        if alert.runModal() == .alertFirstButtonReturn { disconnectAndGo() } else { reply(false) }
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

    /// Set by SimpleVPNApp once the stores exist. Called on every quit attempt;
    /// must call the reply exactly once: true = go ahead (tunnels already
    /// disconnected), false = the user cancelled.
    var quitHandler: ((@escaping (Bool) -> Void) -> Void)?

    /// True when THIS process is a second copy of an already-running SimpleVPN —
    /// it exits immediately and must never run the quit handler (the tunnels
    /// belong to the first copy).
    private var isDuplicateInstance = false

    /// Quitting must never leave a tunnel behind: the tunnel lives in the
    /// system extension and would keep running after the app is gone. Every
    /// quit path (⌘Q, Dock, last-window-close) funnels through here, where the
    /// handler disconnects — after a confirmation if apps are mid-use.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !isDuplicateInstance, let quitHandler else { return .terminateNow }
        quitHandler { proceed in
            NSApp.reply(toApplicationShouldTerminate: proceed)
        }
        return .terminateLater
    }

    /// The menu-bar icon state THIS process launched with (the scene is fixed
    /// per-launch — see menuBarIconAtLaunch in SimpleVPNApp). Behaviour must
    /// track the icon that's actually visible, not a setting that only takes
    /// effect next start.
    private lazy var menuBarIconAtLaunch = defaultsBool(menuBarIconDefaultsKey, initially: true)

    /// With a menu-bar icon, closing the window is just closing the window —
    /// the app (and its menu-bar presence) stays. Without one, a closed window
    /// would strand an invisible app, so closing the last window quits
    /// (which flows through applicationShouldTerminate → disconnect).
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !menuBarIconAtLaunch
    }

    /// Opening SimpleVPN while it's already running means "show me the
    /// window" — the recovery path when both icons are off and the window was
    /// minimised. Un-minimise what exists; if nothing does, returning true
    /// lets SwiftUI recreate the main window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        NSApp.activate()
        var restored = false
        for w in NSApp.windows where w.isMiniaturized { w.deminiaturize(nil); restored = true }
        return !(restored || hasVisibleWindows)
    }

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
        // ONE copy of the app, ever: a second launch (open -n, a stray copy)
        // must not fight the first over the tunnels. Hand focus to the running
        // copy — its reopen handler brings the window back — and bow out
        // without touching anything. EXCEPT as a unit-test host: the runner
        // launches us with the same bundle id, and self-terminating because
        // the real app happens to be open kills the whole test session.
        let isTestHost = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
            || ProcessInfo.processInfo.environment["XCTestBundlePath"] != nil
        let ourPID = ProcessInfo.processInfo.processIdentifier
        if !isTestHost, let bundleID = Bundle.main.bundleIdentifier,
           let other = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
               .first(where: { $0.processIdentifier != ourPID }) {
            isDuplicateInstance = true
            other.activate()
            NSApp.terminate(nil)
            return
        }

        // Dock icon preference (default: shown). Both icons off is allowed —
        // Settings warns about it — because relaunching from Applications
        // always brings the window back (see applicationShouldHandleReopen).
        NSApp.setActivationPolicy(defaultsBool(dockIconDefaultsKey, initially: true) ? .regular : .accessory)

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
    let updater: SPUStandardUpdaterController
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About SimpleVPN") { openWindow(id: "about") }
            // The macOS-conventional home for updates: right under About.
            Button("Check for Updates\u{2026}") { updater.checkForUpdates(nil) }
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

/// Raises the in-app "VPN Sign-In" window whenever an SSO request lands
/// (the simplevpn-sso:// handler feeding SSOAuthModel). Attached to every
/// long-lived surface — main window, Manage VPNs, the menu-bar label — because
/// the observer used to live only in the main window: an SSO connect started
/// from Manage VPNs or the menu bar with the main window closed sat at
/// "Connecting…" with nowhere to sign in. Duplicate fires are harmless
/// (openWindow on an open window just raises it).
private struct SSOWindowOpener: ViewModifier {
    @State private var sso = SSOAuthModel.shared
    @Environment(\.openWindow) private var openWindow

    func body(content: Content) -> some View {
        content.onChange(of: sso.generation) {
            if sso.pending != nil { openWindow(id: "sso") }
        }
    }
}

extension View {
    func opensSSOWindow() -> some View { modifier(SSOWindowOpener()) }
}

// MenuBarView / MenuBarLabel live in MenuBarView.swift.
