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

    @Environment(CompositionStore.self) private var compositions
    @Environment(SubprocessTunnelStore.self) private var tunnels
    @Environment(SubprocessTunnelManager.self) private var tunnelManager
    @Environment(NativeVPNManager.self) private var nativeVPN
    @Environment(SettingsRouter.self) private var settingsRouter: SettingsRouter?
    @Environment(\.dismiss) private var dismissWindow
    @State private var selection: String?
    @FocusState private var sidebarFocused: Bool
    /// The app-wide "Find a Setting…" sheet (⌘⇧F, or the toolbar).
    @State private var showFindSetting = false

    /// Every configured VPN across all backends — "only one VPN" for the
    /// save-closes-the-window behaviour.
    private var totalVPNCount: Int {
        vpn.profiles.count + tunnels.tunnels.count + nativeVPN.configs.count
    }

    /// Sidebar selection is tagged so rows never collide with NE profile ids.
    ///
    /// THE STRINGS COME FROM `ConnectListing` because the connect window's sidebar
    /// uses the same ones, and a settings route travelling between the two windows is
    /// resolved by tag. They used to be two private constants in two files that
    /// happened to agree; agreeing by construction is cheaper than remembering to.
    private static let tunnelTag = ConnectListing.tunnelTag
    private static let nativeTag = ConnectListing.nativeTag
    @State private var showImporter = false
    @State private var showDiscover = false
    @State private var ciscoNote: String?
    @State private var exportDoc: OVPNDocument?
    @State private var exportName = "config"
    @State private var showExporter = false
    /// What the pending export leaves out, in the user's words (empty = nothing).
    /// A note in the file is not enough on its own — nobody opens the file they
    /// just saved — so the app says it too, once, when the file is written.
    @State private var exportOmission = ""
    @State private var seeded = false
    /// The settings route this window has already resolved a profile for. A route is
    /// STICKY (see `SettingsRouter.route`), and two callers now act on it — the
    /// generation change and this window appearing — so the generation is latched
    /// here exactly as `SettingRevealScrollState` latches the reveal's own.
    @State private var routedGeneration = 0
    @State private var editingComposition: VPNComposition?

    var body: some View {
        NavigationSplitView {
            sidebarList
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
            // One focus section per column (Tab: sidebar → editor), and the
            // list takes initial focus so arrow keys pick a VPN immediately.
            .focusSection()
            .focused($sidebarFocused)
            .toolbar {
                ToolbarItemGroup {
                    Menu { addMenu } label: {
                        Image(systemName: "plus").frame(width: 22, height: 22).contentShape(Rectangle())
                    }
                        .help("Add a connection, or import a config file (any supported type)")
                        .accessibilityLabel("Add VPN")
                    // A bare "minus" Image is a ~2pt-tall hairline, so its intrinsic
                    // hit area is nearly unclickable; a fixed square frame + rectangular
                    // content shape gives it a real target (the "plus" Menu above gets
                    // the same frame for parity).
                    Button { removeSelection() } label: {
                        Image(systemName: "minus").frame(width: 22, height: 22).contentShape(Rectangle())
                    }
                        .disabled(!canRemoveSelection)
                        .help("Remove the selected VPN")
                        .accessibilityLabel("Remove the selected VPN")
                    Button("Export .ovpn…") {
                        if let p = vpn.profiles.first(where: { $0.id == selection }) { export(p) }
                    }
                    .disabled(!vpn.profiles.contains { $0.id == selection })
                    .help("Save the selected VPN's configuration as a file. Its private key is not included \u{2014} that stays in your keychain.")
                    // Discoverable AND keyboard-reachable: a toolbar button here
                    // and ⌘⇧F in the VPN menu, both opening the same sheet.
                    Button {
                        showFindSetting = true
                    } label: {
                        Image(systemName: "text.magnifyingglass")
                            .frame(width: 22, height: 22).contentShape(Rectangle())
                    }
                    .help("Find a setting in any VPN editor (\u{2318}\u{21E7}F)")
                    .accessibilityLabel("Find a setting")
                }
            }
        } detail: {
            detailPane
        }
        .frame(minWidth: 760, minHeight: 560)
        // Note for anyone looking for this window by title (tests, scripting):
        // an embedded editor's own `.navigationTitle` REPLACES the window's on
        // macOS, so selecting a VPN retitles this window to that VPN's name —
        // right for the user, useless as a handle. The scene id ("manage") is
        // the stable handle; AppKit publishes it as the window's AX identifier.
        .navigationTitle("Manage VPNs")
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: Self.importTypes,
                      allowsMultipleSelection: true) { result in
            if case let .success(urls) = result { importFiles(urls) }
        }
        .fileExporter(isPresented: $showExporter, document: exportDoc, contentType: UI.ovpnType, defaultFilename: exportName + ".ovpn") { result in
            // Only on a file that actually got written, and only when something
            // was held back.
            if case .success = result, !exportOmission.isEmpty {
                ToastCenter.shared.post(exportOmission, symbol: "key.slash", tint: .indigo, seconds: 10)
            }
        }
        .alert("Config Imported", isPresented: Binding(
            get: { ciscoNote != nil }, set: { if !$0 { ciscoNote = nil } })) {
            Button("OK", role: .cancel) { ciscoNote = nil }
        } message: { Text(ciscoNote ?? "") }
        .fileDropTarget { urls in importFiles(urls) }
        .importOutcomeAlert(vpn: vpn)
        .sheet(isPresented: $showDiscover) {
            DiscoverEndpointView { candidate in createFromDiscovery(candidate) }
        }
        .sheet(item: $editingComposition) { comp in
            CompositionEditor(vpn: vpn, store: compositions, draft: comp) {}
        }
        .sheet(isPresented: $showFindSetting) { GlobalSettingsSearchView() }
        .onChange(of: settingsRouter?.findGeneration ?? 0) { showFindSetting = true }
        // A route arriving from a related-settings link in another editor, or from
        // the global search: this window owns profile SELECTION, so it resolves
        // "which VPN has this setting" and leaves the tab and the reveal to the
        // editor (SettingsEditorShell).
        .onChange(of: settingsRouter?.generation ?? 0) { selectProfileForRoute() }
        // AND ON APPEAR, for the route that arrives from ANOTHER WINDOW. The connect
        // list's "Fix This…" banner opens this window and then routes, so by the time
        // this view exists the generation has already changed and the `onChange`
        // above never fires for it — the same shape of miss `SettingsRevealScroll`
        // documents for a cross-tab reveal. `selectProfileForRoute` acts at most once
        // per generation, so having two callers is free.
        .onAppear { selectProfileForRoute() }
        .alert("No VPN for that setting", isPresented: Binding(
            get: { settingsRouter?.unroutableMessage != nil },
            set: { if !$0 { settingsRouter?.unroutableMessage = nil } })) {
            Button("OK", role: .cancel) { settingsRouter?.unroutableMessage = nil }
        } message: { Text(settingsRouter?.unroutableMessage ?? "") }
        .task {
            await vpn.loadAll()
            compositions.prune(existingProfileIDs: Set(vpn.profiles.map(\.id)))
            // Open on the VPN the user was looking at in the main window.
            if !seeded {
                seeded = true
                selection = vpn.selectedID ?? vpn.profiles.first?.id
                sidebarFocused = true
            }
        }
    }

    /// The sidebar list. Extracted from `body` because SwiftUI type-checks a
    /// `NavigationSplitView` plus its toolbar as one expression, and the added
    /// toolbar item pushed it past what the compiler will do in reasonable time.
    private var sidebarList: some View {
                List(selection: $selection) {
                    // THE HEADINGS THIS WINDOW USED TO HAVE: "VPNs", "Tunnels" and
                    // "Native (IKEv2 / IPsec)" — our three transports, named as though
                    // they were three kinds of thing the user owns. That is where the
                    // reported confusion came from ("why is APM a Tunnel and not a VPN?
                    // it sure behaves like a vpn"), and the answer to the follow-up ("is
                    // that a useful distinction?") is no. Both headings now answer what
                    // connecting the thing DOES — see `ConnectionScope`.
                    //
                    // "Compositions" stays, and is not the same kind of heading: a
                    // composition is a GROUP of VPNs rather than one connection, so it
                    // sits on a different axis and does not divide the list by anything
                    // about our code.
                    scopeSection(.wholeMac)
                    scopeSection(.localPort)
                    if !compositions.compositions.isEmpty {
                        Section("Compositions") {
                            ForEach(compositions.compositions) { comp in
                                compositionRow(comp)
                            }
                        }
                    }
                }
    }

    /// One heading and everything under it, from all three stores. Row layouts are
    /// unchanged — they were lifted out of the three old sections verbatim so this is a
    /// regrouping and nothing else.
    @ViewBuilder private func scopeSection(_ scope: ConnectionScope) -> some View {
        let profiles = vpn.profiles.filter { ConnectionScope.of(profileKind: $0.kind) == scope }
        let subs = tunnels.tunnels.filter { ConnectionScope.of($0) == scope }
        let natives = nativeVPN.configs.filter { ConnectionScope.of(native: $0) == scope }
        if !profiles.isEmpty || !subs.isEmpty || !natives.isEmpty {
            Section {
                ForEach(profiles) { p in profileRow(p) }
                ForEach(subs) { t in tunnelRow(t) }
                ForEach(natives) { c in nativeRow(c) }
            } header: {
                // The heading names itself and says what puts a row under it, spoken as
                // well as shown (Docs/Accessibility.md: nothing hover-only).
                Text(scope.sectionTitle)
                    .help(scope.explanation)
                    .accessibilityLabel(scope.spokenHeader)
            }
        }
    }

    @ViewBuilder private func profileRow(_ p: VPNController.Profile) -> some View {
        HStack(spacing: 8) {
            VPNRow(profile: p, labelDefs: labels.labels(for: p.id))
            CertExpiryBadge(ovpn: vpn.ovpnText(id: p.id))
            InlineKeyStillStoredBadge(reason: vpn.inlineSecretMigrationFailures[p.id])
        }
            .tag(p.id)
            .contextMenu {
                Button("Export .ovpn…") { export(p) }
                Button("Remove", role: .destructive) { Task { try? await vpn.remove(id: p.id) } }
            }
    }

    @ViewBuilder private func tunnelRow(_ t: SubprocessTunnelConfig) -> some View {
        let st = tunnelManager.status(t.id)
        // What this one gives you, when what it gives you is a port. The same string the
        // connect list's caption carries, from the same one place.
        let port = ConnectListing.portSummary(t)
        HStack(spacing: 8) {
            StatusDot(state: .from(subprocess: st))
            Image(systemName: t.kind.systemImage)
                .foregroundStyle(tunnelManager.isActive(t.id) ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(t.name)
                Text(st.isFailed ? (st.failureText ?? "Failed")
                     : [t.kind.displayName, port].compactMap { $0 }.joined(separator: " \u{00B7} "))
                    .font(.caption)
                    .foregroundStyle(st.isFailed ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
            }
            // The SSL-VPN kinds are exactly the ones nobody has been able to try.
            if let notice = t.kind.maturityNotice {
                MaturityBadge(notice: notice)
            }
        }
        // One sentence, dot state in words (the dot is hidden), then the maturity the
        // chip shows.
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(t.name), \(t.kind.displayName)\(port.map { ", \($0)" } ?? ""), \(DotState.from(subprocess: st).accessibilityDescription)\(st.isFailed ? ", \(st.failureText ?? "failed")" : "")\(t.kind.maturityNotice.map { ", \($0.spokenValue)" } ?? "")")
        .tag(Self.tunnelTag + t.id)
        .contextMenu {
            Button("Remove", role: .destructive) {
                tunnelManager.disconnect(t.id); tunnels.remove(t.id)
            }
        }
    }

    @ViewBuilder private func nativeRow(_ c: NativeVPNConfig) -> some View {
        // Reflect real status, not just activeConfigID — an OS-side drop clears
        // activeConfigID, and connecting/failed now read distinctly.
        let isThis = nativeVPN.activeConfigID == c.id
        HStack(spacing: 8) {
            StatusDot(status: isThis ? nativeVPN.status : .disconnected)
            Image(systemName: c.kind.systemImage)
                .foregroundStyle(isThis && nativeVPN.status == .connected ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(c.name)
                Text(c.kind.displayName).font(.caption).foregroundStyle(.secondary)
            }
            // All three native kinds are unproven — this Mac has no IKEv2, IPsec or
            // L2TP server to try.
            if let notice = c.kind.maturityNotice {
                MaturityBadge(notice: notice)
            }
        }
        // One sentence incl. the dot's state in words — the hidden dot and icon tint
        // said "connected" to nobody — then the maturity the chip shows.
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(c.name), \(c.kind.displayName), \(DotState.from(status: isThis ? nativeVPN.status : .disconnected).accessibilityDescription)\(c.kind.maturityNotice.map { ", \($0.spokenValue)" } ?? "")")
        .tag(Self.nativeTag + c.id)
        .contextMenu {
            Button("Remove", role: .destructive) { nativeVPN.remove(c.id) }
        }
    }

    /// A composition row: single Connect/Disconnect for the whole group, plus edit/remove.
    @ViewBuilder private func compositionRow(_ comp: VPNComposition) -> some View {
        let active = vpn.isCompositionActive(comp)
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "square.stack.3d.up")
                    .foregroundStyle(active ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(comp.name)
                    Text("\(comp.members.count) VPNs").font(.caption).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(comp.name), composition of \(comp.members.count) VPNs, \(active ? "connected" : "disconnected")")
            Spacer(minLength: 6)
            if active {
                Button { vpn.disconnectComposition(comp) } label: {
                    Image(systemName: "stop.circle.fill").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                    .buttonStyle(.borderless).help("Disconnect all")
                    .accessibilityLabel("Disconnect all of \(comp.name)")
            } else {
                Button { Task { await vpn.connectComposition(comp) } } label: {
                    Image(systemName: "play.circle.fill").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                    .buttonStyle(.borderless).help("Connect all")
                    .accessibilityLabel("Connect all of \(comp.name)")
            }
            // Edit/Remove used to live only in the context menu, which plain
            // keyboard can't open — this menu is the Tab-reachable path.
            Menu {
                Button("Edit…") { editingComposition = comp }
                Button("Remove", role: .destructive) { compositions.remove(comp.id) }
            } label: {
                Image(systemName: "ellipsis.circle").frame(width: 28, height: 22).contentShape(Rectangle())
            }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .accessibilityLabel("Actions for \(comp.name)")
        }
        .contextMenu {
            Button(active ? "Disconnect All" : "Connect All") {
                if active { vpn.disconnectComposition(comp) } else { Task { await vpn.connectComposition(comp) } }
            }
            Button("Edit…") { editingComposition = comp }
            Button("Remove", role: .destructive) { compositions.remove(comp.id) }
        }
    }

    // MARK: Routing to a setting

    /// Select a VPN that HAS the routed setting. The sidebar's selection is this
    /// window's own business — the editor can't select itself — so the route is
    /// resolved here and the editor picks up the tab and the reveal from the same
    /// (sticky) route.
    ///
    /// A route that already names a profile is honoured as-is; one that doesn't
    /// (every global-search hit) takes the first VPN of a kind whose editor shows
    /// the surface, keeping the current selection when it already qualifies — so
    /// following a Custom Routing relation never jumps you to a different VPN.
    private func selectProfileForRoute() {
        guard let router = settingsRouter, let route = router.route,
              let surface = SettingSurface(rawValue: route.surface),
              // At most once per route, so the `onAppear` caller can't re-select (or
              // re-raise the unroutable alert) every time this window is reopened
              // against a route that is deliberately sticky.
              router.generation != routedGeneration else { return }
        routedGeneration = router.generation
        if let wanted = route.profileID {
            // TRANSLATED, not assigned. A route names a profile by its own id; the
            // sidebar selects tunnels and native configs behind a prefix, so an
            // untranslated id matched no row and the editor never appeared. Nothing
            // routed to one before the connect list's banner started doing it.
            selection = sidebarTag(for: wanted) ?? wanted
            return
        }
        if let current = selection, tagMatches(current, surface: surface) { return }
        guard let tag = firstSelection(for: surface) else {
            router.unroutableMessage =
                "There's no \(surface.title) VPN configured yet, so \u{201C}\(AllSettings.byID[route.settingID]?.setting.name ?? route.settingID)\u{201D} has nothing to apply to. Add one with + first."
            router.clear()
            return
        }
        selection = tag
    }

    /// The sidebar selection tag for a profile id, across all three stores. VPN
    /// profiles are selected by their bare id; tunnels and native configs live behind
    /// a prefix. Returns nil when nothing by that id exists, so the caller can fall
    /// back rather than clearing a good selection.
    private func sidebarTag(for profileID: String) -> String? {
        if vpn.profiles.contains(where: { $0.id == profileID }) { return profileID }
        if tunnels.tunnels.contains(where: { $0.id == profileID }) { return Self.tunnelTag + profileID }
        if nativeVPN.configs.contains(where: { $0.id == profileID }) { return Self.nativeTag + profileID }
        return nil
    }

    /// Whether the currently-selected row's editor shows this surface.
    private func tagMatches(_ tag: String, surface: SettingSurface) -> Bool {
        guard let kind = kind(ofSelection: tag) else { return false }
        return surface.kinds.contains(kind)
    }

    /// The VPN kind behind a sidebar selection tag, across all four stores.
    private func kind(ofSelection tag: String) -> VPNKind? {
        if tag.hasPrefix(Self.tunnelTag) {
            return tunnelBinding(for: tag)?.kind
        }
        if tag.hasPrefix(Self.nativeTag) {
            return nativeBinding(for: tag)?.kind
        }
        guard vpn.profiles.contains(where: { $0.id == tag }) else { return nil }
        if vpn.isWireGuard(tag) { return .wireGuard }
        if vpn.isTailscale(tag) { return .tailscale }
        if vpn.isProxyTunnel(tag) { return .proxyTunnel }
        return .openVPN
    }

    /// The first sidebar row whose editor shows this surface, as a selection tag.
    private func firstSelection(for surface: SettingSurface) -> String? {
        // Custom Routing is every kind's second tab, so anything selectable will
        // do — prefer whatever is already selected (handled by the caller).
        let kinds = Set(surface.kinds)
        for p in vpn.profiles {
            guard let k = kind(ofSelection: p.id), kinds.contains(k) else { continue }
            return p.id
        }
        for t in tunnels.tunnels where kinds.contains(t.kind) {
            return Self.tunnelTag + t.id
        }
        for c in nativeVPN.configs where kinds.contains(c.kind) {
            return Self.nativeTag + c.id
        }
        return nil
    }

    /// The − button removes whatever the sidebar has selected — VPN profiles,
    /// tunnels and native configs alike. (Compositions aren't selectable; their
    /// row menu carries Remove.)
    private var canRemoveSelection: Bool {
        guard let sel = selection else { return false }
        if sel.hasPrefix(Self.tunnelTag) { return true }
        if sel.hasPrefix(Self.nativeTag) { return true }
        return vpn.profiles.contains { $0.id == sel }
    }

    private func removeSelection() {
        guard let sel = selection else { return }
        if sel.hasPrefix(Self.tunnelTag) {
            let id = String(sel.dropFirst(Self.tunnelTag.count))
            tunnelManager.disconnect(id); tunnels.remove(id)
        } else if sel.hasPrefix(Self.nativeTag) {
            nativeVPN.remove(String(sel.dropFirst(Self.nativeTag.count)))
        } else {
            Task { try? await vpn.remove(id: sel) }
        }
    }

    // MARK: Discovery → concrete VPN

    /// Turn a discovery candidate into a real config in the right store and select it.
    private func createFromDiscovery(_ c: DiscoveryCandidate) {
        switch c.engine {
        case .ssh:
            var t = SubprocessTunnelConfig()
            t.kind = .ssh
            t.name = "SSH — \(c.host)"
            t.server = c.host
            t.port = c.port == 22 ? nil : c.port
            tunnels.save(t)
            selection = Self.tunnelTag + t.id

        case .sslVPN:
            var t = SubprocessTunnelConfig()
            t.kind = c.kind ?? .ciscoAnyConnect
            t.name = c.title
            t.server = "https://\(c.host):\(c.port)"
            tunnels.save(t)
            selection = Self.tunnelTag + t.id

        case .ikev2:
            var n = NativeVPNConfig()
            n.kind = .ikev2
            n.name = "IKEv2 — \(c.host)"
            n.server = c.host
            n.remoteID = c.host
            n.ikeEncryption = Self.mapIKEEncryption(c.facts["encryption"])
            n.ikeIntegrity = Self.mapIKEIntegrity(c.facts["integrity"])
            n.ikeDHGroup = c.facts["dhGroup"] ?? ""
            nativeVPN.save(n)
            selection = Self.nativeTag + n.id

        case .openVPN:
            let proto = c.facts["proto"] ?? "udp"
            let stub = """
            client
            dev tun
            proto \(proto)
            remote \(c.host) \(c.port)
            nobind
            persist-tun
            persist-key
            remote-cert-tls server
            # Add the CA your provider gave you (<ca>…</ca>) and your credentials.
            """
            Task {
                if case .imported(let id, _) = await vpn.importProfile(text: stub, suggestedName: "OpenVPN — \(c.host)") {
                    selection = id
                }
            }

        case .wireGuard:
            break   // not creatable from a probe
        }
    }

    private static func mapIKEEncryption(_ name: String?) -> String {
        switch name {
        case "AES-CBC": "aes256"
        case "AES-GCM-16", "AES-GCM-12", "AES-GCM-8": "aes256gcm"
        case "ChaCha20-Poly1305": "chacha20poly1305"
        default: ""   // 3DES/unknown → let macOS negotiate its defaults
        }
    }
    private static func mapIKEIntegrity(_ name: String?) -> String {
        switch name {
        case "SHA256-128": "sha256"
        case "SHA384-192": "sha384"
        case "SHA512-256": "sha512"
        default: ""
        }
    }

    private func newTunnel(_ kind: VPNKind) {
        var t = SubprocessTunnelConfig()
        t.kind = kind
        t.name = kind.displayName
        tunnels.save(t)
        selection = Self.tunnelTag + t.id
    }

    /// The tunnel config for a tagged selection, if it names one.
    private func tunnelBinding(for selection: String) -> SubprocessTunnelConfig? {
        guard selection.hasPrefix(Self.tunnelTag) else { return nil }
        let id = String(selection.dropFirst(Self.tunnelTag.count))
        return tunnels.tunnels.first { $0.id == id }
    }

    private func newNative(_ kind: VPNKind) {
        var c = NativeVPNConfig()
        c.kind = kind
        c.name = kind.displayName
        nativeVPN.save(c)
        selection = Self.nativeTag + c.id
    }

    private func nativeBinding(for selection: String) -> NativeVPNConfig? {
        guard selection.hasPrefix(Self.nativeTag) else { return nil }
        let id = String(selection.dropFirst(Self.nativeTag.count))
        return nativeVPN.configs.first { $0.id == id }
    }

    /// File types the single Import action accepts. Deliberately broad — the
    /// content sniffer (ConfigDetector) does the real routing, so a WireGuard
    /// config saved as .txt or a .pcf with no registered UTType still gets in.
    private static let importTypes: [UTType] = {
        var t: [UTType] = [UI.ovpnType, .data, .plainText, .xml]
        for ext in ["conf", "pcf", "wg", "cfg"] {
            if let ut = UTType(filenameExtension: ext) { t.append(ut) }
        }
        return t
    }()

    private func importFiles(_ urls: [URL]) {
        Task { for url in urls { await importFile(url) } }
    }

    /// Read a file, sniff which engine it belongs to, and route it — the single
    /// pipeline behind both the Import… menu item and drag-and-drop.
    private func importFile(_ url: URL) async {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            vpn.importOutcome = .invalid(reason: "Couldn't read \(url.lastPathComponent).")
            return
        }
        let name = url.deletingPathExtension().lastPathComponent

        switch ConfigDetector.detect(text: text, filename: url.lastPathComponent) {
        case .openVPN:
            switch await vpn.importProfile(text: text, suggestedName: name) {
            case .imported(let id, _): selection = id
            case let outcome:         vpn.importOutcome = outcome
            }

        case .wireGuard:
            let c = WireGuardConfig.parse(text, name: name)
            do { selection = try await vpn.createWireGuard(from: c) }
            catch { vpn.importOutcome = .invalid(reason: error.localizedDescription) }

        case .cisco:
            importCiscoText(text, name: name)
        }
    }

    /// Route a Cisco .pcf / AnyConnect XML config to the right store.
    private func importCiscoText(_ text: String, name: String) {
        switch CiscoImport.parse(text, name: name) {
        case .anyConnect(let configs):
            for c in configs { tunnels.save(c) }
            if let first = configs.first { selection = Self.tunnelTag + first.id }
            ciscoNote = "Imported \(configs.count) Cisco AnyConnect server\(configs.count == 1 ? "" : "s"). Connect uses OpenConnect — install it with: brew install openconnect."
        case .pcf(let config, let secret, let note):
            nativeVPN.save(config)
            if let secret { try? KeychainCredentialStore.saveCredentials(profile: "native.\(config.id)",
                                                                         .init(username: config.username, password: secret)) }
            selection = Self.nativeTag + config.id
            ciscoNote = note ?? "Imported the Cisco IPsec profile “\(config.name)”. It uses the native IPsec transport."
        case .unrecognized:
            vpn.importOutcome = .invalid(reason: "That file isn't a recognisable Cisco .pcf or AnyConnect XML profile.")
        }
    }

    private func newWireGuard() async {
        var c = WireGuardConfig()
        // Sensible defaults for a hand-built tunnel (imports keep their own values):
        // a 25s keepalive so the peer stays reachable through NAT, and an explicit
        // 1420 MTU that fits inside the common 1500 path once WireGuard's own
        // overhead is subtracted — heading off the MTU-blackhole stall.
        c.persistentKeepalive = 25
        c.mtu = 1420
        do { selection = try await vpn.createWireGuard(from: c) }
        catch { vpn.lastError = error.localizedDescription }
    }

    /// The "+" menu. Extracted from the toolbar closure: SwiftUI's result
    /// builders type-check the whole thing as one expression, and this list
    /// alone is past what the compiler will do in reasonable time inline.
    @ViewBuilder private var addMenu: some View {
        Button("OpenVPN") { Task { await newEmpty() } }
        Button("WireGuard") { Task { await newWireGuard() } }
        Button("Tailscale / Headscale") { Task { await newTailscale() } }
        Button("Proxy Tunnel (SOCKS5 / HTTP)") { Task { await newProxyTunnel() } }
        Button("IKEv2") { newNative(.ikev2) }
        Button("IPsec (IKEv1)") { newNative(.ipsec) }
        Button("L2TP / IPsec") { newNative(.l2tp) }
        Button("SSH (SOCKS, forwards, tunnel)") { newTunnel(.ssh) }
        Button("SSH Network Tunnel (routes over SSH)") { Task { await newSSHNetworkTunnel() } }
        Button("FortiGate SSL VPN") { newTunnel(.fortinet) }
        Button("F5 BIG-IP APM") { newTunnel(.f5apm) }
        Button("Cisco AnyConnect") { newTunnel(.ciscoAnyConnect) }
        Button("Palo Alto GlobalProtect") { newTunnel(.globalProtect) }
        Button("Juniper Network Connect") { newTunnel(.juniper) }
        Button("Pulse Connect Secure") { newTunnel(.pulse) }
        Button("Array Networks SSL VPN") { newTunnel(.arrayNetworks) }
        Button("Composition (multiple VPNs)…") { editingComposition = VPNComposition() }
            .disabled(vpn.profiles.count < 2)
        Divider()
        Button("Import…") { showImporter = true }
        Button("Discover from Address…") { showDiscover = true }
    }

    /// Which editor the selected row gets. Tag prefixes route the non-NE
    /// stores; among NE profiles the VPNKind decides, because a Tailscale
    /// profile shares the transport with OpenVPN but nothing in the OpenVPN
    /// editor (raw .ovpn, certificates, engine overrides) applies to it.
    @ViewBuilder private var detailPane: some View {
        if let id = selection, let t = tunnelBinding(for: id) {
            SubprocessTunnelView(vpn: vpn, store: tunnels, manager: tunnelManager, draft: t).id(id)
        } else if let id = selection, let c = nativeBinding(for: id) {
            NativeVPNView(vpn: vpn, manager: nativeVPN, draft: c).id(id)
        } else if let id = selection, vpn.isWireGuard(id) {
            WireGuardView(vpn: vpn, profileID: id).id(id)
        } else if let id = selection, vpn.isTailscale(id) {
            TailscaleView(vpn: vpn, profileID: id).id(id)
        } else if let id = selection, vpn.isProxyTunnel(id) {
            ProxyTunnelView(vpn: vpn, profileID: id).id(id)
        } else if let id = selection, vpn.isSSHNetworkTunnel(id) {
            SSHNetworkTunnelView(vpn: vpn, profileID: id).id(id)
        } else if let id = selection, vpn.profiles.contains(where: { $0.id == id }) {
            EditVPNView(vpn: vpn, labels: labels, profileID: id, embedded: true,
                        onSaved: { if totalVPNCount <= 1 { dismissWindow() } })
                .id(id)   // fresh editor state per VPN
        } else {
            ContentUnavailableView("No VPN Selected", systemImage: "network",
                                   description: Text("Select a VPN, or use + to import or create one."))
        }
    }

    private func newSSHNetworkTunnel() async {
        do { selection = try await vpn.createSSHNetworkTunnel() }
        catch { vpn.lastError = error.localizedDescription }
    }

    private func newTailscale() async {
        do { selection = try await vpn.createTailscale() }
        catch { vpn.lastError = error.localizedDescription }
    }

    private func newProxyTunnel() async {
        do { selection = try await vpn.createProxyTunnel() }
        catch { vpn.lastError = error.localizedDescription }
    }

    private func newEmpty() async {
        do { let id = try await vpn.importProfile(name: "New VPN", ovpn: "", server: ""); selection = id }
        catch { vpn.lastError = error.localizedDescription }
    }

    /// Export the selected VPN's configuration — WITHOUT its private key.
    ///
    /// `exportableOVPNText` is not `ovpnText`: it never reassembles the secret
    /// blocks, and it puts a note in the file naming what was left out and how to
    /// put it back. This used to hand `ovpnText` straight to the exporter, which
    /// wrote the user's client private key to whatever file they chose, in the
    /// clear, with no warning. See `OVPNSecretMaterial.exportText` for why omitting
    /// beats asking.
    private func export(_ p: VPNController.Profile) {
        guard let text = vpn.exportableOVPNText(id: p.id) else {
            vpn.lastError = "No configuration to export"; return
        }
        exportOmission = OVPNSecretMaterial.exportOmissionNotice(vpn.storedOVPNText(id: p.id) ?? "")
        exportDoc = OVPNDocument(text: text); exportName = p.name; showExporter = true
    }
}

/// Shown when SimpleVPN could NOT move this VPN's private key into the keychain,
/// so the key is still stored alongside the configuration. A failed migration that
/// nobody can see is a private key sitting in the preferences with nobody aware of
/// it, which is the whole problem the migration exists to fix.
private struct InlineKeyStillStoredBadge: View {
    let reason: String?

    var body: some View {
        if let reason {
            Label {
                Text("Private key stored with the configuration")
            } icon: {
                Image(systemName: "key.slash.fill")
            }
            .labelStyle(.iconOnly)
            .foregroundStyle(.orange)
            .help(reason)
            .accessibilityLabel("Private key still stored with the configuration")
            .accessibilityValue(reason)
        }
    }
}

/// Small warning badge when any certificate embedded in the profile is expired
/// or expires within 30 days — surfaced in the list so it's seen before the
/// connection fails.
private struct CertExpiryBadge: View {
    let ovpn: String?

    var body: some View {
        if let state = worstExpiry {
            Label {
                Text(state == .expired ? "Certificate expired" : "Certificate expiring")
            } icon: {
                Image(systemName: state == .expired
                      ? "exclamationmark.seal.fill" : "clock.badge.exclamationmark")
            }
            .labelStyle(.iconOnly)
            .foregroundStyle(state == .expired ? AnyShapeStyle(.red) : AnyShapeStyle(.orange))
            .help(state == .expired ? "A certificate in this VPN has expired"
                                    : "A certificate in this VPN expires within 30 days")
            .accessibilityLabel(state == .expired ? "Certificate expired"
                                                  : "Certificate expiring soon")
        }
    }

    private enum State { case expired, expiring }

    private var worstExpiry: State? {
        guard let ovpn else { return nil }
        var expiring = false
        for slot in [CertSlot.ca, .cert] {
            guard let block = OVPNInline.block(for: slot, in: ovpn) else { continue }
            for cert in CertificateImport.certificates(inPEM: block.content) {
                switch CertificateSummary(certificate: cert).expiryState {
                case .expired: return .expired
                case .expiringSoon: expiring = true
                case .ok: break
                }
            }
        }
        return expiring ? .expiring : nil
    }
}
