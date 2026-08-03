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
    @Environment(\.dismiss) private var dismissWindow
    @State private var selection: String?

    /// Every configured VPN across all backends — "only one VPN" for the
    /// save-closes-the-window behaviour.
    private var totalVPNCount: Int {
        vpn.profiles.count + tunnels.tunnels.count + nativeVPN.configs.count
    }

    /// Sidebar selection is tagged so rows never collide with NE profile ids.
    private static let tunnelTag = "tunnel:"
    private static let nativeTag = "native:"
    @State private var showImporter = false
    @State private var showDiscover = false
    @State private var ciscoNote: String?
    @State private var exportDoc: OVPNDocument?
    @State private var exportName = "config"
    @State private var showExporter = false
    @State private var seeded = false
    @State private var editingComposition: VPNComposition?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section("VPNs") {
                    ForEach(vpn.profiles) { p in
                        HStack(spacing: 8) {
                            VPNRow(profile: p, labelDefs: labels.labels(for: p.id))
                            CertExpiryBadge(ovpn: vpn.ovpnText(id: p.id))
                        }
                            .tag(p.id)
                            .contextMenu {
                                Button("Export .ovpn…") { export(p) }
                                Button("Remove", role: .destructive) { Task { try? await vpn.remove(id: p.id) } }
                            }
                    }
                }
                if !tunnels.tunnels.isEmpty {
                    Section("Tunnels") {
                        ForEach(tunnels.tunnels) { t in
                            let st = tunnelManager.status(t.id)
                            HStack(spacing: 8) {
                                StatusDot(state: .from(subprocess: st))
                                Image(systemName: t.kind.systemImage)
                                    .foregroundStyle(tunnelManager.isActive(t.id) ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(t.name)
                                    Text(st.isFailed ? (st.failureText ?? "Failed") : t.kind.displayName)
                                        .font(.caption)
                                        .foregroundStyle(st.isFailed ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                                        .lineLimit(1)
                                }
                            }
                            .tag(Self.tunnelTag + t.id)
                            .contextMenu {
                                Button("Remove", role: .destructive) {
                                    tunnelManager.disconnect(t.id); tunnels.remove(t.id)
                                }
                            }
                        }
                    }
                }
                if !nativeVPN.configs.isEmpty {
                    Section("Native (IKEv2 / IPsec)") {
                        ForEach(nativeVPN.configs) { c in
                            // Reflect real status, not just activeConfigID — an
                            // OS-side drop clears activeConfigID, and connecting/
                            // failed now read distinctly.
                            let isThis = nativeVPN.activeConfigID == c.id
                            HStack(spacing: 8) {
                                StatusDot(status: isThis ? nativeVPN.status : .disconnected)
                                Image(systemName: c.kind.systemImage)
                                    .foregroundStyle(isThis && nativeVPN.status == .connected ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(c.name)
                                    Text(c.kind.displayName).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .tag(Self.nativeTag + c.id)
                            .contextMenu {
                                Button("Remove", role: .destructive) { nativeVPN.remove(c.id) }
                            }
                        }
                    }
                }
                if !compositions.compositions.isEmpty {
                    Section("Compositions") {
                        ForEach(compositions.compositions) { comp in
                            compositionRow(comp)
                        }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240)
            .toolbar {
                ToolbarItemGroup {
                    Menu { addMenu } label: { Image(systemName: "plus") }
                        .help("Add a connection, or import a config file (any supported type)")
                    Button { if let id = selection { Task { try? await vpn.remove(id: id) } } } label: { Image(systemName: "minus") }
                        .disabled(selection == nil || !vpn.profiles.contains { $0.id == selection })
                        .help("Remove")
                }
            }
        } detail: {
            detailPane
        }
        .frame(minWidth: 760, minHeight: 560)
        .navigationTitle("Manage VPNs")
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: Self.importTypes,
                      allowsMultipleSelection: true) { result in
            if case let .success(urls) = result { importFiles(urls) }
        }
        .fileExporter(isPresented: $showExporter, document: exportDoc, contentType: UI.ovpnType, defaultFilename: exportName + ".ovpn") { _ in }
        .alert("Config Imported", isPresented: Binding(
            get: { ciscoNote != nil }, set: { if !$0 { ciscoNote = nil } })) {
            Button("OK") { ciscoNote = nil }
        } message: { Text(ciscoNote ?? "") }
        .fileDropTarget { urls in importFiles(urls) }
        .importOutcomeAlert(vpn: vpn)
        .sheet(isPresented: $showDiscover) {
            DiscoverEndpointView { candidate in createFromDiscovery(candidate) }
        }
        .sheet(item: $editingComposition) { comp in
            CompositionEditor(vpn: vpn, store: compositions, draft: comp) {}
        }
        .task {
            await vpn.loadAll()
            compositions.prune(existingProfileIDs: Set(vpn.profiles.map(\.id)))
            // Open on the VPN the user was looking at in the main window.
            if !seeded {
                seeded = true
                selection = vpn.selectedID ?? vpn.profiles.first?.id
            }
        }
    }

    /// A composition row: single Connect/Disconnect for the whole group, plus edit/remove.
    @ViewBuilder private func compositionRow(_ comp: VPNComposition) -> some View {
        let active = vpn.isCompositionActive(comp)
        HStack(spacing: 8) {
            Image(systemName: "square.stack.3d.up")
                .foregroundStyle(active ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
            VStack(alignment: .leading, spacing: 1) {
                Text(comp.name)
                Text("\(comp.members.count) VPNs").font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 6)
            if active {
                Button { vpn.disconnectComposition(comp) } label: { Image(systemName: "stop.circle.fill") }
                    .buttonStyle(.borderless).help("Disconnect all")
            } else {
                Button { Task { await vpn.connectComposition(comp) } } label: { Image(systemName: "play.circle.fill") }
                    .buttonStyle(.borderless).help("Connect all")
            }
        }
        .contextMenu {
            Button(active ? "Disconnect All" : "Connect All") {
                if active { vpn.disconnectComposition(comp) } else { Task { await vpn.connectComposition(comp) } }
            }
            Button("Edit…") { editingComposition = comp }
            Button("Remove", role: .destructive) { compositions.remove(comp.id) }
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
        } else if let id = selection, vpn.profiles.contains(where: { $0.id == id }) {
            EditVPNView(vpn: vpn, labels: labels, profileID: id, embedded: true,
                        onSaved: { if totalVPNCount <= 1 { dismissWindow() } })
                .id(id)   // fresh editor state per VPN
        } else {
            ContentUnavailableView("No VPN Selected", systemImage: "network",
                                   description: Text("Select a VPN, or use + to import or create one."))
        }
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

    private func export(_ p: VPNController.Profile) {
        guard let text = vpn.ovpnText(id: p.id) else { vpn.lastError = "No configuration to export"; return }
        exportDoc = OVPNDocument(text: text); exportName = p.name; showExporter = true
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
