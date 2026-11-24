// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing

@testable import SimpleVPN

struct NetworkArchitectureBoundaryTests {
    private let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private func source(_ path: String) throws -> String {
        try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }
    @Test func routingAdapterInventoryCoversEverySavedKindAndMode() throws {
        struct Adapter: Decodable {
            let id: String
            let vpnKinds: [String]
            let profileModes: [String]?
        }
        let url = root.appendingPathComponent("Vendor/proxy-engine/src/routelang/catalog/adapters.json")
        let rows = try JSONDecoder().decode([Adapter].self, from: Data(contentsOf: url))
        #expect(Set(rows.flatMap(\.vpnKinds)) == Set(VPNKind.allCases.map(\.rawValue)))
        func modes(for kind: VPNKind) -> Set<String> {
            Set(rows.filter { $0.vpnKinds.contains(kind.rawValue) }.flatMap { $0.profileModes ?? [] })
        }
        #expect(modes(for: .ssh) == Set(SSHMode.allCases.map(\.rawValue)))
        #expect(modes(for: .proxyTunnel) == Set(ProxyTunnelConfig.Preset.allCases.map(\.rawValue)))
        #expect(modes(for: .tailscale) == Set(TailscaleConfig.Preset.allCases.map(\.rawValue)))
        for id in ["openconnect-packet", "openconnect-proxy"] {
            let row = try #require(rows.first { $0.id == id })
            #expect(Set(row.vpnKinds) == Set(VPNKind.allCases.filter(\.isSSLVPN).map(\.rawValue)))
        }
    }

    @Test func allOSSettingsWritesPassThroughTheAcknowledgedWriter() throws {
        let directory = root.appendingPathComponent("PacketTunnel")
        let files = try #require(FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil))
        var owners: Set<String> = []
        for case let url as URL in files where ["swift", "m", "mm"].contains(url.pathExtension) {
            let text = try String(contentsOf: url, encoding: .utf8)
            if text.contains(".setTunnelNetworkSettings(") || text.contains(" setTunnelNetworkSettings:") { owners.insert(url.lastPathComponent) }
        }
        #expect(owners == ["PacketTunnelProvider.swift"], "Docs/Drift.md §18: use NetworkSettingsWriter; a bridge must not own another OS writer.")
    }
    @Test func shippingGoCallersUseScopedInstanceAPIs() throws {
        for engine in ["WireGuardEngine", "TailscaleEngine", "ProxyTunnelEngine", "SSHNetworkTunnelEngine"] {
            let text = try source("PacketTunnel/Engines/\(engine).swift")
            for legacy in ["WGStart(", "WGStop(", "TSStart(", "TSStop(", "PXStart(", "PXStop(", "WGSetCallbacks(", "TSSetCallbacks(", "PXSetCallbacks("] {
                #expect(!text.contains(legacy), "Legacy exports remain compatibility/test-only; preserve scoped handles and callback contexts.")
            }
        }
    }
    @Test func virtualModeExclusionsRemainVisibleUntilRealPortsExist() throws {
        let text = try source("SimpleVPN/ControlPlane/VPNController+VirtualRouting.swift")
        let eligibility = try #require(text.components(separatedBy: "func virtualMemberProblem(").last?.components(separatedBy: "func connectThroughVirtualInterface").first)
        #expect(eligibility.contains("case .wireGuard: nil"))
        #expect(eligibility.contains("case .proxyTunnel: proxyTunnelConfig(for: profile.id).virtualMemberProblem"))
        #expect(eligibility.contains("default:"))
        #expect(eligibility.contains("config.ownedIPsec") && eligibility.contains("WireGuardConfig.isIPLiteral"))
        #expect(eligibility.contains("tailscaleConfig(for: profile.id).virtualMemberProblem"))
        for kind in VPNKind.allCases where ![VPNKind.wireGuard, .openVPN, .ssh, .tailscale, .ikev2, .ipsec, .l2tp, .sshNetworkTunnel, .proxyTunnel].contains(kind) && !kind.supportsSharedOpenConnect {
            #expect(!eligibility.contains("case ." + kind.rawValue + ":"))
        }
        let proxyStart = try source("SimpleVPN/ControlPlane/VPNController+ProxyTunnel.swift")
        #expect(proxyStart.contains("virtualManager(for: id) == nil") && proxyStart.contains("connectionReservations.reserve"))
        #expect(text.contains("Chained VPNs are unavailable"))
        #expect(text.contains("guard custom.proxy.isIdentity"))
        #expect(text.contains("Saved destination diverts require independent connections"))
        #expect(text.contains("let dnsFilter = custom.dns.nativeSettings"))
        #expect(text.contains("connectionReservations.reserve"))
        #expect(text.contains("wireGuardConfigurationOperations.acquire()"))
        let independent = try source("SimpleVPN/ControlPlane/VPNController+WireGuard.swift")
        #expect(independent.contains("virtualManager(for: id) == nil"), "A stopped virtual member cannot restart as an independent VPN while its composition still owns capture.")
        #expect(independent.contains("connectionReservations.reserve"))
        #expect(independent.contains("connectionReservations.isCurrent(attempt)"))
        let engine = try source("PacketTunnel/Engines/VirtualRoutingEngine.swift")
        #expect(engine.contains("router:apply-plan:") && engine.contains("router:dns-plan:"))
        #expect(!engine.contains("request.message == \"gateway:split\""), "Virtual gateway changes must remain one complete OS transaction.")
        let register = try source("Docs/Drift.md")
        #expect(register.contains("Per-app sessions do not elect a whole-Mac gateway"))
        #expect(register.contains("provider crash still needs a separate acceptance run"))
    }
    @Test func privateStateAndSigningStayOutOfTelemetry() throws {
        let stats = try source("Shared/TunnelStats.swift")
        #expect(!stats.contains("nodeState") && !stats.contains("agentRequest") && !stats.contains("privateKey"))
        let broker = try source("Shared/SSHAgentSigningBroker.swift")
        #expect(broker.contains("body.first == 11 || body.first == 13"))
        #expect(broker.contains("262144"))
        let start = try source("Shared/TailscaleConfig.swift")
        #expect(start.contains("copy.nodeState = nodeState.isEmpty ? \"\" : \"<redacted>\""))
    }
}
