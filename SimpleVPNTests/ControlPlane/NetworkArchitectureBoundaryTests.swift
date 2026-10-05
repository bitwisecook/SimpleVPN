// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing

struct NetworkArchitectureBoundaryTests {
    private let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private func source(_ path: String) throws -> String {
        try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
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
        #expect(text.contains("?.kind == .wireGuard"), "Other engines need real packet ports before widening this gate. Retire Docs/Drift.md §18 and this guard together.")
        #expect(text.contains("Chained VPNs are unavailable"))
        #expect(text.contains("custom.dns.isIdentity, custom.proxy.isIdentity"))
        #expect(text.contains("connectionReservations.reserve"))
        #expect(text.contains("wireGuardConfigurationOperations.acquire()"))
        let independent = try source("SimpleVPN/ControlPlane/VPNController+WireGuard.swift")
        #expect(independent.contains("virtualManager(for: id) == nil"), "A stopped virtual member cannot restart as an independent VPN while its composition still owns capture.")
        #expect(independent.contains("connectionReservations.reserve"))
        #expect(independent.contains("connectionReservations.isCurrent(attempt)"))
        let engine = try source("PacketTunnel/Engines/VirtualRoutingEngine.swift")
        #expect(engine.contains("router:apply-plan:"))
        #expect(!engine.contains("request.message == \"gateway:split\""), "Virtual gateway changes must remain one complete OS transaction.")
        let register = try source("Docs/Drift.md")
        #expect(register.contains("per-app/fake-IP/L7/Tcl"))
        #expect(register.contains("provider-crash kill-switch"))
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
