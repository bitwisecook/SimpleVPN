// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct RoutingRailroadTests {
    private func diagram(_ draft: EditorRoutingDraft, tab: SettingsTab = .settings,
                         vpn: VPNController = VPNController()) -> RoutingRailroadDiagram {
        RoutingRailroadProjection.make(profileID: "railroad-test", tab: tab, draft: draft,
                                       vpn: vpn, topology: NetworkTopology())
    }
    private func text(_ graph: RoutingRailroadDiagram, lane: String) -> [String] {
        graph.lanes.first { $0.id == lane }?.stations.flatMap(\.details) ?? []
    }

    @Test func previewUsesEffectivePeersWithoutCallingHooksOrChangingState() {
        let routes = RouteMediator(preferences: nil)
        let peer = RouteIntent(engine: "peer", advertisedPrefixes: ["10.0.0.0/8"],
                               wantsDefault: true, canOwnDefault: true, connectedAt: .distantPast)
        routes.submit(peer, from: "peer")
        var hookCalls = 0
        routes.intentHook = { _ in hookCalls += 1 }
        routes.captureHook = { _ in hookCalls += 1 }
        let draft = RouteIntent(engine: "draft", advertisedPrefixes: ["192.0.2.0/24"],
                                wantsDefault: false, connectedAt: .distantFuture)
        let expected = RouteArbiter.plan(intents: [peer, draft], policy: RoutePolicy(storedOwner: nil, userChoseDirect: false))
        #expect(routes.preview(replacing: draft) == expected)
        #expect(routes.intents == ["peer": peer])
        #expect(routes.appliedPlan == nil)
        #expect(hookCalls == 0)
    }

    @Test func draftRoutesFollowOrderedFiltersAndIgnoreDefaultDemotes() {
        var custom = CustomRoutingProfile()
        custom.routes.rules = [
            .init(verb: .ignore, match: RoutePrefix("default")),
            .init(verb: .replace, match: RoutePrefix("10.0.0.0/8"), target: RoutePrefix("172.16.0.0/12")),
            .init(verb: .add, target: RoutePrefix("192.0.2.0/24"))
        ]
        let graph = diagram(EditorRoutingDraft(networks: ["10.0.0.0/8"], wantsDefault: true, customRouting: custom))
        let result = graph.lanes.first { $0.id == "routes-draft" }!.stations.last!.details
        #expect(result.contains("172.16.0.0/12"))
        #expect(result.contains("192.0.2.0/24"))
        #expect(!result.contains("10.0.0.0/8"))
        #expect(!result.contains("All otherwise unmatched traffic"))
        #expect(text(graph, lane: "routes-applied").contains("No confirmed route plan yet"))
        #expect(graph.lanes.allSatisfy { $0.observedRate == 0 })
    }

    @Test func dnsDomainAndResolverEditsUpdatePreviewWithoutApplying() {
        let vpn = VPNController()
        var custom = CustomRoutingProfile()
        custom.dns.addMatchDomains = ["grlab.co.uk"]
        let before = EditorRoutingDraft(networks: [], wantsDefault: false,
            resolvers: ["192.168.141.101"], customRouting: custom)
        #expect(text(diagram(before, tab: .dns, vpn: vpn), lane: "dns-draft")
            .contains("grlab.co.uk → 192.168.141.101"))
        var after = before
        after.customRouting.dns.resolverRules = [.init(verb: .replace,
            match: "192.168.141.101", target: "192.0.2.53")]
        #expect(text(diagram(after, tab: .dns, vpn: vpn), lane: "dns-draft")
            .contains("grlab.co.uk → 192.0.2.53"))
        #expect(vpn.dns.intents.isEmpty)
        #expect(vpn.dns.appliedPlan == nil)
        #expect(vpn.routes.intents.isEmpty)
        #expect(vpn.proxies.intents.isEmpty)
    }

    @Test func splitTunnelDoesNotClaimTheInternetOrCatchAllDNS() {
        var config = WireGuardConfig()
        config.allowedIPs = ["192.0.2.0/24"]
        config.dns = ["192.0.2.53"]
        let draft = EditorRoutingDraft.wireGuard(config, customRouting: CustomRoutingProfile())
        #expect(!draft.canOwnDefault)
        let graph = diagram(draft)
        let result = graph.lanes.first { $0.id == "routes-draft" }!.stations.last!.details
        #expect(!result.contains("All otherwise unmatched traffic"))
        #expect(!text(graph, lane: "dns-draft").contains { $0.hasPrefix("All other names →") })
    }

    @Test func neverConnectedServerIsUnknownRatherThanDirectOrApplied() {
        let graph = diagram(.openVPN(OpenVPNOverrides(), server: "vpn.example",
                                    configurationChanged: false, customRouting: CustomRoutingProfile()))
        #expect(text(graph, lane: "routes-draft").contains("Server routes are unknown until connection"))
        #expect(text(graph, lane: "dns-applied").contains("No confirmed DNS plan yet"))
    }

    @Test func invalidDraftIsFlaggedAndDoesNotBecomeApplied() {
        let graph = diagram(EditorRoutingDraft(networks: ["10.0.0.0/99"],
            resolvers: ["not-an-IP"], customRouting: CustomRoutingProfile()))
        for lane in ["routes-draft", "dns-draft"] {
            #expect(graph.lanes.first { $0.id == lane }!.stations.last!.warning)
            #expect(text(graph, lane: lane).contains { $0.hasPrefix("Invalid draft") })
        }
        #expect(text(graph, lane: "dns-applied").contains("No confirmed DNS plan yet"))
    }

    @Test func routingFactsOmitKeysAndSignInMaterial() {
        var config = WireGuardConfig()
        config.privateKey = "PRIVATE-KEY-SENTINEL"
        config.presharedKey = "PSK-SENTINEL"
        config.endpoint = "vpn.example:51820"
        config.allowedIPs = ["198.51.100.0/24"]
        let draft = EditorRoutingDraft.wireGuard(config, customRouting: CustomRoutingProfile())
        let graph = diagram(draft)
        let all = graph.lanes.flatMap(\.stations).flatMap(\.details).joined(separator: " ")
        #expect(all.contains("vpn.example"))
        #expect(!all.contains("SENTINEL"))
        #expect(!EditorRoutingDraft.address("https://vpn.example/login?token=SENTINEL").contains("SENTINEL"))
        #expect(!EditorRoutingDraft.address("https://user:SECRET@vpn.example").contains("SECRET"))
    }

    @Test func sshProxyDisabledDraftDoesNotReusePreviouslySuppliedProxy() {
        let vpn = VPNController()
        vpn.pushedProxyIntents["railroad-test"] = ProxyIntent(engine: "railroad-test", mode: .manual(
            ProxyEndpoint(scheme: .socks, host: "127.0.0.1", port: 1080)))
        var config = SubprocessTunnelConfig()
        config.setSystemProxy = false
        let graph = diagram(.subprocess(config, customRouting: CustomRoutingProfile()), vpn: vpn)
        #expect(text(graph, lane: "proxy-draft").contains("Direct — no system proxy"))
        #expect(!text(graph, lane: "proxy-draft").contains { $0.contains(":1080") })
    }

    @Test func diagramScopeAndStationIDsAreUnambiguous() {
        for tab in [SettingsTab.settings, .options, .dns, .customRouting, .configuration, .servers] {
            #expect(RoutingRailroadDiagram.includes(tab))
            let graph = diagram(EditorRoutingDraft(networks: [], resolvers: [], customRouting: CustomRoutingProfile()), tab: tab)
            let ids = graph.lanes.flatMap(\.stations).map(\.id)
            #expect(Set(ids).count == ids.count)
            #expect(graph.lanes.contains { $0.id == "dns-draft" } == (tab != .customRouting))
            #expect(graph.lanes.contains { $0.id == "routes-draft" } == (tab != .dns))
        }
        #expect(!RoutingRailroadDiagram.includes(.general))
    }

    @Test func longRouteListsHaveSeparateLanesAndConnectedStations() {
        let vpn = VPNController()
        let draft = EditorRoutingDraft(networks: (1...100).map { "10.\($0).0.0/16" },
                                       resolvers: [], customRouting: CustomRoutingProfile())
        let graph = diagram(draft, vpn: vpn)
        let layout = RouteGraphView(vpn: vpn, editorGraph: graph).editorLayout(graph)
        #expect(layout.nodes.count == graph.lanes.flatMap(\.stations).count)
        #expect(layout.edges.count == graph.lanes.reduce(0) { $0 + max(0, $1.stations.count - 1) })
        for (index, node) in layout.nodes.enumerated() {
            #expect(node.frame.maxX <= layout.canvas.width)
            #expect(node.frame.maxY <= layout.canvas.height)
            #expect(!layout.nodes.dropFirst(index + 1).contains { $0.frame.intersects(node.frame) })
        }
    }

    @Test func editorRotorsOnlyTargetRenderedStationsAndWarnings() {
        let vpn = VPNController()
        let graph = diagram(EditorRoutingDraft(networks: ["invalid"], resolvers: [],
            customRouting: CustomRoutingProfile()), vpn: vpn)
        let view = RouteGraphView(vpn: vpn, editorGraph: graph)
        let layout = view.editorLayout(graph)
        let targets = view.railroadRotorTargets(layout)
        #expect(targets.count == layout.nodes.count)
        #expect(Set(targets.map(\.id)).count == targets.count)
        let warnings = view.railroadRotorTargets(layout, warningsOnly: true)
        #expect(!warnings.isEmpty)
        #expect(warnings.allSatisfy { warning in targets.contains { $0.id == warning.id } })
        #expect(warnings.allSatisfy { $0.label.contains("preview") || $0.label.contains("policy") })
    }
}
