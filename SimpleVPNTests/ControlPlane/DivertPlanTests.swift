// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DivertPlanTests.swift
//  The divert rules ("send this destination around the VPN" / "route it over
//  that other VPN") used to be decoded and policy-gated inside the extension's
//  OpenVPN branch, so every other kind ignored both halves SILENTLY — the app
//  wrote the blobs for every profile and exactly one engine read them.
//
//  What is pinned here: the policy gates (an MDM escape hatch is the worst thing
//  to get wrong), the CIDR round-trip each kind's `*NetworkSettings` builder
//  consumes, and the per-kind capability table the UI now refuses to lie about
//  (VPNKind.canAcceptRoutedInTraffic / canDivertOutside — a kind that can't
//  carry a routed-in destination must say so, not store a dead rule).
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct DivertPlanTests {

    private static func rule(_ dest: String, _ action: RoutingRule.Action = .outside,
                             enabled: Bool = true) -> RoutingRule {
        RoutingRule(destination: dest, action: action, enabled: enabled)
    }

    @Test func outsideDivertsBecomeCarveOutCIDRs() {
        let plan = DivertPlan.make(rules: [Self.rule("142.250.0.0/16"),
                                           Self.rule("2001:db8::1/128")],
                                   inbound: [], keepInside: false, noDiverts: false)
        #expect(plan.outsideCIDRs == ["142.250.0.0/16", "2001:db8::1/128"])
        #expect(plan.inbound.isEmpty)
        #expect(!plan.isEmpty)
    }

    @Test func disabledMalformedAndDefaultRouteDivertsAreDropped() {
        let plan = DivertPlan.make(rules: [Self.rule("10.0.0.0/8", enabled: false),
                                           Self.rule("not-an-address/24"),
                                           Self.rule("0.0.0.0/0"),      // full bypass
                                           Self.rule("::/0"),           // full bypass
                                           Self.rule("10.1.2.3")],      // bare = /32
                                   inbound: [], keepInside: false, noDiverts: false)
        #expect(plan.outsideCIDRs == ["10.1.2.3/32"])
    }

    @Test func overVPNRulesNeverCarveTheSourceTunnel() {
        // The source side stays INSIDE its tunnel deliberately: excluding it would
        // send that traffic out in cleartext whenever the target VPN is down.
        let plan = DivertPlan.make(rules: [Self.rule("142.250.0.0/16", .overVPN(profileID: "other"))],
                                   inbound: [], keepInside: false, noDiverts: false)
        #expect(plan.outside.isEmpty)
        #expect(plan.isEmpty)
    }

    @Test func forceKeepInsideDropsEveryOutsideDivertButKeepsRoutedInTraffic() {
        let inbound = [RouteDest(address: "10.9.0.0", prefix: 16, ipv6: false)]
        let keepInside = DivertPlan.make(rules: [Self.rule("142.250.0.0/16")],
                                          inbound: inbound, keepInside: true, noDiverts: false)
        #expect(keepInside.outside.isEmpty)          // no traffic may leave the VPN
        #expect(keepInside.inboundCIDRs == ["10.9.0.0/16"])   // still inside *a* VPN
    }

    @Test func disableDivertRulesDropsBothHalves() {
        let plan = DivertPlan.make(rules: [Self.rule("142.250.0.0/16")],
                                   inbound: [RouteDest(address: "10.9.0.0", prefix: 16, ipv6: false)],
                                   keepInside: false, noDiverts: true)
        #expect(plan.isEmpty)
    }

    @Test func planDecodesFromTheProviderConfigurationTheAppWrites() throws {
        let rules = [Self.rule("142.250.0.0/16")]
        let inbound = [RouteDest(address: "10.9.0.0", prefix: 16, ipv6: false)]
        let conf: [String: Any] = ["routingRules": try #require(RoutingRuleStore.encode(rules)),
                                   "routingIncludes": try #require(RouteDestStore.encode(inbound))]
        let plan = DivertPlan.make(providerConfiguration: conf, keepInside: false, noDiverts: false)
        #expect(plan.outsideCIDRs == ["142.250.0.0/16"])
        #expect(plan.inboundCIDRs == ["10.9.0.0/16"])
        // The bridges take dictionaries; same values, same order.
        #expect(plan.outsideDictionaries.first?["address"] as? String == "142.250.0.0")
        #expect(plan.inboundDictionaries.first?["prefix"] as? Int == 16)
    }

    @Test func aMissingBlobIsAnEmptyPlanNotAFailure() {
        let plan = DivertPlan.make(providerConfiguration: nil, keepInside: false, noDiverts: false)
        #expect(plan.isEmpty)
    }

    // MARK: Per-kind capability (what the UI is allowed to offer)

    @Test func everyKindEitherCarriesRoutedInTrafficOrSaysWhyNot() {
        for kind in VPNKind.allCases {
            if kind.canAcceptRoutedInTraffic {
                #expect(kind.routedInUnsupportedReason == nil)
            } else {
                let reason = kind.routedInUnsupportedReason
                #expect(reason?.isEmpty == false, "\(kind.rawValue) refuses routed-in traffic with no reason")
            }
            if kind.canDivertOutside {
                #expect(kind.divertOutsideUnsupportedReason == nil)
            } else {
                #expect(kind.divertOutsideUnsupportedReason?.isEmpty == false)
            }
        }
    }

    @Test func theKindsWeBuildRoutesForAcceptRoutedInTraffic() {
        for kind in [VPNKind.openVPN, .wireGuard, .proxyTunnel, .ciscoAnyConnect, .fortinet, .pulse] {
            #expect(kind.canAcceptRoutedInTraffic, "\(kind.rawValue) should accept routed-in traffic")
        }
    }

    @Test func tailscaleTakesCarveOutsButNotRoutedInTraffic() {
        // A tailnet only carries what the netmap advertises (subnet router / exit
        // node), so an included route for anything else is a black hole — but
        // keeping traffic OUT of it is always well-defined.
        #expect(VPNKind.tailscale.canDivertOutside)
        #expect(!VPNKind.tailscale.canAcceptRoutedInTraffic)
    }

    @Test func theKindsWhoseRoutesWeDoNotOwnRefuseBothHalves() {
        for kind in [VPNKind.ikev2, .ipsec, .l2tp, .ssh] {
            #expect(!kind.canAcceptRoutedInTraffic, "\(kind.rawValue) cannot be routed into")
            #expect(!kind.canDivertOutside, "\(kind.rawValue) cannot be carved out of")
        }
    }

    // MARK: The carve-outs reaching each kind's network settings

    @Test func wireGuardCarvesOutDivertedDestinationsAndCarriesRoutedInOnes() throws {
        var c = WireGuardConfig()
        c.peerPublicKey = "PUBKEY"
        c.endpoint = "vpn.example.com:51820"
        c.addresses = ["10.7.0.2/32"]
        c.allowedIPs = ["0.0.0.0/0"]
        let plan = DivertPlan.make(rules: [Self.rule("142.250.0.0/16")],
                                   inbound: [RouteDest(address: "10.9.0.0", prefix: 16, ipv6: false)],
                                   keepInside: false, noDiverts: false)
        // Routed-in destinations join allowedIPs (the PEER must allow them too, or
        // wireguard-go drops the packet), which is what the provider does at connect.
        c.allowedIPs += plan.inboundCIDRs

        let settings = try #require(WireGuardNetworkSettings.settings(
            for: c, resolvedEndpoint: "198.51.100.7:51820",
            extraExcludedRoutes: plan.outsideCIDRs))
        let v4 = try #require(settings.ipv4Settings)
        #expect(v4.includedRoutes?.contains { $0.destinationAddress == "10.9.0.0" } == true)
        #expect(v4.excludedRoutes?.contains { $0.destinationAddress == "142.250.0.0" } == true)
    }

    @Test func tailscaleCarveOutsJoinTheEnginesOwnLocalRoutes() throws {
        let json = """
        {"localAddrs":["100.64.0.1/32"],"routes":["0.0.0.0/0"],\
        "localRoutes":["192.168.1.0/24"],"mtu":1280,\
        "dns":{"nameservers":[],"searchDomains":[],"matchDomains":[]}}
        """
        let config = try #require(TailscaleTunnelConfig.decode(json: json))
        let plan = DivertPlan.make(rules: [Self.rule("142.250.0.0/16")],
                                   inbound: [], keepInside: false, noDiverts: false)
        let settings = try #require(TailscaleNetworkSettings.settings(
            for: config, extraExcludedRoutes: plan.outsideCIDRs))
        let excluded = try #require(settings.ipv4Settings?.excludedRoutes).map(\.destinationAddress)
        #expect(excluded.contains("192.168.1.0"))    // the engine's own carve-out
        #expect(excluded.contains("142.250.0.0"))    // …and the user's divert
    }
}
