// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

struct VirtualRoutingConfigTests {
    @Test func lossOfDefaultEgressRetainsCaptureUntilExplicitDirect() throws {
        let previous = VirtualRoutingPolicy(defaultOwner: "a")
        let unavailable = VirtualRouteApplyRequest(owner: "", retainUnavailableDefault: true, routes: [:]).applying(to: previous)
        #expect(unavailable.defaultOwner.isEmpty && unavailable.capturesDefault)
        let config = VirtualRoutingConfig(id: "composition", members: [member("a"), member("b")], policy: previous)
        let settings = try #require(config.settings(policy: unavailable, endpoints: ["192.0.2.1:51820"], dns: nil))
        #expect(settings.ipv4Settings?.includedRoutes?.contains { $0.destinationSubnetMask == "0.0.0.0" } == true)
        #expect(settings.ipv6Settings?.includedRoutes?.contains { $0.destinationNetworkPrefixLength.intValue == 0 } == true)
        let direct = VirtualRouteApplyRequest(owner: "", retainUnavailableDefault: false, routes: [:]).applying(to: unavailable)
        #expect(!direct.capturesDefault)
        let splitOnly = VirtualRouteApplyRequest(owner: "", retainUnavailableDefault: true, routes: [:]).applying(to: .init())
        #expect(!splitOnly.capturesDefault)
    }
    private func member(_ id: String, dns: [String] = []) -> VirtualRoutingConfig.Member {
        var config = WireGuardConfig()
        config.id = id; config.name = id
        config.addresses = ["10.0.0.2/32"]
        config.peerPublicKey = Data(repeating: 17, count: 32).base64EncodedString()
        config.endpoint = "192.0.2.1:51820"
        config.dns = dns
        config.allowedIPs = ["0.0.0.0/0"]
        return .init(id: id, wireGuard: config, prefixes: ["10.0.0.0/8"])
    }
    @Test func overlappingVPNAddressesDoNotChangeCaptureAddresses() throws {
        let config = VirtualRoutingConfig(id: "composition", members: [member("a"), member("b")],
            policy: .init(defaultOwner: "a"))
        #expect(config.problem == nil)
        let settings = try #require(config.settings(policy: config.policy,
            endpoints: ["192.0.2.1:51820", "[2001:db8::2]:51820"], dns: nil))
        #expect(settings.ipv4Settings?.addresses == [VirtualRoutingConfig.captureAddresses[0]])
        #expect(settings.ipv6Settings?.addresses == [VirtualRoutingConfig.captureAddresses[1]])
        #expect(settings.ipv4Settings?.includedRoutes?.contains { $0.destinationSubnetMask == "0.0.0.0" } == true)
        #expect(settings.ipv6Settings?.includedRoutes?.contains { $0.destinationNetworkPrefixLength.intValue == 0 } == true)
        #expect(settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress) == ["192.0.2.1"])
        #expect(settings.ipv6Settings?.excludedRoutes?.map(\.destinationAddress) == ["2001:db8::2"])
        #expect(settings.mtu == 1280)
        #expect(config.settings(policy: config.policy, endpoints: ["unresolved.example:51820"], dns: nil) == nil)
    }
    @Test func refusesCredentialsInPersistenceConflictingCaptureAndDistinctResolvers() throws {
        var config = VirtualRoutingConfig(id: "composition", members: [member("a"), member("b")], policy: .init(defaultOwner: "a"))
        config.members[0].wireGuard.privateKey = "private material"
        #expect(config.problem != nil)
        config.members[0] = member("a")
        config.members[0].wireGuard.addresses = [VirtualRoutingConfig.captureAddresses[0] + "/32"]
        #expect(config.problem != nil)
        config.members = [member("a", dns: ["10.0.0.53"]), member("b", dns: ["10.0.0.54"])]
        #expect(config.problem?.contains("different DNS") == true)
        config.members[1] = member("b", dns: ["10.0.0.53"])
        #expect(config.problem == nil)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any])
        #expect(object["routingStart"] == nil)
        config.policy.defaultOwner = ""
        #expect(config.problem != nil)
    }
}
