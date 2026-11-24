// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

struct VirtualRoutingConfigTests {
    @Test func pairedHalfDefaultsNeverBecomeSpecificClaims() throws {
        let v4Halves = ["0.0.0.0/1", "128.0.0.0/1"]
        let v6Halves = ["0:0:0:0:0:0:0:0/1", "8000::/1"]
        let prefixes = v4Halves + v6Halves + ["10.42.0.0/16"]
        var port = member("a")
        port.prefixes = prefixes
        let config = VirtualRoutingConfig(id: "pair", members: [port, member("b")], policy: .init(defaultOwner: "a"))
        let initial = config.initialPolicy(gatewayOwned: false)
        #expect(!initial.capturesDefault)
        #expect(initial.rules.filter { $0.port == "a" }.map(\.prefix) == ["10.42.0.0/16"])
        let rebuilt = config.withMemberRoutes(initial, prefixes: ["a": prefixes], dns: [:])
        #expect(rebuilt == initial)
        #expect(RoutePrefixMath.specificRoutes(in: [v4Halves[0], v6Halves[1]]) == [v4Halves[0], v6Halves[1]])

        var wireGuard = try #require(port.wireGuard)
        wireGuard.allowedIPs = v4Halves + ["10.42.0.0/16"]
        #expect(wireGuard.isFullTunnel)
        let settings = try #require(WireGuardNetworkSettings.settings(for: wireGuard, resolvedEndpoint: "192.0.2.8:51820", suppressDefaultRoute: true))
        #expect(settings.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["10.42.0.0"])
    }

    @Test func childPortsMustNegotiateUnicastTunnelAddresses() {
        for invalid in ["0.0.0.0/32", "192.0.2.5/0", "239.1.1.1/32", "255.255.255.255/32",
                        "::/128", "ff02::1/128", "::ffff:127.0.0.1/128", "198.19.255.1", "fd6e:7853:ffff:0:0:0:0:1"] {
            #expect(!VirtualRoutingConfig.usableMemberAddress(invalid))
        }
        #expect(VirtualRoutingConfig.usableMemberAddress("192.0.2.17/24"))
        #expect(VirtualRoutingConfig.usableMemberAddress("fd00::3/64"))
    }

    @Test func oneWholeMacMemberRequiresTheOnePortReaderAndRoutingABI() throws {
        var group = VirtualRoutingConfig(id: "single", members: [member("a")], policy: .init(defaultOwner: "a"))
        #expect(group.problem != nil)
        group.version = 9
        #expect(group.problem == nil && group.wireVersion == 3)
        let restored = try JSONDecoder().decode(VirtualRoutingConfig.self, from: JSONEncoder().encode(group))
        #expect(restored == group)
    }

    @Test func negotiatedMembersRequireNewReaderAndAuthenticatedDescriptors() throws {
        let ipsec = OwnedIPsecConfiguration(profileID: "ike", kind: .ikev2, server: "192.0.2.8", localID: "alice", remoteID: "gateway", usesXAuth: false)
        let first = VirtualRoutingConfig.Member(id: "ike", ownedIPsec: ipsec, prefixes: [])
        var second = ipsec
        second.profileID = "other"
        let secondPort = VirtualRoutingConfig.Member(id: "other", ownedIPsec: second, prefixes: [])
        var config = VirtualRoutingConfig(version: 6, id: "shared", members: [first, secondPort], policy: .init(defaultOwner: "ike"))
        #expect(config.problem != nil)
        config.version = 7
        #expect(config.problem == nil)
        #expect(try JSONDecoder().decode(VirtualRoutingConfig.self, from: JSONEncoder().encode(config)) == config)
        config.members[0].prefixes = ["0.0.0.0/0"]
        #expect(config.problem != nil)
        config.members[0] = first
        config.members[0].ownedIPsec?.profileID = "other"
        #expect(config.problem != nil)
        config.members[0] = first
        config.members[0].tailscale = TailscaleConfig()
        #expect(config.problem != nil)
    }

    @Test func perMemberPolicyRequiresItsRealTransportAndACompatibleReader() {
        var config = VirtualRoutingConfig(id: "protected", members: [member("a"), member("b")], policy: .init())
        config.members[0].eventSource = "on tally: ip.packet { count(); }"
        config.members[0].adapter = "wireguard"; config.members[0].vpnKind = VPNKind.wireGuard.rawValue
        #expect(config.problem != nil)
        config.version = 8
        #expect(config.problem == nil)
        config.members[0].adapter = "openvpn3"
        #expect(config.problem != nil)
        config.members[0].adapter = "wireguard"; config.members[0].vpnKind = nil
        #expect(config.problem != nil)
        config.members[0].eventSource = nil
        #expect(config.problem != nil)
    }

    @Test func physicalMeshHasNoSyntheticExcludedPeerAndSSHRequiresExactAuthentication() throws {
        let mesh = TailscaleConfig()
        let ports = ["one", "two"].map { VirtualRoutingConfig.Member(id: $0, tailscale: mesh, prefixes: []) }
        let config = VirtualRoutingConfig(version: 7, id: "mesh", members: ports, policy: .init())
        #expect(config.problem == nil)
        let settings = try #require(config.settings(policy: config.policy, endpoints: [], dns: nil))
        #expect(settings.ipv4Settings?.excludedRoutes?.isEmpty != false)
        #expect(settings.ipv6Settings?.excludedRoutes?.isEmpty != false)
        let ordinary = VirtualRoutingConfig(id: "wg", members: [member("a"), member("b")], policy: .init())
        #expect(ordinary.settings(policy: ordinary.policy, endpoints: [], dns: nil) == nil)
        var ssh = SSHNetworkTunnelConfig()
        ssh.server = "192.0.2.5"; ssh.username = "alice"
        #expect(ssh.virtualMemberProblem != nil)
        ssh.pinnedHostKeySHA256 = String(repeating: "ab", count: 32)
        ssh.allowLocalNetworkAccess = false
        #expect(ssh.virtualMemberProblem == nil)
        #expect(throws: (any Error).self) { try ssh.sharedCredentials(options: [:]) }
        #expect(try ssh.sharedCredentials(options: ["password": Data("example".utf8)]).password == "example")
        ssh.authMethod = .certificate
        #expect(throws: (any Error).self) { try ssh.sharedCredentials(options: ["key": Data("fixture".utf8)]) }
        ssh.authMethod = .agent
        #expect(throws: (any Error).self) { try ssh.sharedCredentials(options: ["password": Data("unused".utf8)]) }
        #expect(try ssh.sharedCredentials(options: [:]).key.isEmpty)
    }

    @Test func mixedPortRequiresNewReaderAndPreservesProxyConfiguration() throws {
        var proxy = ProxyTunnelConfig()
        proxy.upstream = "https://192.0.2.2:443"
        proxy.requiresAuth = true
        proxy.dnsServers = ["192.0.2.53"]
        let port = VirtualRoutingConfig.Member(id: "proxy", proxy: proxy, prefixes: ["192.0.2.0/24"])
        var config = VirtualRoutingConfig(id: "mixed", members: [member("wg"), port],
                                          policy: .init(defaultOwner: "proxy"))
        #expect(config.problem != nil)
        config.version = 6
        #expect(config.problem == nil)
        #expect(try JSONDecoder().decode(VirtualRoutingConfig.self, from: JSONEncoder().encode(config)) == config)
        #expect(port.allowed.contains("192.0.2.53/32"))
        proxy.upstream = "https://proxy.example.test:443"
        #expect(proxy.virtualMemberProblem != nil)
        proxy.upstream = "https://192.0.2.2:443"
        proxy.excludedRoutes = ["10.0.0.0/8"]
        #expect(proxy.virtualMemberProblem != nil)
    }

    @Test func embeddedSSHAdmissionUsesTheRustPlanBeforeAChannelOpens() throws {
        let policy = try SSHForwardPolicy(source: #"""
        on local: ssh.forward_open { if ssh.mode == "dynamic" && ssh.target == "db.internal" && ssh.port == 5432 { drop(); } }
        on all: ssh.forward_open { count(); }
        """#)
        #expect(policy.permits(target: "db.internal", port: 5432, mode: "local"))
        #expect(!policy.permits(target: "db.internal", port: 5432, mode: "dynamic"))
        #expect(policy.permits(target: "other.internal", port: 5432, mode: "dynamic"))
        #expect(policy.counters.map(\.entered) == [3, 2])
        #expect(policy.counters.map(\.denied) == [1, 0])
        #expect(throws: (any Error).self) { try SSHForwardPolicy(source: "on ip: ip.packet { drop(); }") }
    }

    @Test func openConnectCheckerBindsTheReceiptToTheRequestedAdapter() async {
        let source = "on ingress: inbound.ip.packet { if flow.adapter == \"openconnect-packet\" { count(); } }"
        #expect(await RoutingEventValidation.check(source, adapter: "openconnect-packet") == .accepted)
        #expect(await RoutingEventValidation.check(source, adapter: "openconnect-proxy") == .accepted)
        if case .accepted = await RoutingEventValidation.check(source, adapter: "apple-personal") {
            Issue.record("The OS-owned IPsec interface accepted an inner-IP rule.")
        }
    }

    @Test func editorRequiresACurrentNativeValidationReceipt() {
        let receipt = #"{"adapter":"wireguard-shared","version":1,"engine":"rust-aot","handlers":2,"scalarEvents":1,"generalEvents":1}"#
        #expect(RoutingEventValidation.outcome(response: Data(receipt.utf8), status: 0) == .accepted)
        for invalid in ["", "[]", receipt.replacingOccurrences(of: "rust-aot", with: "portable"),
                        receipt.replacingOccurrences(of: "wireguard-shared", with: "wireguard"),
                        receipt.replacingOccurrences(of: #""handlers":2"#, with: #""handlers":1"#)] {
            if case .accepted = RoutingEventValidation.outcome(response: Data(invalid.utf8), status: 0) {
                Issue.record("The editor accepted an incompatible checker response.")
            }
        }
        #expect(RoutingEventValidation.outcome(response: Data("line 3: invalid field".utf8), status: 1)
                == .rejected("line 3: invalid field"))
    }

    @Test func bundledCheckerCompilesTheThreeNativeRulePaths() async {
        for source in ["on clamp tcp.syn => clamp-mss 1200",
                       "on scalar: tcp.syn { if port.server == 443 { ip.dscp = 16; } }",
                       #"on general: tls.client_hello { if ends_with(tls.sni, ".example") { drop(); } }"#] {
            #expect(await RoutingEventValidation.check(source) == .accepted)
        }
        if case .accepted = await RoutingEventValidation.check("on bad: tcp.syn { tls.sni = 0; }") {
            Issue.record("The editor accepted an unavailable write.")
        }
    }

    @Test func memberCountDiagnosticsReflectCaptureMode() {
        var config = VirtualRoutingConfig(id: "example", members: [member("a")], policy: .init())
        #expect(config.problem != nil)
        config.version = 9
        #expect(config.problem == nil)
        config.version = 2
        config.members = []
        config.applicationCapture = .init(routes: [], processRouteIDs: [])
        #expect(config.problem == "Choose between one and sixteen different VPNs.")
        config.members = (0...16).map { member(String($0)) }
        #expect(config.problem == "Choose between one and sixteen different VPNs.")
        config.members = [member("same"), member("same")]
        #expect(config.problem == "Choose each VPN only once.")
    }

    @Test func deferredGatewayKeepsSpecificRoutesAndWithholdsCatchAllDNSUntilPromotion() {
        var config = VirtualRoutingConfig(id: "pair", members: [member("a", dns: ["10.0.0.53"]), member("b")],
                                          policy: .init(defaultOwner: "a"))
        config.members[0].prefixes = ["10.0.0.0/24"]
        config.members[1].prefixes = ["10.0.1.0/24"]
        config.policy.rules = [.init(prefix: "10.0.0.53/32", port: "a")]
        #expect(config.problem == nil)
        let initial = config.initialPolicy(gatewayOwned: false)
        #expect(!initial.capturesDefault && initial.defaultOwner.isEmpty)
        #expect(initial.rules == [.init(prefix: "10.0.0.0/24", port: "a"), .init(prefix: "10.0.1.0/24", port: "b")])
        #expect(config.initialPolicy(gatewayOwned: true) == config.policy)
    }

    @Test func reappliedCaptureAndForwardingPoliciesRetainStoppedMembersPrivateClaims() throws {
        var privateVPN = member("private")
        privateVPN.prefixes = ["10.2.0.0/16", "fd02::/64"]
        var fallback = member("fallback")
        fallback.prefixes = ["10.2.0.0/16"]
        let config = VirtualRoutingConfig(id: "pair", members: [privateVPN, fallback], policy: .init())
        let incoming = VirtualRouteApplyRequest(owner: "fallback", retainUnavailableDefault: false,
                                               routes: ["fallback": .init()])
        // The only live member is the fallback. The stopped member's last
        // applied v6 claim overrides its saved one until the session ends.
        let policy = config.withMemberRoutes(incoming.applying(to: config.policy),
            prefixes: ["private": ["10.2.0.0/16", "fd03::/64"]], dns: [:])
        #expect(policy.rules == [.init(prefix: "10.2.0.0/16", port: "private"),
                                 .init(prefix: "fd03::/64", port: "private"),
                                 .init(prefix: "10.2.0.0/16", port: "fallback")])
        let settings = try #require(config.settings(policy: policy, endpoints: ["192.0.2.1:51820"], dns: nil))
        #expect(settings.ipv4Settings?.includedRoutes?.contains { $0.destinationAddress == "10.2.0.0" } == true)
        #expect(settings.ipv6Settings?.includedRoutes?.contains { $0.destinationAddress == "fd03::" } == true)
    }

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
    @Test func refusesCredentialsInPersistenceAndConflictingCapture() throws {
        var config = VirtualRoutingConfig(id: "composition", members: [member("a"), member("b")], policy: .init(defaultOwner: "a"))
        config.members[0].wireGuard?.privateKey = "private material"
        #expect(config.problem != nil)
        config.members[0] = member("a")
        config.members[0].wireGuard?.addresses = [VirtualRoutingConfig.captureAddresses[0] + "/32"]
        #expect(config.problem != nil)
        config.members = [member("a", dns: ["10.0.0.53"]), member("b", dns: ["10.0.0.54"])]
        #expect(config.problem == nil)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any])
        #expect(object["routingStart"] == nil)
        config.policy.defaultOwner = ""
        #expect(config.problem == nil)
    }

    @Test func negotiatedFiltersAndScopedDNSUseAuthenticatedMemberClaims() throws {
        var vpn = member("office", dns: ["10.2.0.53"])
        var routeFilter = RouteFilter()
        routeFilter.rules = [.init(verb: .ignore, match: .default)]
        vpn.routeFilter = routeFilter
        var dnsFilter = DNSCustomization()
        dnsFilter.addMatchDomains = ["office.example"]
        vpn.dnsFilter = dnsFilter
        let config = VirtualRoutingConfig(version: 11, id: "pair", members: [vpn, member("lab")], policy: .init())
        #expect(config.problem == nil)
        let intent = vpn.routeIntent(advertised: ["10.2.0.0/16", "0.0.0.0/0"])
        #expect(!intent.canOwnDefault && intent.advertisedPrefixes == ["10.2.0.0/16"])
        let dns = DNSArbiter.plan(intents: [config.dnsIntent(for: vpn)], policy: .init(defaultOwner: nil)).applyRequests()
        #expect(dns["office"]?.matchDomains == ["office.example"])
        let policy = config.withMemberRoutes(config.policy, prefixes: ["office": intent.advertisedPrefixes], dns: dns)
        #expect(policy.rules.first == .init(prefix: "10.2.0.53/32", port: "office"))
        #expect(config.dnsProblem(dns) == nil)
        #expect(config.dnsProblem(dns, capturesDefault: true) != nil)
        let conflicting = dns.merging(["lab": .init(servers: ["10.2.0.53"], matchDomains: ["lab.example"])]) { first, _ in first }
        #expect(config.dnsProblem(conflicting) != nil)
        #expect(config.settings(policy: policy, endpoints: ["10.2.0.53:51820"], dns: dns["office"]) == nil)
        let settings = try #require(config.settings(policy: policy, endpoints: ["192.0.2.1:51820"], dns: dns["office"]))
        #expect(settings.dnsSettings?.matchDomains == ["office.example"])
    }

    @Test func stoppedDNSOwnerKeepsPrivateScopesWhenItsCatchAllIsReleased() {
        let office = DNSIntent(engine: "office", resolvers: ["10.2.0.53"], searchDomains: ["office.example"],
                               matchDomains: ["", "office.example"], wantsCatchAll: true)
        let home = DNSIntent(engine: "home", resolvers: ["10.3.0.53"], wantsCatchAll: true)
        let plan = DNSArbiter.plan(intents: [office, home], policy: .init(defaultOwner: "office"))
        let protected = VirtualRoutingConfig.stoppedDNSScopes(plan.applyRequests(), stopped: ["office"])
        #expect(protected == ["office": .init(servers: ["10.2.0.53"], searchDomains: ["office.example"],
                                             matchDomains: ["office.example"], matchDomainsNoSearch: true)])
        let config = VirtualRoutingConfig(id: "pair", members: [member("office"), member("home")], policy: .init())
        let policy = config.withMemberRoutes(config.policy, prefixes: [:], dns: protected)
        #expect(policy.rules.first == .init(prefix: "10.2.0.53/32", port: "office"))
        let scopedOnly = DNSIntent(engine: "office", resolvers: ["10.2.0.53"], matchDomains: ["office.example"])
        let scopedPlan = DNSArbiter.plan(intents: [scopedOnly], policy: .init(defaultOwner: "office"))
        #expect(scopedPlan.catchAllOwner == nil)
        #expect(scopedPlan.applyRequests()["office"]?.isScoped == true)
    }
}
