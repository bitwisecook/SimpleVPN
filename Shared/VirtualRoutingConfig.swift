// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NetworkExtension
import Network

/// Persisted capture configuration. Member credentials are deliberately absent;
/// the separate start payload exists only in startTunnel's in-memory options.
nonisolated struct VirtualRoutingConfig: Codable, Sendable, Equatable {
    struct Member: Codable, Sendable, Equatable {
        var id: String
        var wireGuard: WireGuardConfig?
        var proxy: ProxyTunnelConfig?
        var ownedIPsec: OwnedIPsecConfiguration?
        var openVPN: Bool?
        var openConnect: VPNKind?
        var eventSource: String?
        var adapter: String?
        var vpnKind: String?
        var sshTun: SSHTunConfiguration?
        var sshNetwork: SSHNetworkTunnelConfig?
        var tailscale: TailscaleConfig?
        var prefixes: [String]
        var routeFilter: RouteFilter?
        var dnsFilter: DNSCustomization?
        var externalAdapter: String? {
            if openConnect?.isSSLVPN == true { return "openconnect-packet" }
            if openVPN == true { return "openvpn3" }
            if sshTun != nil { return "ssh-tun" }
            if sshNetwork != nil { return "sshnet" }
            if tailscale != nil { return "tailscale-node" }
            return ownedIPsec?.adapterID
        }
        var transportKind: VPNKind? {
            if let ownedIPsec { return ownedIPsec.kind }
            if proxy != nil { return .proxyTunnel }
            if wireGuard != nil { return .wireGuard }
            if let openConnect { return openConnect }
            if openVPN == true { return .openVPN }
            if tailscale != nil { return .tailscale }
            if sshTun != nil { return .ssh }
            if sshNetwork != nil { return .sshNetworkTunnel }
            return nil
        }
        var transportAdapter: String? {
            externalAdapter ?? transportKind.flatMap { RoutingAdapter.packetID(for: $0, teleport: wireGuard?.usesTeleport == true, proxyScheme: proxy?.scheme) }
        }
        var validProgram: Bool {
            guard let eventSource else { return adapter == nil && vpnKind == nil }
            return !eventSource.isEmpty && eventSource.utf8.count <= 32768 && !eventSource.utf8.contains(0)
                && transportAdapter != nil && adapter == transportAdapter && vpnKind == transportKind?.rawValue
        }
        var dns: [String] { wireGuard?.dns ?? proxy?.dnsServers ?? [] }
        var searchDomains: [String] { wireGuard?.searchDomains ?? proxy?.searchDomains ?? [] }
        func routeIntent(advertised: [String]) -> RouteIntent {
            let hasDefault = !RoutePrefixMath.defaultRoutePrefixes(in: advertised).isEmpty
            let raw = RouteIntent(engine: id, advertisedPrefixes: RoutePrefixMath.specificRoutes(in: advertised),
                                  wantsDefault: hasDefault, canOwnDefault: hasDefault)
            return routeFilter?.apply(to: raw) ?? raw
        }
        var allowed: [String] {
            if let wireGuard { return wireGuard.allowedIPs }
            guard let proxy else { return [] }
            let resolvers = proxy.dnsServers.map { $0 + ($0.contains(":") ? "/128" : "/32") }
            return proxy.includedRoutes + resolvers + (proxy.includeDefaultRoute ? ["0.0.0.0/0", "::/0"] : [])
        }

        var addresses: [String] {
            if let wireGuard { return wireGuard.addresses }
            if externalAdapter != nil { return [] }
            return [ProxyTunnelNetworkSettings.tunnelIPv4 + "/32", ProxyTunnelNetworkSettings.tunnelIPv6 + "/128"]
        }
    }
    var version = 1
    var id: String
    var members: [Member]
    var policy: VirtualRoutingPolicy
    var applicationCapture: VPNApplicationCapture?
    static let captureAddresses = ["198.19.255.1", "fd6e:7853:ffff::1"]

    static func usableMemberAddress(_ value: String) -> Bool {
        guard !value.utf8.contains(0), let local = TailscaleNetworkSettings.parse(WireGuardNetworkSettings.withPrefixLength(value)), local.length > 0 else { return false }
        if local.isIPv6 {
            guard let ip = IPv6Address(local.address), ip.rawValue.contains(where: { $0 != 0 }),
                  ip.rawValue.first != 0xff, ip != IPv6Address("::1"), ip != IPv6Address(captureAddresses[1]) else { return false }
            return !(ip.rawValue.prefix(10).allSatisfy { $0 == 0 } && ip.rawValue[10] == 255 && ip.rawValue[11] == 255)
        }
        guard let ip = IPv4Address(local.address), let first = ip.rawValue.first else { return false }
        return first > 0 && first < 224 && first != 127 && ip != IPv4Address(captureAddresses[0])
    }

    static func requiredVersion(capture: VPNApplicationCapture?, eventSource: String?, usesProxyPorts: Bool = false, usesChildPorts: Bool = false, usesMemberRules: Bool = false, singleDestination: Bool = false, usesFilters: Bool = false) -> Int {
        if usesFilters { return 11 }
        if usesChildPorts && capture != nil { return 10 }
        if singleDestination { return 9 }
        if usesMemberRules { return 8 }
        if usesChildPorts { return 7 }
        if usesProxyPorts { return 6 }
        if capture?.requiresLauncherRules == true { return 5 }
        if capture?.requiresProcessCriteria == true { return 4 }
        if eventSource != nil { return 3 }
        return capture == nil ? 1 : 2
    }

    var wireVersion: Int {
        if version >= 7 { return 3 }
        return members.contains { $0.proxy != nil } ? 2 : 1
    }

    var problem: String? {
        guard version == Self.requiredVersion(capture: applicationCapture, eventSource: policy.eventSource, usesProxyPorts: members.contains { $0.proxy != nil }, usesChildPorts: members.contains { $0.externalAdapter != nil }, usesMemberRules: members.contains { $0.eventSource != nil }, singleDestination: members.count == 1 && applicationCapture == nil, usesFilters: members.contains { $0.routeFilter != nil || $0.dnsFilter != nil }),
              policy.version == (policy.eventSource == nil ? 1 : 2),
              policy.eventSource.map({ !$0.isEmpty && $0.utf8.count <= 32768 && !$0.utf8.contains(0) }) ?? true else { return "This routing configuration requires an updated network extension." }
        guard (1...16).contains(members.count) else { return "Choose between one and sixteen different VPNs." }
        guard Set(members.map(\.id)).count == members.count else { return "Choose each VPN only once." }
        guard policy.defaultOwner.isEmpty || (policy.capturesDefault && members.contains { $0.id == policy.defaultOwner }) else {
            return "The default route must be captured and assigned to a selected VPN."
        }
        if let capture = applicationCapture {
            guard capture.isValid(memberIDs: Set(members.map(\.id))), capture.hasPreparedLauncherRules,
                  policy.sourceRules == capture.sourceRules, policy.defaultOwner.isEmpty,
                  policy.rules.isEmpty, policy.captureDefault == true else {
                return "The app routing rules do not match the selected VPNs."
            }
        } else if policy.sourceRules != nil { return "The app routing configuration is missing." }
        for member in members {
            guard [member.wireGuard != nil, member.proxy != nil, member.ownedIPsec != nil, member.tailscale != nil, member.sshNetwork != nil, member.sshTun != nil, member.openVPN == true, member.openConnect != nil].filter({ $0 }).count == 1 else {
                return "Choose one transport for each VPN port."
            }
            guard member.openVPN != false, member.validProgram else { return "A VPN member’s packet program does not match its transport." }
            guard member.dnsFilter?.nativeSettings == member.dnsFilter,
                  applicationCapture == nil || member.routeFilter?.isIdentity != false else {
                return "The filter does not match this connection’s capture mode."
            }
            if let kind = member.openConnect {
                guard kind.supportsSharedOpenConnect, member.prefixes.isEmpty else { return "This SSL VPN does not support shared packet capture." }
                continue
            }
            if member.openVPN == true {
                guard member.prefixes.isEmpty else { return "The OpenVPN gateway negotiates its routes when connecting." }
                continue
            }
            if let ssh = member.sshTun {
                if let issue = ssh.problem { return issue }
                guard member.prefixes.isEmpty else { return "The SSH tunnel uses the routes in its point-to-point configuration." }
                continue
            }
            if let ssh = member.sshNetwork {
                if let issue = ssh.virtualMemberProblem { return issue }
                guard member.prefixes.isEmpty, ssh.agentSocketPath.isEmpty else { return "SSH member routing or broker data is invalid." }
                continue
            }
            if let mesh = member.tailscale {
                if let issue = mesh.virtualMemberProblem { return issue }
                guard member.prefixes.isEmpty else { return "The tailnet supplies its own routes at connection time." }
                continue
            }
            if let ipsec = member.ownedIPsec {
                guard member.wireGuard == nil, member.proxy == nil, member.id == ipsec.profileID,
                      ipsec.problem == nil, WireGuardConfig.isIPLiteral(ipsec.server), member.prefixes.isEmpty else {
                    return "A shared IPsec port requires an exact authenticated configuration and numeric gateway. Routes are negotiated when connecting."
                }
                continue
            }
            guard member.prefixes.allSatisfy({ RoutePrefixMath.canonicalNetwork($0) != nil }) else { return "A VPN has an invalid routing prefix." }
            if let proxy = member.proxy {
                guard member.wireGuard == nil else { return "A VPN port cannot have two transports." }
                if let issue = proxy.virtualMemberProblem { return issue }
                continue
            }
            guard let config = member.wireGuard else { return "A VPN port is missing its transport." }
            if config.addresses.contains(where: { $0.contains(":") }),
               (config.mtu ?? WireGuardStartConfig.defaultMTU) < 1280 {
                return "An IPv6 VPN needs an MTU of at least 1280 for this virtual connection."
            }
            if let problem = config.connectProblem { return "\(config.name): \(problem)" }
            guard config.privateKey.isEmpty, config.presharedKey.isEmpty else {
                return "VPN credentials must be supplied separately from the saved composition."
            }
            guard config.rawExtraPeers.isEmpty else { return "Multiple WireGuard peers are unavailable in a virtual connection." }
            guard config.addresses.allSatisfy({ value in
                guard let address = TailscaleNetworkSettings.parse(value) else { return false }
                return !Self.captureAddresses.contains(address.address)
            }) else { return "A VPN address conflicts with the virtual connection." }
        }
        let known = members.filter { $0.externalAdapter == nil && $0.wireGuard?.usesTeleport != true }
        if applicationCapture != nil {
            let settings = known.map { member in
                appDNSRequest(member: member, servers: member.dns, searches: member.searchDomains, scopes: nil)
            }
            if let first = settings.first, settings.contains(where: { $0 != first }) {
                return "The selected apps need the same DNS settings on each VPN."
            }
        } else {
            let intents = known.map { dnsIntent(for: $0) }
            let requests = DNSArbiter.plan(intents: intents, policy: .init(defaultOwner: policy.defaultOwner)).applyRequests()
            if let problem = dnsProblem(requests, capturesDefault: policy.capturesDefault) { return problem }
        }
        return nil
    }

    /// A per-app manager publishes one resolver configuration for all selected
    /// applications. Resolve profile defaults against authenticated replies first.
    func applicationDNS(servers: [String: [String]], searches: [String: [String]], scopes: [String: [String]] = [:]) -> DNSApplyRequest? {
        let settings = members.map { member in
            appDNSRequest(member: member, servers: servers[member.id] ?? member.dns,
                          searches: searches[member.id] ?? member.searchDomains, scopes: scopes[member.id])
        }
        guard applicationCapture != nil, let first = settings.first, settings.allSatisfy({ $0 == first }),
              first.isValid else { return nil }
        return first
    }

    private func appDNSRequest(member: Member, servers: [String], searches: [String], scopes: [String]?) -> DNSApplyRequest {
        let intent = dnsIntent(for: member, servers: servers, searches: searches, scopes: scopes)
        return .init(servers: intent.resolvers, searchDomains: intent.searchDomains,
                     matchDomains: intent.wantsCatchAll ? [""] + intent.specificDomains : intent.matchDomains)
    }

    func dnsIntent(for member: Member, servers: [String]? = nil, searches: [String]? = nil,
                   scopes: [String]? = nil, filter: DNSCustomization? = nil) -> DNSIntent {
        let addresses = servers ?? member.dns
        let search = searches ?? member.searchDomains
        let raw = DNSIntent(engine: member.id, resolvers: addresses, searchDomains: search,
                            matchDomains: scopes ?? search, wantsCatchAll: scopes.map { $0.isEmpty || $0.contains("") } ?? true)
        return (filter ?? member.dnsFilter)?.apply(to: raw) ?? raw
    }

    func dnsProblem(_ requests: [String: DNSApplyRequest], capturesDefault: Bool = false) -> String? {
        guard requests.allSatisfy({ id, request in members.contains { $0.id == id } && request.isValid }) else {
            return "The virtual connection received an invalid DNS plan."
        }
        if requests.values.filter({ !$0.servers.isEmpty }).count > 1 {
            return "This virtual interface cannot bind DNS scopes to different VPN members. Use independent connections for those DNS scopes."
        }
        if capturesDefault, requests.values.contains(where: \.isScoped) {
            return "macOS applies the full tunnel’s DNS to every name. Use a split tunnel for scoped-only DNS."
        }
        return nil
    }

    /// Keep private suffixes captured when a participant loses transport. An
    /// explicit gateway change can withdraw its former catch-all independently.
    static func stoppedDNSScopes(_ current: [String: DNSApplyRequest], stopped: Set<String>) -> [String: DNSApplyRequest] {
        var protected: [String: DNSApplyRequest] = [:]
        for (id, request) in current where stopped.contains(id) && !request.isEmpty {
            let scopes = request.matchDomains.filter { !$0.isEmpty }
            guard !scopes.isEmpty else { continue }
            protected[id] = .init(servers: request.servers, searchDomains: request.searchDomains,
                                  matchDomains: scopes, matchDomainsNoSearch: true)
        }
        return protected
    }

    /// A second active interface may still own the default. Start with only
    /// member prefixes until the mediator confirms the previous owner's demotion.
    func initialPolicy(gatewayOwned: Bool) -> VirtualRoutingPolicy {
        guard applicationCapture == nil, !gatewayOwned, policy.capturesDefault else { return policy }
        var initial = policy
        initial.defaultOwner = ""
        initial.captureDefault = false
        initial.rules = members.flatMap { member in
            RoutePrefixMath.specificRoutes(in: member.prefixes)
                .map { .init(prefix: $0, port: member.id) }
        }
        return initial
    }

    /// Capture and forward with the same ordered claims. A stopped member still
    /// owns its private prefixes. Its missing egress drops matching new flows.
    func withMemberRoutes(_ policy: VirtualRoutingPolicy, prefixes: [String: [String]],
                          dns: [String: DNSApplyRequest]) -> VirtualRoutingPolicy {
        guard applicationCapture == nil else { return policy }
        var next = policy
        next.rules = members.flatMap { member in
            RoutePrefixMath.specificRoutes(in: prefixes[member.id] ?? member.prefixes)
                .map { .init(prefix: $0, port: member.id) }
        }
        if let owner = dns.first(where: { !$0.value.servers.isEmpty }) {
            next.rules.insert(contentsOf: owner.value.servers.compactMap { server in
                RoutePrefixMath.canonicalNetwork(server).map { .init(prefix: $0, port: owner.key) }
            }, at: 0)
        }
        return next
    }

    func settings(policy: VirtualRoutingPolicy, endpoints: [String],
                  dns: DNSApplyRequest?, proxy: NEProxySettings? = nil) -> NEPacketTunnelNetworkSettings? {
        var capture = WireGuardConfig()
        capture.addresses = Self.captureAddresses.map { $0 + ($0.contains(":") ? "/128" : "/32") }
        var included = Set<String>()
        capture.allowedIPs = policy.rules.map(\.prefix).filter { included.insert($0).inserted }
        if policy.capturesDefault { capture.allowedIPs += ["0.0.0.0/0", "::/0"] }
        capture.mtu = 1280
        let excluded = endpoints.compactMap { endpoint -> String? in
            var config = WireGuardConfig()
            config.endpoint = endpoint
            let host = config.endpointHost
            guard WireGuardConfig.isIPLiteral(host) else { return nil }
            return host + (host.contains(":") ? "/128" : "/32")
        }
        let allDynamicallyBound = !members.isEmpty && members.allSatisfy { $0.tailscale != nil }
        let resolverRoutes = Set((dns?.servers ?? []).compactMap { RoutePrefixMath.canonicalNetwork($0) })
        guard excluded.count == endpoints.count, !endpoints.isEmpty || allDynamicallyBound,
              applicationCapture != nil || resolverRoutes.isDisjoint(with: excluded.compactMap { RoutePrefixMath.canonicalNetwork($0) }),
              let settings = WireGuardNetworkSettings.settings(for: capture,
                resolvedEndpoint: endpoints.first ?? Self.captureAddresses[0], proxySettings: proxy, extraExcludedRoutes: excluded) else { return nil }
        if applicationCapture != nil {
            // The provider binds its own carrier to the physical interface. A
            // destination exclusion would also release a selected app's packets.
            settings.ipv4Settings?.excludedRoutes = nil
            settings.ipv6Settings?.excludedRoutes = nil
        }
        settings.dnsSettings = dns?.makeNEDNSSettings()
        return settings
    }
}

extension SSHNetworkTunnelConfig {
    nonisolated var virtualMemberProblem: String? {
        if let issue = connectProblem { return issue }
        guard !normalizedPin.isEmpty else { return "Use Check and Trust in the SSH VPN’s Security settings before sharing its interface." }
        guard WireGuardConfig.isIPLiteral(server), !server.contains("%"), !allowLocalNetworkAccess, excludedRoutes.isEmpty else {
            return "A shared SSH Network Tunnel requires a numeric server and cannot claim local network exclusions."
        }
        guard mtu >= 1280 else { return "A shared SSH Network Tunnel requires an MTU of at least 1280." }
        return nil
    }

    nonisolated func sharedCredentials(options: [String: Data]) throws -> (password: String, key: String, certificate: String) {
        let contents = options.compactMapValues { String(data: $0, encoding: .utf8) }
        let password = contents["password"] ?? "", key = contents["key"] ?? "", certificate = contents["certificate"] ?? ""
        guard contents.count == options.count, Set(contents.keys).isSubset(of: ["password", "key", "certificate"]),
              contents.values.allSatisfy({ !$0.utf8.contains(0) }), needsPrivateKey == !key.isEmpty,
              needsCertificate == !certificate.isEmpty, authMethod != .password || !password.isEmpty,
              authMethod != .agent || password.isEmpty else {
            throw NSError(domain: "SimpleVPN.SharedSSH", code: 1, userInfo: [NSLocalizedDescriptionKey: "Save the credentials required by this SSH VPN’s selected sign-in method."])
        }
        return (password, key, certificate)
    }

    nonisolated var sharedDestinations: [String] {
        var routes = includedRoutes
        if includeDefaultRoute { routes += ["0.0.0.0/0", "::/0"] }
        routes += SSHNetworkTunnelNetworkSettings.resolvers(for: self).map(WireGuardNetworkSettings.withPrefixLength)
        return routes
    }
}

extension TailscaleConfig {
    nonisolated var virtualMemberProblem: String? {
        if let issue = controlURLProblem ?? exitNodeSelectionProblem ?? Self.routesProblem(advertiseRoutes) { return issue }
        if !advertiseRoutes.isEmpty { return "Use an independent tailnet connection to advertise this Mac’s subnets." }
        if useExitNode && exitNodeAllowLANAccess { return "Turn off local network access for a shared tailnet exit node." }
        return nil
    }
}

extension ProxyTunnelConfig {
    nonisolated var virtualMemberProblem: String? {
        if let connectProblem { return connectProblem }
        guard let endpoint = URLComponents(string: upstream), let host = endpoint.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
              WireGuardConfig.isIPLiteral(host), !host.contains("%"), endpoint.user == nil, endpoint.password == nil else {
            return "A shared Proxy Tunnel requires a numeric upstream IP address and separate credentials."
        }
        guard !allowLocalNetworkAccess, excludedRoutes.isEmpty else { return "Local network access and excluded routes require an independent Proxy Tunnel." }
        guard mtu >= 1280 else { return "A shared Proxy Tunnel requires an MTU of at least 1280." }
        return nil
    }
}

nonisolated struct VirtualRoutingPolicy: Codable, Sendable, Equatable {
    struct Rule: Codable, Sendable, Equatable {
        var prefix: String
        var port: String
    }
    var version = 1
    var revision: UInt64 = 1
    var rules: [Rule] = []
    struct SourceRule: Codable, Sendable, Equatable {
        var source: String
        var port: String
        var destinations: [Rule]?
    }
    var sourceRules: [SourceRule]?
    var eventSource: String?
    var defaultOwner: String = ""
    /// nil reads older saved policies. An unavailable egress can retain capture
    /// with no default port; only an explicit Direct choice releases that route.
    var captureDefault: Bool? = nil
    var capturesDefault: Bool { captureDefault ?? !defaultOwner.isEmpty }
}

/// One transaction for every member sharing an interface. A missing owner means
/// either another interface owns the default, explicit Direct, or unavailable VPN.
nonisolated struct VirtualRouteApplyRequest: Codable, Sendable {
    var owner: String
    var retainUnavailableDefault: Bool
    var routes: [String: RouteApplyRequest]
    var dnsFilters: [String: DNSCustomization]?

    func applying(to policy: VirtualRoutingPolicy) -> VirtualRoutingPolicy {
        guard policy.sourceRules == nil else { return policy }
        var next = policy
        next.defaultOwner = owner
        next.captureDefault = !owner.isEmpty || (retainUnavailableDefault && policy.capturesDefault)
        return next
    }
}

nonisolated struct VirtualRoutingStartConfig: Codable, Sendable {
    // This complete profile is an in-memory child start argument. The saved
    // VirtualRoutingConfig carries only the member ID and transport metadata.
    static let openVPNProfileOption = "ovpn"

    struct External: Codable, Sendable {
        let adapter: String
        let generation: UInt64
    }
    struct Member: Codable, Sendable {
        var id: String
        var addresses: [String]
        var wireGuard: WireGuardStartConfig?
        var proxy: ProxyTunnelStartConfig?
        var allowed: [String]?
        var eventSource: String?
        var adapter: String?
        var vpnKind: String?
        var external: External?
        var mtu: Int?
        var exitNodeID: String?
    }
    // Only the Swift provider reads these secrets. Strip them before encoding the Go start payload.
    var childOptions: [String: [String: Data]]?
    var version = 1
    var captureAddresses = VirtualRoutingConfig.captureAddresses
    var underlayInterfaceIndex: UInt32 = 0
    var members: [Member]
    var policy: VirtualRoutingPolicy
    var processTokens: [String: Data]?
}

nonisolated struct VirtualRoutingMessage: Codable, Sendable {
    var profile: String
    var message: String
}

nonisolated struct VirtualRoutingStatus: Codable, Sendable {
    struct Routing: Codable, Sendable {
        var revision: UInt64
        var flows: Int
        var packetsOut: UInt64
        var packetsIn: UInt64
        var drops: [String: UInt64]
    }
    var state: String
    var mtu: Int
    var routing: Routing
    var ports: [String: WireGuardEngineStatus]
}
