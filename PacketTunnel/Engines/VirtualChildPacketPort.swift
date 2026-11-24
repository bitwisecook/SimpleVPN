// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Network

/// A child authenticates its carrier without reading the host interface or applying OS settings.
protocol VirtualChildPacketPort: AnyObject, Sendable {
    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void)
    func send(_ packet: Data) -> Bool
    func message(_ request: String) -> Data?
    func stop(completion: @escaping @Sendable () -> Void)
}

extension VirtualChildPacketPort {
    func message(_ request: String) -> Data? { nil }
}

nonisolated struct VirtualPortNegotiation: Sendable {
    var addresses: [String]
    var allowed: [String]
    var endpoints: [String]
    var dns: [String]
    var searchDomains: [String]
    var mtu: Int
    var exitNodeID: String? = nil
    var matchDomains: [String]? = nil

    var problem: String? { problem(physicallyBoundMesh: false) }

    func problem(physicallyBoundMesh: Bool) -> String? {
        guard (1280...65535).contains(mtu), (1...16).contains(addresses.count),
              addresses.allSatisfy(VirtualRoutingConfig.usableMemberAddress), (1...256).contains(allowed.count), allowed.allSatisfy({ TailscaleNetworkSettings.parse($0) != nil }),
              (physicallyBoundMesh ? (0...16) : (1...16)).contains(endpoints.count), endpoints.allSatisfy({ endpoint in
                  var config = WireGuardConfig(); config.endpoint = endpoint
                  return WireGuardConfig.endpointProblem(endpoint) == nil && WireGuardConfig.isIPLiteral(config.endpointHost)
              }), dns.count <= 16, dns.allSatisfy(WireGuardConfig.isIPLiteral),
              DNSSearchDomains.problem(list: searchDomains) == nil,
              DNSSearchDomains.problem(list: (matchDomains ?? []).filter { !$0.isEmpty }) == nil else {
            return "The child VPN supplied incompatible addresses, routes, DNS, endpoint or MTU."
        }
        return nil
    }
}
