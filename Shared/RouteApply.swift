// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NetworkExtension

/// nil restores engine prefixes; [] explicitly removes every specific prefix.
/// Default-route ownership is applied separately, in strip-before-promote order.
nonisolated struct RouteApplyRequest: Codable, Sendable, Equatable {
    var prefixes: [String]? = nil
    var isValid: Bool { prefixes?.allSatisfy { TailscaleNetworkSettings.parse($0) != nil } ?? true }

    func apply(to settings: NEPacketTunnelNetworkSettings) {
        guard let prefixes else { return }
        let parsed = TailscaleNetworkSettings.parseAll(prefixes).filter { !$0.isDefaultRoute }
        if let v4 = settings.ipv4Settings?.copy() as? NEIPv4Settings {
            let routes = v4.includedRoutes ?? []
            let halves = Set(routes.filter { $0.destinationSubnetMask == "128.0.0.0" }.map(\.destinationAddress))
            let hasSplitDefault = halves.isSuperset(of: ["0.0.0.0", "128.0.0.0"])
            let defaults = routes.filter {
                $0.destinationSubnetMask == "0.0.0.0" || (hasSplitDefault &&
                    $0.destinationSubnetMask == "128.0.0.0" && ["0.0.0.0", "128.0.0.0"].contains($0.destinationAddress))
            }
            v4.includedRoutes = defaults + parsed.filter { !$0.isIPv6 }.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.ipv4Mask)
            }
            settings.ipv4Settings = v4
        }
        if let v6 = settings.ipv6Settings?.copy() as? NEIPv6Settings {
            let routes = v6.includedRoutes ?? []
            let halves = Set(routes.filter { $0.destinationNetworkPrefixLength.intValue == 1 }.map(\.destinationAddress))
            let hasSplitDefault = halves.isSuperset(of: ["::", "8000::"])
            let defaults = routes.filter {
                $0.destinationNetworkPrefixLength.intValue == 0 || (hasSplitDefault &&
                    $0.destinationNetworkPrefixLength.intValue == 1 && ["::", "8000::"].contains($0.destinationAddress))
            }
            v6.includedRoutes = defaults + parsed.filter(\.isIPv6).map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.length))
            }
            settings.ipv6Settings = v6
        }
    }
}
