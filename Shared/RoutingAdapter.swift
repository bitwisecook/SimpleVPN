// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// The effective inner-IP boundary of a built-in provider. External OpenConnect
/// and SSH helpers have their own lifecycles and do not expose this boundary.
nonisolated enum RoutingAdapter {
    static func packetID(for kind: VPNKind, teleport: Bool = false, proxyScheme: String? = nil) -> String? {
        switch kind {
        case .openVPN: "openvpn3"
        case .wireGuard: teleport ? "wireguard-teleport" : "wireguard"
        case .tailscale: "tailscale-node"
        case .sshNetworkTunnel: "sshnet"
        case .proxyTunnel:
            switch proxyScheme?.lowercased() {
            case "socks5", "socks5h": "proxy-socks5"
            case "http", "httpconnect": "proxy-http"
            case "https", "httpsconnect": "proxy-https"
            default: nil
            }
        case .ciscoAnyConnect, .fortinet, .f5apm, .globalProtect, .juniper, .pulse, .arrayNetworks: "openconnect-packet"
        case .ikev2, .ipsec, .l2tp, .ssh: nil
        }
    }
}
