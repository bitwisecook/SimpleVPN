// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNKind.swift
//  The protocol family of a saved VPN identifies its editor, importer and
//  connection settings. The selected mode determines the routing attachment.
//  Older packet profiles without providerConfiguration["vpnType"] use OpenVPN.
//

import Foundation

nonisolated enum VPNKind: String, Codable, Sendable, CaseIterable {
    case openVPN   = "openvpn"     // OpenVPN 3 engine in our packet-tunnel sysext
    case wireGuard = "wireguard"   // wireguard-go, in-process in our packet-tunnel sysext
    case ikev2     = "ikev2"       // Built-in IPsec provider for app-initiated connections
    case ipsec     = "ipsec"       // IKEv1, including Cisco-style XAuth
    case l2tp      = "l2tp"        // L2TP and PPP over IPsec
    case ssh       = "ssh"         // one SSH kind: SOCKS (-D), port forwards (-L/-R), or network tunnel (-w)
    case fortinet  = "fortinet"    // FortiGate SSL VPN (OpenConnect --protocol=fortinet)
    case f5apm     = "f5apm"       // F5 BIG-IP APM SSL VPN (OpenConnect --protocol=f5)
    case ciscoAnyConnect = "cisco" // Cisco AnyConnect / ocserv (OpenConnect --protocol=anyconnect)
    case globalProtect = "globalprotect" // Palo Alto GlobalProtect (OpenConnect --protocol=gp)
    case juniper   = "juniper"     // Juniper Network Connect / oNCP (OpenConnect --protocol=nc)
    case pulse     = "pulse"       // Pulse Connect Secure (OpenConnect --protocol=pulse)
    case arrayNetworks = "array"   // Array Networks SSL VPN (OpenConnect --protocol=array)
    // One kind, two control planes: Headscale is this engine pointed at a
    // self-hosted server, so it is a preset inside the editor — NOT a kind.
    case tailscale = "tailscale"   // Tailscale / Headscale mesh, in-process in our packet-tunnel sysext
    // One kind, three schemes: the upstream URL's scheme (socks5/http/https)
    // distinguishes SOCKS from CONNECT — a preset in the editor, NOT a kind
    // (the "Headscale rule").
    case proxyTunnel = "proxytunnel" // tun2socks: utun+routes, every flow dialled through a SOCKS5/HTTP(S) proxy, in-process
    // The SSH Network Tunnel terminates TCP locally and opens a direct-tcpip
    // channel for each flow. A point-to-point tunnel in an SSH profile carries
    // the original IP packets on a tun@openssh.com channel.
    case sshNetworkTunnel = "sshnet" // utun+routes, one SSH direct-tcpip channel per flow, in-process (TCP only)

    func configuredDisplayName(usesTeleport: Bool) -> String {
        self == .wireGuard && usesTeleport ? "UniFi Teleport" : displayName
    }

    var displayName: String {
        switch self {
        case .openVPN: "OpenVPN"
        case .wireGuard: "WireGuard"
        case .ikev2: "IKEv2"
        case .ipsec: "IPsec (IKEv1)"
        case .l2tp: "L2TP / IPsec"
        case .ssh: "SSH"
        case .fortinet: "FortiGate SSL VPN"
        case .f5apm: "F5 BIG-IP APM"
        case .ciscoAnyConnect: "Cisco AnyConnect"
        case .globalProtect: "Palo Alto GlobalProtect"
        case .juniper: "Juniper Network Connect"
        case .pulse: "Pulse Connect Secure"
        case .arrayNetworks: "Array Networks SSL VPN"
        case .tailscale: "Tailscale / Headscale"
        case .proxyTunnel: "Proxy Tunnel"
        case .sshNetworkTunnel: "SSH Network Tunnel"
        }
    }

    var systemImage: String {
        switch self {
        case .openVPN, .wireGuard: "lock.shield"
        case .ikev2, .ipsec, .l2tp: "lock.icloud"
        case .ssh: "terminal"
        case .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks: "building.2"
        case .tailscale: "point.3.connected.trianglepath.dotted"   // a mesh, not a hub-and-spoke
        case .proxyTunnel: "arrow.triangle.branch"                  // flows fanned out through a proxy
        // A terminal (SSH) inside a tunnel: the same transport as `.ssh`, but
        // carrying a network rather than a port.
        case .sshNetworkTunnel: "point.topleft.down.to.point.bottomright.curvepath"
        }
    }

    /// The OpenConnect `--protocol` token for the SSL-VPN kinds (nil otherwise).
    /// One source of truth for the subprocess argv, the in-process bridge, and the
    /// endpoint importer/discovery.
    var openconnectProtocol: String? {
        switch self {
        case .fortinet: "fortinet"
        case .f5apm: "f5"
        case .ciscoAnyConnect: "anyconnect"
        case .globalProtect: "gp"
        case .juniper: "nc"
        case .pulse: "pulse"
        case .arrayNetworks: "array"
        default: nil
        }
    }

    /// True for the OpenConnect-driven SSL-VPN kinds.
    var isSSLVPN: Bool { openconnectProtocol != nil }

    /// How this kind is carried on the Mac.
    enum Transport { case packetTunnel, nativePersonalVPN, subprocess }
    var transport: Transport {
        switch self {
        case .openVPN, .wireGuard, .tailscale, .proxyTunnel, .sshNetworkTunnel: .packetTunnel
        case .ikev2, .ipsec, .l2tp: .nativePersonalVPN
        case .ssh: .subprocess
        // The OpenConnect SSL-VPN kinds. NOTE for the next kind added: this
        // `default` is a trap — a new packet-tunnel kind that is not named on the
        // first line silently becomes a subprocess, with no compiler error, and
        // every engine-dispatch seam then looks for a CLI that was never meant to
        // run it. Name it explicitly above.
        default: .subprocess
        }
    }

    /// Native personal-VPN kinds share one NEVPNManager.shared() — only one such
    /// configuration can exist at a time (an OS limit, not ours).
    var isSingletonNative: Bool { transport == .nativePersonalVPN }
}

extension VPNKind {
    /// These SSL VPN packet protocols have verified the shared physical carrier and return path.
    nonisolated var supportsSharedOpenConnect: Bool {
        switch self {
        case .ciscoAnyConnect, .globalProtect, .fortinet, .f5apm, .juniper, .pulse, .arrayNetworks: true
        default: false
        }
    }
}
