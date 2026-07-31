// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNKind.swift
//  The protocol family of a saved VPN. Each kind adds a branch at the dispatch
//  seams: which transport runs it (NETunnelProviderManager+engine, the native
//  NEVPNManager personal VPN, or a managed subprocess), which editor form is
//  shown, which importer handles a payload, and which connect flow runs. Stored
//  in providerConfiguration["vpnType"] (or the SSH/native store); absent means
//  .openVPN (profiles saved before the field existed).
//

import Foundation

nonisolated enum VPNKind: String, Codable, Sendable, CaseIterable {
    case openVPN   = "openvpn"     // OpenVPN 3 engine in our packet-tunnel sysext
    case wireGuard = "wireguard"   // WireGuardKit in a packet-tunnel provider
    case ikev2     = "ikev2"       // native NEVPNProtocolIKEv2 (personal VPN)
    case ipsec     = "ipsec"       // native NEVPNProtocolIPSec (Cisco-style)
    case l2tp      = "l2tp"         // native L2TP/IPsec (NEVPNProtocolIPSec + L2TP)
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
        }
    }

    var systemImage: String {
        switch self {
        case .openVPN, .wireGuard: "lock.shield"
        case .ikev2, .ipsec, .l2tp: "lock.icloud"
        case .ssh: "terminal"
        case .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks: "building.2"
        case .tailscale: "point.3.connected.trianglepath.dotted"   // a mesh, not a hub-and-spoke
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
        case .openVPN, .wireGuard, .tailscale: .packetTunnel
        case .ikev2, .ipsec, .l2tp: .nativePersonalVPN
        case .ssh: .subprocess
        default: .subprocess   // the OpenConnect SSL-VPN kinds
        }
    }

    /// Native personal-VPN kinds share one NEVPNManager.shared() — only one such
    /// configuration can exist at a time (an OS limit, not ours).
    var isSingletonNative: Bool { transport == .nativePersonalVPN }
}
