// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LocalNetworkCarveOut.swift
//  THE one definition of "the local network" — the prefixes that leave a tunnel
//  when a VPN is told to allow local network access (ONTOLOGY.md's binding term).
//
//  WHY THIS IS NOT `excludeLocalNetworks`. That property lives on `NEVPNProtocol`
//  (inherited by `NETunnelProviderProtocol`) and the SDK ties it to the OTHER
//  property: `includeAllNetworks`'s own documentation calls the excludeLocalNetworks
//  / excludeAPNs / excludeCellularServices family "exclusions" from the traffic
//  `includeAllNetworks` captures. `NEPacketTunnelNetworkSettings` has no
//  local-networks property at all. Our packet-tunnel kinds do not set
//  `includeAllNetworks` — a full tunnel here is `NEIPv4Route.default()` in
//  `includedRoutes` (Docs/Networking.md §4.1) — so setting `excludeLocalNetworks`
//  on them would be a property with nothing to modify: a control that reads as
//  protection and changes no packet's path. For our own tunnels the carve-out has
//  to be REAL ROUTES, computed from the interfaces this Mac is actually on.
//
//  THE SAME DECISION, ONE PLACE, THREE SEAMS. The prefixes computed here reach
//  each kind through the seam that kind already has for connect-time carve-outs
//  (Docs/Networking.md §4.3), never through a second mechanism:
//    • OpenVPN — returned from `tun_builder_get_local_networks`, which is exactly
//      what openvpn3 asks the tun builder for when `allowLocalLanAccess` is on
//      (Vendor/openvpn3-include/openvpn/tun/client/tunprop.hpp). The engine turns
//      them into `net_gateway` routes itself.
//    • WireGuard / Proxy Tunnel / SSH Network Tunnel — appended to the session's
//      `extraExcludedRoutes`, beside the tunnel's own carrier address and the
//      `.outside` diverts, and therefore re-passed by every live re-apply.
//    • native IKEv2/IPsec/L2TP — NOT here: those are `excludeLocalNetworks`, where
//      the property is honoured because macOS owns the routing table.
//
//  COMPUTED IN THE APP, PASSED IN THE SESSION. The list rides
//  `startTunnel(options:)` like every other connect-time decision the app makes on
//  the extension's behalf (`gatewayOwned`, `sshExpectedHostKeySHA256`,
//  `policyKeepInside`). The app is unsandboxed and already enumerates interfaces;
//  the extension is sandboxed, and a carve-out that silently came back empty there
//  would be this feature's original bug all over again. Absence therefore means NO
//  CARVE-OUT — the fail-closed direction: traffic stays in the tunnel.
//
//  WIDTH IS THE WHOLE SAFETY ARGUMENT. Every prefix is either one of the fixed
//  link-local/multicast ranges below or a prefix THIS MAC IS ITSELF ON, masked to
//  its network address. Nothing is inferred from RFC 1918: "you might have a
//  10.0.0.0/8 somewhere" is not evidence, and a carve-out wider than the truth
//  sends traffic outside the tunnel that the user believes is inside it.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

nonisolated enum LocalNetworkCarveOut {

    /// The startTunnel option the app passes and the extension reads.
    static let optionKey = "localNetworks"

    /// Ranges that are local by definition rather than by configuration, and the
    /// ones a route-based carve-out most needs, because an on-link prefix already
    /// beats a default route on longest-prefix match while these do not:
    ///
    ///  • `169.254.0.0/16` / `fe80::/10` — link-local. Never routable off-link.
    ///  • `224.0.0.0/4` / `ff00::/8` — multicast, which is how a Mac finds printers,
    ///    AirPlay targets and file shares (mDNS lives at `224.0.0.251`). Captured by
    ///    a default route, and the reason "the VPN broke Bonjour" is a real report.
    ///  • `255.255.255.255/32` — limited broadcast.
    ///
    /// Deliberately NOT here: `127.0.0.0/8` and `::1/128`, because loopback never
    /// reaches an interface and an excluded route for it buys nothing.
    static let fixedPrefixes = [
        "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "fe80::/10", "ff00::/8",
    ]

    /// The narrowest v4/v6 prefix widths a carve-out will accept. A `/0` is the
    /// default route — carving that out is a full VPN bypass and exactly what
    /// `RoutingRule.routeDest` refuses for the same reason. The floors above zero
    /// reject a nonsense netmask (a `/3` is not a local network, it is an eighth of
    /// the internet) rather than trusting whatever an interface reports.
    static let ipv4PrefixFloor = 8
    static let ipv6PrefixFloor = 16

    /// One interface's local prefixes, as the pure input to `prefixes(of:)`.
    /// Deliberately a value type with no `getifaddrs` in it, so what counts as a
    /// local network is decided by a unit-tested function rather than by whatever
    /// the test machine happens to be plugged into.
    nonisolated struct Interface: Sendable, Equatable {
        /// BSD name — `en0`, `bridge0`, `utun4`.
        var name: String
        /// The networks this interface is on, as CIDRs, either family. Host bits
        /// are allowed here: they are masked off below.
        var subnets: [String]

        init(name: String, subnets: [String]) {
            self.name = name
            self.subnets = subnets
        }
    }

    /// Whether an interface's own networks belong in the carve-out, decided by BSD
    /// name alone so the rule is readable and needs no SystemConfiguration.
    ///
    /// Excluded, each for its own reason:
    ///  • `utun*` / `ipsec*` / `tun*` — a TUNNEL's networks. Carving another VPN's
    ///    subnet out of this one is not "local network access", and carving out our
    ///    own would hole the tunnel we are building.
    ///  • `lo*` — loopback, which never leaves.
    ///  • `awdl*` / `llw*` / `anpi*` / `ap*` / `gif*` / `stf*` / `pktap*` — Apple
    ///    Wireless Direct, low-latency WLAN, internal management links and tunnel
    ///    shims. Not networks a person has devices on.
    ///  • `vmenet*` / `vnic*` / `vboxnet*` / `vmnet*`, and `bridge100`+ — VIRTUAL
    ///    MACHINE and container networks. Those have their own consent flow with
    ///    its own explanation (Docs/LocalVirtualNetworks.md, Docs/Networking.md §6),
    ///    which offers one guest network at a time and says what it will do. Folding
    ///    them into this toggle would widen a carve-out the user asked for on their
    ///    printer's behalf to include every guest they happen to be running.
    ///
    /// `bridge0` IS included: it is the ordinary user-configurable
    /// Thunderbolt/Ethernet bridge, so it is a real LAN. macOS allocates vmnet
    /// bridges from `bridge100` upwards, which is the same numbering discriminator
    /// `VirtualizationDiscovery` relies on — read the two rules together: this one
    /// takes exactly the bridges that one rejects.
    static func isLocalNetworkInterface(_ name: String) -> Bool {
        for prefix in ["utun", "ipsec", "tun", "lo", "awdl", "llw", "anpi", "ap",
                       "gif", "stf", "pktap", "vmenet", "vnic", "vboxnet", "vmnet"]
        where name.hasPrefix(prefix) { return false }
        if name.hasPrefix("bridge"),
           let number = Int(name.dropFirst("bridge".count)), number >= 100 { return false }
        return true
    }

    /// The carve-out for a set of interfaces: the fixed ranges plus every accepted
    /// interface network, masked to its network address, de-duplicated, in a stable
    /// order (fixed ranges first, then interface order).
    ///
    /// A subnet that cannot be parsed, is narrower than the floors above, or masks
    /// to nothing usable is DROPPED, not widened — the same "losing one route beats
    /// losing the tunnel" rule the settings builders use, with the extra property
    /// that dropping here always means *more* traffic stays inside the tunnel.
    static func prefixes(of interfaces: [Interface]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        for cidr in fixedPrefixes where !seen.contains(cidr) {
            seen.insert(cidr)
            out.append(cidr)
        }
        for interface in interfaces where isLocalNetworkInterface(interface.name) {
            for subnet in interface.subnets {
                guard let network = networkPrefix(subnet), !seen.contains(network) else { continue }
                seen.insert(network)
                out.append(network)
            }
        }
        return out
    }

    /// "192.168.1.34/24" → "192.168.1.0/24"; nil for anything unusable. The mask
    /// matters: NE installs the masked prefix without complaint, so an unmasked
    /// entry would quietly carve out a different network from the one shown.
    static func networkPrefix(_ cidr: String) -> String? {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]) else { return nil }
        let address = String(parts[0])
        let isV6 = address.contains(":")
        let width = isV6 ? 128 : 32
        guard length >= (isV6 ? ipv6PrefixFloor : ipv4PrefixFloor), length <= width else { return nil }

        var bytes = [UInt8](repeating: 0, count: 16)
        guard address.withCString({ inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }) else {
            return nil
        }
        let byteCount = isV6 ? 16 : 4
        for index in 0..<byteCount {
            let bitsBefore = index * 8
            if bitsBefore >= length {
                bytes[index] = 0
            } else if bitsBefore + 8 > length {
                let keep = length - bitsBefore
                bytes[index] &= UInt8(truncatingIfNeeded: ~((1 << (8 - keep)) - 1))
            }
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard bytes.withUnsafeBufferPointer({ raw -> Bool in
            inet_ntop(isV6 ? AF_INET6 : AF_INET, raw.baseAddress, &buf,
                      socklen_t(INET6_ADDRSTRLEN)) != nil
        }) else { return nil }
        let text = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return text.isEmpty ? nil : "\(text)/\(length)"
    }

    /// The live carve-out for THIS Mac, right now. One `getifaddrs`, no spawn, no
    /// privilege, no routing-table read — so it is safe to call on the connect path
    /// (unlike `getaddrinfo`, it does not block on the network).
    ///
    /// Called ONCE per connect, in the app, and re-passed to every later settings
    /// build for that session — the same discipline as the tunnel's own carrier
    /// address (Docs/Networking.md §4.3). A network change mid-session therefore
    /// does not move the carve-out; it moves on the next connect. That is the
    /// conservative direction: a stale prefix that is no longer on any interface
    /// routes to nothing, whereas re-reading interfaces from the live re-apply paths
    /// would let a joined network silently widen a running tunnel's bypass.
    static func live() -> [String] { prefixes(of: liveInterfaces()) }

    /// The interfaces `live()` reads, exposed so a caller can log or show exactly
    /// what was found. UP and RUNNING only: a cable that is unplugged is not a
    /// network anyone is on.
    static func liveInterfaces() -> [Interface] {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return [] }
        defer { freeifaddrs(addrs) }

        var byName: [String: [String]] = [:]
        var order: [String] = []
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            let name = String(cString: ifa.ifa_name)
            guard isLocalNetworkInterface(name) else { continue }
            guard (ifa.ifa_flags & UInt32(IFF_UP)) != 0,
                  (ifa.ifa_flags & UInt32(IFF_RUNNING)) != 0 else { continue }
            guard let sa = ifa.ifa_addr, let maskSA = ifa.ifa_netmask else { continue }
            guard let cidr = Self.cidr(address: sa, netmask: maskSA) else { continue }
            if byName[name] == nil { order.append(name) }
            byName[name, default: []].append(cidr)
        }
        return order.map { Interface(name: $0, subnets: byName[$0] ?? []) }
    }

    /// One `ifaddrs` entry as a CIDR, both families. Returns nil for a family we do
    /// not route (`AF_LINK` byte counters), a scoped link-local literal we could not
    /// spell without its `%en0` suffix, or a non-contiguous netmask — which nothing
    /// sane produces and which must never be *summarised* as a prefix, because the
    /// summary would mean a different set of addresses.
    private static func cidr(address sa: UnsafeMutablePointer<sockaddr>,
                             netmask maskSA: UnsafeMutablePointer<sockaddr>) -> String? {
        let family = Int32(sa.pointee.sa_family)
        guard family == Int32(maskSA.pointee.sa_family) else { return nil }

        var text = ""
        var maskBytes = [UInt8](repeating: 0, count: 16)
        var maskWidth = 0
        switch family {
        case AF_INET:
            var addr = sockaddr_in()
            memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return nil
            }
            text = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            var mask = sockaddr_in()
            memcpy(&mask, maskSA, MemoryLayout<sockaddr_in>.size)
            withUnsafeBytes(of: mask.sin_addr) { raw in
                for (index, byte) in raw.enumerated() where index < 4 { maskBytes[index] = byte }
            }
            maskWidth = 4
        case AF_INET6:
            var addr = sockaddr_in6()
            memcpy(&addr, sa, MemoryLayout<sockaddr_in6>.size)
            // A scoped address ("fe80::1%en0") is not a route destination, and
            // fe80::/10 is already in the fixed list — skip the whole entry.
            if addr.sin6_addr.__u6_addr.__u6_addr8.0 == 0xfe,
               (addr.sin6_addr.__u6_addr.__u6_addr8.1 & 0xC0) == 0x80 { return nil }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            text = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            var mask = sockaddr_in6()
            memcpy(&mask, maskSA, MemoryLayout<sockaddr_in6>.size)
            withUnsafeBytes(of: mask.sin6_addr) { raw in
                for (index, byte) in raw.enumerated() where index < 16 { maskBytes[index] = byte }
            }
            maskWidth = 16
        default:
            return nil
        }

        guard !text.isEmpty, let length = prefixLength(mask: maskBytes, width: maskWidth) else {
            return nil
        }
        return networkPrefix("\(text)/\(length)")
    }

    /// A netmask's prefix length, or nil when the mask is not a contiguous run of
    /// leading ones — which nothing sane produces, and which we refuse to summarise
    /// as a prefix rather than guess at (the same judgement
    /// `NetworkTopology.prefixLength` makes about the v4 case).
    static func prefixLength(mask: [UInt8], width: Int) -> Int? {
        var length = 0
        var sawZero = false
        for index in 0..<width {
            let byte = mask[index]
            if sawZero {
                guard byte == 0 else { return nil }
                continue
            }
            if byte == 0xFF { length += 8; continue }
            if byte == 0 { sawZero = true; continue }
            // A partial byte is only a prefix boundary if it is 1s then 0s.
            let trailingZeros = byte.trailingZeroBitCount
            guard UInt8(truncatingIfNeeded: ~((1 << trailingZeros) - 1)) == byte else { return nil }
            length += 8 - trailingZeros
            sawZero = true
        }
        return length
    }
}
