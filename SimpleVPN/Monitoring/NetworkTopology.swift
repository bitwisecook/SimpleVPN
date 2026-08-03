// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkTopology.swift
//  Live picture of the Mac's network stack for the railroad diagram: every
//  interface (Wi-Fi, Ethernet, USB dongles, VM networks, this and other VPNs)
//  with addresses and LIVE per-interface byte counters (getifaddrs link data),
//  plus the IPv4 routing table (netstat -rn) classified with the tunnel
//  heuristics: private space / routes pushed at us → the far side of a tunnel;
//  a default route → internet egress, whether full- or split-tunnel.
//

import Foundation
import SystemConfiguration
import Observation
import Darwin

// MARK: - Model

nonisolated struct NetInterface: Identifiable, Sendable, Equatable {
    enum Kind: Sendable, Equatable {
        case wifi, ethernet, usbEthernet, thunderboltEthernet
        case virtualMachine, bridge, tunnel, other
    }

    var id: String { name }
    let name: String            // BSD name: en0, utun4, bridge100…
    let kind: Kind
    let displayName: String     // "Wi-Fi", "USB 10/100/1000 LAN", "VPN tunnel"…
    var ipv4: [String] = []
    var ipv6: [String] = []     // global scope only
    var isUp = false

    // Live rates derived from the link-level counters (bytes/sec).
    var inRate: Double = 0
    var outRate: Double = 0

    var primaryAddress: String? { ipv4.first ?? ipv6.first }

    /// In use = up and holding an address. macOS keeps many idle system `utun`
    /// devices (iCloud/Handoff/other apps) with no address — those are noise.
    var inUse: Bool { isUp && (!ipv4.isEmpty || !ipv6.isEmpty) }

    /// A Tailscale interface carries a 100.64.0.0/10 (CGNAT) address.
    var isTailscale: Bool {
        kind == .tunnel && ipv4.contains { ip in
            let parts = ip.split(separator: ".")
            guard parts.count == 4, parts[0] == "100", let o = Int(parts[1]) else { return false }
            return (64...127).contains(o)
        }
    }

    /// Human label — recognises Tailscale; otherwise the OS/BSD name.
    var friendlyName: String { isTailscale ? "Tailscale" : displayName }

    var systemImage: String {
        if isTailscale { return "point.3.connected.trianglepath.dotted" }
        switch kind {
        case .wifi: return "wifi"
        case .ethernet, .thunderboltEthernet: return "cable.connector"
        case .usbEthernet: return "cable.connector.horizontal"
        case .virtualMachine, .bridge: return "server.rack"
        case .tunnel: return "lock.shield"
        case .other: return "network"
        }
    }
}

nonisolated struct RouteEntry: Sendable, Equatable {
    let destination: String     // "default", "10.11/16", "192.168.147.160/32"…
    let gateway: String
    let interfaceName: String
    /// Raw netstat flags ("UCSg", "UGScIg"…). Additive and defaulted, so existing
    /// call sites are untouched; `RouteResolver` needs it to tell an unscoped
    /// route from an interface-scoped one (RTF_IFSCOPE = capital `I`).
    var flags: String = ""
    var isDefault: Bool { destination == "default" || destination == "0.0.0.0/0" }

    /// The user heuristic: private/CGNAT space on the far side of a tunnel.
    var isPrivateDestination: Bool {
        let d = destination
        return d.hasPrefix("10.") || d.hasPrefix("10/") || d.hasPrefix("192.168.")
            || d.hasPrefix("169.254") == false && Self.matches172(d)
            || d.hasPrefix("100.6") || d.hasPrefix("100.7") || d.hasPrefix("100.8")
            || d.hasPrefix("100.9") || d.hasPrefix("100.1")
    }

    private static func matches172(_ d: String) -> Bool {
        guard d.hasPrefix("172.") else { return false }
        let second = d.dropFirst(4).prefix { $0.isNumber }
        guard let n = Int(second) else { return false }
        return (16...31).contains(n)
    }
}

nonisolated struct NetworkTopology: Sendable, Equatable {
    var interfaces: [NetInterface] = []
    var routes: [RouteEntry] = []
    /// The FULL routing table — both families, unfiltered, with flags — for
    /// `RouteResolver`. Kept separate from `routes` on purpose: `routes` stays
    /// IPv4-only and noise-filtered so every existing consumer of the railroad
    /// diagram behaves exactly as before.
    var snapshot: RouteTableSnapshot = .empty

    /// Interface carrying the (first) IPv4 default route.
    var defaultInterface: String? { routes.first(where: \.isDefault)?.interfaceName }

    func routes(via name: String) -> [RouteEntry] {
        routes.filter { $0.interfaceName == name }
    }

    /// Non-default networks reachable through an interface — the "far side"
    /// of a tunnel per the heuristic (routes the remote pushed at us).
    func farSideNetworks(via name: String) -> [String] {
        routes(via: name)
            .filter { !$0.isDefault }
            .map(\.destination)
            .filter { !$0.hasPrefix("169.254") && !$0.hasPrefix("224.0") && !$0.hasPrefix("255.") }
    }

    /// Does this interface carry the default route (full-tunnel / primary egress)?
    func carriesDefault(_ name: String) -> Bool { defaultInterface == name }

    /// The interface a packet to this IPv4 would actually leave by — longest-prefix
    /// match over the routing table (so a Tailscale/LAN destination is NOT reported
    /// as going through a full-tunnel VPN). Nil for a v6 target or unknown table.
    ///
    /// Delegates to `RouteResolver` — ONE set of routing semantics everywhere.
    /// The old inline scan here ignored interface scoping and let the LAST
    /// equal-length row win (`plen >= bestPrefix`), so on a Mac carrying a VPN plus
    /// Tailscale (three default routes) it attributed internet addresses to the
    /// scoped, gatewayless Tailscale default — the Network Tools path display and
    /// the railroad were naming the wrong carrier. The resolver applies the
    /// kernel's rules: longest prefix, unscoped beats scoped, table order.
    func egressInterface(forIPv4 ip: String) -> NetInterface? {
        // Via the topology initializer, NOT the snapshot directly: a topology built
        // with only `routes` (tests, partial constructions) has an empty snapshot,
        // and resolving against that returned nil for everything.
        guard let name = RouteResolver(topology: self).resolve(ip)?.interfaceName
        else { return nil }
        return interfaces.first { $0.name == name }
    }

    static func ipv4ToUInt32(_ s: String) -> UInt32? {
        let o = s.split(separator: ".")
        guard o.count == 4 else { return nil }
        var v: UInt32 = 0
        for part in o { guard let n = UInt32(part), n <= 255 else { return nil }; v = (v << 8) | n }
        return v
    }

    /// Parse a BSD routing-table destination ("default", "10.11/16",
    /// "192.168.147.160/32", host "10.1.2.3") → (network, prefix-length). IPv4 only.
    static func parseIPv4CIDR(_ s: String) -> (net: UInt32, plen: Int)? {
        if s == "default" { return (0, 0) }
        guard !s.contains(":") else { return nil }   // skip IPv6 / link rows
        let parts = s.split(separator: "/", maxSplits: 1)
        var octets = parts[0].split(separator: ".").compactMap { UInt32($0) }
        guard (1...4).contains(octets.count), octets.allSatisfy({ $0 <= 255 }) else { return nil }
        let shown = octets.count
        while octets.count < 4 { octets.append(0) }
        let net = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        let plen = parts.count == 2 ? (Int(parts[1]) ?? shown * 8) : shown * 8
        return (net, min(32, max(0, plen)))
    }
}

// MARK: - Monitor

/// Polls interfaces (1 Hz — cheap, in-process) and the routing table (every
/// 5 s — spawns netstat) while something is displaying the railroad.
@MainActor
@Observable
final class TopologyMonitor {
    private(set) var topology = NetworkTopology()

    private var pollTask: Task<Void, Never>?
    private var previousCounters: [String: (in: UInt64, out: UInt64, at: Date)] = [:]
    private var watchers = 0

    /// One throughput sample for one interface.
    struct InterfaceSample: Identifiable, Sendable, Equatable {
        let id: Int
        let inRate: Double
        let outRate: Double
    }
    /// Tiered in/out history per interface (BSD name → `TrafficHistory`), so every
    /// interface — physical and each VPN — can be graphed, and scrolled back through:
    /// 1 s resolution for the last hour, then 10 s, then 60 s out to 24 h, at a fixed
    /// ~346 KB per interface. `samples(for:)`/`scaleMax(for:)` stay the "last minute"
    /// view the compact surfaces have always taken; the scrollable chart asks
    /// `history(for:)` for whatever range it is showing.
    private(set) var history: [String: TrafficHistory] = [:]
    private let historyWindow = 60

    func history(for name: String) -> TrafficHistory? { history[name] }
    func samples(for name: String) -> [InterfaceSample] {
        (history[name]?.recent(historyWindow) ?? []).map {
            // id = second-since-reference: monotonic and stable across refreshes.
            InterfaceSample(id: Int($0.start.timeIntervalSinceReferenceDate),
                            inRate: $0.avgIn, outRate: $0.avgOut)
        }
    }
    /// Peak across both directions — a shared y-scale ceiling for one interface.
    func scaleMax(for name: String) -> Double {
        max(1_024, (history[name]?.recent(historyWindow) ?? []).map(\.peak).max() ?? 0)
    }
    /// Newest sample time across the named interfaces — what the scrolling chart
    /// follows instead of running a clock of its own (invariant: no per-view pollers).
    func newestSampleTime(among names: [String]) -> Date? {
        names.compactMap { history[$0]?.newestTime }.max()
    }

    func startWatching() {
        watchers += 1
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            var tick = 0
            var routes: [RouteEntry] = []
            var snapshot = RouteTableSnapshot.empty
            while !Task.isCancelled {
                if tick % 5 == 0 {
                    (routes, snapshot) = await Self.readRoutes()
                }
                self?.update(routes: routes, snapshot: snapshot)
                tick += 1
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopWatching() {
        watchers = max(0, watchers - 1)
        if watchers == 0 {
            pollTask?.cancel()
            pollTask = nil
        }
    }

    private func update(routes: [RouteEntry], snapshot: RouteTableSnapshot = .empty) {
        var (interfaces, counters) = Self.readInterfaces()
        let now = Date()
        for i in interfaces.indices {
            let name = interfaces[i].name
            if let c = counters[name], let prev = previousCounters[name] {
                let dt = now.timeIntervalSince(prev.at)
                if dt > 0.05 {
                    interfaces[i].inRate = max(0, Double(c.in &- prev.in) / dt)
                    interfaces[i].outRate = max(0, Double(c.out &- prev.out) / dt)
                }
            }
        }
        previousCounters = counters.mapValues { (in: $0.in, out: $0.out, at: now) }

        // Per-interface rolling history, so every interface (physical AND each VPN)
        // can be graphed, not just the tunnel the app happens to own. Kept here
        // because this is the one place already sampling link counters at 1 Hz.
        for i in interfaces where i.inUse {
            history[i.name, default: TrafficHistory()]
                .record(inRate: i.inRate, outRate: i.outRate, at: now)
        }
        // Drop interfaces that went away, so the UI doesn't graph ghosts.
        let live = Set(interfaces.filter(\.inUse).map(\.name))
        for k in history.keys where !live.contains(k) { history[k] = nil }

        // Only publish when something actually changed, so idle ticks don't
        // invalidate every topology consumer once a second (NetworkTopology is
        // Equatable — rates differ under load, so this only quiets the idle case).
        let updated = NetworkTopology(interfaces: interfaces, routes: routes, snapshot: snapshot)
        if updated != topology { topology = updated }
    }

    // MARK: getifaddrs (addresses + link byte counters)

    private nonisolated static func readInterfaces()
        -> (interfaces: [NetInterface], counters: [String: (in: UInt64, out: UInt64)]) {

        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return ([], [:]) }
        defer { freeifaddrs(addrs) }

        let sc = scInterfaceInfo()
        var byName: [String: NetInterface] = [:]
        var counters: [String: (in: UInt64, out: UInt64)] = [:]
        var order: [String] = []

        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            let name = String(cString: ifa.ifa_name)
            if isBoring(name) { continue }

            if byName[name] == nil {
                let (kind, display) = classify(name: name, sc: sc)
                guard kind != nil else { continue }   // unclassifiable noise
                byName[name] = NetInterface(name: name, kind: kind!, displayName: display)
                order.append(name)
            }
            byName[name]?.isUp = (ifa.ifa_flags & UInt32(IFF_UP)) != 0
                && (ifa.ifa_flags & UInt32(IFF_RUNNING)) != 0

            guard let sa = ifa.ifa_addr else { continue }
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                var addr = sockaddr_in()
                memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
                byName[name]?.ipv4.append(String(cBuffer: buf))
            case AF_INET6:
                var addr = sockaddr_in6()
                memcpy(&addr, sa, MemoryLayout<sockaddr_in6>.size)
                // global addresses only — link-local fe80:: is noise here
                if addr.sin6_addr.__u6_addr.__u6_addr8.0 == 0xfe { break }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                byName[name]?.ipv6.append(String(cBuffer: buf))
            case AF_LINK:
                if let dataPtr = ifa.ifa_data {
                    let data = dataPtr.assumingMemoryBound(to: if_data.self).pointee
                    counters[name] = (in: UInt64(data.ifi_ibytes), out: UInt64(data.ifi_obytes))
                }
            default:
                break
            }
        }

        // Interfaces that are down with no addresses are clutter, except tunnels
        // (a VPN mid-connect is interesting) — drop them.
        let interfaces = order.compactMap { byName[$0] }.filter { i in
            i.isUp && (i.primaryAddress != nil || i.kind == .tunnel)
        }
        return (interfaces, counters)
    }

    private nonisolated static func isBoring(_ name: String) -> Bool {
        for prefix in ["lo", "awdl", "llw", "anpi", "gif", "stf", "ap", "pktap"]
        where name.hasPrefix(prefix) { return true }
        return false
    }

    /// BSD name → (hardware type, display name) from SystemConfiguration.
    private nonisolated static func scInterfaceInfo() -> [String: (type: String, display: String)] {
        var out: [String: (String, String)] = [:]
        for scIf in (SCNetworkInterfaceCopyAll() as? [SCNetworkInterface]) ?? [] {
            guard let bsd = SCNetworkInterfaceGetBSDName(scIf) as String? else { continue }
            let type = (SCNetworkInterfaceGetInterfaceType(scIf) as String?) ?? ""
            let display = (SCNetworkInterfaceGetLocalizedDisplayName(scIf) as String?) ?? bsd
            out[bsd] = (type, display)
        }
        return out
    }

    private nonisolated static func classify(
        name: String, sc: [String: (type: String, display: String)]
    ) -> (NetInterface.Kind?, String) {
        if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("tun") {
            return (.tunnel, "VPN (\(name))")
        }
        if name.hasPrefix("vmenet") || name.hasPrefix("vnic") { return (.virtualMachine, "VM network (\(name))") }
        if name.hasPrefix("bridge") { return (.bridge, "Bridge (\(name))") }
        if let info = sc[name] {
            if info.type == kSCNetworkInterfaceTypeIEEE80211 as String { return (.wifi, info.display) }
            if info.type == kSCNetworkInterfaceTypeEthernet as String {
                let d = info.display
                if d.localizedCaseInsensitiveContains("usb") { return (.usbEthernet, d) }
                if d.localizedCaseInsensitiveContains("thunderbolt") { return (.thunderboltEthernet, d) }
                return (.ethernet, d)
            }
            return (.other, info.display)
        }
        if name.hasPrefix("en") { return (.ethernet, name) }
        return (nil, name)
    }

    // MARK: Routing table (netstat -rn, both families)

    /// Returns the diagram's IPv4 route list (filtered exactly as it always was)
    /// AND the full unfiltered both-family snapshot that `RouteResolver` needs.
    private nonisolated static func readRoutes() async -> (routes: [RouteEntry], snapshot: RouteTableSnapshot) {
        await Task.detached(priority: .utility) {
            let v4 = netstat(family: "inet")
            let v6 = netstat(family: "inet6")

            var routes: [RouteEntry] = []
            for line in v4.split(separator: "\n") {
                let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
                // Destination Gateway Flags Netif [Expire]
                guard cols.count >= 4, cols[0] != "Destination" else { continue }
                let dest = cols[0], gateway = cols[1], flags = cols[2], netif = cols[3]
                guard dest != "Internet" else { continue }
                // Skip host-scoped noise: broadcast/multicast and link-local rows.
                if dest.hasPrefix("224.0") || dest.hasPrefix("255.255.255.255")
                    || dest.hasPrefix("169.254") { continue }
                // Skip per-host ARP-ish entries with MAC gateways on the LAN.
                if gateway.contains(":") && gateway.count == 17 && !dest.contains("/") { continue }
                routes.append(RouteEntry(destination: dest, gateway: gateway,
                                         interfaceName: netif, flags: flags))
            }
            return (routes, RouteTableSnapshot(ipv4Text: v4, ipv6Text: v6))
        }.value
    }

    private nonisolated static func netstat(family: String) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        p.arguments = ["-rn", "-f", family]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        guard (try? p.run()) != nil else { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
