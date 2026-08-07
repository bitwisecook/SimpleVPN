// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkMemory.swift
//  Remembers which networks a given VPN turned out to be unreachable from, so the app
//  can warn BEFORE you click Connect and sit through another timeout — and forgets the
//  moment that VPN connects successfully from that same network, so a one-off outage
//  doesn't leave a permanent false warning.
//
//  Identity without permission: the fingerprint never depends on the Wi-Fi SSID, which
//  since macOS 14 needs Location Services. It's built from the default gateway's MAC
//  (ARP), the interface's own IPv4 network (getifaddrs), and the interface name — all
//  available to any process. That's also a BETTER identity than an SSID: it tells two
//  different networks both called "Home" apart, and survives a rename.
//
//  It is built from the PHYSICAL default route, never a tunnel's — see
//  `NetworkIdentity.underlayDefaultRoute`. Both the routing table and the ARP cache
//  are read straight from the kernel (RouteTableSource), so no subprocess runs.
//
//  The SSID is used for WORDING ONLY, and only when the user has opted into location
//  (see LocationAuthority) — it is deliberately excluded from `key`, so granting or
//  revoking that permission can never orphan already-remembered failures.
//

import Foundation
import Network
import OSLog

nonisolated struct NetworkFingerprint: Codable, Hashable, Sendable {
    var interface: String          // en0, en6…
    /// May be empty: a link can have an interface and no next-hop address (a
    /// point-to-point default, or no physical default route at all while DHCP is
    /// still thinking). Requiring one is what used to make fingerprinting fail
    /// outright and silently drop the whole memory.
    var gatewayIP: String
    /// The strong part of the identity. `MACAddress` and not text, so that the
    /// fingerprint of one network cannot differ from itself because the address was
    /// spelled two ways — see `Shared/MACAddress.swift`.
    var gatewayMAC: MACAddress?
    /// The interface's own IPv4 network, e.g. "192.168.87.0/24" — read in-process from
    /// getifaddrs, so it works with no gateway, no subprocess and no permission.
    var localNetwork: String?
    /// Wi-Fi network name, purely for wording. Only ever non-nil when the user has
    /// opted into location (see LocationAuthority) — macOS withholds it otherwise.
    var ssid: String?

    /// Stable key — deliberately excludes the SSID so identity doesn't change when the
    /// user grants or revokes location, or when a network is renamed. The gateway MAC
    /// alone is enough when we have it; otherwise fall back to the weaker IP+interface.
    ///
    /// INVARIANT — bringing a tunnel UP IS NOT A NETWORK MOVE. The key describes the
    /// physical network this Mac is attached to, so it must not change when a VPN (or
    /// Tailscale, or anything else that owns a utun) takes over the default route.
    /// Everything that reacts to a key change — re-probing endpoints, re-snapshotting
    /// "home", re-resolving hosts — would otherwise fire at exactly the moment its
    /// answers are measured through the tunnel and are therefore worthless. The
    /// physical-only route pick in `NetworkIdentity.underlayDefaultRoute` is what
    /// upholds this; anything else deriving identity must uphold it too.
    ///
    /// Known ceiling: signing in to a captive portal does NOT change this key — same
    /// gateway, same MAC, so "behind the sign-in page" and "through it" are the same
    /// network by this identity. That is deliberate (the network really is the same
    /// one), and it means nothing keyed off `key` may be relied on to notice a portal
    /// being cleared. Captive-portal resolution is handled separately, by the
    /// ConnectionView captive rechecks (see VPNController.recheckCaptivePortal).
    ///
    /// IT CARRIES A HARDWARE ADDRESS, so it is not a loggable value: the two
    /// `netmemory` lines that mention it mark it `privacy: .private`, and nothing may
    /// put it in the diagnostic report.
    ///
    /// THE SPELLING HERE IS PINNED, and `bsdText` rather than `canonicalText` is not
    /// an oversight. This key is written into `UserDefaults` (the
    /// `network.unreachableMemory.v1` map) the moment a VPN fails somewhere, and it is
    /// looked up again on the next launch. Every key already on every user's disk was
    /// produced from `ether_ntoa`'s unpadded spelling, so canonicalising it would
    /// silently orphan the remembered failures for every gateway with a low octet —
    /// about a third of them — and the symptom would be a warning that quietly stopped
    /// appearing. Changing it needs a migration, not an edit.
    var key: String {
        if let mac = gatewayMAC { return "mac:\(mac.bsdText)" }
        if let net = localNetwork, !net.isEmpty { return "net:\(interface)|\(net)" }
        if !gatewayIP.isEmpty { return "gw:\(interface)|\(gatewayIP)" }
        return "if:\(interface)"
    }

    /// Which of the four identities `key` fell back to — `mac`, `net`, `gw` or `if`,
    /// strongest first. The loggable half of the key: it says how well this network
    /// can be told from another one without saying which network it is.
    var keyStrength: String {
        String(key.prefix { $0 != ":" })
    }

    /// Human wording for a warning. Names the Wi-Fi network when we're allowed to know
    /// it, and otherwise describes the network in terms the user can still recognise.
    var label: String {
        if let ssid, !ssid.isEmpty { return "\u{201C}\(ssid)\u{201D}" }
        if let net = localNetwork, !net.isEmpty { return "the network on \(interface) (\(net))" }
        if !gatewayIP.isEmpty { return "the network on \(interface) (gateway \(gatewayIP))" }
        return "the network on \(interface)"
    }
}

nonisolated enum NetworkIdentity {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "netmemory")

    /// Interface names that carry a TUNNEL rather than a link. Whatever happens on
    /// the far side of one of these, the Mac has not moved: same Wi-Fi, same cable,
    /// same gateway. `utun` covers our own VPNs *and* Tailscale — which this app's
    /// author runs permanently, so a Tailscale utun must never be allowed to become
    /// the identity either, or the "network" would be whatever Tailscale did last.
    static let virtualInterfacePrefixes = ["utun", "tun", "tap", "gif", "stf", "ipsec", "ppp", "feth"]

    static func isVirtualInterface(_ name: String) -> Bool {
        // Zone suffixes ("utun4%utun4") and empty names both answer correctly here.
        let bare = name.split(separator: "%").first.map(String.init) ?? name
        return virtualInterfacePrefixes.contains { bare.hasPrefix($0) }
    }

    /// The default route the fingerprint is taken from: the best PHYSICAL one.
    ///
    /// A full tunnel flips the system default route to a utun but LEAVES the
    /// underlying one in the table, interface-scoped (`UGScIg en0`) — so the
    /// physical network is still there to be described, and describing it is what
    /// keeps `NetworkFingerprint.key` still while a VPN comes up and goes down.
    /// Unscoped candidates come first (that is the route the kernel would use with
    /// no tunnel in the way), then the scoped leftovers, then kernel order.
    static func underlayDefaultRoute(in snapshot: RouteTableSnapshot) -> RouteRecord? {
        let candidates = snapshot.routes.filter {
            $0.isDefault && !$0.isReject && !$0.interfaceName.isEmpty
                && $0.interfaceName != "lo0" && !isVirtualInterface($0.interfaceName)
        }
        func best(_ family: IPFamily) -> RouteRecord? {
            candidates.filter { $0.family == family }
                .min { a, b in rank(a) < rank(b) }
        }
        // IPv4 first: the rest of the fingerprint (ARP MAC, local network) is v4.
        return best(.v4) ?? best(.v6)
    }

    private static func rank(_ route: RouteRecord) -> (Int, Int, Int) {
        (route.isScoped ? 1 : 0, route.hasRealGateway ? 0 : 1, route.order)
    }

    /// Where the internet actually leaves this Mac right now — tunnel included.
    /// The opposite question to `underlayDefaultRoute`, and the one worth asking
    /// before believing a public-address lookup describes home.
    static func activeDefaultRoute(in snapshot: RouteTableSnapshot) -> RouteRecord? {
        snapshot.routes.filter {
            $0.isDefault && !$0.isReject && !$0.isScoped && !$0.interfaceName.isEmpty
        }
        .min { a, b in
            (a.family == .v4 ? 0 : 1, a.order) < (b.family == .v4 ? 0 : 1, b.order)
        }
    }

    /// True when traffic is currently leaving through a tunnel, so "where does the
    /// internet see me?" is the tunnel's answer and not this network's.
    static func defaultRouteIsVirtual(in snapshot: RouteTableSnapshot) -> Bool {
        guard let route = activeDefaultRoute(in: snapshot) else { return false }
        return isVirtualInterface(route.interfaceName)
    }

    /// Live version, straight from the kernel (one sysctl, no subprocess).
    static func defaultRouteIsVirtual() -> Bool {
        guard let snapshot = try? RouteTableSource.snapshot() else { return false }
        return defaultRouteIsVirtual(in: snapshot)
    }

    /// The network this Mac is currently attached to, or nil when genuinely offline.
    static func current() async -> NetworkFingerprint? {
        // Both read as binary from the kernel — see RouteTableSource. Detached
        // because a nonisolated async function now runs on its CALLER's actor
        // (NonisolatedNonsendingByDefault), and the caller is the main one: two
        // sysctl dumps of a large routing table do not belong there.
        let (routes, arp) = await Task.detached(priority: .utility) {
            ((try? RouteTableSource.snapshot()) ?? .empty,
             (try? RouteTableSource.arpTable()) ?? [])
        }.value
        // Only non-nil if the user opted into location; see LocationAuthority.
        let ssid = await MainActor.run {
            LocationAuthority.shared.refreshSSID()
            return LocationAuthority.shared.ssid
        }
        guard let fp = fingerprint(routes: routes, arp: arp, ssid: ssid) else {
            log.error("no network fingerprint: no physical default route and no candidate from getifaddrs")
            return nil
        }
        // `.private`, and the KIND is logged separately so the line still says
        // something. The key's strongest form is "mac:" plus the gateway's hardware
        // address — an identifier for a specific piece of somebody's furniture, in a
        // log that `DiagnosticReportLog` reads and a user then SENDS. Which of the
        // four identity strengths we got is the whole diagnostic content of this line;
        // the address itself never was.
        log.debug("""
            network fingerprint strength=\(fp.keyStrength, privacy: .public) \
            key=\(fp.key, privacy: .private)
            """)
        return fp
    }

    /// The fingerprint for a given routing table and ARP cache — pure, so the
    /// "a tunnel is not a network move" invariant is testable from fixtures.
    static func fingerprint(routes: RouteTableSnapshot,
                            arp: [RouteTableSource.ARPEntry],
                            ssid: String? = nil,
                            localNetwork: (String) -> String? = { ipv4Network(of: $0) },
                            fallbackInterface: () -> String? = { primaryIPv4Interface() })
        -> NetworkFingerprint? {
        let route = underlayDefaultRoute(in: routes)
        // A gateway is a bonus, not a requirement: a point-to-point default route
        // reports an interface and no next-hop address at all. Requiring both is
        // what made this return nil and lose the memory silently.
        var iface = route?.interfaceName ?? ""
        var gateway = route.flatMap { $0.hasRealGateway ? $0.gateway : nil } ?? ""
        if iface.isEmpty {
            // No physical default in the table — a tunnel-only default, or DHCP
            // hasn't finished. The interface holding our address still names the
            // network we're plugged into, which is the whole point.
            iface = fallbackInterface() ?? ""
            gateway = ""
        }
        guard !iface.isEmpty else { return nil }

        var mac: MACAddress?
        if !gateway.isEmpty {
            let matches = arp.filter { $0.ip == gateway }
            mac = (matches.first { $0.interface == iface } ?? matches.first)?.mac
        }
        return NetworkFingerprint(interface: iface, gatewayIP: gateway,
                                  gatewayMAC: mac, localNetwork: localNetwork(iface),
                                  ssid: ssid)
    }

    /// The interface a probe of a VPN SERVER must egress from, so its hello + reply
    /// travel the real underlying path and cannot loop back through the very tunnel
    /// being tested. It is the non-tunnel default route's interface (the same path
    /// the tunnel's own control channel uses) — and, when there is no physical
    /// default at all, the interface holding our address. nil ⇒ none determinable,
    /// so the caller probes unbound (today's behavior). Pure over its snapshot, so
    /// the tunnel-skipping is testable from fixtures.
    static func physicalEgressInterface(in snapshot: RouteTableSnapshot,
                                        fallbackInterface: () -> String? = { primaryIPv4Interface() })
        -> String? {
        if let name = underlayDefaultRoute(in: snapshot)?.interfaceName, !name.isEmpty {
            return name
        }
        return fallbackInterface()
    }

    /// Live `IP_BOUND_IF` index for `physicalEgressInterface`, read straight from the
    /// kernel (one sysctl, no subprocess). 0 ⇒ no non-tunnel interface found, so the
    /// probe binds nothing and falls back to normal routing.
    static func physicalEgressBoundIf() -> UInt32 {
        guard let snapshot = try? RouteTableSource.snapshot(),
              let name = physicalEgressInterface(in: snapshot) else { return 0 }
        return NetworkProbes.interfaceIndex(name)
    }

    /// The IPv4 network the given interface sits on, e.g. "192.168.87.0/24".
    /// In-process (getifaddrs), so no subprocess and no permission involved.
    static func ipv4Network(of iface: String) -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let start = head else { return nil }
        defer { freeifaddrs(head) }
        for p in sequence(first: start, next: { $0.pointee.ifa_next }) {
            let e = p.pointee
            guard let namePtr = e.ifa_name, String(cString: namePtr) == iface,
                  let addr = e.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
                  let maskPtr = e.ifa_netmask else { continue }
            let ip = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let mask = maskPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let net = ip & mask
            let bytes = withUnsafeBytes(of: net) { Array($0) }   // already network order
            guard bytes.count == 4 else { continue }
            return "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])/\(mask.nonzeroBitCount)"
        }
        return nil
    }

    /// Last-resort interface pick when there's no usable PHYSICAL default route:
    /// the first non-loopback, non-tunnel interface carrying an IPv4 address.
    static func primaryIPv4Interface() -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let start = head else { return nil }
        defer { freeifaddrs(head) }
        for p in sequence(first: start, next: { $0.pointee.ifa_next }) {
            let e = p.pointee
            guard let namePtr = e.ifa_name,
                  let addr = e.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: namePtr)
            guard name != "lo0", !isVirtualInterface(name) else { continue }
            return name
        }
        return nil
    }

    /// A remember that couldn't happen is worth a line: the whole feature silently does
    /// nothing when there's no fingerprint, and that's precisely how it failed before.
    ///
    /// THE KEYS ARE `.private` for the reason `NetworkFingerprint.key` states: the
    /// strongest form of one is the gateway's hardware address. "The network changed"
    /// is the fact a maintainer needs, and it survives the redaction.
    static func logNetworkChange(from old: String?, to new: String?) {
        log.log("""
            network changed: \(old ?? "none", privacy: .private) \
            -> \(new ?? "none", privacy: .private)
            """)
    }

    static func logMissedRemember(profile id: String) {
        log.error("cannot remember unreachable network for \(id, privacy: .public): no fingerprint")
    }
}

@MainActor
@Observable
final class NetworkMemory {
    static let shared = NetworkMemory()

    /// The network we're on right now, refreshed on demand.
    private(set) var current: NetworkFingerprint?

    /// profile id → [fingerprint key: human label]. Stored as a plain nested map so a
    /// stale entry is trivially inspectable (and deletable) in defaults.
    private var failures: [String: [String: String]] = [:]
    private static let key = "network.unreachableMemory.v1"

    /// Watches for network changes so `current` is never stale. This is the whole reason
    /// the warning used to persist after switching Wi-Fi: the fingerprint was only taken
    /// when a view appeared, so the app went on believing it was still on the old network
    /// and kept matching the old network's recorded failure.
    private let pathMonitor = NWPathMonitor()
    private var refreshTask: Task<Void, Never>?

    private init() {
        if let data = UserDefaults.standard.data(forKey: Self.key),
           let decoded = try? JSONDecoder().decode([String: [String: String]].self, from: data) {
            failures = decoded
        }
        // No permission needed for path monitoring, so this can simply always run.
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in self?.scheduleRefresh() }
        }
        pathMonitor.start(queue: DispatchQueue.global(qos: .utility))
        scheduleRefresh()
    }

    /// Coalesced: a single Wi-Fi switch emits a burst of path updates, and the settle
    /// delay also gives the new gateway time to appear in the ARP table — without it the
    /// fingerprint can be taken before the MAC is known, producing a weaker key for the
    /// same network.
    private func scheduleRefresh(settle: Duration = .milliseconds(700)) {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            try? await Task.sleep(for: settle)
            guard !Task.isCancelled else { return }
            await self?.refresh()
        }
    }

    private func persist() {
        UserDefaults.standard.set(try? JSONEncoder().encode(failures), forKey: Self.key)
    }

    func refresh() async {
        let fresh = await NetworkIdentity.current()
        if fresh?.key != current?.key {
            NetworkIdentity.logNetworkChange(from: current?.key, to: fresh?.key)
        }
        current = fresh
    }

    /// This VPN failed to be reachable from the network we're on now.
    func rememberFailure(profile id: String) {
        guard let fp = current else {
            NetworkIdentity.logMissedRemember(profile: id); return
        }
        var forProfile = failures[id] ?? [:]
        forProfile[fp.key] = fp.label
        failures[id] = forProfile
        persist()
    }

    /// It worked here after all — drop the warning so it can't nag for ever.
    func forgetFailure(profile id: String) {
        guard let fp = current, failures[id]?[fp.key] != nil else { return }
        failures[id]?[fp.key] = nil
        if failures[id]?.isEmpty == true { failures[id] = nil }
        persist()
    }

    /// A warning to show BEFORE connecting: nil when this VPN has never failed here.
    func knownUnreachableHere(profile id: String) -> String? {
        guard let fp = current else { return nil }
        return failures[id]?[fp.key]
    }

    /// Let the user clear it by hand, for when they know the network was fixed.
    func clear(profile id: String) {
        failures[id] = nil
        persist()
    }
}

/// Riding the network-identity signal from code that isn't a view.
///
/// Views say `.task(id: NetworkMemory.shared.current?.key)` and SwiftUI does the
/// rest; stores and controllers have no body to re-evaluate, so they take one of
/// these instead and hold it for as long as they care. Nothing here starts a
/// timer or a lookup — it is purely a relay of the one NWPathMonitor the app
/// already runs.
@MainActor
enum NetworkChange {

    /// Placeholder identity for "we don't know what network this is yet" — used
    /// where a cache must be keyed by network before the first fingerprint lands.
    /// It becomes a real key moments later, which reads as an ordinary change.
    static let unknownKey = "net:unknown"

    /// The network we're on, or `unknownKey` before the first fingerprint.
    static var key: String { NetworkMemory.shared.current?.key ?? unknownKey }

    /// Calls `body` on every genuine identity change, never for the value that
    /// was already current when observation started. `current` is reassigned on
    /// every refresh — most of which land on the same network — so the key, not
    /// the assignment, is what counts as a change.
    ///
    /// Returns the driving task: cancel it (or drop the property holding it) to
    /// stop observing.
    static func observe(_ body: @escaping @MainActor (String?) -> Void) -> Task<Void, Never> {
        Task { @MainActor in
            var last = NetworkMemory.shared.current?.key
            while !Task.isCancelled {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    // onChange fires during the willSet, so the new value is only
                    // readable once the continuation has resumed us back onto the
                    // main actor — which is why the read happens after the await.
                    withObservationTracking {
                        _ = NetworkMemory.shared.current?.key
                    } onChange: {
                        continuation.resume()
                    }
                }
                guard !Task.isCancelled else { return }
                let now = NetworkMemory.shared.current?.key
                guard now != last else { continue }
                last = now
                body(now)
            }
        }
    }
}
