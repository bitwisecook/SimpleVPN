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
//  The SSID is used for WORDING ONLY, and only when the user has opted into location
//  (see LocationAuthority) — it is deliberately excluded from `key`, so granting or
//  revoking that permission can never orphan already-remembered failures.
//

import Foundation
import Network
import OSLog

nonisolated struct NetworkFingerprint: Codable, Hashable, Sendable {
    var interface: String          // en0, en6…
    /// May be empty: a point-to-point default route (Tailscale/utun) has an interface
    /// but no gateway, which is exactly the case that used to make fingerprinting fail
    /// outright and silently drop the whole memory.
    var gatewayIP: String
    var gatewayMAC: String?        // the strong part of the identity
    /// The interface's own IPv4 network, e.g. "192.168.87.0/24" — read in-process from
    /// getifaddrs, so it works with no gateway, no subprocess and no permission.
    var localNetwork: String?
    /// Wi-Fi network name, purely for wording. Only ever non-nil when the user has
    /// opted into location (see LocationAuthority) — macOS withholds it otherwise.
    var ssid: String?

    /// Stable key — deliberately excludes the SSID so identity doesn't change when the
    /// user grants or revokes location, or when a network is renamed. The gateway MAC
    /// alone is enough when we have it; otherwise fall back to the weaker IP+interface.
    var key: String {
        if let mac = gatewayMAC, !mac.isEmpty { return "mac:\(mac.lowercased())" }
        if let net = localNetwork, !net.isEmpty { return "net:\(interface)|\(net)" }
        if !gatewayIP.isEmpty { return "gw:\(interface)|\(gatewayIP)" }
        return "if:\(interface)"
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

    /// The network this Mac is currently attached to, or nil when genuinely offline.
    static func current() async -> NetworkFingerprint? {
        var gateway = "", iface = ""
        if let routeOut = await run("/sbin/route", ["-n", "get", "default"]) {
            for line in routeOut.split(whereSeparator: \.isNewline) {
                let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count == 2 else { continue }
                if parts[0] == "gateway" { gateway = parts[1] }
                if parts[0] == "interface" { iface = parts[1] }
            }
        }
        // A gateway is a bonus, not a requirement: a point-to-point default route
        // (Tailscale and friends) reports an interface and no gateway at all. Requiring
        // both is what made this return nil and lose the memory silently.
        if iface.isEmpty { iface = primaryIPv4Interface() ?? "" }
        guard !iface.isEmpty else {
            log.error("no network fingerprint: no default-route interface and no candidate from getifaddrs")
            return nil
        }
        // ARP gives the gateway's MAC: "? (192.168.87.10) at 0:8:a2:e:dc:c7 on en0 …"
        var mac: String?
        if !gateway.isEmpty, let arp = await run("/usr/sbin/arp", ["-n", gateway]),
           let atRange = arp.range(of: " at ") {
            let rest = arp[atRange.upperBound...]
            let candidate = String(rest.prefix { !$0.isWhitespace })
            if candidate.contains(":"), candidate != "(incomplete)" { mac = candidate }
        }
        // Only non-nil if the user opted into location; see LocationAuthority.
        let ssid = await MainActor.run {
            LocationAuthority.shared.refreshSSID()
            return LocationAuthority.shared.ssid
        }
        let fp = NetworkFingerprint(interface: iface, gatewayIP: gateway,
                                    gatewayMAC: mac, localNetwork: ipv4Network(of: iface),
                                    ssid: ssid)
        log.debug("network fingerprint key=\(fp.key, privacy: .public)")
        return fp
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

    /// Last-resort interface pick when there's no usable default route: the first
    /// non-loopback, non-tunnel interface carrying an IPv4 address.
    private static func primaryIPv4Interface() -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let start = head else { return nil }
        defer { freeifaddrs(head) }
        for p in sequence(first: start, next: { $0.pointee.ifa_next }) {
            let e = p.pointee
            guard let namePtr = e.ifa_name,
                  let addr = e.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: namePtr)
            guard name != "lo0", !name.hasPrefix("utun"), !name.hasPrefix("ipsec") else { continue }
            return name
        }
        return nil
    }

    /// A remember that couldn't happen is worth a line: the whole feature silently does
    /// nothing when there's no fingerprint, and that's precisely how it failed before.
    static func logNetworkChange(from old: String?, to new: String?) {
        log.log("network changed: \(old ?? "none", privacy: .public) -> \(new ?? "none", privacy: .public)")
    }

    static func logMissedRemember(profile id: String) {
        log.error("cannot remember unreachable network for \(id, privacy: .public): no fingerprint")
    }

    private static func run(_ tool: String, _ args: [String]) async -> String? {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                guard FileManager.default.isExecutableFile(atPath: tool) else {
                    cont.resume(returning: nil); return
                }
                let p = Process()
                p.executableURL = URL(fileURLWithPath: tool)
                p.arguments = args
                let out = Pipe()
                p.standardOutput = out
                p.standardError = Pipe()
                do { try p.run() } catch { cont.resume(returning: nil); return }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: String(data: data, encoding: .utf8))
            }
        }
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
