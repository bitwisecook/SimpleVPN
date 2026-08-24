// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TunnelStats.swift
//  A small telemetry sample the packet-tunnel provider publishes ~1 Hz into the shared
//  App-Group cache; the app reads it to drive the live throughput graph and the
//  connection-detail panel (uptime, reconnects, topology). Cumulative byte counters —
//  the app derives rates from successive samples. No secrets ever go here.
//

import Foundation

struct TunnelStats: Codable, Sendable, Equatable {
    var profile: String            // profile id this sample belongs to
    var timestamp: Double          // epoch seconds when sampled
    var connectedSince: Double     // epoch seconds of the current connect (for uptime)
    var reconnects: Int            // reasserting/reconnecting transitions this session
    var bytesIn: Int64             // cumulative received bytes
    var bytesOut: Int64            // cumulative sent bytes

    // Topology (for the railroad diagram); may be empty until the tunnel is up.
    var serverEndpoint: String     // VPN server address the transport connected to
    var tunnelIPv4: String         // assigned in-tunnel address
    var dnsServers: [String]       // DNS servers pushed by the tunnel
    var proxies: [String]          // HTTP/HTTPS proxies or PAC URL pushed by the tunnel

    // Dual-stack / transport detail for the connection-details panel. Optional so
    // samples written by an older extension (or read by an older app) still decode.
    var tunnelIPv6: String? = nil      // assigned in-tunnel IPv6 address
    var gateway4: String? = nil        // in-tunnel IPv4 gateway
    var gateway6: String? = nil        // in-tunnel IPv6 gateway
    var serverIP: String? = nil        // resolved transport address
    var serverPort: String? = nil      // transport port
    var serverProto: String? = nil     // transport protocol ("udp"/"tcp"…)
    var searchDomains: [String]? = nil // pushed DNS search domains
    var mtu: Int? = nil                // tunnel MTU

    // Structured pushed-proxy capture (Proxy mediator P3 — the per-kind intent for
    // OpenVPN). `proxies` above stays the display-string list for existing consumers;
    // these carry the machine-usable detail the ProxyIntent/NEProxySettings path needs.
    // Optional for app↔extension version skew.
    var proxyHTTPHost: String? = nil   // pushed HTTP proxy host
    var proxyHTTPPort: Int? = nil      // pushed HTTP proxy port
    var proxyHTTPSHost: String? = nil  // pushed HTTPS proxy host
    var proxyHTTPSPort: Int? = nil     // pushed HTTPS proxy port
    var proxyPACURL: String? = nil     // pushed PAC / auto-config URL
    var proxyBypass: [String]? = nil   // pushed proxy-bypass hosts (→ exceptionList)

    // Default-route ownership GROUND TRUTH, reported by the engine (not the stored
    // preference and not the client-.ovpn grep). The app seeds its applied-role
    // cache and the traffic-path UI from `effectiveDefaultOwned`, so it can never
    // show split while the tunnel actually routes full — nor skip a needed
    // gateway:split/full IPC (RC1/RC4). Optional for app↔extension version skew.
    var defaultRouteV4: Bool? = nil        // a v4 default route was pushed
    var defaultRouteV6: Bool? = nil        // a v6 default route was pushed
    var suppressDefaultRoute: Bool? = nil  // ownership demoted: default suppressed
    var effectiveDefaultOwned: Bool? = nil // truly holds 0.0.0.0/0 · ::/0 right now

    var uptime: TimeInterval { max(0, timestamp - connectedSince) }

    /// The transport address the active tunnel reports, stripped of its port.
    ///
    /// `serverIP` is the strongest answer: OpenVPN and WireGuard publish the
    /// literal remote address that actually carried this session. Some engines
    /// can only report their connected endpoint as `host:port`, so use that as
    /// an honest fallback rather than sending a map or diagnostics back to the
    /// profile's configured server selection.
    var activeServerAddress: String {
        let resolved = (serverIP ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return resolved.isEmpty ? Self.hostPart(of: serverEndpoint) : resolved
    }

    /// Host half of a transport endpoint. Supports `host:port`, `[IPv6]:port`,
    /// and bare IPv6 literals without accidentally removing part of an address.
    static func hostPart(of endpoint: String) -> String {
        let value = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return "" }
        if value.first == "[", let closing = value.firstIndex(of: "]") {
            let host = String(value[value.index(after: value.startIndex)..<closing])
            let suffix = value[value.index(after: closing)...]
            if suffix.first == ":", let port = Int(suffix.dropFirst()),
               (1...65_535).contains(port) {
                return host
            }
        }
        let pieces = value.split(separator: ":", omittingEmptySubsequences: false)
        guard pieces.count == 2, let port = Int(pieces[1]), (1...65_535).contains(port) else {
            return value
        }
        return String(pieces[0])
    }
}

/// Shared read/write of the latest per-profile sample in the App Group container.
///
/// Do not use `UserDefaults(suiteName:)` for this IPC. On macOS it is treated as
/// app-data access and can provoke the misleading “access data from other apps”
/// consent alert while a connection is starting. Both the app and packet-tunnel
/// extension have the same group entitlement, so the supported container API gives
/// them one cache without asking the user to approve another app's data.
enum TunnelStatsStore {
    static let appGroupIdentifier = "group.com.bragi0.SimpleVPN"
    private static let directoryName = "TunnelStats"

    private static func fileURL(profile: String) -> URL? {
        let manager = FileManager.default
        guard let groupURL = manager.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else { return nil }

        let directory = groupURL
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Caches", isDirectory: true)
            .appendingPathComponent(directoryName, isDirectory: true)
        guard (try? manager.createDirectory(at: directory, withIntermediateDirectories: true)) != nil else {
            return nil
        }

        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableDirectory = directory
        try? mutableDirectory.setResourceValues(values)

        // Profile IDs are opaque strings. URL-safe base64 produces a stable, single
        // path component even if a future ID contains a slash or other punctuation.
        let name = Data(profile.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return directory.appendingPathComponent("\(name).json", isDirectory: false)
    }

    static func write(_ stats: TunnelStats) {
        guard let data = try? JSONEncoder().encode(stats),
              let url = fileURL(profile: stats.profile) else { return }
        try? data.write(to: url, options: .atomic)
    }

    static func read(profile: String) -> TunnelStats? {
        guard let url = fileURL(profile: profile),
              let data = try? Data(contentsOf: url),
              let s = try? JSONDecoder().decode(TunnelStats.self, from: data) else { return nil }
        return s
    }

    static func clear(profile: String) {
        guard let url = fileURL(profile: profile) else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
