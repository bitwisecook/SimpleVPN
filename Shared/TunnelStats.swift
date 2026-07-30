// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TunnelStats.swift
//  A small telemetry sample the packet-tunnel provider publishes ~1 Hz into the shared
//  App-Group defaults; the app reads it to drive the live throughput graph and the
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

    var uptime: TimeInterval { max(0, timestamp - connectedSince) }
}

/// Shared read/write of the latest per-profile sample via App-Group `UserDefaults`.
/// Both the (unsandboxed) app and the (sandboxed) extension hold the app-group entitlement.
enum TunnelStatsStore {
    static let suiteName = "group.com.bragi0.SimpleVPN"
    // Computed each use: UserDefaults isn't Sendable, and the OS caches suite instances.
    private static var defaults: UserDefaults? { UserDefaults(suiteName: suiteName) }

    private static func key(_ profile: String) -> String { "tunnel.stats.\(profile)" }

    static func write(_ stats: TunnelStats) {
        guard let data = try? JSONEncoder().encode(stats) else { return }
        defaults?.set(data, forKey: key(stats.profile))
    }

    static func read(profile: String) -> TunnelStats? {
        guard let data = defaults?.data(forKey: key(profile)),
              let s = try? JSONDecoder().decode(TunnelStats.self, from: data) else { return nil }
        return s
    }

    static func clear(profile: String) {
        defaults?.removeObject(forKey: key(profile))
    }
}
