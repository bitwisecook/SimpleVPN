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
