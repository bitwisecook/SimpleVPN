// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelConfig.swift
//  The Swift half of the proxy-tunnel engine's JSON contract: the saved per-VPN
//  settings, the start payload handed to PXStart, and the decoder for what
//  PXStatus sends back. Shared between the app (editor, status projection) and
//  the extension (which runs the engine), so it imports nothing beyond
//  Foundation.
//
//  ONE kind, THREE schemes: a Proxy Tunnel presents a utun with routes and
//  dials every TCP flow (and DNS) through an upstream proxy. Whether that proxy
//  is SOCKS5 or HTTP(S) CONNECT is decided by the URL scheme — a preset in the
//  editor, NOT a second VPNKind (the same rule Headscale follows under
//  Tailscale).
//
//  Invariant: no secrets live in this saved type. Credentials ride startTunnel
//  options in memory (see ProxyTunnelStartConfig.username/password), exactly
//  like every other credential in this app — never in providerConfiguration.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Saved settings

nonisolated struct ProxyTunnelConfig: Codable, Sendable, Equatable {

    /// The upstream family, purely a UI affordance over the one thing that
    /// actually differs: the URL scheme.
    nonisolated enum Preset: String, Codable, Sendable, CaseIterable {
        case socks5
        case httpConnect
        case httpsConnect

        var scheme: String {
            switch self {
            case .socks5: "socks5"
            case .httpConnect: "http"
            case .httpsConnect: "https"
            }
        }

        var displayName: String {
            switch self {
            case .socks5: "SOCKS5"
            case .httpConnect: "HTTP CONNECT"
            case .httpsConnect: "HTTPS CONNECT (TLS to proxy)"
            }
        }

        /// Non-technical one-liner for the editor.
        var summary: String {
            switch self {
            case .socks5:
                "A SOCKS5 proxy. Carries any TCP connection, and UDP too when the proxy allows it."
            case .httpConnect:
                "An HTTP proxy that tunnels connections with CONNECT. TCP only; DNS still works."
            case .httpsConnect:
                "Like HTTP CONNECT, but the link to the proxy itself is encrypted with TLS."
            }
        }

        var defaultPort: Int {
            switch self {
            case .socks5: 1080
            case .httpConnect: 8080
            case .httpsConnect: 443
            }
        }

        static func from(scheme raw: String) -> Preset? {
            switch raw.lowercased() {
            case "socks5", "socks5h": .socks5
            case "http": .httpConnect
            case "https": .httpsConnect
            default: nil
            }
        }
    }

    /// The upstream proxy URL. NEVER carries credentials (the editor keeps them
    /// out); e.g. "socks5://proxy.example.com:1080".
    var upstream: String = ""
    /// Whether this proxy needs a username/password. Gates the connect button:
    /// a no-auth proxy connects with nothing typed, an auth proxy needs stored
    /// or entered credentials. The engine still works if this is wrong — it just
    /// changes when the UI asks.
    var requiresAuth: Bool = false

    /// Send ALL traffic through the tunnel (default-route). Off ⇒ only the
    /// included routes below enter the tunnel; everything else stays direct.
    var includeDefaultRoute: Bool = true
    /// Destinations pulled into the tunnel when not using the default route.
    var includedRoutes: [String] = []
    /// Destinations kept OUT of the tunnel even under the default route (the
    /// proxy's own address is excluded automatically by the provider — these are
    /// extra carve-outs the user wants direct).
    var excludedRoutes: [String] = []

    /// DNS servers to advertise on the utun. Queries to these are carried
    /// through the proxy (SOCKS UDP, or DNS-over-TCP for a CONNECT proxy). Empty
    /// ⇒ leave the Mac's own resolvers alone.
    var dnsServers: [String] = []

    /// Tunnel MTU. 1500 is a safe utun default; the proxy re-segments anyway
    /// since flows are re-dialled as fresh TCP, so this rarely needs changing.
    var mtu: Int = ProxyTunnelStartConfig.defaultMTU

    /// The upstream scheme, lowercased, or "" if unparseable.
    var scheme: String {
        URLComponents(string: upstream.trimmingCharacters(in: .whitespacesAndNewlines))?
            .scheme?.lowercased() ?? ""
    }

    /// The preset this upstream URL represents (nil when the scheme is unknown).
    var preset: Preset? { Preset.from(scheme: scheme) }

    // Lenient decoding, same invariant as OpenVPNOverrides/TailscaleConfig: an
    // app and an extension of different vintages must still agree, and a missing
    // field means the documented default, never a decode failure that breaks
    // connecting.
    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        upstream = (try? c.decodeIfPresent(String.self, forKey: .upstream)) ?? ""
        requiresAuth = (try? c.decodeIfPresent(Bool.self, forKey: .requiresAuth)) ?? false
        includeDefaultRoute = (try? c.decodeIfPresent(Bool.self, forKey: .includeDefaultRoute)) ?? true
        includedRoutes = (try? c.decodeIfPresent([String].self, forKey: .includedRoutes)) ?? []
        excludedRoutes = (try? c.decodeIfPresent([String].self, forKey: .excludedRoutes)) ?? []
        dnsServers = (try? c.decodeIfPresent([String].self, forKey: .dnsServers)) ?? []
        mtu = (try? c.decodeIfPresent(Int.self, forKey: .mtu)) ?? ProxyTunnelStartConfig.defaultMTU
    }
}

extension ProxyTunnelConfig {
    static func decode(from blob: Data?) -> ProxyTunnelConfig {
        guard let blob, let c = try? JSONDecoder().decode(ProxyTunnelConfig.self, from: blob) else {
            return ProxyTunnelConfig()
        }
        return c
    }

    func encodedBlob() -> Data? { try? JSONEncoder().encode(self) }

    /// The proxy host as macOS should show it in Network settings and as the
    /// probe/endpoint machinery dials — the honest answer for "what does this
    /// VPN talk to". `nonisolated` because the network-settings builder (a
    /// nonisolated enum, compiled into both the MainActor-default app and the
    /// nonisolated extension) reads it.
    nonisolated var proxyHost: String {
        URLComponents(string: upstream.trimmingCharacters(in: .whitespacesAndNewlines))?.host ?? ""
    }
}

// MARK: - Validation

extension ProxyTunnelConfig {

    /// Why this upstream URL can't be used, in the user's language — nil when
    /// it's fine. Mirrors parseUpstream() in the Go shim; both sides must agree
    /// or the editor accepts something the engine rejects.
    nonisolated static func upstreamProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return "Enter the address of your proxy." }
        guard let comps = URLComponents(string: s), let scheme = comps.scheme?.lowercased() else {
            return "That doesn't look like a proxy address."
        }
        guard Preset.from(scheme: scheme) != nil else {
            return "The address must start with socks5://, http:// or https://"
        }
        guard let host = comps.host, !host.isEmpty else {
            return "The proxy address is missing a host name."
        }
        if s.contains("@") {
            // Credentials belong in the sign-in fields, not the URL — they would
            // be persisted in providerConfiguration otherwise.
            return "Put the username and password in the sign-in fields below, not in the address."
        }
        return nil
    }

    nonisolated var upstreamProblem: String? { Self.upstreamProblem(upstream) }

    /// Why a route CIDR can't be used — nil when it's fine. Same rules as the
    /// Go side (parseRoutes): a real CIDR, in range, with no host bits set.
    /// Self-contained (not delegating to TailscaleConfig) because this must be
    /// nonisolated for the connect flow, and TailscaleConfig's helpers are
    /// MainActor-isolated in the app target.
    nonisolated static func routeProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Enter a network like 192.168.1.0/24." }
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            return "\(s) is missing the /length (for example 192.168.1.0/24)."
        }
        let address = String(parts[0])
        let isV6 = address.contains(":")
        let maxPrefix = isV6 ? 128 : 32
        guard prefix >= 0, prefix <= maxPrefix else {
            return "\(s) has a length outside 0\u{2013}\(maxPrefix)."
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = address.withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
        guard ok else { return "\(address) isn't a valid address." }
        return nil
    }

    /// First problem across a route list, or nil.
    nonisolated static func routesProblem(_ list: [String]) -> String? {
        for r in list {
            if let p = routeProblem(r) { return p }
        }
        return nil
    }

    /// Parse a comma/newline/space separated list into individual CIDR entries.
    nonisolated static func splitRoutes(_ raw: String) -> [String] {
        raw.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " || $0 == "\t" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Why the whole config can't connect (the connect-flow gate), or nil.
    nonisolated var connectProblem: String? {
        if let p = upstreamProblem { return p }
        if !includeDefaultRoute, includedRoutes.isEmpty {
            return "Add at least one network to route through the proxy, or turn on \u{201C}Send all traffic\u{201D}."
        }
        if let p = Self.routesProblem(includedRoutes) { return p }
        if let p = Self.routesProblem(excludedRoutes) { return p }
        return nil
    }
}

// MARK: - Start payload (the PXStart contract)

/// Exactly the JSON `PXStart` parses. Field names are load-bearing — they are
/// checked against the Go side by TestStartConfigKeys over there and
/// ProxyTunnelTests over here.
nonisolated struct ProxyTunnelStartConfig: Codable, Sendable, Equatable {
    var upstream: String
    /// Session-only. Reaches this struct from startTunnel options, is handed
    /// straight to the engine, and is never persisted or logged.
    var username: String
    var password: String
    var mtu: Int

    /// A safe utun default. Flows are re-dialled as fresh TCP through the proxy,
    /// so the engine does not depend on a precise value here.
    static let defaultMTU = 1500

    init(config: ProxyTunnelConfig, username: String, password: String) {
        upstream = config.upstream.trimmingCharacters(in: .whitespacesAndNewlines)
        self.username = username
        self.password = password
        mtu = config.mtu > 0 ? config.mtu : ProxyTunnelStartConfig.defaultMTU
    }

    func jsonString() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let d = try? enc.encode(self), let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }

    /// Same JSON with the credentials replaced — the only form that may be
    /// logged.
    func redactedJSONString() -> String {
        var copy = self
        copy.username = username.isEmpty ? "" : "<redacted>"
        copy.password = password.isEmpty ? "" : "<redacted>"
        return copy.jsonString()
    }
}

// MARK: - Engine → app status (the PXStatus payload)

/// The PXStatus payload. Carries NO secrets and NO upstream address — only the
/// scheme, flow counters and byte counters.
nonisolated struct ProxyTunnelStatus: Codable, Sendable, Equatable {
    var state: String = "stopped"
    var scheme: String = ""
    var lastError: String = ""
    var activeFlows: Int64 = 0
    var totalFlows: Int64 = 0
    var failedFlows: Int64 = 0
    var udpFlows: Int64 = 0
    var dnsQueries: Int64 = 0
    var bytesUp: Int64 = 0
    var bytesDown: Int64 = 0
    var packetsInDropped: Int64 = 0

    var isRunning: Bool { state == "running" }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = (try? c.decodeIfPresent(String.self, forKey: .state)) ?? "stopped"
        scheme = (try? c.decodeIfPresent(String.self, forKey: .scheme)) ?? ""
        lastError = (try? c.decodeIfPresent(String.self, forKey: .lastError)) ?? ""
        activeFlows = (try? c.decodeIfPresent(Int64.self, forKey: .activeFlows)) ?? 0
        totalFlows = (try? c.decodeIfPresent(Int64.self, forKey: .totalFlows)) ?? 0
        failedFlows = (try? c.decodeIfPresent(Int64.self, forKey: .failedFlows)) ?? 0
        udpFlows = (try? c.decodeIfPresent(Int64.self, forKey: .udpFlows)) ?? 0
        dnsQueries = (try? c.decodeIfPresent(Int64.self, forKey: .dnsQueries)) ?? 0
        bytesUp = (try? c.decodeIfPresent(Int64.self, forKey: .bytesUp)) ?? 0
        bytesDown = (try? c.decodeIfPresent(Int64.self, forKey: .bytesDown)) ?? 0
        packetsInDropped = (try? c.decodeIfPresent(Int64.self, forKey: .packetsInDropped)) ?? 0
    }

    static func decode(json: String) -> ProxyTunnelStatus? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ProxyTunnelStatus.self, from: d)
    }
}
