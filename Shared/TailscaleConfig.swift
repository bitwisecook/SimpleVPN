// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleConfig.swift
//  The Swift half of the Tailscale/Headscale engine's JSON contract: the saved
//  per-VPN settings, the start payload handed to TSStart, and the decoders for
//  what the engine sends back (state, netmap/tunnel config, status). Shared
//  between the app (editor, status projection) and the extension (which runs
//  the engine), so it imports nothing beyond Foundation.
//
//  Headscale is NOT a second engine or a second VPNKind — it is this engine
//  pointed at a self-hosted control server. The preset only decides whether the
//  editor asks for that URL.
//
//  Invariant: no secrets live in this type. The auth key rides startTunnel
//  options in memory (see TailscaleStartConfig.authKey), exactly like every
//  other credential in this app.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Saved settings

nonisolated struct TailscaleConfig: Codable, Sendable, Equatable {

    /// Which control plane this VPN talks to. Purely a UI affordance over the
    /// one field that actually differs (`controlURL`).
    nonisolated enum Preset: String, Codable, Sendable, CaseIterable {
        case tailscale
        case headscale

        var displayName: String {
            switch self {
            case .tailscale: "Tailscale"
            case .headscale: "Headscale (self-hosted)"
            }
        }

        /// Non-technical one-liner for the editor.
        var summary: String {
            switch self {
            case .tailscale:
                "Tailscale's own service. Sign in with the account your network is on."
            case .headscale:
                "Your own Tailscale-compatible server. Enter its web address below."
            }
        }
    }

    var preset: Preset = .tailscale
    /// Control server. Empty (and ignored) for the Tailscale preset; required
    /// for Headscale.
    var controlURL: String = ""
    /// The name this Mac appears under on the network. Defaults to the Mac's
    /// name at creation time.
    var hostname: String = ""
    /// Use the routes other machines share (subnet routers). On by default:
    /// switching it off is the surprising choice, not the safe one.
    var acceptRoutes: Bool = true
    /// Use the network's own DNS (MagicDNS) so machine names resolve.
    var acceptDNS: Bool = true
    /// Send all internet traffic through another machine on the network.
    var useExitNode: Bool = false
    /// Which machine: its network address, or its stable id from TSStatus.
    var exitNode: String = ""
    /// Keep reaching the local network (printers, NAS) while an exit node is on.
    var exitNodeAllowLANAccess: Bool = true
    /// Networks this Mac offers to share with the others (advanced).
    var advertiseRoutes: [String] = []

    /// The URL actually handed to the engine: the Tailscale preset always uses
    /// the service's own control plane regardless of any stale text left in the
    /// field by someone who switched presets.
    var effectiveControlURL: String {
        preset == .headscale ? controlURL.trimmingCharacters(in: .whitespacesAndNewlines) : ""
    }

    // Lenient decoding, same invariant as OpenVPNOverrides: an app and an
    // extension of different vintages must still agree, and a missing field
    // must mean "the documented default", never a decode failure that breaks
    // connecting.
    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        preset = (try? c.decodeIfPresent(Preset.self, forKey: .preset)) ?? .tailscale
        controlURL = (try? c.decodeIfPresent(String.self, forKey: .controlURL)) ?? ""
        hostname = (try? c.decodeIfPresent(String.self, forKey: .hostname)) ?? ""
        acceptRoutes = (try? c.decodeIfPresent(Bool.self, forKey: .acceptRoutes)) ?? true
        acceptDNS = (try? c.decodeIfPresent(Bool.self, forKey: .acceptDNS)) ?? true
        useExitNode = (try? c.decodeIfPresent(Bool.self, forKey: .useExitNode)) ?? false
        exitNode = (try? c.decodeIfPresent(String.self, forKey: .exitNode)) ?? ""
        exitNodeAllowLANAccess = (try? c.decodeIfPresent(Bool.self, forKey: .exitNodeAllowLANAccess)) ?? true
        advertiseRoutes = (try? c.decodeIfPresent([String].self, forKey: .advertiseRoutes)) ?? []
    }
}

extension TailscaleConfig {
    static func decode(from blob: Data?) -> TailscaleConfig {
        guard let blob, let c = try? JSONDecoder().decode(TailscaleConfig.self, from: blob) else {
            return TailscaleConfig()
        }
        return c
    }

    func encodedBlob() -> Data? { try? JSONEncoder().encode(self) }
}

// MARK: - Validation

extension TailscaleConfig {

    /// Why this control-server address can't be used, in the user's language —
    /// nil when it's fine. Mirrors validateControlURL() in the Go shim; both
    /// sides must agree or the editor accepts something the engine rejects.
    static func controlURLProblem(_ raw: String, preset: Preset) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty {
            return preset == .headscale ? "Enter the web address of your server." : nil
        }
        guard let url = URL(string: s), let host = url.host, !host.isEmpty else {
            return "That doesn't look like a web address."
        }
        guard url.scheme?.lowercased() == "https" else {
            // Plain http would carry the node key in the clear.
            return "The address must start with https://"
        }
        return nil
    }

    var controlURLProblem: String? {
        Self.controlURLProblem(controlURL, preset: preset)
    }

    /// Why an advertised network can't be used — nil when it's fine. Same rules
    /// as the Go side: a real CIDR, in range, with no host bits set.
    static func routeProblem(_ raw: String) -> String? {
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
            return "\(s) has a length outside 0–\(maxPrefix)."
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = address.withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
        guard ok else { return "\(address) isn't a valid address." }
        guard !hasHostBits(bytes, prefix: prefix, byteCount: isV6 ? 16 : 4) else {
            return "\(s) isn't the start of a network — try \(masked(address: bytes, prefix: prefix, isV6: isV6))/\(prefix)."
        }
        return nil
    }

    /// Parse a comma/newline/space separated list into individual entries. The
    /// editor stores one string; the engine wants a list.
    static func splitRoutes(_ raw: String) -> [String] {
        raw.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " || $0 == "\t" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// First problem across the whole advertised-routes list, or nil.
    static func routesProblem(_ list: [String]) -> String? {
        for r in list {
            if let p = routeProblem(r) { return p }
        }
        return nil
    }

    private static func hasHostBits(_ bytes: [UInt8], prefix: Int, byteCount: Int) -> Bool {
        for i in 0..<byteCount {
            let bitsBefore = i * 8
            if prefix >= bitsBefore + 8 { continue }          // whole byte inside the prefix
            let keep = max(0, min(8, prefix - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            if bytes[i] & ~mask != 0 { return true }
        }
        return false
    }

    private static func masked(address bytes: [UInt8], prefix: Int, isV6: Bool) -> String {
        let byteCount = isV6 ? 16 : 4
        var out = bytes
        for i in 0..<byteCount {
            let bitsBefore = i * 8
            let keep = max(0, min(8, prefix - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            out[i] = bytes[i] & mask
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let s = out.withUnsafeBytes { raw -> String in
            guard let base = raw.baseAddress,
                  let p = inet_ntop(isV6 ? AF_INET6 : AF_INET, base, &buf, socklen_t(INET6_ADDRSTRLEN))
            else { return "" }
            return String(cString: p)
        }
        return s
    }
}

// MARK: - Start payload (the TSStart contract)

/// Exactly the JSON `TSStart` parses. Field names are load-bearing — they are
/// checked against the Go side by TestStartConfigKeys over there and
/// TailscaleConfigTests over here.
nonisolated struct TailscaleStartConfig: Codable, Sendable, Equatable {
    var controlURL: String
    var hostname: String
    /// Session-only. Reaches this struct from startTunnel options, is handed
    /// straight to the engine, and is never persisted or logged.
    var authKey: String
    var stateDir: String
    var acceptRoutes: Bool
    var acceptDNS: Bool
    var useExitNode: Bool
    var exitNode: String
    var exitNodeAllowLANAccess: Bool
    var advertiseRoutes: [String]
    var mtu: Int

    /// Tailscale's own default TUN MTU. Fixed rather than exposed: NE applies
    /// it verbatim and a wrong value here is a silently broken tunnel.
    static let defaultMTU = 1280

    init(config: TailscaleConfig, authKey: String, stateDir: String, mtu: Int = TailscaleStartConfig.defaultMTU) {
        controlURL = config.effectiveControlURL
        hostname = config.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        self.authKey = authKey
        self.stateDir = stateDir
        acceptRoutes = config.acceptRoutes
        acceptDNS = config.acceptDNS
        useExitNode = config.useExitNode
        exitNode = config.useExitNode ? config.exitNode.trimmingCharacters(in: .whitespaces) : ""
        exitNodeAllowLANAccess = config.exitNodeAllowLANAccess
        advertiseRoutes = config.advertiseRoutes
        self.mtu = mtu
    }

    func jsonString() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let d = try? enc.encode(self), let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }

    /// Same JSON with the auth key replaced — the only form that may be logged.
    func redactedJSONString() -> String {
        var copy = self
        copy.authKey = authKey.isEmpty ? "" : "<redacted>"
        return copy.jsonString()
    }
}

/// A partial prefs edit (the TSUpdatePrefs contract). Absent fields are left
/// alone by the engine, so this must encode nils as omissions.
nonisolated struct TailscalePrefsPatch: Codable, Sendable, Equatable {
    var acceptRoutes: Bool?
    var acceptDNS: Bool?
    var useExitNode: Bool?
    var exitNode: String?
    var exitNodeAllowLANAccess: Bool?
    var advertiseRoutes: [String]?

    func jsonString() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let d = try? enc.encode(self), let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }
}

// MARK: - Engine → app payloads

/// The netmapChanged payload: what the engine decided the tunnel should look
/// like. Turned into NEPacketTunnelNetworkSettings by TailscaleNetworkSettings.
nonisolated struct TailscaleTunnelConfig: Codable, Sendable, Equatable {
    var localAddrs: [String] = []
    var routes: [String] = []
    var localRoutes: [String] = []
    var subnetRoutes: [String] = []
    var mtu: Int = TailscaleStartConfig.defaultMTU
    var dns = DNS()

    nonisolated struct DNS: Codable, Sendable, Equatable {
        var nameservers: [String] = []
        var searchDomains: [String] = []
        var matchDomains: [String] = []
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        localAddrs = (try? c.decodeIfPresent([String].self, forKey: .localAddrs)) ?? []
        routes = (try? c.decodeIfPresent([String].self, forKey: .routes)) ?? []
        localRoutes = (try? c.decodeIfPresent([String].self, forKey: .localRoutes)) ?? []
        subnetRoutes = (try? c.decodeIfPresent([String].self, forKey: .subnetRoutes)) ?? []
        mtu = (try? c.decodeIfPresent(Int.self, forKey: .mtu)) ?? TailscaleStartConfig.defaultMTU
        dns = (try? c.decodeIfPresent(DNS.self, forKey: .dns)) ?? DNS()
    }

    static func decode(json: String) -> TailscaleTunnelConfig? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(TailscaleTunnelConfig.self, from: d)
    }

    /// True when an exit node (or an advertised default route we accepted) is
    /// pulling everything through the tunnel.
    var carriesDefaultRoute: Bool {
        routes.contains("0.0.0.0/0") || routes.contains("::/0")
    }
}

/// The stateChanged payload.
nonisolated struct TailscaleStateEvent: Codable, Sendable, Equatable {
    var state: String = ""
    var authURL: String = ""
    var message: String = ""

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = (try? c.decodeIfPresent(String.self, forKey: .state)) ?? ""
        authURL = (try? c.decodeIfPresent(String.self, forKey: .authURL)) ?? ""
        message = (try? c.decodeIfPresent(String.self, forKey: .message)) ?? ""
    }

    init(state: String, authURL: String = "", message: String = "") {
        self.state = state
        self.authURL = authURL
        self.message = message
    }

    static func decode(json: String) -> TailscaleStateEvent? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(TailscaleStateEvent.self, from: d)
    }
}

/// One machine on the network that can act as an exit node.
nonisolated struct TailscalePeer: Codable, Sendable, Equatable, Identifiable {
    var id: String = ""
    var name: String = ""
    var hostName: String = ""
    var ips: [String] = []
    var online: Bool = false
    var active: Bool = false
    var country: String = ""
    var city: String = ""

    /// What the exit-node picker shows: the machine name, with its location
    /// when the network publishes one.
    var pickerLabel: String {
        let base = name.isEmpty ? hostName : name
        let place = [city, country].filter { !$0.isEmpty }.joined(separator: ", ")
        return place.isEmpty ? base : "\(base) — \(place)"
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        name = (try? c.decodeIfPresent(String.self, forKey: .name)) ?? ""
        hostName = (try? c.decodeIfPresent(String.self, forKey: .hostName)) ?? ""
        ips = (try? c.decodeIfPresent([String].self, forKey: .ips)) ?? []
        online = (try? c.decodeIfPresent(Bool.self, forKey: .online)) ?? false
        active = (try? c.decodeIfPresent(Bool.self, forKey: .active)) ?? false
        country = (try? c.decodeIfPresent(String.self, forKey: .country)) ?? ""
        city = (try? c.decodeIfPresent(String.self, forKey: .city)) ?? ""
    }
}

/// The TSStatus payload.
nonisolated struct TailscaleStatus: Codable, Sendable, Equatable {
    var state: String = TailscaleBackendState.noState.rawValue
    var authURL: String = ""
    var haveNodeKey: Bool = false
    var selfIPs: [String] = []
    var selfDNSName: String = ""
    var selfHostName: String = ""
    var magicDNSSuffix: String = ""
    var tailnet: String = ""
    var peerCount: Int = 0
    var peersOnline: Int = 0
    var exitNodes: [TailscalePeer] = []
    var exitNodeID: String = ""
    var exitNodeName: String = ""
    var rxBytes: Int64 = 0
    var txBytes: Int64 = 0
    var health: [String] = []
    var config: TailscaleTunnelConfig?
    var packetsDropped: Int64 = 0

    var backendState: TailscaleBackendState { TailscaleBackendState(engineName: state) }

    /// The address to show as "your address on this network". Prefers IPv4
    /// because that's the 100.x one people recognise.
    var primaryIPv4: String { selfIPs.first { !$0.contains(":") } ?? "" }
    var primaryIPv6: String { selfIPs.first { $0.contains(":") } ?? "" }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = (try? c.decodeIfPresent(String.self, forKey: .state)) ?? TailscaleBackendState.noState.rawValue
        authURL = (try? c.decodeIfPresent(String.self, forKey: .authURL)) ?? ""
        haveNodeKey = (try? c.decodeIfPresent(Bool.self, forKey: .haveNodeKey)) ?? false
        selfIPs = (try? c.decodeIfPresent([String].self, forKey: .selfIPs)) ?? []
        selfDNSName = (try? c.decodeIfPresent(String.self, forKey: .selfDNSName)) ?? ""
        selfHostName = (try? c.decodeIfPresent(String.self, forKey: .selfHostName)) ?? ""
        magicDNSSuffix = (try? c.decodeIfPresent(String.self, forKey: .magicDNSSuffix)) ?? ""
        tailnet = (try? c.decodeIfPresent(String.self, forKey: .tailnet)) ?? ""
        peerCount = (try? c.decodeIfPresent(Int.self, forKey: .peerCount)) ?? 0
        peersOnline = (try? c.decodeIfPresent(Int.self, forKey: .peersOnline)) ?? 0
        exitNodes = (try? c.decodeIfPresent([TailscalePeer].self, forKey: .exitNodes)) ?? []
        exitNodeID = (try? c.decodeIfPresent(String.self, forKey: .exitNodeID)) ?? ""
        exitNodeName = (try? c.decodeIfPresent(String.self, forKey: .exitNodeName)) ?? ""
        rxBytes = (try? c.decodeIfPresent(Int64.self, forKey: .rxBytes)) ?? 0
        txBytes = (try? c.decodeIfPresent(Int64.self, forKey: .txBytes)) ?? 0
        health = (try? c.decodeIfPresent([String].self, forKey: .health)) ?? []
        config = try? c.decodeIfPresent(TailscaleTunnelConfig.self, forKey: .config)
        packetsDropped = (try? c.decodeIfPresent(Int64.self, forKey: .packetsDropped)) ?? 0
    }

    static func decode(json: String) -> TailscaleStatus? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(TailscaleStatus.self, from: d)
    }
}

/// The engine's state machine, spelled the way `ipn.State` spells it.
nonisolated enum TailscaleBackendState: String, Sendable, CaseIterable {
    case noState = "NoState"
    case inUseOtherUser = "InUseOtherUser"
    case needsLogin = "NeedsLogin"
    case needsMachineAuth = "NeedsMachineAuth"
    case stopped = "Stopped"
    case starting = "Starting"
    case running = "Running"

    /// Unknown names from a newer engine degrade to .noState rather than
    /// throwing — a state we don't recognise must not break the tunnel.
    init(engineName: String) {
        self = TailscaleBackendState(rawValue: engineName) ?? .noState
    }

    /// Is the tunnel carrying traffic?
    var isConnected: Bool { self == .running }

    /// Is the user being asked for something? These are the states that must
    /// surface a sign-in window or an incident rather than spin forever.
    var needsUserAction: Bool { self == .needsLogin || self == .needsMachineAuth || self == .inUseOtherUser }

    /// Plain-language status for the connection panel.
    var displayText: String {
        switch self {
        case .noState: "Starting…"
        case .inUseOtherUser: "In use by another user"
        case .needsLogin: "Waiting for sign-in"
        case .needsMachineAuth: "Waiting for approval"
        case .stopped: "Stopped"
        case .starting: "Connecting…"
        case .running: "Connected"
        }
    }

    /// The incident this state represents when the tunnel gives up in it, or
    /// nil when it is a normal, non-terminal state.
    var incidentCategory: IncidentCategory? {
        switch self {
        case .needsLogin, .needsMachineAuth, .inUseOtherUser: .auth
        case .stopped: .network
        default: nil
        }
    }
}
