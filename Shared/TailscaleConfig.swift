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
    /// Which browser opens the sign-in page. Tailscale's identity-provider login
    /// often needs your REAL browser (passkeys, password managers), so this defaults
    /// to the OS default browser rather than the in-app window — but you can point it
    /// at a specific browser/profile or the in-app sign-in window.
    var signInBrowser: BrowserSelection = .osDefault

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
        signInBrowser = (try? c.decodeIfPresent(BrowserSelection.self, forKey: .signInBrowser)) ?? .osDefault
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

    // MARK: Legal ranges / limits (single source of truth for UI validation)

    /// A machine name is a DNS label: at most 63 characters. Tailscale sanitizes
    /// silently (so a bad name becomes a different name than the one on screen);
    /// Headscale may refuse outright. Hence a warning, not a block.
    static let hostnameMaxLength = 63
    /// The tailnet's own address space (RFC 6598 carrier-grade NAT, which is what
    /// Tailscale hands out) — the range a machine address must fall inside.
    static let tailnetPrefix = "100.64.0.0/10"
    /// Advertised prefix lengths. /0 is DELIBERATELY excluded: Tailscale and
    /// Headscale both refuse `0.0.0.0/0` as an advertised route and tell you to
    /// advertise an exit node instead, so accepting it here is a silent
    /// connect failure.
    static let advertisePrefixLengthRange = 1...128
    /// What a Tailscale auth key looks like. Headscale's keys don't follow it,
    /// so this only ever produces a warning.
    static let authKeyPrefix = "tskey-"

    /// Trim everything and drop empties — called from every save path, the same
    /// shape as `OpenVPNOverrides.normalized()`.
    func normalized() -> TailscaleConfig {
        var n = self
        n.controlURL = controlURL.trimmingCharacters(in: .whitespacesAndNewlines)
        n.hostname = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        n.exitNode = exitNode.trimmingCharacters(in: .whitespacesAndNewlines)
        n.advertiseRoutes = advertiseRoutes
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // `exitNode` is deliberately KEPT when the toggle is off: the start
        // payload already refuses to send it, and clearing it here would throw
        // away what the user picked the moment they toggled the feature off.
        return n
    }

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
        // Reject credentials in the address (https://user:secret@host). This
        // URL is persisted in providerConfiguration, NOT the keychain, so a
        // password here would be stored in the clear — the same rule, for the
        // same reason, as ProxyTunnelConfig.upstreamProblem.
        if Self.hasUserInfo(s) {
            return "Take the username and password out of the address — sign in with an auth key (or your browser) under Sign-In."
        }
        return nil
    }

    /// Whether a URL string carries a userinfo component (anything before an
    /// "@" in the authority). Scans the authority itself rather than trusting
    /// `URL.user`, which silently drops what it can't parse.
    private static func hasUserInfo(_ s: String) -> Bool {
        guard let schemeEnd = s.range(of: "://") else { return false }
        return s[schemeEnd.upperBound...].prefix { $0 != "/" }.contains("@")
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
        // A /0 passes every other check and is then refused by the control
        // server ("use --advertise-exit-node"), i.e. a silent connect failure.
        // Point at the setting that actually does what they wanted.
        guard prefix >= advertisePrefixLengthRange.lowerBound else {
            return "\(s) covers everything, which your network won't accept as a shared network. To carry other machines' internet traffic, turn on \u{201C}Send all internet traffic through another machine\u{201D} on THOSE machines instead."
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = address.withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
        guard ok else { return "\(address) isn't a valid address." }
        guard !hasHostBits(bytes, prefix: prefix, byteCount: isV6 ? 16 : 4) else {
            return "\(s) isn't the start of a network — try \(masked(address: bytes, prefix: prefix, isV6: isV6))/\(prefix)."
        }
        return nil
    }

    /// Why this exit machine can't be used — nil when it's fine (and nil for an
    /// empty string; whether an empty one is ALLOWED depends on the toggle, and
    /// that's `exitNodeSelectionProblem`'s question).
    ///
    /// Three shapes are legal, because all three are what people have to hand:
    /// the machine's address in the tailnet range, its stable node id from
    /// TSStatus (`nabc123…`), or its DNS name.
    static func exitNodeProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.contains("/") {
            return "Enter one machine, not a network — its address (100.x.y.z), its name, or the id from your admin page."
        }
        // An address: it must be one of the tailnet's own.
        var bytes = [UInt8](repeating: 0, count: 16)
        let isV6 = s.contains(":")
        if s.withCString({ inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }) {
            guard !isV6 else { return nil }             // Tailscale's own fd7a:… range
            guard RoutePrefixMath.overlaps("\(s)/32", tailnetPrefix) else {
                return "\(s) isn't an address on this network — machines here are numbered 100.64.x.x to 100.127.x.x."
            }
            return nil
        }
        // A stable node id.
        if s.hasPrefix("n"), s.dropFirst().allSatisfy({ $0.isLetter || $0.isNumber }), s.count > 1 {
            return nil
        }
        // Otherwise it must look like a name.
        guard s.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." }) else {
            return "\(s) isn't a machine address, name or id."
        }
        return nil
    }

    /// The exit-node setting as a whole: on with nothing chosen starts a tunnel
    /// that sends traffic NOWHERE — no default route to any machine, and no
    /// direct path either. Gated at Save and at Connect because it is silent.
    var exitNodeSelectionProblem: String? {
        guard useExitNode else { return nil }
        if exitNode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Choose which machine carries your internet traffic — with the setting on and no machine chosen, nothing gets through."
        }
        return Self.exitNodeProblem(exitNode)
    }

    /// Non-blocking: Tailscale silently rewrites a machine name that isn't a
    /// plain DNS label, so the name on the admin page stops matching the one
    /// here; Headscale may refuse it outright.
    static func hostnameWarning(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.count > hostnameMaxLength {
            return "Names are cut to \(hostnameMaxLength) characters, so this Mac will appear under a shortened name."
        }
        if s.contains(where: { !($0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")) }) {
            return "Only letters, numbers and hyphens survive — anything else is replaced, so this Mac may appear under a different name than the one typed here."
        }
        return nil
    }

    /// Non-blocking: a Tailscale auth key starts `tskey-`. Headscale's keys
    /// don't, so this can only ever be a nudge — most often "you pasted half
    /// of it".
    static func authKeyWarning(_ raw: String, preset: Preset) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, preset == .tailscale, !s.hasPrefix(authKeyPrefix) else { return nil }
        return "A Tailscale setup key starts with \u{201C}\(authKeyPrefix)\u{201D} — check you pasted the whole key. (Keys from your own server look different, and that's fine.)"
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
