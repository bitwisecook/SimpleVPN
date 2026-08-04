// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetworkTunnelConfig.swift
//  The Swift half of the SSH Network Tunnel's contract: the saved per-VPN
//  settings, the start payload handed to the engine, and the host-key decision
//  the app makes on the extension's behalf. Shared between the app (editor,
//  status projection, trust resolution) and the extension (which runs the
//  session), so it imports nothing beyond Foundation.
//
//  WHAT THIS KIND IS. A utun with routes, a userspace TCP/IP stack behind it
//  (the same gVisor netstack the Proxy Tunnel uses), and one SSH `direct-tcpip`
//  channel per flow. Traffic the routes send into the utun is terminated by the
//  netstack and re-originated as a byte stream over the SSH session — so from
//  the server's point of view every connection is an ordinary `ssh -L` forward,
//  and no server-side configuration is needed at all. Contrast `ssh -w`
//  (tun@openssh.com), which needs root on the server and `PermitTunnel`.
//
//  TCP ONLY, and that is a protocol fact, not a gap we plan to close: the SSH
//  protocol has no datagram channel. DNS is rescued as DNS-over-TCP (RFC 7766);
//  every other UDP flow is refused per-flow and counted. QUIC does not work
//  through this tunnel, and the editor says so rather than letting someone
//  discover it.
//
//  NO MSS CLAMP AND NO MTU REDUCTION. Nothing here is encapsulated: the netstack
//  TERMINATES the guest's TCP and opens a separate stream to the server, so a
//  guest segment never travels inside another IP packet. There is no outer header
//  to make room for, so clamping would prevent no fragmentation, and the classic
//  TCP-over-TCP meltdown (retransmissions stacking on retransmissions) needs the
//  same nesting to happen and equally does not apply. The real costs are window
//  mismatch and double congestion control, which a smaller MSS makes worse.
//
//  Invariant: no secrets live in this saved type. The username is here (a login
//  name is not a secret); the password, key and certificate ride startTunnel
//  options in memory, exactly like every other credential in this app — never in
//  providerConfiguration.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Saved settings

nonisolated struct SSHNetworkTunnelConfig: Codable, Sendable, Equatable {

    /// How this tunnel signs in. Deliberately THREE cases and not five: an SSH
    /// agent needs `SSH_AUTH_SOCK` and Kerberos needs the user's ticket cache,
    /// and the packet-tunnel extension runs as root in the system context where
    /// neither exists. `unavailableMethodReason` is what the editor shows in
    /// their place — a missing option with no explanation reads as a bug.
    nonisolated enum AuthMethod: String, Codable, Sendable, CaseIterable {
        case password
        case privateKey
        case certificate

        var displayName: String {
            switch self {
            case .password: "Password"
            case .privateKey: "Private Key"
            case .certificate: "Certificate"
            }
        }

        var summary: String {
            switch self {
            case .password:
                "Sign in with the account password on the server."
            case .privateKey:
                "Sign in with a private key. SimpleVPN keeps the key itself, so it works without an SSH agent."
            case .certificate:
                "Sign in with a key plus the certificate your organisation signed it with."
            }
        }
    }

    /// Why an SSH sign-in method everyone expects to see is not offered. Shown
    /// next to the picker, never silently omitted.
    nonisolated static let unavailableMethodReason =
        "SSH agent and Kerberos sign-in can't work here: the tunnel runs as a system service, "
        + "outside your login session, so it can reach neither your agent nor your Kerberos ticket. "
        + "Use a private key or certificate instead — SimpleVPN holds the key for you."

    /// What to do about the server's host key. The EXTENSION is pin-only and
    /// never prompts; this is the app's ladder for arriving at the pin.
    nonisolated enum HostKeyPolicy: String, Codable, Sendable, CaseIterable {
        /// Only the fingerprint in `pinnedHostKeySHA256`. Nothing else connects.
        case pinned
        /// The key must already be in known_hosts. Never trusts a new one.
        case knownHostsOnly
        /// Known hosts, and a new host is trusted once after the user confirms —
        /// the confirmation is a SHEET, never silent, and never in the extension.
        case trustOnFirstUse

        var displayName: String {
            switch self {
            case .pinned: "Only the pinned key"
            case .knownHostsOnly: "Only known hosts"
            case .trustOnFirstUse: "Trust on first use"
            }
        }
    }

    /// The SSH server this tunnel connects to.
    var server: String = ""
    /// The port its SSH service answers on. 0/absent ⇒ 22.
    var port: Int = 0
    /// The login name on the server. Not a secret — it is saved.
    var username: String = ""

    var authMethod: AuthMethod = .password
    var hostKeyPolicy: HostKeyPolicy = .trustOnFirstUse
    /// The expected host-key fingerprint, SHA-256 hex (with or without a
    /// "SHA256:" prefix). REQUIRED for `.pinned`; filled in by the app for the
    /// other policies once trust is resolved, because the extension accepts
    /// nothing else.
    var pinnedHostKeySHA256: String = ""

    /// Send ALL traffic through the tunnel (default-route). Off ⇒ only the
    /// included routes below enter the tunnel.
    var includeDefaultRoute: Bool = true
    /// Destinations pulled into the tunnel when not using the default route.
    var includedRoutes: [String] = []
    /// Destinations kept OUT of the tunnel even under the default route. The SSH
    /// server's own address is excluded automatically by the provider — these are
    /// extra carve-outs the user wants direct.
    var excludedRoutes: [String] = []

    /// DNS servers to advertise on the utun. Each query is carried as
    /// DNS-over-TCP through the session to the resolver the guest addressed.
    /// Empty ⇒ leave the Mac's own resolvers alone (and see `dnsWarning`).
    var dnsServers: [String] = []
    /// Resolve names AT THE SERVER: advertise the sentinel address below and
    /// forward every query addressed to it to `farSideResolver` as the SSH server
    /// sees it. This is the shape SSH is uniquely good at and a SOCKS proxy
    /// cannot express at all.
    var useFarSideResolver: Bool = false
    /// The resolver as the SERVER sees it — "127.0.0.1:53" for the server's own
    /// stub resolver, or an internal address only it can reach.
    var farSideResolver: String = SSHNetworkTunnelConfig.defaultFarSideResolver

    /// Tunnel MTU. Not a knob that fixes stalls here (nothing is encapsulated),
    /// but the link still has to state one.
    var mtu: Int = SSHNetworkTunnelStartConfig.defaultMTU

    /// Seconds between session keepalives, 0 ⇒ off. A netstack flow that goes
    /// quiet must not let a NAT drop the carrier underneath it.
    var keepaliveSeconds: Int = 30

    /// Key-exchange preference (OpenSSH `KexAlgorithms` syntax). Empty ⇒ the
    /// engine's own list, which already prefers the post-quantum hybrids.
    var keyExchange: String = ""

    /// The default far-side resolver: the server's own stub resolver, which is
    /// what "resolve names on the other side" means to almost everyone.
    nonisolated static let defaultFarSideResolver = "127.0.0.1:53"

    var effectivePort: Int { port > 0 ? port : 22 }

    /// The upstream URL the engine parses. `ssh://user@host:port` — the username
    /// rides it because it is not a secret, and the engine's own parser accepts
    /// exactly this shape (see parseUpstream in proxy.go).
    var upstreamURL: String {
        let host = server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { return "" }
        // Bracket a literal IPv6 address so the URL parses.
        let hostPart = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let userPart = user.isEmpty
            ? ""
            : (user.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(
                CharacterSet(charactersIn: "-._~"))) ?? user) + "@"
        return "ssh://\(userPart)\(hostPart):\(effectivePort)"
    }

    // Lenient decoding, same invariant as OpenVPNOverrides/ProxyTunnelConfig: an
    // app and an extension of different vintages must still agree, and a missing
    // field means the documented default, never a decode failure that breaks
    // connecting.
    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        server = (try? c.decodeIfPresent(String.self, forKey: .server)) ?? ""
        port = (try? c.decodeIfPresent(Int.self, forKey: .port)) ?? 0
        username = (try? c.decodeIfPresent(String.self, forKey: .username)) ?? ""
        authMethod = (try? c.decodeIfPresent(AuthMethod.self, forKey: .authMethod)) ?? .password
        hostKeyPolicy = (try? c.decodeIfPresent(HostKeyPolicy.self, forKey: .hostKeyPolicy)) ?? .trustOnFirstUse
        pinnedHostKeySHA256 = (try? c.decodeIfPresent(String.self, forKey: .pinnedHostKeySHA256)) ?? ""
        includeDefaultRoute = (try? c.decodeIfPresent(Bool.self, forKey: .includeDefaultRoute)) ?? true
        includedRoutes = (try? c.decodeIfPresent([String].self, forKey: .includedRoutes)) ?? []
        excludedRoutes = (try? c.decodeIfPresent([String].self, forKey: .excludedRoutes)) ?? []
        dnsServers = (try? c.decodeIfPresent([String].self, forKey: .dnsServers)) ?? []
        useFarSideResolver = (try? c.decodeIfPresent(Bool.self, forKey: .useFarSideResolver)) ?? false
        farSideResolver = (try? c.decodeIfPresent(String.self, forKey: .farSideResolver))
            ?? Self.defaultFarSideResolver
        mtu = (try? c.decodeIfPresent(Int.self, forKey: .mtu)) ?? SSHNetworkTunnelStartConfig.defaultMTU
        keepaliveSeconds = (try? c.decodeIfPresent(Int.self, forKey: .keepaliveSeconds)) ?? 30
        keyExchange = (try? c.decodeIfPresent(String.self, forKey: .keyExchange)) ?? ""
    }
}

extension SSHNetworkTunnelConfig {
    static func decode(from blob: Data?) -> SSHNetworkTunnelConfig {
        guard let blob,
              let c = try? JSONDecoder().decode(SSHNetworkTunnelConfig.self, from: blob) else {
            return SSHNetworkTunnelConfig()
        }
        return c
    }

    func encodedBlob() -> Data? { try? JSONEncoder().encode(self) }

    /// Whether this config needs a private key (and therefore a stored one).
    var needsPrivateKey: Bool { authMethod == .privateKey || authMethod == .certificate }
    /// Whether it needs an OpenSSH certificate as well.
    var needsCertificate: Bool { authMethod == .certificate }
}

// MARK: - Validation

extension SSHNetworkTunnelConfig {

    nonisolated static let portRange = 1...65535
    /// utun MTU. Floor is IPv4's minimum reassembly buffer, ceiling standard
    /// Ethernet. Flows are re-originated as fresh TCP so the engine is forgiving —
    /// but a value outside this can't be carried by the link.
    nonisolated static let mtuRange = 576...1500
    /// Keepalive seconds. 0 is off; below 5 s is a keepalive storm, above an hour
    /// is not a keepalive.
    nonisolated static let keepaliveRange = 0...3600

    /// The utun-side sentinel the guest addresses to mean "resolve at the other
    /// end". Inside the same RFC 2544 benchmarking range as the tunnel's own
    /// address, for the same reason: it is not used for real traffic anywhere.
    nonisolated static let farSideResolverSentinel = "198.18.0.53"
    nonisolated static let farSideResolverSentinelV6 = "fd6e:7853:0::53"

    /// Trim, drop empties, and pull numbers back into range — called from every
    /// save path, so a stored value can never be one the editor's ranges refuse.
    nonisolated func normalized() -> SSHNetworkTunnelConfig {
        var n = self
        n.server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        n.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        n.keyExchange = keyExchange.trimmingCharacters(in: .whitespacesAndNewlines)
        n.farSideResolver = farSideResolver.trimmingCharacters(in: .whitespacesAndNewlines)
        n.pinnedHostKeySHA256 = pinnedHostKeySHA256.trimmingCharacters(in: .whitespacesAndNewlines)
        func cleanList(_ l: [String]) -> [String] {
            l.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        n.includedRoutes = cleanList(includedRoutes)
        n.excludedRoutes = cleanList(excludedRoutes)
        n.dnsServers = cleanList(dnsServers)
        if n.port != 0, !Self.portRange.contains(n.port) { n.port = 0 }
        if !Self.mtuRange.contains(n.mtu) { n.mtu = SSHNetworkTunnelStartConfig.defaultMTU }
        if !Self.keepaliveRange.contains(n.keepaliveSeconds) { n.keepaliveSeconds = 30 }
        if n.farSideResolver.isEmpty { n.farSideResolver = Self.defaultFarSideResolver }
        return n
    }

    /// Why this server address can't be used, in the user's language — nil when
    /// it's fine.
    nonisolated static func serverProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return "Enter the address of your SSH server." }
        if s.contains("://") {
            return "Enter just the server address — SimpleVPN adds the ssh:// part itself."
        }
        if s.contains("@") {
            return "Put the login name in the Username field, not in the address."
        }
        if s.contains(" ") { return "A server address can't contain spaces." }
        return nil
    }

    nonisolated var serverProblem: String? { Self.serverProblem(server) }

    /// Why this far-side resolver can't be used — nil when it's fine. It is a
    /// `host` or `host:port` AS THE SERVER SEES IT, so a name is legal (the
    /// server resolves it), but it must have a host part.
    nonisolated static func farSideResolverProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Enter the resolver as the server sees it, like 127.0.0.1:53." }
        if s.contains("://") { return "Enter an address and port, like 127.0.0.1:53 — not a URL." }
        // Bracketed IPv6 with a port, or the bare literal.
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]"), close > s.index(after: s.startIndex) else {
                return "\(s) is missing the closing bracket around the IPv6 address."
            }
            let rest = s[s.index(after: close)...]
            if rest.isEmpty { return nil }
            guard rest.hasPrefix(":"), let p = Int(rest.dropFirst()), portRange.contains(p) else {
                return "\(s) doesn't end in a valid port."
            }
            return nil
        }
        // A bare IPv6 literal has more than one colon and no port.
        if s.filter({ $0 == ":" }).count > 1 { return nil }
        let parts = s.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard !parts[0].isEmpty else { return "\(s) is missing the resolver's address." }
        if parts.count == 2 {
            guard let p = Int(parts[1]), portRange.contains(p) else {
                return "\(parts[1]) isn't a valid port — use 1 to 65535."
            }
        }
        return nil
    }

    /// Why a route CIDR can't be used — nil when it's fine. Same rules and the
    /// same wording as `ProxyTunnelConfig.routeProblem` (these become
    /// `NEIPv4Route`s in exactly the same way, and NE installs the MASKED prefix
    /// rather than erroring on host bits — so a typo silently routes something
    /// else unless it is refused here).
    nonisolated static func routeProblem(_ raw: String) -> String? {
        ProxyTunnelConfig.routeProblem(raw)
    }

    nonisolated static func routesProblem(_ list: [String]) -> String? {
        ProxyTunnelConfig.routesProblem(list)
    }

    nonisolated static func dnsServerProblem(_ raw: String) -> String? {
        ProxyTunnelConfig.dnsServerProblem(raw)
    }

    nonisolated static func dnsServersProblem(_ list: [String]) -> String? {
        ProxyTunnelConfig.dnsServersProblem(list)
    }

    /// Why the pinned fingerprint can't be used — nil when it's fine. A SHA-256
    /// is 32 bytes; anything shorter is a TRUNCATED pin, and the bridge compares
    /// for exact equality precisely so a truncated one can never match. Refusing
    /// it here means the user learns that at the editor rather than at connect.
    nonisolated static func pinProblem(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Paste the server's SHA-256 host-key fingerprint." }
        // Same tag rule as SSHHostKeyDecision.normalize — see the note there on
        // why the tag is identified by non-hex content and not by position.
        if let colon = s.firstIndex(of: ":") {
            let head = s[s.startIndex..<colon]
            if !head.isEmpty, !head.allSatisfy(\.isHexDigit) {
                s = String(s[s.index(after: colon)...])
            }
        }
        s = s.replacingOccurrences(of: ":", with: "").lowercased()
        guard s.allSatisfy({ $0.isHexDigit }) else {
            return "A host-key fingerprint is hexadecimal — that has other characters in it."
        }
        guard s.count == 64 else {
            return s.count < 64
                ? "That fingerprint is too short (\(s.count) of 64 characters) — a partial fingerprint would never match."
                : "That fingerprint is too long (\(s.count) of 64 characters)."
        }
        return nil
    }

    /// The pin in the form the bridge compares: bare lowercase hex, no prefix,
    /// no separators. Empty when there is nothing usable.
    nonisolated var normalizedPin: String {
        var s = pinnedHostKeySHA256.trimmingCharacters(in: .whitespacesAndNewlines)
        // Same tag rule as SSHHostKeyDecision.normalize — see the note there on
        // why the tag is identified by non-hex content and not by position.
        if let colon = s.firstIndex(of: ":") {
            let head = s[s.startIndex..<colon]
            if !head.isEmpty, !head.allSatisfy(\.isHexDigit) {
                s = String(s[s.index(after: colon)...])
            }
        }
        s = s.replacingOccurrences(of: ":", with: "").lowercased()
        return s.count == 64 && s.allSatisfy(\.isHexDigit) ? s : ""
    }

    /// Non-blocking caveat: this tunnel carries no UDP but DNS, so anything that
    /// insists on UDP will not work through it. Named explicitly because QUIC is
    /// now the default for a lot of the web and "some sites are slow" is a much
    /// worse way to find out.
    nonisolated static let udpCaveat =
        "SSH carries only TCP, so this tunnel can't carry UDP. Name lookups still work "
        + "(they go over TCP), but QUIC \u{2014} which Chrome, Safari and many video apps try first "
        + "\u{2014} is refused, and those apps fall back to TCP after a short delay. "
        + "Anything UDP-only (some games, plain WireGuard, most VoIP) will not work."

    /// Non-blocking caveat about advertising no DNS at all.
    nonisolated var dnsWarning: String? {
        guard dnsServers.isEmpty, !useFarSideResolver else { return nil }
        return includeDefaultRoute
            ? "No DNS servers are set, so lookups keep using your Mac's current resolvers. Under \u{201C}Send all traffic\u{201D} those resolvers are inside the tunnel too, which only works if the SSH server can reach them \u{2014} turn on \u{201C}Resolve names at the server\u{201D} if it can't."
            : "No DNS servers are set, so lookups keep using your Mac's current resolvers \u{2014} outside the tunnel. If the networks you're routing have private names, that's a leak as well as a failure."
    }

    nonisolated static func routeOverlapWarning(included: [String], excluded: [String]) -> String? {
        for e in excluded where routeProblem(e) == nil {
            for i in included where routeProblem(i) == nil {
                if RoutePrefixMath.overlaps(e, i) {
                    return "\(e) overlaps \(i), which you're sending through the tunnel — the exclusion wins, so that part of \(i) stays direct."
                }
            }
        }
        return nil
    }

    /// Non-blocking: the SENTINEL has to reach the utun or the far-side resolver
    /// never sees a query. Under a split tunnel the provider adds its /32, so the
    /// only way to break it is to exclude it explicitly.
    nonisolated var sentinelReachabilityWarning: String? {
        guard useFarSideResolver else { return nil }
        for e in excludedRoutes where Self.routeProblem(e) == nil {
            if RoutePrefixMath.overlaps(Self.farSideResolverSentinel, e) {
                return "\(Self.farSideResolverSentinel) is inside \(e), which you're keeping out of the tunnel — so \u{201C}Resolve names at the server\u{201D} can't work."
            }
        }
        return nil
    }

    /// Why the whole config can't connect (the connect-flow gate), or nil.
    nonisolated var connectProblem: String? {
        if let p = serverProblem { return p }
        if username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Enter the login name to use on the server."
        }
        if port != 0, !Self.portRange.contains(port) {
            return "\(port) isn't a valid port — use 1 to 65535."
        }
        // The extension is PIN-ONLY, so a `.pinned` config with no usable pin can
        // never connect. The other two policies resolve their pin at connect.
        if hostKeyPolicy == .pinned, let p = Self.pinProblem(pinnedHostKeySHA256) { return p }
        if !includeDefaultRoute, includedRoutes.isEmpty {
            return "Add at least one network to route through the tunnel, or turn on \u{201C}Send all traffic\u{201D}."
        }
        if let p = Self.routesProblem(includedRoutes) { return p }
        if let p = Self.routesProblem(excludedRoutes) { return p }
        if let p = Self.dnsServersProblem(dnsServers) { return p }
        if useFarSideResolver, let p = Self.farSideResolverProblem(farSideResolver) { return p }
        return nil
    }
}

// MARK: - Start payload (the PXStart contract for an ssh:// upstream)

/// Exactly the JSON `PXStart` parses, plus the session fields the extension's
/// SSH engine needs. Field names are load-bearing: the upstream/mtu/dnsSentinel
/// half is checked against the Go side by TestStartConfigCarriesTheDNSSentinel
/// over there and SSHNetworkTunnelTests over here.
///
/// The credential fields are NOT in the engine's JSON — they never leave Swift.
/// This type only carries them so one struct describes one connect attempt.
nonisolated struct SSHNetworkTunnelStartConfig: Sendable, Equatable {

    /// A safe utun default. Nothing is encapsulated, so there is no header to
    /// make room for (see the file header on why there is no MTU reduction).
    static let defaultMTU = 1500

    // ---- The engine's half (encoded to JSON for PXStart) ----
    var upstream: String
    var mtu: Int
    var dnsSentinel: String
    var dnsUpstream: String

    // ---- The session's half (Swift only, in memory only) ----
    var username: String
    var password: String
    var privateKeyPEM: String
    var certificatePEM: String
    /// The ONLY host key this session will accept. The extension never prompts,
    /// never trusts on first use and cannot read known_hosts (root, sandboxed) —
    /// so an empty pin here is a refusal to connect, not a permissive default.
    var expectedHostKeySHA256: String
    var keyExchange: String
    var keepaliveSeconds: Int
    var connectTimeoutSeconds: Int

    init(config: SSHNetworkTunnelConfig,
         password: String,
         privateKeyPEM: String,
         certificatePEM: String,
         expectedHostKeySHA256: String,
         connectTimeoutSeconds: Int = 20) {
        upstream = config.upstreamURL
        mtu = SSHNetworkTunnelConfig.mtuRange.contains(config.mtu) ? config.mtu : Self.defaultMTU
        if config.useFarSideResolver {
            dnsSentinel = SSHNetworkTunnelConfig.farSideResolverSentinel
            dnsUpstream = config.farSideResolver.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            dnsSentinel = ""
            dnsUpstream = ""
        }
        username = config.username.trimmingCharacters(in: .whitespacesAndNewlines)
        self.password = password
        self.privateKeyPEM = privateKeyPEM
        self.certificatePEM = certificatePEM
        self.expectedHostKeySHA256 = expectedHostKeySHA256
        keyExchange = config.keyExchange
        keepaliveSeconds = config.keepaliveSeconds
        self.connectTimeoutSeconds = connectTimeoutSeconds
    }

    /// The engine's JSON. Only the four fields above — no credential ever crosses
    /// into Go.
    func engineJSONString() -> String {
        var obj: [String: Any] = [
            "upstream": upstream,
            "username": username,   // a login name; the engine keeps it for status only
            "password": "",         // the engine has no use for one on this path
            "mtu": mtu,
        ]
        if !dnsSentinel.isEmpty {
            obj["dnsSentinel"] = dnsSentinel
            obj["dnsUpstream"] = dnsUpstream
        }
        guard let d = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
              let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }

    /// The only loggable form of the whole attempt.
    func redactedDescription() -> String {
        var bits = ["upstream=\(upstream)", "mtu=\(mtu)"]
        if !dnsSentinel.isEmpty { bits.append("dns=\(dnsSentinel)→\(dnsUpstream)") }
        bits.append("password=\(password.isEmpty ? "-" : "<redacted>")")
        bits.append("key=\(privateKeyPEM.isEmpty ? "-" : "<redacted>")")
        bits.append("cert=\(certificatePEM.isEmpty ? "-" : "<redacted>")")
        // The PIN is not a secret (it is a public key's hash) and is the single
        // most useful thing in a failed-connect log, so it is shown in full.
        bits.append("pin=\(expectedHostKeySHA256.isEmpty ? "MISSING" : expectedHostKeySHA256)")
        bits.append("keepalive=\(keepaliveSeconds)s")
        return bits.joined(separator: " ")
    }

    /// Why this payload cannot be used by the extension — the last gate before a
    /// session is opened, and the one that enforces PIN-ONLY.
    var problem: String? {
        if upstream.isEmpty { return "This tunnel has no server address." }
        if username.isEmpty { return "This tunnel has no login name." }
        if expectedHostKeySHA256.isEmpty {
            return "SimpleVPN doesn't know which host key to expect, so it won't hand your sign-in to whatever answers."
        }
        return nil
    }
}

// MARK: - Status payload

/// What the app's "sshnetstatus" IPC gets back: the netstack's counters plus the
/// session facts only this side knows. Carries NO secrets — the pin is a public
/// key's hash and is deliberately absent anyway, since the app already has it.
nonisolated struct SSHNetworkTunnelStatus: Codable, Sendable, Equatable {
    /// The gVisor netstack's own counters (flows, bytes, DNS, refused UDP).
    var netstack = ProxyTunnelStatus()
    /// Whether the SSH session itself is up right now. False while reconnecting —
    /// during which the tunnel's routes STAY in place and every flow is refused,
    /// rather than leaking to the physical path.
    var sessionUp = false
    var reconnects = 0
    /// SSH channels open right now (one per live TCP flow).
    var activeChannels = 0
    var openedFlows: Int64 = 0
    /// Flows refused because the session was down, timed out, or the server said
    /// no. Cumulative, so a single later flow can't erase the evidence.
    var refusedFlows: Int64 = 0
    var lastSessionError = ""

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        netstack = (try? c.decodeIfPresent(ProxyTunnelStatus.self, forKey: .netstack)) ?? ProxyTunnelStatus()
        sessionUp = (try? c.decodeIfPresent(Bool.self, forKey: .sessionUp)) ?? false
        reconnects = (try? c.decodeIfPresent(Int.self, forKey: .reconnects)) ?? 0
        activeChannels = (try? c.decodeIfPresent(Int.self, forKey: .activeChannels)) ?? 0
        openedFlows = (try? c.decodeIfPresent(Int64.self, forKey: .openedFlows)) ?? 0
        refusedFlows = (try? c.decodeIfPresent(Int64.self, forKey: .refusedFlows)) ?? 0
        lastSessionError = (try? c.decodeIfPresent(String.self, forKey: .lastSessionError)) ?? ""
    }

    static func decode(json: String) -> SSHNetworkTunnelStatus? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(SSHNetworkTunnelStatus.self, from: d)
    }
}
