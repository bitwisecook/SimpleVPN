// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteResolver.swift
//  "Type an IP or CIDR, see exactly where it goes now and where it could go."
//
//  A pure, Sendable resolver over a SNAPSHOT of the BSD routing table (the text
//  `netstat -rn -f inet` / `-f inet6` prints). Nothing in here touches the live
//  system: text in, answers out. That is deliberate — the same engine has to be
//  able to answer "what would happen if…" for the future policy editor, where the
//  table being reasoned about is a hypothetical one, not this Mac's.
//
//  The three things this gets right that a naive longest-prefix match does not:
//
//  1. SCOPING. macOS keeps several default routes at once and disambiguates them
//     with RTF_IFSCOPE (flag `I`). Only traffic explicitly bound to that interface
//     uses a scoped route; unbound ("global") traffic uses the unscoped one. On a
//     typical box with a full-tunnel VPN plus Tailscale the table reads:
//         default  link#27     UCSg     utun8    ← unscoped: the real answer
//         default  10.0.7.254  UGScIg   en0      ← scoped standby, has a gateway
//         default  link#20     UCSIg    utun1    ← scoped AND gatewayless
//     A plain longest-prefix match ties on all three and picks whichever it saw
//     last. The winner is the unscoped one.
//
//  2. VIABLE ALTERNATIVES. "Where could it go" is the takeover order — the routes
//     that would carry this traffic if the winner went away. A scoped default with
//     a real gateway (en0 above) is a genuine standby. A scoped GATEWAYLESS default
//     (utun1 above — that is Tailscale advertising itself with no exit node
//     selected) can carry nothing; listing it would be a lie, so it never appears.
//
//  3. CIDRs SPLIT. A queried range rarely maps to one route. The answer is the
//     honest tiling: each sub-range that a more-specific route diverts, plus the
//     remainder that falls through to the covering route.
//

import Foundation
import Darwin

// MARK: - Address family

nonisolated enum IPFamily: String, Sendable, Hashable, CaseIterable {
    case v4, v6

    var bitWidth: Int { self == .v4 ? 32 : 128 }
    var byteCount: Int { self == .v4 ? 4 : 16 }
    var label: String { self == .v4 ? "IPv4" : "IPv6" }
}

// MARK: - Prefix

/// A normalised network: family + masked address bytes + prefix length.
/// Zone/scope identifiers (`%en0`) are NOT part of the value — they are carried
/// alongside on `RouteRecord`, because they are a scoping qualifier, not part of
/// the address arithmetic.
nonisolated struct IPPrefix: Sendable, Hashable, CustomStringConvertible {
    let family: IPFamily
    /// Network address, masked to `prefixLength`. 4 bytes for v4, 16 for v6.
    let bytes: [UInt8]
    let prefixLength: Int

    init?(family: IPFamily, bytes: [UInt8], prefixLength: Int) {
        guard bytes.count == family.byteCount,
              (0...family.bitWidth).contains(prefixLength) else { return nil }
        self.family = family
        self.prefixLength = prefixLength
        self.bytes = Self.masked(bytes, prefixLength)
    }

    /// The all-zeros /0 for a family — "default".
    static func defaultRoute(_ family: IPFamily) -> IPPrefix {
        IPPrefix(family: family, bytes: [UInt8](repeating: 0, count: family.byteCount), prefixLength: 0)!
    }

    var isDefault: Bool { prefixLength == 0 }
    /// A single address (/32 or /128).
    var isHost: Bool { prefixLength == family.bitWidth }

    // MARK: Containment

    /// True when `other` is entirely inside (or equal to) this prefix.
    func contains(_ other: IPPrefix) -> Bool {
        guard family == other.family, prefixLength <= other.prefixLength else { return false }
        return Self.masked(other.bytes, prefixLength) == bytes
    }

    /// Prefixes either nest or are disjoint — never partially overlap.
    func overlaps(_ other: IPPrefix) -> Bool { contains(other) || other.contains(self) }

    /// Split into the two halves one bit longer. Nil for a host prefix.
    func halves() -> (low: IPPrefix, high: IPPrefix)? {
        guard prefixLength < family.bitWidth else { return nil }
        let newLength = prefixLength + 1
        // `bytes` is masked, so the newly significant bit is already 0 in the low half.
        var high = bytes
        let index = (newLength - 1) / 8
        high[index] |= UInt8(1 << (7 - ((newLength - 1) % 8)))
        guard let lo = IPPrefix(family: family, bytes: bytes, prefixLength: newLength),
              let hi = IPPrefix(family: family, bytes: high, prefixLength: newLength) else { return nil }
        return (lo, hi)
    }

    // MARK: Set arithmetic

    /// `base` minus `hole`, expressed as whole prefixes.
    static func subtracting(_ hole: IPPrefix, from base: IPPrefix) -> [IPPrefix] {
        guard base.overlaps(hole) else { return [base] }
        guard !hole.contains(base) else { return [] }
        guard let (lo, hi) = base.halves() else { return [] }
        return subtracting(hole, from: lo) + subtracting(hole, from: hi)
    }

    /// `base` minus every hole. Returns nil if the tiling would exceed `limit`
    /// pieces — callers report that as a truncated answer instead of guessing.
    static func subtracting(_ holes: [IPPrefix], from base: IPPrefix, limit: Int) -> [IPPrefix]? {
        var pieces = [base]
        for hole in holes {
            var next: [IPPrefix] = []
            next.reserveCapacity(pieces.count)
            for piece in pieces {
                next.append(contentsOf: subtracting(hole, from: piece))
                if next.count > limit { return nil }
            }
            pieces = next
        }
        return pieces
    }

    /// Numeric ordering (address, then prefix length) — the order a table reads in.
    static func ordered(_ a: IPPrefix, _ b: IPPrefix) -> Bool {
        if a.family != b.family { return a.family == .v4 }
        for (x, y) in zip(a.bytes, b.bytes) where x != y { return x < y }
        return a.prefixLength < b.prefixLength
    }

    private static func masked(_ raw: [UInt8], _ prefixLength: Int) -> [UInt8] {
        var out = raw
        for i in out.indices {
            let bitsBefore = i * 8
            if prefixLength >= bitsBefore + 8 { continue }
            if prefixLength <= bitsBefore { out[i] = 0; continue }
            let keep = prefixLength - bitsBefore            // 1…7
            out[i] &= UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
        }
        return out
    }

    // MARK: Text

    /// Canonical address text ("10.0.0.0", "fd7a:115c:a1e0::").
    var addressText: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = self.family == .v4 ? AF_INET : AF_INET6
        let text: String? = bytes.withUnsafeBytes { raw in
            guard let base = raw.baseAddress,
                  let out = inet_ntop(family, base, &buffer, socklen_t(INET6_ADDRSTRLEN))
            else { return nil }
            return String(cString: out)
        }
        return text ?? "?"
    }

    var description: String { "\(addressText)/\(prefixLength)" }

    /// How a user would want it written: a host prefix is just the address.
    var displayText: String { isHost ? addressText : description }

    // MARK: Parsing

    /// Parse a routing-TABLE destination, where BSD shorthand is legal:
    /// "default", "10.11/16", "127" (= 127.0.0.0/8), "10.0.0.4" (host),
    /// "fe80::%lo0/64", "fe80::1%lo0". Returns the prefix plus any zone.
    static func parseDestination(_ text: String, family: IPFamily) -> (prefix: IPPrefix, zone: String?)? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed == "default" { return (defaultRoute(family), nil) }
        return parse(trimmed, family: family, allowShorthand: true)
    }

    /// Parse USER input. Stricter than a table destination: a bare IPv4 must be
    /// all four octets (so "8" is rejected rather than silently read as 8/8), but
    /// shorthand with an explicit length ("10.11/16") is accepted because that is
    /// exactly what the table shows and users copy it straight out.
    static func parseQuery(_ text: String) -> (prefix: IPPrefix, zone: String?)? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed == "default" { return nil }      // ambiguous family — not a query
        let head = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)[0]
        let family: IPFamily = head.contains(":") ? .v6 : .v4
        let hasLength = trimmed.contains("/")
        if family == .v4 && !hasLength {
            guard head.split(separator: ".", omittingEmptySubsequences: false).count == 4 else { return nil }
        }
        return parse(trimmed, family: family, allowShorthand: hasLength)
    }

    /// Parse a strict, complete address (no shorthand, no length) — used for
    /// gateway columns, where anything that is not an address (link#20, a MAC,
    /// an interface name) must come back nil.
    static func parseAddress(_ text: String) -> (prefix: IPPrefix, zone: String?)? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return nil }
        let family: IPFamily = trimmed.contains(":") ? .v6 : .v4
        if family == .v4,
           trimmed.split(separator: ".", omittingEmptySubsequences: false).count != 4 { return nil }
        return parse(trimmed, family: family, allowShorthand: false)
    }

    private static func parse(
        _ text: String, family: IPFamily, allowShorthand: Bool
    ) -> (prefix: IPPrefix, zone: String?)? {
        let parts = text.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), !parts[0].isEmpty else { return nil }

        // Zone ("%en0") sits on the address, before any prefix length.
        var addressText = String(parts[0])
        var zone: String?
        if let percent = addressText.firstIndex(of: "%") {
            let scope = String(addressText[addressText.index(after: percent)...])
            addressText = String(addressText[..<percent])
            // A `%` with nothing after it is malformed, not an unzoned address.
            guard !scope.isEmpty, !addressText.isEmpty, !scope.contains("%") else { return nil }
            zone = scope
        }

        var explicitLength: Int?
        if parts.count == 2 {
            guard let n = Int(parts[1]), (0...family.bitWidth).contains(n) else { return nil }
            explicitLength = n
        }

        switch family {
        case .v4:
            guard !addressText.contains(":") else { return nil }
            let fields = addressText.split(separator: ".", omittingEmptySubsequences: false)
            guard (1...4).contains(fields.count) else { return nil }
            guard allowShorthand || fields.count == 4 else { return nil }
            var octets: [UInt8] = []
            for field in fields {
                guard !field.isEmpty, field.allSatisfy(\.isNumber),
                      let value = UInt16(field), value <= 255 else { return nil }
                octets.append(UInt8(value))
            }
            let shown = octets.count
            while octets.count < 4 { octets.append(0) }
            // BSD shorthand: the octets SHOWN imply the length when none is given.
            let length = explicitLength ?? (shown == 4 ? 32 : shown * 8)
            guard let prefix = IPPrefix(family: .v4, bytes: octets, prefixLength: length) else { return nil }
            return (prefix, zone)

        case .v6:
            guard addressText.contains(":") else { return nil }
            var storage = in6_addr()
            guard inet_pton(AF_INET6, addressText, &storage) == 1 else { return nil }
            let bytes = withUnsafeBytes(of: &storage) { [UInt8]($0) }
            guard bytes.count == 16,
                  let prefix = IPPrefix(family: .v6, bytes: bytes, prefixLength: explicitLength ?? 128)
            else { return nil }
            return (prefix, zone)
        }
    }
}

// MARK: - Route record

/// One row of the routing table, parsed but with its raw text preserved so the UI
/// can show exactly what the kernel says.
nonisolated struct RouteRecord: Sendable, Hashable, Identifiable {
    /// Position in the table — the kernel's own tie-break for equal prefixes.
    let order: Int
    let destination: String         // raw: "default", "10/21", "fe80::%lo0/64"
    let prefix: IPPrefix
    /// Scope identifier from the destination (`fe80::%en0/64` → "en0"), if any.
    let zone: String?
    let gateway: String             // raw: "10.0.7.254", "link#27", a MAC, "::1"
    let flags: String               // raw netstat flags, e.g. "UGScIg"
    let interfaceName: String

    var id: Int { order }
    var family: IPFamily { prefix.family }
    var isDefault: Bool { prefix.isDefault }

    /// RTF_IFSCOPE — only traffic explicitly bound to `interfaceName` uses this
    /// route. Case matters: lowercase `i` is RTF_IFREF, which is not scoping.
    var isScoped: Bool { flags.contains("I") }
    /// RTF_HOST.
    var isHostRoute: Bool { flags.contains("H") }
    /// RTF_WASCLONED — an ARP/ND cache clone of a parent route, not policy.
    var isCloned: Bool { flags.contains("W") }
    /// RTF_REJECT / RTF_BLACKHOLE — traffic is dropped, not forwarded.
    var isReject: Bool { flags.contains("R") || flags.contains("B") }
    /// A gatewayless route: `link#20` means "on-link via this interface".
    var gatewayIsLink: Bool { gateway.hasPrefix("link#") }

    /// The gateway when it really is a next-hop ADDRESS. Nil for `link#20`, a MAC
    /// address, or an interface name.
    var gatewayAddress: IPPrefix? { IPPrefix.parseAddress(gateway)?.prefix }
    var hasRealGateway: Bool { gatewayAddress != nil }

    /// Could this route take over if the winner went away?
    ///
    /// An unscoped route always could. A SCOPED route only counts when it names a
    /// real next hop: a scoped gatewayless default is an interface advertising
    /// itself with nowhere to send traffic (Tailscale with no exit node), and
    /// offering it as a fallback would be a lie.
    var isViableAlternative: Bool { (!isScoped || hasRealGateway) && !isReject }
}

// MARK: - Snapshot

/// An immutable routing table. Build it from netstat text (either or both
/// families) and hand it to a `RouteResolver`.
nonisolated struct RouteTableSnapshot: Sendable, Hashable {
    let routes: [RouteRecord]

    static let empty = RouteTableSnapshot(routes: [])

    init(routes: [RouteRecord]) { self.routes = routes }

    /// Parse `netstat -rn` output. Handles a single-family dump (`-f inet`), a
    /// single-family dump for v6, or the combined output with both sections;
    /// `family` is only a fallback for text with no `Internet:` header.
    init(netstatText: String, family: IPFamily? = nil) {
        self.init(routes: Self.parse(netstatText, family: family, startingAt: 0))
    }

    /// The usual case: both families, captured separately, in one table.
    init(ipv4Text: String, ipv6Text: String) {
        var routes = Self.parse(ipv4Text, family: .v4, startingAt: 0)
        routes += Self.parse(ipv6Text, family: .v6, startingAt: routes.count)
        self.init(routes: routes)
    }

    func routes(family: IPFamily) -> [RouteRecord] { routes.filter { $0.family == family } }

    var isEmpty: Bool { routes.isEmpty }

    static func parse(_ text: String, family hint: IPFamily?, startingAt firstOrder: Int) -> [RouteRecord] {
        var records: [RouteRecord] = []
        var family = hint
        var order = firstOrder

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            // Section headers: "Internet:" then "Internet6:" in combined output.
            if line.hasPrefix("Internet6") { family = .v6; continue }
            if line.hasPrefix("Internet:") { family = .v4; continue }
            if line.hasPrefix("Routing tables") { continue }

            let columns = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            // Destination Gateway Flags Netif [Expire]
            guard columns.count >= 4, columns[0] != "Destination" else { continue }
            let destination = columns[0], gateway = columns[1]
            let flags = columns[2], netif = columns[3]

            // "default" is family-ambiguous, so trust the section header; otherwise
            // a colon in the destination is decisive (a MAC only ever appears as a
            // GATEWAY, never as a destination).
            let rowFamily = family ?? (destination.contains(":") ? .v6 : .v4)
            guard let parsed = IPPrefix.parseDestination(destination, family: rowFamily) else { continue }

            records.append(RouteRecord(
                order: order, destination: destination, prefix: parsed.prefix, zone: parsed.zone,
                gateway: gateway, flags: flags, interfaceName: netif))
            order += 1
        }
        return records
    }
}

// MARK: - Resolution

nonisolated struct RouteResolution: Sendable, Hashable {
    nonisolated enum Kind: Sendable, Hashable {
        /// A single address — one answer.
        case address
        /// A range — potentially several answers, one per sub-range.
        case network
    }

    /// One contiguous sub-range of the query and where it goes.
    nonisolated struct Segment: Sendable, Hashable, Identifiable {
        nonisolated enum Source: Sendable, Hashable {
            /// Diverted by a route MORE specific than the query.
            case specific
            /// Falls through to the route covering the query (the remainder).
            case covering
            /// Nothing in the table covers it.
            case unroutable
        }

        let prefix: IPPrefix
        let route: RouteRecord?
        let alternatives: [RouteRecord]
        let source: Source

        var id: String { "\(prefix)@\(route?.order ?? -1)" }
        var interfaceName: String? { route?.interfaceName }
        /// True when this piece is only handled by the query's covering route.
        var isRemainder: Bool { source != .specific }
    }

    /// Exactly what the user typed.
    let query: String
    /// The normalised query.
    let prefix: IPPrefix
    let zone: String?
    let kind: Kind

    /// Where it goes NOW. For a range this is the covering route — the one that
    /// carries everything `segments` does not divert.
    let winner: RouteRecord?
    /// Where it COULD go, in takeover order. Never includes unusable routes.
    let alternatives: [RouteRecord]
    /// The honest split of the query. One entry for an address.
    let segments: [Segment]
    /// The split was too fine-grained to enumerate; `segments` lists whole route
    /// prefixes instead of an exact tiling.
    let segmentsTruncated: Bool

    var interfaceName: String? { winner?.interfaceName }
    var isRoutable: Bool { winner != nil || segments.contains { $0.route != nil } }

    /// The query does not land on a single route — the UI must show the split.
    /// An unroutable piece counts as its own destination, so "half of this /23
    /// goes via utun1 and half goes nowhere" reads as a split too.
    var spansMultipleRoutes: Bool {
        Set(segments.map { $0.route?.interfaceName ?? "" }).count > 1
    }

    /// Every interface any part of this query would leave by, in segment order.
    var interfaceNames: [String] {
        var seen = Set<String>()
        return segments.compactMap(\.interfaceName).filter { seen.insert($0).inserted }
    }
}

// MARK: - Resolver

/// Answers "where does this go, and where else could it go" against a snapshot.
/// Pure: no process spawning, no system calls, safe to run over a hypothetical
/// table in the policy editor.
nonisolated struct RouteResolver: Sendable {
    let snapshot: RouteTableSnapshot

    /// Ceiling on how many pieces a CIDR answer may be cut into before the answer
    /// is reported as truncated rather than enumerated.
    private let segmentLimit = 512

    init(snapshot: RouteTableSnapshot) { self.snapshot = snapshot }
    init(netstatText: String, family: IPFamily? = nil) {
        self.init(snapshot: RouteTableSnapshot(netstatText: netstatText, family: family))
    }
    init(ipv4Text: String, ipv6Text: String) {
        self.init(snapshot: RouteTableSnapshot(ipv4Text: ipv4Text, ipv6Text: ipv6Text))
    }

    /// From the live topology. Prefers the topology's full snapshot; falls back to
    /// its (IPv4-only, noise-filtered) `routes` when the snapshot is absent.
    init(topology: NetworkTopology) {
        if !topology.snapshot.isEmpty {
            self.init(snapshot: topology.snapshot)
        } else {
            var records: [RouteRecord] = []
            for entry in topology.routes {
                guard let parsed = IPPrefix.parseDestination(entry.destination, family: .v4) else { continue }
                records.append(RouteRecord(
                    order: records.count, destination: entry.destination, prefix: parsed.prefix,
                    zone: parsed.zone, gateway: entry.gateway, flags: entry.flags,
                    interfaceName: entry.interfaceName))
            }
            self.init(snapshot: RouteTableSnapshot(routes: records))
        }
    }

    // MARK: Public API

    /// Resolve a bare IPv4/IPv6 address or a CIDR of either family.
    /// Nil — and only nil — for input that is not an address or network at all.
    func resolve(_ query: String) -> RouteResolution? {
        guard let parsed = IPPrefix.parseQuery(query) else { return nil }
        return resolve(prefix: parsed.prefix, zone: parsed.zone, query: query)
    }

    /// Resolve an already-normalised prefix.
    func resolve(prefix: IPPrefix, zone: String? = nil, query: String? = nil) -> RouteResolution {
        let covering = candidates(covering: prefix, zone: zone)
        let winner = covering.first
        let alternatives = Array(covering.dropFirst().filter(\.isViableAlternative))

        var truncated = false
        let segments = buildSegments(
            for: prefix, zone: zone, coveringWinner: winner,
            coveringAlternatives: alternatives, truncated: &truncated)

        return RouteResolution(
            query: query ?? prefix.displayText,
            prefix: prefix, zone: zone,
            kind: prefix.isHost ? .address : .network,
            winner: winner, alternatives: alternatives,
            segments: segments, segmentsTruncated: truncated)
    }

    /// The route that wins for this prefix, by the rules in the file header.
    func winner(for prefix: IPPrefix, zone: String? = nil) -> RouteRecord? {
        candidates(covering: prefix, zone: zone).first
    }

    /// Every route covering `prefix` (same-length or less specific), best first.
    ///
    /// Ordering — this is the whole semantic:
    ///   1. longest prefix wins;
    ///   2. among equal prefixes, an UNSCOPED route beats an interface-scoped one,
    ///      because unbound traffic ignores scoped routes;
    ///   3. still tied → first in table order.
    func candidates(covering prefix: IPPrefix, zone: String? = nil) -> [RouteRecord] {
        snapshot.routes
            .filter { $0.family == prefix.family && $0.prefix.contains(prefix) && compatible($0, zone) }
            .sorted(by: Self.betterRoute)
    }

    static func betterRoute(_ a: RouteRecord, _ b: RouteRecord) -> Bool {
        if a.prefix.prefixLength != b.prefix.prefixLength {
            return a.prefix.prefixLength > b.prefix.prefixLength
        }
        if a.isScoped != b.isScoped { return !a.isScoped }
        return a.order < b.order
    }

    // MARK: Internals

    /// A zoned route (`fe80::%en0/64`) only applies to a query in that zone. A
    /// query with no zone, or a route with no zone, matches anything.
    private func compatible(_ route: RouteRecord, _ queryZone: String?) -> Bool {
        guard let queryZone, let routeZone = route.zone else { return true }
        return queryZone == routeZone
    }

    /// Cut the query into the pieces that actually go different places.
    private func buildSegments(
        for query: IPPrefix, zone: String?,
        coveringWinner: RouteRecord?, coveringAlternatives: [RouteRecord],
        truncated: inout Bool
    ) -> [RouteResolution.Segment] {

        // Distinct prefixes strictly inside the query, in table order.
        var seen = Set<IPPrefix>()
        var specifics: [IPPrefix] = []
        for route in snapshot.routes
        where route.family == query.family
            && route.prefix.prefixLength > query.prefixLength
            && query.contains(route.prefix)
            && compatible(route, zone) {
            if seen.insert(route.prefix).inserted { specifics.append(route.prefix) }
        }

        // Keep only the prefixes that DIVERT. A more-specific route that lands on
        // the same interface as the route it sits inside changes nothing the user
        // asked about, and dropping it is what stops a /8 query from being shredded
        // into hundreds of ARP-cloned /32s that all say "en0" anyway.
        var diverting: [IPPrefix] = []
        for candidate in specifics {
            let covering = candidates(covering: candidate, zone: zone)
            guard let best = covering.first else { continue }
            let parent = covering.first { $0.prefix.prefixLength < candidate.prefixLength }
            if parent?.interfaceName == best.interfaceName { continue }
            diverting.append(candidate)
        }

        if diverting.isEmpty {
            let source: RouteResolution.Segment.Source = coveringWinner == nil ? .unroutable : .covering
            return [RouteResolution.Segment(
                prefix: query, route: coveringWinner,
                alternatives: coveringAlternatives, source: source)]
        }

        // Tile: longest first, each claiming what nothing longer already took.
        diverting.sort { $0.prefixLength > $1.prefixLength }
        var claimed: [IPPrefix] = []
        var segments: [RouteResolution.Segment] = []

        for candidate in diverting {
            guard let pieces = IPPrefix.subtracting(claimed, from: candidate, limit: segmentLimit) else {
                truncated = true
                return coarseSegments(
                    for: query, diverting: diverting, zone: zone,
                    coveringWinner: coveringWinner, coveringAlternatives: coveringAlternatives)
            }
            claimed.append(candidate)
            guard !pieces.isEmpty else { continue }
            let covering = candidates(covering: candidate, zone: zone)
            let alternatives = Array(covering.dropFirst().filter(\.isViableAlternative))
            for piece in pieces {
                segments.append(RouteResolution.Segment(
                    prefix: piece, route: covering.first,
                    alternatives: alternatives,
                    source: covering.first == nil ? .unroutable : .specific))
            }
        }

        guard let remainder = IPPrefix.subtracting(claimed, from: query, limit: segmentLimit) else {
            truncated = true
            return coarseSegments(
                for: query, diverting: diverting, zone: zone,
                coveringWinner: coveringWinner, coveringAlternatives: coveringAlternatives)
        }
        for piece in remainder {
            segments.append(RouteResolution.Segment(
                prefix: piece, route: coveringWinner, alternatives: coveringAlternatives,
                source: coveringWinner == nil ? .unroutable : .covering))
        }

        segments.sort { IPPrefix.ordered($0.prefix, $1.prefix) }
        if segments.count > segmentLimit {
            truncated = true
            segments = Array(segments.prefix(segmentLimit))
        }
        return segments
    }

    /// Fallback when an exact tiling would be absurdly fine-grained: name the
    /// diverting routes and say the rest falls through, without pretending to
    /// enumerate every remaining sub-range.
    private func coarseSegments(
        for query: IPPrefix, diverting: [IPPrefix], zone: String?,
        coveringWinner: RouteRecord?, coveringAlternatives: [RouteRecord]
    ) -> [RouteResolution.Segment] {
        var segments: [RouteResolution.Segment] = []
        for candidate in diverting.sorted(by: IPPrefix.ordered) {
            let covering = candidates(covering: candidate, zone: zone)
            segments.append(RouteResolution.Segment(
                prefix: candidate, route: covering.first,
                alternatives: Array(covering.dropFirst().filter(\.isViableAlternative)),
                source: covering.first == nil ? .unroutable : .specific))
        }
        segments.append(RouteResolution.Segment(
            prefix: query, route: coveringWinner, alternatives: coveringAlternatives,
            source: coveringWinner == nil ? .unroutable : .covering))
        return segments
    }
}
