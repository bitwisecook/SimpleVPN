// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Darwin

/// Matches the complete queried name, never a URL or a resolver address.
nonisolated struct DNSNameMatch: Codable, Sendable, Equatable {
    enum Kind: String, Codable, Sendable, CaseIterable { case exact, suffix, glob }
    var kind: Kind = .exact
    var pattern = ""

    static func canonical(_ name: String) -> String {
        var name = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        return name
    }
    var problem: String? {
        let p = Self.canonical(pattern)
        guard !p.isEmpty else { return "Enter a queried hostname or pattern." }
        guard p.utf8.count <= 253 else { return "A DNS name pattern must be at most 253 bytes." }
        guard p.utf8.allSatisfy({ $0 > 32 && $0 < 127 }) else { return "Use ASCII DNS names or punycode, without spaces." }
        guard !p.contains("://"), !p.contains(":"), !p.contains("/"), !p.contains("@") else {
            return "Enter a DNS name, without a scheme, path, port or sign-in."
        }
        if p.hasPrefix(".") || p.contains("..") || p.hasSuffix(".") { return "Use a DNS name without empty labels." }
        if kind != .glob { return DNSSearchDomains.problem(p) }
        return Self.tokens(p).error
    }
    func matches(_ name: String) -> Bool {
        guard problem == nil else { return false }
        let p = Self.canonical(pattern), n = Self.canonical(name)
        guard !n.isEmpty, n.utf8.count <= 253, n.utf8.allSatisfy({ $0 > 32 && $0 < 127 }) else { return false }
        switch kind {
        case .exact: return n == p
        case .suffix: return n == p || n.hasSuffix("." + p)
        case .glob:
            // Dynamic programming, O(pattern × name) time and O(name) memory.
            // No recursive glob backtracking on adversarial queries/patterns.
            let bytes = Array(n.utf8)
            var state = [Bool](repeating: false, count: bytes.count + 1); state[0] = true
            for token in Self.tokens(p).values {
                var next = [Bool](repeating: false, count: state.count)
                if case .star = token {
                    next[0] = state[0]
                    for j in 1...bytes.count { next[j] = state[j] || next[j - 1] }
                } else {
                    for j in 1...bytes.count { next[j] = state[j - 1] && token.accepts(bytes[j - 1]) }
                }
                state = next
            }
            return state[bytes.count]
        }
    }
    private enum Token {
        case literal(UInt8), any, star, members([ClosedRange<UInt8>], negated: Bool)
        func accepts(_ byte: UInt8) -> Bool {
            switch self {
            case .literal(let value): return value == byte
            case .any, .star: return true
            case .members(let ranges, let negated): return ranges.contains { $0.contains(byte) } != negated
            }
        }
    }
    private static func tokens(_ pattern: String) -> (values: [Token], error: String?) {
        let bytes = Array(pattern.utf8)
        var index = 0, out: [Token] = []
        func character() -> UInt8? {
            guard index < bytes.count else { return nil }
            let value = bytes[index]; index += 1
            if value == 92 {
                guard index < bytes.count else { return nil }
                let escaped = bytes[index]; index += 1; return escaped
            }
            return value
        }
        while index < bytes.count {
            let value = bytes[index]; index += 1
            switch value {
            case 42: out.append(.star)
            case 63: out.append(.any)
            case 92:
                guard index < bytes.count else { return ([], "A glob cannot end with an unpaired backslash.") }
                out.append(.literal(bytes[index])); index += 1
            case 91:
                let negated = index < bytes.count && bytes[index] == 33
                if negated { index += 1 }
                var ranges: [ClosedRange<UInt8>] = []
                // A closing bracket is literal only in the first class position.
                if index < bytes.count, bytes[index] == 93 { ranges.append(93...93); index += 1 }
                while index < bytes.count, bytes[index] != 93 {
                    guard let first = character() else { return ([], "Incomplete glob escape.") }
                    if index + 1 < bytes.count, bytes[index] == 45, bytes[index + 1] != 93 {
                        index += 1
                        guard let last = character(), first <= last else { return ([], "A glob range must be ascending, such as [a-z].") }
                        ranges.append(first...last)
                    } else { ranges.append(first...first) }
                }
                guard index < bytes.count, bytes[index] == 93, !ranges.isEmpty else { return ([], "Close a non-empty glob character class with ].") }
                index += 1; out.append(.members(ranges, negated: negated))
            case 93: return ([], "A glob has an unmatched closing bracket.")
            default:
                guard (48...57).contains(value) || (97...122).contains(value) || [45, 46, 95].contains(value) else {
                    return ([], "Use DNS labels and glob operators: *, ?, [abc], [a-z], [!abc], or backslash escapes.")
                }
                out.append(.literal(value))
            }
        }
        return (out, nil)
    }
}

nonisolated enum DNSResolverAddress {
    static func isValid(_ raw: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return raw.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }
}

nonisolated struct DNSQueryRule: Codable, Sendable, Equatable, Identifiable {
    enum Target: String, Codable, Sendable, CaseIterable { case resolvers, original }
    var id = UUID()
    var enabled = true
    var match = DNSNameMatch()
    var target: Target = .resolvers
    /// Empty uses this VPN's filtered DNS servers. Non-empty is an explicit override.
    var servers: [String] = []
    func clearingUnusedFields() -> Self {
        var result = self
        if target == .original { result.servers = [] }
        return result
    }
    var problem: String? {
        if let problem = match.problem { return problem }
        if target == .resolvers, servers.count > 16 { return "Use at most 16 resolver addresses per rule." }
        if target == .resolvers, let invalid = servers.first(where: { !DNSResolverAddress.isValid($0) }) {
            return "Invalid DNS server IP address: \(invalid)."
        }
        return nil
    }
}

/// Public, immutable configuration delivered to the DNS proxy. It cannot carry secrets.
nonisolated struct DNSQueryRoute: Codable, Sendable, Equatable {
    var profileID: String
    var profileName: String
    var rule: DNSQueryRule
    var servers: [String]
}
nonisolated struct DNSQueryPolicy: Codable, Sendable, Equatable {
    static let version = 1
    var schema = version
    var routes: [DNSQueryRoute] = []
    var problem: String? {
        guard schema == Self.version else { return "Unsupported DNS query policy version." }
        guard routes.count <= 256 else { return "Use at most 256 active DNS query rules." }
        for route in routes {
            if let p = route.rule.problem { return p }
            if route.servers.count > 16 || !route.servers.allSatisfy(DNSResolverAddress.isValid) {
                return "Invalid DNS query resolver list."
            }
        }
        return nil
    }
    func route(for name: String) -> DNSQueryRoute? {
        routes.first { $0.rule.enabled && $0.rule.match.matches(name) }
    }
}
