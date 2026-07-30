// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Endpoints.swift
//  Scans an .ovpn for every `remote` the profile can connect to (the evaluator
//  only surfaces the first). Feeds the endpoint map and anywhere else that wants
//  the full server list. Pure text scanning — no engine, no network.
//

import Foundation

/// One `remote` from a profile, with top-level `port`/`proto` defaults applied.
/// nil port/proto = the profile left it to the engine default (1194/udp).
struct Endpoint: Identifiable, Equatable, Sendable {
    var host: String
    var port: Int?
    var proto: String?      // "udp"/"tcp" (prefix-normalized: "tcp-client" → "tcp")

    var id: String { "\(host):\(port.map(String.init) ?? "*"):\(proto ?? "*")" }
}

enum EndpointScanner {

    /// All `remote <host> [port] [proto]` endpoints in an .ovpn. Honors top-level
    /// `port`/`proto` directives as defaults (wherever they appear — OpenVPN
    /// applies them regardless of order), skips comments and inline-block bodies
    /// (<ca>…</ca> etc.), and dedupes while preserving first-seen order.
    static func endpoints(in ovpn: String) -> [Endpoint] {
        var remotes: [(host: String, port: Int?, proto: String?)] = []
        var defaultPort: Int?
        var defaultProto: String?
        var openTag: String?

        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }

            // Inline blocks can contain anything (PEM, scripts) — never parse inside.
            if let tag = openTag {
                if line == "</\(tag)>" { openTag = nil }
                continue
            }
            if line.hasPrefix("<"), !line.hasPrefix("</"), line.hasSuffix(">") {
                openTag = String(line.dropFirst().dropLast())
                continue
            }

            let tokens = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard let directive = tokens.first?.lowercased() else { continue }
            switch directive {
            case "remote" where tokens.count >= 2:
                remotes.append((host: tokens[1],
                                port: tokens.count >= 3 ? Int(tokens[2]) : nil,
                                proto: tokens.count >= 4 ? normalizedProto(tokens[3]) : nil))
            case "port" where tokens.count >= 2:
                defaultPort = Int(tokens[1]) ?? defaultPort
            case "proto" where tokens.count >= 2:
                defaultProto = normalizedProto(tokens[1])
            default:
                break
            }
        }

        var seen = Set<String>()
        var result: [Endpoint] = []
        for r in remotes {
            let endpoint = Endpoint(host: r.host,
                                    port: r.port ?? defaultPort,
                                    proto: r.proto ?? defaultProto)
            if seen.insert(endpoint.id).inserted { result.append(endpoint) }
        }
        return result
    }

    /// "TCP-client"/"tcp4"/"tcp6" → "tcp", "udp4" → "udp"; anything else lowercased.
    static func normalizedProto(_ raw: String) -> String {
        let p = raw.lowercased()
        if p.hasPrefix("tcp") { return "tcp" }
        if p.hasPrefix("udp") { return "udp" }
        return p
    }
}
