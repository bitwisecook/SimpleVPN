// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHConfigImport.swift
//  Import from the OpenSSH world: parse ~/.ssh/config-style files into the
//  hosts they define (with their forwards, keys and jump chains resolved the
//  way ssh itself would), classify dropped key/certificate files, and apply a
//  chosen host onto a SubprocessTunnelConfig — so configuring an SSH tunnel is
//  "drop your config in" rather than re-typing what ssh already knows.
//

import Foundation

/// One host alias from an OpenSSH client config, with its EFFECTIVE settings:
/// every `Host` block whose pattern matches the alias contributes, scalars are
/// first-value-wins and list keywords accumulate — the same semantics ssh uses,
/// so what we import is what `ssh <alias>` would actually do.
nonisolated struct SSHConfigHost: Sendable, Equatable, Identifiable {
    var alias: String
    var hostName: String? = nil          // HostName; nil = alias is the hostname
    var port: Int? = nil
    var user: String? = nil
    var identityFiles: [String] = []     // in config order, ~ preserved
    var certificateFiles: [String] = []
    var proxyJump: String? = nil         // full chain as written ("a,b,c")
    var localForwards: [String] = []     // "listen:dest" as written, e.g. "8080:internal:80"
    var remoteForwards: [String] = []
    var dynamicForwards: [Int] = []      // -D ports
    var compression: Bool? = nil
    var serverAliveInterval: Int? = nil

    var id: String { alias }
    var effectiveHostName: String { hostName ?? alias }

    /// The tunnels this host defines, in the app's forward-line syntax.
    var forwardLines: [String] {
        localForwards.map { "L \($0)" } + remoteForwards.map { "R \($0)" }
    }

    /// One-line summary for pickers: "user@real-host · 3 forwards · SOCKS 1080 · via bastion".
    var summary: String {
        var bits: [String] = [user.map { "\($0)@\(effectiveHostName)" } ?? effectiveHostName]
        let forwards = localForwards.count + remoteForwards.count
        if forwards > 0 { bits.append("\(forwards) forward\(forwards == 1 ? "" : "s")") }
        if let d = dynamicForwards.first { bits.append("SOCKS \(d)") }
        if let jump = proxyJump { bits.append("via \(jump.split(separator: ",").first.map(String.init) ?? jump)") }
        if !identityFiles.isEmpty { bits.append("key") }
        return bits.joined(separator: " · ")
    }
}

nonisolated enum SSHConfigImport {

    // MARK: Parsing

    /// Parse an OpenSSH client config into its concrete hosts. Wildcard-only
    /// aliases (`Host *`, `Host *.example.com`) define defaults that are folded
    /// into the concrete hosts, not listed themselves. `Match` blocks and
    /// `Include` directives are skipped (we can't evaluate match criteria, and
    /// an import shouldn't chase files the user didn't drop).
    static func parse(_ text: String) -> [SSHConfigHost] {
        // Pass 1: tokenize into (patterns, [key: values-in-order]) blocks.
        struct Block { var patterns: [String]; var options: [(key: String, value: String)] }
        var blocks: [Block] = []
        var current = Block(patterns: ["*"], options: [])   // pre-Host options apply to all
        var skippingMatch = false

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            guard let (key, value) = parseLine(String(rawLine)) else { continue }
            switch key {
            case "host":
                blocks.append(current)
                current = Block(patterns: splitPatterns(value), options: [])
                skippingMatch = false
            case "match":
                blocks.append(current)
                current = Block(patterns: [], options: [])  // unmatched — contributes nothing
                skippingMatch = true
            case "include":
                continue
            default:
                if !skippingMatch { current.options.append((key, value)) }
            }
        }
        blocks.append(current)

        // Concrete aliases, in order of first appearance.
        var aliases: [String] = []
        for block in blocks {
            for p in block.patterns where !p.contains("*") && !p.contains("?") && !p.hasPrefix("!") {
                if !aliases.contains(p) { aliases.append(p) }
            }
        }

        // Pass 2: effective config per alias, ssh semantics (first value wins,
        // list keywords accumulate, negated patterns veto a block).
        return aliases.map { alias in
            var host = SSHConfigHost(alias: alias)
            for block in blocks where matches(alias: alias, patterns: block.patterns) {
                for (key, value) in block.options {
                    apply(key: key, value: value, to: &host)
                }
            }
            return host
        }
    }

    /// "Key value", "Key=value", quoted values, comments. Returns lowercased key.
    private static func parseLine(_ line: String) -> (String, String)? {
        var s = line.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty, !s.hasPrefix("#") else { return nil }
        // Split on the first '=' or whitespace run.
        guard let splitIndex = s.firstIndex(where: { $0 == "=" || $0 == " " || $0 == "\t" }) else { return nil }
        let key = String(s[..<splitIndex]).lowercased()
        s = String(s[s.index(after: splitIndex)...]).trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("=") { s = String(s.dropFirst()).trimmingCharacters(in: .whitespaces) }
        if s.hasPrefix("\""), s.hasSuffix("\""), s.count >= 2 { s = String(s.dropFirst().dropLast()) }
        guard !s.isEmpty else { return nil }
        return (key, s)
    }

    private static func splitPatterns(_ value: String) -> [String] {
        value.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
    }

    /// OpenSSH Host-pattern matching: `*` and `?` wildcards; a matching `!`
    /// pattern vetoes the whole block; otherwise any positive match applies.
    private static func matches(alias: String, patterns: [String]) -> Bool {
        var matched = false
        for pattern in patterns {
            if pattern.hasPrefix("!") {
                if wildcardMatch(alias, String(pattern.dropFirst())) { return false }
            } else if wildcardMatch(alias, pattern) {
                matched = true
            }
        }
        return matched
    }

    static func wildcardMatch(_ s: String, _ pattern: String) -> Bool {
        // Classic glob over * and ? — iterative to stay linear-ish.
        let s = Array(s), p = Array(pattern)
        var si = 0, pi = 0, starP = -1, starS = -1
        while si < s.count {
            if pi < p.count, p[pi] == "?" || p[pi] == s[si] { si += 1; pi += 1 }
            else if pi < p.count, p[pi] == "*" { starP = pi; starS = si; pi += 1 }
            else if starP >= 0 { starS += 1; si = starS; pi = starP + 1 }
            else { return false }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }

    private static func apply(key: String, value: String, to host: inout SSHConfigHost) {
        switch key {
        case "hostname": if host.hostName == nil { host.hostName = value }
        case "port": if host.port == nil { host.port = Int(value) }
        case "user": if host.user == nil { host.user = value }
        case "identityfile": host.identityFiles.append(value)
        case "certificatefile": host.certificateFiles.append(value)
        case "proxyjump": if host.proxyJump == nil { host.proxyJump = value }
        case "localforward": if let f = normalizeForward(value) { host.localForwards.append(f) }
        case "remoteforward": if let f = normalizeForward(value) { host.remoteForwards.append(f) }
        case "dynamicforward":
            // Value may be "1080" or "localhost:1080" — the port is what we need.
            let port = value.split(separator: ":").last.flatMap { Int($0) }
            if let port, !host.dynamicForwards.contains(port) { host.dynamicForwards.append(port) }
        case "compression": if host.compression == nil { host.compression = value.lowercased() == "yes" }
        case "serveraliveinterval": if host.serverAliveInterval == nil { host.serverAliveInterval = Int(value) }
        default: break
        }
    }

    /// Config forwards are "[bind:]port host:hostport" (space-separated halves);
    /// the app's lines use colons throughout: "port:host:hostport".
    private static func normalizeForward(_ value: String) -> String? {
        let halves = value.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard halves.count == 2 else { return nil }
        // Drop an explicit bind address ("localhost:8080" → "8080") — the app
        // binds loopback anyway; keep IPv6-bracketed binds out of the way too.
        let listen = halves[0].split(separator: ":").last.map(String.init) ?? String(halves[0])
        return "\(listen):\(halves[1])"
    }

    // MARK: Applying a host to a tunnel config

    /// What an apply changed, for the "here's what I did" summary line.
    struct Applied: Sendable, Equatable {
        var notes: [String] = []
        var summary: String { notes.joined(separator: ", ") }
    }

    /// Fill a tunnel draft from a config host. Only meaningful values move —
    /// nothing is blanked by an absent keyword.
    @discardableResult
    static func apply(_ host: SSHConfigHost, to config: inout SubprocessTunnelConfig) -> Applied {
        var applied = Applied()
        config.server = host.effectiveHostName
        if config.name.isEmpty || config.name == "New Tunnel" { config.name = host.alias }
        applied.notes.append("host \(host.effectiveHostName)")
        if let p = host.port { config.port = p; applied.notes.append("port \(p)") }
        if let u = host.user { config.username = u; applied.notes.append("user \(u)") }
        if let key = host.identityFiles.first {
            config.identityFile = key
            applied.notes.append("key \((key as NSString).lastPathComponent)")
        }
        for cert in host.certificateFiles {
            let opt = "CertificateFile \(cert)"
            if !config.sshExtraOptions.contains(opt) { config.sshExtraOptions.append(opt) }
        }
        if let jump = host.proxyJump {
            // First hop only — libssh does a single jump. Note when a longer
            // chain was truncated rather than silently dropping hops.
            let hops = jump.split(separator: ",").map(String.init)
            if let first = hops.first {
                let (user, hostPart, port) = splitUserHostPort(first)
                config.useJumpHost = true
                config.jumpHost = hostPart
                if let user { config.jumpUsername = user }
                if let port { config.jumpPort = port }
                applied.notes.append(hops.count > 1
                    ? "jump via \(hostPart) (chain of \(hops.count) — only the first hop is used)"
                    : "jump via \(hostPart)")
            }
        }
        // The tunnels defined for this endpoint, discovered automatically:
        if let socks = host.dynamicForwards.first {
            config.sshMode = .socks
            config.socksPort = socks
            applied.notes.append("SOCKS proxy on \(socks)")
        }
        if !host.forwardLines.isEmpty {
            config.forwards = host.forwardLines
            if host.dynamicForwards.isEmpty { config.sshMode = .portForward }
            let n = host.forwardLines.count
            applied.notes.append("\(n) port forward\(n == 1 ? "" : "s")")
        }
        if let c = host.compression { config.compression = c }
        if let s = host.serverAliveInterval { config.serverAliveInterval = s }
        return applied
    }

    /// "user@host:port" / "user@host" / "host" / "[v6]:port".
    static func splitUserHostPort(_ s: String) -> (user: String?, host: String, port: Int?) {
        var rest = s
        var user: String?
        if let at = rest.firstIndex(of: "@") {
            user = String(rest[..<at])
            rest = String(rest[rest.index(after: at)...])
        }
        if rest.hasPrefix("[") , let close = rest.firstIndex(of: "]") {
            let host = String(rest[rest.index(after: rest.startIndex)..<close])
            let tail = rest[rest.index(after: close)...]
            let port = tail.hasPrefix(":") ? Int(tail.dropFirst()) : nil
            return (user, host, port)
        }
        let parts = rest.split(separator: ":")
        if parts.count == 2, let port = Int(parts[1]) {
            return (user, String(parts[0]), port)
        }
        return (user, rest, nil)
    }

    // MARK: Classifying dropped files

    enum DroppedFile: Sendable, Equatable {
        case config([SSHConfigHost])
        case privateKey(path: String)
        case certificate(path: String)        // OpenSSH *-cert.pub
        case publicKey(path: String)          // the shareable half — not importable
        case unrecognized
    }

    /// Look at a dropped file's CONTENT (never just the name) and say what it is.
    static func classify(url: URL) -> DroppedFile {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]),
              data.count < 1_000_000,
              let text = String(data: data.prefix(64 * 1024), encoding: .utf8) else { return .unrecognized }
        let head = text.trimmingCharacters(in: .whitespacesAndNewlines)

        if head.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
            || head.contains("PRIVATE KEY-----") {   // RSA/EC/PKCS8 PEM variants
            return .privateKey(path: url.path)
        }
        // Single-line "ssh-ed25519 AAAA…" style: certificate or public key.
        let firstToken = head.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
        if firstToken.hasPrefix("ssh-") || firstToken.hasPrefix("ecdsa-") || firstToken.hasPrefix("sk-") {
            return firstToken.contains("-cert-v01@openssh.com")
                ? .certificate(path: url.path)
                : .publicKey(path: url.path)
        }
        // ssh_config heuristic: any recognized client-config keyword at line start.
        let configKeys = ["host ", "host\t", "hostname", "proxyjump", "identityfile",
                          "localforward", "remoteforward", "dynamicforward", "user ", "port "]
        let lower = text.lowercased()
        if lower.split(separator: "\n").contains(where: { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            return configKeys.contains { t.hasPrefix($0) }
        }) {
            let hosts = parse(text)
            if !hosts.isEmpty { return .config(hosts) }
        }
        return .unrecognized
    }

    /// The user's own client config, for the "find this endpoint in my SSH
    /// config" affordance. Read ONLY on explicit user action.
    static var userConfigURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    }
    static var userConfigExists: Bool {
        FileManager.default.fileExists(atPath: userConfigURL.path)
    }

    /// Hosts in a parsed config that plausibly describe `endpoint` — matching
    /// alias or effective HostName (case-insensitive).
    static func hosts(_ hosts: [SSHConfigHost], matching endpoint: String) -> [SSHConfigHost] {
        let target = endpoint.trimmingCharacters(in: .whitespaces).lowercased()
        guard !target.isEmpty else { return [] }
        return hosts.filter {
            $0.alias.lowercased() == target || $0.effectiveHostName.lowercased() == target
        }
    }
}
