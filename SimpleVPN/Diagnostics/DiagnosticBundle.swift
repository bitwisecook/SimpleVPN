// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticBundle.swift
//  Collects a debug log for a bug report: recent app + system-extension log lines,
//  the routing table, interface MTUs, DNS and proxy configuration — the things that
//  actually explain a broken tunnel (handshake, MTU, routes) — plus a SCRUBBED
//  variant with addresses, hostnames, usernames and anything credential-shaped
//  replaced by stable placeholders.
//
//  Two deliberate design points:
//   • Scrubbing is BEST-EFFORT pattern matching. It cannot be guaranteed complete,
//     which is exactly why the user is always shown the text before it leaves the
//     app, and why "full" is offered as a separate, clearly-labelled choice.
//   • Same value ⇒ same placeholder within one bundle (so you can still see "this
//     is the same host again"), but the salt is per-bundle, so placeholders can't
//     be correlated across reports or reversed with a precomputed table.
//

import Foundation
import CryptoKit
import SystemConfiguration

nonisolated enum DiagnosticBundle {

    enum Variant: String, CaseIterable, Sendable {
        case scrubbed, full
        var title: String { self == .scrubbed ? "Scrubbed" : "Full" }
    }

    /// Collect the bundle. `variant == .scrubbed` runs the scrubber over everything
    /// (including the log lines) before returning.
    static func collect(variant: Variant, header: [String: String], extraSecrets: [String] = []) async -> String {
        let sections = await withTaskGroup(of: (Int, String, String).self) { group -> [(Int, String, String)] in
            for (i, s) in commands.enumerated() {
                group.addTask { (i, s.title, await run(s.tool, s.args)) }
            }
            var out: [(Int, String, String)] = []
            for await r in group { out.append(r) }
            return out
        }

        var text = "# SimpleVPN diagnostics (\(variant.rawValue))\n\n"
        for (k, v) in header.sorted(by: { $0.key < $1.key }) { text += "\(k): \(v)\n" }
        text += "\n"
        for (_, title, body) in sections.sorted(by: { $0.0 < $1.0 }) {
            text += "\n## \(title)\n```\n\(cap(body))\n```\n"
        }

        switch variant {
        case .full:
            text += "\n> FULL capture — this may contain hostnames, IP addresses and usernames.\n"
            return text
        case .scrubbed:
            let scrubber = Scrubber(extraSecrets: extraSecrets + knownLocalIdentifiers())
            return scrubber.scrub(text)
                + "\n> Scrubbed capture: addresses, hostnames and usernames were replaced with placeholders.\n"
                + "> Scrubbing is best-effort — please read it before sharing.\n"
        }
    }

    /// Scrub arbitrary text with the same rules as a bundle. Used by the crash reporter:
    /// a backtrace carries /Users/<name> paths, and the review sheet has to be able to
    /// show the user a scrubbed version before anything is shared.
    static func scrubText(_ text: String) -> String {
        Scrubber(extraSecrets: knownLocalIdentifiers()).scrub(text)
    }

    // MARK: What we collect

    private struct Cmd { let title: String; let tool: String; let args: [String] }

    /// Our own subsystem covers BOTH the app and the packet-tunnel extension
    /// (com.bragi0.SimpleVPN.PacketTunnel), so one predicate gets both sides of a
    /// connection attempt — including the handshake and the negotiated MTU.
    private static var commands: [Cmd] {
        [
            Cmd(title: "SimpleVPN log (last 20 minutes)", tool: "/usr/bin/log",
                args: ["show", "--style", "compact", "--info", "--debug", "--last", "20m",
                       "--predicate", #"subsystem BEGINSWITH "com.bragi0.SimpleVPN""#]),
            Cmd(title: "Routing table (IPv4/IPv6)", tool: "/usr/sbin/netstat", args: ["-rn"]),
            Cmd(title: "Interfaces and MTUs", tool: "/sbin/ifconfig", args: ["-a"]),
            Cmd(title: "Resolver configuration", tool: "/usr/sbin/scutil", args: ["--dns"]),
            Cmd(title: "Proxy configuration", tool: "/usr/sbin/scutil", args: ["--proxy"]),
            Cmd(title: "Network services order", tool: "/usr/sbin/networksetup", args: ["-listnetworkserviceorder"]),
        ]
    }

    /// Keep any single section bounded so a bundle stays reviewable/pasteable.
    private static func cap(_ s: String, limit: Int = 60_000) -> String {
        guard s.count > limit else { return s }
        return String(s.suffix(limit)) + "\n… (truncated; oldest lines dropped)"
    }

    private static func run(_ tool: String, _ args: [String]) async -> String {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                guard FileManager.default.isExecutableFile(atPath: tool) else {
                    cont.resume(returning: "(\(tool) unavailable)"); return
                }
                let p = Process()
                p.executableURL = URL(fileURLWithPath: tool)
                p.arguments = args
                let out = Pipe(), err = Pipe()
                p.standardOutput = out; p.standardError = err
                // Don't let a wedged tool hang the capture.
                let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + 25, execute: killer)
                do { try p.run() } catch {
                    cont.resume(returning: "(failed to run: \(error.localizedDescription))"); return
                }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                let errData = err.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                killer.cancel()
                var text = String(data: data, encoding: .utf8) ?? ""
                if text.isEmpty, let e = String(data: errData, encoding: .utf8), !e.isEmpty { text = "(stderr) " + e }
                cont.resume(returning: text.isEmpty ? "(no output)" : text)
            }
        }
    }

    /// Local identity strings worth redacting even in a "scrubbed" bundle.
    private static func knownLocalIdentifiers() -> [String] {
        var out = [NSUserName(), NSFullUserName(), ProcessInfo.processInfo.hostName]
        if let name = Host.current().localizedName { out.append(name) }
        return out.filter { $0.count >= 3 }
    }
}

// MARK: - Scrubber

/// Best-effort redaction. Ordering matters: credential-shaped key=value pairs are
/// killed first (so a password that happens to look like a hostname is gone before
/// any structural pass), then addresses, then hostnames, then literal secrets.
nonisolated struct Scrubber {
    let extraSecrets: [String]
    /// Per-bundle salt: placeholders stay consistent inside one report but can't be
    /// correlated across reports or reversed with a precomputed table.
    private let salt: String = UUID().uuidString

    func scrub(_ input: String) -> String {
        var s = input
        s = redactSensitiveValues(s)
        s = redactIPv6(s)
        s = redactIPv4(s)
        s = redactMACs(s)
        s = redactHostnames(s)
        s = redactLiterals(s)
        return s
    }

    private func token(_ kind: String, _ value: String) -> String {
        let digest = SHA256.hash(data: Data((salt + value).utf8))
        let hex = digest.compactMap { String(format: "%02x", $0) }.joined().prefix(6)
        return "<\(kind):\(hex)>"
    }

    private func replace(_ s: String, _ pattern: String,
                         options: NSRegularExpression.Options = [.caseInsensitive],
                         _ transform: (_ match: String, _ groups: [String?]) -> String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return s }
        let ns = s as NSString
        var result = ""
        var last = 0
        re.enumerateMatches(in: s, range: NSRange(location: 0, length: ns.length)) { m, _, _ in
            guard let m else { return }
            result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            var groups: [String?] = []
            for i in 1..<m.numberOfRanges {
                let r = m.range(at: i)
                groups.append(r.location == NSNotFound ? nil : ns.substring(with: r))
            }
            result += transform(ns.substring(with: m.range), groups)
            last = m.range.location + m.range.length
        }
        result += ns.substring(from: last)
        return result
    }

    /// password=…, token: …, Authorization: …, cookie=…, otp=… → removed entirely.
    private func redactSensitiveValues(_ s: String) -> String {
        let keys = "password|passwd|pass|secret|token|cookie|authorization|auth[-_]?token|otp|one[-_]?time|apikey|api[-_]?key|bearer|session[-_]?id|private[-_]?key|passphrase"
        var out = replace(s, #"(?<key>\#(keys))(\s*[:=]\s*)(\S+)"#) { _, _ in "<redacted>" }
        // Also drop obvious PEM blocks.
        out = replace(out, #"-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----"#) { _, _ in "<redacted-key-material>" }
        return out
    }

    private func redactIPv4(_ s: String) -> String {
        replace(s, #"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"#, options: []) { match, _ in
            let parts = match.split(separator: ".").compactMap { UInt32($0) }
            guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return match }
            // Keep non-identifying well-known addresses: they carry meaning, not identity.
            let keep: Set<String> = ["0.0.0.0", "127.0.0.1", "255.255.255.255", "169.254.169.254"]
            if keep.contains(match) { return match }
            return token(kindForIPv4(parts), match)
        }
    }

    private func kindForIPv4(_ p: [UInt32]) -> String {
        let a = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
        func within(_ net: UInt32, _ plen: Int) -> Bool {
            let mask: UInt32 = plen == 0 ? 0 : (~UInt32(0)) << (32 - plen)
            return (a & mask) == (net & mask)
        }
        if within(0x6440_0000, 10) { return "ip4-tailscale-or-cgnat" }
        if within(0x0A00_0000, 8) || within(0xAC10_0000, 12) || within(0xC0A8_0000, 16) { return "ip4-private" }
        if within(0xA9FE_0000, 16) { return "ip4-linklocal" }
        if within(0x7F00_0000, 8) { return "ip4-loopback" }
        if within(0xE000_0000, 4) { return "ip4-multicast" }
        return "ip4-public"
    }

    private func redactIPv6(_ s: String) -> String {
        // Conservative: require at least three groups and a colon-pair to avoid
        // eating timestamps (12:34:56) and MAC addresses.
        replace(s, #"\b(?=[0-9a-f]*:)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?\b"#) { match, _ in
            let keep: Set<String> = ["::", "::1"]
            if keep.contains(match.lowercased()) { return match }
            guard match.contains("::") || match.filter({ $0 == ":" }).count >= 4 else { return match }
            let kind = match.lowercased().hasPrefix("fe80") ? "ip6-linklocal"
                : (match.lowercased().hasPrefix("fd") || match.lowercased().hasPrefix("fc")) ? "ip6-private" : "ip6"
            return token(kind, match.lowercased())
        }
    }

    private func redactMACs(_ s: String) -> String {
        replace(s, #"\b([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}\b"#) { match, _ in token("mac", match.lowercased()) }
    }

    /// Hostnames/FQDNs. Deliberately conservative: skip anything whose last label
    /// looks like a file extension or a known non-DNS suffix, so source filenames
    /// and bundle ids in log lines survive (they're useful and not identifying).
    private func redactHostnames(_ s: String) -> String {
        let skipSuffixes: Set<String> = [
            "swift", "plist", "app", "dylib", "framework", "xcframework", "a", "h", "m", "mm", "c", "cpp",
            "sh", "yml", "yaml", "json", "txt", "log", "png", "md", "pem", "crt", "key", "ovpn",
            "systemextension", "appex", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        ]
        // Bundle ids we WANT to keep readable.
        let keepPrefixes = ["com.bragi0.", "com.apple."]
        return replace(s, #"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b"#) { match, _ in
            let lower = match.lowercased()
            if keepPrefixes.contains(where: { lower.hasPrefix($0) }) { return match }
            guard let last = lower.split(separator: ".").last, !skipSuffixes.contains(String(last)) else { return match }
            // Require a plausible TLD (letters, 2+) to avoid version strings like 1.2.3.
            guard last.count >= 2, last.allSatisfy({ $0.isLetter }) else { return match }
            return token("host", lower)
        }
    }

    /// Literal strings we know identify this user/machine (login name, full name,
    /// computer name, configured VPN usernames).
    private func redactLiterals(_ s: String) -> String {
        var out = s
        for secret in extraSecrets.sorted(by: { $0.count > $1.count }) {
            let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.count >= 3 else { continue }
            guard let re = try? NSRegularExpression(pattern: NSRegularExpression.escapedPattern(for: trimmed),
                                                    options: [.caseInsensitive]) else { continue }
            out = re.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out),
                                              withTemplate: "<redacted-identity>")
        }
        return out
    }
}
