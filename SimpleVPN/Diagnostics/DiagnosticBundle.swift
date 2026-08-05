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
//     app, and why "full" is offered as a separate, clearly-labelled choice. When a
//     surface CAN be built from structured facts instead, it must be — see
//     `DiagnosticReport`, which is an allow-list and uses the scrubber only as
//     defence in depth.
//   • Same value ⇒ same placeholder within one bundle (so you can still see "this
//     is the same host again"), but the salt is per-bundle, so placeholders can't
//     be correlated across reports or reversed with a precomputed table.
//
//  The rules themselves live in ONE place, `SecretScrubber` — this file picks the
//  `.logBundle` policy and adds nothing of its own.
//

import Foundation
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
            let scrubber = SecretScrubber(policy: .logBundle,
                                          literalSecrets: extraSecrets + SecretScrubber.machineIdentifiers())
            return scrubber.scrub(text)
                + "\n> Scrubbed capture: addresses, hostnames and usernames were replaced with placeholders.\n"
                + "> Scrubbing is best-effort — please read it before sharing.\n"
        }
    }

    /// Scrub arbitrary text with the same rules as a bundle. Used by the crash reporter:
    /// a backtrace carries /Users/<name> paths, and the review sheet has to be able to
    /// show the user a scrubbed version before anything is shared.
    static func scrubText(_ text: String) -> String {
        SecretScrubber(policy: .logBundle,
                       literalSecrets: SecretScrubber.machineIdentifiers()).scrub(text)
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

    /// Run a read-only system tool with a hard deadline. Shared with
    /// `DiagnosticReportLog`, which needs exactly the same guarantees (absolute
    /// path, no inherited environment surprises, never hangs the collection).
    static func run(_ tool: String, _ args: [String]) async -> String {
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

}
