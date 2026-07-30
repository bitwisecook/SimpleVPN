// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionDiagnostics.swift
//  Active probes run ONCE when a connection fails (never while connected —
//  live health is judged passively from traffic counters):
//    1. DNS-resolve the server name
//    2. TCP reachability probe to the server port (with rough RTT)
//    3. best-effort TLS certificate fetch (only meaningful where the endpoint
//       actually speaks TLS on that port — OpenVPN-over-UDP does not)
//    4. captive-portal check via Apple's canonical probe URL
//  Results are compared against a per-profile baseline recorded on the last
//  successful connection, so "the server's address changed since it last
//  worked" is called out explicitly.
//

import Foundation
import Network
import Security
import CryptoKit

// MARK: - Baseline (what the world looked like when it last worked)

struct ConnectionBaseline: Codable, Sendable, Equatable {
    var serverIP: String?          // transport address of the last good session
    var resolvedIPs: [String] = [] // DNS answers observed at that time (best effort)
    var tlsFingerprint: String?    // only when a TLS probe ever captured one
    var date: Date
}

enum ConnectionBaselineStore {
    private static func key(_ profile: String) -> String { "diagnostics.baseline.\(profile)" }

    static func save(_ baseline: ConnectionBaseline, profile: String) {
        guard let data = try? JSONEncoder().encode(baseline) else { return }
        UserDefaults.standard.set(data, forKey: key(profile))
    }
    static func load(profile: String) -> ConnectionBaseline? {
        guard let data = UserDefaults.standard.data(forKey: key(profile)) else { return nil }
        return try? JSONDecoder().decode(ConnectionBaseline.self, from: data)
    }
    static func clear(profile: String) {
        UserDefaults.standard.removeObject(forKey: key(profile))
    }
}

// MARK: - Report

struct DiagnosticsReport: Sendable, Equatable {
    var host = ""
    var port = 0

    var resolvedIPs: [String] = []
    var dnsFailed = false

    var tcpReachable: Bool?        // nil = probe didn't run
    var rttMilliseconds: Int?

    var tlsSubject: String?        // nil = no TLS spoken / probe skipped
    var tlsFingerprint: String?

    var captivePortal = false
    var portalURL: URL?

    var pathMTU: Int?              // measured by the DF-ping sizer; nil = host won't answer ICMP
    var tcp443Reachable: Bool?     // nil = probe didn't run

    /// Human sentences describing changes since the last good connection.
    var baselineNotes: [String] = []
}

// MARK: - Probes

// nonisolated: probe callbacks (NWConnection state handlers, TLS verify blocks,
// URLSession delegates) arrive on background queues — nothing here may be
// MainActor-isolated under the app target's MainActor default.
nonisolated enum ConnectionDiagnostics {

    /// Run the full failure-time probe sequence. `tryTLS` should be true only
    /// when the endpoint plausibly speaks TLS on `port` (TCP transport).
    static func run(host: String, port: Int, tryTLS: Bool,
                    baseline: ConnectionBaseline?) async -> DiagnosticsReport {
        var report = DiagnosticsReport(host: host, port: port)

        // 1. DNS
        report.resolvedIPs = await resolve(host: host)
        report.dnsFailed = report.resolvedIPs.isEmpty

        // 2. TCP reachability + RTT (uses the resolved name; Network handles
        //    happy-eyeballs itself)
        if !report.dnsFailed {
            let probe = await tcpProbe(host: host, port: port, timeout: 5)
            report.tcpReachable = probe.reachable
            report.rttMilliseconds = probe.rttMS
        }

        // 3. TLS certificate (best effort)
        if tryTLS, report.tcpReachable == true {
            if let tls = await tlsProbe(host: host, port: port, timeout: 6) {
                report.tlsSubject = tls.subject
                report.tlsFingerprint = tls.fingerprint
            }
        }

        // 4. Captive portal
        let portal = await captivePortalProbe()
        report.captivePortal = portal.detected
        report.portalURL = portal.url

        // 5. Is plain web (TCP 443) reachable? Distinguishes "this network blocks
        //    the VPN's UDP" from "no internet at all" — the udp-blocked rule.
        report.tcp443Reachable = port == 443 ? report.tcpReachable
                                             : await tcpReachable(host: host, port: 443, timeout: 4)

        // 6. Path MTU to the server (DF-ping binary search). The server keeps a
        //    host route outside the tunnel, so this measures the physical path
        //    even while a tunnel is up — exactly what mssfix needs.
        report.pathMTU = await pathMTU(to: host)

        // Baseline comparison
        if let baseline {
            if let old = baseline.serverIP, !old.isEmpty, !report.resolvedIPs.isEmpty,
               !report.resolvedIPs.contains(old) {
                report.baselineNotes.append(
                    "The server's address changed since your last successful connection (was \(old), now \(report.resolvedIPs.joined(separator: ", "))).")
            }
            if let oldFP = baseline.tlsFingerprint, let newFP = report.tlsFingerprint, oldFP != newFP {
                report.baselineNotes.append(
                    "The server is presenting a different certificate than when it last worked.")
            }
        }
        return report
    }

    // MARK: DNS

    /// All numeric addresses for a host (A + AAAA), empty on failure.
    static func resolve(host: String) async -> [String] {
        await Task.detached(priority: .userInitiated) {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC,
                                 ai_socktype: SOCK_STREAM, ai_protocol: 0,
                                 ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var result: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return [] }
            defer { freeaddrinfo(first) }
            var out: [String] = []
            var node: UnsafeMutablePointer<addrinfo>? = first
            while let info = node {
                var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen,
                               &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(cString: buffer)
                    if !out.contains(ip) { out.append(ip) }
                }
                node = info.pointee.ai_next
            }
            return out
        }.value
    }

    // MARK: TCP probe

    /// Is a TCP port reachable? (Convenience over `tcpProbe` when RTT isn't needed.)
    static func tcpReachable(host: String, port: Int, timeout: TimeInterval) async -> Bool {
        await tcpProbe(host: host, port: port, timeout: timeout).reachable
    }

    private static func tcpProbe(host: String, port: Int,
                                 timeout: TimeInterval) async -> (reachable: Bool, rttMS: Int?) {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return (false, nil) }
        let started = Date()
        let outcome = await connectionOutcome(
            NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp),
            timeout: timeout)
        let rtt = Int(Date().timeIntervalSince(started) * 1000)
        return (outcome, outcome ? rtt : nil)
    }

    /// TLS handshake that accepts any certificate purely to *capture* it for
    /// display/baseline comparison — nothing is trusted or transmitted.
    private static func tlsProbe(host: String, port: Int,
                                 timeout: TimeInterval) async -> (subject: String, fingerprint: String)? {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return nil }

        let captured = CapturedCertificate()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
               let leaf = chain.first {
                let der = SecCertificateCopyData(leaf) as Data
                let fp = SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
                let subject = (SecCertificateCopySubjectSummary(leaf) as String?) ?? "Unknown"
                captured.set(subject: subject, fingerprint: fp)
            }
            complete(true)   // diagnostic capture only — the connection is discarded
        }, DispatchQueue.global(qos: .userInitiated))

        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        _ = await connectionOutcome(
            NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params),
            timeout: timeout)
        return captured.value()
    }

    /// Wait for an NWConnection to become ready (true) or fail/time out (false).
    private static func connectionOutcome(_ connection: NWConnection,
                                          timeout: TimeInterval) async -> Bool {
        nonisolated final class Flag: @unchecked Sendable {
            private let lock = NSLock()
            private var resumed = false
            func once(_ body: () -> Void) {
                lock.lock(); defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                body()
            }
        }
        let flag = Flag()
        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    flag.once { continuation.resume(returning: true) }
                    connection.cancel()
                case .failed, .cancelled:
                    flag.once { continuation.resume(returning: false) }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                flag.once { continuation.resume(returning: false) }
                connection.cancel()
            }
        }
    }

    /// Thread-safe capture box for the verify block.
    private nonisolated final class CapturedCertificate: @unchecked Sendable {
        private let lock = NSLock()
        private var subject: String?
        private var fingerprint: String?
        func set(subject: String, fingerprint: String) {
            lock.lock(); defer { lock.unlock() }
            if self.subject == nil { self.subject = subject; self.fingerprint = fingerprint }
        }
        func value() -> (subject: String, fingerprint: String)? {
            lock.lock(); defer { lock.unlock() }
            guard let subject, let fingerprint else { return nil }
            return (subject, fingerprint)
        }
    }

    // MARK: Path MTU (DF-ping sizer)

    /// Largest IP packet that reaches `host` without fragmentation, found by
    /// sending don't-fragment ICMP echoes of increasing size and binary-searching
    /// the boundary. Returns the path MTU in bytes, or nil when the host doesn't
    /// answer ICMP at all (so we can't size it — callers fall back to a safe clamp).
    ///
    /// ICMP overhead is 28 bytes (20 IP + 8 ICMP), so payload P ⇒ MTU P+28.
    ///
    /// Thin forwarder: the sizer itself lives in `NetworkProbes.measurePathMTU` so the
    /// Doctor and the Network Tools MTU card share ONE implementation (and one set of
    /// caveats). That version uses the unprivileged ICMP socket directly instead of
    /// spawning /sbin/ping, and is IPv4-only — an IPv6-only host returns nil here,
    /// same as a host that filters ICMP.
    static func pathMTU(to host: String) async -> Int? {
        await NetworkProbes.measurePathMTU(host: host).pathMTU
    }

    // MARK: Captive portal

    /// Apple's canonical probe: anything other than the literal Success page
    /// means something on this network is intercepting traffic — hotel Wi-Fi
    /// sign-in, exhausted data plan, expired day pass.
    static let captivePortalProbeURL = URL(string: "http://captive.apple.com/hotspot-detect.html")!

    private static func captivePortalProbe() async -> (detected: Bool, url: URL?) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 8
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let delegate = NoRedirectDelegate()
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        do {
            let (data, response) = try await session.data(from: captivePortalProbeURL)
            if let http = response as? HTTPURLResponse, (300..<400).contains(http.statusCode) {
                let location = (http.value(forHTTPHeaderField: "Location")).flatMap(URL.init(string:))
                return (true, location ?? captivePortalProbeURL)
            }
            let body = String(data: data, encoding: .utf8) ?? ""
            if body.contains("Success") { return (false, nil) }
            return (true, captivePortalProbeURL)   // 200 with substituted content
        } catch {
            return (false, nil)                    // offline ≠ captive portal
        }
    }

    // nonisolated: URLSession delivers this on a background queue.
    private nonisolated final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
        nonisolated func urlSession(_ session: URLSession, task: URLSessionTask,
                                    willPerformHTTPRedirection response: HTTPURLResponse,
                                    newRequest request: URLRequest,
                                    completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)   // surface the 3xx instead of following it
        }
    }
}
