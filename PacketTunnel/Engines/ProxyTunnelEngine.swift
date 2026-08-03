// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelEngine.swift
//  Drives the in-process proxy-tunnel engine (a tun2socks-style gVisor netstack
//  that re-dials every flow through a SOCKS5/HTTP(S) proxy — see
//  Vendor/proxy-engine/src/engine.go) from the packet-tunnel system extension:
//  owns the packet pump between NEPacketTunnelFlow and the Go netstack, and
//  reports status/failures to the provider.
//
//  The engine's C symbols (PXStart/PXStop/…) are compiled into the SAME Go
//  c-archive as the Tailscale engine (libtsengine.a) — two Go c-archives cannot
//  be linked into one binary. That is a build detail; at the Swift boundary it
//  is an ordinary set of C functions declared in pxengine.h.
//
//  PACKET PUMP — no PF header here (contrast the openvpn3 path; see AGENTS.md).
//  The Go netstack deals in RAW IP packets both ways; the packet's own IP
//  version nibble is what tells us which protocol number to hand
//  NEPacketTunnelFlow.
//
//  CALLBACK CONTEXT — the engine's callbacks are plain C function pointers,
//  which by construction cannot capture Swift context. Exactly one tunnel runs
//  per provider process, so the callbacks route through a single lock-guarded
//  static reference, exactly like TailscaleEngine.
//

import Foundation
import NetworkExtension
import os

protocol ProxyTunnelEngineDelegate: AnyObject {
    /// A failure the session cannot recover from.
    func proxyTunnelEngine(_ engine: ProxyTunnelEngine, didFailWithError error: Error)
    /// Engine diagnostics for os_log.
    func proxyTunnelEngine(_ engine: ProxyTunnelEngine, didLog line: String)
}

final class ProxyTunnelEngine: @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "proxytunnel")

    private weak var provider: NEPacketTunnelProvider?
    private weak var delegate: (any ProxyTunnelEngineDelegate)?

    private let lock = NSLock()
    private var pumpRunning = false
    private var stopped = false

    /// The engine currently wired to the C callbacks.
    private static let currentLock = NSLock()
    nonisolated(unsafe) private static var current: ProxyTunnelEngine?

    private static func active() -> ProxyTunnelEngine? {
        currentLock.lock(); defer { currentLock.unlock() }
        return current
    }

    init(provider: NEPacketTunnelProvider, delegate: any ProxyTunnelEngineDelegate) {
        self.provider = provider
        self.delegate = delegate
    }

    // MARK: - Lifecycle

    /// Compose and start the stack. Synchronous by nature (there is no
    /// control-plane handshake): returns an error on a configuration/engine
    /// failure, or nil once the netstack is up. The caller then applies the
    /// tunnel network settings and calls `startPump()`.
    func start(config: ProxyTunnelStartConfig) -> Error? {
        Self.currentLock.lock(); Self.current = self; Self.currentLock.unlock()
        PXSetCallbacks(Self.packetOut, Self.stateChanged, Self.logLine)

        Self.log.log("proxy tunnel start: \(config.redactedJSONString(), privacy: .public)")

        let reply = config.jsonString().withCString { PXStart($0) }
        let response = Self.takeString(reply)
        return Self.engineError(from: response, fallback: "The proxy tunnel could not start.")
    }

    /// Tear the stack down. Safe to call more than once, and safe after a failed
    /// start.
    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        lock.unlock()

        _ = Self.takeString(PXStop())
        Self.currentLock.lock()
        if Self.current === self { Self.current = nil }
        Self.currentLock.unlock()
        // Drop the callbacks last: a packet already inside the Go writer would
        // otherwise land on a torn-down flow.
        PXSetCallbacks(nil, nil, nil)
        Self.log.log("proxy tunnel stopped")
    }

    // MARK: - Status

    /// Current engine status, or an empty status when the engine is not up.
    func status() -> ProxyTunnelStatus {
        guard let json = Self.takeString(PXStatus()), let s = ProxyTunnelStatus.decode(json: json) else {
            return ProxyTunnelStatus()
        }
        return s
    }

    /// Telemetry sample for the app's 1 Hz poll.
    ///
    /// `serverEndpoint` names the proxy host (there is a single upstream, unlike
    /// a mesh) so the connection panel and map have an honest pin; there is no
    /// in-tunnel address to report (the utun's own 198.18/fd6e addresses are an
    /// implementation detail the user never sees).
    func stats(profile: String, connectedSince: Double, reconnects: Int, proxyHost: String) -> TunnelStats {
        let s = status()
        var out = TunnelStats(
            profile: profile,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: connectedSince,
            reconnects: reconnects,
            bytesIn: s.bytesDown,
            bytesOut: s.bytesUp,
            serverEndpoint: proxyHost,
            tunnelIPv4: "",
            dnsServers: [],
            proxies: proxyHost.isEmpty ? [] : [s.scheme.isEmpty ? proxyHost : "\(s.scheme)://\(proxyHost)"])
        out.serverProto = s.scheme
        return out
    }

    // MARK: - Packet pump

    /// flow → engine. One outstanding read at a time; the handler re-arms itself,
    /// which is the documented NEPacketTunnelFlow pattern. Started by the
    /// provider once the tunnel network settings are applied (the flow has no
    /// addresses before that).
    func startPump() {
        lock.lock()
        if pumpRunning || stopped { lock.unlock(); return }
        pumpRunning = true
        lock.unlock()
        readMore()
    }

    private func readMore() {
        guard let flow = provider?.packetFlow else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            for packet in packets {
                // Raw IP packet straight in — no PF header on this boundary. A
                // full queue drops (PXPacketIn returns 0), which is correct: a
                // VPN must shed load, never stall the flow reader.
                packet.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress, !raw.isEmpty else { return }
                    _ = PXPacketIn(base, Int32(raw.count))
                }
            }
            self.lock.lock(); let running = self.pumpRunning && !self.stopped; self.lock.unlock()
            if running { self.readMore() }
        }
    }

    /// engine → flow. Called from a Go goroutine; NEPacketTunnelFlow's write is
    /// thread-safe, so no hop is needed (and a hop would add latency to every
    /// packet).
    fileprivate func deliver(_ packet: Data) {
        guard let flow = provider?.packetFlow, let first = packet.first else { return }
        let proto: Int32 = (first >> 4) == 6 ? AF_INET6 : AF_INET
        flow.writePackets([packet], withProtocols: [NSNumber(value: proto)])
    }

    // MARK: - Engine events

    fileprivate func handleState(_ json: String) {
        // "running"/"stopped" transitions are informational for the proxy tunnel
        // (there is no auth handshake to surface); the provider already knows the
        // lifecycle from start()/stop(). Log for diagnostics only.
        Self.log.log("proxy tunnel state: \(json, privacy: .public)")
    }

    fileprivate func handleLog(_ line: String) {
        delegate?.proxyTunnelEngine(self, didLog: line)
    }

    // MARK: - C boundary helpers

    private static func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { PXFree(p) }
        return String(cString: p)
    }

    /// Decode `{"error":{"kind","message"}}` into a UserFacingError-friendly
    /// NSError, or nil when the response was `{"ok":true}`.
    private static func engineError(from json: String?, fallback: String) -> Error? {
        guard let json, let data = json.data(using: .utf8) else {
            return ProxyTunnelEngineError.engine(kind: "other", message: fallback)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ProxyTunnelEngineError.engine(kind: "other", message: fallback)
        }
        if let e = obj["error"] as? [String: Any] {
            return ProxyTunnelEngineError.engine(kind: (e["kind"] as? String) ?? "other",
                                                 message: (e["message"] as? String) ?? fallback)
        }
        if obj["ok"] as? Bool == true { return nil }
        return ProxyTunnelEngineError.engine(kind: "other", message: fallback)
    }

    // MARK: - C callbacks
    //
    // `@convention(c)` by inference: none captures anything, which is what lets
    // them be handed to the Go side as function pointers.

    private static let packetOut: PXPacketCallback = { bytes, length in
        guard let bytes, length > 0 else { return }
        let data = Data(bytes: bytes, count: Int(length))
        active()?.deliver(data)
    }

    private static let stateChanged: PXStringCallback = { text in
        guard let text else { return }
        active()?.handleState(String(cString: text))
    }

    private static let logLine: PXStringCallback = { text in
        guard let text else { return }
        active()?.handleLog(String(cString: text))
    }
}

/// Failures the proxy-tunnel engine can produce. Messages are plain prose so
/// UserFacingError's generic classifier makes a usable sheet without a bespoke
/// branch.
enum ProxyTunnelEngineError: LocalizedError {
    case engine(kind: String, message: String)

    var errorDescription: String? {
        switch self {
        case .engine(let kind, let message):
            switch kind {
            case "badRequest":
                return "This proxy tunnel's settings are not usable. \(message)"
            case "alreadyRunning":
                return "This proxy tunnel is already connected."
            default:
                return message.isEmpty ? "The proxy tunnel engine reported a problem." : message
            }
        }
    }

    /// How this failure is filed for the incident card.
    var incidentEvent: String {
        switch self {
        case .engine(let kind, _): "PX_\(kind.uppercased())"
        }
    }

    var incidentCategory: IncidentCategory {
        switch self {
        case .engine(let kind, _):
            switch kind {
            case "badRequest": .tunSetup
            default: .network
            }
        }
    }
}
