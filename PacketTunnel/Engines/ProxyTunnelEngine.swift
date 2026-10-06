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
//  CALLBACK CONTEXT — C callbacks carry a scoped registry ID. Removing a stopped
//  context fences late callbacks without disturbing another engine instance.
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

    private static let callbacks = EngineCallbackRegistry<ProxyTunnelEngine>()
    private var handle: UInt64 = 0
    private var callbackContext: UInt64 = 0
    private var starting = false
    private let packetOutput: (@Sendable (Data) -> Void)?

    init(provider: NEPacketTunnelProvider? = nil, delegate: any ProxyTunnelEngineDelegate,
         packetOutput: (@Sendable (Data) -> Void)? = nil) {
        self.provider = provider
        self.delegate = delegate
        self.packetOutput = packetOutput
    }

    // MARK: - Lifecycle

    /// Compose and start the stack. Synchronous by nature (there is no
    /// control-plane handshake): returns an error on a configuration/engine
    /// failure, or nil once the netstack is up. The caller then applies the
    /// tunnel network settings and calls `startPump()`.
    func start(config: ProxyTunnelStartConfig) -> Error? {
        let context: UInt64? = lock.withLock {
            guard !starting, !stopped, handle == 0 else { return nil }
            starting = true
            let context = Self.callbacks.register(self)
            callbackContext = context
            return context
        }
        guard let context else { return ProxyTunnelEngineError.engine(kind: "alreadyRunning", message: "") }

        Self.log.log("proxy tunnel start: \(config.redactedJSONString(), privacy: .public)")

        let reply = config.jsonString().withCString {
            PXCreateInstance($0, context, Self.packetOut, Self.stateChanged, Self.logLine, nil)
        }
        let response = Self.takeString(reply)
        let error = Self.engineError(from: response, fallback: "The proxy tunnel could not start.")
        let created = EngineCallbackRegistry<ProxyTunnelEngine>.handle(from: response)
        let accepted = lock.withLock {
            starting = false
            guard error == nil, created != 0, !stopped else { return false }
            handle = created
            return true
        }
        if !accepted {
            Self.callbacks.remove(context)
            if created != 0 { _ = Self.takeString(PXStopInstance(created)) }
            return error ?? ProxyTunnelEngineError.engine(kind: "other", message: "The proxy tunnel start was cancelled.")
        }
        return nil
    }

    /// Tear the stack down. Safe to call more than once, and safe after a failed
    /// start.
    func stop() {
        let (current, context) = lock.withLock {
            stopped = true
            pumpRunning = false
            let pair = (handle, callbackContext)
            handle = 0; callbackContext = 0
            return pair
        }
        Self.callbacks.remove(context)
        if current != 0 { _ = Self.takeString(PXStopInstance(current)) }
        Self.log.log("proxy tunnel stopped")
    }

    // MARK: - Status

    /// Current engine status, or an empty status when the engine is not up.
    func status() -> ProxyTunnelStatus {
        guard let json = Self.takeString(PXStatusInstance(lock.withLock { handle })), let s = ProxyTunnelStatus.decode(json: json) else {
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
                _ = self.send(packet)
            }
            self.lock.lock(); let running = self.pumpRunning && !self.stopped; self.lock.unlock()
            if running { self.readMore() }
        }
    }

    /// engine → flow. Called from a Go goroutine; NEPacketTunnelFlow's write is
    /// thread-safe, so no hop is needed (and a hop would add latency to every
    /// packet).
    fileprivate func deliver(_ packet: Data) {
        guard !lock.withLock({ stopped }) else { return }
        if let packetOutput { packetOutput(packet); return }
        guard let flow = provider?.packetFlow, let first = packet.first else { return }
        let proto: Int32 = (first >> 4) == 6 ? AF_INET6 : AF_INET
        flow.writePackets([packet], withProtocols: [NSNumber(value: proto)])
    }

    @discardableResult
    func send(_ packet: Data) -> Bool {
        let current = lock.withLock { stopped ? 0 : handle }
        guard current != 0 else { return false }
        return packet.withUnsafeBytes { raw in
            guard let base = raw.baseAddress, !raw.isEmpty, raw.count <= 65_535 else { return false }
            return PXPacketInInstance(current, base, Int32(raw.count)) == 1
        }
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

    private static let packetOut: PXInstancePacketCallback = { context, bytes, length in
        guard let bytes, length > 0 else { return }
        let data = Data(bytes: bytes, count: Int(length))
        callbacks.lookup(context)?.deliver(data)
    }

    private static let stateChanged: PXInstanceStringCallback = { context, text in
        guard let text else { return }
        callbacks.lookup(context)?.handleState(String(cString: text))
    }

    private static let logLine: PXInstanceStringCallback = { context, text in
        guard let text else { return }
        callbacks.lookup(context)?.handleLog(String(cString: text))
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
