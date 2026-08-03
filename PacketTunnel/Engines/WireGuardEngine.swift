// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardEngine.swift
//  Drives the in-process plain-WireGuard engine (wireguard-go's device package
//  behind a small JSON shim — see Vendor/tailscale-engine/src/wireguard.go)
//  from the packet-tunnel system extension: owns the packet pump between
//  NEPacketTunnelFlow and the Go TUN, and reports status/failures to the
//  provider.
//
//  The engine's C symbols (WGStart/WGStop/…) are compiled into the SAME Go
//  c-archive as the Tailscale and proxy-tunnel engines (libtsengine.a) — two
//  Go c-archives cannot be linked into one binary. That is a build detail; at
//  the Swift boundary it is an ordinary set of C functions in wgengine.h.
//
//  PACKET PUMP — no PF header here (contrast the openvpn3 path; see AGENTS.md).
//  The Go TUN deals in RAW IP packets both ways; the packet's own IP version
//  nibble is what tells us which protocol number to hand NEPacketTunnelFlow.
//
//  CALLBACK CONTEXT — the engine's callbacks are plain C function pointers,
//  which by construction cannot capture Swift context. Exactly one tunnel runs
//  per provider process, so the callbacks route through a single lock-guarded
//  static reference, exactly like TailscaleEngine and ProxyTunnelEngine.
//

import Foundation
import NetworkExtension
import os

protocol WireGuardEngineDelegate: AnyObject {
    /// A failure the session cannot recover from.
    func wireGuardEngine(_ engine: WireGuardEngine, didFailWithError error: Error)
    /// Engine diagnostics for os_log (wireguard-go's own logger — never keys).
    func wireGuardEngine(_ engine: WireGuardEngine, didLog line: String)
}

final class WireGuardEngine: @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "wireguard")

    private weak var provider: NEPacketTunnelProvider?
    private weak var delegate: (any WireGuardEngineDelegate)?

    private let lock = NSLock()
    private var pumpRunning = false
    private var stopped = false
    /// The literal ip:port WGStart resolved the endpoint to — the tunnel's
    /// honest remote address (set once at start, then read-only).
    private var endpoint = ""

    /// The engine currently wired to the C callbacks.
    private static let currentLock = NSLock()
    nonisolated(unsafe) private static var current: WireGuardEngine?

    private static func active() -> WireGuardEngine? {
        currentLock.lock(); defer { currentLock.unlock() }
        return current
    }

    init(provider: NEPacketTunnelProvider, delegate: any WireGuardEngineDelegate) {
        self.provider = provider
        self.delegate = delegate
    }

    // MARK: - Lifecycle

    /// Bring the device up. Synchronous (the Noise handshake is lazy — first
    /// packet or keepalive — so there is no control-plane wait): returns an
    /// error on a configuration/engine failure, or nil once the device runs.
    /// The caller then applies the tunnel network settings (using
    /// `resolvedEndpoint` as the remote address) and calls `startPump()`.
    func start(config: WireGuardStartConfig) -> Error? {
        Self.currentLock.lock(); Self.current = self; Self.currentLock.unlock()
        WGSetCallbacks(Self.packetOut, Self.logLine)

        Self.log.log("wireguard start: \(config.redactedJSONString(), privacy: .public)")

        let reply = config.jsonString().withCString { WGStart($0) }
        guard let response = Self.takeString(reply) else {
            return WireGuardEngineError.engine(kind: "other", message: "The WireGuard engine did not answer.")
        }
        if let error = Self.engineError(from: response, fallback: "WireGuard could not start.") {
            return error
        }
        // Success carries the resolved endpoint alongside ok:true.
        if let data = response.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let resolved = obj["endpoint"] as? String {
            lock.lock(); endpoint = resolved; lock.unlock()
        }
        return nil
    }

    /// The literal ip:port the engine dials — valid after a successful start.
    var resolvedEndpoint: String {
        lock.lock(); defer { lock.unlock() }
        return endpoint
    }

    /// Tear the device down. Safe to call more than once, and safe after a
    /// failed start.
    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        lock.unlock()

        _ = Self.takeString(WGStop())
        Self.currentLock.lock()
        if Self.current === self { Self.current = nil }
        Self.currentLock.unlock()
        // Drop the callbacks last: a packet already inside the Go writer would
        // otherwise land on a torn-down flow.
        WGSetCallbacks(nil, nil)
        Self.log.log("wireguard stopped")
    }

    // MARK: - Status

    /// Current engine status, or an empty status when the engine is not up.
    func status() -> WireGuardEngineStatus {
        guard let json = Self.takeString(WGStatus()),
              let s = WireGuardEngineStatus.decode(json: json) else {
            return WireGuardEngineStatus()
        }
        return s
    }

    /// Telemetry sample for the app's 1 Hz poll. `serverEndpoint` is the
    /// resolved peer endpoint (there IS a single server, unlike a mesh);
    /// the in-tunnel address and DNS come from the config the settings were
    /// built from.
    func stats(profile: String, connectedSince: Double, reconnects: Int,
               config: WireGuardConfig) -> TunnelStats {
        let s = status()
        var out = TunnelStats(
            profile: profile,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: connectedSince,
            reconnects: reconnects,
            bytesIn: s.rxBytes,
            bytesOut: s.txBytes,
            serverEndpoint: s.endpoint.isEmpty ? resolvedEndpoint : s.endpoint,
            tunnelIPv4: config.addresses.first { !$0.contains(":") }
                .map { String($0.prefix { $0 != "/" }) } ?? "",
            dnsServers: config.dns,
            proxies: [])
        out.tunnelIPv6 = config.addresses.first { $0.contains(":") }
            .map { String($0.prefix { $0 != "/" }) }
        out.mtu = (config.mtu ?? 0) > 0 ? config.mtu : WireGuardStartConfig.defaultMTU
        out.serverProto = "udp"
        return out
    }

    // MARK: - Packet pump

    /// flow → engine. One outstanding read at a time; the handler re-arms
    /// itself, which is the documented NEPacketTunnelFlow pattern. Started by
    /// the provider once the tunnel network settings are applied (the flow has
    /// no addresses before that).
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
                // full queue drops (WGPacketIn returns 0), which is correct: a
                // VPN must shed load, never stall the flow reader.
                packet.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress, !raw.isEmpty else { return }
                    _ = WGPacketIn(base, Int32(raw.count))
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

    fileprivate func handleLog(_ line: String) {
        delegate?.wireGuardEngine(self, didLog: line)
    }

    // MARK: - C boundary helpers

    private static func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { WGFree(p) }
        return String(cString: p)
    }

    /// Decode `{"error":{"kind","message"}}` into a UserFacingError-friendly
    /// error, or nil when the response was `{"ok":true,…}`.
    private static func engineError(from json: String?, fallback: String) -> Error? {
        guard let json, let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return WireGuardEngineError.engine(kind: "other", message: fallback)
        }
        if let e = obj["error"] as? [String: Any] {
            return WireGuardEngineError.engine(kind: (e["kind"] as? String) ?? "other",
                                               message: (e["message"] as? String) ?? fallback)
        }
        if obj["ok"] as? Bool == true { return nil }
        return WireGuardEngineError.engine(kind: "other", message: fallback)
    }

    // MARK: - C callbacks
    //
    // `@convention(c)` by inference: none captures anything, which is what lets
    // them be handed to the Go side as function pointers.

    private static let packetOut: WGPacketCallback = { bytes, length in
        guard let bytes, length > 0 else { return }
        let data = Data(bytes: bytes, count: Int(length))
        active()?.deliver(data)
    }

    private static let logLine: WGStringCallback = { text in
        guard let text else { return }
        active()?.handleLog(String(cString: text))
    }
}

/// Failures the WireGuard engine can produce. Messages are plain prose so
/// UserFacingError's generic classifier makes a usable sheet without a bespoke
/// branch.
enum WireGuardEngineError: LocalizedError {
    case engine(kind: String, message: String)

    var errorDescription: String? {
        switch self {
        case .engine(let kind, let message):
            switch kind {
            case "badRequest":
                return "This WireGuard tunnel's settings are not usable. \(message)"
            case "endpoint":
                return "The server's address couldn't be reached. \(message)"
            case "alreadyRunning":
                return "This WireGuard tunnel is already connected."
            default:
                return message.isEmpty ? "The WireGuard engine reported a problem." : message
            }
        }
    }

    /// How this failure is filed for the incident card.
    var incidentEvent: String {
        switch self {
        case .engine(let kind, _): "WG_\(kind.uppercased())"
        }
    }

    var incidentCategory: IncidentCategory {
        switch self {
        case .engine(let kind, _):
            switch kind {
            case "badRequest": .tunSetup
            case "endpoint": .dns
            default: .network
            }
        }
    }
}
