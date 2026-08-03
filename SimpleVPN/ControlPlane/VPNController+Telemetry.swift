// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+Telemetry.swift
//  The IPC face of VPNController: the one-shot provider-message channel — the
//  ONLY channel that crosses the root(system) extension ↔ user app boundary —
//  and the telemetry that rides it: live stats (folding the engine's
//  ground-truth gateway/proxy state back into the mediators), traffic flows,
//  and the pushed-proxy intent capture. Stored state lives in
//  VPNController.swift.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    /// One-shot IPC to the running tunnel; nil when no session or send fails.
    func sendMessage(_ message: String, to id: String) async -> String? {   // was private — internal for the +File split
        await sendMessageData(message, to: id).flatMap { String(data: $0, encoding: .utf8) }
    }

    func sendMessageData(_ message: String, to id: String,   // was private — internal for the +File split
                                 timeout: TimeInterval = 8) async -> Data? {
        guard let session = managers[id]?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            // Single-resume guard + timeout: if the session is torn down between the
            // guard and the call, or the completion never fires, the continuation
            // would otherwise leak and hang this task forever — and this is the
            // channel ReachabilityMonitor/ThroughputMonitor poll continuously.
            let once = OnceResume()
            let finish: @Sendable (Data?) -> Void = { d in if once.claim() { cont.resume(returning: d) } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(nil) }
            do {
                try session.sendProviderMessage(Data(message.utf8)) { reply in finish(reply) }
            } catch {
                finish(nil)
            }
        }
    }

    /// Live telemetry poll — the only channel that crosses the root(system)
    /// extension ↔ user app boundary. nil when not connected.
    func fetchStats(id: String) async -> TunnelStats? {
        guard let data = await sendMessageData("stats", to: id) else { return nil }
        let stats = try? JSONDecoder().decode(TunnelStats.self, from: data)
        // Fold the engine's ground-truth default-route ownership into the gateway
        // coordinator on every poll: keeps the applied-role cache honest and heals
        // any full/split desync live (RC1/RC4). The stats poll is the only channel
        // that crosses the root-extension ↔ user-app boundary.
        if let owned = stats?.effectiveDefaultOwned { routes.noteEngineDefaultOwned(id: id, owned: owned) }
        // Fold the engine's ground-truth pushed proxy into the Proxy mediator, the same
        // way as the default-route ownership above. Only kinds that PUSH a proxy
        // structurally do this today (OpenVPN); OpenConnect is a marked TODO below.
        if let stats { notePushedProxy(id: id, from: stats) }
        return stats
    }

    /// Update the per-profile pushed-proxy cache from a stats sample and, when the
    /// decision changed, ask the Proxy mediator to re-arbitrate + apply. Per-kind
    /// (StateMediators.md › Pushed-proxy sources): OpenVPN carries structured
    /// `dhcp-option PROXY_*` here; the SOCKS/native/none kinds contribute nothing.
    private func notePushedProxy(id: String, from stats: TunnelStats) {
        let kind = profiles.first { $0.id == id }?.kind
        let newIntent: ProxyIntent?
        switch kind {
        case .openVPN:
            newIntent = Self.proxyIntent(engine: id, from: stats)
        // TODO(StateMediators.md › Pushed-proxy sources by VPN kind): OpenConnect
        // (AnyConnect/GlobalProtect) can push a PAC/proxy, but the channel is
        // vendor-specific and needs a real gateway to verify what libopenconnect
        // surfaces — left uncaptured rather than half-implemented. Native IKEv2/IPsec
        // proxy is OS-owned (we only OBSERVE via SCDynamicStore, never push). SSH /
        // proxy-tunnel / Tailscale / WireGuard push no proxy — no intent by design.
        default:
            newIntent = nil
        }
        let changed = pushedProxyIntents[id] != newIntent
        pushedProxyIntents[id] = newIntent
        proxies.noteEnginePushedProxy(changed: changed)
    }

    /// Build a `ProxyIntent` from the structured pushed-proxy fields of a stats sample
    /// (OpenVPN's `dhcp-option PROXY_HTTP/PROXY_HTTPS/PROXY_AUTO_CONFIG_URL/PROXY_BYPASS`).
    /// PAC wins over manual. `nil` when nothing was pushed. No credentials ever — the
    /// push carries none; if the pushed proxy demands sign-in, the Custom Routing hook
    /// attaches the profile's keychain `authSource` REF before arbitration and the
    /// Proxy realizer resolves it at apply time.
    nonisolated static func proxyIntent(engine: String, from stats: TunnelStats) -> ProxyIntent? {
        let bypass = stats.proxyBypass ?? []
        if let pac = stats.proxyPACURL, !pac.isEmpty {
            return ProxyIntent(engine: engine, mode: .pac(pac),
                               connectedAt: nil, bypass: bypass)
        }
        var manual = ProxyManual()
        if let h = stats.proxyHTTPHost, !h.isEmpty {
            manual.http = ProxyEndpoint(scheme: .http, host: h, port: stats.proxyHTTPPort ?? 0)
        }
        if let h = stats.proxyHTTPSHost, !h.isEmpty {
            manual.https = ProxyEndpoint(scheme: .https, host: h, port: stats.proxyHTTPSPort ?? 0)
        }
        guard let representative = manual.representative else { return nil }
        return ProxyIntent(engine: engine, mode: .manual(representative),
                           connectedAt: nil, manual: manual, bypass: bypass)
    }

    /// The traffic flows the extension has observed for this VPN (header-only
    /// accounting; empty when disconnected or the engine doesn't route through us).
    func fetchFlows(id: String) async -> [TrafficFlow] {
        guard let data = await sendMessageData("flows", to: id) else { return [] }
        return (try? JSONDecoder().decode([TrafficFlow].self, from: data)) ?? []
    }
}

/// Thread-safe "resume exactly once" guard for a continuation raced between a
/// callback and a timeout. `nonisolated` so `claim()` is callable from the
/// off-actor @Sendable completion/timeout closures (the app defaults to MainActor
/// isolation, which would otherwise make it main-actor-bound).
private nonisolated final class OnceResume: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
}
