// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ReachabilityMonitor.swift
//  One app-wide, always-on judgement of whether each connected tunnel is actually
//  passing traffic — so the sidebar rows, the connection header and the menu bar
//  can all show the same live reachability without each opening its own poller
//  (the per-view ThroughputMonitor only runs while a detail view is on screen).
//
//  Passive, like ThroughputMonitor: it reads the byte counters the extension
//  already publishes and classifies healthy / quiet / stalled — no probe traffic.
//

import Foundation

@MainActor
@Observable
final class ReachabilityMonitor {
    typealias Health = ThroughputMonitor.LinkHealth

    /// Live health per connected profile id. Absent ⇒ not connected / not yet sampled.
    private(set) var health: [String: Health] = [:]

    /// Latest full stats per connected profile — the world map reads each VPN's
    /// server endpoint from here to plot the hops (home → VPN(s) → egress).
    private(set) var latestStats: [String: TunnelStats] = [:]

    /// Shared throughput history per profile — the single backing for EVERY graph
    /// (main window, inspector, menu-bar sparkline) so the series persists across
    /// window/menu opens and never restarts empty. One poller feeds them all.
    ///
    /// Tiered (`TrafficHistory`): 1 s resolution for the last hour, then 10 s, then
    /// 60 s out to 24 h, at a fixed ~346 KB per connected profile. The accessors
    /// below are the "last minute" view the readouts and sparklines have always
    /// used; surfaces that scroll through history query `history(for:)` directly.
    private(set) var history: [String: TrafficHistory] = [:]
    /// Samples in the flat rolling window the compact surfaces expect.
    private let window = 60

    func history(for id: String) -> TrafficHistory? { history[id] }
    func samples(for id: String) -> [ThroughputMonitor.Sample] {
        (history[id]?.recent(window) ?? []).map(Self.legacySample)
    }
    func inRate(for id: String) -> Double { history[id]?.latest?.avgIn ?? 0 }
    func outRate(for id: String) -> Double { history[id]?.latest?.avgOut ?? 0 }
    func scaleMax(for id: String) -> Double {
        max(1_024, (history[id]?.recent(window) ?? []).map(\.peak).max() ?? 0)
    }
    func stats(for id: String) -> TunnelStats? { latestStats[id] }

    /// Bridge a tiered bucket to the flat `Sample` the older graphs take. The id is
    /// the bucket's second-since-reference, which keeps it monotonic and stable
    /// across refreshes (the menu-bar icon caches on `samples.last?.id`).
    private static func legacySample(_ b: TrafficHistory.Bucket) -> ThroughputMonitor.Sample {
        .init(id: Int(b.start.timeIntervalSinceReferenceDate), inRate: b.avgIn, outRate: b.avgOut)
    }

    private struct Track { var prev: TunnelStats?; var lastRx: Date?; var txSinceRx: Int64 = 0 }
    private var track: [String: Track] = [:]
    private var task: Task<Void, Never>?
    private static let stallThreshold: TimeInterval = 8
    private static let interval: Duration = .seconds(1)   // 1 Hz: smooth enough to back the graphs

    /// Idempotent: safe to call from several always-alive surfaces (menu-bar label,
    /// main window). The first caller wins; later calls are no-ops until stopped.
    func start(connectedIDs: @escaping () -> [String],
               fetch: @escaping (String) async -> TunnelStats?) {
        guard task == nil else { return }
        task = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let ids = Set(connectedIDs())
                for k in self.health.keys where !ids.contains(k) { self.health[k] = nil }
                for k in self.track.keys where !ids.contains(k) { self.track[k] = nil }
                for k in self.latestStats.keys where !ids.contains(k) { self.latestStats[k] = nil }
                for k in self.history.keys where !ids.contains(k) { self.history[k] = nil }
                for id in ids {
                    if let s = await fetch(id) { self.latestStats[id] = s; self.ingest(id: id, s) }
                }
                try? await Task.sleep(for: Self.interval)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    func health(for id: String) -> Health? { health[id] }
    func isStalled(_ id: String) -> Bool { if case .stalled = health[id] { return true }; return false }

    /// The most severe health across all connected tunnels (stalled > quiet >
    /// healthy) — for a single at-a-glance menu-bar indicator.
    var worst: Health? {
        health.values.max { severity($0) < severity($1) }
    }
    private func severity(_ h: Health) -> Int {
        switch h { case .stalled: 2; case .quiet: 1; case .healthy: 0 }
    }

    private func ingest(id: String, _ s: TunnelStats) {
        var t = track[id] ?? Track()
        defer { track[id] = t }
        guard let prev = t.prev else {
            t.prev = s; t.lastRx = Date(); health[id] = .healthy; return
        }
        // Throughput sample for the shared graph backing.
        let dt = s.timestamp - prev.timestamp
        if dt > 0.05 {
            history[id, default: TrafficHistory()]
                .record(inRate: Double(s.bytesIn - prev.bytesIn) / dt,
                        outRate: Double(s.bytesOut - prev.bytesOut) / dt)
        }
        t.prev = s
        if s.bytesIn > prev.bytesIn {                       // something came back → healthy
            t.lastRx = Date(); t.txSinceRx = 0; health[id] = .healthy; return
        }
        t.txSinceRx += max(0, s.bytesOut - prev.bytesOut)   // still sending?
        let lastRx = t.lastRx ?? Date()
        if t.lastRx == nil { t.lastRx = lastRx }
        let quietFor = Date().timeIntervalSince(lastRx)
        if quietFor >= Self.stallThreshold {
            // Sending into the void → stalled; nothing either way → just idle.
            health[id] = t.txSinceRx > 4_096 ? .stalled(seconds: Int(quietFor)) : .quiet
        }
    }
}

extension ThroughputMonitor.LinkHealth {
    /// Short label + dot state for a reachability indicator.
    var reachabilityLabel: String {
        switch self {
        case .healthy: "Reachable"
        case .quiet: "Idle"
        case .stalled: "No response"
        }
    }
    var reachabilityDot: DotState {
        switch self {
        case .healthy: .connected
        case .quiet: .paused        // steady half-dim — idle isn't a problem
        case .stalled: .degraded
        }
    }
    var reachabilitySymbol: String {
        switch self {
        case .healthy: "checkmark.circle.fill"
        case .quiet: "pause.circle"
        case .stalled: "exclamationmark.triangle.fill"
        }
    }
}
