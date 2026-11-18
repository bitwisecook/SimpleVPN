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
    /// Status indicators care about transitions, not the increasing stall age.
    private(set) var stalledProfiles: Set<String> = []

    /// Latest full stats per connected profile — the world map reads each VPN's
    /// server endpoint from here to plot the hops (home → VPN(s) → egress).
    private(set) var latestStats: [String: TunnelStats] = [:]

    struct TunnelAddresses: Equatable {
        let ipv4: String?
        let ipv6: String?
    }

    /// Address rows depend on these values instead of the traffic samples.
    private(set) var tunnelAddresses: [String: TunnelAddresses] = [:]

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
    @ObservationIgnored private var samplers: [String: Task<Void, Never>] = [:]
    var isSampling: Bool { !samplers.isEmpty }
    deinit { for sampler in samplers.values { sampler.cancel() } }
    private static let stallThreshold: TimeInterval = 8
    private static let interval: Duration = .seconds(1)   // 1 Hz: smooth enough to back the graphs

    /// Invoked on connection changes. A disconnected Mac has no sampler or timer.
    func setConnectedProfiles(_ ids: Set<String>, fetch: @escaping @MainActor (String) async -> TunnelStats?) {
        let connectedIDs = Set(samplers.keys)
        guard connectedIDs != ids else { return }
        for id in connectedIDs.subtracting(ids) {
            samplers.removeValue(forKey: id)?.cancel()
            health[id] = nil
            stalledProfiles.remove(id)
            track[id] = nil
            latestStats[id] = nil
            tunnelAddresses[id] = nil
            history[id] = nil
        }
        // Each provider has its own IPC timeout. A slow provider must not
        // postpone another VPN's health updates or restart its in-flight read.
        for id in ids.subtracting(connectedIDs) {
            samplers[id] = Task { [weak self] in
                while !Task.isCancelled {
                    let sample = await fetch(id)
                    guard !Task.isCancelled else { return }
                    if let sample { self?.record(sample, for: id) }
                    do { try await Task.sleep(for: Self.interval, tolerance: .milliseconds(100)) }
                    catch { return }
                }
            }
        }
    }

    private func record(_ sample: TunnelStats, for id: String) {
        latestStats[id] = sample
        let addresses = TunnelAddresses(ipv4: sample.tunnelIPv4, ipv6: sample.tunnelIPv6)
        if tunnelAddresses[id] != addresses { tunnelAddresses[id] = addresses }
        ingest(id: id, sample)
    }

    func health(for id: String) -> Health? { health[id] }
    func isStalled(_ id: String) -> Bool { stalledProfiles.contains(id) }

    private func ingest(id: String, _ s: TunnelStats) {
        var t = track[id] ?? Track()
        defer { track[id] = t }
        guard let prev = t.prev else {
            t.prev = s; t.lastRx = Date(); publishHealth(.healthy, for: id); return
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
            t.lastRx = Date(); t.txSinceRx = 0; publishHealth(.healthy, for: id); return
        }
        t.txSinceRx += max(0, s.bytesOut - prev.bytesOut)   // still sending?
        let lastRx = t.lastRx ?? Date()
        if t.lastRx == nil { t.lastRx = lastRx }
        let quietFor = Date().timeIntervalSince(lastRx)
        if quietFor >= Self.stallThreshold {
            // Sending into the void → stalled; nothing either way → just idle.
            publishHealth(t.txSinceRx > 4_096 ? .stalled(seconds: Int(quietFor)) : .quiet, for: id)
        }
    }

    private func publishHealth(_ value: Health, for id: String) {
        if health[id] != value { health[id] = value }
        if case .stalled = value {
            if !stalledProfiles.contains(id) { stalledProfiles.insert(id) }
        } else if stalledProfiles.contains(id) {
            stalledProfiles.remove(id)
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
