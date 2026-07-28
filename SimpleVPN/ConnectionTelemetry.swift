// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionTelemetry.swift
//  M6 live throughput: polls the App-Group telemetry the extension publishes (~1 Hz),
//  derives up/down rates over a rolling window, and renders an iStat-style Swift Charts
//  graph. Also the connection-detail panel — uptime, reconnects, and a railroad diagram
//  of the path (client → VPN endpoint → internet) with pushed DNS.
//

import SwiftUI
import Charts

@MainActor
@Observable
final class ThroughputMonitor {
    struct Sample: Identifiable, Sendable {
        let id: Int
        let inRate: Double   // bytes/sec received
        let outRate: Double  // bytes/sec sent
    }

    private(set) var samples: [Sample] = []
    private(set) var latest: TunnelStats?

    var inRate: Double { samples.last?.inRate ?? 0 }
    var outRate: Double { samples.last?.outRate ?? 0 }
    /// Peak of either direction across the window — the chart's y-scale ceiling.
    var scaleMax: Double { max(1_024, samples.map { max($0.inRate, $0.outRate) }.max() ?? 0) }

    private var timer: Timer?
    private var previous: TunnelStats?
    private var seq = 0
    private let window = 60

    func start(profile: String) {
        stop()
        samples = []; previous = nil; latest = nil; seq = 0
        tick(profile: profile)
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick(profile: profile) }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func tick(profile: String) {
        guard let s = TunnelStatsStore.read(profile: profile) else { return }
        latest = s
        defer { previous = s }
        guard let prev = previous else { return }
        let dt = s.timestamp - prev.timestamp
        guard dt > 0.05 else { return }
        seq += 1
        samples.append(Sample(id: seq,
                              inRate: max(0, Double(s.bytesIn - prev.bytesIn) / dt),
                              outRate: max(0, Double(s.bytesOut - prev.bytesOut) / dt)))
        if samples.count > window { samples.removeFirst(samples.count - window) }
    }
}

enum Fmt {
    /// e.g. "1.2 MB/s". Binary units, matching transport byte counters.
    static func rate(_ bytesPerSec: Double) -> String {
        byteCount(bytesPerSec) + "/s"
    }
    static func byteCount(_ bytes: Double) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = max(0, bytes), i = 0
        while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
        return String(format: i == 0 ? "%.0f %@" : "%.1f %@", v, units[i])
    }
    static func duration(_ seconds: TimeInterval) -> String {
        let s = Int(seconds)
        let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60)
        return h > 0 ? String(format: "%d:%02d:%02d", h, m, sec) : String(format: "%d:%02d", m, sec)
    }
}

// MARK: - Throughput graph

struct ThroughputGraph: View {
    let samples: [ThroughputMonitor.Sample]
    let scaleMax: Double

    private let down = Color.blue
    private let up = Color.green

    var body: some View {
        Chart {
            ForEach(samples) { s in
                AreaMark(x: .value("t", s.id), y: .value("rate", s.inRate),
                         series: .value("dir", "Download"))
                    .foregroundStyle(down.opacity(0.18)).interpolationMethod(.monotone)
                LineMark(x: .value("t", s.id), y: .value("rate", s.inRate),
                         series: .value("dir", "Download"))
                    .foregroundStyle(down).interpolationMethod(.monotone)

                AreaMark(x: .value("t", s.id), y: .value("rate", s.outRate),
                         series: .value("dir", "Upload"))
                    .foregroundStyle(up.opacity(0.18)).interpolationMethod(.monotone)
                LineMark(x: .value("t", s.id), y: .value("rate", s.outRate),
                         series: .value("dir", "Upload"))
                    .foregroundStyle(up).interpolationMethod(.monotone)
            }
        }
        .chartYScale(domain: 0...scaleMax)
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                AxisGridLine()
                if let v = value.as(Double.self) { AxisValueLabel { Text(Fmt.rate(v)).font(.caption2) } }
            }
        }
        .chartLegend(.hidden)
        .frame(height: 160)
    }
}

/// Monospaced up/down readouts, à la iStat Menus.
struct ThroughputReadout: View {
    let inRate: Double
    let outRate: Double
    var body: some View {
        HStack(spacing: 20) {
            rate(symbol: "arrow.down", color: .blue, value: inRate)
            rate(symbol: "arrow.up", color: .green, value: outRate)
            Spacer()
        }
    }
    private func rate(symbol: String, color: Color, value: Double) -> some View {
        HStack(spacing: 6) {
            Image(systemName: symbol).foregroundStyle(color)
            Text(Fmt.rate(value)).font(.system(.title3, design: .rounded)).monospacedDigit().bold()
        }
    }
}

// MARK: - Connection info (uptime · reconnects · railroad)

struct ConnectionInfoPanel: View {
    let stats: TunnelStats?
    let clientLabel: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 24) {
                metric("Uptime", Fmt.duration(stats?.uptime ?? 0), "clock")
                metric("Reconnects", "\(stats?.reconnects ?? 0)", "arrow.triangle.2.circlepath")
                if let total = stats { metric("Transferred", Fmt.byteCount(Double(total.bytesIn + total.bytesOut)), "arrow.up.arrow.down") }
                Spacer()
            }
            RailroadDiagram(client: clientLabel,
                            endpoint: stats?.serverEndpoint ?? "",
                            tunnelIP: stats?.tunnelIPv4 ?? "",
                            proxies: stats?.proxies ?? [])
            if let dns = stats?.dnsServers, !dns.isEmpty {
                Label(dns.joined(separator: ", "), systemImage: "network")
                    .font(.caption).foregroundStyle(.secondary)
            }
            // Additional proxies beyond the one shown in the railroad node.
            if let proxies = stats?.proxies, proxies.count > 1 {
                Label(proxies.dropFirst().joined(separator: " · "), systemImage: "arrow.triangle.branch")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func metric(_ title: String, _ value: String, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: symbol).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.body, design: .rounded)).monospacedDigit().bold()
        }
    }
}

/// client → VPN endpoint → [proxy] → internet, with the tunnel IP annotated on the client.
struct RailroadDiagram: View {
    let client: String
    let endpoint: String
    let tunnelIP: String
    let proxies: [String]

    var body: some View {
        HStack(spacing: 0) {
            node(icon: "laptopcomputer", title: "This Mac", subtitle: tunnelIP.isEmpty ? client : tunnelIP)
            link
            node(icon: "lock.shield", title: "VPN", subtitle: endpoint.isEmpty ? "endpoint" : endpoint)
            link
            if let proxy = proxies.first {
                node(icon: "arrow.triangle.branch", title: "Proxy", subtitle: proxy)
                link
            }
            node(icon: "globe", title: "Internet", subtitle: "egress")
        }
        .padding(.vertical, 6)
    }

    private func node(icon: String, title: String, subtitle: String) -> some View {
        VStack(spacing: 3) {
            Image(systemName: icon).font(.title2).foregroundStyle(.tint)
            Text(title).font(.caption).bold()
            Text(subtitle).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .frame(maxWidth: .infinity)
    }

    private var link: some View {
        Image(systemName: "arrow.right").foregroundStyle(.secondary).font(.caption)
    }
}
