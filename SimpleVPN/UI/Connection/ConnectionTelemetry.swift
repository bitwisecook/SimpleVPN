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
import Accessibility

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

    /// Passive link-health judgement from the byte counters alone — no probe
    /// traffic. "Stalled" = we kept sending but nothing has come back for a
    /// while, the train-tunnel signature.
    enum LinkHealth: Equatable { case healthy, quiet, stalled(seconds: Int) }
    private(set) var linkHealth: LinkHealth = .healthy
    private var lastRxAdvance: Date?
    private var txSinceRx: Int64 = 0
    private static let stallThreshold: TimeInterval = 8

    var inRate: Double { samples.last?.inRate ?? 0 }
    var outRate: Double { samples.last?.outRate ?? 0 }
    /// Peak of either direction across the window — the chart's y-scale ceiling.
    var scaleMax: Double { max(1_024, samples.map { max($0.inRate, $0.outRate) }.max() ?? 0) }

    private var pollTask: Task<Void, Never>?
    private var previous: TunnelStats?
    private var seq = 0
    private let window = 60

    /// Poll the running tunnel at 1 Hz via the supplied fetcher (IPC — the only
    /// live channel out of the system-context extension).
    func start(profile: String, fetch: @escaping () async -> TunnelStats?) {
        stop()
        samples = []; previous = nil; latest = nil; seq = 0
        linkHealth = .healthy; lastRxAdvance = nil; txSinceRx = 0
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                if let s = await fetch() { self?.tick(with: s) }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stop() { pollTask?.cancel(); pollTask = nil }

    private func tick(with s: TunnelStats) {
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
        updateLinkHealth(current: s, previous: prev)
    }

    private func updateLinkHealth(current: TunnelStats, previous prev: TunnelStats) {
        let now = Date()
        if current.bytesIn > prev.bytesIn {
            lastRxAdvance = now
            txSinceRx = 0
            linkHealth = .healthy
            return
        }
        txSinceRx += max(0, current.bytesOut - prev.bytesOut)
        guard let lastRx = lastRxAdvance else { lastRxAdvance = now; return }
        let quietFor = now.timeIntervalSince(lastRx)
        if quietFor >= Self.stallThreshold {
            // Sending into the void → stalled. Nothing moving either way is just
            // an idle link — quiet, not broken.
            linkHealth = txSinceRx > 4_096 ? .stalled(seconds: Int(quietFor)) : .quiet
        }
    }
}

// nonisolated: pure arithmetic-and-string work, and the audio-graph chart
// descriptors below (a nonisolated protocol) format their axis values with it.
nonisolated enum Fmt {
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
    /// Compact mode for tight surfaces (menu-bar dropdown): no axes, clipped —
    /// axis labels must never spill over neighboring views.
    var compact = false

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
            if !compact {
                AxisMarks(position: .leading) { value in
                    AxisGridLine()
                    if let v = value.as(Double.self) { AxisValueLabel { Text(Fmt.rate(v)).font(.caption2) } }
                }
            }
        }
        .chartLegend(.hidden)
        .frame(height: compact ? 56 : 160)
        .clipped()
        // A real audio graph, not a labeled picture: VoiceOver's "describe
        // chart" / sonification reads both series with human axis units.
        .accessibilityLabel("Throughput graph")
        .accessibilityChartDescriptor(ThroughputChartDescriptor(samples: samples,
                                                                scaleMax: scaleMax))
    }
}

/// The audio-graph description of the throughput chart: download and upload as
/// two continuous series over the rolling window, axes in seconds-ago and
/// human byte rates, and a summary that answers "how fast, right now" first.
/// nonisolated because AXChartDescriptorRepresentable is a nonisolated
/// protocol — this is pure data-to-description work.
nonisolated private struct ThroughputChartDescriptor: AXChartDescriptorRepresentable {
    let samples: [ThroughputMonitor.Sample]
    let scaleMax: Double

    // Sample ids advance once per ~1 s poll, so the id axis IS a seconds axis;
    // values are described relative to the newest sample ("12 seconds ago").
    private func axes() -> (x: AXNumericDataAxisDescriptor, y: AXNumericDataAxisDescriptor) {
        let newest = samples.last?.id ?? 0
        let oldest = samples.first?.id ?? 0
        let x = AXNumericDataAxisDescriptor(
            title: "Time",
            range: Double(oldest)...Double(max(oldest + 1, newest)),
            gridlinePositions: []) { value in
                let ago = Double(newest) - value
                return ago < 1 ? "now" : "\(Int(ago)) seconds ago"
            }
        let y = AXNumericDataAxisDescriptor(
            title: "Throughput",
            range: 0...max(1_024, scaleMax),
            gridlinePositions: []) { Fmt.rate($0) }
        return (x, y)
    }

    private func series() -> [AXDataSeriesDescriptor] {
        [AXDataSeriesDescriptor(
            name: "Download", isContinuous: true,
            dataPoints: samples.map { AXDataPoint(x: Double($0.id), y: $0.inRate) }),
         AXDataSeriesDescriptor(
            name: "Upload", isContinuous: true,
            dataPoints: samples.map { AXDataPoint(x: Double($0.id), y: $0.outRate) })]
    }

    private var summary: String {
        guard let last = samples.last else { return "No traffic samples yet." }
        return "Downloading at \(Fmt.rate(last.inRate)) and uploading at "
            + "\(Fmt.rate(last.outRate)), over the last \(samples.count) seconds."
    }

    func makeChartDescriptor() -> AXChartDescriptor {
        let (x, y) = axes()
        return AXChartDescriptor(title: "Connection throughput", summary: summary,
                                 xAxis: x, yAxis: y, additionalAxes: [],
                                 series: series())
    }

    // Rebuilt on every SwiftUI update so the audio graph tracks the live data
    // the drawing tracks — the default no-op would leave it frozen at open.
    func updateChartDescriptor(_ descriptor: AXChartDescriptor) {
        let (x, y) = axes()
        descriptor.xAxis = x
        descriptor.yAxis = y
        descriptor.series = series()
        descriptor.summary = summary
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

// MARK: - Connection info (uptime · reconnects · railroad · details)

struct ConnectionInfoPanel: View {
    let stats: TunnelStats?
    let clientLabel: String
    let publicIP: PublicIPMonitor?
    var paused = false
    var bypassing = false

    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                metric("Uptime", Fmt.duration(stats?.uptime ?? 0), "clock")
                metric("Reconnects", "\(stats?.reconnects ?? 0)", "arrow.triangle.2.circlepath")
                if let total = stats { metric("Transferred", Fmt.byteCount(Double(total.bytesIn + total.bytesOut)), "arrow.up.arrow.down") }
                Spacer()
            }
            if let topo {
                RailroadView(topology: topo.topology,
                             ourTunnelIPv4: stats?.tunnelIPv4,
                             serverEndpoint: stats?.serverEndpoint ?? "",
                             paused: paused,
                             bypassing: bypassing)
                    .onAppear { topo.startWatching() }
                    .onDisappear { topo.stopWatching() }
            }
            if let proxies = stats?.proxies, !proxies.isEmpty {
                Label(proxies.joined(separator: " · "), systemImage: "arrow.triangle.branch")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ConnectionDetailsPanel(stats: stats, publicIP: publicIP)
        }
    }

    /// Boxed, so a metric reads as one unit with its number — bare stacked text left the
    /// label and value looking like two unrelated lines. Matches the rounded-rect
    /// treatment the address rows already use.
    private func metric(_ title: String, _ value: String, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: symbol).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.body, design: .rounded)).monospacedDigit().bold()
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .frame(minWidth: 92, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Connection details (dual-stack, every value copyable)

/// The precise network picture: IPv4 and IPv6 as first-class parallel columns,
/// server transport, DNS, and where this Mac appears from — every address a
/// CopyableValue.
struct ConnectionDetailsPanel: View {
    let stats: TunnelStats?
    let publicIP: PublicIPMonitor?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            GroupBox("Connection") {
                VStack(alignment: .leading, spacing: 6) {
                    if let server = serverLine {
                        row("Server") { CopyableValue(value: server) }
                    }
                    if let ip = stats?.serverIP, !ip.isEmpty {
                        row("Server address") { CopyableValue(value: ip) }
                    }
                    if let mtu = stats?.mtu {
                        row("MTU") { Text("\(mtu)").font(.callout.monospaced()) }
                    }
                    if let dns = stats?.dnsServers, !dns.isEmpty {
                        row("DNS") {
                            VStack(alignment: .trailing, spacing: 2) {
                                ForEach(dns, id: \.self) { CopyableValue(value: $0) }
                            }
                        }
                    }
                    if let domains = stats?.searchDomains, !domains.isEmpty {
                        row("Search domains") { Text(domains.joined(separator: ", ")).font(.callout) }
                    }
                    if let proxies = stats?.proxies, !proxies.isEmpty {
                        row("Proxies") {
                            VStack(alignment: .trailing, spacing: 2) {
                                ForEach(proxies, id: \.self) { CopyableValue(value: $0) }
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack(alignment: .top, spacing: 10) {
                familyBox(title: "IPv4",
                          tunnel: stats?.tunnelIPv4,
                          gateway: stats?.gateway4,
                          publicAddress: publicIP?.publicIPv4)
                familyBox(title: "IPv6",
                          tunnel: stats?.tunnelIPv6,
                          gateway: stats?.gateway6,
                          publicAddress: publicIP?.publicIPv6)
            }

            if let publicIP, let country = publicIP.countryName {
                HStack(spacing: 6) {
                    Text(CountryCentroids.flag(for: publicIP.countryCode ?? ""))
                    Text("Your connection appears from \(country).")
                        .font(.callout).foregroundStyle(.secondary)
                    if publicIP.isRefreshing {
                        ProgressView().controlSize(.mini)
                    } else {
                        Button {
                            Task { await publicIP.refresh() }
                        } label: {
                            Image(systemName: "arrow.clockwise").frame(width: 22, height: 22).contentShape(Rectangle())
                        }
                            .buttonStyle(.borderless)
                            .help("Check again")
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private var serverLine: String? {
        guard let s = stats, !s.serverEndpoint.isEmpty else { return nil }
        var line = s.serverEndpoint
        if let port = s.serverPort, !port.isEmpty { line += ":\(port)" }
        if let proto = s.serverProto, !proto.isEmpty { line += " · \(proto.uppercased())" }
        return line
    }

    private func familyBox(title: String, tunnel: String?, gateway: String?, publicAddress: String?) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 6) {
                row("Tunnel") { valueOrDash(tunnel) }
                row("Gateway") { valueOrDash(gateway) }
                row("Public") { valueOrDash(publicAddress) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func valueOrDash(_ value: String?) -> some View {
        if let value, !value.isEmpty {
            CopyableValue(value: value)
        } else {
            Text("—").font(.callout).foregroundStyle(.secondary)
                .accessibilityLabel("none")
        }
    }

    private func row(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        LabeledContent {
            value()
        } label: {
            Text(label).font(.callout).foregroundStyle(.secondary)
        }
    }
}

