// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  InterfaceTrafficView.swift
//  In/out throughput for EVERY interface at once — the physical link, each VPN
//  tunnel, Tailscale — on one shared time axis, with a legend that doubles as
//  show/hide toggles so a noisy interface can be taken out of the picture.
//
//  Each interface gets a stable colour (derived from its BSD name, so it doesn't
//  reshuffle when interfaces come and go), download solid and upload dashed. The
//  series are right-aligned in time rather than by sample id: an interface that
//  appeared later has fewer samples, and aligning on "seconds ago" keeps every
//  line honest about when it happened.
//
//  The axis SCROLLS rather than squashing. The old chart crammed however much
//  history it had into the pane width, so a longer series just got denser and less
//  legible. Now the store (`TrafficHistory`) keeps a fixed visible window — five
//  minutes — and you drag back through the last 24 hours: the last hour at 1 s
//  resolution, then 10 s, then 60 s. Coarse buckets carry their peak alongside their
//  average and the peak is drawn as a faint envelope, so a three-second burst three
//  hours ago still reads as a burst instead of being averaged into the floor.
//  Pinned at the trailing edge the chart follows live data; scroll back and it stops
//  following until you scroll home again or press the fixed "Now" button.
//
//  DEFAULT: only our own VPN tunnels are plotted — that's what this app is for, and
//  a graph opening with awdl0/bridge100/Tailscale in it is noise. Everything else is
//  one click away in the legend. Choices are stored as explicit show/hide OVERRIDES
//  rather than a plain visible-set, so the default keeps applying to interfaces that
//  appear later: a newly-connected VPN shows up on its own, a newly-joined Wi-Fi
//  doesn't, and neither overrides a decision the user actually made.
//

import SwiftUI
import Charts
import Accessibility

/// Settings keys: BSD names the user explicitly turned on / off in the graph.
let shownInterfacesDefaultsKey = "graph.shownInterfaces"
let hiddenInterfacesDefaultsKey = "graph.hiddenInterfaces"

struct InterfaceTrafficView: View {
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @AppStorage(shownInterfacesDefaultsKey) private var shownCSV = ""
    @AppStorage(hiddenInterfacesDefaultsKey) private var hiddenCSV = ""
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Only ever holds an SSID if the user opted into location; see LocationAuthority.
    @State private var location = LocationAuthority.shared

    /// Left edge of the visible window. Bound to the chart's scroll position, so it
    /// is written by the user's drag AND by us when we're following live data.
    @State private var scrollX = Date().addingTimeInterval(-InterfaceTrafficView.visibleSpan)
    /// Pinned at the trailing edge? Turns off the moment the user scrolls back, and
    /// on again as soon as they scroll (or press "Now") home.
    @State private var following = true

    /// How much time is on screen at once. Five minutes reads at a glance without
    /// the line turning into a hairball; everything older is a drag away.
    static let visibleSpan: TimeInterval = 300
    /// Extra data fetched either side of the window so a drag doesn't reveal blank.
    private static let margin: TimeInterval = 150
    /// Slack around the trailing edge that still counts as "live" — a drag lands a
    /// pixel or two off, and that shouldn't read as "the user went looking at history".
    private static let pinSlack: TimeInterval = 3

    private func names(_ csv: String) -> Set<String> {
        Set(csv.split(separator: ",").map(String.init).filter { !$0.isEmpty })
    }
    private var shownOverrides: Set<String> { names(shownCSV) }
    private var hiddenOverrides: Set<String> { names(hiddenCSV) }
    private var isCustomised: Bool { !shownOverrides.isEmpty || !hiddenOverrides.isEmpty }

    /// Is this one of OUR tunnels? Exact when we have live stats to match the
    /// in-tunnel address against; otherwise a tunnel that isn't Tailscale is
    /// *probably* ours (it could belong to another VPN app — hence "probably", and
    /// hence why this only picks the DEFAULT, which the user can override).
    private func isOurVPN(_ iface: NetInterface) -> Bool {
        guard iface.kind == .tunnel, !iface.isTailscale else { return false }
        let stats = reach?.latestStats.values ?? [:].values
        if stats.contains(where: { !$0.tunnelIPv4.isEmpty && iface.ipv4.contains($0.tunnelIPv4) }) { return true }
        return stats.allSatisfy { $0.tunnelIPv4.isEmpty }   // no stats to match on yet
    }

    private func isVisible(_ iface: NetInterface) -> Bool {
        if shownOverrides.contains(iface.name) { return true }
        if hiddenOverrides.contains(iface.name) { return false }
        return isOurVPN(iface)   // the default
    }

    /// In-use interfaces only — macOS keeps a pile of idle `utun`s with no address,
    /// and graphing those is pure noise. Ordered so the interesting ones lead:
    /// tunnels first, then whatever carries the default route, then the rest.
    private var interfaces: [NetInterface] {
        guard let topo else { return [] }
        let t = topo.topology
        return t.interfaces.filter(\.inUse).sorted { a, b in
            func rank(_ i: NetInterface) -> Int {
                if i.kind == .tunnel { return 0 }
                if t.carriesDefault(i.name) { return 1 }
                return 2
            }
            let (ra, rb) = (rank(a), rank(b))
            return ra == rb ? a.name < b.name : ra < rb
        }
    }

    private var visible: [NetInterface] { interfaces.filter(isVisible) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Traffic").font(.headline)
                Spacer()
                if isCustomised {
                    Button("VPNs Only") { shownCSV = ""; hiddenCSV = "" }
                        .buttonStyle(.link).controlSize(.small)
                        .help("Back to the default: plot only the connected VPN")
                }
            }

            if interfaces.isEmpty {
                Text("No active interfaces.").font(.callout).foregroundStyle(.secondary)
            } else {
                // Toggles ABOVE the chart: they're the controls for what you're about to
                // read, so they belong before it, not as a footnote after it.
                legend
                chart
                if visible.isEmpty {
                    Text("Nothing plotted \u{2014} switch on a connection above.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        // Interface rates come from the routing/link poller; it's refcounted, so
        // starting it here is safe alongside the railroad.
        .onAppear { topo?.startWatching() }
        .onDisappear { topo?.stopWatching() }
    }

    // MARK: Chart

    /// One interface's slice of the store, already narrowed to what's on (or just
    /// off) screen — so scrolling back an hour transparently switches to the coarser
    /// tier instead of loading 24 hours of 1 s samples.
    private struct Series: Identifiable {
        let id: String
        let color: Color
        let buckets: [TrafficHistory.Bucket]
    }

    /// Newest sample time across the plotted interfaces. The chart follows THIS,
    /// not a clock of its own — the app-wide poller is the only ticker (nil until
    /// the first sample, which also keeps `body` from chasing `Date()`).
    private var newestTime: Date? { topo?.newestSampleTime(among: visible.map(\.name)) }
    /// Right-hand end of the axis: live data if we have any, otherwise the window
    /// we're already showing (stable, so an empty graph doesn't re-render forever).
    private var anchor: Date { newestTime ?? scrollX.addingTimeInterval(Self.visibleSpan) }
    /// Trailing scroll position — the left edge that puts "now" at the right edge.
    private var trailingEdge: Date { anchor.addingTimeInterval(-Self.visibleSpan) }

    /// The full scrollable extent: everything the store still holds, but never
    /// narrower than one screenful or there'd be nothing to scroll.
    private var dataRange: ClosedRange<Date> {
        let oldest = visible.compactMap { topo?.history(for: $0.name)?.oldestTime }.min()
        let lower = min(oldest ?? trailingEdge, trailingEdge)
        return lower...anchor
    }

    private var plotted: [Series] {
        let lower = scrollX.addingTimeInterval(-Self.margin)
        let upper = scrollX.addingTimeInterval(Self.visibleSpan + Self.margin)
        guard lower < upper else { return [] }
        return visible.compactMap { iface in
            guard let history = topo?.history(for: iface.name) else { return nil }
            return Series(id: iface.name, color: color(for: iface.name),
                          buckets: history.samples(in: lower...upper))
        }
    }

    /// Y ceiling from what's actually on screen, so scrolling into a quiet stretch
    /// doesn't leave the lines pinned to the floor by a spike hours away.
    private func visiblePeak(_ series: [Series]) -> Double {
        let lo = scrollX, hi = scrollX.addingTimeInterval(Self.visibleSpan)
        let peak = series.flatMap(\.buckets)
            .filter { $0.end > lo && $0.start < hi }
            .map(\.peak).max() ?? 0
        return max(1_024, peak)
    }

    private var chart: some View {
        let series = plotted
        return Chart {
            ForEach(series) { s in
                ForEach(s.buckets) { b in
                    // Coarse buckets carry a peak that their average hides. Draw it
                    // faintly behind the average so old bursts stay visible; at 1 s
                    // resolution peak IS the sample, so it's skipped entirely.
                    if b.interval > 1 {
                        LineMark(x: .value("Time", b.mid), y: .value("Rate", b.maxIn),
                                 series: .value("series", "\(s.id)·in·peak"))
                            .foregroundStyle(s.color.opacity(0.3))
                            .interpolationMethod(.monotone)
                        LineMark(x: .value("Time", b.mid), y: .value("Rate", b.maxOut),
                                 series: .value("series", "\(s.id)·out·peak"))
                            .foregroundStyle(s.color.opacity(0.3))
                            .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                            .interpolationMethod(.monotone)
                    }
                    LineMark(x: .value("Time", b.mid), y: .value("Rate", b.avgIn),
                             series: .value("series", "\(s.id)·in"))
                        .foregroundStyle(s.color)
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("Time", b.mid), y: .value("Rate", b.avgOut),
                             series: .value("series", "\(s.id)·out"))
                        .foregroundStyle(s.color)
                        .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                        .interpolationMethod(.monotone)
                }
            }
        }
        .chartYScale(domain: 0...visiblePeak(series))
        .chartXScale(domain: dataRange)
        .chartScrollableAxes(.horizontal)
        .chartXVisibleDomain(length: Self.visibleSpan)
        .chartScrollPosition(x: $scrollX)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 4)) { value in
                AxisGridLine()
                if let d = value.as(Date.self) {
                    AxisValueLabel { Text(d, format: .dateTime.hour().minute()).font(.caption2) }
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                AxisGridLine()
                if let v = value.as(Double.self) { AxisValueLabel { Text(Fmt.rate(v)).font(.caption2) } }
            }
        }
        .chartLegend(.hidden)   // the legend below is interactive, so use that one
        .frame(height: 150)
        // Fixed home, top-right of the plot: the button never moves and never
        // reflows anything around it — it only fades, so the chips below and the
        // axis stay exactly where they were (spatial memory).
        .overlay(alignment: .topTrailing) { nowButton }
        .accessibilityLabel("Throughput per network interface, scrollable in time")
        // The audio graph mirrors exactly what's plotted: the visible window
        // of every shown interface, one download + one upload series each,
        // under the same names the legend chips use.
        .accessibilityChartDescriptor(InterfaceTrafficChartDescriptor(
            series: series.map { s in
                (name: visible.first { $0.name == s.id }.map(chipLabel) ?? s.id,
                 buckets: s.buckets)
            },
            window: scrollX...scrollX.addingTimeInterval(Self.visibleSpan),
            peak: visiblePeak(series)))
        .onAppear { if following { scrollX = trailingEdge } }
        .onChange(of: newestTime) { _, _ in
            guard following else { return }
            scrollX = trailingEdge           // keep the live edge pinned
        }
        .onChange(of: scrollX) { _, new in
            // Only the trailing edge counts as live; anything further back means the
            // user went looking at history, so stop dragging the view out from under them.
            following = new >= trailingEdge.addingTimeInterval(-Self.pinSlack)
        }
    }

    /// Re-pins the chart to live data. Always present at its fixed home so it can't
    /// shift the layout; invisible and inert while we're already following.
    private var nowButton: some View {
        Button {
            following = true
            scrollX = trailingEdge
        } label: {
            Label("Now", systemImage: "arrow.right.to.line").font(.caption)
        }
        .buttonStyle(.glass)
        .controlSize(.small)
        .help("Jump back to live traffic")
        .opacity(following ? 0 : 1)
        .disabled(following)
        .allowsHitTesting(!following)
        .accessibilityHidden(following)
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.18), value: following)
        .padding(6)
    }

    // MARK: The toggles (a row of glass chips above the chart)

    /// One chip per connection, tinted with that series' colour in the chart — so
    /// matching a line to its control is a colour match, not a legend lookup.
    ///
    /// A named Wi-Fi network is used when we're allowed to know it (see
    /// LocationAuthority); otherwise the interface's own display name, which is the
    /// honest fallback rather than inventing a friendly label.
    private var legend: some View {
        GlassEffectContainer(spacing: 14) {
            // Wraps rather than clipping: this pane is narrow and there can be several
            // interfaces, so a fixed HStack would push chips off the edge.
            FlowRow(spacing: 6) {
                ForEach(interfaces) { iface in
                    chip(for: iface)
                }
            }
        }
    }

    @ViewBuilder private func chip(for iface: NetInterface) -> some View {
        let shown = isVisible(iface)
        let tint = color(for: iface.name)
        // A real bi-state control, not a styled button. Two independent signals, because
        // one wasn't enough: the toggle's own on/off appearance, AND a swatch filled with
        // the EXACT colour this series is drawn in. Relying on a button's glass tint gave
        // neither — the tint was too subtle to match against a line, and a button has no
        // resting "on" state to read.
        Toggle(isOn: Binding(get: { shown }, set: { _ in toggle(iface) })) {
            HStack(spacing: 6) {
                Circle()
                    .fill(shown ? AnyShapeStyle(tint) : AnyShapeStyle(.clear))
                    .overlay(Circle().strokeBorder(tint, lineWidth: 1.5))
                    .frame(width: 9, height: 9)
                Text(chipLabel(iface))
                    .font(.caption)
                    .lineLimit(1)
                    .foregroundStyle(shown ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
            }
        }
        .toggleStyle(.button)
        .buttonStyle(.glass)
        .controlSize(.small)
        .help(shown ? "Hide \(chipLabel(iface)) from the graph"
                    : "Show \(chipLabel(iface)) in the graph")
        .accessibilityLabel(chipLabel(iface))
        .accessibilityValue(shown ? "plotted" : "hidden")
    }

    /// VPN name for our own tunnels, the Wi-Fi network's name when we may read it,
    /// otherwise the interface's display name.
    private func chipLabel(_ iface: NetInterface) -> String {
        if iface.kind == .wifi, let ssid = location.ssid, !ssid.isEmpty { return ssid }
        return iface.friendlyName
    }

    /// Record an explicit override, and clear the opposite one so the two sets can
    /// never disagree about the same interface.
    private func toggle(_ iface: NetInterface) {
        var shown = shownOverrides, hiddenSet = hiddenOverrides
        let name = iface.name
        if isVisible(iface) {
            shown.remove(name)
            // Only needs recording as hidden if the default would have shown it.
            if isOurVPN(iface) { hiddenSet.insert(name) }
        } else {
            hiddenSet.remove(name)
            if !isOurVPN(iface) { shown.insert(name) }
        }
        shownCSV = shown.sorted().joined(separator: ",")
        hiddenCSV = hiddenSet.sorted().joined(separator: ",")
    }

    /// Stable per-interface colour: hash the BSD name so en0 keeps its colour when a
    /// tunnel appears or disappears. Avoids blue/green, which mean download/upload
    /// everywhere else in the app.
    private func color(for name: String) -> Color {
        let palette: [Color] = [.purple, .orange, .teal, .pink, .indigo, .brown, .mint, .cyan, .yellow, .red]
        var hash: UInt64 = 5381
        for byte in name.utf8 { hash = (hash << 5) &+ hash &+ UInt64(byte) }
        return palette[Int(hash % UInt64(palette.count))]
    }
}

/// The audio-graph description of the per-interface chart: for each plotted
/// interface, a download and an upload series over the visible five-minute
/// window, axes in time-ago and human byte rates. Peaks aren't separate
/// series — coarse buckets' peak envelope is a drawing nicety; the averages
/// are the data. nonisolated because AXChartDescriptorRepresentable is a
/// nonisolated protocol — pure data-to-description work.
nonisolated private struct InterfaceTrafficChartDescriptor: AXChartDescriptorRepresentable {
    let series: [(name: String, buckets: [TrafficHistory.Bucket])]
    let window: ClosedRange<Date>
    let peak: Double

    private func axes() -> (x: AXNumericDataAxisDescriptor, y: AXNumericDataAxisDescriptor) {
        let span = window.upperBound.timeIntervalSince(window.lowerBound)
        let x = AXNumericDataAxisDescriptor(
            title: "Time",
            range: 0...max(1, span),
            gridlinePositions: []) { value in
                let ago = span - value
                if ago < 1 { return "now" }
                if ago < 120 { return "\(Int(ago)) seconds ago" }
                return "\(Int(ago / 60)) minutes ago"
            }
        let y = AXNumericDataAxisDescriptor(
            title: "Throughput",
            range: 0...max(1_024, peak),
            gridlinePositions: []) { Fmt.rate($0) }
        return (x, y)
    }

    private func dataSeries() -> [AXDataSeriesDescriptor] {
        series.flatMap { s -> [AXDataSeriesDescriptor] in
            // Only the window's own buckets: the ±margin fetched so drags
            // don't reveal blank would otherwise put points off the axis.
            let visible = s.buckets.filter {
                $0.end > window.lowerBound && $0.start < window.upperBound
            }
            func points(_ value: (TrafficHistory.Bucket) -> Double) -> [AXDataPoint] {
                visible.map {
                    AXDataPoint(x: max(0, $0.mid.timeIntervalSince(window.lowerBound)),
                                y: value($0))
                }
            }
            return [AXDataSeriesDescriptor(name: "\(s.name) download", isContinuous: true,
                                           dataPoints: points(\.avgIn)),
                    AXDataSeriesDescriptor(name: "\(s.name) upload", isContinuous: true,
                                           dataPoints: points(\.avgOut))]
        }
    }

    private var summary: String {
        guard !series.isEmpty else { return "Nothing is plotted." }
        let names = series.map(\.name).formatted(.list(type: .and))
        return "Five minutes of traffic for \(names); scroll back for up to 24 hours."
    }

    func makeChartDescriptor() -> AXChartDescriptor {
        let (x, y) = axes()
        return AXChartDescriptor(title: "Interface traffic", summary: summary,
                                 xAxis: x, yAxis: y, additionalAxes: [],
                                 series: dataSeries())
    }

    // Rebuilt on every SwiftUI update: this chart both ticks live and scrolls.
    func updateChartDescriptor(_ descriptor: AXChartDescriptor) {
        let (x, y) = axes()
        descriptor.xAxis = x
        descriptor.yAxis = y
        descriptor.series = dataSeries()
        descriptor.summary = summary
    }
}

/// A wrapping horizontal row.
///
/// Needed because the chips live in the narrow inspector column: an HStack would push the
/// last ones off the edge, and a ScrollView would hide them behind a gesture. SwiftUI has
/// no built-in wrapping stack, so this is the minimum Layout that does it.
struct FlowRow: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0, x + size.width > maxWidth {
                widest = max(widest, x - spacing)
                x = 0; y += rowHeight + spacing; rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        widest = max(widest, x - spacing)
        return CGSize(width: min(widest, maxWidth), height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize,
                       subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                x = bounds.minX; y += rowHeight + spacing; rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), anchor: .topLeading, proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
