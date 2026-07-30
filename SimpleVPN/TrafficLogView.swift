// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficLogView.swift
//  Per-VPN traffic log: the flows the extension observed (remote endpoint, proto,
//  bytes each way, recency), filterable, live-updating while open. Select a row to
//  generate a divert rule that routes that destination around the VPN. Shows the
//  active divert rules with a way to remove them. Diversion is address-based (the
//  network layer routes by destination IP), so port/proto are shown for context.
//

import SwiftUI

struct TrafficLogView: View {
    @Bindable var vpn: VPNController
    let profileID: String
    let vpnName: String
    @Environment(\.dismiss) private var dismiss

    @State private var flows: [TrafficFlow] = []
    // Read live from the observable cache in body (not a @State snapshot) so a
    // rule added/removed elsewhere — another editor, syncIncludes, a Doctor fix —
    // is reflected here immediately.
    private var rules: [RoutingRule] { vpn.routingRules(for: profileID) }
    @State private var filter = ""
    @State private var note: String?
    /// Per-flow rolling throughput history, derived by diffing successive polls
    /// (the extension reports cumulative byte counters, not rates).
    @State private var history: [String: FlowHistory] = [:]

    private struct FlowHistory: Equatable {
        var lastTotal: Int64
        var lastAt: Date
        var rates: [Double] = []   // bytes/sec, most recent last
    }

    /// A flow is "active" if it moved bytes very recently; header-only accounting
    /// can't see a TCP FIN, so idle (not truly closed) is the honest label.
    private static func isActive(_ f: TrafficFlow) -> Bool { f.ageLast < 6 }

    private var filtered: [TrafficFlow] {
        let f = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let base = f.isEmpty ? flows
            : flows.filter { $0.address.lowercased().contains(f) || "\($0.port)".contains(f) || $0.protoName.lowercased().contains(f) }
        return base.sorted { $0.bytesTotal > $1.bytesTotal }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if !rules.isEmpty { divertedBar }
                table
            }
            .navigationTitle("Traffic · \(vpnName)")
            .searchable(text: $filter, prompt: "Filter by address, port or protocol")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .frame(minWidth: 620, minHeight: 460)
        }
        .task { await poll() }
        .alert("Divert Rule", isPresented: Binding(get: { note != nil }, set: { if !$0 { note = nil } })) {
            Button("OK") { note = nil }
        } message: { Text(note ?? "") }
    }

    private var divertedBar: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Routed around \(vpnName)").font(.caption).foregroundStyle(.secondary)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(rules) { rule in
                        HStack(spacing: 4) {
                            Image(systemName: ruleSymbol(rule))
                            Text(ruleLabel(rule)).font(.caption.monospaced())
                            Button {
                                Task { await vpn.removeRoutingRule(id: rule.id, for: profileID) }
                            } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.plain).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(.orange.opacity(0.15), in: Capsule())
                    }
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.3))
    }

    private var table: some View {
        Group {
            if flows.isEmpty {
                ContentUnavailableView("No Traffic Yet", systemImage: "waveform.path.ecg",
                    description: Text(vpn.profiles.first { $0.id == profileID }.map { UI.isActive($0.status) } == true
                        ? "Traffic through \(vpnName) will appear here as it flows."
                        : "Connect \(vpnName) to see the traffic passing through it."))
            } else {
                List {
                    Section {
                        ForEach(filtered) { flow in row(flow) }
                    } header: {
                        HStack(spacing: 0) {
                            Text("Connection").frame(maxWidth: .infinity, alignment: .leading)
                            Text("Proto").frame(width: 48, alignment: .leading)
                            Text("Throughput").frame(width: 96, alignment: .center)
                            Text("Total").frame(width: 74, alignment: .trailing)
                            Text("Open").frame(width: 56, alignment: .trailing)
                            Spacer().frame(width: 34)
                        }.font(.caption).foregroundStyle(.secondary)
                    } footer: {
                        Text("A green dot is an active connection; grey is idle. Throughput is live download+upload; Total and Open are for the life of the connection.")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    private func row(_ flow: TrafficFlow) -> some View {
        let active = Self.isActive(flow)
        let rates = history[flow.id]?.rates ?? []
        let rateNow = rates.last ?? 0
        return HStack(spacing: 0) {
            HStack(spacing: 6) {
                Circle()
                    .fill(active ? Color.green : Color.secondary.opacity(0.5))
                    .frame(width: 7, height: 7)
                    .help(active ? "Active" : "Idle")
                VStack(alignment: .leading, spacing: 1) {
                    Text(flow.endpoint).font(.callout.monospaced()).lineLimit(1)
                    Text("↓ \(Fmt.byteCount(Double(flow.bytesIn)))  ↑ \(Fmt.byteCount(Double(flow.bytesOut)))")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            Text(flow.protoName).font(.caption).foregroundStyle(.secondary).frame(width: 48, alignment: .leading)
            VStack(spacing: 1) {
                Sparkline(values: rates, active: active).frame(height: 22)
                Text(rateNow > 0 ? "\(Fmt.byteCount(rateNow))/s" : "—")
                    .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
            }.frame(width: 96)
            Text(Fmt.byteCount(Double(flow.bytesTotal))).font(.caption.monospacedDigit()).frame(width: 74, alignment: .trailing)
            Text(Self.durationText(flow.ageFirst)).font(.caption.monospacedDigit())
                .foregroundStyle(.secondary).frame(width: 56, alignment: .trailing)
            Menu {
                if ManagedPolicy.allowDivertOutside {
                    Button {
                        Task { await divert(flow, to: .outside) }
                    } label: { Label("Send outside \(vpnName)", systemImage: "arrow.uturn.right") }
                }
                let others = vpn.profiles.filter { $0.id != profileID }
                if ManagedPolicy.allowDivertOverVPN && !others.isEmpty {
                    Divider()
                    Section("Route over") {
                        ForEach(others) { p in
                            Button {
                                Task { await divert(flow, to: .overVPN(profileID: p.id)) }
                            } label: { Label(p.name, systemImage: "arrow.triangle.branch") }
                        }
                    }
                }
                if !ManagedPolicy.allowDivertOutside && !ManagedPolicy.allowDivertOverVPN {
                    Label("Diverting traffic is managed by your organization", systemImage: "lock.fill")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .frame(width: 28)
        }
        .padding(.vertical, 1)
    }

    private func divert(_ flow: TrafficFlow, to action: RoutingRule.Action) async {
        let dest = flow.address + (flow.family == 6 ? "/128" : "/32")
        let rule = RoutingRule(destination: dest, port: flow.port > 0 ? flow.port : nil,
                               proto: flow.proto, action: action, note: flow.address)
        await vpn.addRoutingRule(rule, for: profileID)
        switch action {
        case .outside:
            note = "\(flow.address) will now bypass \(vpnName) and use your normal connection."
        case .overVPN(let target):
            let name = vpn.profiles.first { $0.id == target }?.name ?? "the other VPN"
            note = "\(flow.address) will now be routed over \(name) instead of \(vpnName)."
        }
        note = (note ?? "") + " The affected VPNs reconnect to apply the change."
    }

    private func ruleSymbol(_ rule: RoutingRule) -> String {
        if case .overVPN = rule.action { return "arrow.triangle.branch" }
        return "arrow.uturn.right"
    }
    private func ruleLabel(_ rule: RoutingRule) -> String {
        if case .overVPN(let target) = rule.action {
            let name = vpn.profiles.first { $0.id == target }?.name ?? "VPN"
            return "\(rule.destination) → \(name)"
        }
        return rule.destination
    }

    /// Poll the extension for flows while this sheet is open, and fold each poll
    /// into per-flow throughput history (Δbytes ÷ Δt) for the sparklines.
    private func poll() async {
        while !Task.isCancelled {
            let latest = await vpn.fetchFlows(id: profileID)
            guard !Task.isCancelled else { return }
            let now = Date()
            var next = history
            for f in latest {
                if var h = next[f.id] {
                    let dt = max(0.001, now.timeIntervalSince(h.lastAt))
                    let delta = max(0, f.bytesTotal - h.lastTotal)   // counters only grow
                    h.rates.append(Double(delta) / dt)
                    if h.rates.count > 40 { h.rates.removeFirst(h.rates.count - 40) }
                    h.lastTotal = f.bytesTotal; h.lastAt = now
                    next[f.id] = h
                } else {
                    // First sighting: seed the baseline, no rate sample yet.
                    next[f.id] = FlowHistory(lastTotal: f.bytesTotal, lastAt: now)
                }
            }
            // Drop history for flows the extension has aged out.
            let live = Set(latest.map(\.id))
            next = next.filter { live.contains($0.key) }
            history = next
            flows = latest
            try? await Task.sleep(for: .seconds(1))
        }
    }

    private static func durationText(_ seconds: Double) -> String {
        let s = Int(seconds.rounded())
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m" }
        return "\(s / 3600)h\((s % 3600) / 60)m"
    }
}

/// A compact live throughput sparkline for one connection (bytes/sec over the
/// recent polling window). Flat/empty when the flow is idle.
private struct Sparkline: View {
    let values: [Double]
    var active: Bool

    var body: some View {
        Canvas { ctx, size in
            guard values.count > 1, let mx = values.max(), mx > 0 else {
                // Idle baseline.
                var base = Path()
                base.move(to: CGPoint(x: 0, y: size.height - 1))
                base.addLine(to: CGPoint(x: size.width, y: size.height - 1))
                ctx.stroke(base, with: .color(.secondary.opacity(0.35)), lineWidth: 1)
                return
            }
            let stepX = size.width / CGFloat(values.count - 1)
            var path = Path()
            for (i, v) in values.enumerated() {
                let x = CGFloat(i) * stepX
                let y = size.height - CGFloat(v / mx) * (size.height - 2) - 1
                if i == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
            }
            ctx.stroke(path, with: .color(active ? .accentColor : .secondary),
                       style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
        }
        .accessibilityHidden(true)
    }
}
