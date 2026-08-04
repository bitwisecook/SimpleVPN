// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RailroadView.swift
//  The connection railroad: a ladder of tracks from This Mac through every
//  interface (Wi-Fi / Ethernet / dongles / VM networks / VPN tunnels) to where
//  the traffic goes — VPN far-side networks, the internet, or the local net.
//  Tracks are live: dash "trains" flow along each track, speed and brightness
//  driven by that interface's real byte counters (down-trains run toward the
//  Mac, up-trains away). The path carrying the default route is the lit main
//  line; idle tracks sit dim. Reduce Motion swaps trains for static emphasis.
//

import SwiftUI

// MARK: - Track line (the animated rail)

struct TrackLine: View {
    let active: Bool          // on the lit path (default route / our tunnel)
    let inRate: Double        // bytes/sec toward the Mac
    let outRate: Double       // bytes/sec away from the Mac
    var color: Color = .accentColor

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var hasTraffic: Bool { inRate > 64 || outRate > 64 }

    /// Train speed from rate: log-scaled so 1 KB/s visibly crawls and
    /// 100 MB/s hurries without becoming a blur. Points per second.
    nonisolated private func speed(_ rate: Double) -> Double {
        guard rate > 64 else { return 0 }
        return min(120, 12 * log10(rate / 64 + 1) * 8)
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: reduceMotion || !hasTraffic)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                let midY = size.height / 2
                let base = Path { p in
                    p.move(to: CGPoint(x: 0, y: midY))
                    p.addLine(to: CGPoint(x: size.width, y: midY))
                }
                // Rail bed: the constant line. Lit path gets the color; idle dim.
                ctx.stroke(base, with: .color(active ? color.opacity(0.45) : Color.secondary.opacity(0.25)),
                           style: StrokeStyle(lineWidth: active ? 3 : 2, lineCap: .round))

                guard !reduceMotion else { return }

                // Trains: short bright dashes flowing with traffic.
                func trains(rate: Double, towardMac: Bool, offset: CGFloat) {
                    let v = speed(rate)
                    guard v > 0 else { return }
                    let phase = CGFloat((t * v).truncatingRemainder(dividingBy: 26))
                    let dashPhase = towardMac ? phase : -phase
                    let line = Path { p in
                        p.move(to: CGPoint(x: 0, y: midY + offset))
                        p.addLine(to: CGPoint(x: size.width, y: midY + offset))
                    }
                    let intensity = min(1, 0.45 + rate / 1_000_000)   // brighter with load
                    ctx.stroke(line, with: .color(color.opacity(intensity)),
                               style: StrokeStyle(lineWidth: 2, lineCap: .round,
                                                  dash: [7, 19], dashPhase: dashPhase))
                }
                trains(rate: outRate, towardMac: false, offset: -2)
                trains(rate: inRate, towardMac: true, offset: 2)
            }
        }
        .frame(height: 10)
        .frame(minWidth: 24)
        .accessibilityHidden(true)
    }
}

// MARK: - Nodes

private struct RailNode: View {
    let icon: String
    let title: String
    var subtitle: String? = nil
    var active = false
    var loud = false            // bypass-style warning emphasis

    var body: some View {
        VStack(spacing: 2) {
            Image(systemName: icon)
                .font(.body)
                .foregroundStyle(loud ? AnyShapeStyle(.red) : active ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
            Text(title)
                .font(.caption.weight(active ? .semibold : .regular))
                .lineLimit(1)
            if let subtitle, !subtitle.isEmpty {
                Text(subtitle)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .frame(minWidth: 56, maxWidth: 150)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - The railroad

struct RailroadView: View {
    let topology: NetworkTopology
    /// Our tunnel's in-tunnel IPv4 (matches the utun that is ours), or nil.
    let ourTunnelIPv4: String?
    let serverEndpoint: String
    let paused: Bool
    let bypassing: Bool
    var compact = false

    private var ourTunnel: NetInterface? {
        guard let ip = ourTunnelIPv4, !ip.isEmpty else { return nil }
        return topology.interfaces.first { $0.ipv4.contains(ip) }
    }

    /// Rows, most interesting first: our VPN, default-route interface, other
    /// tunnels, remaining physical interfaces. Compact mode trims to the essentials.
    private var rows: [Row] {
        var rows: [Row] = []
        let our = ourTunnel

        for iface in topology.interfaces {
            if iface.name == our?.name { continue }
            if topology.carriesDefault(iface.name) {
                rows.append(Row(iface: iface, role: .defaultEgress))
            } else if !iface.inUse {
                continue   // idle system utun / down interface — not worth a track
            } else if iface.kind == .tunnel {
                rows.append(Row(iface: iface, role: .otherTunnel))
            } else {
                rows.append(Row(iface: iface, role: .local))
            }
        }
        rows.sort { $0.priority < $1.priority }
        if let our { rows.insert(Row(iface: our, role: .ourTunnel), at: 0) }
        if compact {
            rows = Array(rows.prefix(3))   // our VPN + egress + one more
        }
        return rows
    }

    struct Row: Identifiable {
        var id: String { iface.name }
        let iface: NetInterface
        enum Role { case ourTunnel, defaultEgress, otherTunnel, local }
        let role: Role
        var priority: Int {
            switch role {
            case .ourTunnel: 0
            case .defaultEgress: 1
            case .otherTunnel: 2
            case .local: 3
            }
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // The origin + bus bar all tracks branch from.
            VStack(spacing: 2) {
                Image(systemName: "laptopcomputer").font(.title3).foregroundStyle(.tint)
                Text("This Mac").font(.caption.weight(.semibold))
            }
            .frame(minWidth: 60)
            .padding(.top, 2)

            Rectangle()
                .fill(.secondary.opacity(0.3))
                .frame(width: 2)
                .clipShape(Capsule())

            VStack(alignment: .leading, spacing: compact ? 6 : 10) {
                ForEach(rows) { row in
                    track(for: row)
                }
                if rows.isEmpty {
                    Text("No active network interfaces")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity)
        }
        // ONE element for the whole ladder: the headline as the label, every
        // track as a sentence in the value — name, kind, where it goes — read
        // from the same topology the tracks draw, so it stays live. The child
        // nodes are fragments of a picture (icon + name + address), not a
        // walkable structure; the route graph window is where per-node
        // navigation lives.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilitySummary)
        .accessibilityValue(accessibilityLadder)
    }

    @ViewBuilder private func track(for row: Row) -> some View {
        let iface = row.iface
        let far = topology.farSideNetworks(via: iface.name)
        let isDefault = topology.carriesDefault(iface.name)

        HStack(spacing: 6) {
            RailNode(icon: iface.systemImage,
                     title: iface.friendlyName,
                     subtitle: iface.primaryAddress,
                     active: row.role == .ourTunnel || isDefault)

            switch row.role {
            case .ourTunnel:
                TrackLine(active: !paused, inRate: iface.inRate, outRate: iface.outRate,
                          color: bypassing ? .red : .green)
                RailNode(icon: paused ? "pause.circle" : "lock.shield.fill",
                         title: paused ? "VPN (paused)" : "VPN",
                         subtitle: serverEndpoint, active: !paused, loud: bypassing)
                TrackLine(active: !paused, inRate: iface.inRate, outRate: iface.outRate,
                          color: bypassing ? .red : .green)
                farSideNodes(far: far, isDefault: isDefault)

            case .defaultEgress:
                TrackLine(active: true, inRate: iface.inRate, outRate: iface.outRate)
                RailNode(icon: "globe", title: "Internet",
                         subtitle: ourTunnel == nil ? "egress" : "egress (split)",
                         active: true, loud: bypassing)

            case .otherTunnel:
                let active = iface.inRate > 0 || iface.outRate > 0
                TrackLine(active: active, inRate: iface.inRate, outRate: iface.outRate, color: .purple)
                RailNode(icon: iface.systemImage, title: iface.friendlyName,
                         subtitle: far.first.map { far.count > 1 ? "\($0) +\(far.count - 1)" : $0 })

            case .local:
                TrackLine(active: false, inRate: iface.inRate, outRate: iface.outRate)
                RailNode(icon: "house", title: "Local network")
            }
        }
    }

    /// What's behind our tunnel: pushed private networks, and the internet when
    /// the tunnel carries the default route (full tunnel).
    @ViewBuilder private func farSideNodes(far: [String], isDefault: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if !far.isEmpty {
                RailNode(icon: "building.2",
                         title: far.count == 1 ? far[0] : "\(far.count) networks",
                         subtitle: far.count > 1 ? far.prefix(2).joined(separator: " ") : nil,
                         active: !paused)
            }
            if isDefault {
                RailNode(icon: "globe", title: "Internet", subtitle: "full tunnel", active: !paused)
            }
            if far.isEmpty && !isDefault {
                RailNode(icon: "questionmark.circle", title: "No routes yet")
            }
        }
    }

    private var accessibilitySummary: String {
        var parts: [String] = []
        if let our = ourTunnel {
            parts.append("VPN active on \(our.displayName)" + (paused ? ", paused" : ""))
        }
        if let def = topology.defaultInterface,
           let iface = topology.interfaces.first(where: { $0.name == def }) {
            parts.append("Internet via \(iface.displayName)")
        }
        return parts.isEmpty ? "Network diagram" : parts.joined(separator: ". ")
    }

    /// The ladder in words, one sentence per track — the same rows, in the
    /// same order, saying what each drawing says: what the interface is, and
    /// where traffic on it ends up.
    private var accessibilityLadder: String {
        let sentences = rows.map { row -> String in
            let iface = row.iface
            let far = topology.farSideNetworks(via: iface.name)
            let isDefault = topology.carriesDefault(iface.name)
            switch row.role {
            case .ourTunnel:
                var s = "Your VPN on \(iface.friendlyName)"
                if !serverEndpoint.isEmpty { s += " to \(serverEndpoint)" }
                if paused { s += ", paused" }
                if bypassing { s += ", traffic is bypassing it" }
                var reaches: [String] = []
                if !far.isEmpty {
                    reaches.append(far.count == 1 ? far[0] : "\(far.count) networks")
                }
                if isDefault { reaches.append("the Internet as a full tunnel") }
                if reaches.isEmpty { reaches.append("no routes yet") }
                return s + ", reaching " + reaches.formatted(.list(type: .and))
            case .defaultEgress:
                return "\(iface.friendlyName) to the Internet"
                    + (ourTunnel == nil ? "" : ", the split-tunnel egress")
            case .otherTunnel:
                let dest = far.isEmpty ? "no routes yet"
                    : (far.count == 1 ? far[0] : "\(far.count) networks")
                return "\(iface.friendlyName), another tunnel, to \(dest)"
            case .local:
                return "\(iface.friendlyName) to the local network"
            }
        }
        return sentences.isEmpty ? "No active network interfaces"
            : sentences.joined(separator: ". ")
    }
}
