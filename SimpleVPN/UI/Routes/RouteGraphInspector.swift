// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphInspector.swift
//  The inspect popovers for the route graph's nodes, split out of
//  RouteGraphView.swift for size, not redesigned: an interface's live
//  counters, addresses and the actions that apply to it (connect, resume,
//  reconnect, open the sign-in page, disconnect), the globe's facts-only
//  panel, and the proxy hop's. Popovers render OUTSIDE the scaled content, so
//  ordinary controls are allowed here — unlike anything in RouteGraphNodes.
//

import SwiftUI

extension RouteGraphView {

    // MARK: Interface inspector (popover — outside the scaled content, so it may
    // use ordinary controls)

    @ViewBuilder func interfaceInspector(_ snapshot: NetInterface) -> some View {   // was private — internal for the file split
        // Re-read from the monitor so the counters keep ticking while it's open.
        let iface = topo?.topology.interfaces.first { $0.name == snapshot.name } ?? snapshot
        let state = status(for: iface)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: iface.systemImage)
                    .font(.title3).foregroundStyle(tint(for: iface))
                VStack(alignment: .leading, spacing: 1) {
                    Text(label(for: iface)).font(.headline)
                    Text(iface.name).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            Text(state.summary).font(.caption).foregroundStyle(.secondary)

            Divider()
            HStack(spacing: 22) {
                rateBlock("Download", Fmt.rate(iface.inRate), "arrow.down")
                rateBlock("Upload", Fmt.rate(iface.outRate), "arrow.up")
            }

            if !iface.ipv4.isEmpty || !iface.ipv6.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 3) {
                    Text("Addresses").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    ForEach(iface.ipv4 + iface.ipv6, id: \.self) { a in
                        Text(a).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
            }
            if topo?.topology.carriesDefault(iface.name) == true {
                Text("Carries the default route").font(.caption).foregroundStyle(.secondary)
            }

            // Actions only where we can actually act. Wi-Fi and Tailscale get the
            // facts and nothing pretending to be a button.
            if let id = actionProfileID(for: iface) {
                Divider()
                HStack(spacing: 8) { inspectorActions(id: id, state: state) }
            }
        }
        .padding(14)
        .frame(width: 290, alignment: .leading)
    }

    /// The globe's popover: facts only, no actions — whatever you'd want to DO about
    /// the Internet is done to the interface carrying it, one card to the left.
    @ViewBuilder func internetInspector(_ owner: NetInterface?,   // was private — internal for the file split
                                                standbys: [NetInterface]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "globe")
                    .font(.title3).foregroundStyle(owner == nil ? Color.secondary : Color.blue)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Internet").font(.headline)
                    Text("everything not matched by a specific route")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Divider()
            if let owner {
                Text("Internet egress via \(label(for: owner))")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                Text(owner.name).font(.caption.monospaced()).foregroundStyle(.secondary)
                if profileID(for: owner) != nil {
                    Text("This is one of your VPN tunnels, so websites see the VPN's location, not where you actually are.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("Nothing is carrying the default route right now, so there is no way out to the Internet.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // The dashed edges, in words: these hold a default with a real next hop
            // behind the winner, so dropping the tunnel lands you on one of them.
            if !standbys.isEmpty {
                Divider()
                Text("Standby: \(standbys.map { label(for: $0) }.formatted(.list(type: .and))) would take over")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(width: 270, alignment: .leading)
    }

    /// Facts about the hop, and where they came from. No actions: a proxy is pushed by
    /// the connection, so there is nothing here for the user to change.
    @ViewBuilder func proxyInspector(_ proxies: [String]) -> some View {   // was private — internal for the file split
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "server.rack").font(.title3).foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text(proxies.count == 1 ? "Proxy" : "\(proxies.count) Proxies").font(.headline)
                    Text("on the way out to the Internet")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 3) {
                ForEach(proxies, id: \.self) { proxy in
                    Text(proxy).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            Text("Reported by the live connection.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(width: 270, alignment: .leading)
    }

    private func rateBlock(_ title: String, _ value: String, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(title, systemImage: symbol)
                .font(.caption).foregroundStyle(.secondary).labelStyle(.titleAndIcon)
            Text(value).font(.callout.monospacedDigit())
        }
    }

    /// nil ⇒ this interface isn't one of ours (or there's no link monitor to judge
    /// it), so the inspector shows facts and no buttons at all.
    private func actionProfileID(for iface: NetInterface) -> String? {
        guard link != nil else { return nil }
        return profileID(for: iface)
    }

    @ViewBuilder private func inspectorActions(id: String, state: EdgeStatus) -> some View {
        switch state {
        case .paused:
            Button("Resume") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .stalled:
            Button("Reconnect") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .down:
            Button("Connect") { act(on: state); inspecting = nil }
        case .captivePortal:
            Button("Open Sign-In Page") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .healthy:
            Button("Reconnect") { Task { await vpn.reconnect(id: id) }; inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .passive:
            EmptyView()
        }
    }
}
