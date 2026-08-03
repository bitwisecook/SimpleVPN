// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GatewayBar.swift
//  The compact default-gateway picker at the top of the Routes window, split
//  out of RouteGraphView.swift for size, not redesigned. The control itself
//  moved here from the main window's connection detail earlier — this is its
//  natural home, next to the route graph and the drift indicators it directly
//  affects. Same state & actions as ever (effectiveGatewayOwner/
//  displayedGatewayOwner, setDefaultGateway, canBeDefaultGateway) — only the
//  surface lives here, never the gateway logic.
//

import SwiftUI

extension RouteGraphView {

    // MARK: Default-gateway control (PolicyRouting.md Tier 2)
    //
    // Moved here from the main window's connection detail — this is its natural
    // home, next to the route graph and the drift indicators it directly affects.
    // Deliberately a single compact row (a label + a menu picker), not the big
    // card the main window used to show: this window is for people who already
    // want to see the routing table, so the control can be plain and small
    // rather than explained at length. Same state & actions as before
    // (`effectiveGatewayOwner`/`displayedGatewayOwner`, `setDefaultGateway`,
    // `canBeDefaultGateway`) — only the surface moved, not the gateway logic.
    @ViewBuilder var gatewayBar: some View {   // was private — internal for the file split
        if vpn.showsDefaultGatewayControl {
            let connected = vpn.connectedProfiles
            let capable = connected.filter { vpn.canBeDefaultGateway($0.id) }
            let owner = vpn.effectiveGatewayOwner
            let displayed = vpn.displayedGatewayOwner
            HStack(spacing: 8) {
                Label("Default gateway", systemImage: "arrow.triangle.branch")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Picker("Default gateway", selection: Binding(
                    get: { owner },
                    set: { new in Task { await vpn.setDefaultGateway(to: new) } })
                ) {
                    ForEach(capable) { p in
                        Text(p.name).tag(Optional(p.id))
                    }
                    Text("Direct").tag(String?.none)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .controlSize(.small)
                .help(gatewaySummary(owner: owner))
                // Transient desync surfaced honestly, same as the old card: the
                // engines currently route differently from the pick above while
                // reconciliation converges them (RC4/RC5).
                if displayed != owner {
                    Label("Applying…", systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(reconcilingGatewayNote(effective: displayed))
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Default gateway: \(gatewaySummary(owner: owner))")
        }
    }

    private func gatewaySummary(owner: String?) -> String {
        guard let owner, let name = vpn.profiles.first(where: { $0.id == owner })?.name else {
            return "Unmatched traffic goes directly out your normal connection. Each VPN still carries only its own subnets."
        }
        return "Unmatched traffic goes through \(name). Every other VPN carries only its own subnets."
    }

    private func reconcilingGatewayNote(effective: String?) -> String {
        if let effective, let name = vpn.profiles.first(where: { $0.id == effective })?.name {
            return "Applying change — traffic currently routes through \(name)."
        }
        return "Applying change — traffic currently routes directly."
    }
}
