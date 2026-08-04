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
                // The control cluster reads as ONE VoiceOver element (label =
                // what it is, value = what it currently means, applying state
                // included); the strip stays a second element of its own so
                // the path-in-words survives independently of the picker. The
                // nested HStack shares the outer one's spacing, so the pixels
                // don't move.
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
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Default gateway")
                .accessibilityValue(gatewayAXValue(owner: owner, displayed: displayed))
                Spacer(minLength: 8)
                // The picker's pick, as a picture: This Mac → [owner|Direct] →
                // Internet, filling the air the bar always had at its trailing
                // end. Animates only while a switch is happening (see the strip).
                TrafficPathStrip(vpn: vpn)
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
        }
    }

    /// The pick's live meaning, in the same words the tooltip uses — plus the
    /// reconciliation note while the engines are still converging on it. (The
    /// gateway CHANGE itself is spoken by AccessibilityAnnouncer, off the
    /// control plane's gatewayChanged event — this value is what you read when
    /// you come looking, not a second voice saying the same thing.)
    private func gatewayAXValue(owner: String?, displayed: String?) -> String {
        var value = gatewaySummary(owner: owner)
        if displayed != owner {
            value += " " + reconcilingGatewayNote(effective: displayed)
        }
        return value
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
