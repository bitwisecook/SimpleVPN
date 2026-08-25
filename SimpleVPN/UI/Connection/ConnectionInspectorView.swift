// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionInspectorView.swift
//  The main window's inspector (third) column: everything that's alive while
//  connected — the throughput graph and connection details —
//  and a friendly placeholder when the VPN isn't. Split out of
//  ConnectionView.swift, whose split view still decides when it shows.
//

import SwiftUI

// MARK: - Inspector column (live telemetry)

/// The trailing inspector: the selected route is useful before connecting, followed
/// by everything that's alive while connected — the up/down graph and full details.
struct ConnectionInspectorView: View {   // was private — internal for the file split
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @State private var showTrafficLog = false

    private var isPaused: Bool { vpn.pausedProfiles.contains(profile.id) }
    private var live: Bool { UI.isActive(profile.status) || vpn.isReconfiguring(profile.id) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                EndpointSection(vpn: vpn, profile: profile, presentation: .globe)
                    .frame(maxWidth: .infinity)
                Divider()
                if live {
                    HStack {
                        // Shared, app-wide throughput store → the graph keeps its
                        // history and never restarts empty on reopen.
                        ThroughputReadout(inRate: reach?.inRate(for: profile.id) ?? 0,
                                          outRate: reach?.outRate(for: profile.id) ?? 0)
                        Button { showTrafficLog = true } label: { Label("Traffic Log", systemImage: "list.bullet.rectangle") }
                            .controlSize(.small)
                    }
                    // ONE traffic graph. There used to be two stacked here — this VPN's
                    // tunnel counters, then a per-interface chart — which asked the user
                    // to reconcile two different pictures of the same traffic. The
                    // interface chart is the general case (it plots this VPN by default
                    // and can add any other connection), so it's the one that stays.
                    InterfaceTrafficView()
                    Divider()
                    ConnectionInfoPanel(stats: reach?.stats(for: profile.id), clientLabel: profile.server,
                                        publicIP: publicIP,
                                        paused: isPaused,
                                        bypassing: isPaused)
                } else {
                    ContentUnavailableView("Live Details",
                        systemImage: "chart.line.uptrend.xyaxis",
                        description: Text("Connect \(profile.name) to see live traffic and connection details."))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 24)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("")
        .sheet(isPresented: $showTrafficLog) {
            TrafficLogView(vpn: vpn, profileID: profile.id, vpnName: profile.name)
        }
    }
}
