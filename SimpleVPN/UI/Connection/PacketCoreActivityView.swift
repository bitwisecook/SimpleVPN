// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Charts
import SwiftUI

nonisolated struct PacketCoreSnapshot: Decodable {
    struct Direction: Decodable {
        let receivedPackets, receivedBytes, forwardedPackets, forwardedBytes: UInt64
        let droppedPackets, droppedBytes, evaluatedPackets, editedPackets, ruleHits: UInt64
    }

    struct Rule: Decodable, Identifiable {
        let id: String
        let packetsOut, bytesOut, packetsIn, bytesIn, drops: UInt64
    }

    let adapter, sessionID: String
    let outbound, inbound: Direction
    let rules: [Rule]
}

struct PacketCoreActivityButton: View {
    let vpn: VPNController
    let profileID, name: String
    var proxyManager: SubprocessTunnelManager? = nil
    @State private var show = false

    var body: some View {
        Button("Packet Counters") { show = true }
            .controlSize(.small)
            .sheet(isPresented: $show) {
                PacketCoreActivityView(vpn: vpn, profileID: profileID, name: name, proxyManager: proxyManager).tracksWindowActivity()
            }
    }
}

private struct PacketCoreActivityView: View {
    let vpn: VPNController
    let profileID, name: String
    var proxyManager: SubprocessTunnelManager? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var snapshot: PacketCoreSnapshot?
    @State private var engine: TunnelStats?
    @State private var ruleID: String?
    @State private var history = RuleActivityHistory()
    @State private var unavailable = false
    @State private var refresh = 0

    var body: some View {
        NavigationStack {
            Group {
                if unavailable {
                    ContentUnavailableView {
                        Label("Packet Counters Unavailable", systemImage: "network.slash")
                    } description: {
                        Text("Connect this VPN through a packet provider that reports counters.")
                    } actions: {
                        Button("Try Again") { refresh += 1 }
                    }
                } else if let snapshot {
                    Form {
                        Section(snapshot.adapter == "wireguard-shared" ? "Shared Interface" : "Packet Routing") {
                            Grid(alignment: .leading, horizontalSpacing: 22, verticalSpacing: 5) {
                                GridRow {
                                    Text("Inner traffic")
                                    Text("Toward VPN")
                                    Text("Toward Mac")
                                }.font(.headline)
                                counter("Received packets", \.receivedPackets, snapshot)
                                counter("Received bytes", \.receivedBytes, snapshot)
                                counter("Forwarded packets", \.forwardedPackets, snapshot)
                                counter("Forwarded bytes", \.forwardedBytes, snapshot)
                                counter("Dropped packets", \.droppedPackets, snapshot)
                                counter("Dropped bytes", \.droppedBytes, snapshot)
                                counter("Evaluated packets", \.evaluatedPackets, snapshot)
                                counter("Edited packets", \.editedPackets, snapshot)
                                counter("Rule matches", \.ruleHits, snapshot)
                            }.monospacedDigit()
                        }
                        if let engine {
                            Section(snapshot.adapter == "wireguard-shared" ? "Selected VPN Engine" : "VPN Engine") {
                                LabeledContent("Sent bytes", value: engine.bytesOut.formatted())
                                LabeledContent("Received bytes", value: engine.bytesIn.formatted())
                            }
                        }
                        if !snapshot.rules.isEmpty {
                            Section("Rule Activity") {
                                Picker("Rule", selection: $ruleID) {
                                    ForEach(snapshot.rules) { rule in Text(rule.id).tag(Optional(rule.id)) }
                                }
                                if let rule = snapshot.rules.first(where: { $0.id == ruleID }) {
                                    LabeledContent("Packets toward VPN", value: rule.packetsOut.formatted())
                                    LabeledContent("Packets toward Mac", value: rule.packetsIn.formatted())
                                    LabeledContent("Drops", value: rule.drops.formatted())
                                    Chart(history.samples) { sample in
                                        LineMark(x: .value("Time", sample.id), y: .value("Packets/s", sample.packetsOut))
                                            .foregroundStyle(by: .value("Direction", "Toward VPN"))
                                        LineMark(x: .value("Time", sample.id), y: .value("Packets/s", sample.packetsIn))
                                            .foregroundStyle(by: .value("Direction", "Toward Mac"))
                                    }
                                    .frame(height: 100)
                                    .accessibilityLabel("Matched packets per second")
                                }
                            }
                        }
                    }
                    .formStyle(.grouped)
                } else {
                    ProgressView("Reading packet counters…")
                }
            }
            .navigationTitle("Packet Counters · \(name)")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
                }
            }
        }
        .frame(minWidth: 460, minHeight: 350)
        .resizablePanel(idealWidth: 580, idealHeight: 580)
        .onChange(of: ruleID) { history = RuleActivityHistory() }
        .liveWindowTask(id: refresh) { await poll() }
    }

    private func counter(_ label: String, _ field: KeyPath<PacketCoreSnapshot.Direction, UInt64>, _ sample: PacketCoreSnapshot) -> some View {
        GridRow {
            Text(label)
            Text(sample.outbound[keyPath: field].formatted())
            Text(sample.inbound[keyPath: field].formatted())
        }
    }

    private func poll() async {
        history = RuleActivityHistory()
        while !Task.isCancelled {
            let packetReply: Data?
            let engineReply: Data?
            if let proxyManager {
                packetReply = await proxyManager.proxyPacketStatus(profileID)
                engineReply = nil
            } else {
                async let packetData = vpn.sendMessageData("packet-policy:status", to: profileID)
                async let engineData = vpn.sendMessageData("stats", to: profileID)
                (packetReply, engineReply) = await (packetData, engineData)
            }
            guard !Task.isCancelled else { return }
            guard let packetReply,
                  let next = try? JSONDecoder().decode(PacketCoreSnapshot.self, from: packetReply) else {
                snapshot = nil
                engine = nil
                unavailable = true
                return
            }
            unavailable = false
            engine = engineReply.flatMap { try? JSONDecoder().decode(TunnelStats.self, from: $0) }
            snapshot = next
            if !next.rules.contains(where: { $0.id == ruleID }) { ruleID = next.rules.first?.id }
            if let rule = next.rules.first(where: { $0.id == ruleID }) {
                history.record(packetsOut: rule.packetsOut, bytesOut: rule.bytesOut, packetsIn: rule.packetsIn,
                               bytesIn: rule.bytesIn, drops: rule.drops, series: rule.id, session: next.sessionID, at: Date())
            }
            do { try await Task.sleep(for: .seconds(2)) } catch { return }
        }
    }
}

/// libssh owns channel payloads. These counters use that boundary explicitly.
struct SSHChannelActivityView: View {
    let manager: SubprocessTunnelManager
    let profileID: String
    @State private var snapshot: SSHChannelCounters?

    var body: some View {
        Form {
            if let s = snapshot {
                Section("SSH Channels") {
                    LabeledContent("Requested", value: s.requested.formatted())
                    LabeledContent("Opened", value: s.opened.formatted())
                    LabeledContent("Active", value: s.active.formatted())
                    LabeledContent("Denied by rules", value: s.denied.formatted())
                    LabeledContent("Sent payload bytes", value: s.bytesSent.formatted())
                    LabeledContent("Received payload bytes", value: s.bytesReceived.formatted())
                }
                if !s.rules.isEmpty {
                    Section("Channel Rules") {
                        ForEach(s.rules) { rule in
                            LabeledContent(rule.id, value: "\(rule.entered) evaluated, \(rule.denied) denied")
                        }
                    }
                }
            } else {
                ProgressView("Reading channel counters…")
            }
        }
        .formStyle(.grouped)
        .liveWindowTask(id: profileID) {
            while !Task.isCancelled {
                let next = await manager.sshChannelCounters(profileID)
                guard !Task.isCancelled else { return }
                snapshot = next
                guard next != nil else { return }
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
            }
        }
    }
}
