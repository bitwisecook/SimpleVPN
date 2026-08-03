// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DoctorView.swift
//  Two surfaces on the connection screen:
//   • Connection Manager — plain-language on/off controls for how this VPN behaves
//     (full-tunnel explainer, allow local devices, keep everything inside the VPN,
//     stay connected), each saying what its current state means. Every change is
//     verifiable (Applied ✓ / applying) and reversible (one-tap Undo).
//   • Connection Doctor — only appears when something is genuinely wrong (an IPv6
//     or DNS leak, a stalled path, a captive portal, a certificate problem), with a
//     one-tap fix or a plain explanation.
//

import SwiftUI

struct ConnectionManagerPanel: View {
    @Bindable var vpn: VPNController
    let profileID: String
    let vpnName: String
    let snapshot: DoctorSnapshot
    let findings: [DoctorFinding]

    private var connected: Bool { snapshot.isConnected }
    private var fullTunnel: Bool? {
        let observed = ConnectionManager.isFullTunnel(snapshot.topology)
        // A "split tunnel" reading in the first seconds after connect is usually just
        // the default route not having moved onto the tunnel yet. A fact-labelled line
        // must not flip-flop, so report "still checking" until the table has settled;
        // a genuine split tunnel still shows as one — eight seconds later.
        if observed != true, connected, (snapshot.stats?.uptime ?? 0) < 8 { return nil }
        return observed
    }
    private var proxies: [String] { snapshot.stats?.proxies ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            managerSection
            if !findings.isEmpty { doctorSection }
        }
    }

    // MARK: Connection Manager

    private var managerSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Connection Manager", systemImage: "slider.horizontal.3").font(.headline)

            // Tunnel mode — verifiable fact, read from the routing table.
            if connected {
                if let full = fullTunnel {
                    InfoRow(symbol: full ? "globe" : "arrow.triangle.branch",
                            text: ConnectionManager.tunnelModeExplanation(
                                fullTunnel: full, vpnName: vpnName,
                                leakPossible: vpn.overrides(for: profileID).allowUnusedAddrFamilies != .block),
                            footnote: "Confirmed from your Mac's routing table.")
                } else {
                    InfoRow(symbol: "hourglass",
                            text: "Checking how your traffic is routed\u{2026}",
                            footnote: nil)
                }
            }

            // Proxy awareness — make it unmistakable when traffic rides a proxy.
            if !proxies.isEmpty {
                InfoRow(symbol: "arrow.triangle.branch",
                        text: "Your \(vpnName) traffic passes through a proxy: \(proxies.joined(separator: ", ")).",
                        footnote: "Reported by the live connection.")
            }

            ForEach(ConnectionManager.settings) { setting in
                ManagerSettingRow(vpn: vpn, profileID: profileID, vpnName: vpnName,
                                  setting: setting, snapshot: snapshot,
                                  leakActive: leakActive)
            }

            if let undo = vpn.lastChange[profileID] {
                Divider().padding(.vertical, 2)
                HStack(spacing: 8) {
                    Image(systemName: "arrow.uturn.backward.circle").foregroundStyle(.secondary)
                    Text("Last change: \(undo.label)").font(.callout).foregroundStyle(.secondary)
                    Spacer()
                    Button("Undo") { Task { await vpn.undoLastChange(id: profileID) } }
                        .controlSize(.small)
                        .disabled(vpn.isReconfiguring(profileID))
                }
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }

    /// Whether the block-outside setting has a live leak to point at (drives the
    /// "verified: nothing leaking" vs the Doctor warning).
    private var leakActive: Bool { findings.contains { $0.id == "ipv6-leak" } }

    // MARK: Connection Doctor (problems only)

    private var doctorSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Connection Doctor", systemImage: "stethoscope").font(.headline)
            ForEach(findings) { finding in
                DoctorCard(vpn: vpn, profileID: profileID, finding: finding)
            }
        }
    }
}

// MARK: - A single Connection Manager on/off row

private struct ManagerSettingRow: View {
    @Bindable var vpn: VPNController
    let profileID: String
    let vpnName: String
    let setting: ConnectionSetting
    let snapshot: DoctorSnapshot
    let leakActive: Bool

    @Environment(ManualRouter.self) private var router: ManualRouter?
    @Environment(\.openWindow) private var openWindow

    private var desiredOn: Bool { setting.isOn(vpn.overrides(for: profileID)) }
    private var appliedOn: Bool? { vpn.appliedOverrides(for: profileID).map(setting.isOn) }
    private var connected: Bool { snapshot.isConnected }
    private var reconfiguring: Bool { vpn.isReconfiguring(profileID) }
    private var pending: Bool { connected && !reconfiguring && appliedOn != nil && appliedOn != desiredOn }

    /// Org policy forces this setting on and locks it (only keep-inside today).
    private var managedLocked: Bool { setting.id == "block-outside" && ManagedPolicy.forceKeepInsideVPN }

    private var binding: Binding<Bool> {
        Binding(get: { managedLocked ? true : desiredOn }, set: { newValue in
            guard !managedLocked else { return }
            Task {
                await vpn.applyDoctorFix(.overrides { setting.set(&$0, newValue) },
                                         to: profileID, undoLabel: setting.title)
            }
        })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Toggle(isOn: binding) {
                HStack(spacing: 6) {
                    Image(systemName: setting.symbol)
                        .foregroundStyle(setting.riskyWhenOn && desiredOn ? .orange : .secondary)
                        .frame(width: 20)
                    Text(setting.title)
                    if setting.riskyWhenOn && desiredOn {
                        Text("weakens security").font(.caption2).foregroundStyle(.orange)
                    }
                }
            }
            .toggleStyle(.switch)
            .disabled(reconfiguring || managedLocked)

            Text(setting.explanation(desiredOn, vpnName, LocationAuthority.shared.ssid))
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                statusCaption
                Button("Learn more") {
                    router?.navigate(to: setting.manualAnchor)
                    openWindow(id: "manual")
                }
                .buttonStyle(.link).controlSize(.small)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private var statusCaption: some View {
        if managedLocked {
            Label("Managed by your organization", systemImage: "lock.fill")
                .font(.caption).foregroundStyle(.secondary)
        } else if reconfiguring {
            Label("Applying…", systemImage: "arrow.triangle.2.circlepath")
                .font(.caption).foregroundStyle(.secondary)
        } else if !connected {
            Label("Applies when you connect", systemImage: "clock")
                .font(.caption).foregroundStyle(.secondary)
        } else if pending {
            Label("Reconnect to apply", systemImage: "exclamationmark.arrow.triangle.2.circlepath")
                .font(.caption).foregroundStyle(.orange)
        } else if setting.id == "block-outside", desiredOn {
            // Verified from live telemetry: on + no leak detected. (Leak detection
            // is live regardless of whether we know the session's applied config.)
            Label(leakActive ? "On — but a leak is still detected (see below)" : "On — nothing is leaking outside \(vpnName)",
                  systemImage: leakActive ? "exclamationmark.triangle.fill" : "checkmark.seal.fill")
                .font(.caption).foregroundStyle(leakActive ? .orange : .green)
        } else if desiredOn, appliedOn == nil {
            // Connected but we don't know what the running session started with
            // (e.g. after an app relaunch) — don't claim "Applied"; invite a reconnect.
            Label("Can’t confirm — reconnect to be sure", systemImage: "questionmark.circle")
                .font(.caption).foregroundStyle(.secondary)
        } else if desiredOn {
            Label("Applied", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(.green)
        } else {
            EmptyView()
        }
    }
}

private struct InfoRow: View {
    let symbol: String
    let text: String
    var footnote: String? = nil
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(.tint).frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
                if let footnote {
                    Text(footnote).font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
    }
}

// MARK: - Doctor finding card (genuine problems)

private struct DoctorCard: View {
    @Bindable var vpn: VPNController
    let profileID: String
    let finding: DoctorFinding

    @Environment(ManualRouter.self) private var router: ManualRouter?
    @Environment(\.openWindow) private var openWindow
    @State private var applying = false

    private var accent: Color {
        if finding.risky { return .orange }
        switch finding.severity {
        case .critical: return .red
        case .warning: return .orange
        case .advice: return .accentColor
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(accent).font(.title3).frame(width: 22)
            VStack(alignment: .leading, spacing: 4) {
                Text(finding.title).font(.callout).bold()
                Text(finding.detail).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 12) {
                    if let label = finding.fixLabel {
                        Button {
                            applying = true
                            Task { await vpn.applyDoctorFix(finding.fix, to: profileID, undoLabel: finding.title); applying = false }
                        } label: {
                            if applying { ProgressView().controlSize(.small) }
                            else { Text(label) }
                        }
                        .buttonStyle(.glassProminent)
                        .tint(finding.risky ? .orange : .accentColor)
                        .controlSize(.small)
                        .disabled(applying)
                    }
                    Button("Learn more") {
                        router?.navigate(to: finding.manualAnchor)
                        openWindow(id: "manual")
                    }
                    .buttonStyle(.link)
                    .controlSize(.small)
                }
                .padding(.top, 2)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(accent.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(accent.opacity(0.25)))
        .accessibilityElement(children: .combine)
    }

    private var icon: String {
        switch finding.severity {
        case .critical: "exclamationmark.triangle.fill"
        case .warning: "exclamationmark.circle.fill"
        case .advice: "lightbulb.fill"
        }
    }
}
