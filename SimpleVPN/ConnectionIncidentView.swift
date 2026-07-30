// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionIncidentView.swift
//  Rich failure UI: when a tunnel fails, the classified incident (from the
//  extension) is explained in plain language with category-specific advice,
//  and the failure-time diagnostics (DNS → reachability → TLS certificate →
//  captive portal) render as a checklist, highlighting anything that changed
//  since the last successful connection. Captive portals get a prominent
//  "Open Portal" path — the hotel-Wi-Fi-timed-out case.
//  Also the passive degraded-link banners used while connected.
//

import SwiftUI

// MARK: - Failure card

struct ConnectionIncidentCard: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    let incident: TunnelIncident
    /// Effective target for probes (overrides applied), supplied by the caller.
    let host: String
    let port: Int
    let speaksTLS: Bool

    @Environment(\.openURL) private var openURL
    @State private var report: DiagnosticsReport?
    @State private var probing = false
    @State private var showPortalAlert = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: presentation.symbol)
                    .font(.title2)
                    .foregroundStyle(presentation.color)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(presentation.title).font(.headline)
                    Text(presentation.explanation)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Button {
                    vpn.dismissIncident(id: profile.id)
                } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .help("Dismiss")
                    .accessibilityLabel("Dismiss connection problem")
            }

            if !incident.info.isEmpty {
                Text(incident.info)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .textSelection(.enabled)
            }

            Text(presentation.advice)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            Divider()
            diagnosticsChecklist

            HStack {
                if report?.captivePortal == true {
                    Button("Open Sign-in Page") { openPortal() }
                        .buttonStyle(.glassProminent)
                }
                Spacer()
                Button("Try Again") {
                    vpn.dismissIncident(id: profile.id)
                    Task { await vpn.reconnect(id: profile.id) }
                }
            }
        }
        .padding(14)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(presentation.color.opacity(0.5), lineWidth: 1))
        .task(id: incident.timestamp) { await probe() }
        .alert("This Network Needs a Sign-in", isPresented: $showPortalAlert) {
            Button("Open Sign-in Page") { openPortal() }
            Button("Not Now", role: .cancel) {}
        } message: {
            Text("Something on this network is intercepting traffic — typically a Wi-Fi sign-in page, an expired day pass, or a data plan that ran out. The VPN can't connect until you're through it.")
        }
        .accessibilityElement(children: .contain)
    }

    // MARK: Diagnostics rows

    @ViewBuilder private var diagnosticsChecklist: some View {
        if probing {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Checking what's wrong…").font(.callout).foregroundStyle(.secondary)
            }
        } else if let report {
            VStack(alignment: .leading, spacing: 5) {
                checkRow(ok: !report.dnsFailed,
                         okText: "\(host) resolves (\(report.resolvedIPs.joined(separator: ", ")))",
                         badText: "\(host) doesn't resolve — DNS is failing on this network")
                if let reachable = report.tcpReachable {
                    checkRow(ok: reachable,
                             okText: "Server reachable" + (report.rttMilliseconds.map { " (\($0) ms)" } ?? ""),
                             badText: "Server not reachable on port \(port) — it may be blocked here")
                }
                if let subject = report.tlsSubject {
                    checkRow(ok: true, okText: "Presents certificate \u{201C}\(subject)\u{201D}", badText: "")
                }
                if report.captivePortal {
                    checkRow(ok: false, okText: "",
                             badText: "This network is holding traffic behind a sign-in page")
                }
                ForEach(report.baselineNotes, id: \.self) { note in
                    Label(note, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func checkRow(ok: Bool, okText: String, badText: String) -> some View {
        Label {
            Text(ok ? okText : badText)
        } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(ok ? AnyShapeStyle(.green) : AnyShapeStyle(.red))
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func probe() async {
        guard !host.isEmpty else { return }
        probing = true
        let result = await ConnectionDiagnostics.run(
            host: host, port: port, tryTLS: speaksTLS,
            baseline: ConnectionBaselineStore.load(profile: profile.id))
        report = result
        probing = false
        vpn.captivePortalSuspected = result.captivePortal   // feeds the dot state
        vpn.setProbeResult(result, for: profile.id)         // feeds the Connection Doctor
        if result.captivePortal { showPortalAlert = true }
    }

    private func openPortal() {
        openURL(report?.portalURL ?? ConnectionDiagnostics.captivePortalProbeURL)
    }

    // MARK: Category presentation

    private struct Presentation {
        let symbol: String
        let color: Color
        let title: String
        let explanation: String
        let advice: String
    }

    private var presentation: Presentation {
        switch incident.category {
        case .auth:
            Presentation(symbol: "person.badge.key.fill", color: .orange,
                title: "Sign-in Problem",
                explanation: "The server rejected the credentials.",
                advice: "Check your username and password. If you use a one-time code, it may have expired while connecting — try again with a fresh one.")
        case .dns:
            Presentation(symbol: "questionmark.circle.fill", color: .red,
                title: "Can't Find the Server",
                explanation: "The server's name couldn't be looked up.",
                advice: "Check that your internet connection works at all. If it does, this network's DNS may be blocking the VPN's name.")
        case .network:
            Presentation(symbol: "wifi.exclamationmark", color: .red,
                title: "Network Problem",
                explanation: "Traffic to the server isn't getting through.",
                advice: "If you're on a restrictive network (hotel, airport, office guest Wi-Fi), try switching this VPN to TCP on port 443 in Options ▸ Connection — that usually gets through.")
        case .timeout:
            Presentation(symbol: "clock.badge.exclamationmark.fill", color: .orange,
                title: "Server Not Answering",
                explanation: "The server never replied.",
                advice: "The server may be down, or this network may silently drop VPN traffic. Try another endpoint if this VPN has one, or TCP on port 443.")
        case .tlsIdentity:
            Presentation(symbol: "checkmark.seal.trianglebadge.exclamationmark.fill", color: .red,
                title: "Server Identity Problem",
                explanation: "The server's certificate failed verification.",
                advice: "This can mean a misconfigured or expired server — or something impersonating it. Contact the VPN's administrator; don't loosen certificate checks unless they tell you to.")
        case .cipher:
            Presentation(symbol: "lock.rotation", color: .orange,
                title: "No Common Encryption",
                explanation: "This VPN's server and your Mac couldn't agree on a cipher.",
                advice: "Older servers may need \u{201C}Allow older data ciphers\u{201D} — or, for very old ones, \u{201C}Allow outdated encryption\u{201D} — in Options ▸ Security. Both trade some security for compatibility.")
        case .tunSetup:
            Presentation(symbol: "gearshape.arrow.trianglehead.2.clockwise.rotate.90", color: .red,
                title: "Couldn't Set Up the Tunnel",
                explanation: "macOS refused the tunnel's network setup.",
                advice: "Another VPN app may be active — disconnect or quit other VPN software, then try again.")
        case .conflict:
            Presentation(symbol: "arrow.triangle.2.circlepath.circle.fill", color: .orange,
                title: "Another VPN Took Over",
                explanation: "A different VPN configuration was started and superseded this one.",
                advice: "Disconnect the other VPN, then reconnect this one.")
        case .proxy:
            Presentation(symbol: "arrow.triangle.branch", color: .orange,
                title: "Proxy Problem",
                explanation: "The HTTP proxy refused or dropped the connection.",
                advice: "Check the proxy address, port and sign-in in Options ▸ Proxy — or turn the proxy off if this network doesn't need one.")
        case .serverHalt:
            Presentation(symbol: "hand.raised.fill", color: .orange,
                title: "Server Ended the Session",
                explanation: "The server asked this client to disconnect.",
                advice: "This is usually deliberate — maintenance, session limits, or an account issue. Try again in a moment; if it persists, contact the VPN's administrator.")
        case .unknown:
            Presentation(symbol: "exclamationmark.triangle.fill", color: .orange,
                title: "Connection Failed",
                explanation: "The tunnel ended unexpectedly.",
                advice: "Try connecting again. If it keeps failing, the checklist below usually points at the culprit.")
        }
    }
}

// MARK: - Degraded-link banners (passive, while connected)

/// Shown while the engine is reasserting (network changed / vanished) —
/// the train-going-into-a-tunnel state.
struct LinkInterruptionBanner: View {
    let reconnects: Int

    var body: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading, spacing: 1) {
                Text("Connection interrupted — reconnecting…").font(.callout.weight(.medium))
                Text("Your traffic is paused, not exposed. It resumes when the network comes back."
                     + (reconnects > 1 ? " (\(reconnects) reconnects this session)" : ""))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(.yellow.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}

/// Shown when passive traffic analysis says we're sending into the void.
struct LinkStalledBanner: View {
    let seconds: Int

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "wifi.exclamationmark").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 1) {
                Text("Nothing is coming back from the VPN").font(.callout.weight(.medium))
                Text("Your Mac has been sending for \(seconds) seconds with no reply — the network here may have silently dropped.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }
}
