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
    @Environment(\.openWindow) private var openWindow
    /// The last staged check for this VPN, when one has been run. It doesn't
    /// run itself: the card offers it, the user asks for it.
    @State private var ladders = ProbeLadderStore.shared
    @State private var report: DiagnosticsReport?
    @State private var probing = false
    @State private var showPortalAlert = false
    // Alternate-endpoint probing: when the configured location is unreachable
    // and the VPN advertises others, check them AUTOMATICALLY and offer the
    // switch — don't make the user discover the endpoint picker.
    @State private var altProbing = false
    @State private var reachableAlt: Endpoint?
    @State private var altChecked = false
    /// The network the last probe was STARTED on (not finished on): a probe that
    /// never came back must still count as covering its own network, or a change
    /// arriving mid-probe would be indistinguishable from no probe at all.
    /// Empty means nothing has been probed yet.
    @State private var probedNetworkKey = ""

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
            // WHERE it broke, visually: the path from this Mac to a working
            // tunnel with the failing hop marked. The checklist below carries
            // the detail; this carries the understanding.
            FailurePathDiagram(incident: incident, report: report, probing: probing,
                               serverName: host.isEmpty ? "VPN server" : host,
                               ladder: ladder)
            diagnosticsChecklist
            ladderSummary
            suggestions

            HStack {
                if report?.captivePortal == true {
                    Button("Open Sign-in Page") { openPortal() }
                        .buttonStyle(.glassProminent)
                }
                Button(ladder == nil ? "Check Step by Step\u{2026}" : "Check Again\u{2026}") {
                    openStagedCheck()
                }
                .help("Runs each step of this VPN's own handshake in order and shows exactly where it stops")
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
        // The card stays until a connect SUCCEEDS — but the diagram must not
        // keep blaming a network the user already left. Re-probe on every
        // network change so a fixed path turns green (with "try again") by
        // itself, per the probe-don't-ask rule.
        .task(id: NetworkMemory.shared.current?.key) {
            // Not "did the first probe finish" — a first probe still in flight
            // (or one that failed to produce a report) left the diagram blaming
            // the old network just the same. Only the very first run is skipped,
            // because the incident task above already owns it.
            guard !probedNetworkKey.isEmpty, probedNetworkKey != NetworkChange.key else { return }
            altChecked = false          // other locations answer differently here
            reachableAlt = nil
            await probe()
        }
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
                Text("Checking the VPN's availability…").font(.callout).foregroundStyle(.secondary)
            }
        } else if let report {
            VStack(alignment: .leading, spacing: 5) {
                checkRow(ok: !report.dnsFailed,
                         okText: "\(host) resolves (\(report.resolvedIPs.joined(separator: ", ")))",
                         badText: "\(host) doesn't resolve — DNS is failing on this network")
                if let reachable = report.tcpReachable {
                    checkRow(ok: reachable,
                             okText: "The VPN answers" + (report.rttMilliseconds.map { " (\($0) ms)" } ?? ""),
                             badText: "The VPN isn't answering on port \(port) — it may be blocked here")
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

    // MARK: The staged check

    private var ladder: ProbeLadder? { ladders.ladder(for: profile.id) }

    /// The one line the detailed check adds here: which rung stopped, in its own
    /// words. The full ladder lives in Network Tools; this card stays a summary.
    @ViewBuilder private var ladderSummary: some View {
        if let ladder, ladder.isComplete {
            Divider()
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: ladder.firstFailure == nil ? "checkmark.seal.fill" : "list.bullet.indent")
                    .foregroundStyle(ladder.firstFailure == nil ? Color.green : .orange)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Step-by-step check").font(.callout.weight(.semibold))
                    Text(ladder.summary)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
    }

    /// Hand Network Tools this VPN and let it run the ladder there — one place
    /// for the detail, rather than a second copy of it inside the card.
    private func openStagedCheck() {
        let target = host.isEmpty ? profile.server : host
        guard !target.isEmpty else { return }
        NetworkToolsRequest.shared.probe(
            host: target, port: port, proto: nil, vpnKind: profile.kind,
            ladderKey: ProbeLadderKey.make(kind: profile.kind, id: profile.id))
        openWindow(id: "tools")
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
        probedNetworkKey = NetworkChange.key
        let result = await ConnectionDiagnostics.run(
            host: host, port: port, tryTLS: speaksTLS,
            baseline: ConnectionBaselineStore.load(profile: profile.id),
            networkKey: NetworkMemory.shared.current?.key)
        report = result
        probing = false
        vpn.captivePortalSuspected = result.captivePortal   // feeds the dot state
        vpn.setProbeResult(result, for: profile.id)         // feeds the Connection Doctor
        if result.captivePortal { showPortalAlert = true }
        // The configured location is dead but the internet works → check the
        // VPN's OTHER locations before the user has to think about it.
        if result.tcpReachable == false, !result.captivePortal {
            await probeAlternates()
        }
    }

    // MARK: Suggestions ("what to try", from what the probes found)

    private var endpoints: [Endpoint] {
        vpn.ovpnText(id: profile.id).map { EndpointScanner.endpoints(in: $0) } ?? []
    }
    private var endpointPinned: Bool { vpn.overrides(for: profile.id).server != nil }

    private func probeAlternates() async {
        guard !altChecked, endpoints.count > 1 else { return }
        altProbing = true
        defer { altProbing = false; altChecked = true }
        for e in endpoints.prefix(6) where e.host != host {
            if Task.isCancelled { return }
            let r = await ConnectionDiagnostics.run(host: e.host, port: e.port ?? port,
                                                    tryTLS: false, baseline: nil)
            if r.tcpReachable == true {
                reachableAlt = e
                return
            }
        }
    }

    @ViewBuilder private var suggestions: some View {
        let wifiHistory = NetworkMemory.shared.knownUnreachableHere(profile: profile.id)
        if wifiHistory != nil || altProbing || reachableAlt != nil {
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Label("What to try", systemImage: "lightbulb")
                    .font(.callout.weight(.semibold))
                if let networkLabel = wifiHistory {
                    Label("Try a different Wi-Fi network — \(networkLabel) has had trouble reaching this VPN before.",
                          systemImage: "wifi.exclamationmark")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if altProbing {
                    HStack(spacing: 8) {
                        DrawnSpinner()
                        Text("Checking this VPN's other locations\u{2026}")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                } else if let alt = reachableAlt {
                    Label("Good news — the \(alt.host) location answers from this network.",
                          systemImage: "checkmark.circle")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Switch to \(alt.host) and Try Again") { switchAndRetry(alt) }
                            .buttonStyle(.glassProminent).controlSize(.small)
                        if endpointPinned {
                            Button("Use Automatic Instead") { autoAndRetry() }
                                .buttonStyle(.glass).controlSize(.small)
                                .help("Automatic tries each of this VPN's locations until one answers")
                        }
                    }
                }
            }
        }
    }

    private func switchAndRetry(_ e: Endpoint) {
        Task {
            await vpn.applyDoctorFix(.overrides { o in
                o.server = e.host
                o.port = e.port
                o.proto = e.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) }
            }, to: profile.id, undoLabel: "endpoint: \(e.host)")
            vpn.dismissIncident(id: profile.id)
            try? await vpn.connectUsingConfiguredSource(
                id: profile.id, typedOTP: vpn.transientCredentials(for: profile.id).otp)
        }
    }

    private func autoAndRetry() {
        Task {
            await vpn.applyDoctorFix(.overrides { o in
                o.server = nil
                o.port = nil
                o.proto = nil
            }, to: profile.id, undoLabel: "endpoint: Automatic")
            vpn.dismissIncident(id: profile.id)
            try? await vpn.connectUsingConfiguredSource(
                id: profile.id, typedOTP: vpn.transientCredentials(for: profile.id).otp)
        }
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

// (The degraded-link banners — LinkInterruptionBanner / LinkStalledBanner — are
// gone: connection state has ONE spot in the window, the header badge and its
// plain-English problem chip. Details live in the opt-in Connection Manager.)

// MARK: - Failure path diagram

/// The connection's journey as five hops — this Mac → this network → the
/// internet → the VPN server → the sign-in — with the automatic probes' verdict
/// drawn on each: green got through, red is where it broke, indigo is a sign-in
/// page in the way, grey was never reached. Non-technical users read WHERE it
/// failed at a glance; the checklist underneath carries the specifics.
struct FailurePathDiagram: View {
    let incident: TunnelIncident
    let report: DiagnosticsReport?
    let probing: Bool
    let serverName: String
    /// A completed step-by-step check, when one has been run. It OUTRANKS the
    /// generic probes below: the ladder actually tried this VPN's own keys and
    /// certificates, so where it stopped is a better answer than "the port
    /// answered". Absent (the default), the diagram behaves exactly as before.
    var ladder: ProbeLadder? = nil

    private enum HopState: Equatable {
        case ok, failed, portal, unknown
        var color: Color {
            switch self {
            case .ok: .green
            case .failed: .red
            case .portal: .indigo
            case .unknown: Color.gray.opacity(0.45)
            }
        }
        /// The verdict in words for the diagram's combined accessibility value.
        var accessibilityWord: String {
            switch self {
            case .ok: "OK"
            case .failed: "failed"
            case .portal: "sign-in page in the way"
            case .unknown: "not checked"
            }
        }
    }
    private struct Hop {
        let icon: String
        let label: String
        var state: HopState = .unknown
        var verdict: String? = nil   // plain-English, only on the failing hop
    }

    private var hops: [Hop] {
        var mac = Hop(icon: "laptopcomputer", label: "Your Mac", state: .ok)
        var network = Hop(icon: "wifi", label: "This network")
        var internet = Hop(icon: "globe", label: "Internet")
        var server = Hop(icon: "server.rack", label: "The VPN")
        var signIn = Hop(icon: "person.badge.key", label: "Sign-in")

        func done(_ hops: [Hop]) -> [Hop] { hops }

        // The staged check ran and knows precisely where it stopped — say that,
        // and leave every hop before it green because they were all proved.
        if let ladder, ladder.isComplete {
            network.state = .ok
            internet.state = .ok
            if let failure = ladder.firstFailure {
                switch failure.stage.diagramHop {
                case .network:
                    network.state = .failed; network.verdict = failure.detail
                    internet.state = .unknown
                case .internet:
                    internet.state = .failed; internet.verdict = failure.detail
                case .server:
                    server.state = .failed; server.verdict = failure.detail
                case .signIn:
                    server.state = .ok
                    signIn.state = .failed; signIn.verdict = failure.detail
                }
                return done([mac, network, internet, server, signIn])
            }
            server.state = .ok
            // Nothing failed, and the ladder stops short of the sign-in on
            // purpose — so the sign-in hop stays grey rather than claiming a
            // pass it never tested.
            if !ladder.hasUntestedSignIn { signIn.state = .ok }
            server.verdict = ladder.hasUntestedSignIn
                ? "Everything up to the sign-in checks out. The sign-in itself wasn\u{2019}t tested."
                : "Every step checked out \u{2014} try connecting again."
            return done([mac, network, internet, server, signIn])
        }

        if probing || (report == nil && incident.category == .unknown) {
            return done([mac, network, internet, server, signIn])
        }

        if let report {
            if report.captivePortal {
                network.state = .ok
                internet.state = .portal
                internet.verdict = "A Wi-Fi sign-in page is blocking the way — sign in there first."
                return done([mac, network, internet, server, signIn])
            }
            if report.dnsFailed, report.tcpReachable != true {
                network.state = .ok
                internet.state = .failed
                internet.verdict = "This network isn't reaching the internet (name lookups fail)."
                return done([mac, network, internet, server, signIn])
            }
            network.state = .ok
            internet.state = .ok
            if report.tcpReachable == false {
                server.state = .failed
                server.verdict = "The internet works here, but the VPN never answered."
                return done([mac, network, internet, server, signIn])
            }
            server.state = .ok
            // The failure was network-shaped and the path is CLEAR now (Wi-Fi
            // changed, portal solved, outage over): say so, positively — the
            // diagram's job includes announcing that the problem is gone.
            let networkShaped: Set<IncidentCategory> = [.network, .timeout, .dns, .proxy]
            if report.tcpReachable == true, !report.dnsFailed,
               networkShaped.contains(incident.category) {
                signIn.state = .unknown
                server.verdict = "The path to the VPN looks clear from this network now — try connecting again."
                return done([mac, network, internet, server, signIn])
            }
        }

        // The wire worked (or was never probed) — the incident says the rest.
        switch incident.category {
        case .auth:
            if report == nil { network.state = .ok; internet.state = .ok; server.state = .ok }
            signIn.state = .failed
            signIn.verdict = "The VPN answered but rejected the sign-in — wrong password or a stale one-time code."
        case .dns:
            internet.state = .failed
            internet.verdict = "The VPN's address can't be looked up on this network."
            server.state = .unknown
        case .timeout, .network:
            if report == nil { network.state = .ok }
            server.state = server.state == .ok ? .failed : server.state
            if server.state == .failed && server.verdict == nil {
                server.verdict = "The VPN stopped answering partway through connecting."
            } else if server.state == .unknown {
                server.state = .failed
                server.verdict = "The VPN couldn't be reached."
            }
        case .tlsIdentity, .cipher:
            server.state = .failed
            server.verdict = "Something answered, but it doesn't look like the right VPN (a certificate or security mismatch)."
        case .proxy:
            internet.state = .failed
            internet.verdict = "The proxy between you and the internet refused the connection."
        case .tunSetup, .conflict:
            signIn.state = .ok
            server.verdict = nil
            mac.state = .failed
            mac.verdict = incident.category == .conflict
                ? "Another VPN on this Mac took over the connection."
                : "macOS refused to apply the tunnel's network settings."
        case .serverHalt:
            server.state = .failed
            server.verdict = "The VPN told SimpleVPN to disconnect."
        case .unknown:
            break
        }
        return done([mac, network, internet, server, signIn])
    }

    /// Aligns the connector lines to the CIRCLES' vertical centers, not the
    /// centre of circle+caption (which put lines below the circles).
    private struct HopCenter: AlignmentID {
        static func defaultValue(in d: ViewDimensions) -> CGFloat { d[VerticalAlignment.center] }
    }
    private static let hopCenter = VerticalAlignment(HopCenter.self)
    // nonisolated: alignment guides are evaluated by the layout engine off the
    // main actor, so the metric it reads must not be actor-isolated.
    nonisolated private static let circleSize: CGFloat = 38
    private static let columnWidth: CGFloat = 76

    var body: some View {
        let hops = self.hops
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: Self.hopCenter, spacing: 0) {
                ForEach(Array(hops.enumerated()), id: \.offset) { index, hop in
                    if index > 0 {
                        // The link INTO a hop carries that hop's verdict color.
                        // Negative padding tucks the line ends under the fixed-
                        // width columns so it visually meets each circle; the
                        // circles' solid backing hides it underneath.
                        Rectangle()
                            .fill(hop.state.color.opacity(hop.state == .unknown ? 0.4 : 0.8))
                            .frame(height: 2)
                            .frame(maxWidth: .infinity)
                            .alignmentGuide(Self.hopCenter) { $0[VerticalAlignment.center] }
                            .padding(.horizontal, -(Self.columnWidth - Self.circleSize) / 2 + 3)
                            .zIndex(-1)
                    }
                    node(hop)
                }
            }
            if let verdict = hops.compactMap(\.verdict).first {
                Label(verdict, systemImage: "arrow.up.right")
                    .font(.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
            } else if probing {
                Text("Checking the VPN's availability\u{2026}").font(.callout).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(hops.compactMap(\.verdict).first ?? "Connection path")
        // The per-hop verdicts as the element's value, so VoiceOver hears the
        // same story the colors tell: "Your Mac: OK, this network: OK, …".
        .accessibilityValue(hops.map { "\($0.label): \($0.state.accessibilityWord)" }
            .joined(separator: ", "))
    }

    private func node(_ hop: Hop) -> some View {
        VStack(spacing: 4) {
            ZStack {
                // Solid backing so the tucked-under connector line can't show
                // through the translucent tint fill.
                Circle().fill(.background)
                Circle()
                    .fill(hop.state.color.opacity(hop.state == .unknown ? 0.15 : 0.22))
                Circle()
                    .strokeBorder(hop.state.color, lineWidth: hop.verdict == nil ? 1.5 : 2.5)
                Image(systemName: hop.icon)
                    .font(.system(size: 15))
                    .foregroundStyle(hop.state.color)
            }
            .frame(width: Self.circleSize, height: Self.circleSize)
            .overlay(alignment: .topTrailing) {
                switch hop.state {
                case .failed:
                    badge("xmark.circle.fill", .red)
                case .portal:
                    badge("exclamationmark.circle.fill", .indigo)
                case .ok:
                    badge("checkmark.circle.fill", .green)
                case .unknown:
                    EmptyView()
                }
            }
            Text(hop.label)
                .font(.caption2)
                .foregroundStyle(hop.verdict == nil ? .secondary : .primary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: Self.columnWidth)
        }
        // Every column the same width (captions no longer skew the gaps), and
        // the alignment guide pins connectors to the circles' centre line.
        .frame(width: Self.columnWidth)
        .alignmentGuide(Self.hopCenter) { _ in Self.circleSize / 2 }
        .zIndex(1)
    }

    private func badge(_ symbol: String, _ color: Color) -> some View {
        Image(systemName: symbol)
            .font(.system(size: 12))
            .foregroundStyle(color)
            .background(Circle().fill(.background).padding(1))
            .offset(x: 4, y: -3)
    }
}
