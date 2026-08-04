// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkToolsView.swift
//  Native diagnostics (no subprocesses): a live latency + packet-loss graph, a
//  traceroute, a DNS test that shows which server answered and where it is, an MTU
//  test (ICMP DF sizing, or negotiated MSS + blackhole detection for TCP/TLS/HTTP)
//  judged against the active tunnel's MTU, and a flow "railroad" — this device → the
//  VPN hop(s) → internet egress → the target — each node carrying its name,
//  IPv4/IPv6 and reverse lookup.
//

import SwiftUI
import Charts
import Accessibility

// MARK: - Live latency

@MainActor
@Observable
final class LatencyMonitor {
    struct Sample: Identifiable, Sendable { let id: Int; let rttMS: Double? }  // nil = lost
    private(set) var samples: [Sample] = []
    private(set) var lastRTT: Double?
    private(set) var lossPercent: Double = 0
    private(set) var targetIP: String?

    private var task: Task<Void, Never>?
    private var seq = 0

    /// How long an address is trusted before the name is asked again. Plain DNS
    /// changes (short TTLs, failover) don't move the network fingerprint, so the
    /// only way to follow them is to re-ask.
    static let reresolveAfter: TimeInterval = 60

    /// Whether the address being pinged should be looked up again: either the
    /// machine moved network (split-horizon DNS gives a different answer there)
    /// or the answer is simply old. Pure, so the policy is testable without a
    /// live network or a real path monitor.
    static func shouldReresolve(networkKey: String?, resolvedOn: String?,
                                age: TimeInterval) -> Bool {
        networkKey != resolvedOn || age >= reresolveAfter
    }

    func start(host: String, boundIf: UInt32 = 0) {
        stop()
        task = Task { [weak self] in
            // Ping the first IPv4 (unprivileged ICMP is v4 here).
            var target = await NetworkProbes.resolve(host: host).v4.first ?? host
            guard let self, !Task.isCancelled else { return }   // a restart may have superseded us
            var resolvedOn = NetworkMemory.shared.current?.key
            var resolvedAt = Date()
            self.targetIP = target
            while !Task.isCancelled {
                let r = await NetworkProbes.pingOnce(host: target, seq: UInt16(truncatingIfNeeded: self.seq), boundIf: boundIf)
                // stop() may have fired (and cleared samples) while we were awaiting
                // the ping — don't append a stale sample into a cleared/next session.
                guard !Task.isCancelled else { return }
                self.tick(r)
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { return }

                let key = NetworkMemory.shared.current?.key
                guard Self.shouldReresolve(networkKey: key, resolvedOn: resolvedOn,
                                           age: Date().timeIntervalSince(resolvedAt)) else { continue }
                resolvedOn = key
                resolvedAt = Date()
                // Keep pinging the old address if the name stops resolving —
                // losing the graph tells the user less than stale packet loss.
                if let fresh = await NetworkProbes.resolve(host: host).v4.first, fresh != target {
                    guard !Task.isCancelled else { return }
                    target = fresh
                    self.targetIP = fresh
                }
            }
        }
    }
    func stop() { task?.cancel(); task = nil; samples = []; seq = 0; lastRTT = nil; lossPercent = 0; targetIP = nil }

    private func tick(_ r: NetworkProbes.PingReply) {
        seq += 1
        samples.append(Sample(id: seq, rttMS: r.rttMS))
        if samples.count > 60 { samples.removeFirst(samples.count - 60) }
        lastRTT = r.rttMS
        let lost = samples.filter { $0.rttMS == nil }.count
        lossPercent = samples.isEmpty ? 0 : Double(lost) / Double(samples.count) * 100
    }
    var scaleMax: Double { max(20, samples.compactMap { $0.rttMS }.max() ?? 0) }
}

// MARK: - A resolved node for the flow railroad / lists

struct NetNode: Identifiable {
    let id = UUID()
    var label: String
    var symbol: String
    var ipv4: String?
    var ipv6: String?
    var reverse: String?
    var countryCode: String?
    var subtitle: String?
}

// MARK: - Tools view

struct NetworkToolsView: View {
    @Bindable var vpn: VPNController
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?
    @Environment(ProfileEvaluator.self) private var evaluator: ProfileEvaluator?
    // The other three places a saved VPN can live. Optional so the window still
    // works when it's opened somewhere they aren't injected.
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(WireGuardStore.self) private var wireguard: WireGuardStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?

    @State private var target = ""
    @FocusState private var targetFocused: Bool
    /// Which egress the diagnostics go out of. Automatic = a normal, route-table-obeying
    /// socket (today's behavior); the others pin the probe sockets to a chosen
    /// interface via `IP_BOUND_IF` so reachability/latency can be tested THROUGH a
    /// specific tunnel even when routing wouldn't send it there.
    @State private var egress: ProbeEgress = .automatic
    @State private var request = NetworkToolsRequest.shared
    @State private var latency = LatencyMonitor()
    @State private var running = false
    @State private var hops: [NetworkProbes.TraceHop] = []
    @State private var hopNames: [Int: String] = [:]
    @State private var dnsAnswers: [DNSAnswer] = []
    @State private var dnsServerNode: NetNode?

    /// One resolver's answer. `matchesOS` marks the server whose answer equals what
    /// the OS actually resolved (getaddrinfo) — i.e. the one macOS took it from.
    struct DNSAnswer: Identifiable {
        let id = UUID()
        let server: String
        let result: NetworkProbes.DNSResult?
        let reverse: String?
        let matchesOS: Bool
    }
    @State private var targetNode: NetNode?
    @State private var tracing = false
    @State private var probeTasks: [Task<Void, Never>] = []

    // MTU test: the protocol picker plus whichever result kind it produces. Tracked
    // in its own task so changing the protocol re-runs only this probe.
    @State private var mtuProto: NetworkProbes.MTUProtocol = .icmp
    @State private var mtuPortText = ""
    @State private var pathMTU: NetworkProbes.PathMTUResult?
    @State private var transportMTU: NetworkProbes.TransportMTUResult?
    @State private var mtuRunning = false
    @State private var mtuTask: Task<Void, Never>?

    // VPN protocol fingerprint + captive portal. Both run on every test: "what is
    // actually answering there" and "is something intercepting my traffic" are the
    // two questions that make every other number meaningless when they go wrong.
    @State private var probeKind: VPNKind?
    @State private var probeTransport: VPNProbe.Transport = .auto
    @State private var probePortText = ""
    @State private var fingerprint: VPNProbe.Fingerprint?
    @State private var probeRunning = false
    @State private var probeTask: Task<Void, Never>?
    @State private var portal: PortalCheck?
    @State private var portalTask: Task<Void, Never>?

    struct PortalCheck: Equatable { var detected: Bool; var url: URL? }

    // The staged, authenticated check. Separate from the anonymous fingerprint
    // above it on purpose: the fingerprint asks "what is that?", the ladder asks
    // "would MY configuration get in?", and both answers are worth having.
    @State private var ladderRunner = ProbeLadderRunner()
    @State private var ladderKey: String = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                targetBar
                routingStateCard
                dnsStateCard
                proxyStateCard
                ladderSection
                vpnProbeCard
                if hasResults {
                    flowRailroad
                    latencyCard
                    mtuCard
                    tracerouteCard
                    dnsCard
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 620, minHeight: 640)
        .navigationTitle("Network Tools")
        // Opened from the connect-failure toast: adopt the host it was trying to reach.
        // `initial: true` matters — the request is set before this window exists.
        .onChange(of: request.generation, initial: true) { adoptRequest() }
        // Every number on this page — the resolved node, which resolver answered,
        // the hops, the MTU — belongs to the network it was measured on, and a
        // split-horizon name resolves somewhere else entirely on the next one.
        // One re-run per settle (the fingerprint is already debounced), and only
        // when there is something on screen to invalidate.
        .onChange(of: NetworkMemory.shared.current?.key) { _, _ in
            guard !target.trimmingCharacters(in: .whitespaces).isEmpty,
                  running || hasResults else { return }
            run()
        }
        // Initial focus: the target field — the window exists to test an address.
        .onAppear { topo?.startWatching(); targetFocused = true }      // need the routing table to classify the path
        .onDisappear {
            topo?.stopWatching()
            stop()                          // cancel latency/traceroute/DNS/resolve/MTU
            ladderRunner.cancel()           // …and drop whatever key material it held
        }
    }

    private var hasResults: Bool {
        latency.targetIP != nil || !hops.isEmpty || !dnsAnswers.isEmpty
            || mtuRunning || pathMTU != nil || transportMTU != nil
    }

    // MARK: The staged check

    /// Every saved VPN, from all four stores, as (key, menu label). Built from
    /// names only — nothing is read out of a profile until one is chosen.
    private var ladderChoices: [(key: String, label: String)] {
        var out: [(String, String)] = []
        for p in vpn.profiles {
            out.append((ProbeLadderKey.make(kind: p.kind, id: p.id), "\(p.name) \u{2014} \(p.kind.displayName)"))
        }
        for t in tunnels?.tunnels ?? [] {
            out.append((ProbeLadderKey.make(kind: t.kind, id: t.id), "\(t.name) \u{2014} \(t.kind.displayName)"))
        }
        for w in wireguard?.configs ?? [] {
            out.append((ProbeLadderKey.make(kind: .wireGuard, id: w.id), "\(w.name) \u{2014} WireGuard"))
        }
        for n in nativeVPN?.configs ?? [] {
            out.append((ProbeLadderKey.make(kind: n.kind, id: n.id), "\(n.name) \u{2014} \(n.kind.displayName)"))
        }
        return out
    }

    /// Read the chosen VPN's material, at the moment of the click and no sooner.
    private func ladderFacts(for key: String) -> ProbeTargetFacts? {
        guard let (kind, id) = ProbeLadderKey.split(key) else { return nil }
        if let profile = vpn.profiles.first(where: { $0.id == id && $0.kind == kind }) {
            return .resolve(profile: profile, vpn: vpn, evaluator: evaluator)
        }
        if let tunnel = tunnels?.tunnels.first(where: { $0.id == id }) {
            return .resolve(tunnel: tunnel)
        }
        if kind == .wireGuard, let config = wireguard?.configs.first(where: { $0.id == id }) {
            return .resolve(wireGuard: config)
        }
        if let native = nativeVPN?.configs.first(where: { $0.id == id }) {
            return .resolve(native: native)
        }
        return nil
    }

    // MARK: Routing state (the Route mediator's live effective state)
    //
    // Everything here reads the mediator's PUBLISHED state (`vpn.routes.*`, all
    // `@Observable`) — the current default owner, each connected tunnel's live role,
    // and the last external-drift event — so the panel reflects reality, not the stored
    // preference. "Re-assert" drives the mediator to reconcile the OS back to desired.
    @ViewBuilder private var routingStateCard: some View {
        let owner = vpn.routes.displayedGatewayOwner
        let ownerName = vpn.routes.name(for: owner)
        let participants = vpn.routes.connectedProfiles
        GroupBox("Routing") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: owner == nil ? "arrow.up.forward" : "lock.shield.fill")
                            .foregroundStyle(owner == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.accentColor))
                            .accessibilityHidden(true)
                        Text("Default gateway:")
                            .foregroundStyle(.secondary)
                        Text(ownerName ?? "Direct").fontWeight(.medium)
                    }
                    .accessibilityElement(children: .combine)
                    Spacer()
                    // Three windows-worth of bare "Re-assert" buttons — name the subject.
                    Button("Re-assert") { vpn.routes.reassertNow() }
                        .controlSize(.small)
                        .help("Drive routing back to the intended default owner now.")
                        .disabled(participants.isEmpty)
                        .accessibilityLabel("Re-assert routing")
                }
                .font(.callout)

                if !participants.isEmpty {
                    Divider()
                    ForEach(participants) { p in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(vpn.routes.gatewayRole(for: p.id) == .full ? Color.accentColor : Color.secondary)
                                .frame(width: 7, height: 7)
                                .accessibilityHidden(true)   // the role sentence carries it
                            Text(p.name)
                            Spacer()
                            Text(vpn.routes.gatewayRole(for: p.id) == .full ? "full — carries the default" : "split — its subnets only")
                                .foregroundStyle(.secondary)
                        }
                        .font(.caption)
                        .accessibilityElement(children: .combine)
                    }
                }

                Divider()
                if let drift = vpn.routes.lastDrift {
                    driftLine(drift)
                } else {
                    Label("No external routing changes detected.", systemImage: "checkmark.seal")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: DNS state (the DNS mediator's live effective state — P2)
    //
    // Reads the mediator's PUBLISHED state (`vpn.dns.*`, all `@Observable`): the
    // effective catch-all owner + its resolvers, the split-DNS domain assignments, the
    // resolvers the OS is actually using (SCDynamicStore), and the last external-drift
    // event. "Re-assert" re-establishes the catch-all owner's DNS.
    @ViewBuilder private var dnsStateCard: some View {
        let plan = vpn.dns.plan
        let ownerName = vpn.dns.name(for: plan.catchAllOwner)
        GroupBox("DNS") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: plan.catchAllOwner == nil ? "network" : "lock.shield.fill")
                            .foregroundStyle(plan.catchAllOwner == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.accentColor))
                            .accessibilityHidden(true)
                        Text("Resolves through:").foregroundStyle(.secondary)
                        Text(ownerName ?? "Direct (system resolvers)").fontWeight(.medium)
                    }
                    .accessibilityElement(children: .combine)
                    Spacer()
                    Button("Re-assert") { vpn.dns.reassertNow() }
                        .controlSize(.small)
                        .help("Re-establish the intended resolvers now.")
                        .disabled(plan.catchAllOwner == nil)
                        .accessibilityLabel("Re-assert DNS")
                }
                .font(.callout)

                if !plan.systemResolvers.isEmpty {
                    Text(plan.systemResolvers.joined(separator: ", "))
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if !plan.perDomain.isEmpty {
                    Divider()
                    ForEach(plan.perDomain) { a in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(a.domains.joined(separator: " · "))
                                .font(.caption).foregroundStyle(.secondary)
                            Text("→").font(.caption).foregroundStyle(.tertiary)
                            Text("\(vpn.dns.name(for: a.engine) ?? a.engine) (\(a.resolvers.joined(separator: ", ")))")
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        // One sentence; the "→" glyph becomes words.
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(a.domains.joined(separator: ", ")) resolve through \(vpn.dns.name(for: a.engine) ?? a.engine), \(a.resolvers.joined(separator: ", "))")
                    }
                }

                Divider()
                if !vpn.dns.observedResolvers.isEmpty {
                    Text("System now uses: \(vpn.dns.observedResolvers.joined(separator: ", "))")
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                }
                if let drift = vpn.dns.lastDrift {
                    driftLine(drift)
                } else {
                    Label("No external DNS changes detected.", systemImage: "checkmark.seal")
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: Proxy state (the Proxy mediator's live effective state — P3)
    @ViewBuilder private var proxyStateCard: some View {
        let plan = vpn.proxies.plan
        let ownerName = vpn.proxies.name(for: plan.owner)
        GroupBox("Proxy") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: plan.providesProxy ? "server.rack" : "arrow.up.forward")
                            .foregroundStyle(plan.providesProxy ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.secondary))
                            .accessibilityHidden(true)
                        Text("System proxy:").foregroundStyle(.secondary)
                        Text(vpn.proxies.effectiveProxyDescription).fontWeight(.medium)
                    }
                    .accessibilityElement(children: .combine)
                    Spacer()
                    Button("Re-assert") { vpn.proxies.reassertNow() }
                        .controlSize(.small)
                        .help("Re-apply the intended system proxy now.")
                        .disabled(!plan.providesProxy)
                        .accessibilityLabel("Re-assert proxy")
                }
                .font(.callout)

                if let ownerName, plan.providesProxy {
                    Text("from \(ownerName)").font(.caption).foregroundStyle(.secondary)
                }
                // Where the proxy's sign-in landed (only shown when it needs one):
                // applied, or NOT injectable and why — never silently dropped.
                if let advisory = vpn.proxies.authAdvisory {
                    Label(advisory.message(owner: ownerName), systemImage: advisory.symbol)
                        .font(.caption)
                        .foregroundStyle(advisory == .applied ? AnyShapeStyle(.secondary)
                                                              : AnyShapeStyle(Color.orange))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Divider()
                if vpn.proxies.observed.enabled, let e = vpn.proxies.observed.endpoint {
                    Text("System now: \(e.display)")
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                } else if vpn.proxies.observed.enabled, let pac = vpn.proxies.observed.pacURL {
                    Text("System now: PAC \(pac)")
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
                if let drift = vpn.proxies.lastDrift {
                    driftLine(drift)
                } else {
                    Label("No external proxy changes detected.", systemImage: "checkmark.seal")
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// One shared drift line (used by the DNS + Proxy cards) — icon, summary, time.
    @ViewBuilder private func driftLine(_ drift: MediatorDriftEvent) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "exclamationmark.arrow.triangle.2.circlepath")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(drift.summary).foregroundStyle(.secondary)
                Text("\(drift.at.formatted(.relative(presentation: .named)))\(drift.reasserted ? " · re-asserted" : "")")
                    .foregroundStyle(.tertiary)
            }
        }
        .font(.caption)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var ladderSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            ladderControls
            if let facts = ladderRunner.facts, isLadderProfileConnected(facts) {
                Label("This VPN is connected right now. The checks are sent out the physical network, not through the tunnel, so they test the real path rather than answering their own hello.",
                      systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let problem = ladderRunner.signInProblem {
                Label("\(problem.title). \(problem.explanation)", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let ladder = ladderRunner.ladder {
                ProbeLadderCard(
                    ladder: ladder,
                    isRunning: ladderRunner.isRunning,
                    testSignIn: ladderRunner.facts.map { facts in
                        { ladderRunner.runIncludingSignIn(facts, vpn: vpn) }
                    },
                    rerun: { ladderRunner.checkAgain(vpn: vpn) })
                if let note = rerunModeNote, !ladderRunner.isRunning {
                    Label(note, systemImage: "arrow.clockwise")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    /// One line saying how the last re-check went — everything, or just the rung
    /// that hadn't passed — so "Check Again" is never a silent no-op.
    private var rerunModeNote: String? {
        switch ladderRunner.lastRerun {
        case .incremental:
            return "The network hadn\u{2019}t changed, so only the step that hadn\u{2019}t passed was re-checked."
        case .incrementalSignIn:
            return "The network hadn\u{2019}t changed, so only the sign-in was re-checked."
        case .full:
            return "The network changed, so every step was re-checked."
        case .none:
            return nil
        }
    }

    /// Is the VPN this ladder belongs to connected right now? That is the context
    /// that made the old behavior confusing — a probe that went THROUGH the VPN it
    /// was testing — so it is worth naming on screen.
    private func isLadderProfileConnected(_ facts: ProbeTargetFacts) -> Bool {
        let id = facts.profileID
        guard !id.isEmpty else { return false }
        if vpn.profiles.contains(where: { $0.id == id && UI.isActive($0.status) }) { return true }
        if let s = reach?.latestStats[id], !s.tunnelIPv4.isEmpty { return true }
        if facts.kind.isSingletonNative, nativeVPN?.status == .connected,
           nativeVPN?.configs.contains(where: { $0.id == id }) == true { return true }
        return false
    }

    @ViewBuilder private var ladderControls: some View {
        let choices = ladderChoices
        if !choices.isEmpty {
            HStack {
                Picker("Check a saved VPN", selection: $ladderKey) {
                    Text("Choose a VPN\u{2026}").tag("")
                    ForEach(choices, id: \.key) { Text($0.label).tag($0.key) }
                }
                .labelsHidden().fixedSize()
                .help("Runs each step of this VPN's own handshake in order \u{2014} its address, this network, its shared key and certificates \u{2014} and shows exactly where it stops.")
                Button("Check Step by Step") { runLadder() }
                    .disabled(ladderKey.isEmpty || ladderRunner.isRunning)
                Spacer()
            }
        }
    }

    private func runLadder() {
        guard let facts = ladderFacts(for: ladderKey) else { return }
        ladderRunner.run(facts)
    }

    // MARK: VPN probe (what kind of VPN answers there) + captive portal

    private var vpnProbeCard: some View {
        GroupBox("VPN Probe") {
            VStack(alignment: .leading, spacing: 10) {
                probeControls
                if probeRunning {
                    Label("Asking \(target) what it speaks…", systemImage: "waveform.path.ecg")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if let f = fingerprint {
                    probeVerdict(f)
                    if f.findings.count > 1 || f.best == nil {
                        DisclosureGroup("What each test found (\(f.findings.count))") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(f.findings) { probeFindingRow($0) }
                            }
                            .padding(.top, 4)
                        }
                        .font(.caption)
                    }
                }
                captivePortalRow
                Text("The probe sends one harmless hello in each protocol's own language and reads the answer. Nothing is logged in and no session is made.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }.padding(6)
        }
    }

    private var probeControls: some View {
        HStack {
            TextField("Port", text: $probePortText, prompt: Text("\(defaultProbePort)"))
                .textFieldStyle(.roundedBorder).frame(width: 70)
                .onSubmit { restartVPNProbe() }
                .accessibilityLabel("Probe port")
            Picker("Transport", selection: $probeTransport) {
                ForEach(VPNProbe.Transport.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .accessibilityLabel("Probe transport")
            Picker("Kind", selection: $probeKind) {
                Text("Auto-detect").tag(VPNKind?.none)
                ForEach(VPNKind.allCases, id: \.self) { Text($0.displayName).tag(VPNKind?.some($0)) }
            }
            .labelsHidden().fixedSize()
            .help("Narrows the probe to one protocol. Auto-detect tries a small battery.")
            .accessibilityLabel("VPN kind to probe for")
            Spacer()
            Button("Probe") { restartVPNProbe() }
                .disabled(target.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    /// The plain-language headline. `best` is a positive protocol answer; without one
    /// the summary explains what silence does and doesn't mean.
    @ViewBuilder
    private func probeVerdict(_ f: VPNProbe.Fingerprint) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: f.best?.kind?.systemImage ?? (f.best != nil ? "checkmark.seal" : "questionmark.circle"))
                .foregroundStyle(f.best != nil ? Color.green : .secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(f.best.map { "VPN detected: \($0.label)" } ?? f.summary)
                    .font(.callout.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                if let best = f.best {
                    Text(best.detail).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func probeFindingRow(_ finding: VPNProbe.Finding) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: finding.detected ? "checkmark.circle.fill" : "minus.circle")
                .foregroundStyle(finding.detected ? Color.green : .secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(finding.probe).font(.caption.weight(.medium))
                Text(finding.label).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(finding.detail).font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if finding.detected {
                Text(finding.confidence.label).font(.caption2)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.green.opacity(0.15), in: Capsule())
            }
        }
        // One sentence, detected-state first (the glyph carried it before).
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(finding.detected ? "Detected" : "Not detected"): \(finding.probe). \(finding.label). \(finding.detail)\(finding.detected ? ". Confidence \(finding.confidence.label.lowercased())" : "")")
    }

    @ViewBuilder
    private var captivePortalRow: some View {
        if let portal {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: portal.detected ? "wifi.exclamationmark" : "checkmark.shield")
                    .foregroundStyle(portal.detected ? Color.orange : .green)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(portal.detected
                         ? "Something is intercepting traffic — a Wi-Fi sign-in page."
                         : "No sign-in page in the way.")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    if portal.detected {
                        Text("Until you sign in to this network, a VPN can't connect through it.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                Spacer(minLength: 8)
                if portal.detected, let url = portal.url {
                    Link("Open Sign-In Page", destination: url).font(.caption)
                }
            }
        }
    }

    /// Port the probe uses when the field is empty: whatever the chosen kind lives on.
    private var defaultProbePort: Int {
        switch probeKind {
        case .openVPN: 1194
        case .wireGuard: VPNProbe.wireGuardDefaultPort
        case .ikev2, .ipsec, .l2tp: VPNProbe.ikeDefaultPort
        case .ssh: 22
        case .some(let k) where k.isSSLVPN: 443
        default: 443
        }
    }

    private var targetBar: some View {
        HStack {
            TextField("Host or IP to test", text: $target, prompt: Text("example.com"))
                .textFieldStyle(.roundedBorder).autocorrectionDisabled()
                .onSubmit { run() }
                .focused($targetFocused)
            egressPicker
            Picker("MTU via", selection: $mtuProto) {
                ForEach(NetworkProbes.MTUProtocol.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .accessibilityLabel("MTU test technique")
            .help("Which technique the MTU test uses. Only ICMP can size the path with the don't-fragment bit; the TCP-based tests report the negotiated MSS and look for a blackhole.")
            if mtuProto.isTCP {
                TextField("Port", text: $mtuPortText,
                          prompt: Text("\(mtuProto.defaultPort ?? 443)"))
                    .textFieldStyle(.roundedBorder).frame(width: 64)
                    .onSubmit { restartMTU() }
                    .accessibilityLabel("MTU test port")
            }
            Button(running ? "Stop" : "Run") { running ? stop() : run() }
                .keyboardShortcut(.defaultAction)
                .disabled(target.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .onChange(of: mtuProto) { restartMTU() }
    }

    // MARK: Egress picker (send diagnostics out a chosen tunnel — IP_BOUND_IF)

    /// Where a diagnostic egresses. `.automatic` is a normal (unbound) socket that
    /// obeys the route table; `.direct` pins to the physical link; `.profile` pins to a
    /// connected route-participant's tunnel interface.
    enum ProbeEgress: Hashable {
        case automatic
        case direct
        case profile(String)   // profile id
    }

    private var egressPicker: some View {
        Menu {
            Picker("Egress", selection: $egress) {
                Text("Automatic").tag(ProbeEgress.automatic)
                let directName = physicalEgressName
                Text("Direct" + (directName == nil ? " (unavailable)" : ""))
                    .tag(ProbeEgress.direct)
                Divider()
                // Only route-participants can be an egress here — a proxy-only / native
                // kind has no bindable tunnel interface. Each is disabled with the
                // reason when its interface isn't up yet.
                ForEach(vpn.routes.connectedProfiles) { p in
                    if RouteMediator.participation(for: p.kind).appliesGatewayRole {
                        let name = tunnelInterfaceName(for: p.id)
                        Text(p.name + (name == nil ? " (not up)" : ""))
                            .tag(ProbeEgress.profile(p.id))
                    }
                }
            }
            .pickerStyle(.inline)
        } label: {
            Label(egressLabel, systemImage: "arrow.up.right.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        // No socket-option jargon in anything a person hears or reads.
        .help("Send the diagnostics out a specific tunnel, regardless of the route table. Automatic uses the normal routing.")
        .accessibilityLabel("Diagnostics egress")
        .accessibilityValue(egressLabel)
        // A chosen egress that isn't resolvable (interface not up) silently falls back
        // to Automatic at bind time — so the picker never sends a probe nowhere.
        .onChange(of: egress) { _, _ in if running { run() } }
    }

    private var egressLabel: String {
        switch egress {
        case .automatic: return "Automatic"
        case .direct: return "Direct"
        case .profile(let id): return vpn.routes.name(for: id) ?? "VPN"
        }
    }

    /// The BSD name for the chosen egress, or nil when it can't be resolved to an up
    /// interface (⇒ Automatic behavior at bind time).
    private func egressInterfaceName(_ e: ProbeEgress) -> String? {
        switch e {
        case .automatic: return nil
        case .direct: return physicalEgressName
        case .profile(let id): return tunnelInterfaceName(for: id)
        }
    }

    /// The `IP_BOUND_IF` index for the current selection (0 = Automatic/unbound).
    private var egressBoundIf: UInt32 {
        NetworkProbes.interfaceIndex(egressInterfaceName(egress))
    }

    /// The physical (non-tunnel) interface currently carrying traffic — "Direct".
    private var physicalEgressName: String? {
        topo?.topology.interfaces.first { $0.inUse && $0.kind != .tunnel }?.name
    }

    /// The tunnel interface a connected profile currently owns, matched by its live
    /// tunnel address (the same mapping the Routes graph uses). nil ⇒ not up yet.
    private func tunnelInterfaceName(for id: String) -> String? {
        guard let ip = (reach?.latestStats ?? [:])[id]?.tunnelIPv4, !ip.isEmpty,
              let iface = topo?.topology.interfaces.first(where: { $0.ipv4.contains(ip) })
        else { return nil }
        return iface.name
    }

    // MARK: Flow railroad (device → VPN(s) → egress → target)

    private var flowRailroad: some View {
        GroupBox("Path") {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 0) {
                    ForEach(Array(flowNodes.enumerated()), id: \.element.id) { i, node in
                        NetNodeChip(node: node)
                        if i < flowNodes.count - 1 {
                            Image(systemName: "arrow.right").foregroundStyle(.secondary).padding(.horizontal, 6)
                                .accessibilityHidden(true)   // reading order IS the path
                        }
                    }
                }.padding(6)
            }
        }
    }

    /// Route-aware path: what a packet to the target ACTUALLY traverses, not a
    /// hard-coded This Mac → VPN → Egress. A Tailscale/LAN destination bypasses the
    /// full-tunnel VPN, so it must not be drawn as going through it.
    private var flowNodes: [NetNode] {
        var nodes: [NetNode] = [thisMacNode]

        guard let target = targetNode else {   // no specific target yet → general picture
            appendVPNsAndEgress(&nodes)
            return nodes
        }

        if let ip = target.ipv4, let ifc = topo?.topology.egressInterface(forIPv4: ip) {
            if let match = ourVPN(for: ifc) {                 // over one of our VPNs → hop + egress
                nodes.append(vpnNode(id: match.key, stats: match.value))
                nodes.append(egressNode)
            } else if ifc.isTailscale {
                nodes.append(NetNode(label: "Tailscale", symbol: ifc.systemImage,
                                     subtitle: "mesh — not via the VPN"))
            } else if ifc.kind == .tunnel {
                nodes.append(NetNode(label: ifc.friendlyName, symbol: ifc.systemImage, subtitle: "tunnel"))
            } else {
                let priv = Self.isPrivate(ip)
                nodes.append(NetNode(label: priv ? "Local network" : "Internet",
                                     symbol: priv ? "house" : "globe",
                                     subtitle: "via \(ifc.friendlyName)"))
            }
        } else {
            appendVPNsAndEgress(&nodes)   // IPv6 target or routing table not yet read
        }
        nodes.append(target)
        return nodes
    }

    private var thisMacNode: NetNode {
        NetNode(label: "This Mac", symbol: "laptopcomputer",
                reverse: Host.current().localizedName,
                countryCode: publicIP.homeCountryCode,
                subtitle: "Home · \(publicIP.homeCountryName ?? "local network")")
    }
    private var egressNode: NetNode {
        NetNode(label: "Egress", symbol: "globe",
                ipv4: publicIP.publicIPv4, ipv6: publicIP.publicIPv6,
                countryCode: publicIP.countryCode, subtitle: publicIP.countryName)
    }
    private func vpnNode(id: String, stats s: TunnelStats) -> NetNode {
        let name = vpn.profiles.first { $0.id == id }?.name ?? "VPN"
        return NetNode(label: name, symbol: "lock.shield", ipv4: s.serverIP,
                       countryCode: s.serverIP.flatMap { GeoIP.shared?.countryCode(for: $0) },
                       subtitle: s.serverEndpoint.isEmpty ? nil : "VPN server")
    }
    private func appendVPNsAndEgress(_ nodes: inout [NetNode]) {
        for (id, s) in (reach?.latestStats ?? [:]).sorted(by: { $0.key < $1.key }) {
            nodes.append(vpnNode(id: id, stats: s))
        }
        nodes.append(egressNode)
    }
    /// The connected VPN (if any) that owns this egress interface — matched by the
    /// tunnel's in-tunnel IPv4 appearing among the interface's addresses.
    private func ourVPN(for ifc: NetInterface) -> (key: String, value: TunnelStats)? {
        (reach?.latestStats ?? [:]).first { _, s in
            !s.tunnelIPv4.isEmpty && ifc.ipv4.contains(s.tunnelIPv4)
        }
    }
    static func isPrivate(_ ip: String) -> Bool {
        guard let a = NetworkTopology.ipv4ToUInt32(ip) else { return false }
        func within(_ net: UInt32, _ plen: Int) -> Bool {
            let mask: UInt32 = plen == 0 ? 0 : (~UInt32(0)) << (32 - plen)
            return (a & mask) == (net & mask)
        }
        return within(0x0A00_0000, 8)      // 10/8
            || within(0xAC10_0000, 12)     // 172.16/12
            || within(0xC0A8_0000, 16)     // 192.168/16
            || within(0xA9FE_0000, 16)     // 169.254/16 link-local
            || within(0x7F00_0000, 8)      // 127/8 loopback
            || within(0x6440_0000, 10)     // 100.64/10 CGNAT / Tailscale
    }

    // MARK: Latency

    private var latencyCard: some View {
        GroupBox("Latency & Packet Loss") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 20) {
                    metric("Latency", latency.lastRTT.map { String(format: "%.0f ms", $0) } ?? "—")
                    metric("Loss", String(format: "%.0f%%", latency.lossPercent))
                    if let ip = latency.targetIP { metric("Target", ip) }
                    Spacer()
                }
                Chart(latency.samples) { s in
                    if let rtt = s.rttMS {
                        LineMark(x: .value("t", s.id), y: .value("ms", rtt)).foregroundStyle(.blue)
                        AreaMark(x: .value("t", s.id), y: .value("ms", rtt)).foregroundStyle(.blue.opacity(0.15))
                    } else {
                        // A drop: an ✕, not a colour-only dot — red alone can't
                        // distinguish it from the line for everyone.
                        PointMark(x: .value("t", s.id), y: .value("ms", 0))
                            .foregroundStyle(.red)
                            .symbol(.cross)
                    }
                }
                .chartYScale(domain: 0...latency.scaleMax)
                .chartXAxis(.hidden)
                .frame(height: 120)
                // The audio-graph rule from the throughput charts.
                .accessibilityChartDescriptor(LatencyChartDescriptor(
                    samples: latency.samples, lossPercent: latency.lossPercent,
                    scaleMax: latency.scaleMax))
            }.padding(6)
        }
    }

    // MARK: MTU / path MTU

    /// Which of our tunnels (if any) actually carries the probed target, decided from
    /// the routing table — the same test the Path railroad uses, so the two can never
    /// disagree about whether the traffic goes through the VPN.
    private var mtuContext: TunnelMTUContext {
        var ctx = TunnelMTUContext()
        let ip = targetNode?.ipv4 ?? pathMTU?.target ?? transportMTU?.target
        var carrier: (key: String, value: TunnelStats)?
        if let ip, NetworkProbes.isIPv4Literal(ip),
           let ifc = topo?.topology.egressInterface(forIPv4: ip) {
            carrier = ourVPN(for: ifc)
        }
        // With exactly one tunnel up we still name it and show its MTU, but
        // carriesTarget stays false so no verdict is drawn from an unrelated path.
        let stats = reach?.latestStats ?? [:]
        let chosen = carrier ?? (stats.count == 1 ? stats.first : nil)
        guard let chosen else { return ctx }
        ctx.profileName = vpn.profiles.first { $0.id == chosen.key }?.name ?? "the VPN"
        ctx.tunnelMTU = chosen.value.mtu
        ctx.carriesTarget = carrier != nil
        if let config = vpn.ovpnText(id: chosen.key) {
            let d = TunnelMTUContext.openVPNDirectives(in: config)
            ctx.mssfix = d.mssfix; ctx.tunMTU = d.tunMTU; ctx.fragment = d.fragment
        }
        return ctx
    }

    private var mtuCard: some View {
        let ctx = mtuContext
        let assessment = MTUAssessment.make(proto: mtuProto, path: pathMTU,
                                            transport: transportMTU, context: ctx)
        // Hold the verdict back while the first probe is still in flight — an
        // "inconclusive" badge that turns into an answer a second later reads as noise.
        let pending = mtuRunning && pathMTU == nil && transportMTU == nil
        return GroupBox("MTU & Fragmentation") {
            VStack(alignment: .leading, spacing: 10) {
                if mtuRunning {
                    Label(mtuProto == .icmp ? "Sizing the path…" : "Testing \(mtuProto.label)…",
                          systemImage: "ruler")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if !pending { mtuFindings(assessment, ctx) }
                Text(mtuTechniqueNote).font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }.padding(6)
        }
    }

    @ViewBuilder
    private func mtuFindings(_ assessment: MTUAssessment, _ ctx: TunnelMTUContext) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: assessment.verdict.symbol)
                .foregroundStyle(tint(assessment.verdict.severity))
            VStack(alignment: .leading, spacing: 2) {
                Text(assessment.verdict.title).font(.callout.weight(.semibold))
                Text(assessment.headline).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        HStack(spacing: 20) {
            if mtuProto == .icmp {
                metric("Path MTU", pathMTU?.pathMTU.map { "\($0)" } ?? "—")
                metric("Payload", pathMTU?.payload.map { "\($0)" } ?? "—")
                metric("Fragments", fragmentsText)
            } else {
                metric("MSS", transportMTU?.mss.map { "\($0)" } ?? "—")
                metric("Segment size", transportMTU?.impliedMTU.map { "≈\($0)" } ?? "—")
                metric("Large exchange", largeExchangeText)
            }
            metric("Tunnel MTU", ctx.tunnelMTU.map { "\($0)" } ?? "—")
            metric("mssfix", ctx.mssfix.map { "\($0)" } ?? "—")
            Spacer()
        }
        ForEach(Array(assessment.details.enumerated()), id: \.offset) { _, line in
            Text("• " + line).font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        if let fix = assessment.suggestedMSSFix {
            // Applying fixes belongs to the Connection Manager (which records an undo);
            // this card only names the number it measured.
            Label("Suggested clamp: mssfix \(fix) — the Connection Manager can apply it.",
                  systemImage: "wrench.and.screwdriver")
                .font(.caption).foregroundStyle(.orange)
        }
        if mtuProto == .icmp, let steps = pathMTU?.steps, !steps.isEmpty {
            DisclosureGroup("Sizes probed (\(steps.count))") {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) { ForEach(steps) { stepChip($0) } }
                        .padding(.vertical, 4)
                }
            }.font(.caption)
        }
    }

    private func stepChip(_ step: NetworkProbes.MTUStep) -> some View {
        let colour: Color = step.passed ? .green : (step.localTooBig ? .orange : .red)
        return Text("\(step.payload + NetworkProbes.icmpOverhead)")
            .font(.caption2.monospacedDigit())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(colour.opacity(0.18), in: Capsule())
            .foregroundStyle(colour)
            .help(step.passed ? "Reply came back"
                  : step.localTooBig ? "Our own interface refused to send it (too big for the first hop)"
                  : "No reply")
    }

    private var fragmentsText: String {
        guard let f = pathMTU?.fragmentsCorrectly else { return "—" }
        return f ? "Yes" : "Dropped"
    }
    private var largeExchangeText: String {
        guard let e = transportMTU?.largeExchange else { return "—" }
        return e.completed ? "Answered" : "Stalled"
    }

    /// Honest description of what the selected technique can and cannot establish.
    private var mtuTechniqueNote: String {
        switch mtuProto {
        case .icmp:
            return "Don't-fragment ICMP echoes, binary-searched for the largest that survives, then one oversized echo with fragmentation allowed. This is a real path-MTU measurement; it needs the target to answer ICMP."
        case .tcp:
            return "Reads TCP_MAXSEG on a live connection to report the negotiated MSS. No payload is exchanged, so a blackhole can't be detected — and an unprivileged app cannot set the don't-fragment bit per segment on a TCP connection, so no DF probing happens here."
        case .tls:
            return "Reads the negotiated MSS, then compares a plain TLS 1.2 ClientHello with one padded past that MSS. Sizes are inferred from what completes, not measured with DF: macOS gives an app no way to read the MTU out of an ICMP \"fragmentation needed\" error (no IP_RECVERR). Endpoints that only answer TLS 1.3 or a specific ALPN may not reply at all."
        case .http:
            return "Reads the negotiated MSS, then compares a small GET with one whose headers push it past that MSS. Sizes are inferred from what completes, not measured with DF: macOS gives an app no way to read the MTU out of an ICMP \"fragmentation needed\" error (no IP_RECVERR)."
        }
    }

    private func tint(_ s: MTUVerdict.Severity) -> Color {
        switch s {
        case .ok: return .green
        case .warning: return .orange
        case .bad: return .red
        case .unknown: return .secondary
        }
    }

    // MARK: Traceroute

    private var tracerouteCard: some View {
        GroupBox("Traceroute") {
            VStack(alignment: .leading, spacing: 4) {
                if tracing { Label("Tracing route…", systemImage: "point.topleft.down.to.point.bottomright.curvepath").font(.callout).foregroundStyle(.secondary) }
                ForEach(hops) { hop in
                    HStack(spacing: 8) {
                        Text("\(hop.ttl)").font(.caption.monospacedDigit()).foregroundStyle(.secondary).frame(width: 22, alignment: .trailing)
                        if let ip = hop.ip {
                            Text(flagFor(ip)).frame(width: 18)
                            VStack(alignment: .leading, spacing: 0) {
                                Text(ip).font(.callout.monospaced())
                                if let name = hopNames[hop.ttl], name != ip { Text(name).font(.caption).foregroundStyle(.secondary) }
                            }
                        } else {
                            Text("* * *").foregroundStyle(.secondary)
                        }
                        Spacer()
                        if let rtt = hop.rttMS { Text(String(format: "%.0f ms", rtt)).font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                    }
                    .padding(.vertical, 1)
                    // One sentence per hop; "* * *" is traceroute-speak nobody
                    // should have to hear read out as asterisks.
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(hopSentence(hop))
                }
            }.padding(6)
        }
    }

    /// "Hop 3, 10.1.0.1, gateway.example.net, 12 milliseconds" — or "no reply".
    private func hopSentence(_ hop: NetworkProbes.TraceHop) -> String {
        var bits = ["Hop \(hop.ttl)"]
        if let ip = hop.ip {
            bits.append(ip)
            if let name = hopNames[hop.ttl], name != ip { bits.append(name) }
        } else {
            bits.append("no reply")
        }
        if let rtt = hop.rttMS { bits.append(String(format: "%.0f milliseconds", rtt)) }
        return bits.joined(separator: ", ")
    }

    // MARK: DNS

    private var dnsCard: some View {
        GroupBox("DNS Lookup") {
            VStack(alignment: .leading, spacing: 8) {
                if dnsAnswers.isEmpty {
                    Text("Run a test to query DNS.").font(.callout).foregroundStyle(.secondary)
                } else {
                    Text("Every system resolver, asked directly. The ✓ is the one macOS actually took the answer from.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(dnsAnswers) { dnsRow($0) }
                    if let t = targetNode, let rev = t.reverse {
                        Divider()
                        LabeledContent("Reverse (\(t.ipv4 ?? ""))") { Text(rev).font(.callout.monospaced()) }
                    }
                }
            }.padding(6)
        }
    }

    private func dnsRow(_ a: DNSAnswer) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: a.matchesOS ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(a.matchesOS ? .green : .secondary)
                .help(a.matchesOS ? "The resolver macOS took the answer from" : "Also asked")
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(flagFor(a.server))
                    Text(a.server).font(.callout.monospaced())
                    if let rev = a.reverse { Text("(\(rev))").font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                }
                if let recs = a.result?.records, !recs.isEmpty {
                    Text(recs.joined(separator: ", ")).font(.caption.monospaced()).foregroundStyle(.secondary)
                } else {
                    Text("no answer").font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: 8)
            if let ms = a.result?.elapsedMS {
                Text(String(format: "%.0f ms", ms)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2).padding(.horizontal, 4)
        .background(a.matchesOS ? Color.green.opacity(0.08) : .clear, in: RoundedRectangle(cornerRadius: 6))
        // One sentence; the ✓-and-green-wash "macOS used this one" rides in words.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(dnsSentence(a))
    }

    private func dnsSentence(_ a: DNSAnswer) -> String {
        var bits = [a.server]
        if let rev = a.reverse { bits.append(rev) }
        if let recs = a.result?.records, !recs.isEmpty {
            bits.append("answered \(recs.joined(separator: ", "))")
        } else {
            bits.append("no answer")
        }
        if let ms = a.result?.elapsedMS { bits.append(String(format: "%.0f milliseconds", ms)) }
        if a.matchesOS { bits.append("the answer macOS used") }
        return bits.joined(separator: ", ")
    }

    // MARK: Actions

    /// Adopt a target handed over by something that already knows it (the connect
    /// timeout toast). Put on the view root by `.networkToolsRequests()`.
    private func adoptRequest() {
        guard !request.target.isEmpty else {
            // Opened cold with nothing to investigate: if there's exactly one VPN
            // and it isn't connected, the user almost certainly came here to test
            // IT — prefill and probe its endpoint rather than showing a blank form.
            if target.isEmpty { assumeSingleVPN() }
            return
        }
        target = request.target
        // A Probe request also carries the endpoint a connect would dial, so the
        // fingerprint asks the right port in the right protocol instead of guessing.
        probePortText = request.port.map(String.init) ?? ""
        probeTransport = VPNProbe.Transport(hint: request.proto)
        probeKind = request.vpnKind
        // …and, when it came from a saved VPN, which one — so the staged check
        // runs against that VPN's own keys rather than waiting to be told again.
        if let key = request.ladderKey, ladderFacts(for: key) != nil {
            ladderKey = key
            if request.autoRun { runLadder() }
        }
        if request.autoRun { run() }
    }

    /// One VPN configured and not connected → that's what the user came to test.
    /// Fills the form from what a connect would actually dial and runs everything.
    private func assumeSingleVPN() {
        guard vpn.profiles.count == 1, let profile = vpn.profiles.first,
              !UI.isActive(profile.status) else { return }
        let t = VPNProbeTarget.resolve(profile: profile, vpn: vpn, evaluator: evaluator)
        guard !t.host.isEmpty else { return }
        target = t.host
        probePortText = String(t.port)
        probeTransport = VPNProbe.Transport(hint: t.proto)
        probeKind = t.kind
        run()
    }

    private func run() {
        let host = target.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return }
        stop()          // cancel any in-flight run so its late results can't land on the new target
        running = true
        // Reset per-run state so a new target never shows the previous run's hops,
        // reverse-DNS labels, or nodes.
        hops = []; hopNames = [:]; dnsAnswers = []; targetNode = nil; dnsServerNode = nil
        pathMTU = nil; transportMTU = nil
        latency.start(host: host, boundIf: egressBoundIf)
        probeTasks = [
            Task { await resolveTarget(host) },
            Task { await runTraceroute(host) },
            Task { await runDNS(host) },
        ]
        mtuTask = Task { await runMTU(host) }
        restartVPNProbe()
    }

    private func stop() {
        running = false
        latency.stop()
        for t in probeTasks { t.cancel() }
        probeTasks = []
        mtuTask?.cancel(); mtuTask = nil
        mtuRunning = false
        probeTask?.cancel(); probeTask = nil
        portalTask?.cancel(); portalTask = nil
        probeRunning = false
    }

    /// The VPN fingerprint + captive-portal check. Separate from `run()`'s other
    /// probes so the port/transport/kind pickers can re-ask without restarting the
    /// latency graph, and so the Probe button works on its own.
    private func restartVPNProbe() {
        let host = target.trimmingCharacters(in: .whitespaces)
        probeTask?.cancel(); portalTask?.cancel()
        fingerprint = nil; portal = nil
        guard !host.isEmpty else { probeRunning = false; return }
        let port = Int(probePortText.trimmingCharacters(in: .whitespaces)) ?? defaultProbePort
        let transport = probeTransport
        let kind = probeKind
        probeTask = Task {
            probeRunning = true
            defer { if !Task.isCancelled { probeRunning = false } }
            // The VPN Probe asks a VPN server what it is, so it must go out the
            // PHYSICAL egress — never through a tunnel (least of all the one it's
            // testing, which would answer its own hello). This is the same binding
            // the step-by-step ladder uses, so the two never contradict. 0 ⇒ no
            // non-tunnel interface, which honestly falls back to normal routing.
            let boundIf = await Task.detached { NetworkIdentity.physicalEgressBoundIf() }.value
            let result = await VPNProbe.fingerprint(host: host, port: port,
                                                    proto: transport, hint: kind, boundIf: boundIf)
            guard !Task.isCancelled else { return }
            fingerprint = result
        }
        // Always, alongside every probe: a sign-in page in the way makes every other
        // result here a lie about the real network.
        portalTask = Task {
            let result = await ConnectionDiagnostics.captivePortalProbe()
            guard !Task.isCancelled else { return }
            portal = PortalCheck(detected: result.detected, url: result.url)
        }
    }

    /// Re-run only the MTU probe (protocol or port changed) against the current
    /// target, discarding the other technique's stale result.
    private func restartMTU() {
        let host = target.trimmingCharacters(in: .whitespaces)
        mtuTask?.cancel()
        mtuTask = nil
        pathMTU = nil; transportMTU = nil
        guard running, !host.isEmpty else { mtuRunning = false; return }
        mtuTask = Task { await runMTU(host) }
    }

    private func runMTU(_ host: String) async {
        mtuRunning = true
        // Only clear the flag if we are still the current probe — a superseded task
        // resuming late must not switch off the spinner of the one that replaced it.
        defer { if !Task.isCancelled { mtuRunning = false } }
        let proto = mtuProto
        let boundIf = egressBoundIf
        if proto == .icmp {
            let result = await NetworkProbes.measurePathMTU(host: host, boundIf: boundIf)
            guard !Task.isCancelled else { return }
            pathMTU = result
        } else {
            let port = Int(mtuPortText.trimmingCharacters(in: .whitespaces))
                ?? proto.defaultPort ?? 443
            let result = await NetworkProbes.measureTransportMTU(host: host, port: port, proto: proto, boundIf: boundIf)
            guard !Task.isCancelled else { return }
            transportMTU = result
        }
    }

    private func resolveTarget(_ host: String) async {
        let (v4, v6) = await NetworkProbes.resolve(host: host)
        guard !Task.isCancelled else { return }
        let primary = v4.first ?? v6.first
        let reverse = primary.flatMap { _ in host }   // host is the name the user asked for
        var node = NetNode(label: host, symbol: "target", ipv4: v4.first, ipv6: v6.first,
                           reverse: reverse, countryCode: primary.flatMap { GeoIP.shared?.countryCode(for: $0) })
        node.subtitle = primary.flatMap { GeoIP.shared?.countryCode(for: $0) }.flatMap { CountryCentroids.name(for: $0) }
        targetNode = node
    }

    private func runTraceroute(_ host: String) async {
        tracing = true; defer { tracing = false }
        let ip = await NetworkProbes.resolve(host: host).v4.first ?? host
        let result = await NetworkProbes.traceroute(host: ip, boundIf: egressBoundIf)
        guard !Task.isCancelled else { return }
        hops = result
        // Reverse-resolve each hop for readability.
        for hop in result {
            if Task.isCancelled { return }
            if let ip = hop.ip, let name = await NetworkProbes.reverseLookup(ip: ip) {
                if Task.isCancelled { return }
                hopNames[hop.ttl] = name
            }
        }
    }

    private func runDNS(_ host: String) async {
        let servers = NetworkProbes.systemDNSServers()
        guard !servers.isEmpty else { return }
        // What the OS actually resolves (getaddrinfo) — used to mark which resolver
        // the answer came from (split-DNS / MagicDNS means it isn't always the first).
        let osAnswer = await NetworkProbes.resolve(host: host).v4.first
        let boundIf = egressBoundIf
        // Ask every resolver in parallel so one slow/unreachable server can't stall.
        let collected = await withTaskGroup(of: (Int, NetworkProbes.DNSResult?, String?).self) { group -> [(Int, NetworkProbes.DNSResult?, String?)] in
            for (i, server) in servers.enumerated() {
                group.addTask {
                    async let ans = NetworkProbes.dnsQuery(name: host, type: .a, server: server, boundIf: boundIf)
                    async let rev = NetworkProbes.reverseLookup(ip: server)
                    return (i, await ans, await rev)
                }
            }
            var out: [(Int, NetworkProbes.DNSResult?, String?)] = []
            for await r in group { out.append(r) }
            return out
        }
        guard !Task.isCancelled else { return }
        dnsAnswers = collected.sorted { $0.0 < $1.0 }.map { (i, res, rev) in
            let matches: Bool = {
                if let osAnswer, let recs = res?.records { return recs.contains(osAnswer) }
                return i == 0   // no OS answer to compare → assume the primary resolver
            }()
            return DNSAnswer(server: servers[i], result: res, reverse: rev, matchesOS: matches)
        }
        // Flow chip = the resolver the OS took it from (else the primary).
        let chosen = dnsAnswers.first(where: \.matchesOS) ?? dnsAnswers.first
        if let chosen {
            dnsServerNode = NetNode(label: chosen.server, symbol: "server.rack", reverse: chosen.reverse,
                                    countryCode: GeoIP.shared?.countryCode(for: chosen.server))
        }
    }

    private func flagFor(_ ip: String) -> String {
        GeoIP.shared?.countryCode(for: ip).map { CountryCentroids.flag(for: $0) } ?? ""
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.body, design: .rounded)).monospacedDigit().bold()
        }
        // Caption + number read as one ("Latency: 32 ms"), and the em-dash
        // placeholder becomes words.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title): \(value == "\u{2014}" ? "no data yet" : value)")
    }
}

private struct NetNodeChip: View {
    let node: NetNode
    var body: some View {
        chipBody
            .accessibilityElement(children: .combine)
    }
    private var chipBody: some View {
        VStack(spacing: 3) {
            Image(systemName: node.symbol).font(.title2).foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text(node.label).font(.caption.weight(.medium)).lineLimit(1)
            if let cc = node.countryCode { Text(CountryCentroids.flag(for: cc)).font(.caption2) }
            if let ip = node.ipv4 { Text(ip).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1) }
            if let ip6 = node.ipv6 { Text(ip6).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1) }
            if let rev = node.reverse { Text(rev).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
        }
        .frame(width: 120)
        .padding(8)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
        .help([node.label, node.ipv4, node.ipv6, node.reverse, node.subtitle].compactMap { $0 }.joined(separator: "\n"))
    }
}

/// The latency graph as an audio graph — same rule as the throughput charts:
/// a Swift Chart is navigable data, not a picture. Lost pings become their own
/// discrete "Lost" series (the red ✕ marks), so sonification renders drops as
/// absences rather than zero-latency lies.
/// nonisolated because AXChartDescriptorRepresentable is a nonisolated protocol.
nonisolated private struct LatencyChartDescriptor: AXChartDescriptorRepresentable {
    let samples: [LatencyMonitor.Sample]
    let lossPercent: Double
    let scaleMax: Double

    private func axes() -> (x: AXNumericDataAxisDescriptor, y: AXNumericDataAxisDescriptor) {
        let newest = samples.last?.id ?? 0
        let oldest = samples.first?.id ?? 0
        let x = AXNumericDataAxisDescriptor(
            title: "Ping number",
            range: Double(oldest)...Double(max(oldest + 1, newest)),
            gridlinePositions: []) { value in
                let ago = Double(newest) - value
                return ago < 1 ? "newest" : "\(Int(ago)) pings ago"
            }
        let y = AXNumericDataAxisDescriptor(
            title: "Round trip",
            range: 0...max(1, scaleMax),
            gridlinePositions: []) { String(format: "%.0f milliseconds", $0) }
        return (x, y)
    }

    private func series() -> [AXDataSeriesDescriptor] {
        [AXDataSeriesDescriptor(
            name: "Round trip", isContinuous: true,
            dataPoints: samples.compactMap { s in
                s.rttMS.map { AXDataPoint(x: Double(s.id), y: $0) }
            }),
         AXDataSeriesDescriptor(
            name: "Lost pings", isContinuous: false,
            dataPoints: samples.filter { $0.rttMS == nil }.map {
                AXDataPoint(x: Double($0.id), y: 0, label: "lost")
            })]
    }

    private var summary: String {
        guard let last = samples.last else { return "No pings sent yet." }
        let latest = last.rttMS.map { String(format: "%.0f milliseconds", $0) } ?? "lost"
        return "Latest ping \(latest); \(String(format: "%.0f", lossPercent)) percent lost over \(samples.count) pings."
    }

    func makeChartDescriptor() -> AXChartDescriptor {
        let (x, y) = axes()
        return AXChartDescriptor(title: "Latency and packet loss", summary: summary,
                                 xAxis: x, yAxis: y, additionalAxes: [], series: series())
    }

    // Rebuilt on every SwiftUI update so the audio graph tracks the live pings.
    func updateChartDescriptor(_ descriptor: AXChartDescriptor) {
        let (x, y) = axes()
        descriptor.xAxis = x
        descriptor.yAxis = y
        descriptor.summary = summary
        descriptor.series = series()
    }
}
