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

    func start(host: String) {
        stop()
        task = Task { [weak self] in
            // Ping the first IPv4 (unprivileged ICMP is v4 here).
            var target = await NetworkProbes.resolve(host: host).v4.first ?? host
            guard let self, !Task.isCancelled else { return }   // a restart may have superseded us
            var resolvedOn = NetworkMemory.shared.current?.key
            var resolvedAt = Date()
            self.targetIP = target
            while !Task.isCancelled {
                let r = await NetworkProbes.pingOnce(host: target, seq: UInt16(truncatingIfNeeded: self.seq))
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

    @State private var target = ""
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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                targetBar
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
        .onAppear { topo?.startWatching() }      // need the routing table to classify the path
        .onDisappear { topo?.stopWatching(); stop() }   // + cancel latency/traceroute/DNS/resolve/MTU
    }

    private var hasResults: Bool {
        latency.targetIP != nil || !hops.isEmpty || !dnsAnswers.isEmpty
            || mtuRunning || pathMTU != nil || transportMTU != nil
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
            Picker("Transport", selection: $probeTransport) {
                ForEach(VPNProbe.Transport.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            Picker("Kind", selection: $probeKind) {
                Text("Auto-detect").tag(VPNKind?.none)
                ForEach(VPNKind.allCases, id: \.self) { Text($0.displayName).tag(VPNKind?.some($0)) }
            }
            .labelsHidden().fixedSize()
            .help("Narrows the probe to one protocol. Auto-detect tries a small battery.")
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
    }

    private func probeFindingRow(_ finding: VPNProbe.Finding) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: finding.detected ? "checkmark.circle.fill" : "minus.circle")
                .foregroundStyle(finding.detected ? Color.green : .secondary)
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
    }

    @ViewBuilder
    private var captivePortalRow: some View {
        if let portal {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: portal.detected ? "wifi.exclamationmark" : "checkmark.shield")
                    .foregroundStyle(portal.detected ? Color.orange : .green)
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
            Picker("MTU via", selection: $mtuProto) {
                ForEach(NetworkProbes.MTUProtocol.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            .help("Which technique the MTU test uses. Only ICMP can size the path with the don't-fragment bit; the TCP-based tests report the negotiated MSS and look for a blackhole.")
            if mtuProto.isTCP {
                TextField("Port", text: $mtuPortText,
                          prompt: Text("\(mtuProto.defaultPort ?? 443)"))
                    .textFieldStyle(.roundedBorder).frame(width: 64)
                    .onSubmit { restartMTU() }
            }
            Button(running ? "Stop" : "Run") { running ? stop() : run() }
                .keyboardShortcut(.defaultAction)
                .disabled(target.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .onChange(of: mtuProto) { restartMTU() }
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
                       subtitle: s.serverEndpoint.isEmpty ? nil : "Gateway")
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
                        PointMark(x: .value("t", s.id), y: .value("ms", 0)).foregroundStyle(.red)  // a drop
                    }
                }
                .chartYScale(domain: 0...latency.scaleMax)
                .chartXAxis(.hidden)
                .frame(height: 120)
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
                }
            }.padding(6)
        }
    }

    // MARK: DNS

    private var dnsCard: some View {
        GroupBox("DNS") {
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
        latency.start(host: host)
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
            let result = await VPNProbe.fingerprint(host: host, port: port,
                                                    proto: transport, hint: kind)
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
        if proto == .icmp {
            let result = await NetworkProbes.measurePathMTU(host: host)
            guard !Task.isCancelled else { return }
            pathMTU = result
        } else {
            let port = Int(mtuPortText.trimmingCharacters(in: .whitespaces))
                ?? proto.defaultPort ?? 443
            let result = await NetworkProbes.measureTransportMTU(host: host, port: port, proto: proto)
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
        let result = await NetworkProbes.traceroute(host: ip)
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
        // Ask every resolver in parallel so one slow/unreachable server can't stall.
        let collected = await withTaskGroup(of: (Int, NetworkProbes.DNSResult?, String?).self) { group -> [(Int, NetworkProbes.DNSResult?, String?)] in
            for (i, server) in servers.enumerated() {
                group.addTask {
                    async let ans = NetworkProbes.dnsQuery(name: host, type: .a, server: server)
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
    }
}

private struct NetNodeChip: View {
    let node: NetNode
    var body: some View {
        VStack(spacing: 3) {
            Image(systemName: node.symbol).font(.title2).foregroundStyle(.tint)
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
