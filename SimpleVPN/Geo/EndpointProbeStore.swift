// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointProbeStore.swift
//  Measures how far away a VPN's endpoints actually are, so the pickers can put
//  the quickest one first instead of guessing from a map.
//
//  The app's probing rule, kept here as it is everywhere else: probes run where
//  they are cheap AND the user has just asked for the thing they inform —
//  opening an endpoint picker or a VPN's page. There is no timer, no background
//  sweep, and when the Settings switch is off NOTHING here touches the network
//  at all; ordering falls back to the geographic guess with no traffic sent.
//
//  What one measurement costs: a DNS lookup, up to two unprivileged ICMP echoes,
//  and the protocol-appropriate VPNProbe fingerprint (a single short exchange —
//  no session is established). Results are cached for a few minutes so flipping
//  between VPNs doesn't re-probe the same servers over and over.
//
//  One VPN is never measured: the one you are currently connected to (or
//  connecting to). Its traffic would go INTO its own tunnel and hairpin back out
//  at the far end, so the number is either nonsense or a timeout — and it would
//  be recorded as "no answer" for a server that is plainly answering, since it is
//  carrying the session that asked. Being connected IS the reachability answer.
//  Every other VPN's endpoints are still measured normally.
//

import Foundation

/// Settings key: probe endpoints to order them by real speed. Default ON —
/// unlike a location or public-address lookup, this only ever talks to servers
/// the user has already configured a VPN for.
let endpointProbeDefaultsKey = "probe.endpointsAutomatic"

@MainActor
@Observable
final class EndpointProbeStore {

    /// Results keyed by network fingerprint AND `VPNEndpoint.id`, shared across
    /// every surface so the sidebar, the picker and the map agree.
    ///
    /// The network is part of the key because a measurement only means anything
    /// on the network it was taken from: endpoints are commonly split-horizon
    /// (the same name is a LAN address in the office and a public one outside),
    /// and even where they aren't, "3 ms" from the office is a lie in a café.
    private(set) var results: [String: EndpointMeasurement] = [:]
    /// Endpoints with a probe in flight — the UI shows these as "checking…".
    private(set) var probing: Set<String> = []

    /// How long a measurement is trusted before a fresh visit re-probes.
    private static let freshness: TimeInterval = 5 * 60
    /// How many endpoints are probed at once. A provider list can be forty long;
    /// forty simultaneous probes is a burst that looks like a scan.
    private static let concurrency = 4

    static var isEnabled: Bool {
        defaultsBool(endpointProbeDefaultsKey, initially: true)
    }

    /// Which network we're measuring from. Injected so the keying can be
    /// exercised without a real path monitor.
    @ObservationIgnored private let networkKey: @MainActor () -> String

    /// "Is this VPN up, or coming up?" — wired to the controller at launch, so
    /// the store needs no reference to it. Default: nothing is connected.
    @ObservationIgnored var isProfileEngaged: @MainActor (String) -> Bool = { _ in false }

    init(networkKey: @escaping @MainActor () -> String = { NetworkChange.key }) {
        self.networkKey = networkKey
    }

    /// Composite result key. Nothing parses it back — it only ever has to be
    /// unique per (network, endpoint) and cheap to prefix-match when purging.
    static func resultKey(network: String, endpoint: String) -> String {
        "\(network)\u{1F}\(endpoint)"
    }

    func measurement(for id: String) -> EndpointMeasurement? {
        results[Self.resultKey(network: networkKey(), endpoint: id)]
    }

    /// File a measurement under the network it was taken on.
    ///
    /// Refused outright while `profile` is engaged: a sweep started just before
    /// the tunnel came up finishes just after it, and its results were measured
    /// through the tunnel. Dropping them at the door is what keeps a bogus "no
    /// answer" from outliving the session that produced it.
    func record(_ measurement: EndpointMeasurement, for id: String, network: String,
                profile: String? = nil) {
        if let profile, isProfileEngaged(profile) { return }
        results[Self.resultKey(network: network, endpoint: id)] = measurement
    }

    /// Arriving on a different network makes every earlier measurement dead
    /// weight — nothing can ever read it again — so drop it rather than let it
    /// accumulate. The views re-drive `refresh` on the same signal, so the
    /// current network's numbers are refilled immediately.
    func dropMeasurements(notOn network: String) {
        guard !results.isEmpty else { return }
        let prefix = Self.resultKey(network: network, endpoint: "")
        results = results.filter { $0.key.hasPrefix(prefix) }
    }

    /// Drop everything measured (called when the switch is turned off, so the
    /// UI stops showing timings the user has just opted out of).
    func clear() {
        results.removeAll()
        probing.removeAll()
    }

    /// Probe every endpoint that hasn't been measured recently. Safe to call on
    /// every `.task` / picker open: stale-only, de-duplicated, and a no-op when
    /// the setting is off.
    /// - Parameter profile: whose endpoints these are. Given one, the sweep is
    ///   skipped entirely while that VPN is engaged — the measurement would be
    ///   taken through its own tunnel.
    func refresh(_ endpoints: [VPNEndpoint], kind: VPNKind, profile: String? = nil,
                 force: Bool = false) {
        guard Self.isEnabled else { return }
        if let profile, isProfileEngaged(profile) { return }
        let network = networkKey()
        dropMeasurements(notOn: network)
        let now = Date()
        let due = endpoints.filter { e in
            guard !probing.contains(e.id) else { return false }
            guard !force else { return true }
            guard let at = results[Self.resultKey(network: network, endpoint: e.id)]?.measuredAt
            else { return true }
            return now.timeIntervalSince(at) > Self.freshness
        }
        guard !due.isEmpty else { return }

        // Resolve the default port on this side: VPNProbeTarget is main-actor
        // code, and the probe itself must not be.
        let jobs = due.map { e in
            (id: e.id, host: e.host,
             port: e.port ?? VPNProbeTarget.defaultPort(for: kind),
             proto: e.proto, kind: kind)
        }
        for job in jobs { probing.insert(job.id) }

        Task { [weak self] in
            await withTaskGroup(of: (String, EndpointMeasurement).self) { group in
                var next = 0
                func submit() {
                    guard next < jobs.count else { return }
                    let job = jobs[next]
                    next += 1
                    group.addTask {
                        (job.id, await Self.measure(host: job.host, port: job.port,
                                                    proto: job.proto, kind: job.kind))
                    }
                }
                for _ in 0..<min(Self.concurrency, jobs.count) { submit() }
                for await (id, measurement) in group {
                    // Filed under the network it was MEASURED on, captured before
                    // the probes started — a Wi-Fi hop mid-sweep must not stamp
                    // the old network's numbers onto the new one. A connect
                    // mid-sweep is refused by `record` for the same reason.
                    self?.record(measurement, for: id, network: network, profile: profile)
                    self?.probing.remove(id)
                    submit()
                }
            }
        }
    }

    // MARK: The measurement itself

    /// DNS → ping → protocol fingerprint, best-effort at every step.
    ///
    /// The RTT reported is the ICMP round trip where the host answers pings, and
    /// a timed TCP connect where it doesn't but the endpoint is TCP. The VPN
    /// fingerprint is deliberately NOT timed for latency: it runs several probes
    /// with their own timeouts, so its elapsed time measures our patience, not
    /// the network. It contributes reachability and the one-line explanation.
    nonisolated static func measure(host: String, port: Int, proto: String?,
                                    kind: VPNKind) async -> EndpointMeasurement {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            return EndpointMeasurement(reachable: false, detail: "No address to check.",
                                       measuredAt: Date())
        }

        let addresses = await NetworkProbes.resolve(host: host)
        guard !addresses.v4.isEmpty || !addresses.v6.isEmpty else {
            return EndpointMeasurement(reachable: false,
                                       detail: "This address couldn't be looked up.",
                                       measuredAt: Date())
        }

        let transport = VPNProbe.Transport(hint: proto)
        async let pingRTT = bestPing(addresses.v4.first)
        async let fingerprint = VPNProbe.fingerprint(host: host, port: port,
                                                     proto: transport, hint: kind)
        var rtt = await pingRTT
        let print = await fingerprint

        if rtt == nil, transport != .udp {
            // ICMP is widely dropped; a TCP handshake to the port we'd dial
            // anyway is the next most honest stopwatch.
            let start = Date()
            if await ConnectionDiagnostics.tcpReachable(host: host, port: port, timeout: 4) {
                rtt = Date().timeIntervalSince(start) * 1000
            }
        }

        let answered = print.best != nil
        return EndpointMeasurement(
            rttMS: rtt,
            // "Nothing answered" is not "unreachable" for a server that only
            // replies to signed clients — so reachability is only asserted false
            // when neither ping nor probe got anything back at all.
            reachable: answered || rtt != nil ? true : false,
            detail: print.summary.isEmpty ? nil : print.summary,
            measuredAt: Date())
    }

    /// Two echoes, quickest wins — one lost packet shouldn't demote a server.
    nonisolated private static func bestPing(_ ipv4: String?) async -> Double? {
        guard let ipv4 else { return nil }
        var best: Double?
        for seq in UInt16(1)...UInt16(2) {
            let reply = await NetworkProbes.pingOnce(host: ipv4, seq: seq, timeout: 2)
            if let rtt = reply.rttMS { best = min(best ?? rtt, rtt) }
        }
        return best
    }
}
