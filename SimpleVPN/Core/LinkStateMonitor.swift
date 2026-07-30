// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LinkStateMonitor.swift
//  THE single answer to "what is this connection actually doing right now".
//
//  Before this existed, every surface assembled that answer itself — the sidebar dot,
//  the header pill, the menu-bar glyph, the route graph — and they drifted: two
//  different captive-portal predicates and two independent stall classifiers, so the
//  header could say "No response" while the sidebar dot stayed green. Reviews caught
//  it twice. Deriving it in one place makes that class of bug impossible.
//
//  It is a DERIVATION, not another poller: the inputs are already monitored
//  continuously (VPNController owns NE status / paused / incidents / captive-portal
//  suspicion, ReachabilityMonitor owns the 1 Hz stall + throughput judgement). Reads
//  happen inside view bodies, so Observation tracks straight through to those stores
//  and every consumer updates together, from one shared truth.
//

import Foundation
import NetworkExtension

@MainActor
@Observable
final class LinkStateMonitor {

    /// Everything a surface needs to know, ordered by severity so `worst` is trivial.
    enum State: Equatable, Comparable {
        case disconnected
        case connecting
        case disconnecting
        case connected
        case paused(VPNController.PauseMode)
        /// Connected, but nothing is coming back — the train-tunnel case. Seconds
        /// quiet when we know it.
        case stalled(seconds: Int?)
        /// A sign-in page is intercepting traffic.
        case captivePortal

        /// Severity for "which of these should the menu bar shout about".
        private var rank: Int {
            switch self {
            case .connected: 0
            case .disconnected: 1
            case .disconnecting: 2
            case .connecting: 3
            case .paused: 4
            case .stalled: 5
            case .captivePortal: 6
            }
        }
        static func < (a: State, b: State) -> Bool { a.rank < b.rank }

        var isActive: Bool {
            switch self {
            case .connecting, .connected, .paused, .stalled, .captivePortal: true
            case .disconnected, .disconnecting: false
            }
        }
        /// Up, but not actually carrying traffic — draw it dashed/attention-seeking.
        var isImpaired: Bool {
            switch self {
            case .stalled, .captivePortal, .paused: true
            default: false
            }
        }
    }

    private let vpn: VPNController
    private let reach: ReachabilityMonitor?

    init(vpn: VPNController, reach: ReachabilityMonitor?) {
        self.vpn = vpn
        self.reach = reach
    }

    /// The canonical state for a profile. Precedence is deliberate and is now stated
    /// once: a captive portal explains every other symptom, so it wins; an explicit
    /// user pause outranks a stall (of course it isn't passing traffic); a stall only
    /// means anything while the tunnel is nominally up.
    func state(for id: String) -> State {
        guard let profile = vpn.profiles.first(where: { $0.id == id }) else { return .disconnected }
        if vpn.captivePortalSuspected, vpn.incidents[id] != nil { return .captivePortal }
        if let mode = vpn.pausedProfiles[id] { return .paused(mode) }
        switch profile.status {
        case .connecting: return .connecting
        case .disconnecting: return .disconnecting
        case .connected:
            if case .stalled(let s) = reach?.health(for: id) { return .stalled(seconds: s) }
            return .connected
        case .reasserting:
            // NE is re-establishing: that IS the impaired-but-connected case.
            return .stalled(seconds: nil)
        default: return .disconnected
        }
    }

    /// The dot presentation. Goes through DotState so the colour/rhythm mapping stays
    /// the single one it already is — this only decides which DotState to ask for.
    func dot(for id: String) -> DotState {
        switch state(for: id) {
        case .captivePortal: .captivePortal
        case .paused: .paused
        case .stalled: .degraded
        case .connecting, .disconnecting: .busy
        case .connected: .connected
        case .disconnected: .off
        }
    }

    /// The most attention-worthy state across every profile — for the menu bar, which
    /// has one glyph to represent everything.
    func worst() -> State? {
        vpn.profiles.map { state(for: $0.id) }.filter(\.isActive).max()
    }

    var anyActive: Bool { vpn.profiles.contains { state(for: $0.id).isActive } }
}
