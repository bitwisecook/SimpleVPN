// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DNSArbiter.swift
//  The DNS mediator's PURE core (Docs/StateMediators.md › DNS mediator, P2). Total,
//  testable, no-I/O functions:
//    • `DNSArbiter.plan(intents:policy:)` — merge every connected tunnel's DNS intent
//      into ONE coherent split-DNS config: which resolver serves which domain, with a
//      precedence that stops the last VPN's push from clobbering the rest. Exactly one
//      engine (the route default owner, if it advertises resolvers) owns the CATCH-ALL
//      (`[""]`); every other engine keeps only its SPECIFIC match domains.
//    • `DNSDriftDecision.action(...)` — given the monitor's observed system resolvers
//      vs the plan's expected catch-all resolvers (and the just-applied suppress
//      window), decide whether an EXTERNAL change warrants a re-assert.
//  Plus `DNSParticipation` — the per-kind classifier (mirrors the Route one) so no kind
//  is silently mis-handled.
//

import Foundation

extension DNSArbiter: MediatorArbiter {}

// MARK: - Observation + drift decision (stage 4 → re-assert)

/// What the DNS monitor read from `State:/Network/Global/DNS` — the resolvers the OS is
/// actually using right now (includes any VPN-pushed DNS), and the search domains.
nonisolated struct DNSObservation: Sendable, Equatable {
    var resolvers: [String]
    var searchDomains: [String]
    var scoped: [DNSApplyRequest] = []
}

nonisolated enum DNSDriftAction: Sendable, Equatable {
    case none         // matches expectation (or our own change) — do nothing
    case reassert     // genuine external drift — drive the OS back to desired
}

nonisolated enum DNSDriftDecision {
    static func action(expected: DNSPlan, observed: DNSObservation,
                       withinSuppressWindow: Bool) -> DNSDriftAction {
        guard !withinSuppressWindow else { return .none }
        for request in expected.applyRequests().values where !request.servers.isEmpty {
            let scopes = Set(request.matchDomains.map(DNSSearchDomains.normalized(one:)))
            let candidates = observed.scoped.filter {
                let domains = Set($0.matchDomains.map(DNSSearchDomains.normalized(one:)))
                return scopes.isSubset(of: domains)
            }
            let global = scopes == [""] ? [DNSApplyRequest(servers: observed.resolvers,
                searchDomains: observed.searchDomains, matchDomains: [""])] : []
            let matches = (candidates + global).contains {
                Set(request.servers).isSubset(of: Set($0.servers)) &&
                    Set(request.searchDomains.map(DNSSearchDomains.normalized(one:)))
                    .isSubset(of: Set($0.searchDomains.map(DNSSearchDomains.normalized(one:))))
            }
            if !matches { return .reassert }
        }
        return .none
    }
    /// Decide what to do about an observed system-resolver change.
    ///
    /// - `withinSuppressWindow`: we applied a DNS change moments ago, so this
    ///   observation is almost certainly our OWN change echoing back — never re-assert
    ///   against ourselves.
    /// - otherwise: when we EXPECT a catch-all owner (non-empty expected resolvers) and
    ///   the observed system resolvers no longer contain ALL of ours, something external
    ///   changed DNS ⇒ re-assert. An empty expectation (Direct DNS) never manufactures
    ///   drift — the Mac's own resolvers changing is not ours to fight.
    static func action(expected: [String], observed: [String],
                       withinSuppressWindow: Bool) -> DNSDriftAction {
        if withinSuppressWindow { return .none }
        guard !expected.isEmpty else { return .none }
        let observedSet = Set(observed)
        return expected.allSatisfy(observedSet.contains) ? .none : .reassert
    }
}

// MARK: - VPN-kind participation classifier (DNS resource)

/// Which clean bucket a connected profile falls into for the DNS resource
/// (StateMediators.md › VPN-kind participation). Every kind resolves to exactly one.
nonisolated enum DNSParticipation: Sendable, Equatable {
    /// Pushes real resolvers we arbitrate into split-DNS (OpenVPN, proxy-tunnel,
    /// Tailscale/MagicDNS, WireGuard's DNS= servers, in-process-NE OpenConnect
    /// and the other SSL VPNs).
    case full
    /// Coarse OS-managed DNS (native NEVPNManager kinds via `NEDNSSettings`) — surfaced
    /// but not part of the live split-DNS arbitration.
    case limited
    /// No DNS of its own (SSH SOCKS, subprocess kinds) — excluded with a reason.
    case none

    // No `.unsupported` bucket: it was "engine not built", nothing returned it, and
    // the sentence it produced could never be shown. `classify(_:)` below switches
    // over `VPNKind` exhaustively with no `default` arm, so a new kind is forced to
    // pick a bucket by the compiler — which is what the spare case was standing in
    // for. Removed here in step with `RouteParticipation`, so the three mediators'
    // buckets stay readable side by side.

    /// Does this bucket contribute an intent to the split-DNS arbitration?
    var participatesInSplitDNS: Bool { self == .full }

    nonisolated static func classify(_ kind: VPNKind) -> DNSParticipation {
        switch kind {
        case .openVPN, .proxyTunnel, .tailscale, .wireGuard, .sshNetworkTunnel,
             .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks:
            // .sshNetworkTunnel advertises real resolvers on its utun and carries
            // every query as DNS-over-TCP through the session, so it contributes a
            // genuine split-DNS intent — unlike `.ssh`, which has no interface to
            // advertise one on.
            return .full
        case .ikev2, .ipsec, .l2tp:
            return .limited
        case .ssh:
            return .none
        }
    }
}
