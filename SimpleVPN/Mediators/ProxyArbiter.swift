// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyArbiter.swift
//  The Proxy mediator's PURE core (Docs/StateMediators.md › Proxy mediator, P3). Total,
//  testable, no-I/O functions:
//    • `ProxyArbiter.plan(intents:policy:)` — resolve the ONE system proxy decision from
//      every connected tunnel's proxy intent. Tier-2 realization (per the Proxies
//      model): apply the default OWNER's proxy as the system proxy; if the owner pushes
//      none, a single proxy-provider (e.g. an SSH SOCKS tunnel) may set it — so multiple
//      VPNs' proxies never fight over the one system setting.
//    • `ProxyDriftDecision.action(...)` — observed system proxy vs the plan's expected
//      decision (and the suppress window) → re-assert or not.
//  Plus `ProxyParticipation` — the per-kind classifier so no kind is mis-handled.
//

import Foundation

// MARK: - Intent (stage 1 payload)

nonisolated enum ProxyScheme: String, Sendable, Equatable, Codable {
    case socks, http, https
}

/// One proxy endpoint (manual proxy config).
nonisolated struct ProxyEndpoint: Sendable, Equatable {
    var scheme: ProxyScheme
    var host: String
    var port: Int

    var display: String { "\(scheme.rawValue)://\(host):\(port)" }
}

/// Full per-scheme manual proxy detail (what `NEProxySettings` needs). `mode` above
/// stays the single-endpoint summary the arbiter/drift compare against the one system
/// proxy; this carries the complete picture (an OpenVPN push can name BOTH http and
/// https) for the tier-2 `NEProxySettings` realizer.
nonisolated struct ProxyManual: Sendable, Equatable {
    var http: ProxyEndpoint?
    var https: ProxyEndpoint?
    var socks: ProxyEndpoint?

    init(http: ProxyEndpoint? = nil, https: ProxyEndpoint? = nil, socks: ProxyEndpoint? = nil) {
        self.http = http; self.https = https; self.socks = socks
    }

    /// The single representative endpoint for the coarse decision + drift compare,
    /// SOCKS > HTTPS > HTTP (matching `ProxyMediator.readSystemProxy` priority).
    var representative: ProxyEndpoint? { socks ?? https ?? http }
    var isEmpty: Bool { http == nil && https == nil && socks == nil }
}

/// One engine's structured proxy intent — captured from each VPN's pushed proxy config
/// (`PUSH::proxy`, `NEProxySettings`) or, for SOCKS kinds, the local proxy it exposes.
/// The tier-3 `PROXY_PUSHED` hook rewrites exactly this before arbitration.
nonisolated struct ProxyIntent: MediatorIntent {
    let engine: String

    nonisolated enum Mode: Sendable, Equatable {
        case none                       // no proxy
        case manual(ProxyEndpoint)      // an explicit proxy endpoint
        case pac(String)                // a PAC URL/script
    }
    var mode: Mode
    var egress: String?                 // BSD interface, best-effort
    var connectedAt: Date?

    // Full realization detail (tier-2 NEProxySettings). `mode` stays the coarse
    // single-decision summary the arbiter/drift use; these carry the per-scheme detail
    // + bypass NEProxySettings needs. `authSource` is a keychain REF only — never
    // inline creds (OpenVPN's push carries none; a 407 is answered from the keychain).
    var manual: ProxyManual?
    var bypass: [String]
    var excludeSimpleHostnames: Bool
    var authSource: String?

    init(engine: String, mode: Mode = .none, egress: String? = nil, connectedAt: Date? = nil,
         manual: ProxyManual? = nil, bypass: [String] = [],
         excludeSimpleHostnames: Bool = false, authSource: String? = nil) {
        self.engine = engine
        self.mode = mode
        self.egress = egress
        self.connectedAt = connectedAt
        self.manual = manual
        self.bypass = bypass
        self.excludeSimpleHostnames = excludeSimpleHostnames
        self.authSource = authSource
    }

    /// The PAC url, when this intent is a PAC (mirrors `mode`).
    var pacURL: String? { if case .pac(let u) = mode { return u }; return nil }

    var providesProxy: Bool { if case .none = mode { return false }; return true }
}

// MARK: - Policy input

/// The policy the Proxy arbiter resolves against (tier-2): the route DEFAULT OWNER's
/// proxy becomes the system proxy. nil ⇒ no owner.
nonisolated struct ProxyPolicy: Sendable, Equatable {
    var defaultOwner: String?
}

// MARK: - Plan (stage 2 output)

/// The ONE computed system-proxy decision: who it came from and what it is.
nonisolated struct ProxyPlan: Sendable, Equatable {
    /// The engine whose proxy is the system proxy. nil ⇒ no system proxy (Direct).
    var owner: String?
    var mode: ProxyIntent.Mode

    // Full realization detail for the tier-2 NEProxySettings applier, copied from the
    // chosen intent. Defaulted so `ProxyPlan(owner:mode:)` still constructs.
    var manual: ProxyManual?
    var bypass: [String]
    var excludeSimpleHostnames: Bool
    var authSource: String?

    init(owner: String?, mode: ProxyIntent.Mode, manual: ProxyManual? = nil,
         bypass: [String] = [], excludeSimpleHostnames: Bool = false, authSource: String? = nil) {
        self.owner = owner
        self.mode = mode
        self.manual = manual
        self.bypass = bypass
        self.excludeSimpleHostnames = excludeSimpleHostnames
        self.authSource = authSource
    }

    /// Build the sole-writer wire payload from the plan (Docs/StateMediators.md › P3
    /// applier). PAC wins over manual; bypass → exceptionList. Empty ⇒ clear.
    var applyRequest: ProxyApplyRequest { applyRequest(username: nil, password: nil) }

    /// The wire payload with the plan's `authSource` REF already resolved to a sign-in
    /// (the realizer's job — this stays pure). Credentials attach to MANUAL servers
    /// only: `NEProxySettings` has no PAC credential slot, so a PAC decision never
    /// carries them (`ProxyAuthAdvisory` surfaces that instead of silently dropping).
    func applyRequest(username: String?, password: String?) -> ProxyApplyRequest {
        if case .pac(let url) = mode {
            return ProxyApplyRequest(pacURL: url, bypass: bypass,
                                     excludeSimpleHostnames: excludeSimpleHostnames)
        }
        let m = manual
        return ProxyApplyRequest(
            httpHost: m?.http?.host, httpPort: m?.http?.port,
            httpsHost: m?.https?.host, httpsPort: m?.https?.port,
            bypass: bypass, excludeSimpleHostnames: excludeSimpleHostnames,
            username: username, password: password)
    }

    var providesProxy: Bool { if case .none = mode { return false }; return true }
}

// MARK: - Arbiter

nonisolated enum ProxyArbiter: MediatorArbiter {

    /// The single system-proxy decision from intents + policy. PURE.
    ///
    /// Precedence: the route default OWNER's proxy wins (its egress carries the traffic,
    /// so its proxy is the coherent choice). If the owner pushes no proxy, exactly one
    /// proxy-PROVIDER (an SSH SOCKS tunnel, an ocproxy OpenConnect) may set the system
    /// proxy — the SOCKS kinds whose whole purpose is to be a proxy egress. Ties among
    /// providers break by most-recent connection, then id order, so it is deterministic.
    static func plan(intents: [ProxyIntent], policy: ProxyPolicy) -> ProxyPlan {
        // 1. The owner's proxy, if it pushes one.
        if let owner = policy.defaultOwner,
           let ownerIntent = intents.first(where: { $0.engine == owner }),
           ownerIntent.providesProxy {
            return plan(from: ownerIntent)
        }
        // 2. Otherwise a single proxy-provider sets it (deterministic precedence).
        let providers = intents
            .filter(\.providesProxy)
            .sorted { a, b in
                let ta = a.connectedAt ?? .distantPast
                let tb = b.connectedAt ?? .distantPast
                if ta != tb { return ta > tb }
                return a.engine < b.engine
            }
        if let pick = providers.first {
            return plan(from: pick)
        }
        // 3. Nobody wants a proxy.
        return ProxyPlan(owner: nil, mode: .none)
    }

    /// Project one chosen intent into the plan, carrying its full realization detail.
    private static func plan(from intent: ProxyIntent) -> ProxyPlan {
        ProxyPlan(owner: intent.engine, mode: intent.mode, manual: intent.manual,
                  bypass: intent.bypass, excludeSimpleHostnames: intent.excludeSimpleHostnames,
                  authSource: intent.authSource)
    }
}

// MARK: - Observation + drift decision (stage 4 → re-assert)

/// What the Proxy monitor read from `State:/Network/Global/Proxies`, reduced to the
/// coarse "is a proxy enabled, and to where" the drift diff needs.
nonisolated struct ProxyObservation: Sendable, Equatable {
    var enabled: Bool
    var endpoint: ProxyEndpoint?    // nil when disabled or PAC
    var pacURL: String?

    static let none = ProxyObservation(enabled: false, endpoint: nil, pacURL: nil)
}

nonisolated enum ProxyDriftAction: Sendable, Equatable {
    case none
    case reassert
}

nonisolated enum ProxyDriftDecision {
    /// Decide about an observed system-proxy change.
    ///
    /// - `withinSuppressWindow`: our own recent change echoing back — ignore.
    /// - When we EXPECT a proxy (the plan provides one) and the observed system proxy no
    ///   longer matches (disabled, or a different endpoint/PAC), something external
    ///   changed it ⇒ re-assert. When we expect NO proxy, an externally-added proxy is
    ///   also drift (someone else set one under us) ⇒ re-assert. Matching ⇒ none.
    static func action(expected: ProxyPlan, observed: ProxyObservation,
                       withinSuppressWindow: Bool) -> ProxyDriftAction {
        if withinSuppressWindow { return .none }
        switch expected.mode {
        case .none:
            return observed.enabled ? .reassert : .none
        case .manual(let endpoint):
            return (observed.enabled && observed.endpoint == endpoint) ? .none : .reassert
        case .pac(let url):
            return (observed.enabled && observed.pacURL == url) ? .none : .reassert
        }
    }
}

// MARK: - Auth advisory (where the proxy's sign-in actually landed — never silent)

/// The PURE decision about the arbitrated proxy's authentication: given the plan, whether
/// the `authSource` REF resolved to stored credentials, and the sole-writer apply's ack,
/// say where the sign-in landed — applied with the proxy, or NOT injectable (and why).
/// nil ⇒ no proxy, or a proxy with no sign-in configured (nothing to say). The mediator
/// publishes this so a proxy that needs auth we can't provide is surfaced, not silent.
nonisolated enum ProxyAuthAdvisory: Sendable, Equatable {
    /// Credentials rode the apply and the owner engine acked it — `NEProxyServer`
    /// carries `authenticationRequired` + the sign-in.
    case applied
    /// The plan names an `authSource` but the keychain holds nothing for it.
    case missingCredentials
    /// A PAC decision: `NEProxySettings` has no PAC credential slot, so each app
    /// answers the proxy's 407 itself.
    case pacManualAuth
    /// No live NE applier took the credentials (no ack) — this proxy is applied
    /// outside our control (native/OS-owned, or a subprocess kind's own setter),
    /// so the sign-in can't be injected; we only observe.
    case observeOnly

    static func decide(plan: ProxyPlan, credentialsFound: Bool, ack: String?) -> ProxyAuthAdvisory? {
        guard plan.providesProxy, plan.authSource != nil else { return nil }
        if case .pac = plan.mode { return .pacManualAuth }
        guard credentialsFound else { return .missingCredentials }
        return ack == "ok" ? .applied : .observeOnly
    }

    /// The one-liner a UI surface shows (no secrets — names only).
    func message(owner: String?) -> String {
        let name = owner ?? "the VPN"
        switch self {
        case .applied:
            return "Proxy sign-in from your Keychain is applied with the proxy."
        case .missingCredentials:
            return "This proxy is set to authenticate, but no sign-in is stored — add one in \(name)'s Custom Routing ▸ Proxy."
        case .pacManualAuth:
            return "A PAC proxy names its servers per request — the stored sign-in can't be attached system-wide, so apps may prompt."
        case .observeOnly:
            return "\(name)'s proxy is applied outside SimpleVPN's control — the stored sign-in can't be attached, so apps may prompt."
        }
    }

    var symbol: String {
        switch self {
        case .applied: "lock.fill"
        case .missingCredentials: "lock.slash"
        case .pacManualAuth, .observeOnly: "lock.open"
        }
    }
}

// MARK: - VPN-kind participation classifier (Proxy resource)

/// Which clean bucket a connected profile falls into for the PROXY resource
/// (StateMediators.md › VPN-kind participation). Every kind resolves to exactly one.
nonisolated enum ProxyParticipation: Sendable, Equatable {
    /// Can contribute a system-proxy decision: SOCKS kinds that SET the system proxy
    /// (SSH), and tunnels that may PUSH a proxy (OpenVPN, the SSL VPNs). These enter
    /// arbitration.
    case provider
    /// It IS a proxy egress itself (proxy-tunnel) — it re-dials flows through its own
    /// upstream and does not set a separate system proxy.
    case egressItself
    /// Coarse OS-managed proxy (native NEVPNManager kinds via `NEProxySettings`).
    case limited
    /// No proxy of its own (Tailscale, WireGuard, the SSH network tunnel).
    case none
    /// Engine not built — no kind lands here today; kept so the next
    /// engine-less kind gets the honest bucket rather than a lie.
    case unsupported

    /// Does this bucket contribute an intent to the system-proxy arbitration?
    var participates: Bool { self == .provider }

    nonisolated static func classify(_ kind: VPNKind) -> ProxyParticipation {
        switch kind {
        case .ssh,
             .openVPN, .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks:
            return .provider
        case .proxyTunnel:
            return .egressItself
        case .ikev2, .ipsec, .l2tp:
            return .limited
        case .tailscale, .wireGuard, .sshNetworkTunnel:
            // Neither pushes nor sets a proxy — WireGuard's config format has
            // no proxy directive at all.
            //
            // .sshNetworkTunnel is `.none`, NOT `.egressItself`. It looks like the
            // proxy tunnel and is `.egressItself`'s obvious neighbour, but the two
            // buckets mean different things: `.egressItself` says "this VPN IS the
            // proxy the system would otherwise be pointed at", which is what makes
            // the arbiter refuse to nominate the proxy tunnel as system-proxy owner.
            // An SSH network tunnel exposes no proxy endpoint at all — nothing on
            // this Mac could be pointed at it, there is no port to name — so it has
            // no proxy opinion to arbitrate. `.ssh` is `.provider` precisely because
            // it DOES publish a local SOCKS port; this kind publishes none.
            return .none
        }
    }
}
