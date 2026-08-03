// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GatewayPolicy.swift
//  The pure decision logic behind the "default gateway" picker (PolicyRouting.md
//  Tier 2). Kept UI-free and nonisolated so it can be exercised in isolation —
//  the invariant it enforces is safety-critical: at most ONE connected VPN may
//  advertise 0.0.0.0/0 at a time (macOS will not arbitrate two full-tunnel
//  providers). Everything here is a total function of its inputs; VPNController
//  owns the live NE state and calls in.
//

import Foundation

/// What a connected VPN does with the default route.
///   `.full`  — it owns 0.0.0.0/0: unmatched traffic goes through it.
///   `.split` — its default route is suppressed; only its own pushed subnets
///              are advertised. A VPN that *wanted* full-tunnel but isn't the
///              picked owner is transparently demoted to this.
nonisolated enum GatewayRole: String, Equatable, Sendable {
    case full
    case split
}

nonisolated enum GatewayPolicy {

    /// The role a connected profile plays given the current default-route owner
    /// (`owner == nil` ⇒ Direct: nobody owns the default, so everyone is split).
    /// This is the whole invariant in one line: exactly the owner is `.full`.
    static func role(for profileID: String, owner: String?) -> GatewayRole {
        profileID == owner ? .full : .split
    }

    /// Can this kind carry 0.0.0.0/0 as the default gateway when connected?
    ///   - packet-egress full-tunnel kinds (openvpn3, the OpenConnect SSL-VPNs,
    ///     the proxy tunnel, WireGuard — its engine re-applies the demotion
    ///     live like the proxy tunnel) can, once connected.
    ///   - tailscale can *only* when an exit node is configured or available —
    ///     without one it has no way to carry everything, so it stays split.
    ///   - anything that cannot advertise a default route at all (SSH, the native
    ///     personal-VPN kinds) never can.
    static func canBeDefaultGateway(kind: VPNKind, connected: Bool,
                                    tailscaleHasExitNode: Bool) -> Bool {
        guard connected else { return false }
        switch kind {
        case .openVPN, .proxyTunnel, .wireGuard,
             .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks:
            return true
        case .tailscale:
            return tailscaleHasExitNode
        case .ikev2, .ipsec, .l2tp, .ssh:
            return false
        }
    }

    /// One atomic-switch step. The ORDER these are produced in is the safety
    /// property: STRIP-OLD before ADD-NEW.
    nonisolated enum Step: Equatable, Sendable {
        case split(String)   // strip the default route from this (former) owner
        case full(String)    // grant the default route to this (new) owner
    }

    /// The steps to move the default-gateway ownership from `current` to `next`.
    ///
    /// ORDERING — STRIP-OLD → (confirm) → ADD-NEW, deliberately:
    /// the current owner is told to go split *before* the new owner is told to go
    /// full. This yields a brief sub-second window where NOBODY owns the default
    /// (traffic is momentarily direct), but it makes it **structurally
    /// impossible** for two VPNs to both hold 0.0.0.0/0 at once — which macOS
    /// cannot arbitrate. Two-defaults is the failure we never permit; a masked
    /// one-frame gap is the price. The caller awaits the split ack before issuing
    /// the full.
    static func switchSteps(from current: String?, to next: String?) -> [Step] {
        guard current != next else { return [] }
        var steps: [Step] = []
        if let current { steps.append(.split(current)) }
        if let next { steps.append(.full(next)) }
        return steps
    }

    /// The gateway IPC (if any) needed to bring a connected profile whose engine
    /// currently reports `engineOwnsDefault` to the desired `role`. Returns nil when
    /// the engine already matches — otherwise the role to send.
    ///
    /// The baseline is ENGINE REALITY, never a client-.ovpn text grep. This is the
    /// whole RC1 fix in one total function: a `.connected` engine reporting
    /// effective-FULL while the desired role is `.split` MUST yield `.split` here.
    /// (The old code seeded the baseline from the config text; when the server
    /// pushed `redirect-gateway` but the client text didn't restate it, it saw
    /// split==split and wrongly sent nothing, leaving the tunnel full — and, with
    /// two VPNs, both advertising the default.)
    static func gatewayAction(engineOwnsDefault: Bool, desired: GatewayRole) -> GatewayRole? {
        let engineRole: GatewayRole = engineOwnsDefault ? .full : .split
        return engineRole == desired ? nil : desired
    }

    /// Resolve who should own the default route, given the capable connected
    /// profiles (most-recently-connected FIRST), the user's stored pick, and
    /// whether the user explicitly chose Direct.
    ///
    /// - a stored pick that is still a capable connected profile wins;
    /// - otherwise, unless the user explicitly chose Direct, we auto-adopt the
    ///   most-recently-connected capable profile (this both preserves stock
    ///   single-VPN behaviour — the lone VPN keeps its default — and, when the
    ///   owner disconnects, transparently promotes the next capable VPN);
    /// - if the user chose Direct, or nothing is capable, the owner is nil.
    ///
    /// Deterministic tiebreak: `capableConnected` is ordered most-recent-first,
    /// so `.first` is the newest connection among the capable set.
    static func resolveOwner(stored: String?, userChoseDirect: Bool,
                             capableConnected: [String]) -> String? {
        if let stored, capableConnected.contains(stored) { return stored }
        if userChoseDirect { return nil }
        return capableConnected.first
    }
}
