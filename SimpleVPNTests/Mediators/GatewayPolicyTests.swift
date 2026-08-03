// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GatewayPolicyTests.swift
//  The default-gateway (PolicyRouting.md Tier 2) decision logic. The property
//  that matters is safety: no reachable state may have two `.full` owners, and
//  the switch must strip the old owner before adding the new one. These are pure
//  functions, so they're pinned here rather than driven through the live NE
//  coordinator.
//

import Foundation
import Testing
@testable import SimpleVPN

struct GatewayPolicyTests {

    // MARK: role(for:)

    @Test func roleIsFullOnlyForTheOwner() {
        #expect(GatewayPolicy.role(for: "corp", owner: "corp") == .full)
        #expect(GatewayPolicy.role(for: "home", owner: "corp") == .split)
        #expect(GatewayPolicy.role(for: "corp", owner: nil) == .split)   // Direct ⇒ everyone split
    }

    /// The core invariant: across ANY set of connected profiles and ANY owner
    /// (including a non-connected or nil owner), at most one profile is `.full`.
    @Test func atMostOneFullOwnerForAnyReachableState() {
        let profiles = ["corp", "home", "lab", "personal"]
        let owners: [String?] = [nil, "corp", "home", "lab", "personal", "not-connected"]
        for owner in owners {
            let fullCount = profiles.filter { GatewayPolicy.role(for: $0, owner: owner) == .full }.count
            #expect(fullCount <= 1, "owner=\(owner ?? "nil") produced \(fullCount) full owners")
        }
    }

    // MARK: switchSteps — the atomic strip→add state machine

    @Test func switchStripsOldBeforeAddingNew() {
        let steps = GatewayPolicy.switchSteps(from: "corp", to: "home")
        #expect(steps == [.split("corp"), .full("home")])
        // The split MUST precede the full — never two fulls, never add-before-strip.
        #expect(steps.firstIndex(of: .split("corp"))! < steps.firstIndex(of: .full("home"))!)
    }

    @Test func switchToDirectOnlyStrips() {
        #expect(GatewayPolicy.switchSteps(from: "corp", to: nil) == [.split("corp")])
    }

    @Test func switchFromDirectOnlyAdds() {
        #expect(GatewayPolicy.switchSteps(from: nil, to: "home") == [.full("home")])
    }

    @Test func switchToSameOwnerIsNoOp() {
        #expect(GatewayPolicy.switchSteps(from: "corp", to: "corp").isEmpty)
        #expect(GatewayPolicy.switchSteps(from: nil, to: nil).isEmpty)
    }

    /// No sequence produced by the switch ever grants two fulls.
    @Test func switchNeverProducesTwoFulls() {
        let ids: [String?] = [nil, "a", "b", "c"]
        for from in ids {
            for to in ids {
                let fulls = GatewayPolicy.switchSteps(from: from, to: to).filter {
                    if case .full = $0 { return true }; return false
                }
                #expect(fulls.count <= 1)
            }
        }
    }

    // MARK: canBeDefaultGateway per kind

    @Test func capabilityPerKind() {
        // Packet-egress full-tunnel kinds: capable when connected.
        for kind: VPNKind in [.openVPN, .proxyTunnel, .wireGuard, .fortinet, .f5apm, .ciscoAnyConnect,
                              .globalProtect, .juniper, .pulse, .arrayNetworks] {
            #expect(GatewayPolicy.canBeDefaultGateway(kind: kind, connected: true, tailscaleHasExitNode: false))
            #expect(!GatewayPolicy.canBeDefaultGateway(kind: kind, connected: false, tailscaleHasExitNode: false))
        }
        // Tailscale only with an exit node.
        #expect(!GatewayPolicy.canBeDefaultGateway(kind: .tailscale, connected: true, tailscaleHasExitNode: false))
        #expect(GatewayPolicy.canBeDefaultGateway(kind: .tailscale, connected: true, tailscaleHasExitNode: true))
        // Kinds that can't carry a default route, ever.
        for kind: VPNKind in [.ssh, .ikev2, .ipsec, .l2tp] {
            #expect(!GatewayPolicy.canBeDefaultGateway(kind: kind, connected: true, tailscaleHasExitNode: true))
        }
    }

    // MARK: resolveOwner

    @Test func resolveHonoursAStoredCapablePick() {
        #expect(GatewayPolicy.resolveOwner(stored: "home", userChoseDirect: false,
                                           capableConnected: ["corp", "home"]) == "home")
    }

    @Test func resolveAutoAdoptsMostRecentWhenUnset() {
        // capableConnected is most-recent-first, so .first is the newest.
        #expect(GatewayPolicy.resolveOwner(stored: nil, userChoseDirect: false,
                                           capableConnected: ["home", "corp"]) == "home")
    }

    @Test func resolveFallsBackWhenStoredOwnerVanishes() {
        // "home" disconnected; auto-promote the remaining capable profile.
        #expect(GatewayPolicy.resolveOwner(stored: "home", userChoseDirect: false,
                                           capableConnected: ["corp"]) == "corp")
    }

    @Test func resolveRespectsExplicitDirect() {
        #expect(GatewayPolicy.resolveOwner(stored: nil, userChoseDirect: true,
                                           capableConnected: ["corp", "home"]) == nil)
    }

    @Test func resolveIsDirectWhenNothingCapable() {
        #expect(GatewayPolicy.resolveOwner(stored: "corp", userChoseDirect: false,
                                           capableConnected: []) == nil)
    }

    /// End-to-end of the invariant through the resolver + role: whatever the
    /// resolver picks, exactly one connected-capable profile ends up full.
    @Test func resolvedOwnerYieldsAtMostOneFull() {
        let capable = ["corp", "home", "lab"]
        let owner = GatewayPolicy.resolveOwner(stored: "home", userChoseDirect: false,
                                               capableConnected: capable)
        let fulls = capable.filter { GatewayPolicy.role(for: $0, owner: owner) == .full }
        #expect(fulls == ["home"])
    }

    // MARK: gatewayAction — the RC1 regression (seed the baseline from ENGINE
    // REALITY, not the client-.ovpn text grep)

    /// THE RC1 REGRESSION: the server pushed `redirect-gateway` so the engine is
    /// effectively FULL, but this VPN isn't the owner ⇒ we MUST send gateway:split.
    /// The old text-grep baseline (split) matched the desired split and skipped it,
    /// leaving the tunnel full (and, with two VPNs, two default owners).
    @Test func engineFullButNotOwnerMustSendSplit() {
        #expect(GatewayPolicy.gatewayAction(engineOwnsDefault: true, desired: .split) == .split)
    }

    /// A server-pushed-full single VPN the user turned to Direct: engine full,
    /// desired split ⇒ split. This is exactly the single-VPN "internet through the
    /// VPN off" case that was previously impossible to send.
    @Test func engineFullWithDirectDesiredMustSendSplit() {
        #expect(GatewayPolicy.gatewayAction(engineOwnsDefault: true, desired: .split) == .split)
    }

    /// The owner really needs the default but the engine came up split (not the
    /// owner's config, or a stale suppress) ⇒ send full.
    @Test func engineSplitButOwnerMustSendFull() {
        #expect(GatewayPolicy.gatewayAction(engineOwnsDefault: false, desired: .full) == .full)
    }

    /// Engine already matches the desired role ⇒ no IPC (the legitimate skip the
    /// idempotency guard is FOR — as long as the baseline is engine reality).
    @Test func engineMatchesDesiredIsNoOp() {
        #expect(GatewayPolicy.gatewayAction(engineOwnsDefault: true, desired: .full) == nil)
        #expect(GatewayPolicy.gatewayAction(engineOwnsDefault: false, desired: .split) == nil)
    }

    // MARK: single-VPN control (RC2) — owner/Direct resolves correctly

    @Test func singleVPNOwnsByDefaultAndCanGoDirect() {
        // The lone connected capable VPN auto-adopts the default (its "route all
        // internet through this VPN" switch defaults on)…
        let owner = GatewayPolicy.resolveOwner(stored: nil, userChoseDirect: false,
                                               capableConnected: ["solo"])
        #expect(owner == "solo")
        #expect(GatewayPolicy.role(for: "solo", owner: owner) == .full)
        // …and turning it off (explicit Direct) demotes it to split.
        let direct = GatewayPolicy.resolveOwner(stored: nil, userChoseDirect: true,
                                                capableConnected: ["solo"])
        #expect(direct == nil)
        #expect(GatewayPolicy.role(for: "solo", owner: direct) == .split)
    }

    // MARK: two-VPN invariant holds under the new engine-truth seeding

    /// With the bug's starting state (BOTH engines report full) the resolver still
    /// picks exactly one owner and the per-profile action drives every non-owner to
    /// split — so the resulting state never has two `.full` owners.
    @Test func twoBothFullEnginesResolveToOneOwner() {
        let capable = ["corp", "home"]
        let picks: [String?] = ["corp", "home", nil]
        for pick in picks {
            let owner = GatewayPolicy.resolveOwner(stored: pick, userChoseDirect: pick == nil,
                                                   capableConnected: capable)
            // Both engines currently full (the bug state); compute each resulting role.
            let resulting = capable.map { id -> GatewayRole in
                let desired = GatewayPolicy.role(for: id, owner: owner)
                let action = GatewayPolicy.gatewayAction(engineOwnsDefault: true, desired: desired)
                return action ?? .full   // nil action ⇒ stays at the engine's current (full)
            }
            #expect(resulting.filter { $0 == .full }.count <= 1,
                    "pick=\(pick ?? "nil") left \(resulting.filter { $0 == .full }.count) full owners")
        }
    }
}
