// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteMediatorTests.swift
//  The Route mediator's PURE core (Docs/StateMediators.md, P1). Everything exercised
//  here is a total function with no I/O — the arbiter plan (≤1 owner, strip-old →
//  add-new ordering, owner-disconnect promotion), the VPN-kind participation
//  classifier, the drift → re-assert decision, and the PF_ROUTE message parser (fed
//  hand-built `rt_msghdr` bytes). No live network, no NE, no socket.
//

import Foundation
import Darwin
import os
import Testing
@testable import SimpleVPN

/// Minimal `RouteMediatorHost` whose gateway IPC reply is scriptable, for exercising
/// the realizer's apply outcome in isolation (no NE, no live session).
@MainActor
private final class StubRouteHost: RouteMediatorHost {
    var gatewayReply: String?
    var routeProfiles: [RouteProfileInfo] { [] }
    func routeSendGateway(full: Bool, to id: String) async -> String? { gatewayReply }
    func routeApplyTailscaleGateway(full: Bool, to id: String) async -> String? { nil }
    func routeReconnect(id: String) async {}
    func routeSampleEffectiveOwned(id: String) async -> Bool? { nil }
    func routeWantsFullTunnel(id: String) -> Bool { false }
    func routeAdvertisedPrefixes(id: String) -> [String] { [] }
}

struct RouteMediatorTests {

    // MARK: - Arbiter plan (stage 2)

    private func intent(_ id: String, capable: Bool = true, at seconds: Double? = nil) -> RouteIntent {
        RouteIntent(engine: id, advertisedPrefixes: [], wantsDefault: capable,
                    canOwnDefault: capable, metric: 0,
                    connectedAt: seconds.map { Date(timeIntervalSinceReferenceDate: $0) })
    }

    /// Whatever the resolver picks, at most one engine ends up `.full`.
    @Test func planNeverProducesTwoFullOwners() {
        let intents = [intent("corp", at: 1), intent("home", at: 2), intent("lab", at: 3)]
        for stored in [nil, "corp", "home", "lab", "ghost"] as [String?] {
            let plan = RouteArbiter.plan(intents: intents,
                                         policy: RoutePolicy(storedOwner: stored, userChoseDirect: false))
            #expect(plan.fullOwners.count <= 1, "stored=\(stored ?? "nil") produced \(plan.fullOwners)")
        }
    }

    /// The ordered application strips every non-owner BEFORE granting the owner — the
    /// property that makes two simultaneous defaults structurally impossible.
    @Test func planStripsOldBeforeAddingNew() {
        let plan = RouteArbiter.plan(
            intents: [intent("corp", at: 1), intent("home", at: 2)],
            policy: RoutePolicy(storedOwner: "corp", userChoseDirect: false))
        #expect(plan.owner == "corp")
        // The single `.full` must be the last step; every `.split` precedes it.
        guard let fullIndex = plan.orderedApplication.firstIndex(of: .full("corp")) else {
            Issue.record("no full step for the owner"); return
        }
        for (i, step) in plan.orderedApplication.enumerated() {
            if case .split = step { #expect(i < fullIndex, "a split came after the full") }
        }
        #expect(plan.orderedApplication.last == .full("corp"))
        #expect(plan.roles["home"] == .split)
        #expect(plan.roles["corp"] == .full)
    }

    /// The owner disconnected ⇒ the stored pick is no longer among the intents, so the
    /// plan auto-promotes the most-recent remaining capable engine.
    @Test func planPromotesOnOwnerDisconnect() {
        // "home" (stored owner) is gone; only "corp" and "lab" remain, lab most recent.
        let plan = RouteArbiter.plan(
            intents: [intent("corp", at: 1), intent("lab", at: 5)],
            policy: RoutePolicy(storedOwner: "home", userChoseDirect: false))
        #expect(plan.owner == "lab")
        #expect(plan.fullOwners == ["lab"])
    }

    /// An explicit Direct means nobody owns the default, whatever is connected.
    @Test func planHonoursExplicitDirect() {
        let plan = RouteArbiter.plan(
            intents: [intent("corp", at: 1), intent("home", at: 2)],
            policy: RoutePolicy(storedOwner: nil, userChoseDirect: true))
        #expect(plan.owner == nil)
        #expect(plan.fullOwners.isEmpty)
        #expect(plan.orderedApplication.allSatisfy { if case .split = $0 { return true }; return false })
    }

    /// Non-capable engines (e.g. a Tailscale with no exit node) never win the owner
    /// slot but still get a split role.
    @Test func planExcludesIncapableFromOwnership() {
        let plan = RouteArbiter.plan(
            intents: [intent("corp", capable: false, at: 2), intent("home", at: 1)],
            policy: RoutePolicy(storedOwner: nil, userChoseDirect: false))
        #expect(plan.owner == "home")
        #expect(plan.roles["corp"] == .split)
    }

    // MARK: - VPN-kind participation classifier

    @Test func participationBucketsEveryKind() {
        // Route-participants (get a live gateway role + ≤1-owner arbitration).
        for kind: VPNKind in [.openVPN, .proxyTunnel, .tailscale, .wireGuard, .fortinet, .f5apm,
                              .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks] {
            #expect(RouteMediator.participation(for: kind) == .full, "\(kind) should be .full")
            #expect(RouteMediator.participation(for: kind).appliesGatewayRole)
            #expect(RouteMediator.participation(for: kind).isSelectableOwner)
        }
        // Native NEVPNManager kinds: coarse / limited, out of the live switch.
        for kind: VPNKind in [.ikev2, .ipsec, .l2tp] {
            #expect(RouteMediator.participation(for: kind) == .limited, "\(kind) should be .limited")
            #expect(!RouteMediator.participation(for: kind).appliesGatewayRole)
            #expect(!RouteMediator.participation(for: kind).isSelectableOwner)
        }
        // Proxy-only (SOCKS egress, no default route) — the Proxy mediator's turf.
        #expect(RouteMediator.participation(for: .ssh) == .proxyOnly)
        #expect(!RouteMediator.participation(for: .ssh).appliesGatewayRole)
    }

    /// Tailscale participates in role application regardless of exit node (ownership is
    /// gated separately by `canBeDefaultGateway`) — behavior-preserving.
    @Test func tailscaleAlwaysParticipatesInRoleApplication() {
        #expect(RouteMediator.participation(for: .tailscale, tailscaleHasExitNode: false) == .full)
        #expect(RouteMediator.participation(for: .tailscale, tailscaleHasExitNode: true) == .full)
    }

    /// OpenConnect now demotes LIVE (task 15 closed): an "ok" ack from its bridge
    /// means the role was applied in place — the realizer must NOT fall back to a
    /// reconnect. The needs-reconnect outcome survives only as a generic fallback.
    @MainActor
    @Test func openConnectDemotesLiveNotViaReconnect() async {
        let host = StubRouteHost()
        let realizer = MultiTunnelRealizer(
            host: host, log: Logger(subsystem: "com.bragi0.SimpleVPN.tests", category: "route"))

        // Live demote: an OpenConnect (SSL-VPN) kind acking "ok" ⇒ .applied, no reconnect.
        host.gatewayReply = "ok"
        let live = await realizer.apply(.split, to: "oc", kind: .ciscoAnyConnect, hasExitNode: false)
        #expect(live == .applied)

        // The reconnect fallback is still honored for any engine that reports it.
        realizer.forget(id: "oc2")
        host.gatewayReply = "needs-reconnect"
        let fallback = await realizer.apply(.split, to: "oc2", kind: .fortinet, hasExitNode: false)
        #expect(fallback == .needsReconnect)
    }

    // MARK: - Drift → re-assert decision (stage 4)

    @Test func driftReassertsWhenObservedDiffersFromExpected() {
        // We expect a tunnel to own the default; the OS now routes direct ⇒ re-assert.
        let expected = DefaultRouteState(ownedByTunnel: true, interface: nil)
        let observed = DefaultRouteState(ownedByTunnel: false, interface: "en0")
        #expect(RouteDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .reassert)
    }

    @Test func driftIgnoredWithinSuppressWindow() {
        // Same divergence, but it's inside the window after our OWN write ⇒ ignore.
        let expected = DefaultRouteState(ownedByTunnel: true, interface: nil)
        let observed = DefaultRouteState(ownedByTunnel: false, interface: "en0")
        #expect(RouteDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: true) == .none)
    }

    @Test func driftNoActionWhenObservedMatchesExpected() {
        let expected = DefaultRouteState(ownedByTunnel: true, interface: nil)
        let observed = DefaultRouteState(ownedByTunnel: true, interface: "utun4")
        #expect(RouteDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .none)
    }

    @Test func driftReassertsWhenKnownExpectedInterfaceChanges() {
        // Both tunnels, but we know the owner's egress and the observed one differs.
        let expected = DefaultRouteState(ownedByTunnel: true, interface: "utun4")
        let observed = DefaultRouteState(ownedByTunnel: true, interface: "utun7")
        #expect(RouteDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .reassert)
    }

    // MARK: - PF_ROUTE message parsing (fed hand-built rt_msghdr bytes)

    /// Build one routing-socket message: an `rt_msghdr` header padded to stride,
    /// followed by the packed RTAX_* sockaddrs the mask selects.
    private func routeMessage(type: Int32, dst: [UInt8], mask: [UInt8]?, host: Bool = false) -> [UInt8] {
        let headerSize = MemoryLayout<rt_msghdr>.stride

        // DST sockaddr_in (16 bytes): sin_len, sin_family, port(2), addr(4), zero(8).
        var dstSA = [UInt8](repeating: 0, count: 16)
        dstSA[0] = 16
        dstSA[1] = UInt8(AF_INET)
        for (i, b) in dst.prefix(4).enumerated() { dstSA[4 + i] = b }

        var addrs: Int32 = RTA_DST
        var sockaddrs = dstSA
        if let mask {
            addrs |= RTA_NETMASK
            if mask.isEmpty {
                sockaddrs += [0, 0, 0, 0]                 // /0: an sa_len==0 placeholder slot
            } else {
                var maskSA = [UInt8](repeating: 0, count: 16)
                maskSA[0] = 16
                maskSA[1] = UInt8(AF_INET)
                for (i, b) in mask.prefix(4).enumerated() { maskSA[4 + i] = b }
                sockaddrs += maskSA
            }
        }

        var hdr = rt_msghdr()
        hdr.rtm_msglen = UInt16(headerSize + sockaddrs.count)
        hdr.rtm_version = UInt8(RTM_VERSION)
        hdr.rtm_type = UInt8(truncatingIfNeeded: type)
        hdr.rtm_index = 7
        hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | (host ? RTF_HOST : 0)
        hdr.rtm_addrs = addrs

        var bytes = withUnsafeBytes(of: hdr) { Array($0) }
        if bytes.count < headerSize { bytes += [UInt8](repeating: 0, count: headerSize - bytes.count) }
        bytes += sockaddrs
        return bytes
    }

    @Test func parsesDefaultRouteAddAsDefaultChange() {
        let bytes = routeMessage(type: RTM_ADD, dst: [0, 0, 0, 0], mask: [])
        let messages = PFRouteMonitor.parseMessages(bytes, length: bytes.count)
        #expect(messages.count == 1)
        let m = try! #require(messages.first)
        #expect(m.kind == .add)
        #expect(m.family == .v4)
        #expect(m.isDefault)
        #expect(m.isDefaultRouteChange)
        #expect(m.interfaceIndex == 7)
    }

    @Test func parsesDefaultRouteDeleteAndChange() {
        for (type, expected) in [(RTM_DELETE, ParsedRouteMessage.Kind.delete),
                                 (RTM_CHANGE, ParsedRouteMessage.Kind.change)] {
            let bytes = routeMessage(type: type, dst: [0, 0, 0, 0], mask: [])
            let m = try! #require(PFRouteMonitor.parseMessages(bytes, length: bytes.count).first)
            #expect(m.kind == expected)
            #expect(m.isDefaultRouteChange)
        }
    }

    /// A specific (non-default) route is parsed but is NOT a default-route change.
    @Test func specificRouteIsNotADefaultChange() {
        let bytes = routeMessage(type: RTM_ADD, dst: [10, 0, 0, 0], mask: [255, 0, 0, 0])
        let m = try! #require(PFRouteMonitor.parseMessages(bytes, length: bytes.count).first)
        #expect(m.family == .v4)
        #expect(!m.isDefault)
        #expect(!m.isDefaultRouteChange)
    }

    /// A host route to 0.0.0.0 (RTF_HOST) is not a default route.
    @Test func zeroHostRouteIsNotDefault() {
        let bytes = routeMessage(type: RTM_ADD, dst: [0, 0, 0, 0], mask: nil, host: true)
        let m = try! #require(PFRouteMonitor.parseMessages(bytes, length: bytes.count).first)
        #expect(!m.isDefault)
    }

    /// Two concatenated messages both parse (the walker advances by rtm_msglen).
    @Test func parsesMultipleConcatenatedMessages() {
        let a = routeMessage(type: RTM_ADD, dst: [0, 0, 0, 0], mask: [])
        let b = routeMessage(type: RTM_DELETE, dst: [10, 0, 0, 0], mask: [255, 0, 0, 0])
        let bytes = a + b
        let messages = PFRouteMonitor.parseMessages(bytes, length: bytes.count)
        #expect(messages.count == 2)
        #expect(messages[0].isDefault)
        #expect(!messages[1].isDefault)
    }
}
