// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import os
import Testing
@testable import SimpleVPN

@MainActor
private final class DelayedRouteHost: RouteMediatorHost {
    var routeProfiles = ["a", "b"].enumerated().map { index, id in
        RouteProfileInfo(id: id, name: id, kind: .wireGuard, connected: true,
                         engaged: true, lastConnectedAt: Date(timeIntervalSince1970: Double(index)),
                         tailscaleHasExitNode: false)
    }
    var writes: [GatewayPolicy.Step] = []
    var prefixes: [String: RouteApplyRequest] = [:]
    var routeVirtualProfileIDs: Set<String> = []
    var virtualPlans: [RoutePlan] = []
    var refuseVirtualPlan = false
    var rejectDemotion = false
    var holdFirst = false
    var release: CheckedContinuation<Void, Never>?
    let events = AsyncStream<Void>.makeStream()
    func routeApplyVirtualPlan(_ plan: RoutePlan) async -> Bool {
        virtualPlans.append(plan)
        if holdFirst {
            holdFirst = false
            await withCheckedContinuation { release = $0; events.continuation.yield(()) }
        }
        return !refuseVirtualPlan
    }
    func routeSendGateway(full: Bool, to id: String) async -> String? {
        writes.append(full ? .full(id) : .split(id))
        if holdFirst {
            holdFirst = false
            await withCheckedContinuation { release = $0; events.continuation.yield(()) }
        }
        return !full && rejectDemotion ? "error: refused" : "ok"
    }
    func routeApplyPrefixes(_ request: RouteApplyRequest, to id: String) async -> String? {
        prefixes[id] = request
        return "ok"
    }
    func routeApplyTailscaleGateway(full: Bool, to id: String) async -> String? { nil }
    func routeReconnect(id: String) async {}
    var holdSample = false
    var releaseSample: CheckedContinuation<Void, Never>?
    let sampleStarted = AsyncStream<Void>.makeStream()
    let sampleFinished = AsyncStream<Bool>.makeStream()
    func routeSampleEffectiveOwned(id: String) async -> Bool? {
        guard holdSample else { return nil }
        holdSample = false
        await withCheckedContinuation { releaseSample = $0; sampleStarted.continuation.yield(()) }
        sampleFinished.continuation.yield(Task.isCancelled)
        return false
    }
    func routeWantsFullTunnel(id: String) -> Bool { true }
    func routeAdvertisedPrefixes(id: String) -> [String] { ["10.0.0.0/8"] }
}

@MainActor
private final class DNSApplyHost: DNSMediatorHost {
    var dnsProfiles: [DNSProfileInfo] = []
    var dnsDefaultOwner: String? { "a" }
    var reply: String? = "ok"
    var calls = 0
    var reconnects = 0
    var holdNext = false
    let events = AsyncStream<Void>.makeStream()
    var release: CheckedContinuation<Void, Never>?
    var requests: [DNSApplyRequest?] = []
    var dnsVirtualProfileIDs: Set<String> = []
    var virtualRequests: [[String: DNSApplyRequest]] = []
    func dnsApplyVirtual(_ requests: [String: DNSApplyRequest]) async -> Bool {
        virtualRequests.append(requests)
        return reply == "ok"
    }
    func dnsApply(_ request: DNSApplyRequest?, to id: String) async -> String? {
        calls += 1
        requests.append(request)
        if holdNext {
            holdNext = false
            await withCheckedContinuation { release = $0; events.continuation.yield(()) }
        }
        return reply
    }
    func dnsReconnect(id: String) async { reconnects += 1 }
}

@MainActor
private final class ProxyApplyHost: ProxyMediatorHost {
    var proxyProfiles = ["a", "b"].map {
        ProxyProfileInfo(id: $0, name: $0, kind: .openVPN, connected: true,
            engaged: true, lastConnectedAt: nil, mode: .pac("https://proxy.example/\($0).pac"))
    }
    var proxyDefaultOwner: String? { "a" }
    var refuse: String?
    var writes: [String] = []
    func proxyReassert(owner: String) async {}
    func proxyApply(_ request: ProxyApplyRequest?, to id: String) async -> String? {
        writes.append("\(id):\(request == nil ? "clear" : "set")")
        return request != nil && refuse == id ? "error" : "ok"
    }
}

@Suite(.serialized)
@MainActor
struct MediatorApplyIntegrationTests {
    @Test func refreshingAnExistingGatewayReappliesItAfterOtherRoutesAreWithdrawn() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        await mediator.setDefaultGateway(to: "b")
        host.writes.removeAll()

        await mediator.applyGatewayPreference(mediator.gatewayPreference, refreshGateway: true)

        #expect(host.writes == [.split("a"), .full("b")])
        #expect(mediator.appliedPlan?.owner == "b")
    }

    @Test func virtualGatewaySwitchHasOneCompleteTransactionAndRequiresAck() async {
        let host = DelayedRouteHost()
        host.routeVirtualProfileIDs = ["a", "b"]
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        await mediator.setDefaultGateway(to: "a")
        host.holdFirst = true
        let change = Task { await mediator.setDefaultGateway(to: "b") }
        var events = host.events.stream.makeAsyncIterator()
        await events.next()
        #expect(mediator.appliedPlan?.owner == "a")
        #expect(host.virtualPlans.map(\.owner) == ["a", "b"])
        #expect(host.writes.isEmpty && host.prefixes.isEmpty)
        #expect(host.virtualPlans.last?.roles == ["a": .split, "b": .full])
        host.release?.resume()
        await change.value
        #expect(mediator.appliedPlan?.owner == "b")
        #expect(mediator.displayedGatewayOwner == "b")
        host.refuseVirtualPlan = true
        await mediator.setDefaultGateway(to: nil)
        #expect(mediator.appliedPlan?.owner == "b")
        #expect(mediator.lastApplyError != nil)
        #expect(host.virtualPlans.last?.userChoseDirect == true)
    }
    @Test func overlappingStartsAndDepartingGatewayWaitForOwnership() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        let connected = host.routeProfiles
        host.routeProfiles = []
        var initial: [Bool] = []
        mediator.startWithGateway(for: "a", wantsDefault: true) { initial.append($0) }
        mediator.startWithGateway(for: "b", wantsDefault: true) { initial.append($0) }
        #expect(initial == [true, false])
        host.routeProfiles = [connected[1]] // the split session became ready first
        await mediator.setDefaultGateway(to: "b")
        #expect(host.writes.isEmpty)
        host.routeProfiles = connected
        mediator.handleStatusChange(id: "a", connected: true, reasserting: false, disconnected: false)
        await mediator.waitUntilIdle()
        #expect(host.writes == [.split("a"), .full("b")])

        var leaving = RouteProfileInfo(id: "b", name: "b", kind: .wireGuard, connected: false,
                                      engaged: false, lastConnectedAt: nil, tailscaleHasExitNode: false)
        leaving.retainingRoutesDuringTransition = true
        host.routeProfiles = [connected[0], leaving]
        await mediator.setDefaultGateway(to: "a")
        #expect(!host.writes.contains(.full("a")))
        host.routeProfiles = [connected[0]]
        mediator.handleStatusChange(id: "b", connected: false, reasserting: false, disconnected: true)
        await mediator.waitUntilIdle()
        #expect(host.writes.last == .full("a"))
    }

    @Test func removingAnEstablishingProfileReleasesItsClaimAndCancelsOutstandingSeeds() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        let connected = host.routeProfiles[0]
        host.routeProfiles = []
        var initial: [Bool] = []
        mediator.startWithGateway(for: "a", wantsDefault: true) { initial.append($0) }
        mediator.forgetSession("a")  // preferences removal without an NE callback
        mediator.startWithGateway(for: "b", wantsDefault: true) { initial.append($0) }
        #expect(initial == [true, true])
        mediator.forgetSession("b")

        host.routeProfiles = [connected]
        host.holdSample = true
        var started = host.sampleStarted.stream.makeAsyncIterator()
        mediator.handleStatusChange(id: "a", connected: true, reasserting: false, disconnected: false)
        await started.next()
        mediator.forgetSession("a")
        mediator.handleStatusChange(id: "a", connected: true, reasserting: false, disconnected: false)
        await mediator.waitUntilIdle()
        var finished = host.sampleFinished.stream.makeAsyncIterator()
        host.releaseSample?.resume()
        #expect(await finished.next() == true)
        #expect(mediator.engineDefaultOwned["a"] == true)
    }

    @Test func lateGatewayAckCannotSeedReplacementSession() async {
        let host = DelayedRouteHost()
        let realizer = MultiTunnelRealizer(host: host, log: Logger(subsystem: "test", category: "route"))
        host.holdFirst = true
        let old = Task { await realizer.apply(.full, to: "a", kind: .wireGuard, hasExitNode: false) }
        var events = host.events.stream.makeAsyncIterator()
        await events.next()
        realizer.forget(id: "a")
        host.release?.resume()
        #expect(await old.value == .failed)
        #expect(realizer.applied("a") == nil)
        #expect(await realizer.apply(.full, to: "a", kind: .wireGuard, hasExitNode: false) == .applied)
        #expect(host.writes == [.full("a"), .full("a")])
    }

    @Test func expiredDNSReplyCannotSkipReapplyOrLeaveAnUnconfirmedResolver() async {
        let host = DNSApplyHost()
        host.dnsProfiles = [.init(id: "a", name: "a", kind: .wireGuard, connected: true, engaged: true,
                                  lastConnectedAt: nil, resolvers: [], searchDomains: [], matchDomains: [], wantsCatchAll: true)]
        let realizer = DNSRealizer(host: host, log: Logger(subsystem: "test", category: "dns"))
        let plan = DNSArbiter.plan(intents: [.init(engine: "a", resolvers: ["10.0.0.53"], wantsCatchAll: true)],
                                   policy: .init(defaultOwner: "a"))
        host.holdNext = true
        let old = Task { await realizer.apply(plan, force: false) }
        var events = host.events.stream.makeAsyncIterator()
        await events.next()
        realizer.forget(id: "a")
        host.release?.resume()
        #expect(await old.value == false)
        host.reply = nil
        #expect(await realizer.apply(plan, force: false) == false)
        host.reply = "ok"
        let empty = DNSArbiter.plan(intents: [], policy: .init(defaultOwner: nil))
        #expect(await realizer.apply(empty, force: false))
        #expect(host.requests == [plan.applyRequests()["a"], plan.applyRequests()["a"], nil])
    }

    @Test func sharedDNSOwnerSwitchUsesOneCompleteWriteAndRetriesUnacknowledgedPlans() async {
        let host = DNSApplyHost()
        host.dnsVirtualProfileIDs = ["a", "b"]
        let realizer = DNSRealizer(host: host, log: Logger(subsystem: "test", category: "dns"))
        let intents = [DNSIntent(engine: "a", resolvers: ["10.0.0.53"], wantsCatchAll: true),
                       DNSIntent(engine: "b", resolvers: ["10.0.0.54"], wantsCatchAll: true)]
        let first = DNSArbiter.plan(intents: intents, policy: .init(defaultOwner: "a"))
        let next = DNSArbiter.plan(intents: intents, policy: .init(defaultOwner: "b"))
        #expect(await realizer.apply(first, force: false))
        host.reply = "error"
        #expect(!(await realizer.apply(next, force: false)))
        host.reply = "ok"
        #expect(await realizer.apply(next, force: false))
        #expect(await realizer.apply(next, force: false))
        #expect(host.virtualRequests == [first.applyRequests(), next.applyRequests(), next.applyRequests()])
        #expect(host.virtualRequests.last?["a"]?.isEmpty == true)
        #expect(host.virtualRequests.last?["b"]?.servers == ["10.0.0.54"])
        #expect(host.requests.isEmpty)
    }

    @Test func partiallyFailedProxySwitchCannotSuppressRestoreOfPreviousOwner() async {
        let host = ProxyApplyHost()
        let realizer = ProxyRealizer(host: host, log: Logger(subsystem: "SimpleVPN.tests", category: "proxy"))
        let first = ProxyPlan(owner: "a", mode: .pac("https://proxy.example/a.pac"))
        let next = ProxyPlan(owner: "b", mode: .pac("https://proxy.example/b.pac"))
        #expect(await realizer.apply(first, force: false))
        host.refuse = "b"
        #expect(await realizer.apply(next, force: false) == false)
        #expect(await realizer.apply(first, force: false))
        #expect(host.writes == ["a:set", "a:clear", "b:set", "a:set"])
    }
    @Test func failedDemotionCannotPromoteNewOwner() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        host.rejectDemotion = true
        await mediator.setDefaultGateway(to: "b")
        #expect(host.writes == [.split("a")])
        #expect(mediator.appliedPlan == nil)
        #expect(mediator.lastApplyError != nil)
        host.rejectDemotion = false
        mediator.reconcileGateway()
        await mediator.waitUntilIdle()
        #expect(host.writes == [.split("a"), .split("a"), .full("b")])
        #expect(mediator.appliedPlan?.owner == "b")
    }

    @Test func filteredPlanReachesLiveOwnerAndPrefixApplier() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        mediator.intentHook = { intent in
            if intent.engine == "b" {
                var filter = RouteFilter()
                filter.rules = [.init(verb: .ignore, match: .default),
                                .init(verb: .replace, match: RoutePrefix("10.0.0.0/8"),
                                      target: RoutePrefix("10.42.0.0/16"))]
                intent = filter.apply(to: intent)
            }
        }
        await mediator.setDefaultGateway(to: "b")
        #expect(mediator.plan.owner == "a")
        #expect(mediator.appliedPlan == mediator.plan)
        #expect(!host.writes.contains(.full("b")))
        #expect(host.prefixes["b"]?.prefixes == ["10.42.0.0/16"])
        #expect(!mediator.predictedGatewayOwned("b"))
    }

    @Test func supersededSwitchCannotPromoteItsOldTarget() async {
        let host = DelayedRouteHost()
        host.holdFirst = true
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        let first = Task { await mediator.setDefaultGateway(to: "a") }
        var events = host.events.stream.makeAsyncIterator()
        await events.next()
        let latest = Task { await mediator.setDefaultGateway(to: "b") }
        // Wait until the latest desired owner is recorded before releasing the write.
        while mediator.plan.owner != "b" { await Task.yield() }
        host.release?.resume()
        await first.value
        await latest.value
        #expect(!host.writes.contains(.full("a")))
        #expect(host.writes.last == .full("b"))
        #expect(mediator.appliedPlan?.owner == "b")
    }

    @Test func reassertActuallyWritesUnchangedRoles() async {
        let host = DelayedRouteHost()
        let mediator = RouteMediator(preferences: nil)
        mediator.host = host
        await mediator.setDefaultGateway(to: "a")
        let initial = host.writes.count
        mediator.reassertNow()
        await mediator.waitUntilIdle()
        #expect(host.writes.count == initial + 2)
    }

    @Test func failedOrMissingDNSAckIsRetriedWithoutOriginalConfigReconnect() async {
        let host = DNSApplyHost()
        let realizer = DNSRealizer(host: host, log: Logger(subsystem: "SimpleVPN.tests", category: "dns"))
        let plan = DNSArbiter.plan(intents: [DNSIntent(engine: "a", resolvers: ["10.0.0.53"],
            searchDomains: ["corp.example"], wantsCatchAll: true)], policy: DNSPolicy(defaultOwner: "a"))
        host.reply = "error: refused"
        #expect(await realizer.apply(plan, force: false) == false)
        host.reply = nil
        #expect(await realizer.apply(plan, force: false) == false)
        host.reply = "ok"
        #expect(await realizer.apply(plan, force: false))
        #expect(host.calls == 3)
        #expect(host.reconnects == 0)
        #expect(await realizer.apply(plan, force: false))
        #expect(host.calls == 3)
        #expect(await realizer.apply(plan, force: true))
        #expect(host.calls == 4)
        #expect(plan.applyRequests()["a"]?.searchDomains == ["corp.example"])
    }

    @Test func losingCatchAllExplicitlySuppressesUnscopedDNS() {
        let plan = DNSArbiter.plan(intents: [DNSIntent(engine: "a", resolvers: ["10.0.0.53"], wantsCatchAll: true),
            DNSIntent(engine: "b", resolvers: ["10.1.0.53"], wantsCatchAll: true)],
            policy: DNSPolicy(defaultOwner: "a"))
        #expect(plan.applyRequests()["b"] == DNSApplyRequest())
    }
}
