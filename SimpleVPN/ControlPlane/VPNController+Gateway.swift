// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+Gateway.swift
//  The routing face of VPNController: the thin default-gateway forwarders the
//  UI/menu call (the decision itself lives in RouteMediator — Docs/
//  StateMediators.md), per-VPN Custom Routing (the tier-2 pushed-intent
//  filters), the divert rules (route a destination around this VPN), and the
//  three mediator-host conformances that make this controller the live NE side
//  for the Route, DNS and Proxy mediators. Stored state (the routing-rule and
//  custom-routing caches) lives in VPNController.swift.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: Custom Routing (per-VPN pushed-intent filters — Mediators/CustomRouting.swift)


    /// The saved Custom Routing filter for a profile; identity (no-op) when none was set.
    /// Profiles with no NE manager (the native NEVPNManager kinds) read the UserDefaults
    /// fallback the setter wrote instead of a providerConfiguration blob.
    func customRouting(for id: String) -> CustomRoutingProfile {
        if let cached = customRoutingCache[id] { return cached }
        guard let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol else {
            return CustomRoutingFallbackStore().load(id)
        }
        return CustomRoutingProfile.decode(from: proto.providerConfiguration?["customrouting"] as? Data)
    }

    /// Persist a profile's Custom Routing filter (dropped entirely when empty) and
    /// LIVE-APPLY it immediately: re-arbitrate + push through the route/DNS/proxy appliers
    /// with no reconnect. Safe to call when the profile is offline — it then only persists
    /// and takes effect on the next connect.
    /// MDM `LockConfiguration` covers this exactly as it covers the engine
    /// settings — routes, DNS and the system proxy are connection settings, and
    /// the proxy sign-in is a keychain write. The guard lives HERE, below the UI,
    /// so the disabled tab is a courtesy rather than the enforcement point (the
    /// shape `setWireGuardConfig`/`setOverrides` already had).
    func setCustomRouting(_ profile: CustomRoutingProfile, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else {
            // No NE manager: the native NEVPNManager kinds live here permanently (their
            // filter — the custom proxy especially — must survive relaunch, so it goes
            // to the UserDefaults fallback store), and a fresh import lands here
            // transiently (the cache carries it until a real manager exists).
            customRoutingCache[id] = profile
            CustomRoutingFallbackStore().save(profile, for: id)
            return
        }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = profile.encodedBlob() { conf["customrouting"] = blob }
        else { conf.removeValue(forKey: "customrouting") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        customRoutingCache[id] = profile
        // The providerConfiguration blob is authoritative now — retire any fallback
        // entry a pre-manager save left behind.
        CustomRoutingFallbackStore().clear(id)
        await applyCustomRouting(forProfile: id)
    }

    /// Live-reconcile entry point the UI calls on commit (Save / navigate-away). Re-projects
    /// the FILTERED intent for the mediators (captured ∘ filter, via the intent hooks) and
    /// drives all three to re-arbitrate + live-apply through the existing appliers — no
    /// reconnect. When the profile isn't connected there is nothing live to re-project, so
    /// it is a no-op beyond the already-persisted config (which applies on next connect).
    /// Idempotent: the arbiters are pure and the realizers skip an unchanged plan, so it is
    /// safe to call repeatedly.
    func applyCustomRouting(forProfile id: String) async {
        // Arbitration is inherently cross-profile (≤1 default owner, one system proxy, one
        // coherent split-DNS), so a single profile's filter change re-arbitrates the whole
        // connected set. `reassertNow` re-runs intent capture (through the hooks) then
        // reconciles + realizes.
        routes.reassertNow()
        dns.reassertNow()
        proxies.reassertNow()
    }

    // MARK: Default gateway (PolicyRouting.md Tier 2 — the ≤1-default-owner invariant)
    //
    // At most ONE connected VPN owns 0.0.0.0/0 (full-tunnel) at a time — macOS
    // will not arbitrate two full-tunnel providers, so this is enforced, not
    // hoped for. Every other connected VPN is demoted to split (its own subnets
    // only). The user picks the owner live between any connected VPN and Direct.
    // The pure decision logic lives in GatewayPolicy; this owns the live NE side.

    // The gateway decision + state now live in `routes` (RouteMediator). VPNController
    // keeps only the thin forwarders the UI/menu already call, plus the profile-derived
    // helpers the mediator asks it for through `RouteMediatorHost` (below). See
    // Docs/StateMediators.md — this is the behavior-preserving P1 extraction.

    /// Whether a connected profile can be the full-tunnel owner. (Delegates.)
    func canBeDefaultGateway(_ id: String) -> Bool { routes.canBeDefaultGateway(id) }
    /// The role a connected profile currently plays. (Delegates.)
    func gatewayRole(for id: String) -> GatewayRole { routes.gatewayRole(for: id) }
    /// The owner actually in force right now. (Delegates.)
    var effectiveGatewayOwner: String? { routes.effectiveGatewayOwner }
    /// What the traffic-path picture should show (engine truth). (Delegates.)
    var displayedGatewayOwner: String? { routes.displayedGatewayOwner }
    /// The owner the engines actually report. (Delegates.)
    var engineReportedGatewayOwner: String? { routes.engineReportedGatewayOwner }
    /// Show the default-gateway control when there's a choice to make. (Delegates.)
    var showsDefaultGatewayControl: Bool { routes.showsDefaultGatewayControl }
    /// Establish-time ownership prediction (RC3), passed via `startTunnel`. (Delegates.)
    func predictedGatewayOwned(_ id: String) -> Bool { routes.predictedGatewayOwned(id) }
    /// The user picked a new default-gateway owner. (Delegates the atomic switch.)
    func setDefaultGateway(to newOwner: String?) async {
        // Guarded here (not just in the dispatcher): the Routes window's picker
        // calls this directly, and MDM's ForceKeepInsideVPN must bind it too.
        if let why = controlDenied(.setDefaultGateway(profile: newOwner)) { lastError = why; return }
        await routes.setDefaultGateway(to: newOwner)
    }

    /// Connected profiles, most-recently-connected FIRST (the deterministic
    /// tiebreak for auto-promotion). Falls back to name order when recency is
    /// unknown so the ordering is always total.
    var connectedProfiles: [Profile] {
        profiles.filter { $0.status == .connected }
            .sorted { a, b in
                let ta = lastConnectedAt[a.id] ?? .distantPast
                let tb = lastConnectedAt[b.id] ?? .distantPast
                if ta != tb { return ta > tb }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    /// The exit node this Tailscale profile would use as a gateway: its
    /// configured node if set, else the first available one the engine sees.
    private func tailscaleExitNode(for id: String) -> String {
        let c = tailscaleConfig(for: id)
        if c.useExitNode, !c.exitNode.isEmpty { return c.exitNode }
        return tailscaleStatuses[id]?.exitNodes.first(where: { $0.online })?.id
            ?? tailscaleStatuses[id]?.exitNodes.first?.id ?? ""
    }

    /// Whether a profile's own config wants to carry everything (redirect-gateway
    /// / default route / exit node). Drives the "wants everything but isn't the
    /// default" demotion note and the initial-role assumption.
    func profileWantsFullTunnel(_ id: String) -> Bool {
        guard let p = profiles.first(where: { $0.id == id }) else { return false }
        switch p.kind {
        case .proxyTunnel:
            return proxyTunnelConfig(for: id).includeDefaultRoute
        case .tailscale:
            let c = tailscaleConfig(for: id)
            return c.useExitNode && !c.exitNode.isEmpty
        case .wireGuard:
            return wireGuardConfig(for: id).isFullTunnel
        case .openVPN:
            return (ovpnText(id: id) ?? "").range(of: "redirect-gateway", options: .caseInsensitive) != nil
        default:
            return p.kind.isSSLVPN   // OpenConnect builds a full-tunnel by default
        }
    }

    /// The specific subnets a connected VPN carries besides (or instead of) the
    /// default route — the "X also routes …" line under the picker. Best-effort
    /// per engine; empty when we can't enumerate them.
    func gatewaySubnets(for id: String) -> [String] {
        guard let p = profiles.first(where: { $0.id == id }) else { return [] }
        switch p.kind {
        case .proxyTunnel:
            let c = proxyTunnelConfig(for: id)
            return c.includeDefaultRoute ? [] : c.includedRoutes
        case .tailscale:
            let routes = tailscaleStatuses[id]?.config?.subnetRoutes ?? []
            return routes.filter { $0 != "0.0.0.0/0" && $0 != "::/0" }
        case .wireGuard:
            // The peer's allowed IPs besides the default routes.
            return wireGuardConfig(for: id).allowedIPs.filter { $0 != "0.0.0.0/0" && $0 != "::/0" }
        default:
            return []
        }
    }

    // MARK: Divert rules (route a destination around this VPN)


    func routingRules(for id: String) -> [RoutingRule] {
        if let cached = routingRulesCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return RoutingRuleStore.decode(from: proto?.providerConfiguration?["routingRules"] as? Data)
    }

    /// Persist a profile's own rules (its excluded/divert destinations), then
    /// re-materialise every profile's "route into me" include-set and reconnect
    /// whatever's live so the change takes effect.
    func setRoutingRules(_ rules: [RoutingRule], for id: String) async {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = RoutingRuleStore.encode(rules) { conf["routingRules"] = blob }
        else { conf.removeValue(forKey: "routingRules") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        routingRulesCache[id] = rules

        // The source profile's excludes changed → reconnect it.
        await reconnectIfActive(id)
        // Targets of any .overVPN rule need their include-set refreshed.
        await syncIncludes()
    }

    private func reconnectIfActive(_ id: String) async {
        guard profiles.first(where: { $0.id == id }).map({ UI.isActive($0.status) }) == true else { return }
        beginReconfiguring(id); defer { endReconfiguring(id) }
        await reconnect(id: id)
    }

    /// Recompute, for every profile, the destinations *other* profiles route into
    /// it (the target side of `.overVPN`), write them to its providerConfiguration,
    /// and reconnect it if the set changed while live.
    private func syncIncludes() async {
        for target in profiles {
            // A kind whose routes we don't own can't be handed a destination
            // (VPNKind.canAcceptRoutedInTraffic — Tailscale's netmap decides what a
            // tailnet carries; macOS owns the native kinds' table; SSH carries only
            // its forwards). The traffic-log menu no longer offers those targets, but
            // a rule stored before that check existed must not keep reconnecting a
            // VPN to install routes its engine will ignore.
            guard target.kind.canAcceptRoutedInTraffic else { continue }
            let dests: [RouteDest] = profiles
                .filter { $0.id != target.id }
                .flatMap { routingRules(for: $0.id) }
                .filter { $0.enabled && $0.action == .overVPN(profileID: target.id) }
                .compactMap { $0.routeDest }
            guard let mgr = managers[target.id],
                  let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { continue }
            var conf = proto.providerConfiguration ?? [:]
            let newBlob = RouteDestStore.encode(dests)
            let oldBlob = conf["routingIncludes"] as? Data
            if newBlob == oldBlob { continue }              // no change for this target
            if let newBlob { conf["routingIncludes"] = newBlob } else { conf.removeValue(forKey: "routingIncludes") }
            proto.providerConfiguration = conf
            mgr.protocolConfiguration = proto
            try? await mgr.saveToPreferences()
            try? await mgr.loadFromPreferences()
            await reconnectIfActive(target.id)
        }
    }

    func addRoutingRule(_ rule: RoutingRule, for id: String) async {
        // Org policy can forbid diverting traffic around / off the VPN.
        switch rule.action {
        case .outside where !ManagedPolicy.allowDivertOutside: return
        case .overVPN where !ManagedPolicy.allowDivertOverVPN: return
        default: break
        }
        var rules = routingRules(for: id)
        // Replace any existing rule for the same destination.
        rules.removeAll { $0.destination == rule.destination }
        rules.append(rule)
        await setRoutingRules(rules, for: id)
    }

    func removeRoutingRule(id ruleID: String, for id: String) async {
        var rules = routingRules(for: id)
        rules.removeAll { $0.id == ruleID }
        await setRoutingRules(rules, for: id)
    }
}

// MARK: - RouteMediatorHost (the live NE side for the Route mediator)

extension VPNController: RouteMediatorHost {
    /// Project the live profiles into the mediator's snapshot. Reads the observable
    /// `profiles` (and `lastConnectedAt`) so the mediator's computeds stay tracked.
    var routeProfiles: [RouteProfileInfo] {
        profiles.map { p in
            RouteProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                tailscaleHasExitNode: p.kind == .tailscale && !tailscaleExitNode(for: p.id).isEmpty)
        }
    }

    func routeSendGateway(full: Bool, to id: String) async -> String? {
        await sendMessage(full ? "gateway:full" : "gateway:split", to: id)
    }

    /// Apply gateway ownership to a Tailscale profile via its exit-node prefs path —
    /// the exact patch the inline code built.
    func routeApplyTailscaleGateway(full: Bool, to id: String) async -> String? {
        let patch: TailscalePrefsPatch
        if full {
            let node = tailscaleExitNode(for: id)
            guard !node.isEmpty else { return nil }   // not capable; leave as-is (no-op success)
            patch = TailscalePrefsPatch(acceptRoutes: nil, acceptDNS: nil,
                                        useExitNode: true, exitNode: node,
                                        exitNodeAllowLANAccess: nil, advertiseRoutes: nil)
        } else {
            patch = TailscalePrefsPatch(acceptRoutes: nil, acceptDNS: nil,
                                        useExitNode: false, exitNode: nil,
                                        exitNodeAllowLANAccess: nil, advertiseRoutes: nil)
        }
        return await pushTailscalePrefs(patch, id: id)
    }

    func routeReconnect(id: String) async { await reconnect(id: id) }

    @discardableResult
    func routeSampleEffectiveOwned(id: String) async -> Bool? {
        await fetchStats(id: id)?.effectiveDefaultOwned
    }

    func routeWantsFullTunnel(id: String) -> Bool { profileWantsFullTunnel(id) }
    func routeAdvertisedPrefixes(id: String) -> [String] { gatewaySubnets(for: id) }
}

// MARK: - DNSMediatorHost (the live NE side for the DNS mediator)

extension VPNController: DNSMediatorHost {
    /// Project the live profiles into the DNS mediator's snapshot, sourcing each
    /// tunnel's DNS intent from the config we hold app-side. Best-effort: proxy-tunnels
    /// carry an explicit resolver list; other kinds' pushed DNS lands at the engine
    /// bridge (the tier-3 `DNS_PUSHED` capture seam) and reads back through the observed
    /// system resolvers the mediator already publishes.
    var dnsProfiles: [DNSProfileInfo] {
        profiles.map { p in
            var resolvers: [String] = []
            var matchDomains: [String] = []
            var wantsCatchAll = false
            if p.kind == .proxyTunnel {
                let c = proxyTunnelConfig(for: p.id)
                resolvers = c.dnsServers
                wantsCatchAll = c.includeDefaultRoute && !c.dnsServers.isEmpty
                matchDomains = wantsCatchAll ? [""] : []
            }
            if p.kind == .wireGuard {
                // wg-quick's DNS= servers become the catch-all resolver (that
                // is the directive's meaning); a config with no DNS= line
                // contributes nothing.
                let c = wireGuardConfig(for: p.id)
                resolvers = c.dns
                wantsCatchAll = !c.dns.isEmpty
                matchDomains = wantsCatchAll ? [""] : []
            }
            return DNSProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                resolvers: resolvers, searchDomains: [],
                matchDomains: matchDomains, wantsCatchAll: wantsCatchAll)
        }
    }

    var dnsDefaultOwner: String? { routes.effectiveGatewayOwner }

    /// SOLE-WRITER DNS apply: send ONE participant's arbitrated `NEDNSSettings` slice to
    /// its live session via the `dns:apply:` IPC (nil/empty ⇒ `dns:clear`), the same
    /// shape as `proxyApply`. Returns the engine ack, or `nil` when there is no live DNS
    /// applier for this tunnel (native kinds have no NETunnelProviderSession; the
    /// proxy-tunnel / Tailscale engines reply nil because they can't hot-swap DNS) — the
    /// realizer reads that nil as "fall back to reconnect".
    func dnsApply(_ request: DNSApplyRequest?, to id: String) async -> String? {
        guard let request, !request.isEmpty else { return await sendMessage("dns:clear", to: id) }
        guard let json = try? JSONEncoder().encode(request),
              let text = String(data: json, encoding: .utf8) else { return nil }
        return await sendMessage("dns:apply:\(text)", to: id)
    }

    func dnsReconnect(id: String) async { await reconnect(id: id) }
}

// MARK: - ProxyMediatorHost (the live NE side for the Proxy mediator)

extension VPNController: ProxyMediatorHost {
    /// Project the live profiles into the Proxy mediator's snapshot. Pushed/SOCKS proxy
    /// detail for the subprocess kinds (SSH `-D`, ocproxy) is owned by the subprocess
    /// manager, not this controller, so those arrive as `.none` here and the mediator
    /// leans on the observed system proxy it publishes from SCDynamicStore — the
    /// intent-capture seam for populating them live is deliberately left clean (tier-3
    /// `PROXY_PUSHED`).
    var proxyProfiles: [ProxyProfileInfo] {
        profiles.map { p in
            // The engine's ground-truth pushed proxy (from stats) is the OpenVPN
            // per-kind capture; other kinds contribute nothing (mode .none).
            let pushed = pushedProxyIntents[p.id]
            return ProxyProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                mode: pushed?.mode ?? .none,
                manual: pushed?.manual,
                bypass: pushed?.bypass ?? [],
                excludeSimpleHostnames: pushed?.excludeSimpleHostnames ?? false,
                authSource: pushed?.authSource)
        }
    }

    var proxyDefaultOwner: String? { routes.effectiveGatewayOwner }

    func proxyReassert(owner: String) async { await reconnect(id: owner) }

    /// SOLE-WRITER proxy apply: send the arbitrated `NEProxySettings` decision to ONE
    /// tunnel's live session via the `proxy:apply:` IPC (nil ⇒ `proxy:clear`), the same
    /// shape as the `gateway:full|split` + DNS re-apply paths. Returns the engine ack
    /// (nil when there's no NE session — e.g. an SSH SOCKS kind that isn't ours to set).
    func proxyApply(_ request: ProxyApplyRequest?, to id: String) async -> String? {
        guard let request, !request.isEmpty else { return await sendMessage("proxy:clear", to: id) }
        guard let json = try? JSONEncoder().encode(request),
              let text = String(data: json, encoding: .utf8) else { return nil }
        return await sendMessage("proxy:apply:\(text)", to: id)
    }
}
