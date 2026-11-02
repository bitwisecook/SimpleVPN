// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated struct RoutingRailroadStation: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    var details: [String]
    var symbol = "arrow.triangle.branch"
    var warning = false
}

nonisolated struct RoutingRailroadLane: Identifiable, Equatable, Sendable {
    let id: String
    var stations: [RoutingRailroadStation]
    // Only an observed interface may animate. A preview has no measured traffic.
    var observedRate: Double = 0
}

nonisolated struct RoutingRailroadDiagram: Equatable, Sendable {
    var title: String
    var lanes: [RoutingRailroadLane]

    static func includes(_ tab: SettingsTab) -> Bool {
        [.settings, .options, .dns, .customRouting, .configuration, .servers].contains(tab)
    }
}

/// Projects drafts through the real filters and arbiters. No probes, profile
/// saves, provider messages, reconnects, or second routing implementation.
@MainActor
enum RoutingRailroadProjection {
    static func make(profileID id: String, tab: SettingsTab, draft: EditorRoutingDraft,
                     vpn: VPNController, topology: NetworkTopology) -> RoutingRailroadDiagram {
        let snapshot = vpn.lastPushedIntent(for: id)
        let hasReport = snapshot?.capturedAt != nil
        let raw = snapshot ?? PushedIntentSnapshot()
        // A snapshot can have a timestamp from DNS/proxy capture alone.
        // An empty route field is not evidence that the server offered no routes.
        let knownRoutes = draft.networks != nil || (hasReport && !raw.routes.isEmpty && !draft.serverSettingsChanged)
        let prefixes = (draft.networks ?? raw.routes.advertisedPrefixes).filter { !RoutePrefix($0).isDefault }
        let routeInput = RouteIntent(engine: id, advertisedPrefixes: knownRoutes ? prefixes : [],
            wantsDefault: knownRoutes && (draft.wantsDefault ?? raw.routes.wantsDefault),
            canOwnDefault: knownRoutes && draft.canOwnDefault
                && (draft.wantsDefault ?? raw.routes.wantsDefault) && !draft.osManaged,
            connectedAt: vpn.routes.intents[id]?.connectedAt ?? .distantFuture)
        let filteredRoutes = draft.customRouting.routes.apply(to: routeInput)
        let routePlan = vpn.routes.preview(replacing: filteredRoutes)
        let dnsInput = DNSIntent(engine: id,
            resolvers: draft.dnsEnabled ? (draft.resolvers ?? (draft.serverSettingsChanged ? [] : raw.dns.resolvers)) : [],
            searchDomains: draft.resolvers != nil ? draft.searchDomains : (draft.serverSettingsChanged ? [] : raw.dns.searchDomains),
            matchDomains: draft.resolvers != nil || draft.serverSettingsChanged ? [] : raw.dns.matchDomains,
            connectedAt: routeInput.connectedAt)
        let filteredDNS = draft.customRouting.dns.apply(to: dnsInput)
        let dnsPlan = DNSArbiter.plan(intents: vpn.dns.intents.values.filter { $0.engine != id } + [filteredDNS],
                                    policy: DNSPolicy(defaultOwner: routePlan.owner))
        let suppliedProxy: ProxyIntent? = if let local = draft.localProxy {
            ProxyIntent(engine: id, mode: .manual(local))
        } else if draft.proxyKnown || draft.serverSettingsChanged {
            nil
        } else {
            vpn.pushedProxyIntents[id] ?? proxyIntent(raw.proxy, engine: id)
        }
        let filteredProxy = draft.customRouting.proxy.apply(to: suppliedProxy, engine: id)
        var proxyIntents = vpn.proxies.intents.values.filter { $0.engine != id }
        if let filteredProxy { proxyIntents.append(filteredProxy) }
        let proxyPlan = ProxyArbiter.plan(intents: proxyIntents, policy: ProxyPolicy(defaultOwner: routePlan.owner))
        let issues = (CustomRoutingValidator.validate(draft.customRouting, against: snapshot)
            + (draft.networks ?? []).flatMap { CustomRoutingValidator.validateCIDR(RoutePrefix($0), field: "Route", required: true) }
            + (draft.resolvers ?? []).flatMap { CustomRoutingValidator.validateIP($0, field: "DNS server", required: true) })
            .filter(\.isError).map(\.message)
        var lanes: [RoutingRailroadLane] = []

        if tab != .dns {
            let offered = knownRoutes ? routeLines(routeInput) : ["Routes will be learned at connection"]
            var effectiveRoutes = filteredRoutes
            effectiveRoutes.wantsDefault = routePlan.roles[id] == .full
            var effects = routeLines(effectiveRoutes)
            if !knownRoutes { effects = ["Server routes are unknown until connection"] + filteredRoutes.advertisedPrefixes }
            let configurationNotes = draft.notes + draft.bypasses.map { "Requested exclusion: \($0)" }
            if !draft.acceptsSharedRoutes { effects.append("Shared subnet routes disabled; machine addresses remain reachable") }
            if draft.osManaged { effects = ["macOS applies routing on connection"] + draft.notes + draft.bypasses }
            if !issues.isEmpty { effects = ["Invalid draft — this is not an applied route"] + issues }
            lanes.append(lane("routes-draft", [
                station("source", "Traffic — draft", draft.connection, symbol: "laptopcomputer"),
                station("offered", draft.networks == nil ? "Last reported routes" : "Configured routes", offered + configurationNotes),
                station("filter", "Custom Routing", routeRules(draft.customRouting.routes)),
                station("result", "After routing policy", effects + ["Internet default: " + owner(routePlan.owner, vpn)], warning: !issues.isEmpty)
            ]))
            lanes.append(lane("proxy-draft", [
                station("source", "Proxy-aware applications", ["Apps must support the chosen proxy"], symbol: "app.connected.to.app.below.fill"),
                station("offered", "Supplied proxy", proxyLines(suppliedProxy?.mode, manual: suppliedProxy?.manual, bypass: suppliedProxy?.bypass ?? [], simple: suppliedProxy?.excludeSimpleHostnames ?? false)),
                station("filter", "Custom proxy routing", [draft.customRouting.proxy.mode.rawValue]),
                station("result", "System proxy — preview", proxyLines(proxyPlan.mode, manual: proxyPlan.manual, bypass: proxyPlan.bypass, simple: proxyPlan.excludeSimpleHostnames) + ["From: " + owner(proxyPlan.owner, vpn)])
            ]))
        }
        if tab != .customRouting {
            var assignments = dnsLines(dnsPlan)
            if draft.resolvers == nil && (!hasReport || draft.serverSettingsChanged) {
                assignments.insert("Server DNS is unknown until connection", at: 0)
            }
            if !issues.isEmpty { assignments = ["Invalid draft — this is not an applied DNS setting"] + issues }
            if draft.osManaged { assignments = ["DNS is managed by macOS at connection"] }
            lanes.append(lane("dns-draft", [
                station("source", "Name lookups — draft", [draft.dnsEnabled ? "Use this VPN's DNS when assigned" : "Network DNS is disabled"], symbol: "magnifyingglass"),
                station("offered", draft.resolvers == nil ? "Last supplied DNS" : "Configured DNS", dnsInput.resolvers.isEmpty ? ["No resolver supplied"] : dnsInput.resolvers),
                station("filter", "DNS Custom Routing", dnsRules(draft.customRouting.dns)),
                station("result", "Resolver assignments — preview", assignments, warning: !issues.isEmpty)
            ]))
            lanes.append(lane("dns-applied", [
                station("source", "Name lookups — now", ["Settings confirmed by SimpleVPN"], symbol: "checkmark.circle"),
                station("result", "Applied DNS", vpn.dns.appliedPlan.map(dnsLines) ?? ["No confirmed DNS plan yet"])
            ]))
            let scopes = vpn.dns.observedScopes
            for (index, scope) in scopes.enumerated() where !scope.servers.isEmpty {
                lanes.append(lane("dns-observed-\(index)", [
                    station("source", "DNS reported by macOS", ["Includes DNS from other VPN apps"], symbol: "desktopcomputer"),
                    station("scope", "Matching names", scope.matchDomains.isEmpty ? ["Default resolver"] : scope.matchDomains.map { $0.isEmpty ? "All other names" : $0 }),
                    station("result", "DNS servers", scope.servers)
                ]))
            }
            if scopes.isEmpty {
                lanes.append(lane("dns-observed", [station("result", "DNS reported by macOS", vpn.dns.observedResolvers.isEmpty ? ["No resolver observation yet"] : vpn.dns.observedResolvers)]))
            }
        }
        if tab != .dns {
            lanes.append(lane("routes-applied", [
                station("source", "Traffic — applied", ["Settings confirmed by SimpleVPN"], symbol: "checkmark.circle"),
                station("result", "Applied default route", [vpn.routes.appliedPlan.map { owner($0.owner, vpn) } ?? "No confirmed route plan yet"]),
                station("proxy", "Applied system proxy", vpn.proxies.appliedPlan.map { proxyLines($0.mode, manual: $0.manual, bypass: $0.bypass, simple: $0.excludeSimpleHostnames) } ?? ["No confirmed proxy plan yet"])
            ]))
            for iface in topology.interfaces.filter(\.inUse) {
                let observed = topology.snapshot.routes.filter { $0.interfaceName == iface.name }
                let routes = observed.isEmpty
                    ? topology.routes(via: iface.name).map(\.destination)
                    : observed.map { $0.destination + ($0.isScoped ? " (interface-scoped)" : "") }
                let names = routes.isEmpty ? ["No routes reported"] : Array(Set(routes)).sorted()
                lanes.append(RoutingRailroadLane(id: "observed-\(iface.name)", stations: [
                    station("source-\(iface.name)", "Traffic reported by macOS", ["Interface counters; traffic is not attributed to individual rules"], symbol: "desktopcomputer"),
                    station("interface-\(iface.name)", iface.friendlyName, [iface.name] + iface.ipv4, symbol: iface.systemImage),
                    station("networks-\(iface.name)", topology.carriesDefault(iface.name) ? "Internet and destinations" : "Destinations", names)
                ], observedRate: iface.inRate + iface.outRate))
            }
        }
        let title = tab == .dns ? "DNS routing" : tab == .customRouting ? "Custom routing" : "Traffic and DNS routing"
        return RoutingRailroadDiagram(title: title, lanes: lanes)
    }

    private static func owner(_ id: String?, _ vpn: VPNController) -> String {
        guard let id else { return "This Mac's other connection" }
        return vpn.profiles.first(where: { $0.id == id })?.name ?? id
    }

    private static func station(_ id: String, _ title: String, _ details: [String],
                                symbol: String = "arrow.triangle.branch", warning: Bool = false) -> RoutingRailroadStation {
        RoutingRailroadStation(id: id, title: title, details: details, symbol: symbol, warning: warning)
    }

    private static func lane(_ id: String, _ stations: [RoutingRailroadStation]) -> RoutingRailroadLane {
        RoutingRailroadLane(id: id, stations: stations.map { item in
            RoutingRailroadStation(id: id + ":" + item.id, title: item.title,
                details: item.details, symbol: item.symbol, warning: item.warning)
        })
    }

    private static func routeLines(_ intent: RouteIntent) -> [String] {
        (intent.wantsDefault ? ["All otherwise unmatched traffic"] : []) + intent.advertisedPrefixes
            + ((!intent.wantsDefault && intent.advertisedPrefixes.isEmpty) ? ["No destinations through this VPN"] : [])
    }

    private static func routeRules(_ filter: RouteFilter) -> [String] {
        ["Unmatched routes: \(filter.defaultDisposition.rawValue)"] + filter.rules.enumerated().map { index, rule in
            "\(index + 1). \(rule.verb.rawValue): \(rule.match?.value ?? "new route")"
                + (rule.target.map { " → \($0.value)" } ?? "")
        }
    }

    private static func dnsRules(_ dns: DNSCustomization) -> [String] {
        var out = ["Unmatched resolvers: \(dns.defaultDisposition.rawValue)"]
        out += dns.resolverRules.enumerated().map { index, rule in
            "\(index + 1). \(rule.verb.rawValue): \(rule.match ?? "new resolver")" + (rule.target.map { " → \($0)" } ?? "")
        }
        if dns.ignorePushedSearchDomains { out.append("Ignore supplied search domains") }
        if dns.ignorePushedMatchDomains { out.append("Ignore supplied match domains") }
        out += dns.addSearchDomains.map { "Add search domain: \($0)" }
        out += dns.ignoreSearchDomains.map { "Ignore search domain: \($0)" }
        out += dns.addMatchDomains.map { "Use this VPN for: \($0)" }
        out += dns.ignoreMatchDomains.map { "Ignore match domain: \($0)" }
        return out
    }

    private static func dnsLines(_ plan: DNSPlan) -> [String] {
        let lines = plan.applyRequests().sorted { $0.key < $1.key }.flatMap { _, request in
            guard !request.servers.isEmpty else { return [String]() }
            let servers = request.servers.joined(separator: ", ")
            return request.matchDomains.map { ($0.isEmpty ? "All other names" : $0) + " → " + servers }
                + request.searchDomains.map { "Short-name search: " + $0 }
        }
        return lines.isEmpty ? ["Keep this Mac's other resolvers"] : lines
    }

    private static func proxyIntent(_ supplied: PushedIntentSnapshot.Proxy?, engine: String) -> ProxyIntent? {
        guard let supplied else { return nil }
        if let pac = supplied.pacURL { return ProxyIntent(engine: engine, mode: .pac(pac)) }
        func endpoint(_ scheme: ProxyScheme, _ host: String?, _ port: Int?) -> ProxyEndpoint? {
            guard let host, let port else { return nil }
            return ProxyEndpoint(scheme: scheme, host: host, port: port)
        }
        let manual = ProxyManual(http: endpoint(.http, supplied.httpHost, supplied.httpPort),
                                 https: endpoint(.https, supplied.httpsHost, supplied.httpsPort),
                                 socks: endpoint(.socks, supplied.socksHost, supplied.socksPort))
        guard let first = manual.representative else { return nil }
        return ProxyIntent(engine: engine, mode: .manual(first), manual: manual)
    }

    private static func proxyLines(_ mode: ProxyIntent.Mode?, manual: ProxyManual? = nil,
                                   bypass: [String] = [], simple: Bool = false) -> [String] {
        let lines: [String] = switch mode {
        case Optional.none, .some(ProxyIntent.Mode.none): ["Direct — no system proxy"]
        case .some(.manual(let endpoint)):
            if let manual, !manual.isEmpty {
                [manual.http.map { "HTTP → " + $0.display },
                 manual.https.map { "HTTPS → " + $0.display },
                 manual.socks.map { "SOCKS → " + $0.display }].compactMap { $0 }
            } else { [endpoint.display] }
        case .some(.pac(let url)): ["PAC decisions made by: " + EditorRoutingDraft.address(url), "Per-site choices require evaluating the PAC script"]
        }
        return lines + bypass.map { "Direct exception: " + $0 }
            + (simple ? ["Simple hostnames bypass this proxy"] : [])
    }
}
