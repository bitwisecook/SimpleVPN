// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

extension VPNController {
    /// Connected auxiliary engines share the same query policy; no second DNS router.
    func setAuxiliaryDNSQueryProfiles(_ profiles: [String: String]) {
        guard profiles != auxiliaryDNSQueryProfiles else { return }
        auxiliaryDNSQueryProfiles = profiles
        syncDNSQueryRouting()
    }
    func syncDNSQueryRouting(force: Bool = false) {
        dnsQueries.update(dnsQueryPolicy(), force: force)
    }
    /// Preview includes the selected draft even while disconnected, but never activates it.
    func dnsQueryPolicy(replacing id: String? = nil, with draft: DNSCustomization? = nil, resolversOverride: [String]? = nil) -> DNSQueryPolicy {
        var names = Dictionary(uniqueKeysWithValues: profiles.filter { $0.status == .connected }.map { ($0.id, $0.name) })
        for (id, name) in auxiliaryDNSQueryProfiles { names[id] = name }
        if let id { names[id] = profiles.first { $0.id == id }?.name ?? auxiliaryDNSQueryProfiles[id] ?? "This VPN" }
        let inputs = names.keys.map { id in
            DNSIntent(engine: id, connectedAt: lastConnectedAt[id])
        }
        let order = DNSArbiter.ranked(intents: inputs, policy: DNSPolicy(defaultOwner: dnsDefaultOwner))
        var routes: [DNSQueryRoute] = []
        for input in order {
            let custom = input.engine == id ? (draft ?? customRouting(for: input.engine).dns) : customRouting(for: input.engine).dns
            guard custom.queryRoutingEnabled else { continue }
            let supplied = dnsProfiles.first { $0.id == input.engine }
            let raw = DNSIntent(engine: input.engine, resolvers: input.engine == id ? (resolversOverride ?? supplied?.resolvers ?? []) : (supplied?.resolvers ?? []))
            let resolvers = custom.apply(to: raw).resolvers
            for rule in custom.queryRules where rule.enabled {
                routes.append(DNSQueryRoute(profileID: input.engine, profileName: names[input.engine] ?? input.engine,
                    rule: rule, servers: rule.target == .original ? [] : (rule.servers.isEmpty ? resolvers : rule.servers)))
            }
        }
        return DNSQueryPolicy(routes: routes)
    }
}
