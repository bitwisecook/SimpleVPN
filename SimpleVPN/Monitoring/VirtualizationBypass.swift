// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VirtualizationBypass.swift
//  Turning "a VPN is about to swallow your container's network" into the app's
//  EXISTING bypass concept, and refusing to do so where it could not help.
//
//  NO NEW MECHANISM. A guest subnet that must stay reachable is a `RoutingRule`
//  with `.outside` — the same divert rule the traffic log already creates, carried
//  to every engine by the same `DivertPlan` → `extraExcludedRoutes` path, and
//  governed by the same `ManagedPolicy.allowDivertOutside`. Inventing a parallel
//  "VM exclusions" list would have produced a second answer to "what leaves this
//  tunnel", and the two would drift.
//
//  WHAT THIS FILE REFUSES TO DO, which is most of its value:
//
//   • It offers NOTHING for a `.userspace` product. Docker Desktop's guests have
//     no subnet, so there is no rule that could help; producing one would be a
//     visible, satisfying, completely inert change.
//   • It never returns a rule for `bridge0` or a physical LAN — that filtering
//     happens upstream in `VirtualizationDiscovery.guestNetworks`, and the tests
//     here pin that it stays true through this layer.
//   • It applies nothing. It RETURNS what could be applied, so the caller can show
//     it, name the consequence and wait to be told. Excluding a subnet is a
//     split-tunnel decision — traffic to it leaves the VPN — and this feature must
//     never make one silently.
//

import Foundation

/// One thing SimpleVPN could offer to do, with the consequence spelled out.
nonisolated struct VirtualizationBypassOffer: Sendable, Equatable, Identifiable {
    /// The guest subnet to keep out of the tunnel.
    var subnet: String
    /// What is on it, in the words the report and the UI both use.
    var attribution: String
    /// The rule that would be added — the app's ordinary divert rule, not a new
    /// kind of thing.
    var rule: RoutingRule

    var id: String { subnet }

    /// The consequence, stated plainly. Never softened: this is a split tunnel.
    var consequence: String {
        "Traffic to \(subnet) will leave this Mac outside the VPN. That is what keeps "
        + "\(attribution) reachable, and it also means the VPN neither carries nor protects it."
    }
}

/// Why there is nothing to offer. Reported rather than returning an empty list,
/// because "nothing to do" and "nothing that could work" need different sentences.
nonisolated enum VirtualizationBypassRefusal: Sendable, Equatable, Error {
    /// Detection is switched off, so we know nothing.
    case detectionOff
    /// Nothing was running with a network of its own.
    case noLiveGuestNetwork
    /// Everything installed translates in userspace: there is no subnet to keep
    /// out, and routing settings cannot help. Carries the products, so the message
    /// can name them.
    case onlyUserspaceProducts([String])
    /// An administrator has forbidden diverting traffic out of the tunnel.
    case forbiddenByPolicy

    var words: String {
        switch self {
        case .detectionOff:
            "SimpleVPN isn\u{2019}t looking for virtual machines on this Mac (that setting is off)."
        case .noLiveGuestNetwork:
            "Nothing was running with a network of its own. A guest\u{2019}s network only exists "
            + "while the guest is running."
        case .onlyUserspaceProducts(let titles):
            "\(titles.joined(separator: " and ")) sends its guests\u{2019} traffic out as this "
            + "Mac\u{2019}s own, so there is no network to keep out of the tunnel and routing "
            + "settings cannot help. Lower the guest\u{2019}s MTU to at or below the tunnel\u{2019}s, "
            + "and point it at a resolver it can reach."
        case .forbiddenByPolicy:
            "Your organisation does not allow traffic to be sent outside the VPN."
        }
    }
}

nonisolated enum VirtualizationBypass {

    /// What could be offered for a snapshot, or why nothing can be.
    ///
    /// `allowDivertOutside` is passed in rather than read from `ManagedPolicy`
    /// here so this stays a pure function — and so the MDM refusal is TESTED
    /// rather than assumed. The caller is still gated again downstream: the
    /// extension re-applies `policyKeepInside` when it builds the `DivertPlan`, so
    /// a rule stored before a policy arrived cannot leak.
    static func offers(for snapshot: VirtualizationSnapshot,
                       allowDivertOutside: Bool)
        -> Result<[VirtualizationBypassOffer], VirtualizationBypassRefusal> {

        guard snapshot.detectionEnabled else { return .failure(.detectionOff) }
        guard allowDivertOutside else { return .failure(.forbiddenByPolicy) }

        guard !snapshot.guestNetworks.isEmpty else {
            // Distinguish "nothing was running" from "nothing here could ever be
            // helped by a route". Someone with only Docker installed needs the
            // second sentence, and giving them the first would send them off to
            // start a container that was never the problem.
            let userspaceOnly = snapshot.userspaceOnlyProducts
            if !userspaceOnly.isEmpty,
               snapshot.installed.allSatisfy({ $0.networking == .userspace }) {
                return .failure(.onlyUserspaceProducts(userspaceOnly.map(\.title)))
            }
            return .failure(.noLiveGuestNetwork)
        }

        var seen = Set<String>()
        let offers = snapshot.guestNetworks.compactMap { network -> VirtualizationBypassOffer? in
            guard seen.insert(network.subnet).inserted else { return nil }
            let rule = RoutingRule(
                destination: network.subnet,
                action: .outside,
                note: "\(network.attribution) on \(network.interfaceName)")
            // A rule the divert path would reject is not offered. `routeDest` refuses
            // prefix 0, so a guest network that somehow presented as 0.0.0.0/0 could
            // never become a whole-VPN bypass wearing this feature's clothes.
            guard rule.isValidDivert else { return nil }
            return VirtualizationBypassOffer(subnet: network.subnet,
                                             attribution: network.attribution,
                                             rule: rule)
        }
        guard !offers.isEmpty else { return .failure(.noLiveGuestNetwork) }
        return .success(offers)
    }

    /// Which of the offers a profile has not already got a rule for. So a second
    /// connection does not re-offer what the user already accepted, and accepting
    /// twice cannot produce two rules for one subnet.
    static func outstanding(_ offers: [VirtualizationBypassOffer],
                            existing: [RoutingRule]) -> [VirtualizationBypassOffer] {
        let covered = Set(existing
            .filter { $0.action == .outside && $0.enabled }
            .map(\.destination))
        return offers.filter { !covered.contains($0.subnet) }
    }
}
