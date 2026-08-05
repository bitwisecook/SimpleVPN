// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+GuestNetworks.swift
//  THE CONNECT-TIME HOOK for `VirtualizationBypass`. Everything below this line was
//  built and tested by the VM/container feed; nothing called it, so `vm.warn-on-connect`
//  gated a path that never ran. This file is that call, and nothing else.
//
//  WHY THE HOOK IS `handleStatusChange(.connecting)` AND NOT A CONNECT METHOD.
//  There is no single connect method to hang it on: `connect(id:plan:…)` is the funnel
//  for the credential-carrying engines, but Tailscale, WireGuard, the Proxy Tunnel and
//  the SSH Network Tunnel each have their own (`connectWithTransientCredentials`
//  dispatches to them BEFORE reaching the funnel). Four call sites for one warning is
//  how three of them end up out of date. Every one of those engines is an
//  `NETunnelProviderManager` underneath, so all four arrive at `.connecting` — which is
//  also the honest moment: the guest network is about to be swallowed, and the
//  interface list has to be read live because a guest's subnet exists only while the
//  guest is running.
//
//  WHAT IT REFUSES TO DO:
//
//   • It never applies a rule. `VirtualizationBypass` returns offers precisely so the
//     consequence can be named and consented to; this file preserves that. Accepting is
//     `acceptGuestNetworkBypass` and the user has to press it.
//   • It says nothing about a VPN that would not capture the network anyway. A
//     split-tunnel VPN carrying 10.0.0.0/8 has no quarrel with 192.168.64.0/24, and a
//     banner there would be noise that teaches people to ignore the banner.
//   • It does not persist a dismissal. See `dismissedGuestNetworkCaptures`.
//

import Foundation

extension VirtualizationBypass {

    /// Which outstanding offers THIS tunnel would actually swallow.
    ///
    /// A PURE FUNCTION taking the tunnel's shape rather than a profile id, for the same
    /// reason `offers(for:allowDivertOutside:)` takes the MDM answer as a parameter: the
    /// decision that matters is testable without a running virtual machine, a real
    /// profile or a real VPN. `VPNController` supplies the two facts and nothing else.
    ///
    /// Two cases, and conflating them is what would make this feature cry wolf:
    ///   • A full tunnel takes the default route, so it takes everything — including a
    ///     guest subnet nobody ever mentioned to it.
    ///   • A split tunnel takes only what it says it takes, so the question is whether
    ///     any of its carried prefixes overlaps the guest subnet. `RoutePrefixMath`
    ///     answers that; it is the same arithmetic the routing-rule editor uses to flag
    ///     an overlap, so the two cannot disagree. A VPN carrying 10.0.0.0/8 has no
    ///     quarrel with 192.168.64.0/24 and must say nothing about it.
    static func captured(from offers: [VirtualizationBypassOffer],
                         wantsFullTunnel: Bool,
                         carriedSubnets: [String]) -> [VirtualizationBypassOffer] {
        guard !wantsFullTunnel else { return offers }
        return offers.filter { offer in
            carriedSubnets.contains { RoutePrefixMath.overlaps($0, offer.subnet) }
        }
    }
}

extension VPNController {

    /// Guest networks THIS profile's tunnel would capture, and the divert rule that
    /// would keep each one reachable — or an empty list, which is the answer almost
    /// always and must stay cheap.
    ///
    /// The snapshot is a parameter so the setting, the MDM refusal, the
    /// full-versus-split question and the already-accepted filter can all be exercised
    /// from a test with a synthesised machine.
    func capturedGuestNetworks(for id: String,
                               in snapshot: VirtualizationSnapshot) -> [VirtualizationBypassOffer] {
        // The setting this whole path exists to honour. Checked FIRST so a user who
        // turned the warning off pays nothing for it.
        guard VirtualizationSettings.warningEnabled else { return [] }
        guard case .success(let offers) = VirtualizationBypass.offers(
            for: snapshot, allowDivertOutside: ManagedPolicy.allowDivertOutside)
        else { return [] }
        // Not re-offering what the user already accepted, so a second connect is quiet.
        let outstanding = VirtualizationBypass.outstanding(
            offers, existing: routingRules(for: id))
        guard !outstanding.isEmpty else { return [] }
        return VirtualizationBypass.captured(from: outstanding,
                                             wantsFullTunnel: profileWantsFullTunnel(id),
                                             carriedSubnets: gatewaySubnets(for: id))
    }

    /// Silent when detection is off, when nothing is running with a network of its own,
    /// when an administrator forbids diverting traffic outside the tunnel, when this VPN
    /// would not capture the network anyway, or when the user already accepted the rule —
    /// which is to say silent nearly always, which is the point.
    ///
    /// Called from `handleStatusChange` the moment a profile goes `.connecting`. Returns
    /// immediately; the scan runs off the main actor and the banner appears when it lands.
    func evaluateGuestNetworkCapture(id: String) {
        // The setting is checked HERE, before the provider is called, as well as inside
        // `capturedGuestNetworks`. Not belt-and-braces: this is what stops a user who
        // turned the warning off paying for a filesystem scan whose answer is thrown away.
        guard VirtualizationSettings.warningEnabled else {
            guestNetworkCaptures[id] = nil
            return
        }
        guard let provider = virtualizationSnapshotProvider else { return }
        // A DETACHED-ISH AWAIT RATHER THAN A SYNCHRONOUS CALL, and the reason is measured:
        // `VirtualizationDiscovery` reads the filesystem, and `contentsOfDirectory` on
        // UTM's container was seen to block in `open` and never return. Doing that inside
        // a status notification froze the entire app. Nothing here is urgent — the profile
        // stays in `.connecting` for seconds — so the scan happens off the main actor and
        // the result is applied when it arrives.
        Task { [weak self] in
            let snapshot = await provider()
            guard let self else { return }
            // Re-checked on the way back: the session may already have ended, or the user
            // may have turned the warning off, while the scan was running.
            guard VirtualizationSettings.warningEnabled,
                  self.profiles.first(where: { $0.id == id })?.status != .disconnected else {
                return
            }
            let captures = self.capturedGuestNetworks(for: id, in: snapshot)
            guard !captures.isEmpty else {
                self.guestNetworkCaptures[id] = nil
                return
            }
            self.guestNetworkCaptures[id] = captures
            Self.log.log("""
                guest networks \(captures.map(\.subnet).joined(separator: ", "), privacy: .public) \
                would be captured by \(id, privacy: .public)
                """)
        }
    }

    /// The session ended: forget both the warning and the dismissal, so the next
    /// connect asks again against a freshly-read interface list.
    func clearGuestNetworkCapture(id: String) {
        guestNetworkCaptures[id] = nil
        dismissedGuestNetworkCaptures.remove(id)
    }

    /// What the banner shows, or nil for "say nothing". One accessor so the view has no
    /// opinion about the dismissal or the setting.
    func guestNetworkWarning(for id: String) -> [VirtualizationBypassOffer]? {
        guard !dismissedGuestNetworkCaptures.contains(id),
              let captures = guestNetworkCaptures[id], !captures.isEmpty else { return nil }
        return captures
    }

    /// "Not now." Session-scoped — see `dismissedGuestNetworkCaptures`.
    func dismissGuestNetworkWarning(id: String) {
        dismissedGuestNetworkCaptures.insert(id)
    }

    /// The user accepted the consequence: add the offered divert rules to this
    /// profile's own routing rules.
    ///
    /// It goes through `setRoutingRules(_:for:)` — the ordinary, already-guarded path
    /// that re-materialises every profile's include-set and reconnects whatever is live —
    /// rather than writing routes itself. That is the whole design of
    /// `VirtualizationBypass`: no new mechanism, no second answer to "what leaves this
    /// tunnel". The extension re-applies `policyKeepInside` when it builds the
    /// `DivertPlan`, so even a rule stored before an MDM policy arrived cannot leak.
    func acceptGuestNetworkBypass(id: String, offers: [VirtualizationBypassOffer]) async {
        var rules = routingRules(for: id)
        let existing = Set(rules.map(\.destination))
        for offer in offers where !existing.contains(offer.subnet) {
            rules.append(offer.rule)
        }
        await setRoutingRules(rules, for: id)
        // The offer has been taken, so the banner goes now rather than at the next
        // `.connecting`. `outstanding` would filter the accepted subnet out anyway —
        // this is what stops the banner being on screen for the seconds in between,
        // saying the tunnel is about to do something the user has just prevented.
        guestNetworkCaptures[id] = nil
    }
}
