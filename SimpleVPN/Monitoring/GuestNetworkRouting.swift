// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GuestNetworkRouting.swift
//  WHERE ONE GUEST NETWORK'S TRAFFIC GOES RIGHT NOW, and whether the user may
//  change it. A pure function over facts the caller supplies, for the same reason
//  `VirtualizationBypass.offers(for:allowDivertOutside:)` is one: this is the
//  security-determining decision in the whole feature, and it must be testable
//  without a running guest, a real profile or a real VPN.
//
//  IT DECIDES NOTHING AND APPLIES NOTHING. It reports, and it produces the rule the
//  caller could apply — the app's ORDINARY divert rule, through `DivertPlan`, under
//  the `ManagedPolicy` gate. `Docs/Networking.md` §6 is explicit that there is to be
//  no parallel mechanism, and §6.3 is explicit that today's default — guest traffic
//  goes into the tunnel — stays until somebody measures otherwise. So: no rule
//  stored means `.throughVPN`, and that is the whole of the default behaviour.
//
//  THE ONE THING THIS FILE EXISTS TO STOP BEING SAID WRONG. A kept-direct rule is
//  DESTINATION-BASED (`RoutingRule`'s own header: "Diversion is by destination
//  IP/CIDR — NEPacketTunnelNetworkSettings routes at the network layer"). So a rule
//  for `192.168.64.0/24` takes traffic ADDRESSED TO the guest network out of the
//  tunnel. It does NOT move the guests' own outbound internet traffic, which is
//  translated to this Mac's address by vmnet and then follows this Mac's default
//  route like anything else. Those are two different journeys and the copy here
//  names them separately:
//
//    • "reaching them"  — this Mac → the guests. The rule controls this.
//    • "their way out"  — the guests → the internet. This Mac's default route
//                         decides it, and nothing on this screen can move it.
//
//  Saying "keep your containers out of the VPN" for a control that does the first
//  would be a security claim we cannot honour: someone would believe their guests
//  were outside a tunnel they are still inside. Whether a full tunnel breaks a guest
//  at all is STILL UNMEASURED (`Docs/Networking.md` §6.1–§6.4 — the original
//  measurement ran under a split tunnel), which is the other reason not to promise a
//  fix.
//
//  MDM, IN BOTH DIRECTIONS. `ForceKeepInsideVPN` does not merely disable the
//  control: it makes the answer `.throughVPN` even where a rule is stored, because
//  `DivertPlan.make` drops every `.outside` rule under that policy when the tunnel
//  is built. Reporting `.aroundVPN` there would tell a user their guests were
//  outside a tunnel the extension is putting them back inside — the exact inversion
//  that matters most.
//

import Foundation

/// One VPN that this guest network's traffic currently meets.
nonisolated struct GuestNetworkCarrier: Sendable, Equatable, Identifiable {
    var profileID: String
    /// The name the user gave it.
    var name: String
    /// Whether an enabled, valid kept-direct rule for this exact subnet is stored on
    /// this profile. `nil`-safe by construction: the caller resolves it from
    /// `routingRules(for:)`, which is the same list the extension reads.
    var keptDirect: Bool = false
    /// `VPNKind.canDivertOutside` — some kinds cannot carve anything out at all
    /// (macOS owns the native kinds' routing table; an SSH tunnel has no routes).
    var canDivert: Bool = true
    /// `VPNKind.divertOutsideUnsupportedReason`, nil when it can.
    var divertUnsupportedReason: String? = nil

    var id: String { profileID }
}

nonisolated struct GuestNetworkRouting: Sendable, Equatable {

    /// What is true of this guest network's traffic right now.
    enum Path: String, Sendable, Equatable {
        /// Bridged: the guests are on the same network as this Mac and this Mac is
        /// not on their path. Nothing here can change where their traffic goes.
        case notThisMacsDecision
        /// No VPN is carrying the traffic that reaches them.
        case noVPN
        /// A VPN is, and no kept-direct rule is in force — TODAY'S DEFAULT.
        case throughVPN
        /// A VPN is, and every one of them keeps this network direct.
        case aroundVPN
        /// More than one VPN carries it and they disagree. Named rather than
        /// rounded to one of the two, because "some of your VPNs" is the honest
        /// answer and rounding it either way is a false security claim.
        case partlyAround
    }

    var path: Path
    var carriers: [GuestNetworkCarrier]
    /// May the user change it here? False under MDM, for a bridged network, for a
    /// kind whose routes we do not own, and when there is no VPN to change.
    var choiceAvailable: Bool
    /// Why not — the same string for `.help` and `accessibilityValue`
    /// (`Docs/Accessibility.md` rule 5: a disabled control says why). Nil when it
    /// is available.
    var choiceBlockedReason: String?

    /// The badge on the graph edge — six words, the whole answer.
    var edgeLabel: String {
        switch path {
        case .notThisMacsDecision: "not through this Mac"
        case .noVPN: "no VPN in the way"
        case .throughVPN: "through " + carrierNames
        case .aroundVPN: "around " + carrierNames
        case .partlyAround: "around some of " + carrierNames
        }
    }

    var carrierNames: String {
        carriers.map(\.name).formatted(.list(type: .and))
    }

    /// What the button would do next, as a verb phrase. Nil when there is nothing to
    /// offer.
    var nextChoiceTitle: String? {
        guard choiceAvailable else { return nil }
        return path == .aroundVPN ? "Send Through the VPN" : "Keep Reachable Outside the VPN"
    }

    /// The consequence of taking `nextChoiceTitle`, in the user's terms and never
    /// softened. Two sentences at most: what leaves the tunnel, and what that means.
    func nextChoiceConsequence(subnet: String) -> String {
        switch path {
        case .aroundVPN:
            "Traffic from this Mac to \(subnet) goes back inside \(carrierNames). If the VPN "
            + "carries that range, you may stop being able to reach these guests from this Mac."
        default:
            "Traffic from this Mac to \(subnet) leaves outside \(carrierNames), over your ordinary "
            + "connection \u{2014} so the VPN neither carries nor protects it. It does not change "
            + "how the guests themselves reach the internet: that follows this Mac\u{2019}s "
            + "own route out, whichever way this is set."
        }
    }

    // MARK: The decision

    /// `ForceKeepInsideVPN`, `DisableDivertRules` and the mode, applied once.
    ///
    /// `allowDivertOutside` and `forceKeepInside` are parameters rather than reads of
    /// `ManagedPolicy` so the refusal is TESTED rather than assumed — the same reason
    /// `VirtualizationBypass.offers` takes its gate as an argument.
    static func decide(mode: GuestNetworkMode,
                       carriers: [GuestNetworkCarrier],
                       allowDivertOutside: Bool,
                       forceKeepInside: Bool) -> GuestNetworkRouting {

        // Bridged first: there is no question to answer. This Mac is not on the
        // path, so neither the state nor the choice is ours to report.
        guard mode.routingChoiceApplies else {
            return GuestNetworkRouting(
                path: .notThisMacsDecision, carriers: [], choiceAvailable: false,
                choiceBlockedReason:
                    "These guests are on the same network as this Mac, with addresses of their "
                    + "own, so this Mac does not decide where their traffic goes and a VPN here "
                    + "cannot change it.")
        }

        guard !carriers.isEmpty else {
            return GuestNetworkRouting(
                path: .noVPN, carriers: [], choiceAvailable: false,
                choiceBlockedReason:
                    "No VPN is carrying the traffic that reaches this network, so there is "
                    + "nothing to keep it out of.")
        }

        // MDM WINS OVER THE STORED STATE, not just over the control. Under
        // ForceKeepInsideVPN the extension drops every `.outside` rule when it builds
        // the DivertPlan, so a stored rule is not in force and must not be reported as
        // though it were.
        if forceKeepInside {
            return GuestNetworkRouting(
                path: .throughVPN, carriers: carriers, choiceAvailable: false,
                choiceBlockedReason:
                    "Your organisation requires everything to go through the VPN, so this "
                    + "network stays inside it whatever is stored here.")
        }

        let kept = carriers.filter(\.keptDirect).count
        let path: Path = kept == 0 ? .throughVPN
            : (kept == carriers.count ? .aroundVPN : .partlyAround)

        guard allowDivertOutside else {
            return GuestNetworkRouting(
                path: path, carriers: carriers, choiceAvailable: false,
                choiceBlockedReason:
                    "Your organisation does not allow traffic to be sent outside the VPN.")
        }
        // A kind whose routes we do not own cannot carve anything out, and offering
        // the control there would be a switch that changes nothing. Its own sentence
        // says which kind and why.
        if let stuck = carriers.first(where: { !$0.canDivert }) {
            return GuestNetworkRouting(
                path: path, carriers: carriers, choiceAvailable: false,
                choiceBlockedReason: stuck.divertUnsupportedReason
                    ?? "\(stuck.name) can\u{2019}t have destinations carved out of it.")
        }
        return GuestNetworkRouting(path: path, carriers: carriers,
                                   choiceAvailable: true, choiceBlockedReason: nil)
    }

    // MARK: The rule

    /// The kept-direct rule for a guest network, or nil where the divert path would
    /// refuse it.
    ///
    /// **`RoutingRule.routeDest` is the validator, and it is the SAME one every
    /// divert passes.** It refuses a malformed address and any prefix 0, so a guest
    /// network that somehow presented as `0.0.0.0/0` could never become a
    /// whole-tunnel bypass wearing this feature's clothes — which is precisely the
    /// escape `ForceKeepInsideVPN` exists to prevent, so it must not be reachable by
    /// a second door.
    static func rule(subnet: String, attribution: String, interfaceName: String) -> RoutingRule? {
        let rule = RoutingRule(destination: subnet, action: .outside,
                               note: "\(attribution) on \(interfaceName)")
        return rule.isValidDivert ? rule : nil
    }

    /// Whether a profile's stored rules keep this subnet direct: an enabled
    /// `.outside` rule for exactly this destination that the divert path would
    /// actually apply. An invalid stored rule reads as NOT kept direct, because that
    /// is what the extension will do with it.
    static func isKeptDirect(subnet: String, rules: [RoutingRule]) -> Bool {
        rules.contains {
            $0.enabled && $0.action == .outside
                && $0.destination == subnet && $0.isValidDivert
        }
    }
}
