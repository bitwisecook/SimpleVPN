// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GuestNetworkRoutingTests.swift
//  THE FOUR SEMANTICS THE GUEST-NETWORK FEATURE IS PINNED ON, and they are all
//  security semantics rather than behaviour:
//
//    1. THE DEFAULT IS UNCHANGED. No stored rule means "through the VPN", which is
//       what happens today (`Docs/Networking.md` §6.3: the carve-out deliberately
//       excludes guest bridges, and that stays until somebody runs §6.4).
//    2. A `/0` IS REFUSED. The one prefix that would turn a guest network into a
//       whole-tunnel bypass, and therefore into a `ForceKeepInsideVPN` escape.
//    3. `ForceKeepInsideVPN` OVERRIDES THE STORED STATE, not merely the control. The
//       extension drops every `.outside` rule under that policy, so reporting
//       "around the VPN" there would tell a user their guests were outside a tunnel
//       they are inside — the inversion that matters most.
//    4. A GUEST NETWORK APPEARS ONCE. Two addresses on one bridge, or a tap already
//       counted as a member of a network, must not produce a second node.
//
//  Plus the arrangement table, because bridged/host-only/shared are the whole reason
//  the UI can say anything useful, and getting one of them wrong means telling
//  somebody a control will help when it cannot.
//

import Testing
import Foundation
@testable import SimpleVPN

struct GuestNetworkRoutingTests {

    private func carrier(_ name: String, keptDirect: Bool = false,
                         canDivert: Bool = true) -> GuestNetworkCarrier {
        GuestNetworkCarrier(profileID: "p-\(name)", name: name, keptDirect: keptDirect,
                            canDivert: canDivert,
                            divertUnsupportedReason: canDivert ? nil
                                : "macOS owns the routes for this kind of VPN.")
    }

    // MARK: 1 — the default is today's behaviour

    /// No rule stored ⇒ through the VPN. This is the whole of "we changed no default".
    @Test func withNoRuleStoredTheGuestNetworkGoesThroughTheVPN() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [carrier("Tig Lab")],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.path == .throughVPN)
        #expect(routing.edgeLabel == "through Tig Lab")
        // The choice is OFFERED — that is the new part — but taking it is an act.
        #expect(routing.choiceAvailable)
        #expect(routing.nextChoiceTitle == "Keep Reachable Outside the VPN")
    }

    /// And with no VPN carrying it at all there is nothing to decide, which must not
    /// read as "outside the VPN" — an absence of tunnel is not a bypass.
    @Test func withNoVPNCarryingItThereIsNothingToDecide() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [], allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.path == .noVPN)
        #expect(!routing.choiceAvailable)
        #expect(routing.nextChoiceTitle == nil)
        #expect(routing.choiceBlockedReason?.contains("No VPN") == true)
    }

    // MARK: 2 — a /0 can never become a whole-tunnel bypass

    @Test func aDefaultRouteIsRefusedAsAGuestNetworkRule() {
        #expect(GuestNetworkRouting.rule(subnet: "0.0.0.0/0", attribution: "Whatever",
                                         interfaceName: "bridge100") == nil)
        #expect(GuestNetworkRouting.rule(subnet: "::/0", attribution: "Whatever",
                                         interfaceName: "bridge100") == nil)
    }

    @Test func aMalformedSubnetIsRefused() {
        #expect(GuestNetworkRouting.rule(subnet: "not-an-address/24", attribution: "X",
                                         interfaceName: "bridge100") == nil)
        #expect(GuestNetworkRouting.rule(subnet: "192.168.64.0/33", attribution: "X",
                                         interfaceName: "bridge100") == nil)
    }

    /// A real guest subnet makes an ORDINARY divert rule — the same object, through
    /// the same validator, as any other kept-direct route.
    @Test func aRealGuestSubnetMakesAnOrdinaryOutsideRule() throws {
        let rule = try #require(GuestNetworkRouting.rule(
            subnet: "192.168.64.0/24", attribution: "Apple Containers (container)",
            interfaceName: "bridge100"))
        #expect(rule.action == .outside)
        #expect(rule.destination == "192.168.64.0/24")
        #expect(rule.routeDest?.prefix == 24)
        #expect(rule.note.contains("bridge100"))
    }

    /// A stored rule the divert path would REJECT does not count as kept-direct —
    /// what the card reports has to be what the extension will do.
    @Test func aStoredButInvalidRuleDoesNotCountAsKeptDirect() {
        let bogus = RoutingRule(destination: "0.0.0.0/0", action: .outside)
        #expect(!GuestNetworkRouting.isKeptDirect(subnet: "0.0.0.0/0", rules: [bogus]))
        let disabled = RoutingRule(destination: "192.168.64.0/24", action: .outside,
                                   enabled: false)
        #expect(!GuestNetworkRouting.isKeptDirect(subnet: "192.168.64.0/24", rules: [disabled]))
        let good = RoutingRule(destination: "192.168.64.0/24", action: .outside)
        #expect(GuestNetworkRouting.isKeptDirect(subnet: "192.168.64.0/24", rules: [good]))
    }

    // MARK: 3 — ForceKeepInsideVPN wins, exactly as it does for the LAN carve-out

    /// Even with the rule stored and in the profile's list, the answer is "through
    /// the VPN" — because `DivertPlan.make(keepInside: true, …)` drops it.
    @Test func forceKeepInsideOverridesAStoredKeptDirectRule() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [carrier("Tig Lab", keptDirect: true)],
            allowDivertOutside: false, forceKeepInside: true)
        #expect(routing.path == .throughVPN)
        #expect(!routing.choiceAvailable)
        #expect(routing.choiceBlockedReason?.contains("organisation") == true)
    }

    /// The claim above is only true because the plan really does drop it. Pinned
    /// here, against the same builder the extension calls, so the two can't drift.
    @Test func theDivertPlanReallyDropsItUnderForceKeepInside() throws {
        let rule = try #require(GuestNetworkRouting.rule(
            subnet: "192.168.64.0/24", attribution: "Apple Containers (container)",
            interfaceName: "bridge100"))
        let allowed = DivertPlan.make(rules: [rule], inbound: [],
                                      keepInside: false, noDiverts: false)
        #expect(allowed.outsideCIDRs == ["192.168.64.0/24"])
        let forced = DivertPlan.make(rules: [rule], inbound: [],
                                     keepInside: true, noDiverts: false)
        #expect(forced.outside.isEmpty)
        let banned = DivertPlan.make(rules: [rule], inbound: [],
                                     keepInside: false, noDiverts: true)
        #expect(banned.outside.isEmpty)
    }

    /// `DisableDivertRules` alone (no ForceKeepInsideVPN) blocks the control but must
    /// still report the state honestly rather than pretending it is inside.
    @Test func disableDivertRulesBlocksTheChoiceWithoutRewritingTheState() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [carrier("Tig Lab", keptDirect: true)],
            allowDivertOutside: false, forceKeepInside: false)
        #expect(routing.path == .aroundVPN)
        #expect(!routing.choiceAvailable)
        #expect(routing.choiceBlockedReason?.contains("does not allow") == true)
    }

    /// A kind whose routes we do not own gets no control, and says which kind.
    @Test func aKindThatCannotDivertGetsNoControlAndSaysWhy() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [carrier("Work IKEv2", canDivert: false)],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(!routing.choiceAvailable)
        #expect(routing.choiceBlockedReason?.contains("macOS owns the routes") == true)
    }

    // MARK: The arrangements, and what each one may offer

    /// A BRIDGED network is not this Mac's decision, so no control is offered — a
    /// rule there would apply perfectly and change nothing whatever.
    @Test func aBridgedNetworkIsOfferedNoChoiceBecauseThisMacIsNotOnThePath() {
        let routing = GuestNetworkRouting.decide(
            mode: .bridged, carriers: [carrier("Tig Lab")],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.path == .notThisMacsDecision)
        #expect(!routing.choiceAvailable)
        #expect(routing.edgeLabel == "not through this Mac")
        // And no carrier is claimed, because claiming one would say a VPN is doing
        // something to traffic it never sees.
        #expect(routing.carriers.isEmpty)
    }

    /// A HOST-ONLY network still gets the choice: there is no way out to leak, but a
    /// tunnel can still take away this Mac's own path to the guests.
    @Test func aHostOnlyNetworkStillGetsTheChoice() {
        let routing = GuestNetworkRouting.decide(
            mode: .hostOnly, carriers: [carrier("Tig Lab")],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.path == .throughVPN)
        #expect(routing.choiceAvailable)
    }

    /// `.unknown` keeps the network visible and the choice offered — the cautious
    /// direction. Deciding it was irrelevant because we could not see it would hide
    /// exactly the case a user needs told about.
    @Test func anUnseeableArrangementStillShowsAndStillOffers() {
        #expect(GuestNetworkMode.unknown.thisMacIsOnThePath)
        let routing = GuestNetworkRouting.decide(
            mode: .unknown, carriers: [carrier("Tig Lab")],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.choiceAvailable)
    }

    /// Two VPNs disagreeing is its own answer and is NOT rounded to either — rounding
    /// it is a false security claim in one direction or a false breakage claim in the
    /// other.
    @Test func vpnsThatDisagreeAreReportedAsDisagreeing() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared,
            carriers: [carrier("Tig Lab", keptDirect: true), carrier("Work")],
            allowDivertOutside: true, forceKeepInside: false)
        #expect(routing.path == .partlyAround)
        #expect(routing.edgeLabel == "around some of Tig Lab and Work")
    }

    // MARK: The copy says what it actually does

    /// The consequence must name the split tunnel AND must not claim to move the
    /// guests' own way out — the destination-based rule cannot, and saying it does
    /// would be the one security claim this feature must never make.
    @Test func theConsequenceNamesTheSplitTunnelAndRefusesTheBiggerClaim() {
        let routing = GuestNetworkRouting.decide(
            mode: .shared, carriers: [carrier("Tig Lab")],
            allowDivertOutside: true, forceKeepInside: false)
        let words = routing.nextChoiceConsequence(subnet: "192.168.64.0/24")
        #expect(words.contains("192.168.64.0/24"))
        #expect(words.contains("outside Tig Lab"))
        #expect(words.contains("neither carries nor protects"))
        #expect(words.contains("does not change how the guests themselves reach the internet"))
    }

    /// "Credential" is banned from UI copy (ONTOLOGY.md) and so is every internal
    /// term this feature could easily have leaked.
    @Test func theCopyUsesNoJargon() {
        var strings: [String] = GuestNetworkMode.allCases.flatMap { [$0.title, $0.summary] }
        strings.append(VirtualizationDiscovery.unseeable)
        for mode in [GuestNetworkMode.shared, .hostOnly, .bridged, .unknown] {
            let routing = GuestNetworkRouting.decide(
                mode: mode, carriers: [carrier("Tig Lab")],
                allowDivertOutside: true, forceKeepInside: false)
            strings.append(routing.edgeLabel)
            strings.append(routing.nextChoiceConsequence(subnet: "192.168.64.0/24"))
            if let why = routing.choiceBlockedReason { strings.append(why) }
        }
        for banned in ["credential", "NAT", "slirp", "vmnet", "hypervisor", "utun",
                       "DivertPlan", "RoutingRule", "packet tunnel"] {
            for text in strings {
                #expect(!text.localizedCaseInsensitiveContains(banned),
                        "\u{201C}\(banned)\u{201D} leaked into user copy: \(text)")
            }
        }
    }
}
