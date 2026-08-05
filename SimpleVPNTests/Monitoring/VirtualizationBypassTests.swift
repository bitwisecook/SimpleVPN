// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VirtualizationBypassTests.swift
//  The REFUSALS matter more than the offers here. An offer that appears is easy to
//  eyeball; an offer that should never have appeared is the bug that makes this
//  whole feature a placebo, so most of what follows asserts that nothing is
//  offered where nothing could work.
//

import Testing
import Foundation
@testable import SimpleVPN

struct VirtualizationBypassTests {

    private func appleContainerSnapshot() -> VirtualizationSnapshot {
        VirtualizationSnapshot(
            installed: [InstalledVirtualization(
                productID: "apple-container", title: "Apple Containers (container)",
                networking: .routedSubnet, evidence: ["/usr/local/bin/container"],
                verifiedLocally: true)],
            guestNetworks: [GuestNetwork(
                interfaceName: "bridge100", hostAddress: "192.168.64.1",
                subnet: "192.168.64.0/24",
                candidateProductIDs: ["apple-container"],
                attachedGuestInterfaces: ["vmenet0"])])
    }

    /// The offer is an ordinary divert rule, not a new kind of object — the whole
    /// point of routing this through the existing bypass concept rather than a
    /// parallel "VM exclusions" list.
    @Test func anOfferIsAnOrdinaryOutsideDivertRule() throws {
        let offers = try VirtualizationBypass.offers(for: appleContainerSnapshot(),
                                                     allowDivertOutside: true).get()
        #expect(offers.count == 1)
        let offer = try #require(offers.first)
        #expect(offer.subnet == "192.168.64.0/24")
        #expect(offer.rule.action == .outside)
        #expect(offer.rule.destination == "192.168.64.0/24")
        #expect(offer.rule.isValidDivert)
        #expect(offer.rule.routeDest?.prefix == 24)
    }

    /// The copy must state the split-tunnel consequence rather than sell the fix.
    @Test func theConsequenceIsStatedNotSoftened() throws {
        let offers = try VirtualizationBypass.offers(for: appleContainerSnapshot(),
                                                     allowDivertOutside: true).get()
        let words = try #require(offers.first?.consequence)
        #expect(words.contains("outside the VPN"))
        #expect(words.localizedCaseInsensitiveContains("neither carries nor protects"))
    }

    /// THE refusal this feature exists for. A Docker-only machine must be told that
    /// routing cannot help, not handed a toggle that does nothing.
    @Test func aDockerOnlyMachineIsRefusedWithTheRealRemedy() {
        let snapshot = VirtualizationSnapshot(installed: [
            InstalledVirtualization(productID: "docker-desktop", title: "Docker Desktop",
                                    networking: .userspace, evidence: ["/usr/local/bin/docker"]),
        ])
        guard case .failure(let refusal) = VirtualizationBypass.offers(
            for: snapshot, allowDivertOutside: true) else {
            Issue.record("a userspace-only machine must be refused, not offered a route")
            return
        }
        #expect(refusal == .onlyUserspaceProducts(["Docker Desktop"]))
        #expect(refusal.words.localizedCaseInsensitiveContains("cannot help"))
        #expect(refusal.words.localizedCaseInsensitiveContains("MTU"))
    }

    /// An MDM that forbids diverting outside must win, and say so.
    @Test func anAdministratorsRefusalWinsAndIsExplained() {
        guard case .failure(let refusal) = VirtualizationBypass.offers(
            for: appleContainerSnapshot(), allowDivertOutside: false) else {
            Issue.record("policy must be able to refuse this outright")
            return
        }
        #expect(refusal == .forbiddenByPolicy)
        #expect(!refusal.words.isEmpty)
    }

    @Test func detectionOffIsItsOwnRefusal() {
        guard case .failure(let refusal) = VirtualizationBypass.offers(
            for: VirtualizationSnapshot(detectionEnabled: false),
            allowDivertOutside: true) else {
            Issue.record("expected a refusal"); return
        }
        #expect(refusal == .detectionOff)
    }

    /// Installed-but-not-running is a different sentence from "cannot be helped",
    /// and conflating them sends someone off to start a container that was never
    /// the problem.
    @Test func nothingRunningIsDistinguishedFromNothingHelpable() {
        let snapshot = VirtualizationSnapshot(installed: [
            InstalledVirtualization(productID: "apple-container",
                                    title: "Apple Containers (container)",
                                    networking: .routedSubnet,
                                    evidence: ["/usr/local/bin/container"],
                                    verifiedLocally: true),
        ])
        guard case .failure(let refusal) = VirtualizationBypass.offers(
            for: snapshot, allowDivertOutside: true) else {
            Issue.record("expected a refusal"); return
        }
        #expect(refusal == .noLiveGuestNetwork)
    }

    @Test func everyRefusalHasItsOwnSentence() {
        let refusals: [VirtualizationBypassRefusal] = [
            .detectionOff, .noLiveGuestNetwork,
            .onlyUserspaceProducts(["Docker Desktop"]), .forbiddenByPolicy,
        ]
        var seen = Set<String>()
        for refusal in refusals {
            #expect(!refusal.words.isEmpty)
            #expect(seen.insert(refusal.words).inserted)
        }
    }

    /// Accepting an offer once must not re-offer it, and accepting twice must never
    /// produce two rules for one subnet.
    @Test func anAlreadyAcceptedSubnetIsNotOfferedAgain() throws {
        let offers = try VirtualizationBypass.offers(for: appleContainerSnapshot(),
                                                     allowDivertOutside: true).get()
        let accepted = [RoutingRule(destination: "192.168.64.0/24", action: .outside)]
        #expect(VirtualizationBypass.outstanding(offers, existing: accepted).isEmpty)

        // A DISABLED rule is not cover — the guest is still captured.
        var disabled = accepted
        disabled[0].enabled = false
        #expect(VirtualizationBypass.outstanding(offers, existing: disabled).count == 1)

        // Nor is a rule that routes the subnet into ANOTHER VPN rather than outside.
        let overVPN = [RoutingRule(destination: "192.168.64.0/24",
                                   action: .overVPN(profileID: "other"))]
        #expect(VirtualizationBypass.outstanding(offers, existing: overVPN).count == 1)
    }

    /// A guest network that somehow presented as a default route must never become a
    /// whole-VPN bypass wearing this feature's clothes — which is also an MDM
    /// `ForceKeepInsideVPN` escape.
    @Test func aDefaultRouteIsNeverOfferedAsAGuestNetwork() {
        let snapshot = VirtualizationSnapshot(guestNetworks: [
            GuestNetwork(interfaceName: "bridge100", hostAddress: "0.0.0.0",
                         subnet: "0.0.0.0/0"),
        ])
        guard case .failure = VirtualizationBypass.offers(for: snapshot,
                                                         allowDivertOutside: true) else {
            Issue.record("0.0.0.0/0 must never be offered as a guest network")
            return
        }
    }

    /// Two guests on one subnet is one offer, not two identical rules.
    @Test func oneSubnetYieldsOneOffer() throws {
        var snapshot = appleContainerSnapshot()
        snapshot.guestNetworks.append(GuestNetwork(
            interfaceName: "bridge101", hostAddress: "192.168.64.1",
            subnet: "192.168.64.0/24"))
        let offers = try VirtualizationBypass.offers(for: snapshot,
                                                     allowDivertOutside: true).get()
        #expect(offers.count == 1)
    }
}
