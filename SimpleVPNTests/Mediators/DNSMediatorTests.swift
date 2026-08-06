// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DNSMediatorTests.swift
//  The DNS mediator's PURE core (Docs/StateMediators.md, P2): the split-DNS arbiter
//  (catch-all precedence, per-domain assignment, no clobber), the VPN-kind DNS
//  participation classifier, and the drift → re-assert decision. No SCDynamicStore, no
//  NE — every function here is total and I/O-free.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct DNSMediatorTests {

    private func intent(_ id: String, resolvers: [String], match: [String] = [],
                        catchAll: Bool = false, at seconds: Double? = nil) -> DNSIntent {
        DNSIntent(engine: id, resolvers: resolvers, searchDomains: [], matchDomains: match,
                  wantsCatchAll: catchAll,
                  connectedAt: seconds.map { Date(timeIntervalSinceReferenceDate: $0) })
    }

    // MARK: - Arbiter plan (stage 2)

    /// The route default owner (if it advertises resolvers) owns the catch-all; a
    /// non-owner's catch-all push never becomes the system resolver (the clobber fix).
    @Test func ownerOwnsCatchAllNonOwnerDoesNot() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], catchAll: true, at: 1),
                      intent("home", resolvers: ["192.168.1.1"], catchAll: true, at: 2)],
            policy: DNSPolicy(defaultOwner: "corp"))
        #expect(plan.catchAllOwner == "corp")
        #expect(plan.systemResolvers == ["10.0.0.53"])
    }

    /// No owner (Direct route) ⇒ nobody owns the catch-all, even if tunnels push DNS.
    @Test func noOwnerMeansDirectDNS() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], catchAll: true, at: 1)],
            policy: DNSPolicy(defaultOwner: nil))
        #expect(plan.catchAllOwner == nil)
        #expect(plan.systemResolvers.isEmpty)
    }

    /// Split-DNS: each engine's SPECIFIC domains resolve through its own resolvers.
    @Test func splitDNSAssignsSpecificDomains() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], match: [""], catchAll: true, at: 1),
                      intent("lab", resolvers: ["10.9.0.53"], match: ["lab.internal"], at: 2)],
            policy: DNSPolicy(defaultOwner: "corp"))
        #expect(plan.catchAllOwner == "corp")
        let lab = plan.perDomain.first { $0.engine == "lab" }
        #expect(lab?.domains == ["lab.internal"])
        #expect(lab?.resolvers == ["10.9.0.53"])
    }

    /// A domain claimed by two engines resolves exactly ONE way — the owner wins.
    @Test func domainConflictResolvesToOwner() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], match: ["shared.internal"], at: 1),
                      intent("lab", resolvers: ["10.9.0.53"], match: ["shared.internal"], at: 5)],
            policy: DNSPolicy(defaultOwner: "corp"))
        let owners = plan.perDomain.filter { $0.domains.contains("shared.internal") }
        #expect(owners.count == 1)
        #expect(owners.first?.engine == "corp")
    }

    /// With no owner, a domain conflict breaks by recency (newest connection wins).
    @Test func domainConflictBreaksByRecencyWithoutOwner() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], match: ["shared.internal"], at: 1),
                      intent("lab", resolvers: ["10.9.0.53"], match: ["shared.internal"], at: 5)],
            policy: DNSPolicy(defaultOwner: nil))
        let winner = plan.perDomain.first { $0.domains.contains("shared.internal") }
        #expect(winner?.engine == "lab")
    }

    // MARK: - Participation classifier

    @Test func dnsParticipationBucketsEveryKind() {
        for kind: VPNKind in [.openVPN, .proxyTunnel, .tailscale, .wireGuard, .sshNetworkTunnel,
                              .fortinet, .f5apm,
                              .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks] {
            #expect(DNSParticipation.classify(kind) == .full, "\(kind) should be .full")
            #expect(DNSParticipation.classify(kind).participatesInSplitDNS)
        }
        for kind: VPNKind in [.ikev2, .ipsec, .l2tp] {
            #expect(DNSParticipation.classify(kind) == .limited)
            #expect(!DNSParticipation.classify(kind).participatesInSplitDNS)
        }
        #expect(DNSParticipation.classify(.ssh) == .none)
        // …while the SSH NETWORK tunnel does advertise resolvers on its utun.
        #expect(DNSParticipation.classify(.sshNetworkTunnel) == .full)
    }

    // MARK: - Drift → re-assert decision (stage 4)

    @Test func dnsDriftReassertsWhenOurResolversVanish() {
        // We expect corp's resolver; the OS now lists only the ISP's ⇒ external drift.
        #expect(DNSDriftDecision.action(expected: ["10.0.0.53"], observed: ["1.1.1.1"],
                                        withinSuppressWindow: false) == .reassert)
    }

    @Test func dnsDriftIgnoredWhenOurResolversStillPresent() {
        // Ours are still there (alongside others) ⇒ no drift to fight.
        #expect(DNSDriftDecision.action(expected: ["10.0.0.53"], observed: ["10.0.0.53", "1.1.1.1"],
                                        withinSuppressWindow: false) == .none)
    }

    @Test func dnsDriftIgnoredWithinSuppressWindow() {
        #expect(DNSDriftDecision.action(expected: ["10.0.0.53"], observed: ["1.1.1.1"],
                                        withinSuppressWindow: true) == .none)
    }

    @Test func dnsDriftNoActionWithoutExpectation() {
        // Direct DNS (no catch-all owner): the Mac's own resolvers changing isn't ours.
        #expect(DNSDriftDecision.action(expected: [], observed: ["1.1.1.1"],
                                        withinSuppressWindow: false) == .none)
    }

    // MARK: - DNSApplyRequest → NEDNSSettings (tier-2 sole-writer applier)

    /// A populated request maps every field onto NEDNSSettings.
    @Test func dnsApplyRequestBuildsNEDNSSettings() {
        let req = DNSApplyRequest(servers: ["10.0.0.53", "10.0.0.54"],
                                  searchDomains: ["corp.internal"],
                                  matchDomains: ["corp.internal", "svc.internal"],
                                  matchDomainsNoSearch: true)
        let s = req.makeNEDNSSettings()
        #expect(s?.servers == ["10.0.0.53", "10.0.0.54"])
        #expect(s?.searchDomains == ["corp.internal"])
        #expect(s?.matchDomains == ["corp.internal", "svc.internal"])
        #expect(s?.matchDomainsNoSearch == true)
    }

    /// The catch-all shape: resolvers scoped to `[""]`, search not forced.
    @Test func dnsApplyRequestCatchAllMapsMatchEmpty() {
        let req = DNSApplyRequest(servers: ["10.0.0.53"], matchDomains: [""])
        let s = req.makeNEDNSSettings()
        #expect(s?.servers == ["10.0.0.53"])
        #expect(s?.matchDomains == [""])
        #expect(s?.matchDomainsNoSearch == false)
    }

    /// Empty servers ⇒ nil (clear the override).
    @Test func dnsApplyRequestEmptyMapsToNil() {
        #expect(DNSApplyRequest(servers: []).isEmpty)
        #expect(DNSApplyRequest(servers: [], matchDomains: ["x"]).makeNEDNSSettings() == nil)
    }

    // MARK: - DNSPlan → per-engine DNSApplyRequest split

    /// The catch-all owner gets the default resolvers scoped to every lookup; each split
    /// participant gets ONLY the specific domains it won.
    @Test func dnsPlanSplitsRequestsPerParticipant() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], match: [""], catchAll: true, at: 1),
                      intent("lab", resolvers: ["10.9.0.53"], match: ["lab.internal"], at: 2)],
            policy: DNSPolicy(defaultOwner: "corp"))
        let reqs = plan.applyRequests()

        // Owner: default resolvers, catch-all, search not forced-off.
        #expect(reqs["corp"]?.servers == ["10.0.0.53"])
        #expect(reqs["corp"]?.matchDomains == [""])
        #expect(reqs["corp"]?.matchDomainsNoSearch == false)

        // Participant: its resolvers, scoped to only its won domain, no-search.
        #expect(reqs["lab"]?.servers == ["10.9.0.53"])
        #expect(reqs["lab"]?.matchDomains == ["lab.internal"])
        #expect(reqs["lab"]?.matchDomainsNoSearch == true)
    }

    /// No catch-all owner (Direct route) ⇒ only the split participants get requests.
    @Test func dnsPlanNoOwnerEmitsOnlySplitParticipants() {
        let plan = DNSArbiter.plan(
            intents: [intent("lab", resolvers: ["10.9.0.53"], match: ["lab.internal"], at: 2)],
            policy: DNSPolicy(defaultOwner: nil))
        let reqs = plan.applyRequests()
        #expect(reqs["lab"]?.matchDomains == ["lab.internal"])
        #expect(reqs.count == 1)
    }

    /// The owner is emitted ONCE as the catch-all even if it also won specific domains
    /// (the catch-all `[""]` already covers them) — never two requests for one engine.
    @Test func dnsPlanOwnerEmittedOnceAsCatchAll() {
        let plan = DNSArbiter.plan(
            intents: [intent("corp", resolvers: ["10.0.0.53"], match: ["corp.internal"], catchAll: true, at: 1)],
            policy: DNSPolicy(defaultOwner: "corp"))
        let reqs = plan.applyRequests()
        #expect(reqs.count == 1)
        #expect(reqs["corp"]?.matchDomains == [""])
    }
}

// MARK: - Search domains (one spelling, three config formats)

/// `DNSSearchDomains` exists because WireGuard, the Proxy Tunnel and the SSH Network
/// Tunnel each carry their own list now, and a domain spelled three slightly
/// different ways is a lookup that works on one kind and not the next.
struct DNSSearchDomainTests {

    @Test func normalisationTrimsDotsCaseAndDuplicatesButKeepsOrder() {
        // Order is load-bearing: a stub resolver tries a search list in order, so
        // re-sorting it would change which name wins.
        #expect(DNSSearchDomains.normalized(["  .Corp.Example. ", "", "corp.example",
                                             "Example.COM"])
                == ["corp.example", "example.com"])
        #expect(DNSSearchDomains.normalized([]).isEmpty)
        #expect(DNSSearchDomains.normalized([".", "..", "   "]).isEmpty)
    }

    @Test func aPlainDomainIsAccepted() {
        for good in ["corp.example", "example.com", "internal", "a-b.c_d.example",
                     "corp.example.", ".corp.example"] {
            #expect(DNSSearchDomains.problem(good) == nil, "\(good) should be accepted")
        }
    }

    @Test func everyRefusalNamesWhatIsWrong() {
        // macOS accepts an unusable search list in SILENCE and short names then simply
        // never resolve — so each of these is refused at the editor, with a reason.
        #expect(DNSSearchDomains.problem("")?.contains("corp.example.com") == true)
        #expect(DNSSearchDomains.problem("corp example")?.contains("spaces") == true)
        #expect(DNSSearchDomains.problem("https://corp.example")?.contains("URL") == true)
        #expect(DNSSearchDomains.problem("corp.example/x")?.contains("slashes") == true)
        #expect(DNSSearchDomains.problem("me@corp.example")?.contains("@") == true)
        #expect(DNSSearchDomains.problem("*.corp.example")?.contains("wildcards") == true)
        #expect(DNSSearchDomains.problem("corp..example")?.contains("empty part") == true)
        #expect(DNSSearchDomains.problem(String(repeating: "a", count: 64) + ".example")?
                    .contains("at most 63") == true)
    }

    @Test func theListCheckReportsTheFirstRealProblemAndIgnoresBlanks() {
        #expect(DNSSearchDomains.problem(list: ["corp.example", "", "  "]) == nil)
        #expect(DNSSearchDomains.problem(list: ["corp.example", "bad domain"])?
                    .contains("spaces") == true)
    }
}
