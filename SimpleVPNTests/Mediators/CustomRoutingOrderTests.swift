// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CustomRoutingOrderTests.swift
//  Reordering Custom Routing rules is not a presentation change — it decides where
//  traffic goes. These tests pin that SEMANTICS rather than the gesture: that a
//  reorder changes which rule matches, that the new order survives the commit path
//  every other edit on the tab uses, and that a rule can be moved to and from every
//  position without the list losing or duplicating one.
//

import Foundation
import Testing
@testable import SimpleVPN

struct CustomRoutingOrderTests {

    private func rule(_ verb: FilterVerb, _ match: String? = nil, target: String? = nil)
        -> RouteFilter.RouteRule {
        RouteFilter.RouteRule(verb: verb,
                              match: match.map(RoutePrefix.init),
                              target: target.map(RoutePrefix.init))
    }

    private func captured(_ prefixes: [String], wantsDefault: Bool = false) -> RouteIntent {
        RouteIntent(engine: "p", advertisedPrefixes: prefixes, wantsDefault: wantsDefault,
                    canOwnDefault: true)
    }

    // MARK: The point of the whole exercise

    /// SWAPPING TWO RULES SENDS TRAFFIC SOMEWHERE ELSE. `10.0.0.0/8` is dropped when
    /// Ignore is on top and replaced when Replace is — same two rules, same pushed
    /// route, different outcome. This is why a reorder here is security-determining
    /// and why the UI has to say so.
    @Test func reorderingChangesWhichRuleMatches() {
        var filter = RouteFilter()
        filter.rules = [rule(.ignore, "10.0.0.0/8"),
                        rule(.replace, "10.0.0.0/8", target: "10.99.0.0/16")]
        #expect(filter.apply(to: captured(["10.0.0.0/8"])).advertisedPrefixes == [])

        filter.rules = Reorder.moved(filter.rules, from: 1, to: 0)
        #expect(filter.apply(to: captured(["10.0.0.0/8"])).advertisedPrefixes == ["10.99.0.0/16"])
    }

    /// The same for the default route, where the stakes are highest: whether this VPN
    /// may own the gateway at all depends on which rule is first.
    @Test func reorderingDecidesWhetherTheDefaultSurvives() {
        var filter = RouteFilter()
        filter.rules = [rule(.accept, "default"), rule(.ignore, "default")]
        #expect(filter.apply(to: captured([], wantsDefault: true)).wantsDefault)

        filter.rules = Reorder.moved(filter.rules, from: 1, to: 0)
        let out = filter.apply(to: captured([], wantsDefault: true))
        #expect(!out.wantsDefault)
        // Removing a pushed default forces split — the arbiter can no longer make
        // this profile the gateway. A reorder reaches that far.
        #expect(!out.canOwnDefault)
    }

    /// Resolver rules are the same machine, so the same test holds: which DNS server
    /// the Mac ends up using depends on the order.
    @Test func reorderingResolverRulesChangesWhichResolverIsUsed() {
        var dns = DNSCustomization()
        dns.resolverRules = [DNSCustomization.ResolverRule(verb: .ignore, match: "10.0.0.53"),
                             DNSCustomization.ResolverRule(verb: .replace, match: "10.0.0.53",
                                                           target: "10.0.0.54")]
        let intent = DNSIntent(engine: "p", resolvers: ["10.0.0.53"])
        #expect(dns.apply(to: intent).resolvers == [])

        dns.resolverRules = Reorder.moved(dns.resolverRules, from: 1, to: 0)
        #expect(dns.apply(to: intent).resolvers == ["10.0.0.54"])
    }

    /// An `Add` rule injects wherever it sits, so moving one must NOT change the
    /// outcome — the honest counterpart to the tests above, and the reason the
    /// manual says so explicitly.
    @Test func movingAnAddRuleChangesNothing() {
        var filter = RouteFilter()
        filter.rules = [rule(.add, target: "192.168.9.0/24"), rule(.accept, "10.0.0.0/8")]
        let before = filter.apply(to: captured(["10.0.0.0/8"]))
        filter.rules = Reorder.moved(filter.rules, from: 0, to: 1)
        let after = filter.apply(to: captured(["10.0.0.0/8"]))
        #expect(before.advertisedPrefixes == after.advertisedPrefixes)
        #expect(after.advertisedPrefixes.contains("192.168.9.0/24"))
    }

    // MARK: The new order has to survive the commit

    /// A reorder must persist by the SAME path every other edit on this tab uses:
    /// `commitCustomRouting` sanitizes and hands the profile to `setCustomRouting`,
    /// and `sanitizedCustomRoutingProfile` is the one transform in between. If it
    /// reordered or dropped rules, a reorder would silently lose on tab-switch.
    @Test func theCommitPathPreservesTheOrder() {
        var profile = CustomRoutingProfile()
        profile.routes.rules = [rule(.accept, "10.1.0.0/16"),
                                rule(.ignore, "10.2.0.0/16"),
                                rule(.replace, "10.3.0.0/16", target: "10.4.0.0/16")]
        profile.dns.resolverRules = [DNSCustomization.ResolverRule(verb: .accept, match: "10.0.0.53"),
                                     DNSCustomization.ResolverRule(verb: .ignore, match: "10.0.0.54")]
        let moved = { () -> CustomRoutingProfile in
            var p = profile
            p.routes.rules = Reorder.moved(p.routes.rules, from: 2, to: 0)
            p.dns.resolverRules = Reorder.moved(p.dns.resolverRules, from: 1, to: 0)
            return p
        }()
        let out = sanitizedCustomRoutingProfile(moved)
        #expect(out.routes.rules.map(\.id) == moved.routes.rules.map(\.id))
        #expect(out.dns.resolverRules.map(\.id) == moved.dns.resolverRules.map(\.id))
        // …and the rule the user dragged to the top is the one that is now first,
        // which is what "the first match wins" makes load-bearing.
        #expect(out.routes.rules.first?.verb == .replace)
        #expect(out.dns.resolverRules.first?.verb == .ignore)
    }

    /// A rule with an ERROR in it is dropped on commit (it never reaches the
    /// mediators) — but dropping it must not disturb the order of the rules that
    /// survive, or fixing one rule would rearrange the others.
    @Test func droppingABrokenRuleLeavesTheRestInOrder() {
        var profile = CustomRoutingProfile()
        profile.routes.rules = [rule(.accept, "10.1.0.0/16"),
                                rule(.accept, "10.0.0.0/33"),     // invalid
                                rule(.accept, "10.2.0.0/16")]
        let out = sanitizedCustomRoutingProfile(profile)
        #expect(out.routes.rules.map { $0.match?.value } == ["10.1.0.0/16", "10.2.0.0/16"])
    }

    // MARK: The list itself stays intact

    /// Walking a rule from the top to the bottom one step at a time and back again
    /// must return the original list — no rule lost, none duplicated, whatever route
    /// the move took.
    @Test func aRuleCanWalkTheWholeListAndComeBack() {
        var rules = (0..<5).map { rule(.accept, "10.\($0).0.0/16") }
        let original = rules.map(\.id)
        for i in 0..<4 { rules = Reorder.moved(rules, from: i, to: i + 1) }
        #expect(rules.map(\.id).last == original.first)
        for i in stride(from: 4, to: 0, by: -1) { rules = Reorder.moved(rules, from: i, to: i - 1) }
        #expect(rules.map(\.id) == original)
        #expect(Set(rules.map(\.id)).count == 5)
    }

    /// A stale index — the row was deleted while a drag was in flight — leaves the
    /// list exactly as it was. Total over bad input, on the real type.
    @Test func aStaleIndexLeavesTheRulesAlone() {
        let rules = [rule(.accept, "10.1.0.0/16"), rule(.ignore, "10.2.0.0/16")]
        #expect(Reorder.moved(rules, from: 7, to: 0).map(\.id) == rules.map(\.id))
        #expect(Reorder.moved(rules, from: 0, insertingBefore: 99).map(\.id)
                == [rules[1].id, rules[0].id])
    }
}
