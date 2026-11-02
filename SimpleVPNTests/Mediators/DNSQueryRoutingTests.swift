// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
private final class RecordingDNSQueryBackend: DNSQueryRoutingBackend {
    var calls: [DNSQueryPolicy] = []
    var failure = false
    var observed: (@MainActor (Bool) -> Void)?
    func observeConfiguration(_ handler: @escaping @MainActor (Bool) -> Void) { observed = handler }
    func configure(_ policy: DNSQueryPolicy) async throws {
        calls.append(policy)
        if failure { throw DNSQueryRoutingController.error("Configuration rejected") }
    }
}

@MainActor
struct DNSQueryRoutingTests {
    @Test(arguments: [
        ("tig-portal.grlab.co.uk", "tig-portal.grlab.co.uk", true),
        ("tig-portal.grlab.co.uk", "TIG-PORTAL.GRLAB.CO.UK.", true),
        ("tig-portal.grlab.co.uk.", "tig-portal.grlab.co.uk", true),
        ("tig-portal.grlab.co.uk", "x.tig-portal.grlab.co.uk", false),
        ("tig-portal.grlab.co.uk", "tig-portal.grlab.co.uk.attacker.test", false)
    ]) func exactIsWholeNameAndCaseInsensitive(_ input: (String, String, Bool)) {
        #expect(DNSNameMatch(kind: .exact, pattern: input.0).matches(input.1) == input.2)
    }
    @Test(arguments: [
        ("grlab.co.uk", true), ("portal.grlab.co.uk", true),
        ("x.portal.grlab.co.uk.", true), ("notgrlab.co.uk", false), ("grlab.co.uk.test", false)
    ]) func suffixHasLabelBoundariesAndIncludesApex(_ input: (String, Bool)) {
        #expect(DNSNameMatch(kind: .suffix, pattern: "GRLAB.CO.UK.").matches(input.0) == input.1)
    }
    @Test(arguments: [
        ("*.grlab.co.uk", "grlab.co.uk", false),
        ("*.grlab.co.uk", "tig-portal.grlab.co.uk", true),
        ("*.grlab.co.uk", "deep.internal.grlab.co.uk", true),
        ("tig-?.grlab.co.uk", "tig-a.grlab.co.uk", true),
        ("tig-?.grlab.co.uk", "tig-aa.grlab.co.uk", false),
        ("tig-[ab].grlab.co.uk", "tig-a.grlab.co.uk", true),
        ("tig-[a-c].grlab.co.uk", "tig-b.grlab.co.uk", true),
        ("tig-[!a].grlab.co.uk", "tig-a.grlab.co.uk", false),
        ("tig-[!a].grlab.co.uk", "tig-z.grlab.co.uk", true),
        ("*.GRLAB.CO.UK.", "TIG-PORTAL.grlab.co.uk", true),
        ("*.grlab.co.uk", "portal.grlab.co.uk.attacker.test", false),
        ("foo\\*.example", "foo*.example", true)
    ]) func globIsAnchoredAndSupportsClasses(_ input: (String, String, Bool)) {
        let match = DNSNameMatch(kind: .glob, pattern: input.0)
        #expect(match.problem == nil)
        #expect(match.matches(input.1) == input.2)
    }
    @Test(arguments: ["", "https://example.com", "name example.com", "user@example.com", "name:53", "name/path", "[abc", "abc]", "[]", "[z-a]", "abc\\", "é.example"])
    func invalidGlobsAreRejected(_ pattern: String) {
        #expect(DNSNameMatch(kind: .glob, pattern: pattern).problem != nil)
    }
    @Test func adversarialGlobHasBoundedMatchingCost() {
        let match = DNSNameMatch(kind: .glob, pattern: String(repeating: "*a", count: 100) + "b")
        #expect(match.problem == nil)
        #expect(!match.matches(String(repeating: "a", count: 250)))
    }
    @Test func disabledRulesAndFirstMatchPrecedenceAreExplicit() {
        var exact = DNSQueryRule(match: .init(kind: .exact, pattern: "portal.grlab.co.uk"), target: .original)
        let glob = DNSQueryRule(match: .init(kind: .glob, pattern: "*.grlab.co.uk"), servers: ["192.0.2.53"])
        func route(_ rule: DNSQueryRule) -> DNSQueryRoute {
            DNSQueryRoute(profileID: "vpn", profileName: "Lab", rule: rule, servers: rule.servers)
        }
        var policy = DNSQueryPolicy(routes: [route(exact), route(glob)])
        #expect(policy.route(for: "portal.grlab.co.uk")?.rule.target == .original)
        policy.routes.reverse()
        #expect(policy.route(for: "portal.grlab.co.uk")?.rule.id == glob.id)
        exact.enabled = false
        policy.routes = [route(exact), route(glob)]
        #expect(policy.route(for: "portal.grlab.co.uk")?.rule.id == glob.id)
        #expect(policy.route(for: "other.example") == nil)
    }
    @Test func oldDNSBlobsKeepTheirSettingsAndDoNotEnableQueryRouting() throws {
        let data = Data(#"{"defaultDisposition":"ignore","resolverRules":[],"addMatchDomains":["grlab.co.uk"],"ignorePushedMatchDomains":true}"#.utf8)
        let dns = try JSONDecoder().decode(DNSCustomization.self, from: data)
        #expect(dns.defaultDisposition == .ignore)
        #expect(dns.addMatchDomains == ["grlab.co.uk"])
        #expect(dns.ignorePushedMatchDomains)
        #expect(!dns.queryRoutingEnabled && dns.queryRules.isEmpty)
        #expect(try JSONDecoder().decode(DNSCustomization.self, from: JSONEncoder().encode(dns)) == dns)
    }
    @Test func nativeSuffixCollisionNormalizesCaseAndRootDots() {
        let a = DNSIntent(engine: "a", resolvers: ["192.0.2.1"], matchDomains: ["CORP.EXAMPLE."])
        let b = DNSIntent(engine: "b", resolvers: ["192.0.2.2"], matchDomains: ["corp.example"])
        let plan = DNSArbiter.plan(intents: [b, a], policy: DNSPolicy(defaultOwner: "a"))
        #expect(plan.perDomain.count == 1)
        #expect(plan.perDomain.first?.engine == "a")
        #expect(plan.splitDomains == ["corp.example"])
    }
    @Test func suffixRemovalHasTheSameCanonicalizationAsArbitration() {
        var dns = DNSCustomization()
        dns.ignoreMatchDomains = ["CORP.EXAMPLE."]
        let out = dns.apply(to: DNSIntent(engine: "a", resolvers: ["192.0.2.53"], matchDomains: ["corp.example", ""]))
        #expect(out.matchDomains == [""])
    }
    @Test func originalTargetClearsHiddenResolverValues() {
        let rule = DNSQueryRule(match: .init(pattern: "portal.example"), target: .original, servers: ["unused"])
        #expect(rule.clearingUnusedFields().servers.isEmpty)
        #expect(rule.problem == nil)
    }
    @Test func invalidCommitCannotSilentlyStoreAPartialProfile() async {
        let vpn = VPNController()
        let id = "invalid-dns-query-" + UUID().uuidString
        var profile = CustomRoutingProfile()
        profile.dns.queryRoutingEnabled = true
        profile.dns.queryRules = [DNSQueryRule(match: .init(kind: .glob, pattern: "[invalid"))]
        do {
            try await vpn.setCustomRouting(profile, for: id)
            Issue.record("Invalid DNS query policy was saved")
        } catch {
            #expect(vpn.customRouting(for: id).isEmpty)
        }
    }
    @Test func configurationAckIsIdempotentAndFailureDoesNotPublishNewPolicy() async {
        let backend = RecordingDNSQueryBackend()
        let controller = DNSQueryRoutingController(backend: backend)
        let rule = DNSQueryRule(match: .init(pattern: "portal.example"), servers: ["192.0.2.53"])
        let policy = DNSQueryPolicy(routes: [.init(profileID: "a", profileName: "A", rule: rule, servers: rule.servers)])
        controller.update(policy); await controller.waitUntilIdle()
        #expect(controller.configured && controller.configuration == policy)
        controller.update(policy); await controller.waitUntilIdle()
        #expect(backend.calls.count == 1)
        backend.failure = true
        controller.update(DNSQueryPolicy()); await controller.waitUntilIdle()
        #expect(controller.configuration == policy)
        #expect(controller.lastError == "Configuration rejected")
    }
    @Test func externalDisableDoesNotStartAProxyReassertFight() async {
        let backend = RecordingDNSQueryBackend()
        let controller = DNSQueryRoutingController(backend: backend)
        let rule = DNSQueryRule(match: .init(pattern: "portal.example"), servers: ["192.0.2.53"])
        let policy = DNSQueryPolicy(routes: [.init(profileID: "a", profileName: "A", rule: rule, servers: rule.servers)])
        controller.update(policy); await controller.waitUntilIdle()
        backend.observed?(false)
        #expect(!controller.configured && controller.lastError != nil)
        controller.update(policy); await controller.waitUntilIdle()
        #expect(backend.calls.count == 1)
        var changed = policy
        changed.routes[0].rule.match.pattern = "changed.example"
        controller.update(changed); await controller.waitUntilIdle()
        #expect(backend.calls.count == 1)
        controller.update(changed, force: true); await controller.waitUntilIdle()
        #expect(backend.calls.count == 2 && controller.configured)
    }
    @Test func queryOnlyEditDoesNotReassertOtherNetworkPlanes() async {
        let vpn = VPNController()
        let id = "query-only-" + UUID().uuidString
        let previous = CustomRoutingProfile()
        var next = previous
        next.dns.queryRules = [DNSQueryRule(match: .init(pattern: "portal.example"), servers: ["192.0.2.53"])]
        next.dns.queryRoutingEnabled = true
        vpn.customRoutingCache[id] = next
        await vpn.applyCustomRouting(forProfile: id, previous: previous)
        #expect(vpn.routes.appliedPlan == nil)
        #expect(vpn.dns.appliedPlan == nil)
        #expect(vpn.proxies.appliedPlan == nil)
    }
    @Test func noResolverMatchRemainsAnExplicitFailureTarget() {
        let rule = DNSQueryRule(match: .init(pattern: "portal.example"))
        let policy = DNSQueryPolicy(routes: [.init(profileID: "a", profileName: "A", rule: rule, servers: [])])
        #expect(policy.route(for: "portal.example")?.servers.isEmpty == true)
        #expect(policy.route(for: "unmatched.example") == nil)
    }
}
