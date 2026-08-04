// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CustomRoutingTests.swift
//  The per-VPN Custom Routing model + intent transforms (Mediators/CustomRouting.swift):
//  the tier-2 static form of the tier-3 ROUTE_ADVERTISED/DNS_PUSHED/PROXY_PUSHED rewrite
//  hooks. Every function here is pure and I/O-free — the transforms, the rule-status
//  diagnostics, the CIDR-overlap helper — plus a round-trip of the durable pushed-intent
//  snapshot through an injected UserDefaults suite. No NE, no mediator instances.
//

import Foundation
import Testing
@testable import SimpleVPN

struct CustomRoutingTests {

    // MARK: - Helpers

    private func routeIntent(_ engine: String = "vpn",
                             prefixes: [String] = [], wantsDefault: Bool = false,
                             canOwn: Bool = true) -> RouteIntent {
        RouteIntent(engine: engine, advertisedPrefixes: prefixes, wantsDefault: wantsDefault,
                    canOwnDefault: canOwn)
    }

    private func rule(_ verb: FilterVerb, match: String? = nil, target: String? = nil) -> RouteFilter.RouteRule {
        RouteFilter.RouteRule(verb: verb,
                              match: match.map(RoutePrefix.init),
                              target: target.map(RoutePrefix.init))
    }

    // MARK: - Routes: identity

    @Test func routeEmptyFilterIsIdentity() {
        let captured = routeIntent(prefixes: ["10.0.0.0/8"], wantsDefault: true)
        #expect(RouteFilter().apply(to: captured) == captured)
    }

    // MARK: - Routes: the four verbs (accept-unmatched default)

    @Test func routeAcceptUnmatchedKeepsPushed() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "192.168.0.0/16")]   // unrelated
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8"]))
        #expect(out.advertisedPrefixes == ["10.0.0.0/8"])
    }

    @Test func routeIgnoreDropsMatched() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "10.0.0.0/8")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8", "172.16.0.0/12"]))
        #expect(out.advertisedPrefixes == ["172.16.0.0/12"])
    }

    @Test func routeReplaceSubstitutes() {
        var f = RouteFilter()
        f.rules = [rule(.replace, match: "10.0.0.0/8", target: "10.1.0.0/16")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8"]))
        #expect(out.advertisedPrefixes == ["10.1.0.0/16"])
    }

    @Test func routeAddInjects() {
        var f = RouteFilter()
        f.rules = [rule(.add, target: "203.0.113.0/24")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8"]))
        #expect(out.advertisedPrefixes == ["10.0.0.0/8", "203.0.113.0/24"])
    }

    // MARK: - Routes: allow-list (ignore-unmatched) + explicit Accept

    @Test func routeAllowListDropsUnmatched() {
        var f = RouteFilter()
        f.defaultDisposition = .ignore
        f.rules = [rule(.accept, match: "10.0.0.0/8")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8", "172.16.0.0/12"]))
        #expect(out.advertisedPrefixes == ["10.0.0.0/8"])   // only the explicitly-accepted survives
    }

    @Test func routeAllowListKeepsReplaced() {
        var f = RouteFilter()
        f.defaultDisposition = .ignore
        f.rules = [rule(.replace, match: "10.0.0.0/8", target: "10.9.0.0/16")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8", "172.16.0.0/12"]))
        #expect(out.advertisedPrefixes == ["10.9.0.0/16"])
    }

    // MARK: - Routes: default handling → force split

    @Test func routeIgnoreDefaultForcesSplit() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "default")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8"], wantsDefault: true, canOwn: true))
        #expect(out.wantsDefault == false)
        #expect(out.canOwnDefault == false)          // dropping a pushed default forces split
        #expect(out.advertisedPrefixes == ["10.0.0.0/8"])
    }

    @Test func routeIgnoreDefaultViaZeroToken() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "0.0.0.0/0")]
        let out = f.apply(to: routeIntent(wantsDefault: true))
        #expect(out.wantsDefault == false)
    }

    @Test func routeReplaceDefaultWithPrefixSplits() {
        var f = RouteFilter()
        f.rules = [rule(.replace, match: "default", target: "10.0.0.0/8")]
        let out = f.apply(to: routeIntent(wantsDefault: true, canOwn: true))
        #expect(out.wantsDefault == false)
        #expect(out.canOwnDefault == false)
        #expect(out.advertisedPrefixes == ["10.0.0.0/8"])
    }

    @Test func routeAcceptDefaultKeepsOwnership() {
        var f = RouteFilter()
        f.defaultDisposition = .ignore
        f.rules = [rule(.accept, match: "default")]
        let out = f.apply(to: routeIntent(prefixes: ["10.0.0.0/8"], wantsDefault: true, canOwn: true))
        #expect(out.wantsDefault == true)
        #expect(out.canOwnDefault == true)
        #expect(out.advertisedPrefixes == [])        // allow-list dropped the specific prefix
    }

    // MARK: - Routes: composed through the arbiter (Ignore-default → no owner)

    @Test func routeIgnoreDefaultRemovesOwnerAtArbiter() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "default")]
        let filtered = f.apply(to: routeIntent("corp", wantsDefault: true, canOwn: true))
        let plan = RouteArbiter.plan(intents: [filtered],
                                     policy: RoutePolicy(storedOwner: "corp", userChoseDirect: false))
        #expect(plan.owner == nil)                   // no capable engine ⇒ Direct
    }

    // MARK: - DNS: resolver verbs

    private func dnsRule(_ verb: FilterVerb, match: String? = nil, target: String? = nil) -> DNSCustomization.ResolverRule {
        DNSCustomization.ResolverRule(verb: verb, match: match, target: target)
    }

    @Test func dnsEmptyFilterIsIdentity() {
        let captured = DNSIntent(engine: "vpn", resolvers: ["1.1.1.1"], searchDomains: ["corp"])
        #expect(DNSCustomization().apply(to: captured) == captured)
    }

    @Test func dnsIgnoreResolver() {
        var c = DNSCustomization()
        c.resolverRules = [dnsRule(.ignore, match: "1.1.1.1")]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1", "8.8.8.8"]))
        #expect(out.resolvers == ["8.8.8.8"])
    }

    @Test func dnsReplaceResolver() {
        var c = DNSCustomization()
        c.resolverRules = [dnsRule(.replace, match: "1.1.1.1", target: "9.9.9.9")]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1"]))
        #expect(out.resolvers == ["9.9.9.9"])
    }

    @Test func dnsAddResolver() {
        var c = DNSCustomization()
        c.resolverRules = [dnsRule(.add, target: "9.9.9.9")]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1"]))
        #expect(out.resolvers == ["1.1.1.1", "9.9.9.9"])
    }

    @Test func dnsResolverAllowList() {
        var c = DNSCustomization()
        c.defaultDisposition = .ignore
        c.resolverRules = [dnsRule(.accept, match: "1.1.1.1")]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1", "8.8.8.8"]))
        #expect(out.resolvers == ["1.1.1.1"])
    }

    // MARK: - DNS: domain handling

    @Test func dnsIgnorePushedSearchAndAdd() {
        var c = DNSCustomization()
        c.ignorePushedSearchDomains = true
        c.addSearchDomains = ["home.arpa"]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1"],
                                        searchDomains: ["corp.example", "eng.example"]))
        #expect(out.searchDomains == ["home.arpa"])
    }

    @Test func dnsIgnoreSpecificMatchDomain() {
        var c = DNSCustomization()
        c.ignoreMatchDomains = ["eng.example"]
        c.addMatchDomains = ["lab.example"]
        let out = c.apply(to: DNSIntent(engine: "v", resolvers: ["1.1.1.1"],
                                        matchDomains: ["corp.example", "eng.example"]))
        #expect(out.matchDomains == ["corp.example", "lab.example"])
    }

    // MARK: - Proxy: accept / ignore / custom

    @Test func proxyAcceptPassesCaptured() {
        let captured = ProxyIntent(engine: "v", mode: .manual(ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)))
        var c = ProxyCustomization(); c.mode = .accept
        #expect(c.apply(to: captured, engine: "v") == captured)
    }

    @Test func proxyIgnoreIsDirect() {
        let captured = ProxyIntent(engine: "v", mode: .pac("http://wpad/wpad.dat"))
        var c = ProxyCustomization(); c.mode = .ignore
        #expect(c.apply(to: captured, engine: "v") == nil)
    }

    @Test func proxyCustomManualURL() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "http://proxy.example:8080"
        let out = c.apply(to: nil, engine: "v")
        #expect(out?.mode == .manual(ProxyEndpoint(scheme: .http, host: "proxy.example", port: 8080)))
        #expect(out?.manual?.http == ProxyEndpoint(scheme: .http, host: "proxy.example", port: 8080))
    }

    @Test func proxyCustomSocks5URL() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "socks5://127.0.0.1:1080"
        let out = c.apply(to: nil, engine: "v")
        #expect(out?.mode == .manual(ProxyEndpoint(scheme: .socks, host: "127.0.0.1", port: 1080)))
    }

    @Test func proxyCustomPACWinsOverManual() {
        var c = ProxyCustomization(); c.mode = .custom
        c.manualURL = "http://proxy.example:8080"
        c.pacURL = "http://wpad.example/wpad.dat"
        let out = c.apply(to: nil, engine: "v")
        #expect(out?.mode == .pac("http://wpad.example/wpad.dat"))
    }

    @Test func proxyCustomCarriesAuthSourceRefOnly() {
        var c = ProxyCustomization(); c.mode = .custom
        c.manualURL = "https://proxy.example:8080"; c.authSource = "keychain-ref-123"
        let out = c.apply(to: nil, engine: "v")
        #expect(out?.authSource == "keychain-ref-123")
    }

    /// Accept + a stored sign-in ⇒ the PUSHED proxy passes through carrying the auth
    /// REF (how an authenticated pushed proxy reaches the realizer's keychain lookup).
    @Test func proxyAcceptAttachesAuthSourceToPushedProxy() {
        let captured = ProxyIntent(engine: "v", mode: .manual(ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)))
        var c = ProxyCustomization(); c.mode = .accept
        c.authSource = ProxyAuthSourceRef.ref(forProfile: "v")
        let out = c.apply(to: captured, engine: "v")
        #expect(out?.mode == captured.mode)
        #expect(out?.authSource == "customrouting:v")
    }

    /// Accept + auth with NO push stays nil (the REF can't conjure a proxy), and a
    /// non-providing capture is passed through without the REF (nothing to sign into).
    @Test func proxyAcceptAuthNeedsAPushedProxy() {
        var c = ProxyCustomization(); c.mode = .accept
        c.authSource = ProxyAuthSourceRef.ref(forProfile: "v")
        #expect(c.apply(to: nil, engine: "v") == nil)
        let none = ProxyIntent(engine: "v", mode: .none)
        #expect(c.apply(to: none, engine: "v")?.authSource == nil)
    }

    // MARK: - Proxy: the native (app-applied-at-connect) payload

    @Test func nativeApplyRequestMapsManualWithAuth() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "https://proxy.example:8080"
        let req = c.nativeApplyRequest(username: "alice", password: "s3cret")
        #expect(req?.httpsHost == "proxy.example")
        #expect(req?.httpsPort == 8080)
        #expect(req?.username == "alice")
        #expect(req?.password == "s3cret")
    }

    @Test func nativeApplyRequestMapsPAC() {
        var c = ProxyCustomization(); c.mode = .custom; c.pacURL = "http://wpad.example/wpad.dat"
        #expect(c.nativeApplyRequest()?.pacURL == "http://wpad.example/wpad.dat")
    }

    /// NEProxySettings has no SOCKS slot, so a SOCKS custom maps to nil — the editor
    /// warns for the native kinds instead of half-applying.
    @Test func nativeApplyRequestSOCKSIsNil() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "socks5://127.0.0.1:1080"
        #expect(c.nativeApplyRequest() == nil)
        #expect(c.customIsSOCKS)
    }

    /// Only `.custom` produces a native payload — Accept/Ignore have nothing the app
    /// can apply through the VPN configuration for these kinds.
    @Test func nativeApplyRequestNilUnlessCustom() {
        var c = ProxyCustomization(); c.manualURL = "http://proxy.example:8080"
        c.mode = .accept
        #expect(c.nativeApplyRequest() == nil)
        c.mode = .ignore
        #expect(c.nativeApplyRequest() == nil)
    }

    // MARK: - Persistence: the no-NE-manager fallback store (native kinds)

    @Test func fallbackStoreRoundTripsAndDropsIdentity() throws {
        let suite = try #require(UserDefaults(suiteName: "test.customrouting.fallback.\(UUID().uuidString)"))
        let store = CustomRoutingFallbackStore(defaults: suite)
        var profile = CustomRoutingProfile()
        profile.proxy.mode = .custom
        profile.proxy.manualURL = "http://proxy.example:8080"
        profile.proxy.authSource = ProxyAuthSourceRef.ref(forProfile: "native-1")
        store.save(profile, for: "native-1")
        #expect(store.load("native-1") == profile)
        // An identity profile removes the entry (mirrors the omitted-when-empty blob).
        store.save(CustomRoutingProfile(), for: "native-1")
        #expect(store.load("native-1") == CustomRoutingProfile())
    }

    // MARK: - Persistence: blob round-trip + lenient decode

    @Test func profileEmptyDropsBlob() {
        #expect(CustomRoutingProfile().encodedBlob() == nil)
    }

    @Test func profileMissingBlobDecodesIdentity() {
        #expect(CustomRoutingProfile.decode(from: nil) == CustomRoutingProfile())
    }

    @Test func profileRoundTrips() throws {
        var p = CustomRoutingProfile()
        p.routes.rules = [rule(.ignore, match: "default")]
        p.dns.addSearchDomains = ["home.arpa"]
        p.proxy.mode = .custom; p.proxy.pacURL = "http://wpad/wpad.dat"
        let blob = try #require(p.encodedBlob())
        #expect(CustomRoutingProfile.decode(from: blob) == p)
    }

    @Test func profileCorruptBlobDecodesIdentity() {
        let junk = Data("not json".utf8)
        #expect(CustomRoutingProfile.decode(from: junk) == CustomRoutingProfile())
    }

    // MARK: - Pushed-intent snapshot: store round-trip (injected suite)

    @Test func pushedSnapshotRoundTrips() throws {
        let suite = try #require(UserDefaults(suiteName: "test.customrouting.\(UUID().uuidString)"))
        let store = PushedIntentStore(defaults: suite)
        var snap = PushedIntentSnapshot()
        snap.routes = .init(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: true)
        snap.dns = .init(resolvers: ["1.1.1.1"], searchDomains: ["corp"], matchDomains: [])
        snap.proxy = PushedIntentSnapshot.Proxy(
            ProxyIntent(engine: "v", mode: .pac("http://wpad/wpad.dat")))
        store.save(snap, for: "corp")
        #expect(store.load("corp") == snap)
        store.clear("corp")
        #expect(store.load("corp") == nil)
    }

    @Test func pushedProxySnapshotNilWhenNoProxy() {
        #expect(PushedIntentSnapshot.Proxy(ProxyIntent(engine: "v", mode: .none)) == nil)
    }

    // MARK: - Rule status diagnostics

    @Test func routeStatusActiveAndOrphaned() {
        let f = RouteFilter()
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        #expect(f.ruleStatus(rule(.ignore, match: "10.0.0.0/8"), against: pushed) == .active)
        #expect(f.ruleStatus(rule(.ignore, match: "172.16.0.0/12"), against: pushed) == .orphaned)
    }

    @Test func routeStatusRedundantReplaceAndAdd() {
        let f = RouteFilter()
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        // Replace whose target already equals a pushed route.
        #expect(f.ruleStatus(rule(.replace, match: "10.0.0.0/8", target: "10.0.0.0/8"), against: pushed) == .redundant)
        // Add of something already pushed.
        #expect(f.ruleStatus(rule(.add, target: "10.0.0.0/8"), against: pushed) == .redundant)
    }

    @Test func routeStatusOverlappingAdd() {
        let f = RouteFilter()
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        // 10.1.0.0/16 is contained by the pushed 10.0.0.0/8 (overlap, not exact).
        #expect(f.ruleStatus(rule(.add, target: "10.1.0.0/16"), against: pushed) == .overlapping)
        // 203.0.113.0/24 is disjoint ⇒ genuinely new.
        #expect(f.ruleStatus(rule(.add, target: "203.0.113.0/24"), against: pushed) == .active)
    }

    @Test func routeStatusReplaceOrphanedWhenMatchGone() {
        let f = RouteFilter()
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        #expect(f.ruleStatus(rule(.replace, match: "192.168.0.0/16", target: "10.1.0.0/16"), against: pushed) == .orphaned)
    }

    /// An allow-list already drops everything no rule accepts, so an explicit
    /// Ignore inside one can't change the outcome — the badge existed, the model
    /// just never computed this case.
    @Test func ignoreIsRedundantUnderAnIgnoreAllDisposition() {
        var f = RouteFilter()
        f.defaultDisposition = .ignore
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        // True whether or not the prefix is currently pushed: the rule can never bite.
        #expect(f.ruleStatus(rule(.ignore, match: "10.0.0.0/8"), against: pushed) == .redundant)
        #expect(f.ruleStatus(rule(.ignore, match: "172.16.0.0/12"), against: pushed) == .redundant)
        // The other verbs are untouched — an Accept is what an allow-list is FOR.
        #expect(f.ruleStatus(rule(.accept, match: "10.0.0.0/8"), against: pushed) == .active)
        #expect(f.ruleStatus(rule(.add, target: "203.0.113.0/24"), against: pushed) == .active)
        // …and with the default disposition it stays exactly as before.
        var accepting = RouteFilter()
        accepting.defaultDisposition = .accept
        #expect(accepting.ruleStatus(rule(.ignore, match: "10.0.0.0/8"), against: pushed) == .active)
    }

    @Test func dnsIgnoreIsRedundantUnderAnIgnoreAllDisposition() {
        var c = DNSCustomization()
        c.defaultDisposition = .ignore
        let pushed = PushedIntentSnapshot.DNS(resolvers: ["1.1.1.1"], searchDomains: [], matchDomains: [])
        #expect(c.ruleStatus(dnsRule(.ignore, match: "1.1.1.1"), against: pushed) == .redundant)
        #expect(c.ruleStatus(dnsRule(.ignore, match: "8.8.8.8"), against: pushed) == .redundant)
        #expect(c.ruleStatus(dnsRule(.accept, match: "1.1.1.1"), against: pushed) == .active)
    }

    // MARK: - Verb changes clear the fields the new verb hides
    //
    // The editor hides the control a verb doesn't use, but the filter still READS
    // it (`dispositionForPrefix` consults a Replace's target; `apply` injects an
    // Add's). A hidden field the tunnel obeys is state the user can't see.

    @Test func switchingToAcceptOrIgnoreDropsTheTarget() {
        var r = RouteFilter.RouteRule(verb: .replace, match: RoutePrefix("10.0.0.0/8"),
                                      target: RoutePrefix("10.1.0.0/16"))
        r.verb = .accept
        #expect(r.clearingUnusedFields().target == nil)
        #expect(r.clearingUnusedFields().match == RoutePrefix("10.0.0.0/8"))
        r.verb = .ignore
        #expect(r.clearingUnusedFields().target == nil)
    }

    @Test func switchingToAddDropsTheMatch() {
        var r = RouteFilter.RouteRule(verb: .replace, match: RoutePrefix("10.0.0.0/8"),
                                      target: RoutePrefix("10.1.0.0/16"))
        r.verb = .add
        let cleared = r.clearingUnusedFields()
        #expect(cleared.match == nil)
        #expect(cleared.target == RoutePrefix("10.1.0.0/16"))
    }

    @Test func replaceKeepsBothAndTheIdNeverMoves() {
        let r = RouteFilter.RouteRule(verb: .replace, match: RoutePrefix("10.0.0.0/8"),
                                      target: RoutePrefix("10.1.0.0/16"))
        #expect(r.clearingUnusedFields() == r)
        #expect(r.clearingUnusedFields().id == r.id)
    }

    @Test func dnsRulesClearTheSameWay() {
        var r = DNSCustomization.ResolverRule(verb: .replace, match: "1.1.1.1", target: "10.0.0.1")
        r.verb = .ignore
        #expect(r.clearingUnusedFields().target == nil)
        #expect(r.clearingUnusedFields().match == "1.1.1.1")
        r.verb = .add
        #expect(r.clearingUnusedFields().match == nil)
        #expect(r.clearingUnusedFields().target == "10.0.0.1")
    }

    /// Rules stored before the editor cleared them (or written by MDM/the CLI)
    /// are cleaned on the way to the mediators, so the stale value can't act.
    @Test func theSanitizerClearsStaleHiddenFields() {
        var p = CustomRoutingProfile()
        p.routes.rules = [.init(verb: .accept, match: RoutePrefix("10.0.0.0/8"),
                                target: RoutePrefix("192.168.0.0/16")),
                          .init(verb: .add, match: RoutePrefix("10.0.0.0/8"),
                                target: RoutePrefix("203.0.113.0/24"))]
        p.dns.resolverRules = [.init(verb: .ignore, match: "1.1.1.1", target: "8.8.8.8")]
        let out = sanitizedCustomRoutingProfile(p)
        #expect(out.routes.rules[0].target == nil)
        #expect(out.routes.rules[1].match == nil)
        #expect(out.dns.resolverRules[0].target == nil)
    }

    /// The whole point: a stale target on an Accept must not reach the transform.
    @Test func aStaleTargetCannotChangeTheAppliedIntent() {
        var p = CustomRoutingProfile()
        p.routes.rules = [.init(verb: .accept, match: RoutePrefix("10.0.0.0/8"),
                                target: RoutePrefix("192.168.0.0/16"))]
        let captured = routeIntent("wg", prefixes: ["10.0.0.0/8"])
        let out = sanitizedCustomRoutingProfile(p).routes.apply(to: captured)
        #expect(out.advertisedPrefixes == ["10.0.0.0/8"])
    }

    @Test func dnsStatusOrphanedAndRedundant() {
        let c = DNSCustomization()
        let pushed = PushedIntentSnapshot.DNS(resolvers: ["1.1.1.1"], searchDomains: [], matchDomains: [])
        #expect(c.ruleStatus(dnsRule(.ignore, match: "8.8.8.8"), against: pushed) == .orphaned)
        #expect(c.ruleStatus(dnsRule(.add, target: "1.1.1.1"), against: pushed) == .redundant)
        #expect(c.ruleStatus(dnsRule(.ignore, match: "1.1.1.1"), against: pushed) == .active)
    }

    @Test func proxyStatusOrphanedWhenNoPush() {
        var accept = ProxyCustomization(); accept.mode = .accept
        var custom = ProxyCustomization(); custom.mode = .custom
        let pushed = PushedIntentSnapshot.Proxy(ProxyIntent(engine: "v", mode: .pac("http://wpad/x")))
        #expect(accept.ruleStatus(against: nil) == .orphaned)
        #expect(accept.ruleStatus(against: pushed) == .active)
        #expect(custom.ruleStatus(against: nil) == .active)
    }

    // MARK: - CIDR overlap helper

    @Test func cidrOverlapContainment() {
        #expect(RoutePrefixMath.overlaps("10.0.0.0/8", "10.1.2.0/24") == true)
        #expect(RoutePrefixMath.overlaps("10.1.2.0/24", "10.0.0.0/8") == true)
        #expect(RoutePrefixMath.overlaps("10.0.0.0/8", "11.0.0.0/8") == false)
        #expect(RoutePrefixMath.overlaps("10.0.0.0/8", "2001:db8::/32") == false)   // mixed family
        #expect(RoutePrefixMath.overlaps("2001:db8::/32", "2001:db8:1::/48") == true)
    }

    // MARK: - Validation: route CIDR fields

    @Test func validateMalformedCIDRIsFieldError() {
        let issues = CustomRoutingValidator.validate(rule(.add, target: "10.0.0.0/33"))
        let e = issues.first { $0.field == "target" && $0.isError }
        #expect(e != nil)
        #expect(e?.message.contains("0…32") == true)
    }

    @Test func validateBadAddressIsError() {
        let issues = CustomRoutingValidator.validate(rule(.ignore, match: "not.an.ip/8"))
        #expect(issues.contains { $0.field == "match" && $0.isError })
    }

    @Test func validateHostBitsSetIsError() {
        let issues = CustomRoutingValidator.validate(rule(.add, target: "10.1.2.3/8"))
        #expect(issues.contains { $0.field == "target" && $0.isError && $0.message.contains("Host bits") })
    }

    @Test func validateDefaultTokenIsAccepted() {
        // default token as an Add is valid but warned (carries all traffic).
        let issues = CustomRoutingValidator.validate(rule(.add, target: "default"))
        #expect(issues.allSatisfy { !$0.isError })
        #expect(issues.contains { $0.severity == .warning })
    }

    @Test func validateV6CIDR() {
        #expect(CustomRoutingValidator.validate(rule(.add, target: "2001:db8::/32")).isEmpty)
        #expect(CustomRoutingValidator.validate(rule(.add, target: "2001:db8::/129"))
            .contains { $0.isError })
    }

    @Test func validateLoopbackWarns() {
        let issues = CustomRoutingValidator.validate(rule(.add, target: "127.0.0.0/8"))
        #expect(issues.contains { $0.severity == .warning && $0.message.contains("loopback") })
    }

    // MARK: - Validation: overlap (cross-rule + vs pushed)

    @Test func validateOverlapWithAnotherRuleWarns() {
        var f = RouteFilter()
        f.rules = [rule(.add, target: "10.0.0.0/8"), rule(.add, target: "10.1.0.0/16")]
        let issues = CustomRoutingValidator.validate(f)
        let w = issues.first { $0.severity == .warning && $0.field == "target"
            && $0.message.contains("overlaps") && $0.message.contains("10.0.0.0/8") }
        #expect(w != nil)
    }

    @Test func validateOverlapWithPushedRouteWarns() {
        var f = RouteFilter()
        f.rules = [rule(.add, target: "10.1.0.0/16")]
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        let issues = CustomRoutingValidator.validate(f, against: pushed)
        #expect(issues.contains { $0.severity == .warning && $0.field == "target"
            && $0.message.contains("10.0.0.0/8") && $0.message.contains("this VPN") })
    }

    @Test func validateOverlapReportsRelatedRefs() {
        var f = RouteFilter()
        let r1 = RouteFilter.RouteRule(verb: .add, target: RoutePrefix("10.0.0.0/8"))
        let r2 = RouteFilter.RouteRule(verb: .add, target: RoutePrefix("10.1.0.0/16"))
        f.rules = [r1, r2]
        // 10.0.0.0/8 contains BOTH the sibling rule 10.1.0.0/16 and the pushed 10.2.0.0/16.
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.2.0.0/16"], wantsDefault: false)
        let issues = CustomRoutingValidator.validate(f, against: pushed)
        let issue = issues.first { $0.field == "target" && $0.message.hasPrefix("10.0.0.0/8 overlaps") }
        #expect(issue != nil)
        #expect(issue?.related.count == 2)
        #expect(issue?.related.contains { $0.kind == .pushedRoute && $0.value == "10.2.0.0/16" } == true)
        #expect(issue?.related.contains {
            $0.kind == .rule && $0.ruleID == r2.id && $0.ruleIndex == 1 && $0.value == "10.1.0.0/16"
        } == true)
    }

    @Test func validateNoOverlapNoWarning() {
        var f = RouteFilter()
        f.rules = [rule(.add, target: "203.0.113.0/24")]
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: false)
        let issues = CustomRoutingValidator.validate(f, against: pushed)
        #expect(issues.contains { $0.message.contains("overlaps") } == false)
    }

    // MARK: - Validation: DNS + proxy

    @Test func validateDNSBadResolverIsError() {
        let issues = CustomRoutingValidator.validate(dnsRule(.add, target: "999.1.1.1"))
        #expect(issues.contains { $0.field == "target" && $0.isError })
    }

    @Test func validateDNSBadDomainIsError() {
        var c = DNSCustomization(); c.addSearchDomains = ["-bad-.example"]
        #expect(CustomRoutingValidator.validate(c).contains { $0.field == "searchDomain" && $0.isError })
    }

    @Test func validateProxyBadURLIsError() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "ftp://nope"
        #expect(CustomRoutingValidator.validate(c).contains { $0.field == "manualURL" && $0.isError })
    }

    @Test func validateProxyBadPACIsError() {
        var c = ProxyCustomization(); c.mode = .custom; c.pacURL = "not a url"
        #expect(CustomRoutingValidator.validate(c).contains { $0.field == "pacURL" && $0.isError })
    }

    @Test func validateProxyCustomEmptyIsError() {
        var c = ProxyCustomization(); c.mode = .custom
        #expect(CustomRoutingValidator.validate(c).contains { $0.isError })
    }

    @Test func validateGoodProxyIsClean() {
        var c = ProxyCustomization(); c.mode = .custom; c.manualURL = "socks5://127.0.0.1:1080"
        #expect(CustomRoutingValidator.validate(c).isEmpty)
    }

    // MARK: - Diff: routes / DNS / proxy

    @Test func diffRoutesUnchangedAddedReplacedRemoved() {
        var f = RouteFilter()
        f.rules = [
            rule(.ignore, match: "172.16.0.0/12"),                       // removed
            rule(.replace, match: "10.0.0.0/8", target: "10.9.0.0/16"),  // replaced
            rule(.add, target: "203.0.113.0/24"),                        // added
        ]
        let pushed = PushedIntentSnapshot.Routes(
            advertisedPrefixes: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], wantsDefault: false)
        let d = CustomRoutingDiff.diffRoutes(filter: f, pushed: pushed)

        #expect(d.items.contains { $0.value == "192.168.0.0/16" && $0.delta == .unchanged })
        #expect(d.items.contains { $0.value == "10.9.0.0/16" && $0.delta == .replaced })
        #expect(d.items.contains { $0.value == "203.0.113.0/24" && $0.delta == .added })
        #expect(d.removed.contains("172.16.0.0/12"))
        #expect(d.removed.contains("10.0.0.0/8"))   // supplanted by the replace target
    }

    @Test func diffRoutesDefaultRemoved() {
        var f = RouteFilter()
        f.rules = [rule(.ignore, match: "default")]
        let pushed = PushedIntentSnapshot.Routes(advertisedPrefixes: ["10.0.0.0/8"], wantsDefault: true)
        let d = CustomRoutingDiff.diffRoutes(filter: f, pushed: pushed)
        #expect(d.removed.contains("default"))
        #expect(d.items.contains { $0.value == "10.0.0.0/8" && $0.delta == .unchanged })
    }

    @Test func diffDNSResolvers() {
        var c = DNSCustomization()
        c.resolverRules = [
            dnsRule(.ignore, match: "8.8.8.8"),
            dnsRule(.replace, match: "1.1.1.1", target: "9.9.9.9"),
            dnsRule(.add, target: "1.0.0.1"),
        ]
        let pushed = PushedIntentSnapshot.DNS(resolvers: ["1.1.1.1", "8.8.8.8", "1.2.3.4"],
                                              searchDomains: [], matchDomains: [])
        let d = CustomRoutingDiff.diffDNSResolvers(filter: c, pushed: pushed)
        #expect(d.items.contains { $0.value == "1.2.3.4" && $0.delta == .unchanged })
        #expect(d.items.contains { $0.value == "9.9.9.9" && $0.delta == .replaced })
        #expect(d.items.contains { $0.value == "1.0.0.1" && $0.delta == .added })
        #expect(d.removed.contains("8.8.8.8"))
    }

    @Test func diffProxyAddedReplacedRemoved() {
        let pushedPAC = PushedIntentSnapshot.Proxy(ProxyIntent(engine: "v", mode: .pac("http://wpad/x")))

        // Custom over a pushed proxy ⇒ replaced (+ pushed removed).
        var custom = ProxyCustomization(); custom.mode = .custom; custom.manualURL = "http://p.example:8080"
        let dReplace = CustomRoutingDiff.diffProxy(filter: custom, pushed: pushedPAC)
        #expect(dReplace.items.first?.delta == .replaced)
        #expect(dReplace.removed == ["PAC http://wpad/x"])

        // Custom with no pushed proxy ⇒ added.
        let dAdd = CustomRoutingDiff.diffProxy(filter: custom, pushed: nil)
        #expect(dAdd.items.first?.delta == .added)

        // Ignore a pushed proxy ⇒ removed, nothing effective.
        var ignore = ProxyCustomization(); ignore.mode = .ignore
        let dRemove = CustomRoutingDiff.diffProxy(filter: ignore, pushed: pushedPAC)
        #expect(dRemove.items.isEmpty)
        #expect(dRemove.removed == ["PAC http://wpad/x"])

        // Accept a pushed proxy ⇒ unchanged.
        var accept = ProxyCustomization(); accept.mode = .accept
        let dSame = CustomRoutingDiff.diffProxy(filter: accept, pushed: pushedPAC)
        #expect(dSame.items.first?.delta == .unchanged)
    }
}

// MARK: - MDM LockConfiguration reaches Custom Routing (the policy-bypass fix)

/// Routes, DNS and the system proxy ARE connection settings, and the Custom
/// Routing proxy sign-in is a keychain write — so `LockConfiguration` governs them
/// exactly as it governs the engine overrides. It didn't: the OpenVPN editor's tab
/// had no `.disabled` and the setter had no guard, so under a managed lock all of
/// it stayed editable and persisted. Both halves are fixed; the guard below the UI
/// is the one that matters, because the UI must never be the only enforcement
/// point (`SettingRenderingTests` covers the modifier in all six editors).
@MainActor
struct CustomRoutingManagedLockTests {

    private static let lockKey = "LockConfiguration"

    private func withLock(_ body: () async throws -> Void) async rethrows {
        let previous = UserDefaults.standard.object(forKey: Self.lockKey)
        UserDefaults.standard.set(true, forKey: Self.lockKey)
        defer {
            if let previous { UserDefaults.standard.set(previous, forKey: Self.lockKey) }
            else { UserDefaults.standard.removeObject(forKey: Self.lockKey) }
        }
        #expect(ManagedPolicy.lockConfiguration)
        try await body()
    }

    private func filter() -> CustomRoutingProfile {
        var p = CustomRoutingProfile()
        p.dns.addSearchDomains = ["corp.example.com"]
        return p
    }

    @Test func theSetterRefusesUnderAManagedLock() async throws {
        let id = "lock-test-\(UUID().uuidString)"
        let store = CustomRoutingFallbackStore()
        defer { store.clear(id) }
        let vpn = VPNController()

        await withLock {
            await #expect(throws: (any Error).self) {
                try await vpn.setCustomRouting(filter(), for: id)
            }
            // …and nothing was written on the way to throwing.
            #expect(store.load(id) == CustomRoutingProfile())
            #expect(vpn.customRouting(for: id) == CustomRoutingProfile())
        }

        // Unlocked, the same call persists — so the guard is the lock, not a bug.
        try await vpn.setCustomRouting(filter(), for: id)
        #expect(store.load(id).dns.addSearchDomains == ["corp.example.com"])
    }

    /// The commit helper every editor's Save calls stops BEFORE
    /// `syncCustomRoutingProxyAuth`, which is the keychain write — a locked
    /// configuration must not have its proxy credential rewritten (or deleted)
    /// either.
    @Test func theCommitHelperIsANoOpUnderAManagedLock() async throws {
        let id = "lock-commit-\(UUID().uuidString)"
        let store = CustomRoutingFallbackStore()
        defer { store.clear(id) }
        let vpn = VPNController()
        let wanted = filter()

        await withLock {
            let out = await commitCustomRouting(vpn, profileID: id, profile: wanted,
                                                proxyAuthUsername: "alex", proxyAuthPassword: "s3cret")
            // Returned untouched — no authSource ref invented, nothing persisted.
            #expect(out == wanted)
            #expect(out.proxy.authSource == nil)
            #expect(store.load(id) == CustomRoutingProfile())
        }
    }
}
