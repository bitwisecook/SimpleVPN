// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyMediatorTests.swift
//  The Proxy mediator's PURE core (Docs/StateMediators.md, P3): the single-decision
//  arbiter (owner precedence, single-provider fallback), the VPN-kind proxy
//  participation classifier, and the drift → re-assert decision. No SCDynamicStore, no
//  NE — every function here is total and I/O-free.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct ProxyMediatorTests {

    // MARK: - OpenVPN pushed proxy → ProxyIntent capture (per-kind, StateMediators.md)

    /// A stats sample carrying only the base (required) fields — the structured proxy
    /// fields are set per test.
    private func baseStats(_ id: String) -> TunnelStats {
        TunnelStats(profile: id, timestamp: 0, connectedSince: 0, reconnects: 0,
                    bytesIn: 0, bytesOut: 0, serverEndpoint: "", tunnelIPv4: "",
                    dnsServers: [], proxies: [])
    }

    /// Manual PROXY_HTTP + PROXY_HTTPS + PROXY_BYPASS → a manual intent whose per-scheme
    /// map carries both endpoints (representative = HTTPS) and the bypass list.
    @Test func openVPNManualPushMapsToIntent() {
        var s = baseStats("corp")
        s.proxyHTTPHost = "10.0.0.1"; s.proxyHTTPPort = 3128
        s.proxyHTTPSHost = "10.0.0.2"; s.proxyHTTPSPort = 3129
        s.proxyBypass = ["*.internal", "169.254.0.0/16"]

        let intent = VPNController.proxyIntent(engine: "corp", from: s)
        #expect(intent != nil)
        #expect(intent?.mode == .manual(ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129)))
        #expect(intent?.manual?.http == ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128))
        #expect(intent?.manual?.https == ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129))
        #expect(intent?.bypass == ["*.internal", "169.254.0.0/16"])
    }

    /// A pushed PAC URL wins over any manual host and becomes a `.pac` intent.
    @Test func openVPNPACPushMapsToPACIntent() {
        var s = baseStats("corp")
        s.proxyHTTPHost = "10.0.0.1"; s.proxyHTTPPort = 3128
        s.proxyPACURL = "http://wpad.example/wpad.dat"

        let intent = VPNController.proxyIntent(engine: "corp", from: s)
        #expect(intent?.mode == .pac("http://wpad.example/wpad.dat"))
        #expect(intent?.pacURL == "http://wpad.example/wpad.dat")
    }

    /// No pushed proxy fields ⇒ no intent (contributes nothing to arbitration).
    @Test func openVPNNoPushMeansNoIntent() {
        #expect(VPNController.proxyIntent(engine: "corp", from: baseStats("corp")) == nil)
    }

    // MARK: - ProxyPlan → NEProxySettings construction (tier-2 applier)

    @Test func planManualBuildsNEProxySettings() {
        let plan = ProxyPlan(
            owner: "corp",
            mode: .manual(ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129)),
            manual: ProxyManual(http: ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128),
                                https: ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129)),
            bypass: ["*.internal"], excludeSimpleHostnames: true)
        let settings = plan.applyRequest.makeNEProxySettings()
        #expect(settings != nil)
        #expect(settings?.httpEnabled == true)
        #expect(settings?.httpServer?.address == "10.0.0.1")
        #expect(settings?.httpServer?.port == 3128)
        #expect(settings?.httpsEnabled == true)
        #expect(settings?.httpsServer?.address == "10.0.0.2")
        #expect(settings?.httpsServer?.port == 3129)
        #expect(settings?.autoProxyConfigurationEnabled == false)
        #expect(settings?.exceptionList == ["*.internal"])
        #expect(settings?.excludeSimpleHostnames == true)
    }

    @Test func planPACBuildsNEProxySettings() {
        let plan = ProxyPlan(owner: "corp", mode: .pac("http://wpad.example/wpad.dat"))
        let settings = plan.applyRequest.makeNEProxySettings()
        #expect(settings?.autoProxyConfigurationEnabled == true)
        #expect(settings?.proxyAutoConfigurationURL == URL(string: "http://wpad.example/wpad.dat"))
        #expect(settings?.httpEnabled == false)
        #expect(settings?.httpsEnabled == false)
    }

    @Test func directPlanBuildsNoNEProxySettings() {
        let plan = ProxyPlan(owner: nil, mode: .none)
        #expect(plan.applyRequest.makeNEProxySettings() == nil)
    }

    // MARK: - Proxy authentication (authenticated pushed/custom proxies)

    /// Resolved credentials ride the apply request and land on EVERY manual
    /// `NEProxyServer` as `authenticationRequired` + username/password.
    @Test func planManualWithAuthSetsNEProxyServerCredentials() {
        let plan = ProxyPlan(
            owner: "corp",
            mode: .manual(ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129)),
            manual: ProxyManual(http: ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128),
                                https: ProxyEndpoint(scheme: .https, host: "10.0.0.2", port: 3129)),
            authSource: "customrouting:corp")
        let request = plan.applyRequest(username: "alice", password: "s3cret")
        #expect(request.username == "alice")
        #expect(request.password == "s3cret")
        let settings = request.makeNEProxySettings()
        for server in [settings?.httpServer, settings?.httpsServer] {
            #expect(server?.authenticationRequired == true)
            #expect(server?.username == "alice")
            #expect(server?.password == "s3cret")
        }
    }

    /// No sign-in resolved ⇒ the servers stay auth-free (the pre-auth behavior).
    @Test func planManualWithoutAuthLeavesServersAuthFree() {
        let plan = ProxyPlan(
            owner: "corp",
            mode: .manual(ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)),
            manual: ProxyManual(http: ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)))
        let settings = plan.applyRequest.makeNEProxySettings()
        #expect(settings?.httpServer?.authenticationRequired == false)
        #expect(settings?.httpServer?.username == nil)
        #expect(settings?.httpServer?.password == nil)
    }

    /// A one-sided sign-in (password only) still marks the server authenticated —
    /// some proxies take a bare secret.
    @Test func planManualWithPasswordOnlyStillAuthenticates() {
        let plan = ProxyPlan(
            owner: "corp",
            mode: .manual(ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)),
            manual: ProxyManual(http: ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)))
        let settings = plan.applyRequest(username: nil, password: "s3cret").makeNEProxySettings()
        #expect(settings?.httpServer?.authenticationRequired == true)
        #expect(settings?.httpServer?.password == "s3cret")
    }

    /// `NEProxySettings` has no PAC credential slot, so a PAC plan never carries the
    /// sign-in on the wire (ProxyAuthAdvisory surfaces that instead).
    @Test func planPACNeverCarriesInlineAuth() {
        let plan = ProxyPlan(owner: "corp", mode: .pac("http://wpad.example/wpad.dat"),
                             authSource: "customrouting:corp")
        let request = plan.applyRequest(username: "alice", password: "s3cret")
        #expect(request.username == nil)
        #expect(request.password == nil)
    }

    /// The auth-advisory decision: nil without a sign-in in play; otherwise exactly one
    /// honest bucket — applied / missing creds / PAC / observe-only.
    @Test func authAdvisoryDecidesEveryBucket() {
        let manual = ProxyPlan(
            owner: "corp",
            mode: .manual(ProxyEndpoint(scheme: .http, host: "10.0.0.1", port: 3128)),
            authSource: "customrouting:corp")
        // No proxy, or a proxy with no authSource ⇒ nothing to say.
        #expect(ProxyAuthAdvisory.decide(plan: ProxyPlan(owner: nil, mode: .none),
                                         credentialsFound: false, ack: nil) == nil)
        var unauthenticated = manual; unauthenticated.authSource = nil
        #expect(ProxyAuthAdvisory.decide(plan: unauthenticated,
                                         credentialsFound: true, ack: "ok") == nil)
        // The four buckets.
        #expect(ProxyAuthAdvisory.decide(plan: manual, credentialsFound: true, ack: "ok") == .applied)
        #expect(ProxyAuthAdvisory.decide(plan: manual, credentialsFound: false, ack: "ok") == .missingCredentials)
        #expect(ProxyAuthAdvisory.decide(plan: manual, credentialsFound: true, ack: nil) == .observeOnly)
        let pac = ProxyPlan(owner: "corp", mode: .pac("http://wpad.example/wpad.dat"),
                            authSource: "customrouting:corp")
        #expect(ProxyAuthAdvisory.decide(plan: pac, credentialsFound: true, ack: "ok") == .pacManualAuth)
    }

    /// The advisory's one-liners never leak a secret — they carry names only.
    @Test func authAdvisoryMessagesNameNoSecrets() {
        for advisory: ProxyAuthAdvisory in [.applied, .missingCredentials, .pacManualAuth, .observeOnly] {
            let message = advisory.message(owner: "Corp VPN")
            #expect(!message.isEmpty)
            #expect(!message.localizedCaseInsensitiveContains("s3cret"))
        }
        // A nil owner degrades to a generic name, not a crash or a blank.
        #expect(ProxyAuthAdvisory.observeOnly.message(owner: nil).contains("the VPN"))
    }

    /// The keychain REF format round-trips and rejects foreign strings.
    @Test func authSourceRefRoundTrips() {
        let ref = ProxyAuthSourceRef.ref(forProfile: "corp-1")
        #expect(ProxyAuthSourceRef.profileID(from: ref) == "corp-1")
        #expect(ProxyAuthSourceRef.profileID(from: "customrouting:") == nil)
        #expect(ProxyAuthSourceRef.profileID(from: "keychain-ref-123") == nil)
    }

    private func socks(_ host: String, _ port: Int) -> ProxyIntent.Mode {
        .manual(ProxyEndpoint(scheme: .socks, host: host, port: port))
    }

    private func intent(_ id: String, mode: ProxyIntent.Mode, at seconds: Double? = nil) -> ProxyIntent {
        ProxyIntent(engine: id, mode: mode,
                    connectedAt: seconds.map { Date(timeIntervalSinceReferenceDate: $0) })
    }

    // MARK: - Arbiter plan (stage 2)

    /// The route default owner's proxy is the system proxy.
    @Test func ownerProxyWins() {
        let plan = ProxyArbiter.plan(
            intents: [intent("corp", mode: socks("127.0.0.1", 1080), at: 1),
                      intent("home", mode: socks("127.0.0.1", 1081), at: 2)],
            policy: ProxyPolicy(defaultOwner: "corp"))
        #expect(plan.owner == "corp")
        #expect(plan.mode == socks("127.0.0.1", 1080))
    }

    /// When the owner pushes no proxy, a single provider (an SSH SOCKS tunnel) sets it.
    @Test func singleProviderSetsSystemProxyWithoutOwner() {
        let plan = ProxyArbiter.plan(
            intents: [intent("corp", mode: .none, at: 1),
                      intent("jump", mode: socks("127.0.0.1", 1080), at: 2)],
            policy: ProxyPolicy(defaultOwner: "corp"))
        #expect(plan.owner == "jump")
        #expect(plan.providesProxy)
    }

    /// Two providers with no owner ⇒ deterministic pick (most-recent wins).
    @Test func multipleProvidersBreakByRecency() {
        let plan = ProxyArbiter.plan(
            intents: [intent("a", mode: socks("127.0.0.1", 1080), at: 1),
                      intent("b", mode: socks("127.0.0.1", 1081), at: 5)],
            policy: ProxyPolicy(defaultOwner: nil))
        #expect(plan.owner == "b")
    }

    /// Nobody wants a proxy ⇒ Direct.
    @Test func noProxyMeansDirect() {
        let plan = ProxyArbiter.plan(
            intents: [intent("corp", mode: .none, at: 1)],
            policy: ProxyPolicy(defaultOwner: "corp"))
        #expect(plan.owner == nil)
        #expect(!plan.providesProxy)
    }

    // MARK: - Participation classifier

    @Test func proxyParticipationBucketsEveryKind() {
        for kind: VPNKind in [.ssh, .openVPN, .fortinet, .f5apm, .ciscoAnyConnect,
                              .globalProtect, .juniper, .pulse, .arrayNetworks] {
            #expect(ProxyParticipation.classify(kind) == .provider, "\(kind) should be .provider")
            #expect(ProxyParticipation.classify(kind).participates)
        }
        #expect(ProxyParticipation.classify(.proxyTunnel) == .egressItself)
        #expect(!ProxyParticipation.classify(.proxyTunnel).participates)
        for kind: VPNKind in [.ikev2, .ipsec, .l2tp] {
            #expect(ProxyParticipation.classify(kind) == .limited)
        }
        // Neither Tailscale nor WireGuard pushes/sets a proxy of its own.
        #expect(ProxyParticipation.classify(.tailscale) == .none)
        #expect(ProxyParticipation.classify(.wireGuard) == .none)
    }

    // MARK: - Drift → re-assert decision (stage 4)

    @Test func proxyDriftReassertsWhenSystemProxyChanged() {
        let expected = ProxyPlan(owner: "corp", mode: socks("127.0.0.1", 1080))
        let observed = ProxyObservation(enabled: true,
                                        endpoint: ProxyEndpoint(scheme: .socks, host: "10.0.0.9", port: 8080),
                                        pacURL: nil)
        #expect(ProxyDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .reassert)
    }

    @Test func proxyDriftReassertsWhenOurProxyCleared() {
        let expected = ProxyPlan(owner: "corp", mode: socks("127.0.0.1", 1080))
        #expect(ProxyDriftDecision.action(expected: expected, observed: .none,
                                          withinSuppressWindow: false) == .reassert)
    }

    @Test func proxyNoDriftWhenSystemProxyMatches() {
        let endpoint = ProxyEndpoint(scheme: .socks, host: "127.0.0.1", port: 1080)
        let expected = ProxyPlan(owner: "corp", mode: .manual(endpoint))
        let observed = ProxyObservation(enabled: true, endpoint: endpoint, pacURL: nil)
        #expect(ProxyDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .none)
    }

    @Test func proxyDriftWhenExternallyAddedWithNoExpectation() {
        // We expect no proxy, but something set one under us ⇒ drift (surface it).
        let expected = ProxyPlan(owner: nil, mode: .none)
        let observed = ProxyObservation(enabled: true,
                                        endpoint: ProxyEndpoint(scheme: .http, host: "10.0.0.9", port: 8080),
                                        pacURL: nil)
        #expect(ProxyDriftDecision.action(expected: expected, observed: observed,
                                          withinSuppressWindow: false) == .reassert)
    }

    @Test func proxyDriftIgnoredWithinSuppressWindow() {
        let expected = ProxyPlan(owner: "corp", mode: socks("127.0.0.1", 1080))
        #expect(ProxyDriftDecision.action(expected: expected, observed: .none,
                                          withinSuppressWindow: true) == .none)
    }
}
