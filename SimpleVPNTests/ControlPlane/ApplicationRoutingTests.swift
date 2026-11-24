// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NetworkExtension
import Synchronization
import Testing
@testable import SimpleVPN

@MainActor
struct ApplicationRoutingTests {
    private func rule(_ id: String, _ port: String = "work") -> VPNApplicationRoute {
        .init(id: id, name: "Example", signingIdentifier: "test.client",
              designatedRequirement: "(always) and anchor apple", port: port)
    }

    @Test func installedRulesMustMatchAndTemporarySelectionNeverWidensOnRestart() throws {
        let app = rule("client")
        let instance = rule("one-run", "finance")
        let capture = VPNApplicationCapture(routes: [instance, app], processRouteIDs: [instance.id])
        #expect(capture.isValid(memberIDs: ["finance", "work"]))
        let installed = capture.makeAppRules()
        #expect(installed.count == 1)
        #expect(capture.matchesInstalledRules(installed))
        #expect(!capture.matchesInstalledRules([]))
        let unrelated = NEAppRule(signingIdentifier: app.signingIdentifier, designatedRequirement: "anchor trusted")
        #expect(!capture.matchesInstalledRules([unrelated]))
        let perApp = NETunnelProviderManager.forPerAppVPN()
        perApp.appRules = installed
        #expect(perApp.routingMethod == .sourceApplication)
        #expect(capture.matchesInstalledRules(perApp.appRules))
        #expect(!capture.accepts(processTokens: [:]))
        let saved = try JSONDecoder().decode(VPNApplicationCapture.self, from: JSONEncoder().encode(capture))
        #expect(saved == capture)
        let current = Data([1]), replacement = Data([2])
        #expect(capture.candidates(token: current, signingIdentifier: app.signingIdentifier,
                                   processTokens: [instance.id: current]) == [instance])
        #expect(capture.candidates(token: replacement, signingIdentifier: app.signingIdentifier,
                                   processTokens: [instance.id: current]) == [app])
        #expect(capture.candidates(token: current, signingIdentifier: "another", processTokens: [instance.id: current]).isEmpty)
    }

    @Test func destinationsLowerToCanonicalPrefixesAndRejectAmbiguousNetworks() {
        var app = rule("client")
        app.destinations = [.init(prefix: "2001:0db8::1", port: "finance"), .init(prefix: "10.0.0.0/8", port: "work")]
        let members: Set<String> = ["work", "finance"]
        #expect(app.destinationProblem(memberIDs: members) == nil)
        let capture = VPNApplicationCapture(routes: [app], processRouteIDs: [])
        #expect(capture.sourceRules.first?.destinations?.map(\.prefix) == ["2001:db8::1/128", "10.0.0.0/8"])
        app.destinations?.append(.init(prefix: "2001:db8::1/128", port: "work"))
        #expect(app.destinationProblem(memberIDs: members) != nil)
        for prefix in ["10.0.0.1/24", "::ffff:192.0.2.1", "192.0.2.1\0extra", "/24"] {
            #expect(RoutePrefixMath.canonicalNetwork(prefix) == nil)
        }
    }

    @Test func sourceDefaultsAndOverridesShareThePacketRouterRuleLimit() {
        var app = rule("client")
        app.destinations = (0..<63).map { .init(prefix: "192.0.2.\($0)", port: "work") }
        var capture = VPNApplicationCapture(routes: Array(repeating: app, count: 64), processRouteIDs: [])
        #expect(capture.fitsRuleBudget)
        capture.routes[0].destinations?.append(.init(prefix: "192.0.2.63", port: "work"))
        #expect(!capture.fitsRuleBudget)
    }

    @Test func packetsFromOneInstanceShareVerificationAndPreserveOrder() async throws {
        let queue = DispatchQueue(label: "test.app-routing.admission")
        let app = rule("client")
        let narrow = rule("selected-process", "finance")
        var words = [UInt32](repeating: 0, count: 8)
        words[5] = 123
        words[7] = 7
        let token = words.withUnsafeBytes { Data($0) }
        words[7] = 8
        let reusedPID = words.withUnsafeBytes { Data($0) }
        let capture = VPNApplicationCapture(routes: [narrow, app], processRouteIDs: [narrow.id])
        let lookups = Mutex([String]())
        let output = Mutex([String]())
        let admission = ApplicationPacketAdmission(queue: queue, capture: capture, tokens: [narrow.id: token],
            resolve: { _, candidates in
                let selected = candidates.first?.id
                lookups.withLock { $0.append(selected ?? "?") }
                return selected
            }, forward: { packet, source, _ in
                output.withLock { $0.append("\(packet.first ?? 0) \(source ?? "drop")") }
            })
        queue.sync {
            admission.submit(Data([1]), token: token, signer: app.signingIdentifier, binary: Data())
            admission.submit(Data([2]), token: token, signer: app.signingIdentifier, binary: Data())
            admission.submit(Data([3]), token: nil, signer: app.signingIdentifier, binary: Data())
            admission.submit(Data([4]), token: reusedPID, signer: app.signingIdentifier, binary: Data())
        }
        let deadline = ContinuousClock.now + .seconds(3)
        while output.withLock({ $0.count }) < 4, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        queue.sync {
            admission.submit(Data([5]), token: token, signer: app.signingIdentifier, binary: Data())
            admission.stop()
            admission.submit(Data([6]), token: token, signer: app.signingIdentifier, binary: Data())
        }
        let packets = output.withLock { $0 }
        #expect(packets.filter { $0.hasSuffix("selected-process") } == ["1 selected-process", "2 selected-process", "5 selected-process"])
        #expect(packets.contains("3 drop") && packets.contains("4 client"))
        #expect(packets.count == 5)
        let queried = lookups.withLock { $0.sorted() }
        #expect(queried == ["client", "selected-process"])
    }

    @Test func negotiatedAppPortsRequireCurrentReaderAndMatchingResolverSettings() {
        let capture = VPNApplicationCapture(routes: [rule("client")], processRouteIDs: [])
        let policy = VirtualRoutingPolicy(sourceRules: capture.sourceRules, captureDefault: true)
        let ids = ["work", "other"]
        var config = VirtualRoutingConfig(version: 7, id: "apps", members: ids.map {
            .init(id: $0, openVPN: true, prefixes: [])
        }, policy: policy, applicationCapture: capture)
        #expect(config.problem != nil)
        config.version = 10
        #expect(config.problem == nil)
        let dns = ["work": ["10.0.0.53"], "other": ["10.0.0.53"]]
        let searches = ["work": ["lab.example"], "other": ["lab.example"]]
        #expect(config.applicationDNS(servers: dns, searches: searches)?.servers == dns["work"])
        #expect(config.applicationDNS(servers: dns, searches: ["work": ["private.example"]]) == nil)
        #expect(config.applicationDNS(servers: ["work": ["10.0.0.53"]], searches: searches) == nil)
    }

    @Test func sourceCaptureSurvivesGatewayChangesAndDoesNotExcludeCarrierAddressForSelectedApps() throws {
        let app = rule("client")
        let capture = VPNApplicationCapture(routes: [app], processRouteIDs: [])
        var wg = WireGuardConfig()
        wg.id = app.port
        wg.peerPublicKey = Data(repeating: 17, count: 32).base64EncodedString()
        wg.endpoint = "192.0.2.1:51820"
        wg.allowedIPs = ["10.0.0.0/8"]
        wg.addresses = ["10.0.0.2/32"]
        let policy = VirtualRoutingPolicy(sourceRules: capture.sourceRules, captureDefault: true)
        var config = VirtualRoutingConfig(version: 2, id: "example", members: [.init(id: app.port, wireGuard: wg, prefixes: wg.allowedIPs)],
                                          policy: policy, applicationCapture: capture)
        #expect(config.problem == nil)
        #expect(config.initialPolicy(gatewayOwned: false) == policy)
        #expect(config.withMemberRoutes(policy, prefixes: [:], dns: [:]) == policy)
        #expect(VirtualRouteApplyRequest(owner: "other", retainUnavailableDefault: false, routes: [:]).applying(to: policy) == policy)
        let settings = try #require(config.settings(policy: policy, endpoints: [wg.endpoint], dns: nil))
        #expect(settings.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask == "0.0.0.0")
        #expect(settings.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength == 0)
        let excludedRoutes = settings.ipv4Settings?.excludedRoutes ?? []
        #expect(excludedRoutes.isEmpty)
        config.applicationCapture?.routes[0].processCriteria = .init(executableName: "curl")
        #expect(config.problem != nil) // A v2 provider would otherwise ignore the constraint.
        config.version = 4
        #expect(config.problem == nil)
        config.applicationCapture?.routes[0].processCriteria = SourceProcessCriteria()
        #expect(config.problem != nil)
        config.applicationCapture = nil
        #expect(config.problem != nil)
    }
}

@MainActor
struct ApplicationLauncherRuleTests {
    private let terminal = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    private let curl = "/usr/bin/curl"

    @Test func terminalAndCurlRequireTheExactSignedNestedCapture() async throws {
        let signer = try await SourceIdentityService.signedApplication(at: URL(fileURLWithPath: curl))
        var route = VPNApplicationRoute(id: "cli", name: "curl", signingIdentifier: signer.signingIdentifier,
                                        designatedRequirement: signer.designatedRequirement, port: "work")
        route.processCriteria = .init(executableName: "curl", executablePath: curl, ancestorPath: terminal)
        let draft = VPNApplicationCapture(routes: [route], processRouteIDs: [])
        #expect(VirtualRoutingConfig.requiredVersion(capture: draft, eventSource: nil) == 5)
        #expect(!draft.hasPreparedLauncherRules)
        #expect(draft.makeAppRules().isEmpty)
        let capture = try await draft.preparingLauncherRules { try await SourceIdentityService.signedApplication(at: $0) }
        let rules = capture.makeAppRules()
        try #require(rules.count == 2)
        let direct = try #require(rules.first { $0.matchSigningIdentifier == "com.apple.curl" })
        let launcher = try #require(rules.first { $0.matchSigningIdentifier == "com.apple.Terminal" })
        let tool = try #require(launcher.matchTools?.first)
        #expect(launcher.matchPath == terminal && direct.matchPath == curl && tool.matchPath == curl)
        #expect(launcher.matchTools?.count == 1 && tool.matchTools == nil && direct.matchTools == nil)
        #expect(tool.matchSigningIdentifier == direct.matchSigningIdentifier)
        #expect(tool.matchDesignatedRequirement == direct.matchDesignatedRequirement)
        #expect(capture.matchesInstalledRules(rules))
        #expect(!draft.matchesInstalledRules(rules))
        let manager = NETunnelProviderManager.forPerAppVPN()
        manager.appRules = rules
        #expect(capture.matchesInstalledRules(manager.appRules))
        let archive = try NSKeyedArchiver.archivedData(withRootObject: rules, requiringSecureCoding: true)
        let decoded = try NSKeyedUnarchiver.unarchivedObject(ofClasses: [NSArray.self, NSString.self, NEAppRule.self], from: archive) as? [NEAppRule]
        #expect(capture.matchesInstalledRules(decoded))
        // A responsible-app-only token cannot satisfy the curl rule.
        #expect(capture.candidates(token: Data(), signingIdentifier: launcher.matchSigningIdentifier, processTokens: [:]).isEmpty)
        tool.matchPath = nil
        #expect(!capture.matchesInstalledRules(rules))
        tool.matchPath = curl
        tool.matchTools = []
        #expect(!capture.matchesInstalledRules(rules))
        tool.matchTools = nil
        launcher.matchTools = [tool, tool]
        #expect(!capture.matchesInstalledRules(rules))
        launcher.matchTools = []
        #expect(!capture.matchesInstalledRules(rules))
        launcher.matchTools = nil
        #expect(!capture.matchesInstalledRules(rules))
        #expect(!capture.matchesInstalledRules([direct]))
    }

    @Test func nonAppAncestorsKeepDirectCaptureAndInvalidBundlePathsCannotWidenIt() async throws {
        var route = VPNApplicationRoute(id: "cli", name: "curl", signingIdentifier: "com.apple.curl",
                                        designatedRequirement: "(identifier \"com.apple.curl\" and anchor apple) and anchor apple", port: "work")
        route.processCriteria = .init(executableName: "curl", ancestorPath: "/bin/zsh")
        var draft = VPNApplicationCapture(routes: [route], processRouteIDs: [])
        let bare = try await draft.preparingLauncherRules { _ in
            Issue.record("Non-app ancestors do not require a launcher identity lookup")
            throw CancellationError()
        }
        #expect(bare.launcherIdentities == nil && !bare.requiresLauncherRules)
        #expect(VirtualRoutingConfig.requiredVersion(capture: bare, eventSource: nil) == 4)
        let rules = bare.makeAppRules()
        #expect(rules.count == 1 && rules.first?.matchTools == nil && bare.matchesInstalledRules(rules))
        draft.routes[0].processCriteria?.ancestorPath = terminal + "-other"
        await #expect(throws: (any Error).self) {
            try await draft.preparingLauncherRules { _ in
                Issue.record("An unrelated file inside an app cannot identify the launcher")
                throw CancellationError()
            }
        }
        draft.routes[0].processCriteria = .init(executablePath: "/usr/bin/true", ancestorPath: terminal)
        await #expect(throws: (any Error).self) {
            try await draft.preparingLauncherRules { try await SourceIdentityService.signedApplication(at: $0) }
        }
    }
}
