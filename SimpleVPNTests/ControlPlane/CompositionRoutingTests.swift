// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

struct CompositionRoutingTests {
    @Test @MainActor func oneMemberRoutedGroupStaysOutOfOlderClients() throws {
        let name = "SimpleVPN.OneRoutedMember." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let store = CompositionStore(defaults: defaults)
        let group = VPNComposition(name: "Only", members: [.init(profileID: "vpn", role: .split)], sharedInterface: true)
        store.save(group)
        #expect(group.usesSharedRouter)
        #expect(CompositionStore(defaults: defaults).compositions == [group])
        let legacy = try #require(defaults.data(forKey: "compositions.v1"))
        #expect(try JSONDecoder().decode([VPNComposition].self, from: legacy).isEmpty)
    }

    @Test func validDependenciesStartBeforeDependents() {
        let composition = VPNComposition(members: [.init(profileID: "child", dependsOn: "parent"),
                                                   .init(profileID: "parent")])
        #expect(composition.validationProblem == nil)
        #expect(composition.startOrder.map(\.profileID) == ["parent", "child"])
    }
    @Test func cyclesDuplicatesAndMissingDependenciesNeverProduceAStartOrder() {
        for members: [VPNComposition.Member] in [
            [.init(profileID: "a", dependsOn: "b"), .init(profileID: "b", dependsOn: "a")],
            [.init(profileID: "a", dependsOn: "a")],
            [.init(profileID: "a", dependsOn: "missing")],
            [.init(profileID: "a"), .init(profileID: "a")]
        ] {
            let composition = VPNComposition(members: members)
            #expect(composition.validationProblem != nil)
            #expect(composition.startOrder.isEmpty)
        }
    }
}

@MainActor
struct CompositionAppRoutingTests {
    private let app = VPNApplicationRoute(id: "app", name: "Mail", signingIdentifier: "test.mail",
                                          designatedRequirement: "(always) and anchor apple", port: "work")

    private var fixtureAuditToken: Data {
        // An isolated audit_token_t with positive PID and generation fields.
        let words: [UInt32] = [0, 0, 0, 0, 0, 123, 0, 7]
        return words.withUnsafeBytes { Data($0) }
    }

    @Test func processOnlyModeSurvivesSavingButTheSelectedInstanceDoesNot() throws {
        let only = VPNComposition(name: "Mail", members: [.init(profileID: "work")], applicationRoutes: [])
        let transient = VPNProcessRoute(route: app, auditToken: fixtureAuditToken)
        #expect(only.applicationRouteProblem(temporary: [transient]) == nil)
        let data = try JSONEncoder().encode(only)
        let restored = try JSONDecoder().decode(VPNComposition.self, from: data)
        #expect(restored.applicationRoutes == [])
        #expect(restored.applicationRouteProblem(temporary: []) != nil)
        #expect(!String(decoding: data, as: UTF8.self).contains("test.mail"))

        let old = try JSONDecoder().decode(VPNComposition.self,
            from: Data(#"{"id":"old","name":"Old","members":[]}"#.utf8))
        #expect(old.applicationRoutes == nil)
    }

    @Test func olderReleasesNeverSeeAnAppCompositionAsAWholeMacConnection() throws {
        let suite = "fixture.app-routing." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = CompositionStore(defaults: defaults)
        let ordinary = VPNComposition(id: "unchanged", name: "Original")
        var edited = VPNComposition(id: "changes", name: "Changes", members: [.init(profileID: "work")])
        store.save(ordinary)
        store.save(edited)
        func legacyIDs() throws -> [String] {
            struct Legacy: Decodable { var id: String }
            let data = try #require(defaults.data(forKey: "compositions.v1"))
            return try JSONDecoder().decode([Legacy].self, from: data).map(\.id)
        }

        edited.applicationRoutes = []
        store.save(edited)
        #expect(try legacyIDs() == [ordinary.id])
        let restored = CompositionStore(defaults: defaults)
        #expect(restored.compositions == [ordinary, edited])
        #expect(restored.compositions.last?.applicationRouteProblem(temporary: []) != nil)

        edited.applicationRoutes = [app]
        restored.save(edited)
        #expect(try legacyIDs() == [ordinary.id])
        #expect(CompositionStore(defaults: defaults).compositions == [ordinary, edited])

        edited.applicationRoutes = nil
        restored.save(edited)
        #expect(try legacyIDs() == [ordinary.id, edited.id])
        #expect(CompositionStore(defaults: defaults).compositions == [ordinary, edited])
        restored.remove(edited.id)
        #expect(CompositionStore(defaults: defaults).compositions == [ordinary])
    }

    @Test func eventProgramsNeverAppearInAnOlderClientsUnrestrictedStore() throws {
        let name = "SimpleVPN.event-store-test." + UUID().uuidString
        let prefs = try #require(UserDefaults(suiteName: name))
        defer { prefs.removePersistentDomain(forName: name) }
        let store = CompositionStore(defaults: prefs)
        var draft = VPNComposition(id: "lab", members: [.init(profileID: "work"), .init(profileID: "lab")])
        store.save(draft)
        draft.eventSource = "on handshake tcp.syn => count"
        store.save(draft)
        let unrestricted = try #require(prefs.data(forKey: "compositions.v1"))
        #expect(try JSONDecoder().decode([VPNComposition].self, from: unrestricted).isEmpty)
        #expect(CompositionStore(defaults: prefs).compositions == [draft])
        draft.eventSource = nil
        store.save(draft)
        #expect(CompositionStore(defaults: prefs).compositions == [draft])
    }

    @Test func persistentProcessConditionsStayNarrowAcrossStorageAndProviderVersions() throws {
        let prefsName = "SimpleVPN.process-store-test." + UUID().uuidString
        let prefs = try #require(UserDefaults(suiteName: prefsName))
        defer { prefs.removePersistentDomain(forName: prefsName) }
        let store = CompositionStore(defaults: prefs)
        let member = VPNComposition.Member(profileID: "work")
        var route = app
        var draft = VPNComposition(id: "curl-group", members: [member], applicationRoutes: [route])
        store.save(draft)
        route.processCriteria = .init(executableName: "curl", executablePath: "/usr/bin/curl")
        draft.applicationRoutes = [route]
        store.save(draft)

        func saved(_ key: String) throws -> [VPNComposition] {
            try JSONDecoder().decode([VPNComposition].self, from: #require(prefs.data(forKey: key)))
        }
        for key in ["compositions.v1", "compositions.events.v1", "compositions.app-routing.v1"] {
            #expect(try saved(key).isEmpty)
        }
        #expect(try saved("compositions.process-context.v1") == [draft])
        #expect(CompositionStore(defaults: prefs).compositions == [draft])
        let capture = VPNApplicationCapture(routes: [route], processRouteIDs: [])
        #expect(VirtualRoutingConfig.requiredVersion(capture: capture, eventSource: nil) == 4)
        #expect(VirtualRoutingConfig.requiredVersion(capture: capture, eventSource: "on mark tcp.syn => count") == 4)

        draft.eventSource = "on mark tcp.syn => count"
        store.save(draft)
        #expect(try saved("compositions.events.v1").isEmpty)
        route.processCriteria = nil
        draft.applicationRoutes = [route]
        store.save(draft)
        #expect(try saved("compositions.events.v1") == [draft])
        #expect(try saved("compositions.process-context.v1").isEmpty)
    }

    @Test func persistentConditionsRejectAmbiguousBranchesAndIncompleteDrafts() {
        var a = app
        a.processCriteria = .init(executableName: "curl", ancestorPath: "/bin/zsh", httpProxyEndpoint: "proxy.example:8080")
        var b = app
        b.id = "other"
        let composition = { (rules: [VPNApplicationRoute]) in
            VPNComposition(members: [.init(profileID: "work")], applicationRoutes: rules)
        }
        #expect(composition([a]).applicationRouteProblem(temporary: []) == nil)
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) != nil)
        b.processCriteria = .init(executableName: "curl", ancestorPath: "/bin/sh", httpProxyEndpoint: "http://PROXY.example:8080/")
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) != nil)
        b.processCriteria?.httpProxyEndpoint = "proxy.example:8081"
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) == nil)
        b.processCriteria?.httpProxyVariable = "http_proxy"
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) != nil)
        b.processCriteria = .init(executableName: "curl-debug")
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) == nil)
        a.processCriteria = .init(executablePath: "/opt/tools/curl")
        b.processCriteria = .init(executablePath: "/usr/bin/curl")
        #expect(composition([a, b]).applicationRouteProblem(temporary: []) == nil)
        let temporary = VPNProcessRoute(route: b, auditToken: fixtureAuditToken)
        #expect(composition([]).applicationRouteProblem(temporary: [temporary]) != nil)
        b.processCriteria = SourceProcessCriteria()
        #expect(composition([b]).applicationRouteProblem(temporary: []) != nil)
        #expect(!VPNApplicationCapture(routes: [b], processRouteIDs: []).isValid(memberIDs: ["work"]))
    }

    @Test func aDestinationOverrideMustResolveBeforeEitherKindOfRuleCanBeSaved() throws {
        var route = app
        route.destinations = [.init(prefix: "10.42.8.19", port: "finance")]
        var draft = VPNComposition(members: [.init(profileID: "work"), .init(profileID: "finance")], applicationRoutes: [route])
        #expect(draft.applicationRouteProblem(temporary: []) == nil)
        let encoded = try JSONEncoder().encode(draft)
        let restored = try JSONDecoder().decode(VPNComposition.self, from: encoded)
        #expect(restored.applicationRoutes?.first?.destinations == route.destinations)

        draft.members.removeLast()
        #expect(draft.applicationRouteProblem(temporary: [])?.contains(route.name) == true)
        draft.applicationRoutes = []
        #expect(draft.applicationRouteProblem(temporary: [.init(route: route, auditToken: fixtureAuditToken)])?.contains(route.name) == true)
        route.destinations = [.init(prefix: "", port: "work")]
        #expect(draft.applicationRouteProblem(temporary: [.init(route: route, auditToken: fixtureAuditToken)]) != nil)
    }

    @Test func selectedInstanceCanOverrideAnAppButCannotBeAssignedToTwoVPNs() {
        var instance = app
        instance.id = "process"
        instance.port = "lab"
        let temporary = VPNProcessRoute(route: instance, auditToken: fixtureAuditToken)
        var draft = VPNComposition(members: [.init(profileID: "work"), .init(profileID: "lab")], applicationRoutes: [app])
        #expect(draft.applicationRouteProblem(temporary: [temporary]) == nil)
        #expect(draft.applicationRouteProblem(temporary: [temporary, temporary]) != nil)
        draft.members.removeLast()
        #expect(draft.applicationRouteProblem(temporary: [temporary]) != nil)
    }
}
