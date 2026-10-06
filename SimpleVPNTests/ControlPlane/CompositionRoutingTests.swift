// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Testing
@testable import SimpleVPN

struct CompositionRoutingTests {
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
