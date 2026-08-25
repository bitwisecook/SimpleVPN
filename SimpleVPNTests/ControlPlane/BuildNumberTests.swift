// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing

@testable import SimpleVPN

struct BuildNumberTests {
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private func text(_ relativePath: String) throws -> String {
        try String(contentsOf: Self.repoRoot.appendingPathComponent(relativePath), encoding: .utf8)
    }

    @Test("Xcode's default build number matches the committed release counter")
    func xcodeDefaultMatchesCommittedBuildNumber() throws {
        let buildNumber = try #require(Int(text("BUILDNUMBER").trimmingCharacters(in: .whitespacesAndNewlines)))
        let project = try text("project.yml")
        let match = try #require(project.firstMatch(of: /CURRENT_PROJECT_VERSION:\s*"([0-9]+)"/))
        let projectBuildNumber = try #require(Int(match.output.1))
        #expect(projectBuildNumber == buildNumber)
    }

    @Test("every Xcode app build allocates and stamps one monotonic number")
    func xcodeBuildGraphOwnsBuildNumberAllocation() throws {
        let project = try text("project.yml")

        #expect(project.contains("BuildNumber:"))
        #expect(project.contains("legacy:"))
        #expect(project.contains("Tools/bump-build-number.sh"))
        #expect(project.contains("- target: BuildNumber"))
        #expect(project.components(separatedBy: "name: Apply monotonic build number").count - 1 == 2,
                "the app and its system extension must stamp the same allocated number")
        #expect(project.components(separatedBy: "Set :CFBundleVersion ${BUILD_NUMBER}").count - 1 == 2)
        #expect(project.components(separatedBy: "$(TARGET_BUILD_DIR)/$(INFOPLIST_PATH)").count - 1 == 2,
                "each phase must depend on Xcode's processed plist so it runs afterwards")
        #expect(project.components(separatedBy: "ENABLE_USER_SCRIPT_SANDBOXING: NO").count - 1 == 2,
                "Xcode otherwise makes the generated plist input read-only")
    }

    @Test("distribution entry points read the number Xcode actually produced")
    func releaseEntryPointsHaveNoSecondCounter() throws {
        let releaseBuild = try text("Tools/build-release-dmg.sh")
        let localBuild = try text("Tools/build-notarize-install.sh")
        let workflow = try text(".github/workflows/release.yml")

        #expect(releaseBuild.contains("Print :CFBundleVersion"))
        #expect(!releaseBuild.contains("build/buildnumber.txt"))
        #expect(!releaseBuild.contains("Tools/bump-build-number.sh"),
                "the Xcode dependency—not a wrapper—must allocate the number")
        #expect(localBuild.contains("Print :CFBundleVersion"))
        #expect(!localBuild.contains("Tools/bump-build-number.sh"))
        #expect(workflow.contains("BUILT_BUILD="))
        #expect(workflow.contains("buildno=$BUILT_BUILD"))
    }
}
