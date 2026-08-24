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

    @Test("release entry points use the committed build counter")
    func releaseEntryPointsHaveNoSecondCounter() throws {
        let releaseBuild = try text("Tools/build-release-dmg.sh")
        let localBuild = try text("Tools/build-notarize-install.sh")
        let workflow = try text(".github/workflows/release.yml")

        #expect(releaseBuild.contains("$REPO/BUILDNUMBER"))
        #expect(!releaseBuild.contains("build/buildnumber.txt"))
        #expect(localBuild.contains("Tools/bump-build-number.sh"))
        #expect(workflow.contains("BUILDNUMBER ($CURRENT_PROJECT_VERSION) and project.yml"))
    }
}
