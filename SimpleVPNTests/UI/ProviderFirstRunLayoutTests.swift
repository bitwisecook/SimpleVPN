// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

/// The provider page is deliberately a guided scroll view, not a pile of cards
/// with unrelated widths and a buried importer. These checks protect the flow's
/// structural invariants that a screenshot of one viewport cannot cover.
struct ProviderFirstRunLayoutTests {
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    @Test func providerSetupUsesOneWidthAndPlacesInputAtItsStep() throws {
        let source = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Connection/ProviderFirstRunView.swift"), encoding: .utf8)
        #expect(source.contains("static let contentWidth: CGFloat = 760"))
        #expect(source.contains("ConfigurationDropTarget(isTargeted: isDropTargeted, maximumWidth: nil)"))
        #expect(source.contains("setupStep(number: 2, step: steps[1])"))
        #expect(source.contains("waitingStep(number: 3, step: steps[2])"))
        #expect(source.contains("waitingStep(number: 4, step: steps[3])"))
    }

    @Test func providerSetupOffersAnAccessibleScrollCue() throws {
        let source = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Connection/ProviderFirstRunView.swift"), encoding: .utf8)
        #expect(source.contains(".safeAreaInset(edge: .bottom"))
        #expect(source.contains("Continue to import configuration"))
        #expect(source.contains("proxy.scrollTo(Anchor.importConfiguration"))
        #expect(source.contains("if reduceMotion"))
        #expect(source.contains("accessibilityHint(\"Scrolls directly"))
    }
}
