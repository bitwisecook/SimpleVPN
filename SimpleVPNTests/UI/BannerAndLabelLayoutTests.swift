// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// BannerAndLabelLayoutTests.swift
//  Compact UI must remain compact when SwiftUI asks it to measure before it has
//  assigned a real split-view column width.

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct BannerAndLabelLayoutTests {

    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private func size<V: View>(_ view: V, in proposal: CGSize) -> CGSize {
        NSHostingController(rootView: view).sizeThatFits(in: proposal)
    }

    @Test("every standard banner lets support copy be selected")
    func bannerSurfaceEnablesTextSelection() throws {
        let surface = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Components/BannerSurface.swift"), encoding: .utf8)
        #expect(surface.contains(".textSelection(.enabled)"))
    }

    @Test func aStandardBannerHasASaneMinimumSize() {
        let view = Text(String(repeating: "A deliberately long explanatory sentence. ", count: 10))
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
            .bannerSurface(tint: .orange)
        let squeezed = size(view, in: .zero)

        #expect(squeezed.width >= BannerMetrics.minimumReadableWidth)
        #expect(squeezed.height < 420,
                "a zero-width split-pane measurement must not turn banner copy into a vertical wall")
    }

    @Test func aLongLabelIsBounded() {
        let longName = String(repeating: "A very long label ", count: 20)
        let label = LabelDef(name: longName, r: 0.2, g: 0.4, b: 0.8)
        let rendered = size(LabelPill(label: label),
                            in: CGSize(width: CGFloat.greatestFiniteMagnitude,
                                       height: CGFloat.greatestFiniteMagnitude))

        // Text gets at most 92pt; the padding is 14pt. A little room is allowed
        // for the platform's capsule layout, but the label can never take a row.
        #expect(rendered.width <= LabelPillMetrics.maximumTextWidth + 20)
    }

    @Test func touchIDProtectionStaysInTheCredentialControls() throws {
        let detail = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Connection/ConnectionDetailView.swift"), encoding: .utf8)
        let chooser = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Credentials/SignInSourceChooser.swift"), encoding: .utf8)

        #expect(!detail.contains("Sign-in protected by Touch ID"))
        #expect(!detail.contains("protectedForm"))
        #expect(detail.contains("if neverConnected"))
        #expect(detail.contains("SavedCredentialField(label: \"Username\""))
        #expect(detail.contains("SavedCredentialField(label: \"Password\""))
        #expect(detail.contains("localizedReason: \"Reveal the saved sign-in"))
        #expect(detail.contains("Text(value ?? \"••••••••\")"))
        #expect(detail.contains("Image(systemName: revealed ? \"eye.slash\" : \"eye\")"))
        #expect(detail.contains("Toggle(\"Protect them with Touch ID\""))
        #expect(detail.contains(".disabled(isProtected)"))
        #expect(chooser.contains("arrowEdge: .trailing"))
        #expect(chooser.contains("static let maximumHeight: CGFloat = 520"))
        #expect(chooser.contains("ScrollView"))
        #expect(chooser.contains("compact: true"))
    }

    @Test func supportDetailsHaveOnePointerAndKeyboardReachableControl() throws {
        let sheet = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Components/UserFacingErrorSheet.swift"), encoding: .utf8)

        #expect(sheet.contains("Button {\n                showDetail.toggle()"))
        #expect(sheet.contains(".contentShape(Rectangle())"))
        #expect(!sheet.contains("DisclosureGroup(\"Details for support\""))
    }

    @Test func aLabelRunShowsABoundedPrefixAndAnOverflowCount() {
        let labels = (0..<6).map {
            LabelDef(name: "An intentionally long label \($0)", r: 0.2, g: 0.4, b: 0.8)
        }
        let rendered = size(LabelPills(labels: labels),
                            in: CGSize(width: CGFloat.greatestFiniteMagnitude,
                                       height: CGFloat.greatestFiniteMagnitude))

        #expect(rendered.width <= 260,
                "two shortened labels and +4 must fit a compact connection row")
    }

    /// The old first-run picker put each provider's full instructions in its row.
    /// Four vertically fixed paragraphs then became the main window's minimum
    /// height, and resizing could grow the window beyond the display. The first page
    /// is now a four-column row of glass name tiles; the prose lives in a
    /// scrollable second page.
    @Test func firstRunProviderChoicesHaveABoundedHeight() {
        let picker = ProviderPickerSection(
            title: ProviderPickerCopy.firstRunSectionTitle,
            detail: ProviderPickerCopy.firstRunDetail,
            showsDetails: false,
            allowsBlockedSelection: true,
            action: { _ in })
            .frame(width: 460)
        let rendered = size(picker, in: CGSize(width: 460, height: 300))

        #expect(rendered.height < 240,
                "provider instructions belong on the second page, not in four tall first-page rows")
        #expect(ProviderPickerMetrics.firstRunColumnCount == 4)
        #expect(ProviderPickerMetrics.firstRunTileSide == 72,
                "a first-run vendor tile should remain approximately 2.5 cm square")
    }

    @Test func configurationDropTargetStaysAUsableMacHitRegion() {
        let rendered = size(ConfigurationDropTarget(isTargeted: false).frame(width: 420),
                            in: CGSize(width: 420, height: 240))

        #expect(rendered.width == 420)
        #expect(rendered.height >= 72,
                "the Finder drop target must remain comfortably larger than a standard control")
        #expect(rendered.height < 220,
                "the drop target must not force a setup page beyond a small Mac display")
    }
}
