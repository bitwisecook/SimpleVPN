// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

/// Utility panels must have a useful opening size without becoming fixed-size
/// dialogs.  The latter is especially painful for long imported-setting diffs and
/// filtered server lists, where widening the sheet is the normal Mac action.
@MainActor
struct PanelLayoutTests {
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    @Test func panelSizingIsAnIdealWithAUsableMinimum() {
        let view = Text("A utility panel")
            .resizablePanel(idealWidth: 460, idealHeight: 340)
        let size = NSHostingController(rootView: view).sizeThatFits(in: .zero)

        #expect(size.width >= PanelMetrics.minimumWidth)
        #expect(size.height >= PanelMetrics.minimumHeight)
    }

    @Test func standardUtilitySurfacesUseTheSharedResizablePanel() throws {
        let paths = [
            "SimpleVPN/UI/Settings/SettingsView.swift",
            "SimpleVPN/UI/Editors/GlobalSettingsSearchView.swift",
            "SimpleVPN/UI/Editors/CompositionEditor.swift",
            "SimpleVPN/UI/Map/EndpointRegionPicker.swift",
            "SimpleVPN/UI/Components/AddServersFromProviderSheet.swift",
            "SimpleVPN/UI/Components/AddServersFromFilesSheet.swift",
            "SimpleVPN/UI/Components/ProviderListUpdateSheet.swift",
            "SimpleVPN/UI/Settings/ExportImportSettings.swift",
            "SimpleVPN/UI/Settings/AboutView.swift",
        ]

        for path in paths {
            let source = try String(contentsOf: Self.repoRoot.appendingPathComponent(path), encoding: .utf8)
            #expect(source.contains(".resizablePanel("),
                    "\(path) locks a utility surface to one fixed size instead of using the shared panel contract")
        }
    }

    /// The connection window is a split view.  Letting the scene continually
    /// recompute its minimum from SwiftUI content while AppKit is tracking its
    /// divider can invalidate constraints in the display cycle and abort the
    /// process.  A first-launch default size is sufficient; macOS preserves the
    /// person's later size and placement for the stable `main` scene identity.
    @Test func mainWindowUsesDefaultSizeWithoutContentDrivenResizability() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/App/SimpleVPNApp.swift"),
            encoding: .utf8
        )
        guard let start = source.range(of: "WindowGroup(\"SimpleVPN\", id: \"main\")"),
              let end = source.range(
                of: "Window(\"About SimpleVPN\"",
                range: start.upperBound..<source.endIndex
              ) else {
            Issue.record("Could not isolate the main-window scene")
            return
        }

        let mainScene = String(source[start.lowerBound..<end.lowerBound])
        #expect(mainScene.contains(".defaultSize(width: 1_160, height: 900)"))
        #expect(!mainScene.contains(".windowResizability(.contentMinSize)"))
    }

    @Test func mainContentCannotShowOnboardingBeforeProfilesFinishLoading() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Connection/ConnectionView.swift"),
            encoding: .utf8
        )
        #expect(source.contains("if !hasCompletedInitialConfigurationLoad"))
        #expect(source.contains("InitialConfigurationLoadingView()"))
        #expect(source.contains("} else {\n            // The extension's state"))
    }

    /// The globe is hosted inside a scrollable split-view detail.  Its renderer
    /// must not request an AppKit redraw synchronously from SwiftUI's layout
    /// update; doing so has caused an NSWindow update-constraints loop while a
    /// person drags a live-details divider.
    @Test func metalGlobeUsesDisplayLinkRatherThanLayoutTimeRedraw() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Map/MetalGlobeView.swift"),
            encoding: .utf8
        )
        guard let start = source.range(of: "private struct MetalGlobeSurface"),
              let end = source.range(of: "private final class GlobeMetalView", range: start.upperBound..<source.endIndex) else {
            Issue.record("Could not isolate MetalGlobeSurface")
            return
        }

        let surface = String(source[start.lowerBound..<end.lowerBound])
        #expect(surface.contains("view.enableSetNeedsDisplay = false"))
        #expect(surface.contains("view.isPaused = false"))
        #expect(surface.contains("LiveVisualCadence.globeFramesPerSecond(lowPower: lowPowerMode)"))
        #expect(!surface.contains("setNeedsDisplay("))
        #expect(source.contains("override var intrinsicContentSize: NSSize"))
    }
}
