// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import ImageIO
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

    /// Main-window sizing is a small number of explicit structural suggestions,
    /// never SwiftUI's continuous content-size negotiation. A manual live resize
    /// permanently hands sizing back to macOS and the person.
    @Test func mainWindowUsesOptOutAdaptiveSizing() throws {
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
        #expect(mainScene.contains(".defaultSize(width: 900, height: 660)"))
        #expect(!mainScene.contains(".windowResizability(.contentMinSize)"))

        let connection = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Connection/ConnectionView.swift"),
            encoding: .utf8
        )
        let sizing = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Components/MainWindowSizing.swift"),
            encoding: .utf8
        )
        #expect(connection.contains(".adaptiveMainWindowSizing(windowLayoutMode)"))
        #expect(sizing.contains("NSWindow.didEndLiveResizeNotification"))
        #expect(sizing.contains("ui.mainWindow.manualSizing"))
        #expect(sizing.contains("willStartLiveResizeNotification"))
        #expect(sizing.contains("guard liveResizeWasStarted else { return }"),
                "an unmatched end-resize notification must not disable automatic sizing")
        #expect(sizing.contains("screen.visibleFrame"))
        #expect(sizing.contains("DispatchQueue.main.async"),
                "Window frame changes must leave SwiftUI's update/layout pass before crossing into AppKit")
        #expect(sizing.contains("window.isVisible"),
                "Automatic sizing must wait for a real, visible window")
        #expect(sizing.contains("suggestedFrameSize"),
                "Scene defaults and adaptive sizes use the same outer-window geometry")

        guard let updateStart = sizing.range(of: "func updateNSView"),
              let coordinatorStart = sizing.range(
                of: "final class Coordinator",
                range: updateStart.upperBound..<sizing.endIndex
              ) else {
            Issue.record("Could not isolate MainWindowSizingBridge.updateNSView")
            return
        }
        let updateMethod = sizing[updateStart.lowerBound..<coordinatorStart.lowerBound]
        #expect(!updateMethod.contains("setFrame("),
                "Calling NSWindow.setFrame during updateNSView re-enters AppKit constraint layout and crashes")
    }

    @Test func automaticMainWindowFramesStayInsideVisibleScreen() {
        let screen = CGRect(x: 0, y: 80, width: 1_440, height: 780)
        let current = CGRect(x: 1_000, y: 100, width: 700, height: 500)
        let fitted = MainWindowSizingPolicy.fittedFrame(
            frameSize: CGSize(width: 1_200, height: 900),
            currentFrame: current,
            visibleFrame: screen
        )
        let safe = screen.insetBy(dx: MainWindowSizingPolicy.screenInset,
                                  dy: MainWindowSizingPolicy.screenInset)
        #expect(safe.contains(fitted))
        #expect(fitted.width == 1_200)
        #expect(fitted.height == safe.height)
    }

    @Test func endpointGlobeLivesOnlyInTrailingInspector() throws {
        let shell = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Connection/ConnectionView.swift"),
            encoding: .utf8
        )
        let inspector = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Connection/ConnectionInspectorView.swift"),
            encoding: .utf8
        )
        let detail = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Connection/ConnectionDetailView.swift"),
            encoding: .utf8
        )
        #expect(!shell.contains("presentation: .globe"))
        #expect(shell.contains(".navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 440)"))
        #expect(inspector.contains("EndpointSection(vpn: vpn, profile: profile, presentation: .globe)"))
        #expect(detail.contains("EndpointSection(vpn: vpn, profile: profile)"))
        #expect(!detail.contains("presentation: .globe"))
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

    /// The connection screen contains native external-drop destinations. An
    /// embedded MTKView used to prevent those nested SwiftUI targets negotiating
    /// a 1Password drag, which forced the compact globe onto a flat fallback.
    /// Stitchable shape shaders retain both textures without an AppKit view or a
    /// layout-time display-link callback.
    @Test func texturedGlobeUsesSwiftUIShadersWithoutAnEmbeddedAppKitView() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Map/MetalGlobeView.swift"),
            encoding: .utf8
        )
        let shader = try String(
            contentsOf: Self.repoRoot.appendingPathComponent("SimpleVPN/UI/Map/MetalGlobeShaders.metal"),
            encoding: .utf8
        )
        #expect(!source.contains("NSViewRepresentable"))
        #expect(!source.contains("MTKView"))
        #expect(source.contains("ShaderLibrary.globeDay"))
        #expect(source.contains("blue-marble-2004-5400"))
        #expect(source.contains("ShaderLibrary.globeNightLights"))
        #expect(source.contains("black-marble-2016-01deg"))
        #expect(shader.contains("[[ stitchable ]] half4 globeDay"))
        #expect(shader.contains("outerAtmosphere"))
        #expect(shader.contains("[[ stitchable ]] half4 globeNightLights"))
        #expect(shader.contains("right * disk.x - up * disk.y + forward * depth"))
        #expect(!shader.contains("right * disk.x + up * disk.y + forward * depth"))
    }

    @Test func globeShadersCompileAsSwiftUIShapeStyles() async throws {
        let dayImage = try shaderImage(named: "blue-marble-2004-5400")
        let nightImage = try shaderImage(named: "black-marble-2016-01deg")
        let day = ShaderLibrary.globeDay(
            .boundingRect,
            .float3(1, 0, 0), .float3(0, 1, 0), .float3(0, 0, 1),
            .float3(1, 0, 0),
            .image(dayImage)
        )
        let night = ShaderLibrary.globeNightLights(
            .boundingRect,
            .float3(1, 0, 0), .float3(0, 1, 0), .float3(0, 0, 1),
            .float3(1, 0, 0),
            .image(nightImage)
        )

        try await day.compile(as: .shapeStyle)
        try await night.compile(as: .shapeStyle)
    }

    private func shaderImage(named name: String) throws -> Image {
        let url = try #require(Bundle.main.url(forResource: name, withExtension: "jpg"))
        let source = try #require(CGImageSourceCreateWithURL(url as CFURL, nil))
        let image = try #require(CGImageSourceCreateImageAtIndex(source, 0, nil))
        return Image(decorative: image, scale: 1)
    }
}
