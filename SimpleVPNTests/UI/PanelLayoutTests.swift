// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import ImageIO
import SwiftUI
import Testing
import WebKit
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

// Exercise the shipped HTML in WebKit, rather than only checking CSS strings.

@MainActor
@Suite(.serialized)
struct ManualResponsiveLayoutTests {
    @Test(arguments: [CGSize(width: 1180, height: 720), CGSize(width: 760, height: 640),
                      CGSize(width: 430, height: 600), CGSize(width: 320, height: 260),
                      CGSize(width: 760, height: 300)])
    func helpReflowsWithoutHorizontalPageOverflow(_ size: CGSize) async throws {
        let fixture = ManualWebFixture(size: size)
        defer { fixture.window.close() }
        try await fixture.load()
        let state = try await fixture.web.evaluateJavaScript("""
            (() => {
              const n = document.getElementById('help-contents');
              return { width: innerWidth, overflow: document.documentElement.scrollWidth > innerWidth + 1,
                       position: getComputedStyle(n).position, open: n.dataset.open };
            })()
            """) as? [String: Any]
        let values = try #require(state)
        #expect(values["overflow"] as? Bool == false)
        #expect(values["position"] as? String == (size.width > 900 ? "sticky" : "fixed"))
        #expect(values["open"] as? String == (size.width <= 900 ? "false" : "true"))
    }

    @Test(arguments: [360.0, 760.0])
    func compactContentsSupportsApproachKeyboardEscapeAndReadingLinks(_ width: Double) async throws {
        let fixture = ManualWebFixture(size: CGSize(width: width, height: 520))
        defer { fixture.window.close() }
        try await fixture.load()
        let outcome = try await fixture.web.evaluateJavaScript("""
            (() => {
              const nav = document.getElementById('help-contents');
              const button = document.getElementById('contents-toggle');
              const list = document.getElementById('contents-list');
              const initiallyClosed = nav.dataset.open === 'false' && list.inert;
              const r = nav.getBoundingClientRect();
              document.dispatchEvent(new PointerEvent('pointermove', {clientX: r.left + 4, clientY: r.bottom + 16, pointerType: 'mouse'}));
              const approached = nav.dataset.open === 'true' && !list.inert;
              nav.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}));
              const escaped = nav.dataset.open === 'false';
              button.click();
              const clicked = button.getAttribute('aria-expanded') === 'true';
              list.querySelector('a').click();
              const reading = nav.dataset.open === 'false' && list.inert;
              return initiallyClosed && approached && escaped && clicked && reading;
            })()
            """) as? Bool
        #expect(outcome == true)
    }

    @Test func compactContentsAutomaticallyRetreatsAfterThePointerLeaves() async throws {
        let fixture = ManualWebFixture(size: CGSize(width: 360, height: 520))
        defer { fixture.window.close() }
        try await fixture.load()
        _ = try await fixture.web.evaluateJavaScript("""
            const nav = document.getElementById('help-contents');
            nav.dispatchEvent(new PointerEvent('pointerenter', {pointerType: 'mouse'}));
            nav.dispatchEvent(new PointerEvent('pointerleave', {pointerType: 'mouse'}));
            """)
        try await Task.sleep(for: .milliseconds(500))
        let closed = try await fixture.web.evaluateJavaScript("document.getElementById('help-contents').dataset.open === 'false'") as? Bool
        #expect(closed == true)
    }

    @Test func restoredHelpFramesFitOffsetAndSmallerDisplays() {
        for visible in [CGRect(x: 0, y: 40, width: 800, height: 560),
                        CGRect(x: -1920, y: 80, width: 1920, height: 1000)] {
            let fitted = MainWindowSizingPolicy.fittedFrame(frameSize: CGSize(width: 2200, height: 1400),
                currentFrame: CGRect(x: 1600, y: -400, width: 2200, height: 1400), visibleFrame: visible)
            #expect(visible.contains(fitted))
        }
    }
}

@MainActor
private final class ManualWebFixture: NSObject, WKNavigationDelegate {
    let web: WKWebView
    let window: NSWindow
    private var completion: CheckedContinuation<Void, Error>?
    private var timeout: Task<Void, Never>?

    init(size: CGSize) {
        web = WKWebView(frame: CGRect(origin: .zero, size: size))
        window = NSWindow(contentRect: CGRect(origin: .zero, size: size),
                          styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = web
        super.init()
        web.navigationDelegate = self
    }

    func load() async throws {
        let url = try #require(Bundle.main.url(forResource: "manual", withExtension: "html"))
        try await withCheckedThrowingContinuation { continuation in
            completion = continuation
            web.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
            timeout = Task { @MainActor [weak self] in
                do { try await Task.sleep(for: .seconds(10)) } catch { return }
                self?.finish(NSError(domain: "ManualWebFixture", code: 1,
                                     userInfo: [NSLocalizedDescriptionKey: "The bundled manual did not finish loading."]))
            }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { finish(nil) }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { finish(error) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { finish(error) }
    private func finish(_ error: Error?) {
        guard let completion else { return }
        self.completion = nil
        timeout?.cancel()
        if let error { completion.resume(throwing: error) } else { completion.resume() }
    }
}
