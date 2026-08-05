// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ManualWindow.swift
//  The bundled manual, rendered in a WKWebView: long-form anchored rich text with
//  find-on-page and zero rendering cost to the settings UI. Content lives in
//  Resources/Manual/manual.html (self-contained, dark/light via CSS variables).
//  Every "Learn more" button deep-links here via ManualRouter (one shared window,
//  navigated by anchor).
//

import SwiftUI
import WebKit

/// Deep-link state: navigating scrolls the (single) manual window. The
/// generation counter makes re-clicking the same link re-scroll.
@Observable
final class ManualRouter {
    private(set) var anchor: String?
    private(set) var generation = 0

    func navigate(to anchor: String) {
        self.anchor = anchor
        generation += 1
    }
}

/// How the manual window moves to an anchor. Its own type because the OBVIOUS
/// implementation is wrong in a way that only shows up on the SECOND click.
///
/// It used to be `location.hash = ''; location.hash = '#anchor'` — the empty
/// assignment there to make a repeat of the same link re-trigger. Clearing the
/// fragment scrolls the document to the TOP, and WebKit coalesces both assignments
/// from one synchronous script, so the re-set produced no second scroll: the first
/// click landed on the entry and every click after it landed at the top of the
/// manual. Scrolling the ELEMENT instead is
///
///  • idempotent — the same anchor twice scrolls twice, with no clear-then-set trick,
///  • centred, matching what a settings reveal does (Components/SettingReveal.swift),
///    so the app's two "take me to that" navigations behave alike,
///  • and free of history entries: fragment navigation pushes onto the web view's
///    back/forward list and `scrollIntoView` does not, which matters now that the
///    editors have a back button of their own.
nonisolated enum ManualScroll {
    /// JSON-encoded rather than hand-escaped: these are our own catalog ids, but
    /// approximate escaping inside an `evaluateJavaScript` string is not worth
    /// keeping around to be copied.
    static func script(anchor: String) -> String {
        let id = (try? JSONEncoder().encode(anchor))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "\"\""
        return """
            (function () {
              var el = document.getElementById(\(id));
              if (el) { el.scrollIntoView({ block: 'center' }); }
            })();
            """
    }
}

struct ManualWindow: View {
    @Environment(ManualRouter.self) private var router

    var body: some View {
        if let url = Bundle.main.url(forResource: "manual", withExtension: "html") {
            ManualWebView(url: url, anchor: router.anchor, generation: router.generation)
                .navigationTitle("SimpleVPN Help")
                .ignoresSafeArea(edges: .bottom)
        } else {
            ContentUnavailableView("Manual Missing", systemImage: "book.closed",
                                   description: Text("The bundled manual could not be found."))
        }
    }
}

private struct ManualWebView: NSViewRepresentable {
    let url: URL
    let anchor: String?
    let generation: Int

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.allowsMagnification = true
        webView.underPageBackgroundColor = .windowBackgroundColor
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        context.coordinator.pendingAnchor = anchor
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        guard let anchor, context.coordinator.shownGeneration != generation else { return }
        if context.coordinator.loaded {
            context.coordinator.shownGeneration = generation
            context.coordinator.scroll(webView, to: anchor)
        } else {
            context.coordinator.pendingAnchor = anchor
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var loaded = false
        var pendingAnchor: String?
        var shownGeneration = 0

        func scroll(_ webView: WKWebView, to anchor: String) {
            webView.evaluateJavaScript(ManualScroll.script(anchor: anchor))
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            loaded = true
            if let anchor = pendingAnchor {
                pendingAnchor = nil
                scroll(webView, to: anchor)
            }
        }

        // Keep navigation inside the bundle; external links open in the browser.
        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url else { decisionHandler(.allow); return }
            if url.isFileURL {
                decisionHandler(.allow)
            } else {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
            }
        }
    }
}
