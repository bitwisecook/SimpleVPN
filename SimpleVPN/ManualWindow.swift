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
            let escaped = anchor.replacingOccurrences(of: "'", with: "")
            webView.evaluateJavaScript("location.hash = ''; location.hash = '#\(escaped)';")
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
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
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
