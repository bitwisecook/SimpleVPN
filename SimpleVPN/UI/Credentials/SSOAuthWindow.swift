// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSOAuthWindow.swift
//  An in-app WKWebView window for SAML/SSO sign-in — the "SimpleVPN window"
//  browser choice. OpenConnect (user-context subprocess) runs a local listener and
//  finishes SSO when the identity provider redirects to http://127.0.0.1:<port>/…;
//  the external-browser launcher hands us the sign-in URL (via the simplevpn-sso://
//  URL scheme), we load it here, the user authenticates, and when the webview
//  follows the redirect to localhost — which OpenConnect catches — we close.
//  No token handoff is needed: OpenConnect's own listener captures the result.
//
//  NOTE: the localhost-redirect completion needs validating against a live SAML
//  gateway; the plumbing is standard but the exact success URL varies by IdP.
//

import SwiftUI
import WebKit

extension Data {
    /// Decode base64url (as emitted by the in-app launcher script).
    init?(base64URLEncoded s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b.append("=") }
        self.init(base64Encoded: b)
    }
}

/// Shared bridge between the URL-scheme handler (AppDelegate) and the window.
@MainActor
@Observable
final class SSOAuthModel {
    static let shared = SSOAuthModel()
    private(set) var pending: URL?
    /// Bumped on each request so a window observer can open/raise the window.
    private(set) var generation = 0

    func request(_ url: URL) { pending = url; generation += 1 }
    func finish() { pending = nil }
}

struct SSOAuthWindowView: View {
    @State private var model = SSOAuthModel.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let url = model.pending {
                SSOWebView(url: url) {
                    model.finish()
                    dismiss()
                }
                .id(url)   // reload cleanly if a new sign-in arrives
            } else {
                ContentUnavailableView("No sign-in in progress",
                    systemImage: "person.badge.key",
                    description: Text("This window opens automatically when a VPN needs you to sign in."))
            }
        }
        .frame(minWidth: 460, minHeight: 560)
        .navigationTitle("VPN Sign-In")
    }
}

/// A minimal WKWebView that loads the SSO URL and reports when it reaches the
/// loopback redirect OpenConnect is listening on (sign-in complete).
private struct SSOWebView: NSViewRepresentable {
    let url: URL
    let onComplete: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onComplete: onComplete) }

    func makeNSView(context: Context) -> WKWebView {
        let web = WKWebView(frame: .zero)
        web.navigationDelegate = context.coordinator
        web.load(URLRequest(url: url))
        return web
    }

    func updateNSView(_ web: WKWebView, context: Context) {
        context.coordinator.onComplete = onComplete
        if web.url == nil { web.load(URLRequest(url: url)) }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var onComplete: () -> Void
        private var completed = false
        init(onComplete: @escaping () -> Void) { self.onComplete = onComplete }

        private func isLoopback(_ url: URL?) -> Bool {
            guard let host = url?.host else { return false }
            return host == "127.0.0.1" || host == "localhost" || host == "::1"
        }

        // Let the loopback request go through (OpenConnect's listener must receive
        // it), then close the window a beat later.
        func webView(_ web: WKWebView, didFinish nav: WKNavigation!) {
            guard !completed, isLoopback(web.url) else { return }
            completed = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [onComplete] in onComplete() }
        }
    }
}
