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
    private(set) var problem: String?
    /// Bumped on each request so a window observer can open/raise the window.
    private(set) var generation = 0

    nonisolated static func accepts(_ url: URL) -> Bool {
        ["http", "https"].contains(url.scheme?.lowercased() ?? "")
            && !(url.host ?? "").isEmpty && url.user == nil && url.password == nil
    }

    func request(_ url: URL) {
        problem = Self.accepts(url) ? nil : "This sign-in link cannot be opened. Ask your VPN administrator for an HTTP or HTTPS sign-in address."
        pending = problem == nil ? url : nil
        generation += 1
    }
    func failed() { problem = "The sign-in page could not open. Check your connection and try again." }
    func retry() { problem = nil; generation += 1 }
    func finish() { pending = nil; problem = nil }
}

struct SSOAuthWindowView: View {
    @State private var model = SSOAuthModel.shared
    @Environment(\.dismiss) private var dismiss
    @State private var loading = true

    var body: some View {
        Group {
            if let url = model.pending {
                VStack(spacing: 0) {
                    if let problem = model.problem {
                        Label(problem, systemImage: "exclamationmark.triangle").padding()
                        Button("Try Again") { loading = true; model.retry() }
                    } else if loading {
                        ProgressView("Opening sign-in…").padding()
                    }
                    SSOWebView(url: url, onLoaded: { loading = false }, onFailure: {
                        loading = false
                        model.failed()
                        AccessibilityAnnouncer.sayNow("The sign-in page could not open. Check your connection and try again.")
                    }) {
                        model.finish()
                        dismiss()
                    }
                    .id(model.generation)
                }
            } else if let problem = model.problem {
                ContentUnavailableView("Sign-in Link Unavailable", systemImage: "exclamationmark.triangle",
                                       description: Text(problem))
            } else {
                ContentUnavailableView("No sign-in in progress",
                    systemImage: "person.badge.key",
                    description: Text("This window opens automatically when a VPN needs you to sign in."))
            }
        }
        .frame(minWidth: 460, minHeight: 560)
        .task(id: model.generation) {
            guard model.pending != nil, model.problem == nil else { return }
            loading = true
            do { try await Task.sleep(for: .seconds(20)) } catch { return }
            guard loading else { return }
            loading = false
            model.failed()
            AccessibilityAnnouncer.sayNow("The sign-in page is taking longer than expected. Try again or close this window.")
        }
        .navigationTitle("VPN Sign-In")
        .toolbar { ToolbarItem(placement: .cancellationAction) {
            Button("Close Sign-In") { model.finish(); dismiss() }
                .keyboardShortcut(.cancelAction)
                .help("Closes this sign-in window. Use the connection controls in SimpleVPN to cancel the VPN connection.")
        } }
        .onDisappear { model.finish() }
    }
}

/// A minimal WKWebView that loads the SSO URL and reports when it reaches the
/// loopback redirect OpenConnect is listening on (sign-in complete).
private struct SSOWebView: NSViewRepresentable {
    let url: URL
    let onLoaded: () -> Void
    let onFailure: () -> Void
    let onComplete: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onLoaded: onLoaded, onFailure: onFailure, onComplete: onComplete)
    }

    func makeNSView(context: Context) -> WKWebView {
        let web = WKWebView(frame: .zero)
        web.navigationDelegate = context.coordinator
        web.load(URLRequest(url: url))
        return web
    }

    func updateNSView(_ web: WKWebView, context: Context) {
        context.coordinator.onComplete = onComplete
        context.coordinator.onLoaded = onLoaded
        context.coordinator.onFailure = onFailure
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var onLoaded: () -> Void
        var onFailure: () -> Void
        var onComplete: () -> Void
        private var completed = false
        init(onLoaded: @escaping () -> Void, onFailure: @escaping () -> Void, onComplete: @escaping () -> Void) {
            self.onLoaded = onLoaded; self.onFailure = onFailure; self.onComplete = onComplete
        }

        private func isLoopback(_ url: URL?) -> Bool {
            guard let host = url?.host else { return false }
            return host == "127.0.0.1" || host == "localhost" || host == "::1"
        }

        // Let the loopback request go through (OpenConnect's listener must receive
        // it), then close the window a beat later.
        func webView(_ web: WKWebView, didFinish nav: WKNavigation!) {
            onLoaded()
            guard !completed, isLoopback(web.url) else { return }
            completed = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [onComplete] in onComplete() }
        }

        func webView(_ web: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            if (error as NSError).code != NSURLErrorCancelled { onFailure() }
        }

        func webView(_ web: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            if (error as NSError).code != NSURLErrorCancelled { onFailure() }
        }

        func webViewWebContentProcessDidTerminate(_ web: WKWebView) { onFailure() }
    }
}
