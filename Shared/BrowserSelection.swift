// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  BrowserSelection.swift
//  Which browser (and profile) to use when a VPN's sign-in needs one (SAML/SSO)
//  — and the app's own default for opening links. `nil` bundleID means "the OS
//  default browser"; `nil` profile means that browser's default profile.
//  Codable so it can live in a VPN's config and in app preferences.
//

import Foundation

// `nonisolated`: this value type is referenced from nonisolated shared code
// (TailscaleConfig's `signInBrowser` default is `.osDefault`), and the app target
// defaults to MainActor isolation — which would otherwise pin these statics to the
// main actor and make them unusable from a nonisolated context.
nonisolated struct BrowserSelection: Codable, Sendable, Equatable {
    /// Application bundle id (e.g. "com.google.Chrome"); nil ⇒ OS default browser.
    var bundleID: String? = nil
    /// Browser-specific profile key: Chromium `--profile-directory` dir (e.g.
    /// "Profile 1"), or a Firefox profile name. nil ⇒ the browser's default profile.
    var profile: String? = nil

    /// The OS default browser / profile.
    static let osDefault = BrowserSelection()
    var isOSDefault: Bool { bundleID == nil }

    /// Sentinel bundle id meaning "SimpleVPN's own in-app WKWebView window".
    static let inAppBundleID = "com.bragi0.SimpleVPN.inapp"
    static let inApp = BrowserSelection(bundleID: inAppBundleID)
    var isInApp: Bool { bundleID == BrowserSelection.inAppBundleID }
}
