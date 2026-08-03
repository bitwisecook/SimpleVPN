// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  BrowserLauncher.swift
//  Detects installed browsers and their profiles, and opens a URL in a chosen
//  browser+profile — for SAML/SSO sign-in and for the app's own links. Everything
//  here runs in the APP (user context): the system extension runs as root and
//  cannot launch a GUI browser, so SSO that needs a browser uses the user-context
//  subprocess path (see SubprocessTunnelManager) and this launcher.
//
//  Chromium picks a profile with `--profile-directory=<dir>`, Firefox with
//  `-P <name>`, Safari has no CLI-selectable profile. We shell out to `/usr/bin/
//  open` (arg-array, no shell) — the documented, reliable way to pass browser args.
//

import Foundation
import AppKit

enum BrowserFamily: String, Codable, Sendable { case safari, chromium, firefox, other }

struct InstalledBrowser: Identifiable, Hashable, Sendable {
    var id: String { bundleID }
    let bundleID: String
    let name: String
    let family: BrowserFamily
    /// Path under ~/Library/Application Support that holds this browser's profiles.
    let appSupport: String?
}

struct BrowserProfile: Identifiable, Hashable, Sendable {
    let id: String     // Chromium dir ("Default"/"Profile 1") or Firefox profile name
    let name: String   // human label
}

enum BrowserCatalog {
    /// Browsers we know how to drive (profile args). Presence is checked at runtime.
    static let known: [InstalledBrowser] = [
        .init(bundleID: "com.apple.Safari",          name: "Safari",   family: .safari,   appSupport: nil),
        .init(bundleID: "com.google.Chrome",         name: "Chrome",   family: .chromium, appSupport: "Google/Chrome"),
        .init(bundleID: "com.google.Chrome.canary",  name: "Chrome Canary", family: .chromium, appSupport: "Google/Chrome Canary"),
        .init(bundleID: "com.microsoft.edgemac",     name: "Microsoft Edge", family: .chromium, appSupport: "Microsoft Edge"),
        .init(bundleID: "com.brave.Browser",         name: "Brave",    family: .chromium, appSupport: "BraveSoftware/Brave-Browser"),
        .init(bundleID: "com.vivaldi.Vivaldi",       name: "Vivaldi",  family: .chromium, appSupport: "Vivaldi"),
        .init(bundleID: "org.chromium.Chromium",     name: "Chromium", family: .chromium, appSupport: "Chromium"),
        .init(bundleID: "com.operasoftware.Opera",   name: "Opera",    family: .chromium, appSupport: "com.operasoftware.Opera"),
        .init(bundleID: "company.thebrowser.Browser", name: "Arc",     family: .chromium, appSupport: "Arc/User Data"),
        .init(bundleID: "org.mozilla.firefox",       name: "Firefox",  family: .firefox,  appSupport: "Firefox"),
    ]

    /// Installed subset, in the catalog's order.
    static var installed: [InstalledBrowser] {
        known.filter { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0.bundleID) != nil }
    }

    static func browser(_ bundleID: String?) -> InstalledBrowser? {
        guard let bundleID else { return nil }
        return known.first { $0.bundleID == bundleID }
    }

    static let inAppName = "SimpleVPN window (in-app)"

    /// Short human label for a selection ("System Default", "Chrome", "Chrome · Work").
    static func label(_ sel: BrowserSelection) -> String {
        if sel.isInApp { return inAppName }
        guard let b = browser(sel.bundleID) else { return osDefaultName }
        guard let p = sel.profile, !p.isEmpty else { return b.name }
        let profileName = profiles(for: b).first { $0.id == p }?.name ?? p
        return "\(b.name) · \(profileName)"
    }

    /// The name of the OS default browser (for the "System Default" picker label).
    static var osDefaultName: String {
        guard let http = URL(string: "https://apple.com"),
              let appURL = NSWorkspace.shared.urlForApplication(toOpen: http) else { return "System Default" }
        let name = FileManager.default.displayName(atPath: appURL.path)
        return name.replacingOccurrences(of: ".app", with: "")
    }

    // MARK: Profiles

    static func profiles(for b: InstalledBrowser) -> [BrowserProfile] {
        guard let sub = b.appSupport else { return [] }
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support").appendingPathComponent(sub)
        switch b.family {
        case .chromium: return chromiumProfiles(base: base)
        case .firefox:  return firefoxProfiles(base: base)
        default:        return []
        }
    }

    private static func chromiumProfiles(base: URL) -> [BrowserProfile] {
        // "Local State" holds profile.info_cache: { "<dir>": { "name": "<label>" } }.
        let localState = base.appendingPathComponent("Local State")
        if let data = try? Data(contentsOf: localState),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let profile = obj["profile"] as? [String: Any],
           let cache = profile["info_cache"] as? [String: Any] {
            let list = cache.compactMap { (dir, v) -> BrowserProfile? in
                let name = (v as? [String: Any])?["name"] as? String ?? dir
                return BrowserProfile(id: dir, name: name)
            }
            if !list.isEmpty {
                // "Default" first, then the rest alphabetically for stability.
                return list.sorted { ($0.id == "Default" ? "" : $0.name.lowercased())
                    < ($1.id == "Default" ? "" : $1.name.lowercased()) }
            }
        }
        // Fallback: scan for Default / "Profile N" directories.
        let dirs = (try? FileManager.default.contentsOfDirectory(atPath: base.path)) ?? []
        return dirs.filter { $0 == "Default" || $0.hasPrefix("Profile ") }
            .sorted().map { BrowserProfile(id: $0, name: $0) }
    }

    private static func firefoxProfiles(base: URL) -> [BrowserProfile] {
        // Parse profiles.ini: [ProfileN] Name=… Path=… (Name is what -P expects).
        guard let text = try? String(contentsOf: base.appendingPathComponent("profiles.ini"), encoding: .utf8) else { return [] }
        var out: [BrowserProfile] = []
        var current: String?
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("["), line.hasSuffix("]") { current = String(line.dropFirst().dropLast()); continue }
            if current?.hasPrefix("Profile") == true, line.hasPrefix("Name=") {
                let name = String(line.dropFirst("Name=".count))
                if !name.isEmpty { out.append(BrowserProfile(id: name, name: name)) }
            }
        }
        return out
    }

    // MARK: Launch

    /// Open `url` in the selected browser/profile (or the OS default when unset).
    static func open(_ url: URL, using sel: BrowserSelection) {
        if sel.isInApp { Task { @MainActor in SSOAuthModel.shared.request(url) }; return }
        guard let b = browser(sel.bundleID) else { NSWorkspace.shared.open(url); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = openArguments(for: b, profile: sel.profile, url: url.absoluteString)
        try? p.run()
    }

    /// `open` argv for a browser+profile+URL (arg array — no shell interpolation).
    static func openArguments(for b: InstalledBrowser, profile: String?, url: String) -> [String] {
        switch b.family {
        case .chromium:
            var a = ["-b", b.bundleID, "--args"]
            if let profile, !profile.isEmpty { a.append("--profile-directory=\(profile)") }
            a.append(url)
            return a
        case .firefox:
            var a = ["-b", b.bundleID, "--args"]
            if let profile, !profile.isEmpty { a += ["-P", profile] }
            a += ["-url", url]
            return a
        default:   // Safari / other — no profile selection
            return ["-b", b.bundleID, url]
        }
    }

    /// A tiny launcher script for OpenConnect's `--external-browser` (which runs
    /// `CMD <url>`), so SSO opens in the chosen browser+profile. Returns nil for the
    /// OS default (let OpenConnect open the default browser itself).
    static func externalBrowserScript(for sel: BrowserSelection, id: String) -> String? {
        if sel.isInApp { return inAppBrowserScript(id: id) }
        guard let b = browser(sel.bundleID) else { return nil }
        // Build the `open` argv with a sentinel for the URL, then emit a shell line
        // where the sentinel becomes "$1" and every other token is single-quoted.
        let sentinel = "\u{1}URL\u{1}"
        let line = openArguments(for: b, profile: sel.profile, url: sentinel).map { tok in
            tok == sentinel ? "\"$1\"" : "'" + tok.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
        return writeScript("#!/bin/sh\nexec /usr/bin/open \(line)\n", id: id)
    }

    /// Launcher that hands the sign-in URL to the app's in-app WKWebView window via
    /// the simplevpn-sso:// scheme (base64url, so +/ =-quoting can't corrupt it).
    private static func inAppBrowserScript(id: String) -> String? {
        let body = """
        #!/bin/sh
        u=$(printf '%s' "$1" | /usr/bin/base64 | /usr/bin/tr '+/' '-_' | /usr/bin/tr -d '=\\n')
        exec /usr/bin/open "simplevpn-sso://auth?u=$u"
        """
        return writeScript(body + "\n", id: id)
    }

    private static func writeScript(_ body: String, id: String) -> String? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("svpn-browser-\(id).sh")
        do {
            try Data(body.utf8).write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        } catch { return nil }
        return url.path
    }
}

/// The app-wide default browser for SSO / links, and per-VPN resolution.
enum BrowserDefaults {
    private static let key = "app.browser.default.v1"

    static var appDefault: BrowserSelection {
        get {
            // Default to the in-app sign-in window (no external browser, no profile
            // fuss, and it just works out of the box). The user can change it.
            guard let d = UserDefaults.standard.data(forKey: key),
                  let s = try? JSONDecoder().decode(BrowserSelection.self, from: d) else { return .inApp }
            return s
        }
        set { UserDefaults.standard.set(try? JSONEncoder().encode(newValue), forKey: key) }
    }

    /// Per-VPN wins; otherwise the app default; otherwise the OS default.
    static func resolve(_ perVPN: BrowserSelection) -> BrowserSelection {
        perVPN.isOSDefault ? appDefault : perVPN
    }
}
