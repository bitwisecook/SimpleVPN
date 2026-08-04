// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AboutView.swift
//  The About window: app identity + license, the open-source components SimpleVPN
//  bundles or links with their licenses, and a plain statement of how those
//  licenses fit together. Opened from SimpleVPN ▸ About SimpleVPN.
//

import SwiftUI
import AppKit

struct AboutComponent: Identifiable {
    let id = UUID()
    let name: String
    let license: String
    let role: String
    let url: String
}

enum Acknowledgements {
    /// Everything statically linked or bundled into the app / extension.
    static let components: [AboutComponent] = [
        .init(name: "OpenVPN 3 Core", license: "AGPL-3.0", role: "OpenVPN engine",
              url: "https://github.com/OpenVPN/openvpn3"),
        .init(name: "OpenConnect (libopenconnect)", license: "LGPL-2.1", role: "Fortinet / F5 / AnyConnect / GlobalProtect / Juniper / Pulse / Array engine",
              url: "https://www.infradead.org/openconnect/"),
        .init(name: "libssh2", license: "BSD-3-Clause", role: "SSH tunnel engine",
              url: "https://libssh2.org"),
        .init(name: "Tailscale", license: "BSD-3-Clause", role: "Tailscale / Headscale engine",
              url: "https://github.com/tailscale/tailscale"),
        .init(name: "wireguard-go", license: "MIT", role: "WireGuard data plane inside the Tailscale engine",
              url: "https://github.com/tailscale/wireguard-go"),
        .init(name: "gVisor", license: "Apache-2.0", role: "Userspace network stack inside the Tailscale engine",
              url: "https://gvisor.dev"),
        .init(name: "OpenSSL 3", license: "Apache-2.0", role: "TLS / crypto for all engines",
              url: "https://www.openssl.org"),
        .init(name: "Asio", license: "BSL-1.0", role: "OpenVPN async I/O",
              url: "https://think-async.com/Asio/"),
        .init(name: "{fmt}", license: "MIT", role: "OpenVPN formatting",
              url: "https://fmt.dev"),
        .init(name: "LZ4", license: "BSD-2-Clause", role: "OpenVPN compression",
              url: "https://lz4.org"),
        .init(name: "xxHash", license: "BSD-2-Clause", role: "OpenVPN hashing",
              url: "https://github.com/Cyan4973/xxHash"),
        .init(name: "libxml2", license: "MIT", role: "OpenConnect XML (system library)",
              url: "https://gitlab.gnome.org/GNOME/libxml2"),
        .init(name: "Natural Earth", license: "Public Domain", role: "World map coastlines",
              url: "https://www.naturalearthdata.com"),
        .init(name: "IP Geolocation by DB-IP", license: "CC BY 4.0", role: "Country-level endpoint locations (unmodified; used to derive country codes)",
              url: "https://creativecommons.org/licenses/by/4.0/"),
    ]

    /// Where the corresponding source (SimpleVPN's own code + these build scripts)
    /// is offered — required by GPLv3 §6 / AGPLv3 §13 / the LGPL relink clause for
    /// the statically-linked components.
    static let sourceURL = "https://github.com/bitwisecook/SimpleVPN"

    static let compatibilityNote = """
    SimpleVPN's own source is GPL-3.0. Because the distributed binary statically \
    links the OpenVPN 3 Core (AGPL-3.0), the application as a whole must be conveyed \
    under the AGPL-3.0 — including the AGPL's network-use source-availability \
    obligation — so the binary is distributed as AGPL-3.0. The corresponding source \
    (SimpleVPN's code and the engine build scripts) is available at the Source Code \
    link above, which also satisfies the LGPL-2.1 relink requirement for the \
    statically-linked OpenConnect. OpenConnect is LGPL-2.1 (GPL-compatible), OpenSSL \
    is Apache-2.0 (one-way compatible with GPLv3, no linking exception needed), and \
    DB-IP's data is CC BY 4.0 — used unmodified to derive country codes, attributed \
    here with a link to the licence. The Tailscale client stack (with wireguard-go \
    and gVisor, which it embeds) is statically linked into the network extension; \
    BSD-3-Clause, MIT and Apache-2.0 are all one-way compatible with GPLv3/AGPLv3, \
    so they impose no obligation beyond the attribution given above.
    """
}

/// The pre-filled GitHub issue. Everything that leaves the app is assembled HERE,
/// in one place, so the privacy promise is auditable at a glance: versions, the OS,
/// the CPU architecture, and a COUNT PER VPN TYPE. Never a VPN's name, server or
/// hostname, username, credentials, routes, or any other profile content.
enum IssueReport {
    struct Facts: Equatable {
        var appVersion: String
        var extensionVersion: String
        var osVersion: String
        var architecture: String
        /// Type name → how many are configured. Deliberately no per-VPN detail.
        var vpnTypeCounts: [String: Int]

        /// e.g. "OpenVPN ×2, SSH ×1" — types only, alphabetical for stability.
        var vpnTypeSummary: String {
            guard !vpnTypeCounts.isEmpty else { return "none configured" }
            return vpnTypeCounts.sorted { $0.key < $1.key }
                .map { "\($0.key) ×\($0.value)" }
                .joined(separator: ", ")
        }
    }

    static var architecture: String {
        #if arch(arm64)
        "arm64"
        #elseif arch(x86_64)
        "x86_64"
        #else
        "unknown"
        #endif
    }

    /// One attached fact. The UI renders these as a proper grid; the markdown below is
    /// generated from the same list, so what the user is shown and what GitHub receives
    /// cannot drift apart.
    struct Fact: Identifiable, Equatable {
        var label: String
        var value: String
        var id: String { label }
    }

    static func factRows(_ f: Facts) -> [Fact] {
        [Fact(label: "App", value: f.appVersion),
         Fact(label: "System extension", value: f.extensionVersion),
         Fact(label: "macOS", value: f.osVersion),
         Fact(label: "Architecture", value: f.architecture),
         Fact(label: "Configured VPN types", value: f.vpnTypeSummary)]
    }

    /// The `diagnostics` field of the GitHub issue forms (.github/ISSUE_TEMPLATE/*.yml).
    /// Versions + VPN type counts only.
    static func diagnosticsMarkdown(_ f: Facts) -> String {
        let rows = factRows(f).map { "| \($0.label) | \($0.value) |" }.joined(separator: "\n")
        return """
        | | |
        |---|---|
        \(rows)
        """
    }

    /// Percent-encode strictly (an allow-list), so newlines, `|`, and `+` in the
    /// markdown can't be misread by the query parser.
    private static func encode(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }

    /// Opens the GitHub issue FORM with the diagnostics field prefilled. Field names
    /// here must match the `id:`s in .github/ISSUE_TEMPLATE/bug_report.yml.
    /// A log is never prefilled — logs are far too long for a URL, so the sheet puts
    /// the (user-approved) text on the clipboard to paste into the bundle field.
    static func url(_ f: Facts, includingLogNote: Bool = false) -> URL? {
        var query = "template=bug_report.yml&diagnostics=\(encode(diagnosticsMarkdown(f)))"
        if includingLogNote {
            query += "&logs=\(encode("(paste the diagnostics bundle here — it's on your clipboard)"))"
        }
        return URL(string: "\(Acknowledgements.sourceURL)/issues/new?\(query)")
    }

    /// Assemble the facts from every backend — types only, never a name or address.
    /// Shared so the About window and the crash prompt report identically.
    @MainActor
    static func gather(vpn: VPNController?, tunnels: SubprocessTunnelStore?,
                       nativeVPN: NativeVPNManager?, wireguard: WireGuardStore?) -> Facts {
        var counts: [String: Int] = [:]
        for p in vpn?.profiles ?? [] { counts[p.kind.displayName, default: 0] += 1 }
        for t in tunnels?.tunnels ?? [] { counts[t.kind.displayName, default: 0] += 1 }
        for c in nativeVPN?.configs ?? [] { counts[c.kind.displayName, default: 0] += 1 }
        let wg = wireguard?.configs.count ?? 0
        if wg > 0 { counts["WireGuard", default: 0] += wg }
        return .init(appVersion: UI.appVersion,
                     extensionVersion: vpn?.extensionVersion ?? "unavailable",
                     osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
                     architecture: architecture,
                     vpnTypeCounts: counts)
    }

    /// Issues this user opened, resolved by GitHub for whoever is signed in — so the
    /// app never has to store or track issue numbers.
    static var myIssuesURL: URL? {
        URL(string: "\(Acknowledgements.sourceURL)/issues?q=\(encode("is:issue author:@me sort:updated-desc"))")
    }

    /// Light/dark, display scale and the accessibility settings that change layout —
    /// a UI bug report is much weaker without them.
    /// Structured so the sheet can render it; `appearanceSummary` is derived from it.
    @MainActor
    static var appearanceRows: [Fact] {
        let dark = NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        let scale = NSScreen.main?.backingScaleFactor ?? 1
        let ws = NSWorkspace.shared
        var a11y: [String] = []
        if ws.accessibilityDisplayShouldIncreaseContrast { a11y.append("Increase Contrast") }
        if ws.accessibilityDisplayShouldReduceMotion { a11y.append("Reduce Motion") }
        if ws.accessibilityDisplayShouldReduceTransparency { a11y.append("Reduce Transparency") }
        return [
            Fact(label: "Appearance",
                 value: "\(dark ? "Dark" : "Light"), \(String(format: "%gx", scale)) scale"),
            Fact(label: "Accessibility",
                 value: a11y.isEmpty
                     ? "none of Increase Contrast / Reduce Motion / Reduce Transparency"
                     : a11y.joined(separator: ", ")),
        ]
    }

    @MainActor
    static var appearanceSummary: String {
        appearanceRows.map { "\($0.label): \($0.value)" }.joined(separator: "\n")
    }

    /// The crash form, prefilled with diagnostics + a short crash summary. The full
    /// backtrace can't ride a URL, so CrashReportSheet puts it on the clipboard and the
    /// template asks for it to be pasted.
    @MainActor
    static func crashURL(_ f: Facts, summary: String) -> URL? {
        let query = "template=crash_report.yml"
            + "&diagnostics=\(encode(diagnosticsMarkdown(f)))"
            + "&summary=\(encode(summary))"
            + "&backtrace=\(encode("(paste the crash details here \u{2014} they're on your clipboard)"))"
        return URL(string: "\(Acknowledgements.sourceURL)/issues/new?\(query)")
    }

    /// The UI/appearance form, prefilled with diagnostics + appearance context.
    @MainActor
    static func uiIssueURL(_ f: Facts) -> URL? {
        let query = "template=ui_issue.yml"
            + "&diagnostics=\(encode(diagnosticsMarkdown(f)))"
            + "&appearance=\(encode(appearanceSummary))"
        return URL(string: "\(Acknowledgements.sourceURL)/issues/new?\(query)")
    }
}

/// Which report the user asked for, so a Help-menu item can open the About window
/// and have it present the right sheet (same pattern as SSOAuthModel).
@MainActor
@Observable
final class ReportRequest {
    static let shared = ReportRequest()
    enum Kind { case bug, ui }
    private(set) var kind: Kind?
    private(set) var generation = 0
    func request(_ k: Kind) { kind = k; generation += 1 }
    func clear() { kind = nil }
}

struct AboutView: View {
    @Environment(\.openURL) private var openURL
    // Optional environment: the About window shows what it's given and degrades
    // gracefully (extension version / VPN types omitted) if something isn't injected.
    @Environment(VPNController.self) private var vpn: VPNController?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @Environment(WireGuardStore.self) private var wireguard: WireGuardStore?
    @State private var showReport = false
    @State private var showUIReport = false
    @State private var capture = DiagnosticsCapture()
    @State private var report = ReportRequest.shared

    /// Count the configured VPNs by type across every backend — types only.
    private var facts: IssueReport.Facts {
        IssueReport.gather(vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN, wireguard: wireguard)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable().frame(width: 64, height: 64)
                        .accessibilityHidden(true)   // decorative; the title says the name
                    VStack(alignment: .leading, spacing: 2) {
                        // Name + version + copyright read as one identity block.
                        VStack(alignment: .leading, spacing: 2) {
                            Text("SimpleVPN").font(.largeTitle.bold())
                                .accessibilityAddTraits(.isHeader)
                            Text(UI.appVersion).foregroundStyle(.secondary)
                            Text("© 2026 James Deucker · AGPL-3.0")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                        HStack(spacing: 12) {
                            Link("Source Code", destination: URL(string: Acknowledgements.sourceURL)!)
                            // Opens GitHub's new-issue form pre-filled with versions
                            // and VPN *types* only (see IssueReport).
                            Button("Report an Issue…") { showReport = true }
                            .buttonStyle(.link)
                            .help("Opens a new GitHub issue pre-filled with your app, extension and macOS versions plus which VPN types you have configured — no names, addresses or credentials.")
                            // The privacy promise shouldn't be hover-only.
                            .accessibilityHint("Opens a new GitHub issue pre-filled with version numbers only — no names, addresses or credentials")
                        }
                        .font(.callout)
                    }
                    Spacer()
                }

                GroupBox("Open-Source Components") {
                    VStack(spacing: 0) {
                        ForEach(Acknowledgements.components) { c in
                            HStack(alignment: .firstTextBaseline) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Link(c.name, destination: URL(string: c.url)!)
                                        .font(.callout.weight(.medium))
                                    Text(c.role).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 12)
                                Text(c.license)
                                    .font(.caption.monospaced())
                                    .padding(.horizontal, 7).padding(.vertical, 2)
                                    .background(.quaternary, in: Capsule())
                            }
                            .padding(.vertical, 6)
                            // One sentence per component, not three fragments ×13
                            // rows; the element keeps the link's activation.
                            .accessibilityElement(children: .combine)
                            .accessibilityLabel("\(c.name), \(c.role), licence \(c.license)")
                            if c.id != Acknowledgements.components.last?.id { Divider() }
                        }
                    }
                    .padding(6)
                }

                GroupBox("License Compatibility") {
                    Text(Acknowledgements.compatibilityNote)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                }

                Text("Full license texts ship with each project at the source links above.")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 560, height: 620)
        .sheet(isPresented: $showReport) {
            IssueReportSheet(facts: facts, capture: configuredCapture)
        }
        .sheet(isPresented: $showUIReport) {
            UIIssueSheet(facts: facts)
        }
        // Help ▸ Report an Issue / Report a UI Issue open this window and ask for
        // the matching sheet.
        .onChange(of: report.generation) {
            switch report.kind {
            case .bug: showReport = true
            case .ui: showUIReport = true
            case nil: break
            }
            report.clear()
        }
    }

    /// The capture helper, told what to put in the header and what to redact.
    private var configuredCapture: DiagnosticsCapture {
        capture.header = [
            "App": facts.appVersion,
            "System extension": facts.extensionVersion,
            "macOS": facts.osVersion,
            "Architecture": facts.architecture,
            "Configured VPN types": facts.vpnTypeSummary,
        ]
        // Redact configured VPN usernames from scrubbed output as literal strings.
        capture.secrets = (tunnels?.tunnels ?? []).map(\.username).filter { !$0.isEmpty }
        return capture
    }
}
