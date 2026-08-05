// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SearchableSetting.swift
//  The one shape every setting in the app presents to the things that ADDRESS
//  settings rather than render them: search, the related-settings links, the
//  manual, and (already) the CLI and MDM.
//
//  Two concrete types carry setting metadata — `SettingDescriptor` (the OpenVPN
//  registry, which also owns availability rules and reset closures) and
//  `EngineSettingSpec` (every other engine's catalog). They were never going to
//  merge: the OpenVPN one is keypath-bound to one config struct. But everything
//  that only wants "id, name, summary, group, anchor, relations" had to pick
//  one, which is why SettingsSearch was hard-coded to OpenVPN and existed in
//  exactly one editor. This protocol is that shared vocabulary, and
//  `SettingSurface` below is the registry that makes it app-wide.
//

import Foundation

/// What search, the help popover and the router need from a setting. Deliberately
/// read-only metadata: nothing here can change a value, so any catalog can
/// conform without exposing its bindings.
///
/// `@MainActor` because both conforming types are (the module's default
/// isolation), and everything that reads a setting's metadata is a view or a view
/// model. Leaving the protocol nonisolated makes both conformances "cross into
/// main actor-isolated code" — the exact error, not a theoretical one.
@MainActor
protocol SearchableSetting: Identifiable {
    var id: String { get }
    var name: String { get }
    var summary: String { get }
    /// The canonical taxonomy group (AGENTS.md "Config surfaces"). Optional
    /// because `EngineSettingSpec` allows it to be; every shipped spec declares
    /// one and ManualAnchorParityTests holds them to it.
    var canonicalGroup: SettingGroup? { get }
    /// Manual deep-link anchor — the id with dots→dashes.
    var manualAnchor: String { get }
    /// Ids of settings a reader of this one needs to know about
    /// (SettingRelations). Symmetric by construction.
    var related: [String] { get }
}

extension SettingDescriptor: @MainActor SearchableSetting {
    var canonicalGroup: SettingGroup? { group }
}

extension EngineSettingSpec: @MainActor SearchableSetting {
    var canonicalGroup: SettingGroup? { group }
}

// MARK: - The app-wide registry

/// One config SURFACE: a namespace of setting ids, the editor that renders them,
/// and the VPN kinds that editor serves. Keyed by namespace rather than by
/// `VPNKind` because seven of the fifteen kinds share one editor and one
/// catalog (the OpenConnect SSL VPNs) — listing `oc.mtu` seven times in a global
/// result list would be seven ways to reach the same row.
///
/// Adding an engine means adding a case here. That is what makes the global
/// search, the related-settings links and the `SettingsRoute` intent total: a
/// catalog nobody registered is a catalog search can't find.
@MainActor
enum SettingSurface: String, CaseIterable, Identifiable {
    case openVPN, wireGuard, tailscale, proxyTunnel, native, ssh, sshNetworkTunnel, openConnect,
         customRouting, securityKey
    /// The one surface that is NOT a VPN editor: which password apps SimpleVPN may
    /// use and where their tools are (Settings ▸ Sign-In Sources). It belongs here
    /// anyway — being registered is what makes app-wide search, the manual anchors
    /// and the MDM/CLI addressing total. See `isAppLevel`, which is what keeps
    /// Manage VPNs from trying to find "a Sign-In Sources VPN".
    case credentialSources
    /// The second app-level surface: whether SimpleVPN looks for virtual machines
    /// and containers on this Mac, and whether it warns before a VPN cuts their
    /// networks off (Settings ▸ General ▸ Privacy). Not any VPN's editor, so it
    /// belongs to no kind — see `isAppLevel`.
    case virtualization

    nonisolated var id: String { rawValue }

    /// True for a surface that lives in the app's own Settings window rather than
    /// in a VPN's editor. Routing, "which VPN does this belong to" and the
    /// related-links reachability test all branch on this rather than on the case.
    nonisolated var isAppLevel: Bool { self == .credentialSources || self == .virtualization }

    /// The id prefix every setting on this surface carries (the CLI/MDM contract).
    nonisolated var namespace: String {
        switch self {
        case .openVPN: "openvpn."
        case .wireGuard: "wg."
        case .tailscale: "ts."
        case .proxyTunnel: "px."
        case .native: "native."
        case .ssh: "ssh."
        // A namespace of its own, NOT a reuse of "ssh.": ids are global and bound
        // 1:1 to a surface and a manual anchor, so one id cannot mean two things.
        case .sshNetworkTunnel: "sshnet."
        case .openConnect: "oc."
        case .customRouting: "cr."
        // Security keys (YubiKey and similar) supplying a verification code. Its own
        // namespace because ids are global and bound 1:1 to a surface: these rows
        // are per-VPN Sign-In settings that no engine owns.
        case .securityKey: "yk."
        case .credentialSources: "creds."
        case .virtualization: "vm."
        }
    }

    /// What a global search result calls this surface. Kind display names where
    /// one kind owns the surface; the shared editor's own subject where several do.
    nonisolated var title: String {
        switch self {
        case .openVPN: "OpenVPN"
        case .wireGuard: "WireGuard"
        case .tailscale: "Tailscale / Headscale"
        case .proxyTunnel: "Proxy Tunnel"
        case .native: "IKEv2 / IPsec / L2TP"
        case .ssh: "SSH"
        case .sshNetworkTunnel: "SSH Network Tunnel"
        case .openConnect: "SSL VPN (AnyConnect, FortiGate, GlobalProtect…)"
        case .customRouting: "Custom Routing"
        case .securityKey: "Security Key"
        case .credentialSources: "Sign-In Sources"
        case .virtualization: "Virtual Machines & Containers"
        }
    }

    /// Which VPN kinds' editors show this surface. Custom Routing is every kind's
    /// second tab, so it answers with all of them.
    nonisolated var kinds: [VPNKind] {
        switch self {
        case .openVPN: [.openVPN]
        case .wireGuard: [.wireGuard]
        case .tailscale: [.tailscale]
        case .proxyTunnel: [.proxyTunnel]
        case .native: [.ikev2, .ipsec, .l2tp]
        case .ssh: [.ssh]
        case .sshNetworkTunnel: [.sshNetworkTunnel]
        case .openConnect: [.fortinet, .f5apm, .ciscoAnyConnect, .globalProtect,
                            .juniper, .pulse, .arrayNetworks]
        case .customRouting: VPNKind.allCases
        // WHOSE EDITOR SHOWS THE ROWS — which is the question this property asks,
        // and the answer today is the OpenVPN editor alone: `YubiKeySignInSection`
        // is rendered by `EditVPNView`'s Sign-In tab and by nothing else.
        //
        // It listed all eleven kinds whose sign-in can ASK for a verification code,
        // which is a true sentence about the feature and the wrong answer to this
        // question — and it broke exactly the two things this property feeds. A
        // related link to a `yk.` row was offered inside the SSL-VPN and native
        // editors, where there is no such row: `SettingsRouter` produced a route,
        // Manage VPNs kept the current selection because the kind "qualified", and
        // no editor claimed it — a link that did nothing. And a global hit could
        // land on a FortiGate VPN for the same reason.
        //
        // The day `YubiKeySignInSection` appears in SubprocessTunnelView or
        // NativeVPNView, add those kinds back here AND `.securityKey` to that
        // editor's `SettingsSearch`/`settingsEditor` surfaces — the two halves are
        // one change, and the routing only works with both.
        case .securityKey: [.openVPN]
        // App-level: it is not any VPN's editor, so it belongs to no kind. An
        // empty list (rather than "all kinds") is what stops a global hit from
        // being routed into a VPN editor that has no such row.
        case .credentialSources: []
        // App-level, same reasoning: a guest network is a fact about this Mac, not
        // about any one VPN, so no kind's editor shows these rows.
        case .virtualization: []
        }
    }

    /// Which editor tab holds it. The OpenVPN engine options are the "Options"
    /// tab of a seven-tab editor; the other five editors put their canonical
    /// groups on "Settings"; Custom Routing is its own tab everywhere.
    nonisolated var tab: SettingsTab {
        switch self {
        case .openVPN: .options
        case .customRouting: .customRouting
        // The rows live in the OpenVPN editor's Sign-In tab, and in the canonical
        // Sign-In group of every other editor's single Settings tab.
        case .securityKey: .signIn
        case .credentialSources: .signInSources
        // The app's own Settings window, General tab (the Privacy group). There is
        // no `SettingsTab` case of its own because `SettingsView.pane(for:)` sends
        // everything that is not Sign-In Sources to the General pane, which is
        // where these rows live.
        case .virtualization: .general
        default: .settings
        }
    }

    var settings: [any SearchableSetting] {
        switch self {
        case .openVPN: OpenVPNSettings.all
        case .wireGuard: WireGuardSettings.all
        case .tailscale: TailscaleSettings.all
        case .proxyTunnel: ProxyTunnelSettings.all
        case .native: NativeVPNSettings.all
        case .ssh: SSHSettings.all
        case .sshNetworkTunnel: SSHNetSettings.all
        case .openConnect: OpenConnectSettings.all
        case .customRouting: CustomRoutingSettings.all
        case .securityKey: YubiKeySettings.all
        case .credentialSources: CredentialSourceSettings.all
        case .virtualization: VirtualizationSettings.all
        }
    }

    /// The surface an id belongs to, from its namespace alone.
    ///
    /// LONGEST prefix wins, and that is load-bearing rather than tidy: "sshnet."
    /// also starts with "ssh.", so a first-match walk resolved every SSH Network
    /// Tunnel id to the SSH surface — sending its help buttons and every
    /// `SettingsRoute` to the wrong editor, with nothing to see but a tab that
    /// didn't contain the setting.
    static func owning(_ settingID: String) -> SettingSurface? {
        allCases
            .filter { settingID.hasPrefix($0.namespace) }
            .max { $0.namespace.count < $1.namespace.count }
    }
}

/// One setting plus where it lives — what a global (all-surfaces) search returns
/// and what a route is built from.
@MainActor
struct GlobalSetting: Identifiable {
    let surface: SettingSurface
    let setting: any SearchableSetting
    var id: String { setting.id }

    /// "Tailscale ▸ Traffic ▸ Use Shared Networks" — the whole address of a
    /// setting in one line, so a global hit says which editor it will open.
    var breadcrumb: String {
        [surface.title, setting.canonicalGroup?.title, setting.name]
            .compactMap { $0 }.joined(separator: " \u{25B8} ")
    }
    /// The same, spoken — VoiceOver reads "▸" as nothing useful.
    var spokenBreadcrumb: String {
        [surface.title, setting.canonicalGroup?.title, setting.name]
            .compactMap { $0 }.joined(separator: ", ")
    }
}

/// Every setting the app exposes, addressable by id and by kind. The one place
/// that can answer "what is `wg.dns`, which editor shows it, and what else is it
/// related to" without knowing which catalog it came from.
@MainActor
enum AllSettings {

    /// Every setting on every surface, in surface order.
    static let everything: [GlobalSetting] = SettingSurface.allCases.flatMap { surface in
        surface.settings.map { GlobalSetting(surface: surface, setting: $0) }
    }

    static let byID: [String: GlobalSetting] =
        Dictionary(everything.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })

    /// Every setting a VPN of this kind's editor can show — its own surface plus
    /// Custom Routing, which every kind has. The registry the task's "a global hit
    /// can read 'Tailscale ▸ Traffic ▸ …' and route correctly" is built on.
    static let byKind: [VPNKind: [GlobalSetting]] = {
        var out: [VPNKind: [GlobalSetting]] = [:]
        for entry in everything {
            for kind in entry.surface.kinds { out[kind, default: []].append(entry) }
        }
        return out
    }()

    static func setting(_ id: String) -> (any SearchableSetting)? { byID[id]?.setting }

    /// Whether a VPN of this kind has a row for this setting — the test the help
    /// popover applies before offering a related link. A relation from
    /// `cr.route-rule` names every engine's routing control at once; only the one
    /// belonging to the VPN in front of the user is a link they can follow.
    static func isReachable(_ id: String, from kind: VPNKind?) -> Bool {
        guard let entry = byID[id] else { return false }
        guard let kind else { return true }        // no kind in context: show them all
        return entry.surface.kinds.contains(kind)
    }

    /// This kind's OWN first Traffic setting — the destination for the Custom
    /// Routing tab's link back to the group it rewrites. Derived rather than
    /// hard-coded per editor, so a kind whose Traffic group changes shape keeps
    /// a working link (and a kind with no Traffic settings simply has none).
    static func firstTrafficSetting(for kind: VPNKind?) -> GlobalSetting? {
        guard let kind else { return nil }
        return byKind[kind]?.first {
            $0.surface != .customRouting && $0.setting.canonicalGroup == .traffic
        }
    }

    /// The related settings of `id` that a VPN of this kind can actually reach.
    static func related(of id: String, kind: VPNKind?) -> [GlobalSetting] {
        (setting(id)?.related ?? [])
            .filter { isReachable($0, from: kind) }
            .compactMap { byID[$0] }
    }
}

// MARK: - Routing to a setting

/// Which tab of which editor holds a setting. EditVPNView has seven; the other
/// five editors have two. Nothing in the app could select a tab programmatically
/// before this existed — every `TabView` was built without a selection binding —
/// so "take me to that setting" could only ever scroll within the tab you were
/// already on.
enum SettingsTab: String, Hashable, CaseIterable {
    // EditVPNView (OpenVPN)
    case general, servers, signIn, options, certificates, configuration
    /// The canonical-groups tab of the five single-form editors.
    case settings
    /// Present in all six editors.
    case customRouting
    /// The app's own Settings window, Sign-In Sources tab — the one tab that is
    /// not part of a VPN's editor (see `SettingSurface.isAppLevel`).
    case signInSources

    /// What the tab strip calls it. Needed because the back button has to be able to
    /// say WHERE it goes when the destination holds no setting to name it by (the
    /// General tab, the Configuration tab).
    var title: String {
        switch self {
        case .general: "General"
        case .servers: "Servers"
        case .signIn: "Sign-In"
        case .options: "Options"
        case .certificates: "Certificates"
        case .configuration: "Configuration"
        case .settings: "Settings"
        case .customRouting: "Custom Routing"
        case .signInSources: "Sign-In Sources"
        }
    }
}

/// "Open the editor for this setting and put the cursor on it." One intent, two
/// callers: a related-settings link pointing outside the current editor, and a
/// global search hit.
struct SettingsRoute: Equatable, Sendable {
    let settingID: String
    let surface: String            // SettingSurface.rawValue (Sendable across the intent)
    let tab: SettingsTab
    /// The VPN to open it in. nil = "any VPN of a kind that has this setting",
    /// which is what a global search hit means.
    var profileID: String?
}

/// The router the intent travels on. One instance in the environment; Manage VPNs
/// selects the profile, the editor selects the tab, and the editor's
/// `SettingsSearch` does the reveal — so the related-links feature and global
/// search share one code path end to end.
@MainActor
@Observable
final class SettingsRouter {

    /// The current route. STICKY — reading it is not consuming it, because two
    /// different views act on one route and neither may starve the other: the
    /// host editor reads it to select the TAB, the form inside that tab consumes
    /// it to do the reveal, and SwiftUI does not order `onChange` between
    /// siblings. `consume` gates on the generation instead.
    private(set) var route: SettingsRoute?
    /// Bumped with every new route so views can react even to a repeat of the
    /// same one (the reveal's own generation trick).
    private(set) var generation = 0
    /// The generation an editor already acted on; the reveal happens once.
    private var consumedGeneration = 0

    /// Bumped by the "Find a Setting…" command (⌘⇧F) and the Manage VPNs toolbar.
    private(set) var findGeneration = 0

    /// A route to a setting in the app's own Settings window rather than in a VPN's
    /// editor. Kept SEPARATE from `route` on purpose: Manage VPNs reacts to `route`
    /// by hunting for a VPN whose editor shows the surface, and for an app-level
    /// setting there is no such VPN — it would have said "there's no Sign-In Sources
    /// VPN configured yet", which is nonsense dressed as an explanation.
    private(set) var appSettingsRoute: SettingsRoute?
    /// Bumped with each app-level route, so asking for the same tab twice still
    /// moves the window.
    private(set) var appSettingsGeneration = 0

    /// Set when a route named a kind with no VPN configured — Manage VPNs shows
    /// it rather than silently doing nothing.
    var unroutableMessage: String?

    /// Route to a setting by id. Resolves the surface and tab from the id's
    /// namespace, so callers never have to know either.
    func go(to settingID: String, profileID: String? = nil) {
        guard let surface = SettingSurface.owning(settingID) else { return }
        let wanted = SettingsRoute(settingID: settingID, surface: surface.rawValue,
                                   tab: surface.tab, profileID: profileID)
        // An app-level setting travels on its own channel — see `appSettingsRoute`.
        if surface.isAppLevel {
            appSettingsRoute = wanted
            appSettingsGeneration += 1
            return
        }
        route = wanted
        generation += 1
    }

    /// Whether a route for this id belongs in the app's Settings window rather than
    /// in a VPN editor. The one question a caller has to ask before deciding which
    /// window to open.
    static func isAppLevel(settingID: String) -> Bool {
        SettingSurface.owning(settingID)?.isAppLevel ?? false
    }

    func requestFind() { findGeneration += 1 }

    /// Take the pending route if it is one this editor can serve. Idempotent:
    /// both the "appeared" and the "generation changed" path may call it — an
    /// editor built lazily inside a TabView gets it from the first, one already
    /// on screen from the second — and only the first call gets the route.
    func consume(surfaces: Set<SettingSurface>, profileID: String?) -> SettingsRoute? {
        guard generation != consumedGeneration,
              let route,
              let surface = SettingSurface(rawValue: route.surface),
              surfaces.contains(surface) else { return nil }
        if let wanted = route.profileID, let profileID, wanted != profileID { return nil }
        consumedGeneration = generation
        return route
    }

    /// Drop a route nothing claimed (the editor for it isn't open and won't be).
    func clear() {
        route = nil
        consumedGeneration = generation
    }
}
