// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingNavigationTests.swift
//  The gate on the navigation contract — the three ways a user gets from one
//  setting to another, and the ways each of them can silently rot:
//
//   • RELATIONS (SettingRelations → the help popover's "Related settings"): an id
//     that exists in no catalog is a DEAD LINK behind a real-looking label, and
//     a relation declared in one direction only dead-ends when followed back.
//   • SEARCH (SettingsSearch, now catalog-injected): a catalog nobody registered
//     as a `SettingSurface` is invisible to the app-wide search — which is
//     exactly the state five of the six editors were in.
//   • ROUTING (SettingsRoute/SettingsRouter): a route has to resolve to the right
//     surface AND the right tab, or "take me there" lands on the tab you were
//     already looking at.
//
//  Plus the reveal itself: opening a collapsed section is the difference between
//  a jump that works and a scroll to a row nobody can see.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Relations

@MainActor
struct SettingRelationTests {

    /// A relation naming an id no catalog has is a link that opens nothing. This
    /// is the whole reason the map is checked rather than trusted.
    @Test func everyRelatedIDExistsInSomeCatalog() {
        let known = Set(AllSettings.everything.map(\.id))
        let dangling = SettingRelations.referencedIDs.subtracting(known)
        #expect(dangling.isEmpty,
                "these relation targets exist in no catalog: \(dangling.sorted().joined(separator: ", "))")
    }

    /// Symmetric by construction (cliques, not per-spec lists) — asserted anyway,
    /// because the construction is the invariant, and `oneWay` is a door in it.
    @Test func relationsAreSymmetric() {
        for (id, targets) in SettingRelations.related {
            for target in targets {
                let back = SettingRelations.related[target] ?? []
                let declaredOneWay = SettingRelations.oneWay.contains { $0.from == id && $0.to == target }
                #expect(back.contains(id) || declaredOneWay,
                        "\(id) relates to \(target) but \(target) doesn't relate back")
            }
        }
    }

    @Test func nothingRelatesToItself() {
        for (id, targets) in SettingRelations.related {
            #expect(!targets.contains(id), "\(id) relates to itself")
        }
    }

    /// Both metadata types answer the same question from the same map — the point
    /// of computing `related` instead of storing it per spec.
    @Test func bothSpecTypesExposeTheirRelations() {
        // SettingDescriptor (OpenVPN)
        let proxyHost = OpenVPNSettings.byID["openvpn.proxy-host"]!
        #expect(proxyHost.related.contains("openvpn.protocol"))
        #expect(proxyHost.related.contains("openvpn.proxy-port"))
        // EngineSettingSpec (every other engine)
        #expect(WireGuardSettings.catalog["wg.dns"].related.contains("wg.allowed-ips"))
        #expect(TailscaleSettings.catalog["ts.exit-node"].related.contains("ts.accept-routes"))
        #expect(NativeVPNSettings.catalog["native.pfs"].related.contains("native.dh-group"))
        #expect(SSHSettings.catalog["ssh.auth-method"].related.contains("ssh.identity-file"))
        #expect(ProxyTunnelSettings.catalog["px.dns"].related.contains("px.included"))
        #expect(OpenConnectSettings.catalog["oc.mtu"].related.contains("oc.base-mtu"))
    }

    /// The relations the audit named explicitly, each one a caveat or a
    /// disabledReason that used to name a setting in prose.
    @Test func theCuratedRelationsAreAllThere() {
        func relates(_ a: String, _ b: String) -> Bool {
            SettingRelations.related[a]?.contains(b) == true
        }
        #expect(relates("wg.dns", "wg.allowed-ips"))
        #expect(relates("wg.table", "wg.fwmark"))
        for other in ["ts.accept-routes", "ts.accept-dns", "ts.exit-node-lan"] {
            #expect(relates("ts.exit-node", other))
        }
        for other in ["ssh.identity-file", "ssh.certificate-file", "ssh.password"] {
            #expect(relates("ssh.auth-method", other))
        }
        #expect(relates("openvpn.proxy-host", "openvpn.protocol"))
        for other in ["openvpn.proxy-port", "openvpn.proxy-username", "openvpn.proxy-password"] {
            #expect(relates("openvpn.proxy-host", other))
        }
        for other in ["openvpn.tls-version-min", "openvpn.tls-ciphersuites"] {
            #expect(relates("openvpn.tls-cipher-list", other))
        }
        #expect(relates("px.dns", "px.included"))
        #expect(relates("px.dns", "px.excluded"))
        #expect(relates("native.pfs", "native.dh-group"))
    }

    /// `cr.*` names every engine's routing control at once, so the popover filters
    /// by the kind in front of the user. Offering a WireGuard row inside a
    /// Tailscale editor would be a link to a setting that isn't there.
    @Test func customRoutingRelationsAreFilteredByKind() {
        let forTailscale = AllSettings.related(of: "cr.route-rule", kind: .tailscale).map(\.id)
        #expect(forTailscale.contains("ts.accept-routes"))
        #expect(!forTailscale.contains("wg.allowed-ips"))

        let forWireGuard = AllSettings.related(of: "cr.route-rule", kind: .wireGuard).map(\.id)
        #expect(forWireGuard.contains("wg.allowed-ips"))
        #expect(!forWireGuard.contains("ts.accept-routes"))

        // Custom Routing itself is reachable from every kind — it is a tab in all
        // six editors.
        #expect(AllSettings.isReachable("cr.route-rule", from: .ssh))
        #expect(AllSettings.isReachable("cr.route-rule", from: .ikev2))
        // No kind in context (the global search) hides nothing.
        #expect(AllSettings.isReachable("wg.allowed-ips", from: nil))
    }
}

// MARK: - The app-wide registry

@MainActor
struct SettingSurfaceRegistryTests {

    /// Every catalog is registered. An unregistered one is invisible to the
    /// app-wide search and unroutable — the state five editors were in.
    @Test func everySurfaceCarriesItsOwnNamespace() {
        for surface in SettingSurface.allCases {
            #expect(!surface.settings.isEmpty, "\(surface.rawValue) registers no settings")
            for s in surface.settings {
                #expect(s.id.hasPrefix(surface.namespace),
                        "\(s.id) is registered under \(surface.rawValue) (\(surface.namespace)*)")
            }
        }
    }

    @Test func idsAreUniqueAcrossEverySurface() {
        let ids = AllSettings.everything.map(\.id)
        #expect(Set(ids).count == ids.count, "two surfaces claim the same setting id")
    }

    /// Every setting reachable from at least one kind — a setting no editor shows
    /// cannot be routed to.
    ///
    /// …with the one deliberate exception: an APP-LEVEL surface belongs to no VPN
    /// kind because it is not a VPN's editor (Settings ▸ Sign-In Sources). It is
    /// still routable, on the router's own app-settings channel — which is asserted
    /// just below, so "belongs to no kind" cannot become "reachable from nowhere".
    @Test func everySettingBelongsToAtLeastOneKind() {
        for entry in AllSettings.everything where !entry.surface.isAppLevel {
            #expect(!entry.surface.kinds.isEmpty, "\(entry.id) belongs to no VPN kind")
        }
    }

    /// An app-level setting IS routable — via `appSettingsRoute`, and never via the
    /// VPN-editor `route` (which is what Manage VPNs reacts to by hunting for a VPN
    /// whose editor shows the surface; for these there is no such VPN, and it would
    /// have said "there's no Sign-In Sources VPN configured yet").
    @MainActor
    @Test func anAppLevelSettingRoutesToTheSettingsWindow() {
        let appLevel = AllSettings.everything.filter { $0.surface.isAppLevel }
        #expect(!appLevel.isEmpty, "no app-level surface is registered")
        for entry in appLevel {
            #expect(SettingsRouter.isAppLevel(settingID: entry.id))
            let router = SettingsRouter()
            router.go(to: entry.id)
            #expect(router.appSettingsRoute?.settingID == entry.id)
            #expect(router.appSettingsGeneration == 1)
            #expect(router.route == nil, "an app-level route must not travel on the editor channel")
        }
    }

    /// The whole address of a setting in one line, which is what a global hit shows.
    @Test func breadcrumbNamesSurfaceGroupAndSetting() {
        let ts = AllSettings.byID["ts.accept-routes"]!
        #expect(ts.breadcrumb == "Tailscale / Headscale \u{25B8} Traffic \u{25B8} Use Shared Networks")
        // VoiceOver gets the same thing without the glyph.
        #expect(ts.spokenBreadcrumb == "Tailscale / Headscale, Traffic, Use Shared Networks")
    }

    @Test func everyKindHasSettingsIncludingCustomRouting() {
        for kind in VPNKind.allCases {
            let settings = AllSettings.byKind[kind] ?? []
            #expect(!settings.isEmpty, "\(kind.rawValue) has no settings at all")
            #expect(settings.contains { $0.surface == .customRouting },
                    "\(kind.rawValue) is missing the Custom Routing surface every editor has")
        }
    }

    /// The link back from Custom Routing to the group it rewrites, derived per
    /// kind rather than hard-coded in six editors.
    @Test func everyKindResolvesItsFirstTrafficSetting() {
        for kind in VPNKind.allCases {
            let traffic = AllSettings.firstTrafficSetting(for: kind)
            #expect(traffic != nil, "\(kind.rawValue) has no Traffic setting to link back to")
            #expect(traffic?.surface != .customRouting)
            #expect(traffic?.setting.canonicalGroup == .traffic)
        }
    }
}

// MARK: - Search

@MainActor
struct SettingsSearchTests {

    /// Catalog-injected and generic: the same scorer finds a spec in EVERY
    /// catalog, not just the OpenVPN one it used to name in its signatures.
    @Test func searchFindsASpecInEveryCatalog() {
        let probes: [(SettingSurface, String, String)] = [
            (.openVPN, "compression", "openvpn.compression"),
            (.wireGuard, "allowed ips", "wg.allowed-ips"),
            (.tailscale, "shared networks", "ts.accept-routes"),
            (.proxyTunnel, "proxy address", "px.address"),
            (.native, "diffie", "native.dh-group"),
            (.ssh, "jump host", "ssh.proxy-jump"),
            (.sshNetworkTunnel, "resolve names at the server", "sshnet.far-side-dns"),
            (.openConnect, "host checker", "oc.disable-csd"),
            (.customRouting, "pac url", "cr.proxy-pac-url"),
        ]
        for (surface, query, expected) in probes {
            let search = SettingsSearch(surfaces: [surface], kind: surface.kinds.first)
            search.query = query
            #expect(search.matches.contains { $0.id == expected },
                    "\u{201C}\(query)\u{201D} didn't find \(expected) in \(surface.rawValue)")
        }
    }

    /// The global search reaches all eight surfaces at once — the thing no
    /// per-editor field can do.
    @Test func globalSearchSpansEverySurface() {
        let search = SettingsSearch.global()
        #expect(search.catalog.count == AllSettings.everything.count)
        for surface in SettingSurface.allCases {
            let id = surface.settings[0].id
            #expect(search.contains(id), "the global search can't reach \(id)")
        }
    }

    @Test func shortQueriesMatchNothing() {
        let search = SettingsSearch.global()
        search.query = "a"
        #expect(search.matches.isEmpty)
        search.query = ""
        #expect(search.matches.isEmpty)
    }

    /// `contains` is the test a related link applies to choose "reveal here" vs
    /// "route elsewhere", so it has to be exact.
    @Test func containsAnswersOnlyForItsOwnCatalog() {
        let search = SettingsSearch(surfaces: [.wireGuard, .customRouting], kind: .wireGuard)
        #expect(search.contains("wg.dns"))
        #expect(search.contains("cr.route-rule"))
        #expect(!search.contains("ts.accept-dns"))
    }

    /// The reveal publishes everything the row half and the section half need:
    /// the group (so a collapsed section opens), the target (so the scroll and the
    /// pulse fire) and a bumped generation (so a repeat of the same target still
    /// re-triggers).
    @Test func revealPublishesGroupTargetAndGeneration() {
        let search = SettingsSearch(surfaces: [.openVPN], kind: .openVPN)
        search.query = "compression"
        let before = search.revealGeneration

        #expect(search.reveal(id: "openvpn.compression"))
        #expect(search.revealTargetID == "openvpn.compression")
        #expect(search.highlightedID == "openvpn.compression")
        // Security is COLLAPSED by default in the OpenVPN form; the group is what
        // CollapsibleSettingsSection watches to open itself, so a hit inside a
        // closed disclosure is still reachable.
        #expect(search.revealGroup == .security)
        #expect(search.revealGeneration == before + 1)
        // Picking a result clears the field, so the form isn't left filtered.
        #expect(search.query.isEmpty)

        // Same target again still re-triggers.
        #expect(search.reveal(id: "openvpn.compression"))
        #expect(search.revealGeneration == before + 2)
    }

    @Test func revealingSomethingElsesSettingFails() {
        let search = SettingsSearch(surfaces: [.wireGuard, .customRouting], kind: .wireGuard)
        #expect(!search.reveal(id: "ts.accept-dns"))
        #expect(search.revealTargetID == nil)
    }
}

// MARK: - Routing

@MainActor
struct SettingsRouteTests {

    /// Namespace → surface → tab, with no caller having to know any of it.
    @Test func routesResolveToTheRightSurfaceAndTab() {
        let cases: [(String, SettingSurface, SettingsTab)] = [
            ("openvpn.compression", .openVPN, .options),
            ("wg.dns", .wireGuard, .settings),
            ("ts.exit-node", .tailscale, .settings),
            ("px.included", .proxyTunnel, .settings),
            ("native.pfs", .native, .settings),
            ("ssh.auth-method", .ssh, .settings),
            // "sshnet." also has the "ssh." prefix, so this case is the regression
            // guard for SettingSurface.owning's longest-prefix rule.
            ("sshnet.host-key-policy", .sshNetworkTunnel, .settings),
            ("oc.base-mtu", .openConnect, .settings),
            ("cr.route-rule", .customRouting, .customRouting),
        ]
        for (id, surface, tab) in cases {
            #expect(SettingSurface.owning(id) == surface, "\(id) resolved to the wrong surface")
            let router = SettingsRouter()
            router.go(to: id)
            let route = router.route
            #expect(route?.settingID == id)
            #expect(route?.surface == surface.rawValue)
            #expect(route?.tab == tab, "\(id) resolved to the wrong tab")
        }
    }

    @Test func anUnknownNamespaceRoutesNowhere() {
        let router = SettingsRouter()
        router.go(to: "nonsense.setting")
        #expect(router.route == nil)
        #expect(router.generation == 0)
    }

    /// Reading the route is not consuming it: the host editor reads it to select
    /// the tab and the form inside consumes it to do the reveal, and SwiftUI does
    /// not order `onChange` between siblings.
    @Test func theRouteIsStickyAndConsumedOnlyOnce() {
        let router = SettingsRouter()
        router.go(to: "cr.dns-rule")
        #expect(router.route != nil)

        let first = router.consume(surfaces: [.customRouting], profileID: nil)
        #expect(first?.settingID == "cr.dns-rule")
        // Still readable — that is what lets the host select the tab.
        #expect(router.route?.settingID == "cr.dns-rule")
        // But not claimable twice.
        #expect(router.consume(surfaces: [.customRouting], profileID: nil) == nil)
    }

    @Test func anEditorForAnotherSurfaceDoesNotClaimTheRoute() {
        let router = SettingsRouter()
        router.go(to: "wg.allowed-ips")
        #expect(router.consume(surfaces: [.tailscale, .customRouting], profileID: nil) == nil)
        // …and the right editor still gets it.
        #expect(router.consume(surfaces: [.wireGuard, .customRouting], profileID: nil) != nil)
    }

    /// A route naming a profile is only served by that profile's editor —
    /// following a link must never reveal a setting on the wrong VPN.
    @Test func aProfileScopedRouteOnlyServesThatProfile() {
        let router = SettingsRouter()
        router.go(to: "wg.dns", profileID: "abc")
        #expect(router.consume(surfaces: [.wireGuard], profileID: "xyz") == nil)
        #expect(router.consume(surfaces: [.wireGuard], profileID: "abc")?.settingID == "wg.dns")
    }

    @Test func clearDropsAnUnclaimedRoute() {
        let router = SettingsRouter()
        router.go(to: "native.pfs")
        router.clear()
        #expect(router.route == nil)
        #expect(router.consume(surfaces: [.native], profileID: nil) == nil)
    }

    @Test func findRequestsAreCountedSeparatelyFromRoutes() {
        let router = SettingsRouter()
        router.requestFind()
        router.requestFind()
        #expect(router.findGeneration == 2)
        #expect(router.route == nil)
    }
}
