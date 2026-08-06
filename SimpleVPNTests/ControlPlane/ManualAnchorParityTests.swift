// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ManualAnchorParityTests.swift
//  THE gate on the config-surface contract. Every setting SimpleVPN exposes is
//  addressed by a stable id, and that id is also its manual anchor — so the two
//  sides have to agree in BOTH directions:
//
//   • a spec with no anchor is a BROKEN HELP BUTTON: the "?" beside the row opens
//     the manual and lands nowhere. Nine px.* specs shipped that way.
//   • an anchor with no spec is DEAD DOCUMENTATION: a page nothing links to,
//     which then quietly rots when the setting it describes is renamed or
//     removed.
//
//  Every catalog is walked here, in one place, so a new engine's options can't be
//  added without their documentation (and vice versa). Prose-only chapters are
//  listed explicitly below — the list is the point: adding to it is a deliberate
//  act, not a silent exemption.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct ManualAnchorParityTests {

    /// Every catalog in the app, by its id namespace. Adding an engine means
    /// adding it here — which is what makes the reverse check total.
    private static let catalogs: [(namespace: String, specs: [EngineSettingSpec])] = [
        ("wg.", WireGuardSettings.all),
        ("ssh.", SSHSettings.all),
        ("oc.", OpenConnectSettings.all),
        ("native.", NativeVPNSettings.all),
        ("ts.", TailscaleSettings.all),
        ("px.", ProxyTunnelSettings.all),
        ("sshnet.", SSHNetSettings.all),
        ("cr.", CustomRoutingSettings.all),
        ("yk.", YubiKeySettings.all),
        // The one APP-LEVEL surface (Settings ▸ Sign-In Sources, not a VPN
        // editor). Registered here for the same reason as every other catalog:
        // the enable switches and path fields are real user-facing settings, so
        // they get real manual sections and real search entries. The catalog is
        // GENERATED from the vendor list, so a new vendor's settings fail this
        // test until the manual documents them — which is the point.
        ("creds.", CredentialSourceSettings.all),
        // The SECOND app-level surface (Settings ▸ General ▸ Privacy): whether
        // SimpleVPN looks for virtual machines and containers, and whether it warns
        // before a VPN cuts their networks off. Registered for the same reason as
        // every other catalog — a switch that changes what the app notices is a real
        // user-facing setting, so it gets a real manual section and a real search
        // entry.
        ("vm.", VirtualizationSettings.all),
    ]

    /// …and the table is TOTAL, checked against the app-wide surface registry
    /// rather than trusted. Every catalog moved out of its View into ControlPlane
    /// so app-wide search could reach it; a new one that is registered as a
    /// `SettingSurface` but not listed above would ship undocumented.
    @Test func theCatalogTableCoversEverySurface() {
        let listed = Set(Self.catalogs.map(\.namespace))
            .union(["openvpn."])   // the OpenVPN descriptors are walked separately
        let registered = Set(SettingSurface.allCases.map(\.namespace))
        #expect(registered.subtracting(listed).isEmpty,
                "these surfaces aren't in the parity table: \(registered.subtracting(listed).sorted())")
        #expect(listed.subtracting(registered).isEmpty,
                "the parity table lists namespaces no surface registers: \(listed.subtracting(registered).sorted())")
    }

    /// The aliases the six editors still call (`WireGuardView.specs["wg.mtu"]`) are
    /// the SAME tables, not copies — a second copy would drift.
    @Test func theEditorAliasesPointAtTheMovedCatalogs() {
        #expect(WireGuardView.specs.all.map(\.id) == WireGuardSettings.all.map(\.id))
        #expect(TailscaleView.specs.all.map(\.id) == TailscaleSettings.all.map(\.id))
        #expect(ProxyTunnelView.specs.all.map(\.id) == ProxyTunnelSettings.all.map(\.id))
        #expect(NativeVPNView.specs.all.map(\.id) == NativeVPNSettings.all.map(\.id))
        #expect(SubprocessTunnelView.specs.all.map(\.id) == OpenConnectSettings.all.map(\.id))
    }

    /// Manual sections that are prose, not settings: chapters, troubleshooting
    /// pages and per-engine introductions. Anything else with a namespaced anchor
    /// must be a real spec.
    private static let proseAnchors: Set<String> = [
        // App chapters
        "importing", "endpoints-map", "certificates", "pausing",
        "connection-problems", "privacy",
        // What a hand-made server order means and what it beats. PROSE, not a
        // setting: the order is not a value anybody types, it is the list itself —
        // stored as a position on each server's annotations, reached by dragging a
        // row or by Move Up / Move Down.
        "endpoints-order",
        // Why the rule lists are ordered lists: first match wins, so moving a rule
        // changes where traffic goes. PROSE for the same reason — the order is the
        // list, not a field. Both `cr.route-rule` and `cr.dns-rule` link into it.
        "cr-rule-order",
        // Moving a whole setup to another Mac (Settings ▸ General ▸ Export & Import).
        // PROSE, not settings: the two controls are actions — a save panel and an
        // open panel — and the chapter is about what the file does and does not
        // carry, which is a promise rather than a value anybody sets.
        "exporting", "exporting-secrets", "exporting-import", "exporting-managed",
        // Troubleshooting
        "problem-mtu", "problem-ipv6-leak", "problem-dns-leak", "problem-lan",
        "problem-udp-blocked", "problem-otp-reneg", "problem-cipher", "problem-cert",
        "problem-idle", "problem-captive",
        // Per-engine introductions
        "ts-what-is-it", "cr-what-is-it", "sshnet-what-is-it",
        // The WireGuard editor's two export ACTIONS (a save panel each), and the
        // reason there are two: a `wg-quick` file without a private key is refused
        // by the receiving client, so omission-with-no-opt-out is not available the
        // way it is for `.ovpn`. Prose, not settings — nobody sets a value here, and
        // what the chapter documents is which file contains what.
        "wg-exporting",
        // What a security key is, and the difference between the code it types
        // for you and the certificate its PIV applet holds. The settings live
        // under "yk."; this is the chapter their help links into.
        "yk-what-is-it",
        // What a sign-in source is, why SimpleVPN is fussy about which programs it
        // runs, and why it will still tell you where your tool is. The chapter the
        // "creds." settings' help links into.
        "creds-what-is-it",
        "vm-what-is-it",
        // Prose about a WAY of signing in rather than a setting: what an SSH
        // agent is, which agents work, what its three failures mean, and why
        // agent forwarding isn't offered. The setting itself is
        // "ssh.agent-socket"; this is the chapter its row's help links into.
        "ssh-agent",
        // Smartcards / security keys: one chapter, because the subject spans five
        // settings plus facts that belong to none of them (installing a provider
        // module, registering it with p11-kit, the PIN retry counter, and why an
        // OpenVPN profile can't use a token here).
        "oc-smartcards", "oc-smartcards-setup", "oc-smartcards-registration",
        "oc-smartcards-pin-retries", "oc-smartcards-openvpn",
    ]

    private func manualHTML() throws -> String {
        let url = try #require(Bundle(for: ManualBundleToken.self).url(forResource: "manual", withExtension: "html")
                               ?? Bundle.main.url(forResource: "manual", withExtension: "html"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Every heading anchor in the manual, in document order. Only `<h2 id>`/
    /// `<h3 id>` count: an `id="…"` inside the file's own explanatory comment
    /// ("openvpn.compression" → id="openvpn-compression") is prose about the
    /// convention, not a second anchor.
    private func manualAnchors(_ html: String) -> [String] {
        var out: [String] = []
        for tag in ["<h2 id=\"", "<h3 id=\""] {
            var rest = Substring(html)
            while let open = rest.range(of: tag) {
                rest = rest[open.upperBound...]
                guard let close = rest.firstIndex(of: "\"") else { break }
                out.append(String(rest[..<close]))
                rest = rest[close...]
            }
        }
        return out
    }

    // MARK: Direction 1 — every spec has a manual section (no broken help buttons)

    @Test func everySpecHasAManualSection() throws {
        let html = try manualHTML()
        for (namespace, specs) in Self.catalogs {
            for s in specs {
                #expect(s.id.hasPrefix(namespace), "\(s.id) is outside the \(namespace)* namespace")
                #expect(!s.manualAnchor.contains("."), "\(s.id): anchors never contain dots")
                #expect(html.contains("id=\"\(s.manualAnchor)\""),
                        "manual.html is missing #\(s.manualAnchor) — the help button on \u{201C}\(s.name)\u{201D} is a broken link")
            }
        }
        // The OpenVPN descriptors are a separate type with the same contract.
        for d in OpenVPNSettings.all {
            #expect(html.contains("id=\"\(d.manualAnchor)\""),
                    "manual.html is missing #\(d.manualAnchor) — the help button on \u{201C}\(d.name)\u{201D} is a broken link")
        }
    }

    // MARK: Direction 2 — every manual section has a spec (no dead documentation)

    @Test func everyManualSectionHasASpec() throws {
        let html = try manualHTML()
        let known = Set(Self.catalogs.flatMap { $0.specs.map(\.manualAnchor) })
            .union(OpenVPNSettings.all.map(\.manualAnchor))
            .union(Self.proseAnchors)
        for anchor in manualAnchors(html) {
            #expect(known.contains(anchor),
                    "manual.html has #\(anchor) but nothing links to it — either add the spec or list it as prose")
        }
    }

    /// A setting's help button opens the manual at an anchor derived from the id,
    /// so the anchor must be unique across every catalog at once.
    @Test func anchorsAreUniqueAcrossEveryCatalog() {
        var anchors = Self.catalogs.flatMap { $0.specs.map(\.manualAnchor) }
        anchors += OpenVPNSettings.all.map(\.manualAnchor)
        #expect(Set(anchors).count == anchors.count, "two settings share a manual anchor")
    }

    /// The manual's own document order is checked too: a duplicated `id` makes the
    /// second section unreachable, which is a broken help button by another route.
    @Test func manualAnchorsAreUnique() throws {
        let anchors = manualAnchors(try manualHTML())
        let dupes = Dictionary(grouping: anchors, by: { $0 }).filter { $0.value.count > 1 }.keys
        #expect(dupes.isEmpty, "manual.html repeats these ids: \(dupes.sorted().joined(separator: ", "))")
    }

    /// The manual's own links resolve, in both directions: a nav entry pointing at
    /// a missing anchor is a broken link inside the help, and a section no nav
    /// entry reaches can only be found via a row's help button.
    @Test func everyManualLinkResolvesAndEverySectionIsReachable() throws {
        let html = try manualHTML()
        let anchors = Set(manualAnchors(html))
        var links: Set<String> = []
        var rest = Substring(html)
        while let open = rest.range(of: "href=\"#") {
            rest = rest[open.upperBound...]
            guard let close = rest.firstIndex(of: "\"") else { break }
            links.insert(String(rest[..<close]))
            rest = rest[close...]
        }
        #expect(links.subtracting(anchors).isEmpty,
                "manual.html links to missing anchors: \(links.subtracting(anchors).sorted())")
        #expect(anchors.subtracting(links).isEmpty,
                "manual.html sections no link reaches: \(anchors.subtracting(links).sorted())")
    }

    /// Every documented setting states its default — the single most-asked
    /// question about any option ("what happens if I leave it alone?").
    @Test func everySettingSectionStatesItsDefault() throws {
        let html = try manualHTML()
        let sections = html.components(separatedBy: "<h2 id=\"")
        let settingAnchors = Set(Self.catalogs.flatMap { $0.specs.map(\.manualAnchor) })
            .union(OpenVPNSettings.all.map(\.manualAnchor))
        for chunk in sections.dropFirst() {
            guard let close = chunk.firstIndex(of: "\"") else { continue }
            let anchor = String(chunk[chunk.startIndex..<close])
            guard settingAnchors.contains(anchor) else { continue }
            #expect(chunk.contains("class=\"default\""),
                    "manual section #\(anchor) has no Default: line")
        }
    }

    // MARK: Spec contract (name, summary, group)

    @Test func everySpecIsNamedSummarizedAndGrouped() {
        for (_, specs) in Self.catalogs {
            for s in specs {
                #expect(!s.name.isEmpty, "\(s.id) has no display name")
                #expect(!s.summary.isEmpty, "\(s.id) has no plain-English summary")
                // The canonical taxonomy has to be answerable for every setting —
                // it is what the CLI, MDM and search group by.
                #expect(s.group != nil, "\(s.id) declares no canonical group")
            }
        }
        for d in OpenVPNSettings.all {
            #expect(!d.name.isEmpty, "\(d.id) has no display name")
            #expect(!d.summary.isEmpty, "\(d.id) has no plain-English summary")
        }
    }

    /// Catalogs declare their groups in canonical order (Connection → Sign-In →
    /// Traffic → Security → Advanced), so a form rendered by walking the catalog
    /// lays out in taxonomy order by construction.
    ///
    /// `cr.*` is the one exception, and deliberately: Custom Routing is its own
    /// TAB with its own Routes → DNS → Proxy structure, not a run of the canonical
    /// five, so its declaration order follows the tab. Its specs still declare the
    /// group each subject belongs to (checked above) so search, the CLI and MDM can
    /// still answer "which group is this?".
    @Test func catalogsAreInCanonicalGroupOrder() {
        let order = SettingGroup.allCases
        for (namespace, specs) in Self.catalogs where namespace != "cr." {
            let indices = specs.compactMap { $0.group.flatMap(order.firstIndex(of:)) }
            #expect(indices.count == specs.count, "\(namespace)* has an ungrouped spec")
            #expect(indices == indices.sorted(),
                    "\(namespace)* is not in canonical group order")
        }
    }

    // MARK: The regrouping decisions this batch made (they must not drift back)

    @Test func groupPlacementsAreTheDecidedOnes() {
        // A routing escape hatch, sibling of the firewall mark — not Traffic,
        // where it sat beside the Allowed IPs it can silently make inert.
        #expect(WireGuardView.specs["wg.table"].group == .advanced)
        #expect(WireGuardView.specs["wg.fwmark"].group == .advanced)
        // Sharing networks is a decision about which traffic this tunnel carries.
        #expect(TailscaleView.specs["ts.advertise-routes"].group == .traffic)
        // …which leaves Tailscale with nothing in Advanced, so it is omitted.
        #expect(TailscaleView.specs.all.allSatisfy { $0.group != .advanced })
        // It verifies the SERVER's certificate identity.
        #expect(NativeVPNView.specs["native.remote-id"].group == .security)
        // Lifecycle, sibling of on-demand.
        #expect(NativeVPNView.specs["native.disconnect-sleep"].group == .connection)
        #expect(NativeVPNView.specs["native.on-demand"].group == .connection)
        // The user-facing MTU is Traffic; the BASE MTU describes the path
        // underneath the tunnel and stays in Advanced (AGENTS.md records the split).
        #expect(SubprocessTunnelView.specs["oc.mtu"].group == .traffic)
        #expect(SubprocessTunnelView.specs["oc.base-mtu"].group == .advanced)
        // Verifying the SERVER (as opposed to identifying yourself) is Security —
        // and on these seven kinds the pin is the ONLY control that does it.
        #expect(SubprocessTunnelView.specs["oc.pinned-server-cert"].group == .security)
        #expect(SubprocessTunnelView.specs["oc.pfs"].group == .security)
        // The local proxy and "point the whole Mac at it" are routing decisions,
        // the same group their ssh.* twins are in.
        #expect(SubprocessTunnelView.specs["oc.socks-port"].group == .traffic)
        #expect(SubprocessTunnelView.specs["oc.system-proxy"].group == .traffic)
        // What the gateway is TOLD this client is: escape hatches, not Security.
        for id in ["oc.local-hostname", "oc.user-agent", "oc.version-string",
                   "oc.usergroup", "oc.prefer-in-process", "oc.csd-wrapper"] {
            #expect(SubprocessTunnelView.specs[id].group == .advanced, "\(id) isn't in Advanced")
        }
    }

    /// ONE CONCEPT, ONE NAME (AGENTS.md's naming glossary). The SSH and SSL-VPN
    /// surfaces expose the same two SOCKS concepts off the same two model fields,
    /// and this editor renders both — so the words have to be identical. Two kinds
    /// describing one concept two ways is how a user who learned one editor stops
    /// trusting the other, and it is the exact drift the glossary rule exists for.
    @Test func theSOCKSPairIsWordedIdenticallyOnBothSurfaces() {
        for (sshID, ocID) in [("ssh.socks-port", "oc.socks-port"),
                              ("ssh.system-proxy", "oc.system-proxy")] {
            let a = SSHSettings.catalog[sshID], b = OpenConnectSettings.catalog[ocID]
            #expect(a.name == b.name, "\(sshID) and \(ocID) have different names")
            #expect(a.summary == b.summary, "\(sshID) and \(ocID) have different summaries")
            #expect(a.group == b.group, "\(sshID) and \(ocID) are in different groups")
        }
        // Perfect forward secrecy is the same concept the native surface names.
        #expect(OpenConnectSettings.catalog["oc.pfs"].name
                == NativeVPNSettings.catalog["native.pfs"].name)
    }

    /// Ids are the CLI/MDM/manual contract: they may be ADDED to, never renamed.
    @Test func shippedIdsNeverDisappear() {
        let ids = Set(Self.catalogs.flatMap { $0.specs.map(\.id) })
            .union(OpenVPNSettings.all.map(\.id))
        let shipped: Set<String> = [
            // Added by this batch — the surfaces that had no descriptors at all.
            "native.protocol", "native.server", "native.remote-id", "native.group",
            "native.on-demand", "native.auth-method", "native.xauth", "native.username",
            "native.password", "native.shared-secret", "native.xauth-password",
            "ts.preset", "ts.exit-node-machine", "ts.exit-node-lan",
            "wg.private-key", "px.kind",
            "openvpn.proxy-enabled", "openvpn.proxy-password", "openvpn.private-key-password",
            "cr.routes-default", "cr.route-rule", "cr.dns-default", "cr.dns-rule",
            "cr.ignore-pushed-search", "cr.ignore-pushed-match",
            "cr.add-search-domains", "cr.match-domains",
            "cr.proxy-mode", "cr.proxy-manual-url", "cr.proxy-pac-url", "cr.proxy-auth",
            // The OpenConnect surface's last unspec'd controls — the SSL-VPN half
            // of this editor was hand-rolled below Traffic and invisible to search.
            "oc.socks-port", "oc.system-proxy", "oc.pinned-server-cert", "oc.pfs",
            "oc.prefer-in-process", "oc.csd-wrapper", "oc.usergroup", "oc.compression",
            "oc.disable-ipv6", "oc.no-http-keepalive", "oc.local-hostname",
            "oc.user-agent", "oc.version-string",
        ]
        #expect(shipped.isSubset(of: ids))
    }
}

// MARK: - The computed "changed" contract (one derivation, not thirty)

@MainActor
struct EngineSettingChangedTests {

    @Test func aSpecWithoutADefaultNeverClaimsAChange() {
        let s = EngineSettingSpec(id: "x.y", name: "X", summary: "s")
        #expect(!s.declaresDefault)
        #expect(!s.isChanged(true))
        #expect(!s.isChanged("anything"))
    }

    @Test func booleanDefaultsRunBothWays() {
        let offByDefault = EngineSettingSpec(id: "x.off", name: "X", summary: "s", default: false)
        #expect(!offByDefault.isChanged(false))
        #expect(offByDefault.isChanged(true))
        // The inverted case is exactly what hand-written call sites got wrong.
        let onByDefault = EngineSettingSpec(id: "x.on", name: "X", summary: "s", default: true)
        #expect(!onByDefault.isChanged(true))
        #expect(onByDefault.isChanged(false))
    }

    @Test func optionalAndCollectionDefaultsWork() {
        let optional = EngineSettingSpec(id: "x.n", name: "X", summary: "s", default: Int?.none)
        #expect(!optional.isChanged(Int?.none))
        #expect(optional.isChanged(Int?.some(1420)))

        let list = EngineSettingSpec(id: "x.l", name: "X", summary: "s", default: [String]())
        #expect(!list.isChanged([String]()))
        #expect(list.isChanged(["10.0.0.0/8"]))

        let text = EngineSettingSpec(id: "x.t", name: "X", summary: "s", default: "")
        #expect(!text.isChanged(""))
        #expect(text.isChanged("auto"))
    }

    /// A mismatched type at a call site is a programming error, but a wrong BOLD
    /// is not worth a crash — it answers "unchanged".
    @Test func aMismatchedTypeAnswersUnchanged() {
        let s = EngineSettingSpec(id: "x.b", name: "X", summary: "s", default: false)
        #expect(!s.isChanged("true"))
    }

    /// Every real catalog spec that a form asks "is this changed?" about has a
    /// declared default to answer with. `oc.sso-browser` is the documented
    /// exception: its value is a browser identity, not a value with a default.
    @Test func catalogsDeclareTheirDefaults() {
        let undeclared = (WireGuardView.specs.all + TailscaleView.specs.all
                          + ProxyTunnelView.specs.all + NativeVPNView.specs.all
                          + CustomRoutingSettings.all)
            .filter { !$0.declaresDefault }
            .map(\.id)
        #expect(undeclared.isEmpty, "these specs declare no default: \(undeclared.joined(separator: ", "))")
    }
}

// MARK: - The shared MTU control's ranges

@MainActor
struct SharedMTUFieldTests {

    /// One control, three engines — and each engine's own range, so the shared
    /// field can never offer a value that engine would refuse.
    @Test func everyEngineMTURangeIsTheEnginesOwn() {
        // Both floors are IPv4's minimum reassembly buffer: sub-1280 MTUs are
        // legal and shipped by real providers, so refusing them threw away a
        // working configuration (below 1280 is a caveat — no IPv6 — not a bound).
        #expect(WireGuardConfig.mtuRange == 576...1500)
        #expect(SubprocessTunnelConfig.ocMTURange == 576...1500)
        #expect(ProxyTunnelConfig.mtuRange.contains(ProxyTunnelStartConfig.defaultMTU))
        // The base MTU describes the path under the tunnel, which may be jumbo.
        #expect(SubprocessTunnelConfig.baseMTURange.upperBound == 9000)
    }

    /// wg-quick's Table/FwMark grammars, now that both are pickers rather than
    /// free text — the editor and `normalized()` agree on one definition.
    @Test func wireGuardTableAndFwMarkGrammars() {
        #expect(WireGuardConfig.isValidTable("auto"))
        #expect(WireGuardConfig.isValidTable("OFF"))
        #expect(WireGuardConfig.isValidTable("51820"))
        // A NAME is valid wg-quick: anything that isn't auto/off goes to
        // `ip route … table <value>`, which resolves it out of rt_tables.
        #expect(WireGuardConfig.isValidTable("main"))
        #expect(!WireGuardConfig.isValidTable("-1"))     // not a name, not a uint32
        #expect(!WireGuardConfig.isValidTable("two words"))

        #expect(WireGuardConfig.isValidFwMark("off"))
        #expect(WireGuardConfig.isValidFwMark("0x1234"))
        #expect(WireGuardConfig.isValidFwMark("4660"))
        #expect(!WireGuardConfig.isValidFwMark("0xZZ"))
        #expect(!WireGuardConfig.isValidFwMark("nope"))

        // An illegal value collapses to "not set" as an import/CLI/MDM BACKSTOP —
        // the editor blocks Save with the reason rather than rewriting what was
        // typed. A legal one round-trips into the exported .conf untouched.
        var c = WireGuardConfig()
        c.table = "two words"
        c.fwMark = "nope"
        let n = c.normalized()
        #expect(n.table.isEmpty)
        #expect(n.fwMark.isEmpty)

        c.table = "main"
        c.fwMark = "0xff"
        let ok = c.normalized()
        #expect(ok.table == "main")
        #expect(ok.fwMark == "0xff")
    }
}

private final class ManualBundleToken {}
