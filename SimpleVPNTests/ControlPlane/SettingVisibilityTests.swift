// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingVisibilityTests.swift
//  The gate on "take me to that setting" actually GOING somewhere — the half of
//  the reveal feature that was non-functional:
//
//   • A registered spec must be RENDERED by some editor. Thirteen `oc.*` specs
//     shipped declared-but-unrendered: searchable, addressable by the CLI and
//     MDM, documented in the manual, and on no screen anywhere. The anchor-parity
//     tests only check the manual, so that whole class of bug was invisible.
//   • A row an editor gates out of its form must be DECLARED gated
//     (`SettingVisibility`), because the reveal used to scroll to nothing while
//     announcing "Showing X, in Y" to VoiceOver — a lie, which is worse than
//     silence for someone who can't see the screen.
//   • Every Custom Routing host must LOAD the proxy sign-in fields, or the first
//     tab switch deletes the stored credential (see the test at the bottom).
//
//  Two of these are checked against the SOURCE, deliberately: they are facts about
//  what the views render, and nothing else in the app can answer them.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - The declared gating tables

@MainActor
struct SettingVisibilityTests {

    /// Every id a table names must be a real spec on that table's own surface.
    /// A typo here would silently mean "never gated", i.e. back to the lie.
    @Test func everyGatedIDIsARealSpecOnItsOwnSurface() {
        let tables: [(String, SettingVisibility, Set<SettingSurface>)] = [
            ("tailscale", .tailscale(TailscaleConfig()), [.tailscale]),
            ("native/ikev2", .native(Self.native(.ikev2)), [.native]),
            ("native/ipsec", .native(Self.native(.ipsec)), [.native]),
            ("native/l2tp", .native(Self.native(.l2tp)), [.native]),
            ("proxyTunnel", .proxyTunnel(ProxyTunnelConfig()), [.proxyTunnel]),
            ("sshNetworkTunnel", .sshNetworkTunnel(SSHNetworkTunnelConfig()), [.sshNetworkTunnel]),
            ("subprocess/ssh", .subprocess(Self.subprocess(.ssh)), [.ssh, .openConnect]),
            ("subprocess/ssl", .subprocess(Self.subprocess(.fortinet)), [.ssh, .openConnect]),
        ]
        for (label, table, surfaces) in tables {
            let allowed = Set(surfaces.flatMap { $0.settings.map(\.id) })
            for (id, why) in table.hidden {
                #expect(allowed.contains(id), "\(label) hides \(id), which is not a spec on its surface")
                #expect(!why.isEmpty, "\(label) hides \(id) with no reason to show the user")
            }
        }
    }

    /// A gated row must not ALSO be claimed as shown, and a shown row must not be
    /// claimed as gated — the tables are the answer to "is this row on screen".
    @Test func tailscaleGatesTheHeadscaleAndExitNodeRows() {
        var c = TailscaleConfig()
        c.preset = .tailscale
        c.useExitNode = false
        let plain = SettingVisibility.tailscale(c)
        #expect(plain.reason("ts.control-url") != nil)
        // These two are clique members of `ts.exit-node`, so the help popover
        // offers a link to them EXACTLY when they are hidden — the case that made
        // the whole feature look broken.
        #expect(plain.reason("ts.exit-node-machine") != nil)
        #expect(plain.reason("ts.exit-node-lan") != nil)
        #expect(plain.reason("ts.exit-node") == nil)
        #expect(plain.reason("ts.accept-dns") == nil)

        c.preset = .headscale
        c.useExitNode = true
        let full = SettingVisibility.tailscale(c)
        #expect(full.hidden.isEmpty)
    }

    @Test func theNativeEditorGatesOnTheProtocolPicker() {
        let ikev2 = SettingVisibility.native(Self.native(.ikev2))
        #expect(ikev2.reason("native.xauth") != nil)          // IPsec's
        #expect(ikev2.reason("native.group") != nil)
        #expect(ikev2.reason("native.remote-id") == nil)      // IKEv2's own
        #expect(ikev2.reason("native.encryption") == nil)

        let ipsec = SettingVisibility.native(Self.native(.ipsec))
        #expect(ipsec.reason("native.xauth") == nil)
        #expect(ipsec.reason("native.group") == nil)
        #expect(ipsec.reason("native.remote-id") != nil)      // IKEv2-only in macOS
        #expect(ipsec.reason("native.mobike") != nil)

        // L2TP's exported profile carries four fields; everything else is absent.
        let l2tp = SettingVisibility.native(Self.native(.l2tp))
        #expect(l2tp.reason("native.server") == nil)
        #expect(l2tp.reason("native.username") == nil)
        #expect(l2tp.reason("native.on-demand") != nil)
        #expect(l2tp.reason("native.include-all") != nil)
    }

    @Test func theSubprocessEditorGatesOnTheKindPicker() {
        let ssh = SettingVisibility.subprocess(Self.subprocess(.ssh))
        // Every oc.* row belongs to the other surface this one editor serves.
        for id in OpenConnectSettings.all.map(\.id) {
            #expect(ssh.reason(id) != nil, "\(id) should be gated out of an SSH tunnel")
        }
        #expect(ssh.reason("ssh.server") == nil)
        #expect(ssh.reason("ssh.proxy-jump") != nil)          // behind useJumpHost
        #expect(ssh.reason("ssh.jump-identity-file") != nil)

        var withJump = Self.subprocess(.ssh)
        withJump.useJumpHost = true
        #expect(SettingVisibility.subprocess(withJump).reason("ssh.proxy-jump") == nil)

        let ssl = SettingVisibility.subprocess(Self.subprocess(.fortinet))
        for id in SSHSettings.all.map(\.id) {
            #expect(ssl.reason(id) != nil, "\(id) should be gated out of an SSL VPN")
        }
        #expect(ssl.reason("oc.token-secret") != nil)         // no token mode chosen
        #expect(ssl.reason("oc.key-password") != nil)         // no certificate set
        // `oc.sso-browser` is RENDERED and disabled with its reason, so a reveal
        // lands on it — it must not be declared hidden.
        #expect(ssl.reason("oc.sso-browser") == nil)

        var configured = Self.subprocess(.fortinet)
        configured.tokenMode = "totp"
        configured.clientCertFile = "~/client.p12"
        let ready = SettingVisibility.subprocess(configured)
        #expect(ready.reason("oc.token-secret") == nil)
        #expect(ready.reason("oc.key-password") == nil)
    }

    @Test func theProxyTunnelEditorGatesItsSignInAndSplitRows() {
        let plain = SettingVisibility.proxyTunnel(ProxyTunnelConfig())
        #expect(plain.reason("px.username") != nil)
        #expect(plain.reason("px.password") != nil)
        #expect(plain.reason("px.included") != nil)           // full tunnel by default
        #expect(plain.reason("px.address") == nil)

        var c = ProxyTunnelConfig()
        c.requiresAuth = true
        c.includeDefaultRoute = false
        #expect(SettingVisibility.proxyTunnel(c).hidden.isEmpty)
    }

    /// WireGuard renders every row unconditionally, which is what lets it publish
    /// nothing — asserted so a future gated row can't be added silently.
    @Test func theWireGuardEditorGatesNothing() {
        #expect(SettingVisibility.everythingShown.hidden.isEmpty)
        #expect(SettingVisibility.everythingShown.reason("wg.mtu") == nil)
    }

    // MARK: The reveal is honest about a row it can't reach

    @Test func revealingAGatedRowSaysSoInsteadOfPretending() {
        let search = SettingsSearch(surfaces: [.tailscale, .customRouting], kind: .tailscale)
        var c = TailscaleConfig()
        c.useExitNode = false
        search.visibility = SettingVisibility.tailscale(c)
        let before = search.revealGeneration

        // Still "handled" — the catalog has it — but nothing is scrolled to and
        // NOTHING claims it was shown.
        #expect(search.reveal(id: "ts.exit-node-machine"))
        #expect(search.revealTargetID == nil)
        #expect(search.highlightedID == nil)
        #expect(search.revealGeneration == before, "a reveal fired for a row that isn't on screen")
        #expect(search.unavailable?.name == TailscaleSettings.catalog["ts.exit-node-machine"].name)
        #expect(search.unavailable?.reason == search.hiddenReason("ts.exit-node-machine"))

        // A row that IS on screen behaves exactly as before.
        #expect(search.reveal(id: "ts.exit-node"))
        #expect(search.revealTargetID == "ts.exit-node")
        #expect(search.revealGeneration == before + 1)
        #expect(search.unavailable == nil)

        // Turning the gate off (by the user, in the editor) makes it reachable.
        c.useExitNode = true
        search.visibility = SettingVisibility.tailscale(c)
        #expect(search.hiddenReason("ts.exit-node-machine") == nil)
        #expect(search.reveal(id: "ts.exit-node-machine"))
        #expect(search.revealTargetID == "ts.exit-node-machine")
    }

    // MARK: Fixtures

    private static func native(_ kind: VPNKind) -> NativeVPNConfig {
        var c = NativeVPNConfig()
        c.kind = kind
        if kind == .ipsec { c.usesSharedSecret = true }
        return c
    }

    private static func subprocess(_ kind: VPNKind) -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = kind
        return c
    }
}

// MARK: - Every registered spec is on a screen somewhere

/// These two walk the SOURCE. They answer questions about what the views render,
/// which no runtime API can: a `View`'s body can't be enumerated without building
/// and driving the whole hierarchy, and the bug they catch (a spec that is
/// declared, documented, searchable — and on no screen) shipped thirteen times.
@MainActor
struct SettingRenderingTests {

    /// The repo root, from this file's own compile-time path.
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // ControlPlane/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    private static func uiSources() throws -> [String: String] {
        let root = repoRoot.appendingPathComponent("SimpleVPN/UI")
        let e = try #require(FileManager.default.enumerator(at: root,
                                                           includingPropertiesForKeys: nil))
        var out: [String: String] = [:]
        for case let url as URL in e where url.pathExtension == "swift" {
            out[url.lastPathComponent] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        }
        #expect(!out.isEmpty, "no view sources found under \(root.path)")
        return out
    }

    /// EVERY id on EVERY registered surface must be referenced by a view. The
    /// reverse of `ManualAnchorParityTests`: that one proves a spec is documented,
    /// this one proves it is on a screen.
    @Test func everyRegisteredSettingIsRenderedBySomeEditor() throws {
        let sources = try Self.uiSources()
        var unrendered: [String] = []
        for surface in SettingSurface.allCases {
            // A GENERATED catalog is rendered by iteration, not by literal id, so a
            // literal-string scan can't see it. Skipped here and covered by
            // `aGeneratedCatalogIsRenderedByIteration` below, which checks the
            // stronger property: the pane walks the catalog, so a setting cannot be
            // added to it WITHOUT appearing on screen. (A per-id literal scan would
            // be the weaker check for such a surface — it would pass the moment
            // someone pasted the id into a comment.)
            if surface.isAppLevel { continue }
            for setting in surface.settings {
                let needle = "\"\(setting.id)\""
                if !sources.values.contains(where: { $0.contains(needle) }) {
                    unrendered.append(setting.id)
                }
            }
        }
        #expect(unrendered.isEmpty,
                "declared but never rendered — searchable, documented, and on no screen: \(unrendered.sorted().joined(separator: ", "))")
    }

    /// The app-level surface's settings are generated per vendor and per declared
    /// field, so what has to be proved is that its pane ITERATES those two lists —
    /// then every generated setting is on screen by construction, including a future
    /// vendor's.
    @Test func aGeneratedCatalogIsRenderedByIteration() throws {
        let sources = try Self.uiSources()
        let pane = try #require(sources["SignInSourcesSettings.swift"],
                                "the Sign-In Sources pane is missing")
        // The two lists the catalog is generated from.
        #expect(pane.contains("LocalVaultVendor.allCases"),
                "the pane must walk every vendor, or a new vendor ships with no row")
        #expect(pane.contains("SignInSourceSettings.fields(for: vendor)"),
                "the pane must walk each vendor's declared fields")
        // …and it must render them through the shared row idiom, which is what
        // carries the label, summary, manual link and reveal.
        #expect(pane.contains("EngineSettingRow"))
        #expect(pane.contains("EngineSettingLabel"))
        // Every generated id resolves in the catalog the pane subscripts, so no row
        // can look one up and trap.
        for spec in CredentialSourceSettings.all {
            #expect(CredentialSourceSettings.catalog[spec.id].id == spec.id)
        }
    }

    /// THE LANDMINE, checked in the source. `TextField("some example", text:)` passes
    /// the example as the field's TITLE — which `LabeledContent` renders as visible
    /// content and VoiceOver reads as the field's NAME. Twenty-six sites shipped that
    /// way once. The pane pre-fills DETECTED paths, which makes it the most tempting
    /// possible place to do it again, so: every `TextField` in it takes an EMPTY
    /// title, and any example or detection travels as `prompt:`.
    @Test func thePanesFieldsNeverPutAnExampleInTheTitle() throws {
        let sources = try Self.uiSources()
        let pane = try #require(sources["SignInSourcesSettings.swift"])
        var offenders: [String] = []
        for line in pane.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip comments — the file's own header DESCRIBES the bug verbatim, and
            // a scanner that can't tell prose from code would flag the warning
            // against doing it.
            if trimmed.hasPrefix("//") { continue }
            guard let open = trimmed.range(of: "TextField(") else { continue }
            let head = String(trimmed[open.upperBound...])
            // The only sanctioned form: an empty title, with the name supplied by
            // the spec's own label.
            if !head.hasPrefix("\"\", text:") { offenders.append(head) }
        }
        #expect(offenders.isEmpty,
                "a TextField in the Sign-In Sources pane passes a non-empty title, which becomes its VoiceOver name: \(offenders)")
        // …and the pane really does use prompt: for the suggestion.
        #expect(pane.contains("prompt: Text(shown.prompt)"))
    }

    /// THE undefended invariant. `commitCustomRouting` → `syncCustomRoutingProxyAuth`
    /// DELETES the stored proxy credential when both fields are empty, and the tab's
    /// own `onDisappear` commits — so a host that renders `CustomRoutingTabView`
    /// without seeding the fields from the keychain in its `loadOnce` destroys the
    /// credential on the first tab switch, silently. All six hosts do it today; this
    /// is what stops the seventh from not.
    @Test func everyCustomRoutingHostLoadsTheProxySignInFields() throws {
        let sources = try Self.uiSources()
        var offenders: [String] = []
        for (name, text) in sources where text.contains("CustomRoutingTabView(") {
            // The view's own file declares it; the HOSTS instantiate it.
            guard !text.contains("struct CustomRoutingTabView") else { continue }
            if !text.contains("loadCustomRoutingProxyAuthFields(") { offenders.append(name) }
        }
        #expect(offenders.isEmpty,
                "these Custom Routing hosts never load the proxy sign-in, so the first tab switch deletes it: \(offenders.sorted().joined(separator: ", "))")
        // …and the check is only meaningful if it found the hosts at all.
        let hosts = sources.filter { $0.value.contains("CustomRoutingTabView(")
                                     && !$0.value.contains("struct CustomRoutingTabView") }
        #expect(hosts.count == 7, "expected seven Custom Routing hosts, found \(hosts.count)")
    }

    /// MDM `LockConfiguration` must reach the Custom Routing tab in EVERY editor —
    /// the OpenVPN one lacked the modifier, so under a managed lock its routes, DNS
    /// and proxy (including a proxy sign-in written to the keychain) stayed
    /// editable. The guard in `commitCustomRouting`/`setCustomRouting` is the real
    /// enforcement; this is the UI half of it, in all six.
    @Test func everyCustomRoutingHostDisablesUnderAManagedLock() throws {
        let sources = try Self.uiSources()
        var checked = 0
        for (name, text) in sources where text.contains("CustomRoutingTabView(")
            && !text.contains("struct CustomRoutingTabView") {
            // Windowed on purpose: every one of these files mentions
            // `ManagedPolicy.lockConfiguration` SOMEWHERE (the other tabs, the
            // banner), so a whole-file search would have called the OpenVPN editor
            // compliant while its Custom Routing tab was wide open. The modifier
            // has to be on the tab.
            let lines = text.components(separatedBy: "\n")
            guard let call = lines.firstIndex(where: { $0.contains("CustomRoutingTabView(") }) else { continue }
            let window = lines[call..<min(call + 14, lines.count)].joined(separator: "\n")
            #expect(window.contains(".disabled(ManagedPolicy.lockConfiguration)"),
                    "\(name)'s Custom Routing tab isn't disabled under a managed lock")
            checked += 1
        }
        #expect(checked == 7, "expected seven Custom Routing hosts, checked \(checked)")
    }
}
