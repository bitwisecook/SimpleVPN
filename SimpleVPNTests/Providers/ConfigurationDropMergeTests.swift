// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigurationDropMergeTests.swift
//  WHAT A DROP OF SEVERAL FILES DOES, pinned — because the drag gesture itself is
//  unreachable from a unit test and everything BEHIND it must therefore be reachable.
//
//  `ConfigurationKinshipTests` already pins the three categories for one file. These
//  pin the four things a DROP adds, and the one that matters most is the third:
//
//   1. an endpoint-only difference merges;
//   2. a sign-in difference merges the server and leaves the stored sign-in alone;
//   3. A CA OR VERIFICATION DIFFERENCE REFUSES AND OFFERS SEPARATE IMPORT — and it
//      refuses even when it arrives in the same drop as five files that matched,
//      which is the case the UI must make impossible to get wrong;
//   4. several files see each other, so the same server in two downloads is one row.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ConfigurationDropMergeTests {

    /// The IPVanish template, the same one `ConfigurationKinshipTests` uses — the
    /// real file, because the whole idea rests on the measurement that all 3,576 of
    /// theirs are this with one word changed.
    static func ipvanish(server: String, extra: String = "") -> String {
        """
        client
        dev tun
        proto udp
        remote \(server) 443
        resolv-retry infinite
        nobind
        persist-key
        persist-tun
        ca ca.ipvanish.com.crt
        verify-x509-name \(server) name
        auth-user-pass
        verb 3
        auth SHA256
        cipher AES-256-CBC
        \(extra)
        """
    }

    static let mine = ipvanish(server: "ams-c02.ipvanish.com")

    static var existingServers: [VPNEndpoint] {
        [VPNEndpoint(host: "ams-c02.ipvanish.com", port: 443, proto: "udp")]
    }

    static func plan(_ files: [(filename: String, text: String?)],
                     existing: ConfigurationDropMerge.Existing = .openVPN(mine),
                     servers: [VPNEndpoint]? = nil) -> ConfigurationDropMerge.Plan {
        ConfigurationDropMerge.plan(vpnName: "IPVanish",
                                    existing: existing,
                                    existingServers: servers ?? existingServers,
                                    files: files)
    }

    private static func item(_ plan: ConfigurationDropMerge.Plan,
                             named name: String) -> ConfigurationDropMerge.Item? {
        plan.items.first { $0.filename == name }
    }

    // MARK: - 1. The feature

    @Test("a file differing only in its server adds that server")
    func endpointOnlyDifferenceMerges() throws {
        let plan = Self.plan([("lon-c01.ovpn", Self.ipvanish(server: "lon-c01.ipvanish.com"))])
        #expect(plan.serversToAdd.map(\.host) == ["lon-c01.ipvanish.com"])
        #expect(plan.separateImports.isEmpty)
        #expect(!plan.refusesAnythingOnTrust)
        let line = ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "lon-c01.ovpn")))
        #expect(line.contains("lon-c01.ipvanish.com"))
    }

    @Test("a file naming a server the VPN already has adds nothing and says so")
    func alreadyHaveItAddsNothing() throws {
        let plan = Self.plan([("ams-c02.ovpn", Self.mine)])
        #expect(plan.serversToAdd.isEmpty)
        #expect(!plan.addsAnything)
        let line = ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "ams-c02.ovpn")))
        #expect(line.lowercased().contains("already"))
        // A dead button says why, and the reason is not the trust one here.
        #expect(!ConfigurationDropCopy.nothingToAdd(plan).contains("refused"))
    }

    // MARK: - 2. Who you are

    @Test("a sign-in difference adds the server and leaves the stored sign-in alone")
    func signInDifferenceIsReportedNotApplied() throws {
        let plan = Self.plan([("lon-c01.ovpn",
                               Self.ipvanish(server: "lon-c01.ipvanish.com", extra: "auth-nocache"))])
        #expect(plan.serversToAdd.map(\.host) == ["lon-c01.ipvanish.com"])
        #expect(plan.anySignInDiffers, "the difference has to be surfaced, not swallowed")
        let line = ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "lon-c01.ovpn")))
        #expect(line.contains("left alone"),
                "the user must be told their saved sign-in was not replaced")
        // Nothing in the plan carries a sign-in anywhere: what merges is servers.
        #expect(plan.serversToAdd.allSatisfy { $0.label == nil })
    }

    // MARK: - 3. THE ONE THAT MATTERS

    @Test("a different certificate authority refuses and is offered as its own VPN")
    func trustDifferenceRefusesAndOffersSeparateImport() throws {
        let theirs = Self.ipvanish(server: "lon-c01.ipvanish.com")
            .replacingOccurrences(of: "ca ca.ipvanish.com.crt", with: "ca somebody-else.crt")
        let plan = Self.plan([("lon-c01.ovpn", theirs)])
        #expect(plan.serversToAdd.isEmpty, "A DIFFERENT TRUST ANCHOR MUST NEVER MERGE.")
        #expect(plan.refusesAnythingOnTrust)
        #expect(plan.separateImports == [0], "the gesture must not be wasted \u{2014} offer the import")
        let line = ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "lon-c01.ovpn")))
        #expect(line.contains("trusts"))
        #expect(line.contains("Import it on its own"))
        #expect(ConfigurationDropCopy.nothingToAdd(plan).contains("refused"))
    }

    /// Every trust-determining spelling, walked as a table so a future edit that
    /// lets one through fails here rather than in the wild.
    @Test("no trust-determining difference can merge",
          arguments: [("cipher AES-256-CBC", "cipher AES-128-CBC"),
                      ("auth SHA256", "auth SHA1"),
                      ("proto udp", "proto tcp"),
                      ("verify-x509-name lon-c01.ipvanish.com name", "")])
    func noTrustDifferenceMerges(_ change: (from: String, to: String)) {
        let theirs = Self.ipvanish(server: "lon-c01.ipvanish.com")
            .replacingOccurrences(of: change.from, with: change.to)
        let plan = Self.plan([("lon-c01.ovpn", theirs)])
        #expect(plan.serversToAdd.isEmpty,
                "changing \(change.from.debugDescription) must not add a server")
        #expect(plan.refusesAnythingOnTrust)
    }

    /// THE MULTI-FILE CASE THE REQUEST NAMED, and the one a half-merge would ruin:
    /// five good files and one with somebody else's CA in the SAME drop. The five
    /// merge, the sixth is refused, and neither decision leaks into the other.
    @Test("one poisoned file in a drop of six neither merges nor blocks the other five")
    func oneBadFileAmongManyIsIsolated() throws {
        var files: [(filename: String, text: String?)] = []
        for host in ["lon-c01", "par-a01", "fra-a01", "nyc-a01", "syd-a01"] {
            files.append(("\(host).ovpn", Self.ipvanish(server: "\(host).ipvanish.com")))
        }
        files.append(("evil.ovpn",
                      Self.ipvanish(server: "mad-a01.ipvanish.com")
                        .replacingOccurrences(of: "ca ca.ipvanish.com.crt",
                                              with: "ca somebody-else.crt")))
        let plan = Self.plan(files)
        #expect(plan.serversToAdd.count == 5)
        #expect(!plan.serversToAdd.contains { $0.host == "mad-a01.ipvanish.com" },
                "THE REFUSED FILE MUST CONTRIBUTE NOTHING, not even its address.")
        #expect(plan.separateImports == [5])
        // ALL-OR-NOTHING PER FILE: every good file gave its whole contribution.
        #expect(Set(plan.serversToAdd.map(\.host)).count == 5)
    }

    /// Ranked, not alphabetical: the file that needs a decision is first, so it is
    /// not buried under five that do not.
    @Test("the file that needs a decision is listed first")
    func decisionsLeadTheList() throws {
        let plan = Self.plan([
            ("aaa-good.ovpn", Self.ipvanish(server: "lon-c01.ipvanish.com")),
            ("zzz-bad.ovpn", Self.ipvanish(server: "par-a01.ipvanish.com")
                .replacingOccurrences(of: "ca ca.ipvanish.com.crt", with: "ca elsewhere.crt")),
        ])
        #expect(plan.items.first?.filename == "zzz-bad.ovpn")
        #expect(plan.items.first?.refusedOnTrust == true)
    }

    // MARK: - 4. The files see each other

    @Test("the same file dropped twice adds one server, and the second says so")
    func filesSeeEachOther() throws {
        let text = Self.ipvanish(server: "lon-c01.ipvanish.com")
        let plan = Self.plan([("a.ovpn", text), ("b.ovpn", text)])
        #expect(plan.serversToAdd.map(\.host) == ["lon-c01.ipvanish.com"],
                "two downloads of one relay are one server, not a duplicate row")
        let second = try #require(Self.item(plan, named: "b.ovpn"))
        #expect(ConfigurationDropCopy.sentence(second).lowercased().contains("already"))
    }

    // MARK: - Files that are not this VPN at all

    @Test("an unrelated configuration is reported and offered on its own, never merged")
    func unrelatedConfigurationIsOffered() throws {
        let plan = Self.plan([("other.ovpn",
                               Self.ipvanish(server: "lon-c01.ipvanish.com",
                                             extra: "comp-lzo no\ntun-mtu 1200"))])
        #expect(plan.serversToAdd.isEmpty)
        #expect(plan.separateImports == [0])
        #expect(!plan.refusesAnythingOnTrust, "this is 'not this VPN', not 'different trust'")
    }

    @Test("a WireGuard file dropped on an OpenVPN VPN says there is nothing to compare")
    func wrongKindIsSaidRatherThanGuessed() throws {
        let conf = """
            [Interface]
            PrivateKey = qP1+ZbAeMBnHXG0PNq2hFQZi1L3Fm5Vgh7hK7HCQ+2I=
            Address = 10.64.0.2/32
            [Peer]
            PublicKey = ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=
            Endpoint = se-got-wg-001.relays.mullvad.net:51820
            """
        let plan = Self.plan([("relay.conf", conf)])
        #expect(plan.serversToAdd.isEmpty)
        let line = ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "relay.conf")))
        #expect(line.contains("WireGuard"))
        #expect(line.contains("OpenVPN"))
    }

    @Test("an unreadable file is a reported line, never a quietly shorter list")
    func unreadableIsReported() throws {
        let plan = Self.plan([("good.ovpn", Self.ipvanish(server: "lon-c01.ipvanish.com")),
                              ("broken.ovpn", nil)])
        #expect(plan.serversToAdd.count == 1)
        let broken = try #require(Self.item(plan, named: "broken.ovpn"))
        #expect(!broken.offersSeparateImport, "an import cannot read it either")
        #expect(ConfigurationDropCopy.sentence(broken).lowercased().contains("could not read"))
        #expect(ConfigurationDropCopy.summary(plan).contains("unreadable"))
    }

    // MARK: - WireGuard

    /// A second Mullvad `.conf` is the same tunnel reaching another relay, and the
    /// relay's key rides onto the row rather than over the profile's own.
    @Test("a second WireGuard config adds a relay carrying its own public key")
    func wireGuardRelayCarriesItsKey() throws {
        let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
        let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="
        var mine = WireGuardConfig()
        mine.addresses = ["10.64.0.2/32"]
        mine.allowedIPs = ["0.0.0.0/0", "::/0"]
        mine.endpoint = "se-got-wg-001.relays.mullvad.net:51820"
        mine.peerPublicKey = keyA
        let dropped = """
            [Interface]
            PrivateKey = qP1+ZbAeMBnHXG0PNq2hFQZi1L3Fm5Vgh7hK7HCQ+2I=
            Address = 10.64.0.2/32
            [Peer]
            PublicKey = \(keyB)
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = gb-lon-wg-002.relays.mullvad.net:51820
            """
        let plan = ConfigurationDropMerge.plan(
            vpnName: "Mullvad", existing: .wireGuard(mine),
            existingServers: [VPNEndpoint(host: "se-got-wg-001.relays.mullvad.net", port: 51820)],
            files: [("gb-lon.conf", dropped)])
        #expect(plan.serversToAdd.map(\.host) == ["gb-lon-wg-002.relays.mullvad.net"])
        #expect(plan.serversToAdd.first?.peerPublicKey == keyB,
                "the relay's key must travel with its address")
        #expect(ConfigurationDropCopy.sentence(try #require(Self.item(plan, named: "gb-lon.conf")))
            .contains("public key"))
    }

    @Test("a WireGuard config with a different tunnel address refuses")
    func wireGuardDifferentTunnelRefuses() {
        var mine = WireGuardConfig()
        mine.addresses = ["10.64.0.2/32"]
        mine.endpoint = "a.relays.mullvad.net:51820"
        let dropped = """
            [Interface]
            Address = 10.64.9.9/32
            [Peer]
            PublicKey = V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4=
            Endpoint = b.relays.mullvad.net:51820
            """
        let plan = ConfigurationDropMerge.plan(
            vpnName: "Mullvad", existing: .wireGuard(mine),
            existingServers: [VPNEndpoint(host: "a.relays.mullvad.net", port: 51820)],
            files: [("b.conf", dropped)])
        #expect(plan.serversToAdd.isEmpty)
        #expect(plan.refusesAnythingOnTrust)
    }

    // MARK: - The words

    /// Every string this surface can show, so a new one cannot be added outside the
    /// vocabulary checks below without being listed here.
    static var allCopy: [String] {
        let good = plan([("good.ovpn", ipvanish(server: "lon-c01.ipvanish.com"))])
        let bad = plan([("bad.ovpn", ipvanish(server: "lon-c01.ipvanish.com")
            .replacingOccurrences(of: "ca ca.ipvanish.com.crt", with: "ca elsewhere.crt"))])
        let unread = plan([("x.ovpn", nil)])
        var out = [ConfigurationDropCopy.menuTitle,
                   ConfigurationDropCopy.needsAVPN,
                   ConfigurationDropCopy.wrongKindOfVPN("Work"),
                   ConfigurationDropCopy.dropLabel("Work"),
                   ConfigurationDropCopy.title(vpn: "Work"),
                   ConfigurationDropCopy.subtitle(fileCount: 1),
                   ConfigurationDropCopy.subtitle(fileCount: 6),
                   ConfigurationDropCopy.whatItWillNotDo,
                   ConfigurationDropCopy.addTitle(count: 1),
                   ConfigurationDropCopy.addTitle(count: 4),
                   ConfigurationDropCopy.separateImportTitle(count: 1),
                   ConfigurationDropCopy.separateImportTitle(count: 3),
                   ConfigurationDropCopy.nothingToAdd(bad),
                   ConfigurationDropCopy.nothingToAdd(unread),
                   ConfigurationDropCopy.applied(count: 2, vpn: "Work"),
                   ConfigurationDropCopy.declined("Work"),
                   ServersTableCopy.addFromFilesHelp,
                   ServersTableCopy.addFromFilesNoVPN,
                   ServersTableCopy.addFromFilesHint]
        for plan in [good, bad, unread] {
            out.append(ConfigurationDropCopy.summary(plan))
            for item in plan.items {
                out.append(ConfigurationDropCopy.sentence(item))
                out.append(ConfigurationDropCopy.spoken(item))
            }
        }
        return out
    }

    /// ONTOLOGY.md: "credential" is banned from UI copy, the machine a VPN connects
    /// to is a SERVER, and nothing here is a bundle, a pack or a preset.
    @Test("the drop copy keeps the house vocabulary")
    func houseVocabulary() {
        for text in Self.allCopy {
            let lower = text.lowercased()
            for banned in ["credential", "log in", "login", "logon",
                           "bundle", "preset", "endpoint", "profile template"] {
                #expect(!lower.contains(banned),
                        "\(text.debugDescription) uses \(banned.debugDescription) \u{2014} see ONTOLOGY.md")
            }
        }
    }

    /// A row's spoken value IS its visible caption, so nothing on this sheet is
    /// sighted-only (Docs/Accessibility.md).
    @Test("every file's spoken line carries the same sentence the caption shows")
    func nothingIsSightedOnly() {
        let plan = Self.plan([("lon-c01.ovpn", Self.ipvanish(server: "lon-c01.ipvanish.com"))])
        for item in plan.items {
            let spoken = ConfigurationDropCopy.spoken(item)
            #expect(spoken.contains(item.filename))
            #expect(spoken.contains(ConfigurationDropCopy.sentence(item)))
            #expect(!ConfigurationDropCopy.sentence(item).isEmpty)
        }
    }

    // MARK: - Drag is never the only way

    /// The repo root, from this file's own compile-time path (the idiom
    /// `SettingRenderingTests` established).
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Providers/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// EVERY SURFACE THAT ACCEPTS THE DROP ALSO NAMES THE ACTION. This is the reorder
    /// rule applied to the other gesture: a drag-only affordance is unusable without a
    /// pointer, and unlike a wrong label a MISSING alternative is invisible in review.
    ///
    /// Asserted against the sources because the gesture itself is out of reach of any
    /// unit test — which is exactly why the thing beside it must be checkable.
    @Test("every surface with a drop target also offers the named menu equivalent")
    func noSurfaceIsDragOnly() throws {
        let defining = "AddServersFromFilesSheet.swift"
        var checked = 0
        let root = Self.repoRoot.appendingPathComponent("SimpleVPN")
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        while let url = files?.nextObject() as? URL {
            guard url.pathExtension == "swift", url.lastPathComponent != defining else { continue }
            guard let text = try? String(contentsOf: url, encoding: .utf8),
                  text.contains(".serverConfigurationDropTarget(") else { continue }
            checked += 1
            #expect(text.contains("ConfigurationDropCopy.menuTitle"),
                    "\(url.lastPathComponent) accepts a configuration drop but names no pointer-free way to do the same thing \u{2014} Docs/Accessibility.md rule 7")
        }
        #expect(checked >= 2, "expected the sidebars and the servers table to carry drop targets")
    }

    /// The kinds that have no configuration file to compare against take no drop at
    /// all — and the ones that do, do.
    @Test("only the two kinds with a configuration file accept a drop")
    func onlyComparableKindsTakeADrop() {
        #expect(ServerConfigurationRequest.canTake(.openVPN))
        #expect(ServerConfigurationRequest.canTake(.wireGuard))
        for kind in VPNKind.allCases where kind != .openVPN && kind != .wireGuard {
            #expect(!ServerConfigurationRequest.canTake(kind),
                    "\(kind) has no configuration to compare a dropped one against")
        }
    }
}
