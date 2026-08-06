// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardExportTests.swift
//  What `Export .conf…` writes, and what it takes to make it write a key.
//
//  THE SAME SHAPE AS `SimpleVPNTests/Portability/`'s exclusion tests, on purpose:
//  a CANARY value that is present in what the exporter is handed and must not reach
//  the file, plus its OVER-REDACTION COUNTERPART — the public material that must
//  survive, because a redactor that eats the endpoint and the peer's public key has
//  failed just as surely as one that writes the private key out.
//
//  WHY THIS IS NOT THE `.ovpn` ANSWER. `OVPNSecretMaterial.exportText` omits with no
//  opt-out. `wg-quick` refuses a configuration that has no private key, and a
//  WireGuard public key is DERIVED from the private one and registered against the
//  peer server-side, so "ask them to reissue it" is not a thing the user can do
//  alone. Omission-with-no-opt-out would mean a working WireGuard VPN can never be
//  moved to a phone. The decision is explicit consent — with the DEFAULT still the
//  safe one, which is what most of this file exists to hold in place.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Fixture

/// One config whose secrets ARE present, the way an editor draft holds them after
/// `withSecretsFromKeychain()`. Canaries are distinctive strings so a leak is
/// unambiguous, and the public values are equally distinctive so over-redaction is
/// too.
enum WireGuardExportFixture {
    static let privateKeyCanary = "CANARY-WG-PRIVATE-KEY-a91f="
    static let presharedKeyCanary = "CANARY-WG-PRESHARED-KEY-77c2="
    static let peerPublicKey = "PUBLIC-PEER-KEY-1234="
    static let endpoint = "vpn.example.com:51820"

    static func config(presharedKey: String = presharedKeyCanary,
                       privateKey: String = privateKeyCanary) -> WireGuardConfig {
        var c = WireGuardConfig()
        c.name = "Office WireGuard"
        c.privateKey = privateKey
        c.presharedKey = presharedKey
        c.peerPublicKey = peerPublicKey
        c.endpoint = endpoint
        c.addresses = ["10.7.0.2/32"]
        c.dns = ["10.7.0.53"]
        c.allowedIPs = ["10.7.0.0/24"]
        c.mtu = 1380
        c.persistentKeepalive = 25
        c.table = "main"
        c.fwMark = "0xff"
        return c
    }

    /// Strings that must never appear in a secret-free export. The wg-quick key
    /// NAMES are in here as well as the values, for the same reason
    /// `OVPNSecretMaterial` never writes the literal `<key>`: keeping the token out
    /// of the file entirely is what makes a plain grep a real check rather than one
    /// the explanatory header defeats.
    static let forbiddenInASecretFreeFile = [
        privateKeyCanary, presharedKeyCanary, "PrivateKey", "PresharedKey",
    ]
}

// MARK: - The default export

struct WireGuardSecretFreeExportTests {

    /// THE test this change exists to pass. `Export .conf…` wrote `PrivateKey` and
    /// `PresharedKey` in the clear to whatever file the user chose.
    @Test func theDefaultExportContainsNeitherKey() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: false)
        for needle in WireGuardExportFixture.forbiddenInASecretFreeFile {
            #expect(!text.contains(needle), "the exported file contains \(needle)")
        }
    }

    /// …and the other direction, which matters just as much: everything PUBLIC
    /// survives. A file that lost the endpoint or the peer's public key would be a
    /// redactor that had eaten the configuration, and the export would be pointless.
    @Test func everythingPublicSurvives() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: false)
        #expect(text.contains("PublicKey = \(WireGuardExportFixture.peerPublicKey)"))
        #expect(text.contains("Endpoint = \(WireGuardExportFixture.endpoint)"))
        #expect(text.contains("Address = 10.7.0.2/32"))
        #expect(text.contains("AllowedIPs = 10.7.0.0/24"))
        #expect(text.contains("DNS = 10.7.0.53"))
        #expect(text.contains("MTU = 1380"))
        #expect(text.contains("PersistentKeepalive = 25"))
        // The two export-only settings are the whole reason they are editable.
        #expect(text.contains("Table = main"))
        #expect(text.contains("FwMark = 0xff"))
        // Still a wg-quick file, not a fragment.
        #expect(text.contains("[Interface]"))
        #expect(text.contains("[Peer]"))
    }

    /// THE FILE SAYS WHAT IT CONTAINS — the `.ovpn` exporter's precedent, and the
    /// half of the consent that survives the file being forwarded, renamed or found
    /// in a backup by somebody who never saw a dialog. It has to say the receiving
    /// client will REFUSE the file, because that is the difference from an `.ovpn`.
    @Test func theFileSaysWhatItLeftOutAndThatWgQuickWillRefuseIt() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: false)
        #expect(text.contains("No secrets are in this file"))
        #expect(text.contains("Left out on purpose"))
        #expect(text.contains("private key"))
        #expect(text.contains("pre-shared key"))
        #expect(text.contains("keychain"))
        #expect(text.contains("wg-quick REFUSES"))
        // Named where each one belongs, not only once at the top.
        #expect(text.contains(WireGuardConfig.secretMarker(for: "privateKey")))
        #expect(text.contains(WireGuardConfig.secretMarker(for: "presharedKey")))
    }

    /// A marker goes under the SECTION its key belongs to. Anywhere else and it is
    /// telling the reader to paste a private key into the peer block.
    @Test func eachMarkerSitsUnderItsOwnSection() throws {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: false)
        let interface = try #require(text.range(of: "[Interface]"))
        let peer = try #require(text.range(of: "[Peer]"))
        let priv = try #require(text.range(of: WireGuardConfig.secretMarker(for: "privateKey")))
        let psk = try #require(text.range(of: WireGuardConfig.secretMarker(for: "presharedKey")))
        #expect(interface.upperBound < priv.lowerBound)
        #expect(priv.upperBound < peer.lowerBound)
        #expect(peer.upperBound < psk.lowerBound)
    }

    /// A key that was never set is nothing to explain. Same rule as the JSON/YAML
    /// exporter: a file full of notes about keys that were never there is noise that
    /// hides the note that matters.
    @Test func anUnsetKeyRaisesNoNote() {
        let text = WireGuardExportFixture.config(presharedKey: "")
            .exportText(includingSecrets: false)
        #expect(!text.contains("pre-shared key"))
        #expect(text.contains("private key"))
        #expect(!text.contains(WireGuardConfig.secretMarker(for: "presharedKey")))
    }

    /// A configuration with NO secrets in it at all exports verbatim — no header, no
    /// markers. This is the normal shape of a stored config (both keys live in the
    /// keychain), so a lecture here would appear on the common path.
    @Test func aConfigWithNoSecretsExportsVerbatim() {
        let c = WireGuardExportFixture.config(presharedKey: "", privateKey: "")
        #expect(c.exportText(includingSecrets: false) == c.serialize())
        #expect(c.exportText(includingSecrets: true) == c.serialize())
        #expect(c.exportOmissionNotice.isEmpty)
        #expect(c.presentSecretFields.isEmpty)
    }

    /// `includingSecrets: false` is the DEFAULT in the strongest available sense:
    /// the redacted body is exactly `redactedForStorage()`'s, which is the same
    /// function that guards `providerConfiguration`. One redaction, two callers.
    @Test func theRedactedBodyIsTheSameRedactionStorageUses() {
        let c = WireGuardExportFixture.config()
        let exported = c.exportText(includingSecrets: false)
        for line in c.redactedForStorage().serialize().components(separatedBy: "\n")
        where !line.isEmpty {
            #expect(exported.contains(line), "the exported file dropped \(line)")
        }
    }

    /// The app says it too, in the user's language and the house vocabulary. A note
    /// inside a file nobody reopens is not telling anyone anything.
    @Test func theAppNamesWhatItLeftOut() {
        let notice = WireGuardExportFixture.config().exportOmissionNotice
        #expect(notice.contains("private key"))
        #expect(notice.contains("pre-shared key"))
        #expect(notice.contains("keychain"))
        // Names the consequence and the fix, per ONTOLOGY's rule for a partial state.
        #expect(notice.contains("wg-quick refuses"))
        #expect(notice.contains("paste one back in"))
        // Banned from UI copy, and asserted rather than assumed.
        #expect(!notice.lowercased().contains("credential"))
        #expect(!notice.lowercased().contains("log in"))
        // Never the wg-quick token, so the grep in the tests above stays honest.
        #expect(!notice.contains("PrivateKey"))
    }
}

// MARK: - The consenting export

struct WireGuardConsentedExportTests {

    /// The opt-in really does write the keys — otherwise the consent is theatre and
    /// the user is handed a file that silently does not work.
    @Test func theConsentedExportWritesBothKeys() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: true)
        #expect(text.contains("PrivateKey = \(WireGuardExportFixture.privateKeyCanary)"))
        #expect(text.contains("PresharedKey = \(WireGuardExportFixture.presharedKeyCanary)"))
        #expect(text.contains("PublicKey = \(WireGuardExportFixture.peerPublicKey)"))
    }

    /// …and it says so in the FILE, in capitals. This is the part that still works
    /// when the file has been forwarded twice and nobody remembers the dialog.
    @Test func theFileAdmitsWhatItCarries() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: true)
        #expect(text.contains("THIS FILE CONTAINS SECRETS"))
        #expect(text.contains("private key"))
        #expect(text.contains("pre-shared key"))
        #expect(text.contains("connect to this VPN as this Mac"))
        #expect(text.contains("cannot be recalled"))
        #expect(text.contains("Delete it"))
        // It must NOT claim to be secret-free.
        #expect(!text.contains("No secrets are in this file"))
    }

    /// THE CONSENT IS SPECIFIC, not "are you sure". Named material, the concrete
    /// consequence, the irrevocability, and the safe alternative — because a generic
    /// dialog is exactly the thing people click through.
    @Test func theConsentSaysWhatIsInTheFileAndWhatThatMeans() {
        let c = WireGuardExportFixture.config()
        #expect(c.exportConsentTitle.contains("private key"))
        #expect(c.exportConsentTitle.contains("pre-shared key"))
        let message = c.exportConsentMessage
        #expect(message.contains("in the clear"))
        #expect(message.contains("connect to this VPN as this Mac"))
        #expect(message.contains("cannot be recalled"))
        #expect(message.contains("Delete it"))
        // Points at the safe action rather than only warning about this one.
        #expect(message.contains("Export .conf"))
        // No generic "are you sure" anywhere, and no banned vocabulary.
        #expect(!message.lowercased().contains("are you sure"))
        #expect(!message.lowercased().contains("credential"))
        #expect(!c.exportConsentTitle.lowercased().contains("credential"))
    }

    /// The confirming button SAYS WHAT IT DOES. "OK" beside a warning is how a
    /// warning gets dismissed without being read.
    @Test func theConfirmingButtonNamesTheAction() {
        #expect(WireGuardExportFixture.config().exportConsentConfirmTitle == "Export With Keys")
        #expect(WireGuardExportFixture.config(presharedKey: "").exportConsentConfirmTitle
                == "Export With Private Key")
        // And it is never a bare acknowledgement.
        for c in [WireGuardExportFixture.config(), WireGuardExportFixture.config(presharedKey: "")] {
            #expect(c.exportConsentConfirmTitle != "OK")
            #expect(c.exportConsentConfirmTitle.contains("Export"))
        }
    }

    /// The consent only ever promises what is actually there: a VPN with no
    /// pre-shared key must not be told a pre-shared key is about to be written.
    @Test func theConsentNamesOnlyTheKeysThatExist() {
        let c = WireGuardExportFixture.config(presharedKey: "")
        #expect(!c.exportConsentTitle.contains("pre-shared"))
        #expect(!c.exportConsentMessage.contains("pre-shared"))
        #expect(c.presentSecretFields == ["privateKey"])
    }
}

// MARK: - The classification is one list

struct WireGuardSecretClassificationTests {

    /// `WireGuardConfig.secretFieldNames` and the JSON/YAML exporter's
    /// `ConfigSecrets.secretFields` are two lists in two targets, because `Shared/`
    /// cannot see the app target. They must AGREE — a field secret in one exporter
    /// and public in the other is a leak with a passing test suite.
    @Test func bothExportersClassifyTheSameFieldsAsSecret() {
        for field in WireGuardConfig.secretFieldNames {
            #expect(ConfigSecrets.secretFields.contains(field),
                    "\(field) is secret to the .conf exporter and not to ConfigSecrets")
            #expect(ConfigSecrets.isSecret(field))
        }
    }

    /// …and they call them the same THING. One VPN's key described two ways in two
    /// exported files is how a user stops trusting either.
    @Test func bothExportersUseTheSameHouseTerms() {
        for field in WireGuardConfig.secretFieldNames {
            #expect(WireGuardConfig.humanName(forSecretField: field)
                    == ConfigSecrets.humanName(field), "\(field) is named two ways")
        }
    }

    /// The list is TOTAL over the type: every field of `WireGuardConfig` whose name
    /// looks like a secret is on it. A `rotationPassword` added next year fails this
    /// until somebody classifies it — the same guard `ConfigSecretExclusionTests`
    /// applies, aimed at the `.conf` exporter's own list.
    @Test func everySuspiciousFieldOfTheConfigIsOnTheList() {
        var unclassified: [String] = []
        for (name, _) in Mirror(reflecting: WireGuardConfig()).children {
            guard let name else { continue }
            let lower = name.lowercased()
            guard ConfigSecrets.suspiciousFragments.contains(where: { lower.contains($0) }) else { continue }
            // "peerPublicKey" contains no suspicious fragment; anything that does
            // must be either withheld by the .conf exporter or reviewed as safe.
            if !WireGuardConfig.secretFieldNames.contains(name),
               ConfigSecrets.reviewedNotSecret[name] == nil {
                unclassified.append(name)
            }
        }
        #expect(unclassified.isEmpty,
                "these WireGuardConfig fields look like secrets and the .conf exporter does not withhold them: \(unclassified.sorted().joined(separator: ", "))")
    }

    /// A field on the list really is withheld at RUNTIME, not merely named. The list
    /// and the redaction are two things and only the second one protects anybody.
    @Test func everyListedFieldIsActuallyWithheld() {
        let text = WireGuardExportFixture.config().exportText(includingSecrets: false)
        #expect(WireGuardConfig.secretFieldNames == ["privateKey", "presharedKey"])
        #expect(!text.contains(WireGuardExportFixture.privateKeyCanary))
        #expect(!text.contains(WireGuardExportFixture.presharedKeyCanary))
        #expect(WireGuardExportFixture.config().presentSecretFields
                == WireGuardConfig.secretFieldNames)
    }
}

// MARK: - The regression guard on the call site

/// Scans the source. The original bug was not a broken function — it was a call site
/// that wrote `serialize()` to a user-chosen file with nobody looking, exactly the
/// shape `NoInliningRegressionTests` was written for on the OpenVPN side.
struct WireGuardExportCallSiteTests {

    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Import/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    private static func source(_ relative: String) throws -> String {
        try String(contentsOf: repoRoot.appendingPathComponent(relative), encoding: .utf8)
    }

    /// Nothing writes a raw `serialize()` to a FILE. `serialize()` is the round-trip
    /// and engine-facing form and it keeps the keys deliberately; the only thing that
    /// may reach a user-chosen URL is `exportText(includingSecrets:)`, which is where
    /// the decision and the header live.
    @Test func nothingWritesARawSerializeToAFile() throws {
        var offenders: [String] = []
        for dir in ["SimpleVPN", "Shared", "PacketTunnel", "CLI"] {
            let root = Self.repoRoot.appendingPathComponent(dir)
            let e = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
            for case let url as URL in e where url.pathExtension == "swift" {
                let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
                for raw in text.components(separatedBy: "\n") {
                    let line = raw.trimmingCharacters(in: .whitespaces)
                    guard line.contains(".serialize()"), line.contains(".write(to:") else { continue }
                    offenders.append("\(url.lastPathComponent): \(line)")
                }
            }
        }
        #expect(offenders.isEmpty, """
            a WireGuard configuration is written to a file without going through \
            exportText(includingSecrets:): \(offenders.sorted().joined(separator: " | "))
            """)
    }

    /// THE DEFAULT IS NEVER THE LEAKY ONE. The plain `Export .conf…` button passes
    /// `includingSecrets: false`, and only the separately-named action can pass
    /// `true` — so there is no dialog whose default button produces a file with a
    /// key in it.
    /// THE HOST MOVED, THE INVARIANTS DID NOT. Both exports used to be buttons in a
    /// section of `WireGuardView`; they are now items in the VPN's own context menu in
    /// `ManageVPNsView`, because a toolbar or a pane acts on the WINDOW while a
    /// right-click acts on the OBJECT. Everything below is the same guard against the
    /// same bug, pointed at the new call site.
    private static let exportHost = "SimpleVPN/UI/Editors/ManageVPNsView.swift"

    @Test func onlyTheConsentedActionAsksForSecrets() throws {
        let view = try Self.source(Self.exportHost)
        #expect(view.contains("Button(\"Export .conf\\u{2026}\") { exportWireGuard(p.id, includingSecrets: false) }"))
        // The one `includingSecrets: true` is inside the confirmation's own button.
        let consented = view.components(separatedBy: "includingSecrets: true")
        #expect(consented.count == 2, "there is more than one consented export call site")
        let before = try #require(consented.first)
        let dialog = try #require(before.range(of: ".confirmationDialog(wgConsentTarget?.exportConsentTitle"))
        #expect(dialog.upperBound < before.endIndex)
        // …and it is the DESTRUCTIVE role, with nothing claiming the default action:
        // Return and Escape must both cancel.
        #expect(before.contains("role: .destructive"))
        #expect(!view.contains("Button(c.exportConsentConfirmTitle) "))
    }

    /// The consent is asked BEFORE the save panel. Asking after the user has already
    /// named a file makes the question read as a formality on the way to a file they
    /// have decided to create.
    @Test func consentComesBeforeTheSavePanel() throws {
        let view = try Self.source(Self.exportHost)
        #expect(view.contains("Button(\"Export .conf with Keys\\u{2026}\") { wgKeyExportTarget = p.id }"))
        let export = try #require(view.range(of: "private func exportWireGuard(_ id: String, includingSecrets: Bool)")
            .map { String(view[$0.lowerBound...]) })
        // The panel is inside exportWireGuard(); the consent gate is outside it, on the
        // menu item.
        #expect(export.contains("NSSavePanel()"))
        #expect(!export.contains("wgKeyExportTarget = p.id"))
    }

    /// KIND-AWARENESS, which is the other half of the move. `.ovpn` is OpenVPN's format
    /// and `.conf` is WireGuard's; a kind with no interchange format is offered
    /// NOTHING, never a disabled item — an F5 BIG-IP APM page offering "Export .ovpn…"
    /// is what prompted this ("what's the >> Export ovpn doing on an f5 APM page").
    @Test func exportIsOfferedOnlyWhereAFormatExists() throws {
        let view = try Self.source(Self.exportHost)
        // The `.ovpn` item is inside the kind-aware builder…
        let items = try #require(view.range(of: "private func exportItems(for p: VPNController.Profile)")
            .map { String(view[$0.lowerBound...]) })
        #expect(items.contains("Export .ovpn"))
        #expect(items.contains("vpn.isWireGuard(p.id)"))
        // …the kinds with no format are named and given EmptyView…
        #expect(items.contains("vpn.isTailscale(p.id) || vpn.isProxyTunnel(p.id) || vpn.isSSHNetworkTunnel(p.id)"))
        // …and the subprocess and native rows never offer one at all, so an SSL-VPN
        // (F5 APM, FortiGate, AnyConnect…) cannot be handed an .ovpn action.
        for row in ["private func tunnelRow(", "private func nativeRow("] {
            let start = try #require(view.range(of: row))
            let body = String(view[start.lowerBound...]).components(separatedBy: "\n    @ViewBuilder").first ?? ""
            #expect(!body.contains("exportItems"), "\(row) offers an export it has no format for")
            #expect(!body.contains("Export ."), "\(row) offers an export it has no format for")
        }
        // And the toolbar no longer carries one: it acted on the window, not the object.
        #expect(!view.contains("Button(\"Export .ovpn\\u{2026}\") {\n                        if let p ="))
    }
}
