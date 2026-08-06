// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OVPNSecretMaterialTests.swift
//  The tests whose ABSENCE is why a private key shipped inside
//  providerConfiguration and out through Export .ovpn….
//
//  `WireGuardTests.neitherKeyReachesThePersistedBlob` had pinned the same property
//  for WireGuard since the day that engine landed. Nothing pinned it for OpenVPN,
//  the raw `.ovpn` was the source of truth, and `OVPNInline.setBlock("key", …)`
//  wrote PEM private keys into it. Every test here exists so that cannot come back
//  quietly: the value tests catch a broken split, and
//  `NoInliningRegressionTests` catches somebody re-adding an inline write at a new
//  call site, which is the shape the original mistake actually had.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - Fixtures

/// A recognisably-shaped .ovpn with everything inline: public certificates AND
/// secret key material, so a test can tell the two apart rather than checking
/// "nothing PEM survived".
private enum OVPNFixture {
    static let privateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLIENTKEYSECRET
        THISMUSTNEVERREACHPROVIDERCONFIGURATIONORANEXPORTEDFILE0123456789
        -----END PRIVATE KEY-----
        """

    static let encryptedKeyPEM = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiENCRYPTEDCLIENTKEYSECRETVALUE0
        -----END ENCRYPTED PRIVATE KEY-----
        """

    static let caPEM = """
        -----BEGIN CERTIFICATE-----
        MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJDQQ
        -----END CERTIFICATE-----
        """

    static let clientCertPEM = """
        -----BEGIN CERTIFICATE-----
        MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJDTA
        -----END CERTIFICATE-----
        """

    /// tls-crypt / tls-auth material. Note the label's MIXED CASE — this is not
    /// an uppercase PEM label, which is exactly what the diagnostic scrubber's
    /// block pass used to miss.
    static let staticKey = """
        -----BEGIN OpenVPN Static key V1-----
        1f8a3c9e0b7d6452aa11bb22cc33dd44
        55ee66ff778899aabbccddeeff001122
        -----END OpenVPN Static key V1-----
        """

    /// The whole file, as a provider would ship it.
    static func ovpn(tlsMode: String = "tls-crypt", key: String = privateKeyPEM) -> String {
        """
        client
        dev tun
        proto udp
        remote vpn.example.com 1194
        remote-cert-tls server
        cipher AES-256-GCM
        verb 3
        <ca>
        \(caPEM)
        </ca>
        <cert>
        \(clientCertPEM)
        </cert>
        <key>
        \(key)
        </key>
        <\(tlsMode)>
        \(staticKey)
        </\(tlsMode)>
        """
    }

    /// Every PEM shape a stored profile must never contain.
    static let forbiddenMarkers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "ENCRYPTED PRIVATE KEY",
        "-----BEGIN OpenVPN Static key V1-----",
    ]
}

// MARK: - What is secret and what is not

struct OVPNSecretClassificationTests {

    /// A tag cannot be in both lists. The two lists are the whole security
    /// decision, so an overlap is not a typo, it is an unanswered question.
    @Test func secretAndPublicTagsDoNotOverlap() {
        let overlap = Set(OVPNSecretMaterial.secretTags)
            .intersection(OVPNSecretMaterial.publicTags)
        #expect(overlap.isEmpty, "a tag is classified both ways: \(overlap.sorted())")
    }

    /// The private key and the TLS key are secret; the CA and the client
    /// certificate are NOT. Pinned via `CertSlot` so that adding a tag to a slot
    /// forces a decision here rather than silently picking a default.
    ///
    /// Treating a certificate as a secret would be a real regression, not a
    /// harmless over-caution: `<ca>` is integrity-critical and has to stay where a
    /// review or a diff can see it, and the Certificates tab needs `<cert>` to tell
    /// the user whether their key matches it.
    @Test func slotsAreClassifiedTheWayTheThreatModelSays() {
        let sample = OVPNFixture.ovpn()
        for tag in OVPNInline.tags(for: .key, in: sample) {
            #expect(OVPNSecretMaterial.secretTags.contains(tag), "\(tag) must be secret")
        }
        for tag in OVPNInline.tags(for: .tlsKey, in: sample) {
            #expect(OVPNSecretMaterial.secretTags.contains(tag), "\(tag) must be secret")
        }
        for slot in [CertSlot.ca, .cert] {
            for tag in OVPNInline.tags(for: slot, in: sample) {
                #expect(OVPNSecretMaterial.publicTags.contains(tag),
                        "\(tag) is a public certificate and must NOT be moved to the keychain")
                #expect(!OVPNSecretMaterial.secretTags.contains(tag))
            }
        }
    }

    /// tls-crypt-v2 and static-key mode are the two easy ones to forget, and both
    /// are symmetric key material.
    @Test func theLessObviousSymmetricSecretsAreCovered() {
        for tag in ["tls-crypt-v2", "secret", "pkcs12", "auth-user-pass", "http-proxy-user-pass"] {
            #expect(OVPNSecretMaterial.secretTags.contains(tag), "\(tag) must be treated as secret")
        }
    }
}

// MARK: - The stored blob is secret-free

struct OVPNStoredProfileTests {

    /// THE test that was missing. A profile imported from an `.ovpn` that had its
    /// key inline stores no PEM private-key marker and no `<key>` / `<tls-crypt>`
    /// block — and the split's `config` IS what is written to
    /// `providerConfiguration["ovpn"]` (pinned by
    /// `NoInliningRegressionTests.theOnlyThingWrittenToProviderConfigurationIsASplitConfig`).
    @Test(arguments: ["tls-crypt", "tls-auth"])
    func theStoredConfigurationCarriesNoPrivateKey(tlsMode: String) {
        let stored = OVPNSecretMaterial.split(OVPNFixture.ovpn(tlsMode: tlsMode)).config

        for marker in OVPNFixture.forbiddenMarkers {
            #expect(!stored.contains(marker), "stored profile still contains \(marker)")
        }
        for tag in ["key", tlsMode] {
            #expect(!stored.contains("<\(tag)>"), "stored profile still has a <\(tag)> block")
            #expect(!stored.contains("</\(tag)>"))
        }
        // Not one byte of either secret's body survives.
        #expect(!stored.contains("CLIENTKEYSECRET"))
        #expect(!stored.contains("1f8a3c9e0b7d6452aa11bb22cc33dd44"))

        // …and the public material is untouched. Stripping a certificate would be
        // its own bug.
        #expect(stored.contains("<ca>"))
        #expect(stored.contains("<cert>"))
        #expect(OVPNInline.block("ca", in: stored) == OVPNFixture.caPEM)
        #expect(OVPNInline.block("cert", in: stored) == OVPNFixture.clientCertPEM)
        // The rest of the configuration is intact.
        #expect(stored.contains("remote vpn.example.com 1194"))
        #expect(stored.contains("remote-cert-tls server"))
    }

    /// An encrypted (password-protected) key is a private key too. It is the shape
    /// where "it already has a password on it" tempts someone into leaving it in.
    @Test func anEncryptedPrivateKeyIsAlsoStrippedOut() {
        let stored = OVPNSecretMaterial.split(OVPNFixture.ovpn(key: OVPNFixture.encryptedKeyPEM)).config
        #expect(!stored.contains("ENCRYPTED PRIVATE KEY"))
        #expect(!stored.contains("ENCRYPTEDCLIENTKEYSECRETVALUE"))
    }

    /// Splitting is idempotent, so a profile that has already been migrated is not
    /// churned on every launch and the marker lines never stack up.
    @Test func splittingAnAlreadySplitProfileChangesNothing() {
        let once = OVPNSecretMaterial.split(OVPNFixture.ovpn())
        let twice = OVPNSecretMaterial.split(once.config)
        #expect(twice.secrets.isEmpty)
        #expect(twice.config == once.config)
    }

    /// A CRLF file is the shape that broke `setBlock` once already.
    @Test func aCRLFProfileIsSplitToo() {
        let crlf = OVPNFixture.ovpn().replacingOccurrences(of: "\n", with: "\r\n")
        let split = OVPNSecretMaterial.split(crlf)
        #expect(split.secrets["key"] == OVPNFixture.privateKeyPEM.replacingOccurrences(of: "\n", with: "\r\n"))
        #expect(!split.config.contains("BEGIN PRIVATE KEY"))
    }

    /// A duplicated secret block leaves NO copy behind. The first one wins (which
    /// is what openvpn3 does with it); the second is removed rather than left in
    /// place as a spare copy of the key.
    @Test func aDuplicatedSecretBlockLeavesNoCopyBehind() {
        let doubled = OVPNFixture.ovpn() + "\n<key>\n\(OVPNFixture.privateKeyPEM)\n</key>\n"
        let split = OVPNSecretMaterial.split(doubled)
        #expect(split.secrets["key"] == OVPNFixture.privateKeyPEM)
        #expect(!split.config.contains("BEGIN PRIVATE KEY"))
        #expect(!split.config.contains("<key>"))
    }
}

// MARK: - Round trip: the engine still gets a complete configuration

struct OVPNSecretRoundTripTests {

    /// Import → the key is retrievable for connect → the stored configuration is
    /// clean. The three halves of the contract in one test, in the order they
    /// happen: `split` at import, the keychain dictionary handed to
    /// `startTunnel(options:)`, and `merge` inside the extension.
    @Test func importThenConnectGetsTheKeyBackWhileStorageStaysClean() {
        let original = OVPNFixture.ovpn()

        // 1. Import: what is persisted, and what goes to the keychain.
        let split = OVPNSecretMaterial.split(original)
        #expect(split.secrets["key"] == OVPNFixture.privateKeyPEM)
        #expect(split.secrets["tls-crypt"] == OVPNFixture.staticKey)
        #expect(!split.config.contains("BEGIN PRIVATE KEY"))

        // 2. Connect: the extension is handed the stored text plus that dictionary.
        let forEngine = OVPNSecretMaterial.merge(split.config, secrets: split.secrets)

        // 3. The engine sees every block back, byte for byte.
        #expect(OVPNInline.block("key", in: forEngine) == OVPNFixture.privateKeyPEM)
        #expect(OVPNInline.block("tls-crypt", in: forEngine) == OVPNFixture.staticKey)
        #expect(OVPNInline.block("ca", in: forEngine) == OVPNFixture.caPEM)
        #expect(OVPNInline.block("cert", in: forEngine) == OVPNFixture.clientCertPEM)
        // No marker line survives into what the engine parses.
        #expect(!forEngine.contains(OVPNSecretMaterial.markerPrefix))
        // Every directive is still there.
        for line in ["client", "dev tun", "proto udp", "remote vpn.example.com 1194",
                     "remote-cert-tls server", "cipher AES-256-GCM", "verb 3"] {
            #expect(forEngine.contains(line), "lost \(line)")
        }
    }

    /// Migration of an already-inline profile is LOSSLESS. This walks the exact
    /// data flow `migrateInlineOVPNSecrets()` performs — write, verify, then rewrite
    /// the stored text — with a dictionary standing in for the keychain, and
    /// compares the reassembled configuration against the original.
    @Test func migratingAnInlineProfileLosesNothing() {
        let before = OVPNFixture.ovpn()

        // write → verify → destroy, in that order.
        let split = OVPNSecretMaterial.split(before)
        var keychain: [String: String] = [:]
        for (tag, body) in split.secrets { keychain[tag] = body }
        #expect(keychain == split.secrets, "the read-back must match, or nothing is destroyed")
        let stored = split.config                       // only now

        let after = OVPNSecretMaterial.merge(stored, secrets: keychain)

        // Same blocks, same bodies, same directives — the text differs only in
        // where the blocks sit, which no OpenVPN parser cares about.
        for tag in ["ca", "cert", "key", "tls-crypt"] {
            #expect(OVPNInline.block(tag, in: after) == OVPNInline.block(tag, in: before),
                    "<\(tag)> changed across migration")
        }
        #expect(Self.directives(before) == Self.directives(after))
    }

    /// split → merge gives the ORIGINAL TEXT BACK, byte for byte. The strongest
    /// form of "lossless", and the reason each block goes back where its marker was
    /// rather than on the end: the Configuration tab shows this text, so a
    /// reassembly that reordered blocks would make the first save of every profile
    /// look like it had rewritten the user's file.
    @Test func splitThenMergeIsTheIdentity() {
        let original = OVPNFixture.ovpn()
        let split = OVPNSecretMaterial.split(original)
        #expect(OVPNSecretMaterial.merge(split.config, secrets: split.secrets) == original)
    }

    /// A block the keychain holds that the stored configuration never marked is
    /// still handed to the engine rather than silently dropped — the shape an older
    /// build's leftovers would take.
    @Test func anUnmarkedKeychainBlockIsStillGivenToTheEngine() {
        let noKey = """
            client
            remote vpn.example.com 1194
            """
        let merged = OVPNSecretMaterial.merge(noKey, secrets: ["key": OVPNFixture.privateKeyPEM])
        #expect(OVPNInline.block("key", in: merged) == OVPNFixture.privateKeyPEM)
        #expect(merged.contains("remote vpn.example.com 1194"))
    }

    /// The engine's own parser reads the same facts off the reassembled text as off
    /// the original. This is the one that matters beyond string equality: the
    /// evaluator derives `autologin` and `privateKeyPasswordRequired` from the
    /// PRESENCE of `<key>`, and `isAutologin` decides whether a certificate-only
    /// profile is allowed to connect with no username or password. A configuration
    /// with a hole in it would have quietly started demanding a password.
    @Test func theEngineParserSeesTheSameProfileAfterAReassembly() {
        let original = OVPNFixture.ovpn()
        let split = OVPNSecretMaterial.split(original)
        let reassembled = OVPNSecretMaterial.merge(split.config, secrets: split.secrets)

        let a = ProfileEvaluation(bridging: OVPNProfileEvaluator.evaluate(original), ovpnText: original)
        let b = ProfileEvaluation(bridging: OVPNProfileEvaluator.evaluate(reassembled), ovpnText: reassembled)
        #expect(a.error == b.error)
        #expect(a.autologin == b.autologin)
        #expect(a.privateKeyPasswordRequired == b.privateKeyPasswordRequired)
        #expect(a.allowPasswordSave == b.allowPasswordSave)
        #expect(a.remoteHostOrNil == b.remoteHostOrNil)
    }

    /// Re-importing the same file after a migration is a DUPLICATE, not a new VPN.
    /// The trap named in the research record: import detects duplicates by hashing
    /// the text, and stripping the key changes that hash.
    @Test func reImportingAMigratedProfileIsStillDetectedAsADuplicate() {
        let original = OVPNFixture.ovpn()
        let split = OVPNSecretMaterial.split(original)

        let incoming = ProfileEvaluation.contentHash(
            of: OVPNSecretMaterial.canonicalIdentityText(original))
        let stored = ProfileEvaluation.contentHash(
            of: OVPNSecretMaterial.canonicalIdentityText(split.config, secrets: split.secrets))
        #expect(incoming == stored)
    }

    /// …and it still tells two profiles apart when the client key is the ONLY
    /// difference, which is a real shape (two people, one gateway). Hashing the
    /// stripped text alone would have collided them.
    @Test func twoProfilesDifferingOnlyInTheirKeyAreNotDuplicates() {
        let a = OVPNSecretMaterial.canonicalIdentityText(OVPNFixture.ovpn())
        let b = OVPNSecretMaterial.canonicalIdentityText(OVPNFixture.ovpn(key: OVPNFixture.encryptedKeyPEM))
        #expect(ProfileEvaluation.contentHash(of: a) != ProfileEvaluation.contentHash(of: b))
        // The identity text is itself secret-free — it is hashed, logged nowhere,
        // but it must not BE a copy of the key.
        #expect(!a.contains("CLIENTKEYSECRET"))
        #expect(!a.contains("BEGIN PRIVATE KEY"))
    }

    /// Removing the key in the Certificates tab really removes it: with nothing to
    /// merge, reassembly does not resurrect a block.
    @Test func clearingTheKeySlotDoesNotComeBackOnReassembly() {
        let stored = OVPNSecretMaterial.split(OVPNFixture.ovpn()).config
        let reassembled = OVPNSecretMaterial.merge(stored, secrets: [:])
        #expect(OVPNInline.block("key", in: reassembled) == nil)
        #expect(!reassembled.contains(OVPNSecretMaterial.markerPrefix))
    }

    private static func directives(_ ovpn: String) -> Set<String> {
        var out: Set<String> = []
        var inBlock = false
        for raw in ovpn.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("</") { inBlock = false; continue }
            if line.hasPrefix("<") { inBlock = true; continue }
            if inBlock || line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            out.insert(line)
        }
        return out
    }
}

// MARK: - Export

struct OVPNExportTests {

    /// `Export .ovpn…` writes no private key. It used to write the user's client
    /// private key to whatever file they chose, unprotected and unannounced.
    @Test(arguments: ["tls-crypt", "tls-auth"])
    func exportContainsNoPrivateKey(tlsMode: String) {
        let stored = OVPNSecretMaterial.split(OVPNFixture.ovpn(tlsMode: tlsMode)).config
        let exported = OVPNSecretMaterial.exportText(stored)

        for marker in OVPNFixture.forbiddenMarkers {
            #expect(!exported.contains(marker), "the exported file contains \(marker)")
        }
        #expect(!exported.contains("CLIENTKEYSECRET"))
        #expect(!exported.contains("1f8a3c9e0b7d6452aa11bb22cc33dd44"))
        #expect(!exported.contains("<key>"))
        #expect(!exported.contains("<\(tlsMode)>"))

        // It says so, in the file: what was left out and what to do about it — and
        // it says it WITHOUT writing the literal `<key>`, so the grep above stays a
        // real check rather than one the note defeats.
        #expect(exported.contains("Left out on purpose"))
        #expect(exported.contains("keychain"))
        #expect(exported.contains("\"key\""))
        // Still a usable configuration for everything that is not a secret.
        #expect(exported.contains("remote vpn.example.com 1194"))
        #expect(OVPNInline.block("ca", in: exported) == OVPNFixture.caPEM)
        #expect(OVPNInline.block("cert", in: exported) == OVPNFixture.clientCertPEM)
        // No leftover marker lines — the note replaces them.
        #expect(!exported.contains(OVPNSecretMaterial.markerPrefix))
    }

    /// Export is safe even for a profile whose migration could NOT be verified and
    /// therefore still has its key inline. The one path where "we already stripped
    /// it upstream" is an assumption, so export does not make it.
    @Test func exportingAnUnmigratedProfileStillOmitsTheKey() {
        let neverMigrated = OVPNFixture.ovpn()
        let exported = OVPNSecretMaterial.exportText(neverMigrated)
        for marker in OVPNFixture.forbiddenMarkers {
            #expect(!exported.contains(marker), "the exported file contains \(marker)")
        }
        #expect(exported.contains("Left out on purpose"))
    }

    /// A profile with nothing secret in it exports unchanged and gains no note —
    /// a username/password VPN should not be told about a key it never had.
    @Test func aProfileWithNoSecretsExportsVerbatim() {
        let plain = """
            client
            remote vpn.example.com 1194
            auth-user-pass
            <ca>
            \(OVPNFixture.caPEM)
            </ca>
            """
        #expect(OVPNSecretMaterial.exportText(plain) == plain)
        #expect(OVPNSecretMaterial.exportOmissionNotice(plain).isEmpty)
    }

    /// The app says it too. A note inside a file nobody reopens is not telling
    /// anyone anything.
    @Test func theAppNamesWhatItLeftOut() {
        let stored = OVPNSecretMaterial.split(OVPNFixture.ovpn()).config
        let notice = OVPNSecretMaterial.exportOmissionNotice(stored)
        // ONTOLOGY house terms — "private key" and "TLS key", not the OpenVPN tag
        // names, and certainly not "credential" (banned from UI copy).
        #expect(notice.contains("private key"))
        #expect(notice.contains("TLS key"))
        #expect(notice.contains("keychain"))
        #expect(!notice.lowercased().contains("credential"))
        #expect(!notice.lowercased().contains("log in"))
        // Names the fix, per ONTOLOGY's rule for any blocked or partial state.
        #expect(notice.contains("what to add back"))
    }
}

// MARK: - The regression guard

/// Scans the sources. These are the tests that would have caught the original bug,
/// because the bug was not a broken function — it was a call site that wrote a
/// private key into the stored configuration and nobody looking.
struct NoInliningRegressionTests {

    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Import/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    private static func sources(_ relative: String...) throws -> [String: String] {
        var out: [String: String] = [:]
        for dir in relative {
            let root = repoRoot.appendingPathComponent(dir)
            let e = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
            for case let url as URL in e where url.pathExtension == "swift" {
                out[url.lastPathComponent] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            }
        }
        #expect(!out.isEmpty, "no sources found")
        return out
    }

    /// NOTHING may write a secret inline block into a string that is on its way to
    /// storage. `OVPNInline.setBlock` is the tool the original bug used, so every
    /// call naming a secret tag has to be in a file that is allowed to hold one.
    ///
    /// If this fails, do not add your file to the list. Route the material through
    /// `OVPNSecretMaterial` — the point is that a new call site has to come and
    /// justify itself here rather than shipping a leak with a green test run.
    @Test func noSourceOutsideTheSanctionedFilesInlinesASecretBlock() throws {
        // OVPNInline.swift IS the mechanism (`merge` re-inserts for the engine).
        // CertificatesTab edits the in-memory draft the editor then hands to
        // updateOVPN, which splits it again before anything is persisted.
        let allowed: Set<String> = ["OVPNInline.swift", "CertificatesTab.swift"]
        var offenders: [String] = []
        for (file, text) in try Self.sources("SimpleVPN", "Shared", "PacketTunnel", "CLI")
        where !allowed.contains(file) {
            for tag in OVPNSecretMaterial.secretTags {
                // WRITES only. Reading a tag is fine and several places do
                // (`ProfileEvaluation` decides `clientCert` from the presence of a
                // `<key>` block) — what must not happen is a secret block being
                // BUILT into a string. Both shapes the original bug could take:
                // through setBlock, or assembled by hand in a literal.
                for needle in ["setBlock(\"\(tag)\"", "<\(tag)>\\n"]
                where text.contains(needle) {
                    offenders.append("\(file): \(needle)")
                }
            }
        }
        #expect(offenders.isEmpty, """
            these write a SECRET inline block outside OVPNSecretMaterial — route it \
            through the split/merge pair instead: \(offenders.sorted().joined(separator: ", "))
            """)
    }

    /// EVERY value that reaches `providerConfiguration`'s `ovpn` key comes from a
    /// split. This is the assertion that lets the value tests above stand in for
    /// "the stored blob": they test `split(_:).config`, and this proves that is what
    /// gets stored.
    ///
    /// Both write shapes are covered, because they are the two the tree actually
    /// uses and the second was invisible to a `["ovpn"] =` scan: subscript
    /// assignment (`conf["ovpn"] = …`, the update path) and a dictionary literal
    /// (`= ["ovpn": …, …]`, the create path).
    @Test func everythingWrittenToProviderConfigurationComesFromASplit() throws {
        /// Right-hand sides that are provably a split's output.
        let sanctioned: Set<String> = ["split.config", "storedOVPN"]
        var writes: [String] = []
        for (file, text) in try Self.sources("SimpleVPN", "Shared", "PacketTunnel", "CLI") {
            for raw in text.components(separatedBy: "\n") {
                let line = raw.trimmingCharacters(in: .whitespaces)
                // Subscript assignment: `…["ovpn"] = rhs`.
                if let eq = line.range(of: "="), !line.contains("=="),
                   line[line.startIndex..<eq.lowerBound].contains("[\"ovpn\"]") {
                    let rhs = line[eq.upperBound...]
                        .trimmingCharacters(in: .whitespaces)
                        .split(separator: ";").first.map(String.init)?
                        .trimmingCharacters(in: .whitespaces) ?? ""
                    if !sanctioned.contains(rhs) { writes.append("\(file): \(line)") }
                }
                // Dictionary literal: `= ["ovpn": rhs, …]`.
                if let key = line.range(of: "\"ovpn\":") {
                    let rhs = line[key.upperBound...]
                        .trimmingCharacters(in: .whitespaces)
                        .split(separator: ",").first.map(String.init)?
                        .trimmingCharacters(in: .whitespaces) ?? ""
                    if !sanctioned.contains(rhs) { writes.append("\(file): \(line)") }
                }
            }
        }
        #expect(writes.isEmpty, """
            a configuration reaches providerConfiguration without going through \
            OVPNSecretMaterial.split: \(writes.sorted().joined(separator: " | "))
            """)
    }

    /// Export must not read the reassembled text. `ovpnText(id:)` deliberately puts
    /// the key back — that is what the engine and the editor need — so an export
    /// path that called it would be the original bug again, exactly.
    @Test func theExportPathDoesNotReadTheReassembledText() throws {
        let sources = try Self.sources("SimpleVPN")
        let manage = try #require(sources["ManageVPNsView.swift"])
        // The one `export(_:)` function, and what it reads.
        let body = try #require(manage.range(of: "private func export(_ p: VPNController.Profile)")
            .map { String(manage[$0.lowerBound...].prefix(700)) })
        #expect(body.contains("exportableOVPNText"))
        #expect(!body.contains("vpn.ovpnText("),
                "Export .ovpn… is reading the reassembled configuration — it would write the private key out again")
    }

    /// The connect handoff is a STRING contract across a process boundary: the app
    /// writes the option, the extension reads it. A rename on one side alone would
    /// silently stop re-inserting the key and show up as an opaque TLS failure.
    @Test func bothSidesOfTheConnectHandoffAgreeOnTheOptionName() throws {
        let sources = try Self.sources("SimpleVPN", "PacketTunnel")
        let app = try #require(sources["VPNController+Connect.swift"])
        let ext = try #require(sources["PacketTunnelProvider.swift"])
        #expect(app.contains("options[\"ovpnInlineSecrets\"]"))
        #expect(ext.contains("options?[\"ovpnInlineSecrets\"]"))
    }

    /// Migration writes and VERIFIES before it destroys. Pinned in the source
    /// because the ordering is the whole safety property and it is invisible in the
    /// values: `saveAndVerifyOVPNInlineSecrets` must be the guard on the rewrite,
    /// never called after it.
    @Test func migrationVerifiesBeforeItDestroys() throws {
        let crud = try #require(try Self.sources("SimpleVPN")["VPNController+CRUD.swift"])
        let migrate = try #require(crud.range(of: "func migrateInlineOVPNSecrets()")
            .map { String(crud[$0.lowerBound...]) })
        let verify = try #require(migrate.range(of: "saveAndVerifyOVPNInlineSecrets"))
        let rewrite = try #require(migrate.range(of: "conf[\"ovpn\"] = split.config"))
        #expect(verify.lowerBound < rewrite.lowerBound,
                "the stored configuration is rewritten before the keychain copy is verified")
        // …and the verify is a guard, so a false result cannot fall through.
        let guardLine = migrate[migrate.range(of: "saveAndVerifyOVPNInlineSecrets")!.lowerBound...]
        #expect(String(guardLine.prefix(0)) == "")
        #expect(migrate.contains("guard KeychainCredentialStore.saveAndVerifyOVPNInlineSecrets"))
    }
}
