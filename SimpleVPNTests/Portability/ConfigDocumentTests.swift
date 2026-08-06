// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigDocumentTests.swift
//  The whole-configuration export/import file: its grammar, its round trip, what it
//  refuses, and — the one that matters most — the PROOF that it carries no secrets.
//
//  `ConfigSecretExclusionTests` below is the load-bearing suite. It builds a
//  configuration whose keychain-held material is deliberately present in the
//  snapshot handed to the exporter (an inline `<key>`, an inline `<auth-user-pass>`,
//  a WireGuard private key and a pre-shared key) and asserts that none of it
//  appears in either encoding. The exporter has to SCRUB what it is given rather
//  than trust its caller — which is the difference between "we don't put secrets in"
//  and "there is no path that puts secrets in".
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - The value tree and its two encodings

@MainActor
struct ConfigCodingTests {

    /// One model, two encoders: a tree written as YAML and as JSON, read back
    /// either way, is the same tree. This is the property that stops the two
    /// halves drifting.
    @Test func bothEncodingsRoundTripTheSameTree() throws {
        var inner = ConfigMap()
        inner.put("wg.endpoint", .string("vpn.example.com:51820"))
        inner.put("wg.mtu", .int(1380))
        inner.put("wg.allowed-ips", .strings(["0.0.0.0/0", "::/0"]))
        inner.put("openvpn.compression", .string("no"))   // must NOT read back as false
        inner.put("empty-map", .map(ConfigMap()))
        inner.put("empty-list", .list([]))
        inner.put("negative", .int(-1))
        inner.put("colour", .double(0.78))
        inner.put("flag", .bool(true))
        inner.put("configuration", .document("client\nremote vpn.example.com 1197\n# a comment\n\nverb 3"))

        var root = ConfigMap()
        root.put("format", .int(ConfigFormat.current))
        root.put("settings", .map(inner))
        root.put("vpns", .list([.map(inner), .map(inner)]))

        let yaml = ConfigYAML.encode(root, leadingComments: ["a header", "", "another line"])
        let json = ConfigJSON.encode(root, leadingComments: ["a header"])

        let fromYAML = try ConfigYAML.decode(yaml)
        #expect(fromYAML == root, "YAML did not round-trip")

        var fromJSON = try ConfigJSON.decode(json)
        // JSON has no comments, so the header rides in a "_readme" member — dropped
        // before comparing, since it is documentation rather than data.
        fromJSON[ConfigDocumentKeys.readme] = nil
        #expect(fromJSON["format"] == root["format"])
        #expect(fromJSON["settings"]?.mapValue?["openvpn.compression"] == .string("no"))
        #expect(fromJSON["settings"]?.mapValue?["configuration"] == root["settings"]?.mapValue?["configuration"])
    }

    /// The one YAML trap this format walks into constantly: OpenVPN's own tokens
    /// `no` and `yes` are settings VALUES, and unquoted they are booleans.
    @Test func openVPNsOwnNoTokenSurvivesAsText() throws {
        var m = ConfigMap()
        m.put("openvpn.compression", .string("no"))
        m.put("a-real-boolean", .bool(false))
        let yaml = ConfigYAML.encode(m)
        #expect(yaml.contains("openvpn.compression: \"no\""))
        let back = try ConfigYAML.decode(yaml)
        #expect(back["openvpn.compression"] == .string("no"))
        #expect(back["a-real-boolean"] == .bool(false))
    }

    /// A host:port in a list is not a mapping. Without the "a colon only ends a key
    /// when a space follows it" rule, a list of servers parses as a list of records.
    @Test func hostAndPortInAListIsNotAMapping() throws {
        var m = ConfigMap()
        m.put("servers", .strings(["vpn.example.com:1194", "10.0.0.1:443"]))
        let back = try ConfigYAML.decode(ConfigYAML.encode(m))
        #expect(back["servers"]?.stringList == ["vpn.example.com:1194", "10.0.0.1:443"])
    }

    /// A multi-line `.ovpn` rides as a block scalar, so the file shows the
    /// configuration as a configuration rather than as one enormous escaped line.
    @Test func anOVPNRidesAsAReadableBlock() throws {
        let ovpn = "client\ndev tun\nremote vpn.example.com 1197 udp\n<ca>\nMIIB\n</ca>"
        var m = ConfigMap()
        m.put("openvpn-configuration", .document(ovpn))
        let yaml = ConfigYAML.encode(m)
        #expect(yaml.contains("openvpn-configuration: |-"))
        #expect(yaml.contains("  remote vpn.example.com 1197 udp"))
        #expect(try ConfigYAML.decode(yaml)["openvpn-configuration"] == .text(ovpn))
    }

    /// A comment inside an embedded configuration is part of THAT file and must
    /// survive; a comment in our own document is not data.
    @Test func commentsInsideABlockSurviveAndOursDoNot() throws {
        let ovpn = "client\n# GR Lab\nverb 3"
        var m = ConfigMap()
        m.put("openvpn-configuration", .document(ovpn))
        let yaml = "# our own comment\n\n" + ConfigYAML.encode(m)
        let back = try ConfigYAML.decode(yaml)
        #expect(back.keys == ["openvpn-configuration"])
        #expect(back["openvpn-configuration"]?.stringValue?.contains("# GR Lab") == true)
    }

    /// Text a block scalar cannot carry FAITHFULLY falls back to a quoted string
    /// rather than being written out lossily. A `.ovpn` with an indented line or a
    /// trailing space on one is a real thing to be handed, and "readable" must never
    /// win over "exact".
    @Test func textABlockCannotHoldFallsBackToAQuotedString() throws {
        for awkward in ["  indented first line\nclient\nverb 3",
                        "client\ntrailing space \nverb 3",
                        "client\r\nverb 3"] {
            var m = ConfigMap()
            m.put("openvpn-configuration", .document(awkward))
            let yaml = ConfigYAML.encode(m)
            #expect(!yaml.contains("|-"), "an awkward document was written as a block")
            #expect(yaml.components(separatedBy: "\n").filter { !$0.isEmpty }.count == 1,
                    "an awkward document spilled onto a second line")
            #expect(try ConfigYAML.decode(yaml) == m, "an awkward document did not round-trip")
        }
    }

    /// A Mac with nothing configured still produces a valid, readable file that
    /// imports as "this would change nothing" rather than as an error.
    @Test func anEmptyConfigurationStillProducesAValidFile() {
        let text = ConfigDocument.text(from: ConfigSnapshot(), format: .yaml)
        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        #expect(plan.fatal.isEmpty)
        #expect(plan.refusals.isEmpty)
        #expect(!plan.isApplicable)
        #expect(plan.summary == "Nothing in this file would change anything.")
    }

    /// The accepted grammar is deliberately small, and everything outside it is
    /// REFUSED with a line number rather than guessed at. An imported document is a
    /// file from outside every protection the app has.
    @Test func yamlOutsideTheAcceptedSubsetIsRefused() {
        let cases = [
            "base: &anchor\n  a: 1\nother: *anchor\n",
            "settings: { a: 1, b: 2 }\n",
            "list: [1, 2, 3]\n",
            "---\nformat: 1\n",
            "value: !!binary AAAA\n",
            "text: >\n  folded\n",
            "format: 1\n\tbad: 2\n",
        ]
        for text in cases {
            #expect(throws: (any Error).self) { try ConfigYAML.decode(text) }
        }
    }

    @Test func anEmptyOrNonMapFileIsRefused() {
        #expect(throws: (any Error).self) { try ConfigYAML.decode("\n\n# nothing\n") }
        #expect(throws: (any Error).self) { try ConfigJSON.decode("[1,2,3]") }
        #expect(throws: (any Error).self) { try ConfigJSON.decode("{ not json") }
    }

    /// Either encoding is accepted whatever the file is called: a person who saved
    /// JSON as ".yaml" has made a naming mistake, not an unreadable file.
    @Test func eitherEncodingIsAcceptedRegardlessOfTheName() throws {
        var m = ConfigMap()
        m.put("format", .int(1))
        let json = ConfigJSON.encode(m)
        let yaml = ConfigYAML.encode(m)
        #expect(try ConfigImport.parse(json)["format"] == .int(1))
        #expect(try ConfigImport.parse(yaml)["format"] == .int(1))
    }
}

// MARK: - Fixtures

@MainActor
enum ConfigTestFixture {

    static let password = "CANARY-PASSWORD-8f2a"
    static let privateKeyPEM = """
    -----BEGIN PRIVATE KEY-----
    CANARY-OVPN-PRIVATE-KEY-4c1d
    -----END PRIVATE KEY-----
    """
    static let caPEM = """
    -----BEGIN CERTIFICATE-----
    PUBLIC-CA-CERTIFICATE-9911
    -----END CERTIFICATE-----
    """
    static let wireGuardPrivateKey = "CANARYwgPrivateKeyAAAAAAAAAAAAAAAAAAAAAAAAAA="
    static let wireGuardPresharedKey = "CANARYwgPresharedKeyAAAAAAAAAAAAAAAAAAAAAAAA="
    static let tlsCryptKey = "CANARY-TLS-CRYPT-KEY-7d3e"

    /// An `.ovpn` carrying everything an import would strip — plus a public CA,
    /// which must SURVIVE (it is integrity-critical and belongs where a diff can
    /// see it).
    static var leakyOVPN: String {
        """
        client
        dev tun
        remote vpn.example.com 1197 udp
        cipher AES-128-GCM
        <ca>
        \(caPEM)
        </ca>
        <key>
        \(privateKeyPEM)
        </key>
        <tls-crypt>
        \(tlsCryptKey)
        </tls-crypt>
        <auth-user-pass>
        someone
        \(password)
        </auth-user-pass>
        """
    }

    /// A snapshot with one VPN of every kind that has its own settings, and with
    /// the secrets deliberately left IN so the exporter has to remove them.
    static func snapshot() -> ConfigSnapshot {
        var snapshot = ConfigSnapshot()
        snapshot.appVersion = "SimpleVPN 1.0 (test)"
        snapshot.appSettings = [
            .init(id: "app.dock-icon", value: .bool(false)),
            .init(id: "vm.detect", value: .bool(true)),
        ]
        snapshot.labels = [ConfigLabel(id: "prod", name: "Prod", red: 0.9, green: 0.7, blue: 0.7)]

        var openVPN = ConfigSnapshot.VPN(id: "id-openvpn", name: "GR Lab", kind: .openVPN,
                                        server: "vpn.example.com:1197")
        openVPN.ovpn = leakyOVPN
        var overrides = OpenVPNOverrides()
        overrides.port = 1197
        overrides.compression = .no
        overrides.tlsVersionMin = .tls1_2
        overrides.proxyHost = "proxy.example.com"
        overrides.proxyUsername = "someone"
        openVPN.overrides = overrides
        var auth = VPNAuthConfig()
        auth.requiresOTP = true
        openVPN.auth = auth
        openVPN.labelIDs = ["prod"]
        snapshot.vpns.append(openVPN)

        var wg = ConfigSnapshot.VPN(id: "id-wg", name: "Home WireGuard", kind: .wireGuard,
                                    server: "wg.example.com")
        var wgConfig = WireGuardConfig()
        wgConfig.id = "id-wg"
        wgConfig.name = "Home WireGuard"
        wgConfig.privateKey = wireGuardPrivateKey
        wgConfig.presharedKey = wireGuardPresharedKey
        wgConfig.peerPublicKey = "PEERPublicKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        wgConfig.endpoint = "wg.example.com:51820"
        wgConfig.addresses = ["10.7.0.2/32"]
        wgConfig.dns = ["10.7.0.1"]
        // Deliberately NOT wg-quick's default full tunnel: a field at its default
        // is omitted from the file, so a default value would test nothing.
        wgConfig.allowedIPs = ["10.7.0.0/24", "192.168.5.0/24"]
        wgConfig.mtu = 1380
        wgConfig.persistentKeepalive = 25
        wg.wireGuard = wgConfig
        snapshot.vpns.append(wg)

        var ts = ConfigSnapshot.VPN(id: "id-ts", name: "Tailnet", kind: .tailscale, server: "tailscale")
        var tsConfig = TailscaleConfig()
        tsConfig.hostname = "this-mac"
        tsConfig.acceptRoutes = false
        tsConfig.advertiseRoutes = ["192.168.9.0/24"]
        ts.tailscale = tsConfig
        snapshot.vpns.append(ts)

        var px = ConfigSnapshot.VPN(id: "id-px", name: "Work Proxy", kind: .proxyTunnel,
                                    server: "proxy.example.com")
        var pxConfig = ProxyTunnelConfig()
        pxConfig.upstream = "https://proxy.example.com:3128"
        pxConfig.requiresAuth = true
        pxConfig.mtu = 1400
        px.proxyTunnel = pxConfig
        snapshot.vpns.append(px)

        var sshnet = ConfigSnapshot.VPN(id: "id-sshnet", name: "Netstack SSH",
                                       kind: .sshNetworkTunnel, server: "ssh.example.com")
        var sshnetConfig = SSHNetworkTunnelConfig()
        sshnetConfig.server = "ssh.example.com"
        sshnetConfig.port = 2222
        sshnetConfig.username = "someone"
        sshnetConfig.hostKeyPolicy = .pinned
        sshnetConfig.pinnedHostKeySHA256 = "SHA256:abcd"
        sshnetConfig.mtu = 1400
        sshnet.sshNetworkTunnel = sshnetConfig
        snapshot.vpns.append(sshnet)

        var ssh = ConfigSnapshot.VPN(id: "id-ssh", name: "Jump SSH", kind: .ssh,
                                     server: "bastion.example.com")
        var sshConfig = SubprocessTunnelConfig()
        sshConfig.id = "id-ssh"
        sshConfig.name = "Jump SSH"
        sshConfig.kind = .ssh
        sshConfig.server = "bastion.example.com"
        sshConfig.username = "someone"
        sshConfig.socksPort = 1081
        sshConfig.strictHostKey = "yes"
        sshConfig.identityFile = "~/.ssh/id_ed25519"
        ssh.subprocess = sshConfig
        snapshot.vpns.append(ssh)

        var oc = ConfigSnapshot.VPN(id: "id-oc", name: "Office SSL VPN", kind: .fortinet,
                                    server: "https://gw.example.com")
        var ocConfig = SubprocessTunnelConfig()
        ocConfig.id = "id-oc"
        ocConfig.name = "Office SSL VPN"
        ocConfig.kind = .fortinet
        ocConfig.server = "https://gw.example.com"
        ocConfig.trustedCertSHA256 = "pin:0011"
        ocConfig.enablePFS = true
        ocConfig.ocMTU = 1390
        oc.subprocess = ocConfig
        snapshot.vpns.append(oc)

        var native = ConfigSnapshot.VPN(id: "id-native", name: "Office IKEv2", kind: .ikev2,
                                        server: "ike.example.com")
        var nativeConfig = NativeVPNConfig()
        nativeConfig.id = "id-native"
        nativeConfig.name = "Office IKEv2"
        nativeConfig.kind = .ikev2
        nativeConfig.server = "ike.example.com"
        nativeConfig.remoteID = "ike.example.com"
        nativeConfig.username = "someone"
        native.native = nativeConfig
        snapshot.vpns.append(native)

        return snapshot
    }
}

// MARK: - The secret-exclusion proof

@MainActor
struct ConfigSecretExclusionTests {

    /// THE test this feature exists to pass. A configuration whose secrets are
    /// present in what the exporter is handed — an inline private key, an inline
    /// saved password, a TLS key, a WireGuard private key and a pre-shared key —
    /// produces a file in BOTH encodings containing none of them.
    @Test func noSecretReachesEitherEncoding() {
        let snapshot = ConfigTestFixture.snapshot()
        let secrets = [
            ConfigTestFixture.password,
            "CANARY-OVPN-PRIVATE-KEY-4c1d",
            ConfigTestFixture.tlsCryptKey,
            ConfigTestFixture.wireGuardPrivateKey,
            ConfigTestFixture.wireGuardPresharedKey,
        ]
        for format in ConfigFileFormat.allCases {
            let text = ConfigDocument.text(from: snapshot, format: format)
            for secret in secrets {
                #expect(!text.contains(secret),
                        "\(format.title) export leaked \(secret.prefix(20))\u{2026}")
            }
            // Not even the literal tag names of the secret blocks: the same grep
            // that proves this is the one `OVPNSecretMaterial` was designed for.
            for tag in OVPNSecretMaterial.secretTags {
                #expect(!text.contains("<\(tag)>"), "\(format.title) export contains a <\(tag)> block")
            }
            #expect(!text.contains("BEGIN PRIVATE KEY"))
        }
    }

    /// …and the other direction, which is just as important: the PUBLIC material
    /// stays. A CA decides who the tunnel trusts, so it belongs in the file where a
    /// review or a diff can see it — over-redacting would make certificate handling
    /// worse and buy nothing.
    @Test func thePublicCertificateAuthorityIsKept() {
        let text = ConfigDocument.text(from: ConfigTestFixture.snapshot(), format: .yaml)
        #expect(text.contains("PUBLIC-CA-CERTIFICATE-9911"))
        #expect(text.contains("<ca>"))
        #expect(text.contains("cipher AES-128-GCM"))
    }

    /// The file SAYS what it left out and how to get it back. A silently incomplete
    /// configuration that fails mysteriously on the other Mac is worse than one that
    /// explains itself — the `.ovpn` exporter's header is the precedent.
    @Test func theFileSaysWhatItLeftOutAndHowToRestoreIt() {
        let text = ConfigDocument.text(from: ConfigTestFixture.snapshot(), format: .yaml)
        #expect(text.contains("NO PASSWORDS, KEYS OR OTHER SECRETS ARE IN THIS FILE"))
        #expect(text.contains("private key"))
        #expect(text.contains("keychain"))
        // Per VPN, too — not only once in the header.
        let (root, withheld) = ConfigDocument.build(from: ConfigTestFixture.snapshot())
        #expect(withheld.contains("private key"))
        #expect(withheld.contains("pre-shared key"))
        let wireGuard = root[ConfigDocumentKeys.vpns]?.listValue?
            .compactMap(\.mapValue)
            .first { $0[ConfigDocumentKeys.kind] == .string(VPNKind.wireGuard.rawValue) }
        let notes = wireGuard?[ConfigDocumentKeys.omitted]?.stringList ?? []
        #expect(notes.contains { $0.contains("private key") })
        #expect(notes.allSatisfy { $0.contains("keychain") })
    }

    /// A blank secret is nothing to explain. A stored WireGuard config normally HAS
    /// no key in it (it lives in the keychain), and a file full of "your key was
    /// left out" notes for keys that were never there is noise that hides the notes
    /// that matter.
    @Test func anUnsetSecretRaisesNoNote() {
        var snapshot = ConfigSnapshot()
        var vpn = ConfigSnapshot.VPN(id: "a", name: "A", kind: .wireGuard, server: "a")
        vpn.wireGuard = WireGuardConfig()          // no keys at all
        snapshot.vpns = [vpn]
        let (_, withheld) = ConfigDocument.build(from: snapshot)
        #expect(withheld.isEmpty)
    }

    /// Nesting is not a way past the classification: a secret inside a structure is
    /// dropped by the same rule as a top-level field.
    @Test func aSecretNestedInsideAStructureIsAlsoDropped() {
        var inner = ConfigMap()
        inner.put("username", .string("someone"))
        inner.put("password", .string("CANARY-NESTED"))
        var outer = ConfigMap()
        outer.put("proxy", .map(inner))
        outer.put("rules", .list([.map(inner)]))
        let (clean, notes, withheld) = ConfigDocument.redact(outer)
        let text = ConfigYAML.encode(clean)
        #expect(!text.contains("CANARY-NESTED"))
        #expect(text.contains("someone"))
        #expect(notes.count == 2)
        #expect(withheld == ["saved password", "saved password"])
    }

    /// EVERY field of every exported struct whose NAME suggests a secret is
    /// classified: either withheld, or explicitly reviewed with a reason. A field
    /// added next year fails this test until somebody decides which it is — which is
    /// the only way this stays true over time.
    @Test func everySuspiciousFieldIsClassified() {
        var unclassified: [String] = []
        func check<T>(_ value: T, _ type: String) {
            for field in ConfigDocument.fields(of: value) {
                let lower = field.lowercased()
                guard ConfigSecrets.suspiciousFragments.contains(where: { lower.contains($0) }) else { continue }
                guard ConfigSecrets.secretFields.contains(field)
                        || ConfigSecrets.reviewedNotSecret[field] != nil else {
                    unclassified.append("\(type).\(field)")
                    continue
                }
            }
        }
        check(OpenVPNOverrides(), "OpenVPNOverrides")
        check(WireGuardConfig(), "WireGuardConfig")
        check(TailscaleConfig(), "TailscaleConfig")
        check(ProxyTunnelConfig(), "ProxyTunnelConfig")
        check(SSHNetworkTunnelConfig(), "SSHNetworkTunnelConfig")
        check(SubprocessTunnelConfig(), "SubprocessTunnelConfig")
        check(NativeVPNConfig(), "NativeVPNConfig")
        check(VPNAuthConfig(), "VPNAuthConfig")
        check(VPNUIPrefs(), "VPNUIPrefs")
        check(CustomRoutingProfile(), "CustomRoutingProfile")
        #expect(unclassified.isEmpty,
                "these fields look like secrets and are neither withheld nor reviewed: \(unclassified.sorted().joined(separator: ", "))")
    }

    /// A file that has been HAND-EDITED to include a private key still cannot put
    /// one into a stored profile: the import applies the same classification the
    /// export does.
    @Test func aHandEditedSecretCannotBeImported() throws {
        var settings = ConfigMap()
        settings.put("wg.endpoint", .string("vpn.example.com:51820"))
        settings.put("wg.private-key", .string("CANARY-SMUGGLED"))
        settings.put("wg.preshared-key", .string("CANARY-SMUGGLED-2"))
        let config = try ConfigImport.apply(settings, onto: WireGuardConfig(), namespace: "wg.")
        #expect(config.endpoint == "vpn.example.com:51820")
        #expect(config.privateKey.isEmpty)
        #expect(config.presharedKey.isEmpty)
    }
}

// MARK: - Keys are ids, never display names

@MainActor
struct ConfigFormatTests {

    /// Setting ids the file uses that have no registered descriptor. Every one is a
    /// real stored setting with no row of its own in any catalog — so it has no
    /// manual page and cannot be searched for, and the file still has to carry it or
    /// the export would be incomplete. THE LIST IS THE POINT: a new one shows up
    /// here, in a diff, instead of quietly widening the app's addressing vocabulary.
    static let idsWithNoDescriptor: Set<String> = [
        // The SSL-VPN gateway's own address. A REAL GAP IN THE APP, not in this
        // format: `SubprocessTunnelView` renders a server field for the seven
        // OpenConnect kinds and `OpenConnectSettings` declares no spec for it, so it
        // has no manual anchor, no search entry and no CLI/MDM name. The `ssh.`
        // surface does declare `ssh.server`, which is why only the `oc.` half shows
        // up here. Worth closing — in that catalog, not by renaming this key.
        "oc.server",
    ]

    /// A DISPLAY NAME IS NEVER A KEY. Keys are ids, which ONTOLOGY.md says never
    /// change; a label on screen is free to be reworded tomorrow, and a file keyed
    /// on one would rot the first time it was.
    @Test func everySettingsKeyIsAnIdAndNeverADisplayName() {
        let (root, _) = ConfigDocument.build(from: ConfigTestFixture.snapshot())
        let displayNames = Set(AllSettings.everything.map { $0.setting.name.lowercased() })
        var unknown: [String] = []
        for vpn in root[ConfigDocumentKeys.vpns]?.listValue ?? [] {
            guard let settings = vpn.mapValue?[ConfigDocumentKeys.settings]?.mapValue else { continue }
            for key in settings.keys {
                #expect(!displayNames.contains(key.lowercased()), "\(key) is a display name, not an id")
                #expect(key == key.lowercased(), "\(key) isn't a lower-case id")
                #expect(key.contains("."), "\(key) carries no namespace")
                if AllSettings.byID[key] == nil, !Self.idsWithNoDescriptor.contains(key) {
                    unknown.append(key)
                }
            }
        }
        #expect(unknown.isEmpty,
                "these keys are neither registered settings nor listed as undescribed: \(unknown.sorted().joined(separator: ", "))")
    }

    /// The exported ids REALLY ARE the app's own ids where the app has one — the
    /// naming table is not a parallel vocabulary that happens to look similar.
    @Test func knownSettingsUseTheirRealIds() {
        let (root, _) = ConfigDocument.build(from: ConfigTestFixture.snapshot())
        var all: Set<String> = []
        for vpn in root[ConfigDocumentKeys.vpns]?.listValue ?? [] {
            all.formUnion(vpn.mapValue?[ConfigDocumentKeys.settings]?.mapValue?.keys ?? [])
        }
        for id in ["openvpn.port", "openvpn.compression", "openvpn.tls-version-min",
                   "openvpn.proxy-host", "wg.endpoint", "wg.allowed-ips", "wg.address",
                   "wg.public-key", "wg.keepalive", "wg.mtu", "ts.hostname",
                   "ts.advertise-routes", "px.address", "px.mtu", "sshnet.server",
                   "sshnet.host-key-policy", "sshnet.pinned-host-key", "ssh.server",
                   "ssh.socks-port", "ssh.strict-host-key", "ssh.identity-file",
                   "oc.pinned-server-cert", "oc.pfs", "oc.mtu",
                   "native.server", "native.remote-id"] {
            #expect(all.contains(id), "the export never wrote \(id)")
            #expect(AllSettings.byID[id] != nil, "\(id) isn't a registered setting id")
        }
    }

    /// The mapping is correct in BOTH directions. A field that exports under one id
    /// and imports under another is how a setting is silently dropped by a round
    /// trip that looks like it worked.
    @Test func everyFieldsIdResolvesBackToTheSameField() {
        func check<T>(_ value: T, _ namespace: String) {
            let fields = ConfigDocument.fields(of: value)
            for field in fields where !ConfigFieldNaming.skipped.contains(field) {
                let id = ConfigFieldNaming.id(field: field, namespace: namespace)
                #expect(id.hasPrefix(namespace), "\(field) → \(id) left the \(namespace) namespace")
                #expect(ConfigFieldNaming.field(forID: id, fields: fields, namespace: namespace) == field,
                        "\(namespace)\(field) does not round-trip through its id (\(id))")
            }
        }
        check(OpenVPNOverrides(), "openvpn.")
        check(WireGuardConfig(), "wg.")
        check(TailscaleConfig(), "ts.")
        check(ProxyTunnelConfig(), "px.")
        check(SSHNetworkTunnelConfig(), "sshnet.")
        check(SubprocessTunnelConfig(), "ssh.")
        check(SubprocessTunnelConfig(), "oc.")
        check(NativeVPNConfig(), "native.")
    }

    @Test func kebabCasingTreatsARunOfCapitalsAsOneWord() {
        #expect(ConfigFieldNaming.kebab("allowedIPs") == "allowed-ips")
        #expect(ConfigFieldNaming.kebab("controlURL") == "control-url")
        #expect(ConfigFieldNaming.kebab("acceptDNS") == "accept-dns")
        #expect(ConfigFieldNaming.kebab("listenPort") == "listen-port")
        #expect(ConfigFieldNaming.kebab("pinnedHostKeySHA256") == "pinned-host-key-sha256")
        #expect(ConfigFieldNaming.kebab("mtu") == "mtu")
    }

    /// A file from the future is refused rather than read best-effort: its keys may
    /// mean something else, and a misread server address sends traffic elsewhere.
    @Test func aFileFromTheFutureIsRefused() {
        #expect(ConfigFormat.refusalForVersion(ConfigFormat.current) == nil)
        #expect(ConfigFormat.refusalForVersion(ConfigFormat.maximumReadable + 1) != nil)
        #expect(ConfigFormat.refusalForVersion(0) != nil)

        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(99))
        let plan = ConfigImport.plan(root: root, current: ConfigSnapshot())
        #expect(!plan.fatal.isEmpty)
        #expect(!plan.isApplicable)
        #expect(plan.fatal[0].contains("newer version"))
    }

    /// The header, the omission notes and every name in the diff go through the same
    /// vocabulary rules as the rest of the app: "credential" is banned from UI copy,
    /// and so is every spelling of "log in".
    @Test func theFilesOwnProseFollowsTheHouseVocabulary() {
        let forbidden = ["credential", "log in", "login", "logon", "authenticate", "one-time passcode"]
        var prose = ConfigDocument.headerComments(app: "SimpleVPN", exported: .now,
                                                  withheld: ["private key"]).joined(separator: " ")
        let built = ConfigDocument.build(vpn: ConfigTestFixture.snapshot().vpns[0])
        prose += " " + built.notes.joined(separator: " ") + " " + built.withheld.joined(separator: " ")
        prose += " " + ConfigAppSettings.all.map(\.name).joined(separator: " ")
        prose += " " + (ConfigTransfer.policyRefusal ?? "")
        prose += " " + (MaturityNotice.forFeature(.configurationTransfer)?.spokenSummary ?? "")
        prose += " " + ConfigImportGuard.refusal(in: {
            var m = ConfigMap(); m.put("ssh.strict-host-key", .string("no")); return m
        }(), ovpn: nil)!
        prose += " " + ConfigSecrets.secretFields.map { ConfigSecrets.humanName($0) }.joined(separator: " ")
        for word in forbidden {
            #expect(!prose.lowercased().contains(word), "\u{201C}\(word)\u{201D} appears in the file's own words")
        }
    }
}

// MARK: - The round trip

@MainActor
struct ConfigRoundTripTests {

    /// Export, read back, and every kind's settings come out as they went in. Ids
    /// are NOT preserved (an import adds alongside, so it mints its own), which is
    /// why each config is compared with its identity fields normalised.
    @Test func everyKindSurvivesAYAMLRoundTrip() {
        let snapshot = ConfigTestFixture.snapshot()
        let text = ConfigDocument.text(from: snapshot, format: .yaml)
        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        #expect(plan.fatal.isEmpty)
        #expect(plan.refusals.isEmpty, "\(plan.refusals.map(\.reason))")
        #expect(plan.vpns.count == snapshot.vpns.count)

        func planned(_ name: String) -> ConfigSnapshot.VPN? {
            plan.vpns.first { $0.addedName == name }?.vpn
        }

        let wg = planned("Home WireGuard")?.wireGuard
        #expect(wg?.endpoint == "wg.example.com:51820")
        #expect(wg?.allowedIPs == ["10.7.0.0/24", "192.168.5.0/24"])
        #expect(wg?.addresses == ["10.7.0.2/32"])
        #expect(wg?.dns == ["10.7.0.1"])
        #expect(wg?.mtu == 1380)
        #expect(wg?.persistentKeepalive == 25)
        #expect(wg?.peerPublicKey == "PEERPublicKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        // The keys are gone, as they must be.
        #expect(wg?.privateKey.isEmpty == true)
        #expect(wg?.presharedKey.isEmpty == true)

        let overrides = planned("GR Lab")?.overrides
        #expect(overrides?.port == 1197)
        #expect(overrides?.compression == .no)
        #expect(overrides?.tlsVersionMin == .tls1_2)
        #expect(overrides?.proxyHost == "proxy.example.com")
        #expect(overrides?.proxyUsername == "someone")
        #expect(planned("GR Lab")?.auth?.requiresOTP == true)
        // The configuration arrives, minus its secret blocks and with the CA intact.
        let ovpn = planned("GR Lab")?.ovpn ?? ""
        #expect(ovpn.contains("PUBLIC-CA-CERTIFICATE-9911"))
        #expect(!ovpn.contains("CANARY-OVPN-PRIVATE-KEY-4c1d"))

        let ts = planned("Tailnet")?.tailscale
        #expect(ts?.hostname == "this-mac")
        #expect(ts?.acceptRoutes == false)
        #expect(ts?.advertiseRoutes == ["192.168.9.0/24"])

        let px = planned("Work Proxy")?.proxyTunnel
        #expect(px?.upstream == "https://proxy.example.com:3128")
        #expect(px?.requiresAuth == true)
        #expect(px?.mtu == 1400)

        let sshnet = planned("Netstack SSH")?.sshNetworkTunnel
        #expect(sshnet?.server == "ssh.example.com")
        #expect(sshnet?.port == 2222)
        #expect(sshnet?.hostKeyPolicy == .pinned)
        #expect(sshnet?.pinnedHostKeySHA256 == "SHA256:abcd")

        let ssh = planned("Jump SSH")?.subprocess
        #expect(ssh?.kind == .ssh)
        #expect(ssh?.server == "bastion.example.com")
        #expect(ssh?.socksPort == 1081)
        #expect(ssh?.identityFile == "~/.ssh/id_ed25519")

        let oc = planned("Office SSL VPN")?.subprocess
        #expect(oc?.kind == .fortinet)
        #expect(oc?.trustedCertSHA256 == "pin:0011")
        #expect(oc?.enablePFS == true)
        #expect(oc?.ocMTU == 1390)

        let native = planned("Office IKEv2")?.native
        #expect(native?.kind == .ikev2)
        #expect(native?.server == "ike.example.com")
        #expect(native?.remoteID == "ike.example.com")

        #expect(plan.newLabels.map(\.name) == ["Prod"])
    }

    /// Both encodings produce the same PLAN, which is the real "one model, two
    /// encoders" claim: the choice of file format cannot change what an import does.
    @Test func bothEncodingsProduceTheSamePlan() {
        let snapshot = ConfigTestFixture.snapshot()
        let fromYAML = ConfigImport.plan(text: ConfigDocument.text(from: snapshot, format: .yaml),
                                         current: ConfigSnapshot())
        let fromJSON = ConfigImport.plan(text: ConfigDocument.text(from: snapshot, format: .json),
                                         current: ConfigSnapshot())
        #expect(fromYAML.vpns.map(\.addedName).sorted() == fromJSON.vpns.map(\.addedName).sorted())
        #expect(fromYAML.settingChanges.map(\.id).sorted() == fromJSON.settingChanges.map(\.id).sorted())
        #expect(fromYAML.newLabels.map(\.id) == fromJSON.newLabels.map(\.id))
    }

    /// An import ADDS ALONGSIDE. A VPN whose name is already here arrives under a
    /// name that says where it came from, and the one already installed is untouched
    /// — two Macs' configurations of one gateway is the normal case, and the app
    /// cannot know which is wanted.
    @Test func aNameClashAddsAlongsideRatherThanReplacing() {
        var current = ConfigSnapshot()
        current.vpns = [ConfigSnapshot.VPN(id: "existing", name: "GR Lab",
                                           kind: .openVPN, server: "vpn.example.com")]
        let plan = ConfigImport.plan(text: ConfigDocument.text(from: ConfigTestFixture.snapshot(),
                                                              format: .yaml),
                                     current: current)
        #expect(plan.vpns.contains { $0.addedName == "GR Lab (imported)" })
        #expect(!plan.vpns.contains { $0.addedName == "GR Lab" })
        // …and a fresh id, so it can never overwrite the profile it was named after.
        #expect(plan.vpns.allSatisfy { $0.vpn.id != "existing" })
    }

    /// A label this Mac already has is LEFT ALONE — renaming somebody's label out
    /// from under them destroys the thing that organises their sidebar.
    @Test func anExistingLabelIsKeptNotOverwritten() {
        var current = ConfigSnapshot()
        current.labels = [ConfigLabel(id: "prod", name: "Production", red: 0, green: 0, blue: 1)]
        let plan = ConfigImport.plan(text: ConfigDocument.text(from: ConfigTestFixture.snapshot(),
                                                              format: .yaml),
                                     current: current)
        #expect(plan.newLabels.isEmpty)
        #expect(plan.keptLabels == ["Prod"])
    }

    /// The diff answers "would this change anything?" — a file that matches the Mac
    /// exactly proposes no setting changes at all.
    @Test func aFileMatchingThisMacProposesNothing() {
        let snapshot = ConfigTestFixture.snapshot()
        var current = ConfigSnapshot()
        current.appSettings = snapshot.appSettings
        current.labels = snapshot.labels
        let plan = ConfigImport.plan(text: ConfigDocument.text(from: snapshot, format: .yaml),
                                     current: current)
        #expect(plan.settingChanges.isEmpty)
        #expect(plan.newLabels.isEmpty)
    }
}

// MARK: - What import refuses

@MainActor
struct ConfigImportRefusalTests {

    private func document(vpn: ConfigMap) -> String {
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.vpns, .list([.map(vpn)]))
        return ConfigYAML.encode(root)
    }

    private func vpn(kind: String, settings: ConfigMap = ConfigMap(),
                     name: String = "Imported", ovpn: String? = nil) -> ConfigMap {
        var m = ConfigMap()
        m.put(ConfigDocumentKeys.name, .string(name))
        m.put(ConfigDocumentKeys.kind, .string(kind))
        m.put(ConfigDocumentKeys.server, .string("host.example.com"))
        m.put(ConfigDocumentKeys.settings, ifNotEmpty: settings)
        if let ovpn { m.put(ConfigDocumentKeys.openVPNConfiguration, .document(ovpn)) }
        return m
    }

    /// An unknown kind is REFUSED, never coerced. Defaulting it to OpenVPN would
    /// build a profile that cannot work out of settings that meant something else.
    @Test func anUnknownKindIsRefused() {
        let plan = ConfigImport.plan(text: document(vpn: vpn(kind: "quantumVPN")),
                                     current: ConfigSnapshot())
        #expect(plan.vpns.isEmpty)
        #expect(plan.refusals.count == 1)
        #expect(plan.refusals[0].reason.contains("quantumVPN"))
    }

    @Test func aVPNWithNoNameOrNoKindIsRefused() {
        var noName = vpn(kind: VPNKind.openVPN.rawValue)
        noName[ConfigDocumentKeys.name] = .string("   ")
        #expect(ConfigImport.plan(text: document(vpn: noName), current: ConfigSnapshot())
                    .refusals.count == 1)
        var noKind = vpn(kind: VPNKind.openVPN.rawValue)
        noKind[ConfigDocumentKeys.kind] = nil
        #expect(ConfigImport.plan(text: document(vpn: noKind), current: ConfigSnapshot())
                    .refusals.count == 1)
    }

    /// AN IMPORTED FIELD MUST NEVER TURN VERIFICATION OFF. The app has no such
    /// setting anywhere and must not acquire one through a file format.
    @Test func aFileCannotSwitchOffHostKeyChecking() {
        var settings = ConfigMap()
        settings.put("ssh.server", .string("host.example.com"))
        settings.put("ssh.strict-host-key", .string("no"))
        let plan = ConfigImport.plan(text: document(vpn: vpn(kind: VPNKind.ssh.rawValue, settings: settings)),
                                     current: ConfigSnapshot())
        #expect(plan.vpns.isEmpty)
        #expect(plan.refusals.count == 1)
        #expect(plan.refusals[0].reason.contains("host key"))
    }

    /// …including through an escape hatch, which is exactly where somebody would put
    /// it: both the SSH and the SSL-VPN kinds keep a free-form options list.
    @Test func aFileCannotSmuggleVerificationOffThroughAnEscapeHatch() {
        for (kind, id, value) in [
            ("ssh", "ssh.extra-options", "StrictHostKeyChecking=no"),
            ("ssh", "ssh.extra-options", "UserKnownHostsFile=/dev/null"),
            ("fortinet", "oc.extra-args", "--no-cert-check"),
            ("fortinet", "oc.extra-args", "--allow-insecure-crypto"),
        ] {
            var settings = ConfigMap()
            settings.put(id, .strings(["Compression=yes", value]))
            let plan = ConfigImport.plan(text: document(vpn: vpn(kind: kind, settings: settings)),
                                         current: ConfigSnapshot())
            #expect(plan.vpns.isEmpty, "\(value) was accepted")
            #expect(plan.refusals.first?.reason.contains("checking") == true)
        }
    }

    @Test func anOVPNCarryingAVerificationOffDirectiveIsRefused() {
        let plan = ConfigImport.plan(
            text: document(vpn: vpn(kind: VPNKind.openVPN.rawValue, ovpn: "client\n--no-cert-check\nverb 3")),
            current: ConfigSnapshot())
        #expect(plan.vpns.isEmpty)
        #expect(plan.refusals.count == 1)
    }

    @Test func anOpenVPNVPNWithNoConfigurationIsRefused() {
        let plan = ConfigImport.plan(text: document(vpn: vpn(kind: VPNKind.openVPN.rawValue)),
                                     current: ConfigSnapshot())
        #expect(plan.vpns.isEmpty)
        #expect(plan.refusals.count == 1)
    }

    /// A setting this build has never heard of is REPORTED and skipped, not applied
    /// and not fatal: a newer SimpleVPN's file is not an error.
    @Test func anUnknownAppSettingIsReportedAndSkipped() {
        var settings = ConfigMap()
        settings.put("app.holographic-mode", .bool(true))
        settings.put("app.dock-icon", .bool(false))
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.appSettings, .map(settings))
        let plan = ConfigImport.plan(root: root, current: ConfigSnapshot())
        #expect(plan.unknownKeys == ["app.holographic-mode"])
        #expect(plan.settingChanges.map(\.id) == ["app.dock-icon"])
    }

    /// A value of the wrong type is refused rather than coerced.
    @Test func aWronglyTypedAppSettingIsRefused() {
        var settings = ConfigMap()
        settings.put("app.public-address-service", .map(ConfigMap()))
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.appSettings, .map(settings))
        let plan = ConfigImport.plan(root: root, current: ConfigSnapshot())
        #expect(plan.settingChanges.isEmpty)
        #expect(plan.refusals.count == 1)
    }

    /// A file cannot turn on a macOS permission on somebody's behalf. macOS asks
    /// for location exactly when the user flips that switch themselves.
    @Test func aFileCannotTurnOnTheLocationPermission() {
        var settings = ConfigMap()
        settings.put("app.location", .bool(true))
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.appSettings, .map(settings))
        let plan = ConfigImport.plan(root: root, current: ConfigSnapshot())
        #expect(plan.settingChanges.isEmpty)
        #expect(plan.refusals.count == 1)
        #expect(plan.refusals[0].reason.contains("permission"))
    }

    /// One bad VPN does not cost the other nine. Making somebody re-type nine
    /// working configurations because the tenth was odd is a worse outcome than
    /// importing nine and saying so.
    @Test func oneRefusedVPNDoesNotStopTheRest() {
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.vpns, .list([
            .map(vpn(kind: "quantumVPN", name: "Bad")),
            .map(vpn(kind: VPNKind.wireGuard.rawValue, name: "Good")),
        ]))
        let plan = ConfigImport.plan(root: root, current: ConfigSnapshot())
        #expect(plan.vpns.map(\.addedName) == ["Good"])
        #expect(plan.refusals.count == 1)
    }

    /// The confirmation must be able to SHOW what decides trust and destination.
    @Test func theDiffNamesEverySecurityDeterminingValue() {
        let snapshot = ConfigTestFixture.snapshot()
        let plan = ConfigImport.plan(text: ConfigDocument.text(from: snapshot, format: .yaml),
                                     current: ConfigSnapshot())
        func notes(_ name: String) -> [String] {
            plan.vpns.first { $0.addedName == name }?.securityNotes ?? []
        }
        #expect(notes("GR Lab").contains { $0.hasPrefix("Server address:") })
        #expect(notes("GR Lab").contains { $0.hasPrefix("Certificate authority:") })
        #expect(notes("GR Lab").contains { $0.contains("Connects to: vpn.example.com:1197") })
        #expect(notes("GR Lab").contains { $0.hasPrefix("Connection proxy:") })
        #expect(notes("Home WireGuard").contains { $0.contains("Peer public key") })
        #expect(notes("Netstack SSH").contains { $0.contains("Host key checking") })
        #expect(notes("Netstack SSH").contains { $0.contains("Pinned host key") })
        #expect(notes("Office SSL VPN").contains { $0.contains("Pinned server certificate") })
        #expect(notes("Office IKEv2").contains { $0.contains("Server identifier") })
        // Two files differing ONLY in their CA must produce different diffs.
        var other = snapshot
        other.vpns[0].ovpn = snapshot.vpns[0].ovpn?
            .replacingOccurrences(of: "PUBLIC-CA-CERTIFICATE-9911", with: "A-DIFFERENT-CA-0000")
        let otherPlan = ConfigImport.plan(text: ConfigDocument.text(from: other, format: .yaml),
                                          current: ConfigSnapshot())
        let a = notes("GR Lab").first { $0.hasPrefix("Certificate authority:") }
        let b = otherPlan.vpns.first { $0.addedName == "GR Lab" }?
            .securityNotes.first { $0.hasPrefix("Certificate authority:") }
        #expect(a != b, "a different certificate authority produced an identical diff line")
    }

    /// The plan carries the VALUE behind each change, so what was confirmed is what
    /// gets written — not a second reading of the same bytes.
    @Test func theConfirmedValueIsTheValueApplied() {
        var settings = ConfigMap()
        settings.put("app.menu-bar-graph", .bool(true))
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.appSettings, .map(settings))
        var current = ConfigSnapshot()
        current.appSettings = [.init(id: "app.menu-bar-graph", value: .bool(false))]
        let plan = ConfigImport.plan(root: root, current: current)
        #expect(plan.settingChanges.count == 1)
        #expect(plan.settingChanges[0].from == "off")
        #expect(plan.settingChanges[0].to == "on")
        #expect(plan.settingValue(for: "app.menu-bar-graph") == .bool(true))
    }
}

// MARK: - MDM

@MainActor
struct ConfigTransferPolicyTests {

    /// A managed Mac may forbid configuration LEAVING the device, and a whole
    /// configuration file is the most complete form of leaving there is — so
    /// `lockConfiguration` stops both directions, not just the one that writes.
    @Test func aManagedLockStopsExportAsWellAsImport() async {
        let key = "LockConfiguration"
        let restore = UserDefaults.standard.object(forKey: key)
        defer {
            if let restore { UserDefaults.standard.set(restore, forKey: key) }
            else { UserDefaults.standard.removeObject(forKey: key) }
        }
        UserDefaults.standard.set(false, forKey: key)
        #expect(ConfigTransfer.policyRefusal == nil)
        UserDefaults.standard.set(true, forKey: key)
        let refusal = ConfigTransfer.policyRefusal
        #expect(refusal != nil)
        #expect(refusal?.contains("exported") == true)
        #expect(refusal?.contains("imported") == true)
    }

    /// The feature is registered in the maturity registry, and its notice is
    /// DERIVED from that one line rather than written in the view — so flipping the
    /// claim to tested is a one-line change and no view edit, which is the rule that
    /// registry exists to enforce.
    @Test func theFeatureRegistersItsMaturityAndDerivesItsNotice() {
        let maturity = FeatureMaturityRegistry.maturity(ofFeature: .configurationTransfer)
        #expect(maturity.needsNotice, "a claim of fully tested needs a human who has done it")
        let notice = MaturityNotice.forFeature(.configurationTransfer)
        #expect(notice != nil)
        #expect(notice?.subject == FeatureMaturityRegistry.AppFeature.configurationTransfer.title)
        #expect(notice?.key == "feature.configurationTransfer")
        #expect(notice?.detail.contains("only one Mac") == true)
        // …and the same derivation answers for a hypothetical flip, with no view
        // change anywhere.
        #expect(MaturityNotice.forFeature(.configurationTransfer,
                                          in: [.configurationTransfer: .tested]) == nil)
        // An unregistered feature is untested, never silently "fine".
        #expect(FeatureMaturityRegistry.maturity(ofFeature: .configurationTransfer, in: [:]) == .untested)
    }

    /// The app-settings table only reaches settings somebody made reachable. In
    /// particular it must never name one of MDM's own keys, or a hand-edited file
    /// could unlock a managed Mac.
    @Test func noManagedPolicyKeyIsReachableFromAFile() {
        let managed = ["ForceKeepInsideVPN", "DisableDivertRules",
                       "LockProxySettings", "LockConfiguration",
                       "SignInSourcesAllowed", "SignInSourcesForbidden"]
        let reachable = Set(ConfigAppSettings.all.map(\.key))
        for key in managed {
            #expect(!reachable.contains(key), "\(key) is writable by an imported file")
        }
    }

    /// Every entry in the table is distinct in both of its names, and every id is
    /// either a registered setting or an `app.*` id coined for the Settings window's
    /// own toggles.
    @Test func theAppSettingsTableIsWellFormed() {
        let all = ConfigAppSettings.all
        #expect(Set(all.map(\.id)).count == all.count, "two app settings share an id")
        #expect(Set(all.map(\.key)).count == all.count, "two app settings share a preference key")
        for entry in all {
            #expect(!entry.name.isEmpty, "\(entry.id) has no display name")
            #expect(AllSettings.byID[entry.id] != nil || entry.id.hasPrefix("app."),
                    "\(entry.id) is neither a registered setting nor an app.* id")
        }
        // The two that DO have registered descriptors keep their real ids.
        #expect(all.contains { $0.id == "vm.detect" })
        #expect(all.contains { $0.id == "creds.discovery" })
        // …and every password app has a switch, generated from the vendor list.
        for vendor in LocalVaultVendor.allCases {
            #expect(all.contains { $0.id == SignInSourceSettings.enabledSettingID(vendor) },
                    "\(vendor.rawValue) has no switch in the export")
        }
    }
}
