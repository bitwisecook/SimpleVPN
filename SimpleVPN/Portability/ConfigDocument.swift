// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigDocument.swift
//  The whole-configuration document: what every VPN and every app setting looks
//  like as ONE human-readable file, and the rules that keep a secret out of it.
//  Step 1 of Docs/SecretsAndSync.md §5 — useful on its own ("move my setup to the
//  new Mac"), and the serialisation the sync work will need, which is why the
//  format is treated as something that has to survive versioning from the first
//  commit.
//
//  THE SHAPE, and the one rule that decides every key:
//
//      format: 1
//      exported: 2026-08-06T09:12:33Z
//      app: SimpleVPN 1.0 (123)
//      app-settings:
//        vm.detect: true
//      labels: [ … ]
//      vpns:
//        - id: 4F2A…
//          name: GR Lab
//          kind: openvpn
//          server: vpn.example.com:1197
//          settings:
//            openvpn.port: 1197
//            openvpn.compression: "no"
//          openvpn-configuration: |-
//            client
//            …
//          sign-in: { requiresOTP: true }
//          omitted:
//            - this VPN's private key …
//
//  KEYS IN `settings:` ARE STABLE SETTING IDS — `openvpn.port`, `wg.endpoint`,
//  `sshnet.host-key-policy`. ONTOLOGY.md makes ids the CLI/MDM/manual-anchor
//  contract and says they never change when a display name does, which makes them
//  the only safe thing to key a file format on. A DISPLAY NAME IS NEVER A KEY:
//  "Server Address" is what a person reads on screen and is free to be
//  re-translated tomorrow.
//
//  THE OTHER SECTIONS (`sign-in:`, `custom-routing:`, `endpoints:`, `interface:`)
//  carry the app's OWN persisted JSON shape, key for key. Those settings have no
//  descriptor ids — some are structures (a list of routing rules, a list of
//  endpoint annotations) that no flat id could name — and inventing ids for them
//  would put a second, drifting vocabulary in the file. Their keys are the stored
//  schema's field names, which are just as stable: they are the app↔extension wire
//  format, they decode leniently, and renaming one already means a migration.
//
//  SECRET-FREE BY DEFAULT, AND PROVABLY. See `ConfigSecrets`. Nothing here can be
//  switched off: an exported file leaves every protection the app has, cannot be
//  recalled, and the material it would carry is all recoverable — the same
//  argument, and the same answer, as `OVPNSecretMaterial.exportText`.
//

import Foundation

// MARK: - Format version

nonisolated enum ConfigFormat {

    /// The version this build WRITES. Bumped only when the meaning of an existing
    /// key changes; adding keys does not need it, because a reader ignores what it
    /// does not know.
    static let current = 1

    /// The newest version this build can READ. Equal to `current` today, and
    /// separate from it so a future build that gains a key without changing any
    /// meaning can raise one and not the other.
    static let maximumReadable = 1

    /// A file from the future is REFUSED, not read best-effort. Its keys may mean
    /// something else, and applying a misread server address or pinned certificate
    /// is exactly the failure the confirmation diff exists to prevent.
    static func refusalForVersion(_ version: Int) -> String? {
        if version > maximumReadable {
            return "This file was written by a newer version of SimpleVPN (format \(version); "
                + "this one understands up to \(maximumReadable)). Update SimpleVPN and open it again."
        }
        if version < 1 {
            return "This file doesn\u{2019}t say which settings-file format it uses, so SimpleVPN "
                + "can\u{2019}t tell what its values mean."
        }
        return nil
    }
}

// MARK: - Keys

/// Every key the document uses that is not a setting id. Constants rather than
/// literals because both the writer and the reader name them, and a typo in one
/// half is a silently ignored section.
nonisolated enum ConfigDocumentKeys {
    static let readme = "_readme"
    static let format = "format"
    static let exported = "exported"
    static let app = "app"
    static let appSettings = "app-settings"
    static let labels = "labels"
    static let vpns = "vpns"

    // Per VPN
    static let id = "id"
    static let name = "name"
    static let kind = "kind"
    static let server = "server"
    static let settings = "settings"
    static let openVPNConfiguration = "openvpn-configuration"
    static let signIn = "sign-in"
    static let customRouting = "custom-routing"
    static let endpoints = "endpoints"
    static let interfacePrefs = "interface"
    static let labelIDs = "labels"
    static let omitted = "omitted"
}

// MARK: - The snapshot the document is built from

/// One label, as the file carries it. Its own type rather than `LabelDef` so the
/// document layer never depends on a UI type — and so a test can build one.
nonisolated struct ConfigLabel: Sendable, Equatable, Codable {
    var id: String
    var name: String
    var red: Double
    var green: Double
    var blue: Double
}

/// EVERYTHING the exporter needs, as plain data — no `VPNController`, no keychain,
/// no `UserDefaults`.
///
/// That separation is what makes the secret-free claim testable: a test builds a
/// snapshot whose WireGuard config carries a real private key, whose `.ovpn`
/// carries an inline `<key>` block and whose sign-in carries a password, and then
/// asserts that none of the three appears anywhere in the exported bytes. The
/// exporter has to scrub what it is handed, rather than relying on its caller
/// having handed it something already clean.
nonisolated struct ConfigSnapshot: Sendable {

    nonisolated struct AppSetting: Sendable, Equatable {
        /// The stable id — a registered setting id (`vm.detect`) where the app has
        /// one, otherwise the macOS preference key, which is just as stable
        /// (changing it would lose everybody's setting) and is what MDM addresses.
        let id: String
        var value: ConfigValue
    }

    nonisolated struct VPN: Sendable {
        var id: String
        var name: String
        var kind: VPNKind
        var server: String
        var labelIDs: [String] = []

        /// The complete `.ovpn` for an OpenVPN VPN. Handed in AS STORED OR AS
        /// REASSEMBLED — either is safe, because the exporter splits it again.
        var ovpn: String? = nil
        var overrides: OpenVPNOverrides? = nil
        var wireGuard: WireGuardConfig? = nil
        var tailscale: TailscaleConfig? = nil
        var proxyTunnel: ProxyTunnelConfig? = nil
        var sshNetworkTunnel: SSHNetworkTunnelConfig? = nil
        var subprocess: SubprocessTunnelConfig? = nil
        var native: NativeVPNConfig? = nil

        var auth: VPNAuthConfig? = nil
        var credentialSourceJSON: ConfigValue? = nil
        var customRouting: CustomRoutingProfile? = nil
        var endpoints: VPNEndpointList? = nil
        var uiPrefs: VPNUIPrefs? = nil

        init(id: String, name: String, kind: VPNKind, server: String) {
            self.id = id
            self.name = name
            self.kind = kind
            self.server = server
        }
    }

    var appVersion: String = "SimpleVPN"
    var exportedAt: Date = .now
    var appSettings: [AppSetting] = []
    var labels: [ConfigLabel] = []
    var vpns: [VPN] = []

    init() {}
}

// MARK: - Field name ↔ setting id

/// The mapping between a config struct's field and the setting id the file keys it
/// by, in both directions.
///
/// Field ORDER comes from `Mirror`, not from a hand-written list, and that is the
/// point: a field added to `WireGuardConfig` tomorrow appears in the file without
/// anyone remembering to add it here, in the position it was declared in. A
/// hand-written table is exactly how an exported "whole configuration" ends up
/// quietly missing the setting somebody added last month.
///
/// The id is `namespace + kebab-case(field)` unless `exceptions` says otherwise —
/// and the exceptions are where the REAL descriptor ids live, because several of
/// them were named after what the user is deciding rather than after the field
/// (`allowLocalLanAccess` is `openvpn.local-lan`). Anything with no descriptor at
/// all still gets an id in the same namespace; `ConfigFormatTests` lists those
/// explicitly, so the set of settings the file names without a manual page behind
/// them is visible rather than assumed.
nonisolated enum ConfigFieldNaming {

    /// Never exported from a settings map: identity and schema plumbing. `id`,
    /// `name` and `kind` are carried once at the VPN level instead of repeated
    /// inside its settings, and `schema` is the blob's own serialisation version,
    /// which the document's `format` supersedes.
    static let skipped: Set<String> = ["id", "name", "kind", "schema"]

    static let exceptions: [String: [String: String]] = [
        "openvpn.": [
            "proto": "openvpn.protocol",
            "connTimeout": "openvpn.connect-timeout",
            "allowLocalLanAccess": "openvpn.local-lan",
            "allowUnusedAddrFamilies": "openvpn.unused-families",
            "enableLegacyAlgorithms": "openvpn.legacy-algorithms",
            "enableNonPreferredDCAlgorithms": "openvpn.non-preferred-ciphers",
            "tlsCiphersuitesList": "openvpn.tls-ciphersuites",
            "disableClientCert": "openvpn.no-client-cert",
            "defaultKeyDirection": "openvpn.key-direction",
            "proxyAllowCleartextAuth": "openvpn.proxy-cleartext-auth",
            "sslDebugLevel": "openvpn.ssl-debug",
            "synchronousDnsLookup": "openvpn.synchronous-dns",
        ],
        "wg.": [
            "addresses": "wg.address",
            "peerPublicKey": "wg.public-key",
            "allowedIPs": "wg.allowed-ips",
            "persistentKeepalive": "wg.keepalive",
            "fwMark": "wg.fwmark",
        ],
        "ts.": [
            "controlURL": "ts.control-url",
            "acceptDNS": "ts.accept-dns",
            "useExitNode": "ts.exit-node",
            "exitNode": "ts.exit-node-machine",
            "exitNodeAllowLANAccess": "ts.exit-node-lan",
        ],
        "px.": [
            "upstream": "px.address",
            "includeDefaultRoute": "px.default-route",
            "includedRoutes": "px.included",
            "excludedRoutes": "px.excluded",
            "dnsServers": "px.dns",
        ],
        "sshnet.": [
            "pinnedHostKeySHA256": "sshnet.pinned-host-key",
            "includeDefaultRoute": "sshnet.send-all-traffic",
            "includedRoutes": "sshnet.routes",
            "dnsServers": "sshnet.dns",
            "useFarSideResolver": "sshnet.far-side-dns",
            "keepaliveSeconds": "sshnet.keepalive",
        ],
        "ssh.": [
            "sshMode": "ssh.mode",
            "identityFile": "ssh.identity-file",
            "serverAliveInterval": "ssh.keepalive",
            "strictHostKey": "ssh.strict-host-key",
            "sshExtraOptions": "ssh.extra-options",
            "sshAuthMethod": "ssh.auth-method",
            "sshCertificateFile": "ssh.certificate-file",
            "sshAgentSocket": "ssh.agent-socket",
            "sshPinnedHostKey": "ssh.pinned-host-key",
            "sshKexAlgorithms": "ssh.key-exchange",
            "setSystemProxy": "ssh.system-proxy",
            "jumpHost": "ssh.proxy-jump",
        ],
        "oc.": [
            // The SSH kinds' own `-C` flag, which an SSL VPN never uses. Named apart
            // from `ocCompression` on purpose: both fields live in the one
            // `SubprocessTunnelConfig`, and two fields cannot share one id.
            "compression": "oc.ssh-compression",
            "trustedCertSHA256": "oc.pinned-server-cert",
            "caFile": "oc.cafile",
            "spoofOS": "oc.os",
            "disableDTLS": "oc.no-dtls",
            "clientCertFile": "oc.client-cert",
            "clientKeyFile": "oc.client-key",
            "ocCompression": "oc.compression",
            "ocMTU": "oc.mtu",
            "disableIPv6": "oc.disable-ipv6",
            "noHTTPKeepalive": "oc.no-http-keepalive",
            "enablePFS": "oc.pfs",
            "extraArgs": "oc.extra-args",
            "pkcs11ModulePath": "oc.pkcs11-module",
            "pkcs11CertificateURI": "oc.pkcs11-certificate",
            "pkcs11KeyURI": "oc.pkcs11-key",
            "samlBrowser": "oc.sso-browser",
        ],
        // Per-VPN sign-in. No descriptors exist for these (the rows predate the
        // registry), so the ids are coined here — with one deliberate translation:
        // `rememberCredentials` becomes `signin.remember-password`, because
        // "credential" is banned from anything a person reads and this file is
        // meant to be read. The stored field keeps its name; the FILE uses the
        // house term.
        "signin.": [
            "requiresOTP": "signin.verification-code-required",
            "passwordTemplate": "signin.password-template",
            "rememberCredentials": "signin.remember-password",
            "biometricProtection": "signin.touch-id",
            "securityKey": "signin.security-key",
        ],
        "native.": [
            "remoteID": "native.remote-id",
            "groupOrRealm": "native.group",
            "ikeEncryption": "native.encryption",
            "ikeIntegrity": "native.integrity",
            "ikeDHGroup": "native.dh-group",
        ],
    ]

    /// "allowedIPs" → "allowed-ips", "controlURL" → "control-url",
    /// "pinnedHostKeySHA256" → "pinned-host-key-sha256".
    ///
    /// A hyphen goes in only where a lower-case letter or digit is followed by a
    /// capital, so A RUN OF CAPITALS IS ONE WORD — "IPs", "DNS", "URL", "SHA256".
    /// The textbook rule (also split "AB" before a following "b") would give
    /// "allowed-i-ps", which is nobody's idea of the name of that setting.
    static func kebab(_ field: String) -> String {
        var out = ""
        var previous: Character? = nil
        for ch in field {
            if ch.isUppercase, let p = previous, p.isLowercase || p.isNumber { out.append("-") }
            out.append(Character(ch.lowercased()))
            previous = ch
        }
        return out
    }

    static func id(field: String, namespace: String) -> String {
        if let explicit = exceptions[namespace]?[field] { return explicit }
        return namespace + kebab(field)
    }

    /// The inverse, resolved by SEARCHING the struct's own field list rather than
    /// by un-kebabbing: "allowed-ips" → "allowedIps" would be wrong, and a mapping
    /// that is only correct in one direction is how an import silently drops a
    /// setting it happily exported.
    ///
    /// An EXPLICIT exception wins over a kebab match. `SubprocessTunnelConfig` is
    /// the reason: it holds both SSH's `compression` and OpenConnect's
    /// `ocCompression`, and without this rule "oc.compression" resolved to the SSH
    /// field simply because it came first in the declaration.
    static func field(forID id: String, fields: [String], namespace: String) -> String? {
        if let explicit = exceptions[namespace]?.first(where: { $0.value == id })?.key,
           fields.contains(explicit) {
            return explicit
        }
        return fields.first { self.id(field: $0, namespace: namespace) == id }
    }
}

// MARK: - Secrets

/// WHAT MAY NEVER LEAVE, and how the omission is explained.
///
/// The app learned this the hard way twice: setting a profile's private-key block
/// through `OVPNInline` (the call `NoInliningRegressionTests` now watches for) used to
/// keep PEM private keys in `providerConfiguration`, and `Export .ovpn…` wrote them
/// to whatever file the user chose. So the classification is explicit, per field,
/// and enforced in two ways at once:
///
///  • AT RUNTIME a field is dropped if it is named here, OR if its name matches one
///    of `suspiciousFragments` and is not in `reviewedNotSecret`. The second half is
///    the backstop: a `WireGuardConfig.rotationPassword` added next year is left out
///    of the file before anybody remembers this type exists.
///  • AT BUILD TIME `ConfigSecretExclusionTests` walks every exported struct and
///    fails if a suspicious field is neither classified as secret nor reviewed. The
///    list is the point — being on it is a deliberate act.
///
/// The `.ovpn` blocks are NOT listed here: `OVPNSecretMaterial` already owns that
/// classification (eight secret tags, five deliberately public ones) and a second
/// copy of the list is how the two drift. The exporter calls it.
nonisolated enum ConfigSecrets {

    /// Fields whose value is, or can be, a secret. Keyed by field name alone
    /// because these names are unambiguous across every config struct in the app.
    static let secretFields: Set<String> = [
        // WireGuard: the device's own key, and the optional extra symmetric key.
        // Both are normally already blank in a stored config (they live in the
        // keychain) — but a snapshot taken from a live editor draft has them.
        "privateKey", "presharedKey",
        // Anything spelled as a password, wherever it appears.
        "password", "proxyPassword", "privateKeyPassword", "xauthPassword",
        "sharedSecret", "groupSecret",
        // Tailscale's setup key signs a machine in on its own — it is a secret in
        // the strongest sense (it can enrol a NEW machine).
        "authKey",
        // A verification-code seed generates every future code.
        "tokenSecret", "otpSecret", "totpSecret",
        // A smartcard/security-key PIN.
        "pin", "pkcs11PIN",
    ]

    /// Name fragments that MIGHT mean a secret. Never used on their own to decide —
    /// see `reviewedNotSecret`.
    static let suspiciousFragments = [
        "password", "passphrase", "privatekey", "preshared", "secret",
        "authkey", "apikey", "token", "cookie", "credential", "pin",
    ]

    /// Fields whose NAME looks like a secret and whose VALUE is not one. Each needs
    /// a reason, because "it's fine" is how a leak gets waved through.
    static let reviewedNotSecret: [String: String] = [
        // A method choice ("does this concentrator use XAuth as well as the group
        // key?"), not the key itself.
        "usesSharedSecret": "a yes/no choice of sign-in method, not a key",
        "xauth": "a yes/no choice of sign-in method, not a password",
        // "" | totp | hotp | oidc — which KIND of code, never the seed.
        "tokenMode": "which kind of verification code is used, not its seed",
        // Where the PIN comes from ("keychain" / "ask"), never the PIN.
        "pkcs11PINSource": "where the PIN is obtained from, never the PIN itself",
        // A path to a file on disk. The file may hold a key; the path does not.
        "clientKeyFile": "a file path, not the key in it",
        "sshCertificateFile": "a file path, not the key in it",
        "jumpIdentityFile": "a file path, not the key in it",
        "identityFile": "a file path, not the key in it",
        // A URI that NAMES an object on a smartcard; the token keeps the key.
        "pkcs11KeyURI": "names an object on the security key, never its contents",
        // Whether macOS should remember the PIN, not the PIN.
        "pkcs11RemembersPIN": "a yes/no choice about remembering, not the PIN",
        // Whether the proxy password is handed over on the command line rather than
        // on stdin — a choice ABOUT a password's handling, never the password.
        "proxyPasswordInArgv": "a yes/no choice about how a password is passed, not the password",
        // A template ("{password}{otp}") describing how the two typed values are
        // combined. It contains placeholders, never values.
        "passwordTemplate": "a template of placeholders, never a typed password",
        // Whether to save the password at all.
        "rememberCredentials": "a yes/no choice about saving, not the password",
        // Whether releasing the saved password needs Touch ID.
        "biometricProtection": "a yes/no choice about Touch ID, not the password",
        // A FINGERPRINT of a public certificate or host key — publishing it is how
        // pinning is checked, and it is integrity-critical, so it belongs in the
        // file where a diff can see it.
        "trustedCertSHA256": "a fingerprint of a public certificate, integrity-critical",
        "pinnedHostKeySHA256": "a fingerprint of a public host key, integrity-critical",
        "sshPinnedHostKey": "a fingerprint of a public host key, integrity-critical",
    ]

    /// Is this field's value withheld from the file?
    static func isSecret(_ field: String) -> Bool {
        if secretFields.contains(field) { return true }
        if reviewedNotSecret[field] != nil { return false }
        let lower = field.lowercased()
        return suspiciousFragments.contains { lower.contains($0) }
    }

    /// What to tell the reader of the file about one omitted field. Plain English,
    /// ONTOLOGY house terms, and it names how to put the value back — a silently
    /// incomplete configuration that fails mysteriously on the other Mac is worse
    /// than one that explains itself.
    static func omissionNote(field: String) -> String {
        "this VPN\u{2019}s \(humanName(field)) \u{2014} left out because it is a secret. SimpleVPN keeps "
            + "it in the keychain of the Mac this file came from. Type it in again after importing, "
            + "or ask whoever set up this VPN for it."
    }

    /// The house term for one withheld field — a NOUN PHRASE with no article, so it
    /// reads correctly both in a per-VPN sentence ("this VPN's private key…") and in
    /// the header's list of what the whole file leaves out.
    static func humanName(_ field: String) -> String {
        switch field {
        case "privateKey": "private key"
        case "presharedKey": "pre-shared key"
        case "password": "saved password"
        case "proxyPassword": "proxy password"
        case "privateKeyPassword": "key passphrase"
        case "xauthPassword": "second saved password"
        case "sharedSecret", "groupSecret": "shared key"
        case "authKey": "setup key"
        case "tokenSecret", "otpSecret", "totpSecret": "verification-code seed"
        case "pin", "pkcs11PIN": "security key\u{2019}s PIN"
        default: field
        }
    }
}

// MARK: - Building the document

/// `@MainActor`, unlike everything else in this layer, and not by choice: the app
/// target's default isolation is `MainActor`, so `VPNAuthConfig`, `VPNUIPrefs`,
/// `NativeVPNConfig` and `SubprocessTunnelConfig` have main-actor-isolated
/// `Codable` conformances. Encoding them from a `nonisolated` context is a
/// compile error, and giving those types a second, nonisolated conformance to
/// dodge it would be a far worse trade. The value tree, both encoders and both
/// decoders (`ConfigValue`, `ConfigJSON`, `ConfigYAML`) stay nonisolated, which is
/// where it matters — that is the part with no dependency on the app at all.
@MainActor
enum ConfigDocument {

    /// The header. It says what is in the file, what is NOT in it and why, and how
    /// to put back what is missing — the same three things `.ovpn` export's header
    /// says, for the same reason.
    static func headerComments(app: String, exported: Date, withheld: [String]) -> [String] {
        var out = [
            "SimpleVPN \u{2014} exported settings.",
            "",
            "Every VPN and every SimpleVPN setting on the Mac this came from, in one file.",
            "Import it from SimpleVPN Settings \u{25B8} General \u{25B8} Export & Import.",
            "",
            "NO PASSWORDS, KEYS OR OTHER SECRETS ARE IN THIS FILE, and there is no option to",
            "put them in. An exported file leaves every protection SimpleVPN has \u{2014} mail, a",
            "shared folder, a repository, a backup \u{2014} and cannot be recalled. Everything left",
            "out is recoverable: it is still in the keychain of the Mac that wrote this, and",
            "whoever set up the VPN can issue it again.",
        ]
        if !withheld.isEmpty {
            out += [
                "",
                "What was left out, across every VPN in this file:",
                "  " + withheld.joined(separator: ", ") + ".",
                "Each VPN below lists its own under \u{201C}omitted\u{201D}, and says how to put it back.",
            ]
        }
        out += [
            "",
            "Names beginning \u{201C}openvpn.\u{201D}, \u{201C}wg.\u{201D}, \u{201C}ts.\u{201D} and so on are SimpleVPN\u{2019}s own setting",
            "names. They never change, so this file keeps working when a label on screen is",
            "reworded. Look any of them up in Help \u{25B8} SimpleVPN Manual.",
            "",
            "Exported \(ISO8601DateFormatter().string(from: exported)) by \(app).",
        ]
        return out
    }

    /// The document, plus the kinds of secret it had to leave out (which the header
    /// summarises, and each VPN repeats in its own words).
    static func build(from snapshot: ConfigSnapshot) -> (root: ConfigMap, withheld: [String]) {
        var withheld: [String] = []
        var root = ConfigMap()
        root.put(ConfigDocumentKeys.format, .int(ConfigFormat.current))
        root.put(ConfigDocumentKeys.exported, .string(ISO8601DateFormatter().string(from: snapshot.exportedAt)))
        root.put(ConfigDocumentKeys.app, .string(snapshot.appVersion))

        var settings = ConfigMap()
        for setting in snapshot.appSettings where !ConfigSecrets.isSecret(setting.id) {
            settings.put(setting.id, setting.value)
        }
        root.put(ConfigDocumentKeys.appSettings, ifNotEmpty: settings)

        if !snapshot.labels.isEmpty {
            root.put(ConfigDocumentKeys.labels,
                     .list(snapshot.labels.map { .map(structuralMap($0)) }))
        }

        var vpns: [ConfigValue] = []
        for vpn in snapshot.vpns {
            let built = build(vpn: vpn)
            vpns.append(.map(built.map))
            for subject in built.withheld where !withheld.contains(subject) { withheld.append(subject) }
        }
        if !vpns.isEmpty { root.put(ConfigDocumentKeys.vpns, .list(vpns)) }
        return (root, withheld)
    }

    /// The whole file as text, in whichever of the two encodings was asked for.
    static func text(from snapshot: ConfigSnapshot, format: ConfigFileFormat) -> String {
        let (root, withheld) = build(from: snapshot)
        let comments = headerComments(app: snapshot.appVersion,
                                     exported: snapshot.exportedAt,
                                     withheld: withheld)
        switch format {
        case .yaml: return ConfigYAML.encode(root, leadingComments: comments)
        case .json: return ConfigJSON.encode(root, leadingComments: comments)
        }
    }

    // MARK: One VPN

    /// One VPN's entry, the sentences it needs to explain its own omissions, and the
    /// house names of what was withheld (which the header collects).
    static func build(vpn: ConfigSnapshot.VPN) -> (map: ConfigMap, notes: [String], withheld: [String]) {
        var m = ConfigMap()
        var notes: [String] = []
        var withheld: [String] = []
        m.put(ConfigDocumentKeys.id, .string(vpn.id))
        m.put(ConfigDocumentKeys.name, .string(vpn.name))
        m.put(ConfigDocumentKeys.kind, .string(vpn.kind.rawValue))
        m.put(ConfigDocumentKeys.server, ifNotEmpty: vpn.server)
        m.put(ConfigDocumentKeys.labelIDs, ifNotEmpty: vpn.labelIDs)

        var settings = ConfigMap()
        func add<T: Encodable>(_ value: T?, unchanged: T, _ namespace: String) {
            guard let value else { return }
            let built = settingsMap(value, unchanged: unchanged, namespace: namespace)
            settings.entries.append(contentsOf: built.map.entries)
            notes += built.notes
            withheld += built.withheld
        }
        add(vpn.overrides, unchanged: OpenVPNOverrides(), "openvpn.")
        add(vpn.wireGuard, unchanged: WireGuardConfig(), "wg.")
        add(vpn.tailscale, unchanged: TailscaleConfig(), "ts.")
        add(vpn.proxyTunnel, unchanged: ProxyTunnelConfig(), "px.")
        add(vpn.sshNetworkTunnel, unchanged: SSHNetworkTunnelConfig(), "sshnet.")
        add(vpn.native, unchanged: NativeVPNConfig(), "native.")
        if let subprocess = vpn.subprocess {
            add(subprocess, unchanged: SubprocessTunnelConfig(),
                vpn.kind == .ssh ? "ssh." : "oc.")
        }
        m.put(ConfigDocumentKeys.settings, ifNotEmpty: settings)

        // The `.ovpn`, split AGAIN here rather than trusted: the caller may hand
        // over the reassembled text (that is what every other consumer wants), and
        // a profile whose keychain migration could not be verified still carries
        // its key inline. `exportText` writes the note about what it removed into
        // the configuration itself.
        if let ovpn = vpn.ovpn, !ovpn.isEmpty {
            m.put(ConfigDocumentKeys.openVPNConfiguration, .document(OVPNSecretMaterial.exportText(ovpn)))
            let split = OVPNSecretMaterial.split(ovpn)
            let tags = Set(split.secrets.keys).union(OVPNSecretMaterial.markedTags(in: ovpn))
            for tag in OVPNSecretMaterial.secretTags where tags.contains(tag) {
                let name = OVPNSecretMaterial.humanName(for: tag)
                withheld.append(name)
                notes.append("this VPN\u{2019}s \(name) \u{2014} left out because it is a secret. SimpleVPN "
                    + "keeps it in the keychain of the Mac this file came from; the configuration in "
                    + "this file says where it belongs.")
            }
        }

        // Sign-in goes through the SAME id-keyed mechanism as the engine settings.
        // It has no descriptors of its own, but it does have one field whose name is
        // banned from anything a person reads (`rememberCredentials`), and the naming
        // table is where that gets translated once — see the "signin." exceptions.
        var signIn = ConfigMap()
        if let auth = vpn.auth {
            let built = settingsMap(auth, unchanged: VPNAuthConfig(), namespace: "signin.")
            signIn.entries.append(contentsOf: built.map.entries)
            notes += built.notes
            withheld += built.withheld
        }
        if let source = vpn.credentialSourceJSON, let map = source.mapValue {
            let (clean, dropped, subjects) = redact(map)
            signIn.put("signin.source", ifNotEmpty: clean)
            notes += dropped
            withheld += subjects
        }
        m.put(ConfigDocumentKeys.signIn, ifNotEmpty: signIn)

        if let routing = vpn.customRouting, !routing.isEmpty {
            let built = structuralMapRedacting(routing)
            m.put(ConfigDocumentKeys.customRouting, ifNotEmpty: built.map)
            notes += built.notes
            withheld += built.withheld
        }
        if let endpoints = vpn.endpoints, !endpoints.endpoints.isEmpty {
            let built = structuralMapRedacting(endpoints)
            m.put(ConfigDocumentKeys.endpoints, ifNotEmpty: built.map)
            notes += built.notes
            withheld += built.withheld
        }
        if let prefs = vpn.uiPrefs, !prefs.isDefault {
            m.put(ConfigDocumentKeys.interfacePrefs, ifNotEmpty: structuralMapRedacting(prefs).map)
        }

        if !notes.isEmpty {
            m.put(ConfigDocumentKeys.omitted, .strings(notes))
        }
        return (m, notes, withheld)
    }

    // MARK: Struct → map

    /// A config struct as an id-keyed settings map, in DECLARATION order, with every
    /// secret field left out and reported.
    ///
    /// A FIELD AT ITS DEFAULT IS OMITTED, `unchanged` being an untouched instance of
    /// the same type. Three reasons, in order of how much they matter:
    ///  • `OpenVPNOverrides` already works this way — `nil` means "engine default,
    ///    never touched" and is never serialised — so doing it for every other kind
    ///    makes one rule instead of two.
    ///  • ONE struct serves two surfaces. `SubprocessTunnelConfig` holds the SSH
    ///    fields and the SSL-VPN fields together, so writing every field would put
    ///    thirty `oc.*` lines in an SSH tunnel's settings and thirty `ssh.*` lines in
    ///    an SSL VPN's — every one of them meaningless, and the four that matter
    ///    buried among them.
    ///  • A file a person can read is the entire point of the format. What is in it
    ///    should be what somebody chose.
    /// Import starts from the same untouched instance, so an omitted field arrives
    /// with exactly the value it had.
    static func settingsMap<T: Encodable>(_ value: T, unchanged: T, namespace: String)
        -> (map: ConfigMap, notes: [String], withheld: [String]) {
        let json = jsonObject(value)
        let defaults = jsonObject(unchanged)
        var m = ConfigMap()
        var notes: [String] = []
        var withheld: [String] = []
        var seen: Set<String> = []

        func consider(_ field: String) {
            guard !ConfigFieldNaming.skipped.contains(field) else { return }
            if ConfigSecrets.isSecret(field) {
                // Reported only when the value is actually set: a blank private key
                // is nothing to explain, and a file full of notes about keys that
                // were never there buries the ones that matter.
                if let raw = json[field], !isEmptyValue(raw) {
                    notes.append(ConfigSecrets.omissionNote(field: field))
                    withheld.append(ConfigSecrets.humanName(field))
                }
                return
            }
            guard let raw = json[field] else { return }      // an unset Optional
            let value = ConfigJSON.value(raw)
            if let untouched = defaults[field], ConfigJSON.value(untouched) == value { return }
            m.put(ConfigFieldNaming.id(field: field, namespace: namespace), value)
        }

        for field in fields(of: value) {
            seen.insert(field)
            consider(field)
        }
        // A custom `CodingKeys` can name a key no stored property matches. Carried
        // anyway, in sorted order, so the file is never quietly short of a setting.
        for key in json.keys.sorted() where !seen.contains(key) { consider(key) }
        return (m, notes, withheld)
    }

    /// A struct as its OWN persisted shape — the app's JSON keys, key for key. Used
    /// for the sections whose settings have no ids (see this file's header).
    static func structuralMap<T: Encodable>(_ value: T) -> ConfigMap {
        structuralMapRedacting(value).map
    }

    static func structuralMapRedacting<T: Encodable>(_ value: T)
        -> (map: ConfigMap, notes: [String], withheld: [String]) {
        let json = jsonObject(value)
        var ordered = ConfigMap()
        var seen: Set<String> = []
        for field in fields(of: value) where json[field] != nil {
            seen.insert(field)
            ordered.put(field, ConfigJSON.value(json[field]!))
        }
        for key in json.keys.sorted() where !seen.contains(key) {
            ordered.put(key, ConfigJSON.value(json[key]!))
        }
        // One scrub, recursive, over the whole thing — rather than a top-level pass
        // plus a nested one that could disagree with it.
        return redact(ordered)
    }

    /// Recursive scrub of an already-built tree. The last gate before anything is
    /// written: nested structures (a routing rule holding a proxy sign-in, a
    /// credential-source payload) go through the same classification as a top-level
    /// field, so nesting is never a way past it.
    static func redact(_ map: ConfigMap) -> (map: ConfigMap, notes: [String], withheld: [String]) {
        var out = ConfigMap()
        var notes: [String] = []
        var withheld: [String] = []
        for e in map.entries {
            if ConfigSecrets.isSecret(e.key) {
                if !isEmpty(e.value) {
                    notes.append(ConfigSecrets.omissionNote(field: e.key))
                    withheld.append(ConfigSecrets.humanName(e.key))
                }
                continue
            }
            let (clean, dropped, subjects) = redactValue(e.value)
            notes += dropped
            withheld += subjects
            out.put(e.key, clean)
        }
        return (out, notes, withheld)
    }

    private static func redactValue(_ value: ConfigValue)
        -> (ConfigValue, [String], [String]) {
        switch value {
        case .map(let m):
            let (clean, notes, withheld) = redact(m)
            return (.map(clean), notes, withheld)
        case .list(let items):
            var out: [ConfigValue] = []
            var notes: [String] = []
            var withheld: [String] = []
            for item in items {
                let (clean, dropped, subjects) = redactValue(item)
                out.append(clean)
                notes += dropped
                withheld += subjects
            }
            return (.list(out), notes, withheld)
        default:
            return (value, [], [])
        }
    }

    // MARK: Reflection helpers

    /// Declaration order, from the runtime rather than from a list somebody has to
    /// remember to update.
    static func fields<T>(of value: T) -> [String] {
        Mirror(reflecting: value).children.compactMap(\.label)
    }

    static func jsonObject<T: Encodable>(_ value: T) -> [String: Any] {
        guard let data = try? JSONEncoder().encode(value),
              let any = try? JSONSerialization.jsonObject(with: data),
              let dict = any as? [String: Any] else { return [:] }
        return dict
    }

    private static func isEmptyValue(_ any: Any) -> Bool {
        if let s = any as? String { return s.isEmpty }
        if let a = any as? [Any] { return a.isEmpty }
        if any is NSNull { return true }
        return false
    }

    private static func isEmpty(_ value: ConfigValue) -> Bool {
        switch value {
        case .string(let s), .text(let s): s.isEmpty
        case .list(let l): l.isEmpty
        case .map(let m): m.isEmpty
        default: false
        }
    }
}

/// Which encoding a file is written in. The two are the same document (see
/// ConfigValue.swift); this only picks the writer.
nonisolated enum ConfigFileFormat: String, CaseIterable, Sendable {
    case yaml, json

    var fileExtension: String { self == .yaml ? "yaml" : "json" }

    /// What the save panel and the settings row call it.
    var title: String { self == .yaml ? "YAML" : "JSON" }

    /// Guess from a file name; YAML is the default because it is the one a person
    /// is likely to edit by hand.
    static func forFileName(_ name: String) -> ConfigFileFormat {
        name.lowercased().hasSuffix(".json") ? .json : .yaml
    }
}
