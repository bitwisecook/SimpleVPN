// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeTargetFacts.swift
//  Everything the staged probe needs to know about ONE saved VPN, flattened out
//  of wherever the app actually keeps it (the .ovpn text, the overrides, the
//  subprocess/native/WireGuard/Tailscale stores) into a single Sendable value.
//
//  Why a value and not the live objects: the ladder runs off the main actor for
//  seconds at a time, and it must probe the VPN as it was when the user clicked
//  — not as it becomes while they edit it mid-run. It also makes the whole plan
//  layer testable, because a test can hand-build facts without a keychain, a
//  NetworkExtension manager or a network.
//
//  Key material: this value may carry private keys (the profile's own, which
//  the engine gets today by exactly the same route). It is created at the
//  moment of a probe, held for the run, and dropped — never persisted, never
//  logged, never put in a long-lived singleton.
//

import Foundation

nonisolated struct ProbeTargetFacts: Sendable, Equatable {

    // MARK: Identity / endpoint
    var kind: VPNKind = .openVPN
    var profileID = ""
    var profileName = "this VPN"
    var host = ""
    var port = 0
    var transport: VPNProbe.Transport = .auto

    // MARK: Certificates (OpenVPN inline blocks, or an SSL-VPN's files read in)
    var caPEM: String?
    var clientCertificatePEM: String?
    var clientKeyPEM: String?
    /// `verify-x509-name` / the SSL-VPN's expected identity, when the profile pins one.
    var expectedServerName: String?
    /// A pinned server-certificate SHA-256 (OpenConnect `--servercert`).
    var pinnedServerCertificateSHA256: String?

    // MARK: OpenVPN control-channel key
    var tlsKey: OpenVPNStaticKey?

    // MARK: SSH
    var username = ""
    var identityFilePath: String?
    var knownHostsPath: String?
    var pinnedHostKeySHA256: String?
    var strictHostKey = "accept-new"

    // MARK: IKEv2 / IPsec
    var requestedEncryption = ""
    var requestedIntegrity = ""
    var requestedDHGroup = ""
    var remoteIdentifier = ""
    var usesSharedSecret = false

    // MARK: WireGuard
    var wireGuardPrivateKey: String?
    var wireGuardPeerPublicKey: String?
    var wireGuardPresharedKey: String?

    // MARK: Tailscale / Headscale
    var controlURL: String?
    var isSelfHostedControl = false

    // MARK: Sign-in shape
    /// The VPN signs in with a username/password at all (false for a pure
    /// certificate or key VPN — its ladder has no account boundary to cross).
    var usesAccountSignIn = true
    /// …and needs a fresh one-time code each time, which is what makes an
    /// automatic sign-in test unacceptable rather than merely impolite.
    var requiresOTP = false

    var hasClientCertificate: Bool {
        !(clientCertificatePEM ?? "").isEmpty
    }
    var hasCA: Bool { !(caPEM ?? "").isEmpty }

    /// Which of the two OTP/lockout sentences a held-back step should carry.
    var accountSkipReason: String {
        requiresOTP ? ProbeLadderEngine.otpAccountSkipReason
                    : ProbeLadderEngine.defaultAccountSkipReason
    }
}

// MARK: - Building facts from what the app stores

nonisolated extension ProbeTargetFacts {

    /// Facts an OpenVPN profile's text carries. Everything here is read out of
    /// the .ovpn the profile already holds — the same text the engine parses.
    static func openVPN(profileID: String, name: String, host: String, port: Int,
                        transport: VPNProbe.Transport, ovpn: String,
                        requiresOTP: Bool) -> ProbeTargetFacts {
        var f = ProbeTargetFacts()
        f.kind = .openVPN
        f.profileID = profileID
        f.profileName = name
        f.host = host
        f.port = port
        f.transport = transport
        f.caPEM = OVPNInline.block("ca", in: ovpn)
        f.clientCertificatePEM = OVPNInline.block("cert", in: ovpn)
        f.clientKeyPEM = OVPNInline.block("key", in: ovpn)
        f.expectedServerName = Self.verifyX509Name(in: ovpn)
        f.tlsKey = OpenVPNStaticKey(profile: ovpn)
        f.requiresOTP = requiresOTP
        // `auth-user-pass` present (or simply not an autologin profile) means a
        // username/password stage exists at the top of the ladder.
        f.usesAccountSignIn = OVPNInline.directiveValue("auth-user-pass", in: ovpn) != nil
            || OVPNInline.block("auth-user-pass", in: ovpn) != nil
            || requiresOTP
        return f
    }

    /// `verify-x509-name <name> <type>` → the name to check the VPN's
    /// certificate against. `tls-remote` is the ancient spelling; still seen.
    static func verifyX509Name(in ovpn: String) -> String? {
        for key in ["verify-x509-name", "tls-remote"] {
            guard let raw = OVPNInline.directiveValue(key, in: ovpn), !raw.isEmpty else { continue }
            var value = raw.split(separator: " ", maxSplits: 1,
                                  omittingEmptySubsequences: true).first.map(String.init) ?? raw
            value = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            // "CN=vpn.example.org" and a bare subject DN both reduce to the CN.
            if let cnRange = value.range(of: "CN=", options: [.caseInsensitive]) {
                let tail = value[cnRange.upperBound...]
                value = String(tail.split(separator: ",").first ?? tail)
            }
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { return trimmed }
        }
        return nil
    }

    /// Facts for the SSH / SSL-VPN kinds, from their subprocess config. File
    /// paths are read here (on the caller's behalf) because the runner must not
    /// touch the filesystem for material it was never handed.
    static func subprocess(_ config: SubprocessTunnelConfig, host: String, port: Int,
                           requiresOTP: Bool,
                           read: (String) -> String? = { try? String(contentsOfFile: ($0 as NSString).expandingTildeInPath, encoding: .utf8) }) -> ProbeTargetFacts {
        var f = ProbeTargetFacts()
        f.kind = config.kind
        f.profileID = config.id
        f.profileName = config.name
        f.host = host
        f.port = port
        f.transport = config.kind == .ssh ? .tcp : .tcp
        f.username = config.username
        f.requiresOTP = requiresOTP || !config.tokenMode.isEmpty
        f.usesAccountSignIn = config.authMode != "certificate"

        if config.kind == .ssh {
            f.identityFilePath = config.identityFile.isEmpty ? nil : config.identityFile
            f.knownHostsPath = ("~/.ssh/known_hosts" as NSString).expandingTildeInPath
            f.strictHostKey = config.strictHostKey
            // SSH signs in with a key or a password — never a certificate chain.
            f.usesAccountSignIn = true
        } else {
            if !config.clientCertFile.isEmpty { f.clientCertificatePEM = read(config.clientCertFile) }
            if !config.clientKeyFile.isEmpty { f.clientKeyPEM = read(config.clientKeyFile) }
            if !config.caFile.isEmpty { f.caPEM = read(config.caFile) }
            if !config.trustedCertSHA256.isEmpty {
                f.pinnedServerCertificateSHA256 = config.trustedCertSHA256
            }
            f.expectedServerName = host
        }
        return f
    }

    static func wireGuard(_ config: WireGuardConfig, profileID: String,
                          host: String, port: Int) -> ProbeTargetFacts {
        var f = ProbeTargetFacts()
        f.kind = .wireGuard
        f.profileID = profileID
        f.profileName = config.name
        f.host = host
        f.port = port
        f.transport = .udp
        f.wireGuardPrivateKey = config.privateKey.isEmpty ? nil : config.privateKey
        f.wireGuardPeerPublicKey = config.peerPublicKey.isEmpty ? nil : config.peerPublicKey
        f.wireGuardPresharedKey = config.presharedKey.isEmpty ? nil : config.presharedKey
        // WireGuard has no account: its keys ARE the identity, and testing them
        // costs nothing and consumes nothing.
        f.usesAccountSignIn = false
        return f
    }

    static func native(_ config: NativeVPNConfig, host: String) -> ProbeTargetFacts {
        var f = ProbeTargetFacts()
        f.kind = config.kind
        f.profileID = config.id
        f.profileName = config.name
        f.host = host
        f.port = VPNProbe.ikeDefaultPort
        f.transport = .udp
        f.requestedEncryption = config.ikeEncryption
        f.requestedIntegrity = config.ikeIntegrity
        f.requestedDHGroup = config.ikeDHGroup
        f.remoteIdentifier = config.remoteID
        f.usesSharedSecret = config.usesSharedSecret
        f.usesAccountSignIn = !config.username.isEmpty || !config.usesSharedSecret
        return f
    }

    /// Where the Tailscale preset's control plane lives. The engine defaults to
    /// this when `effectiveControlURL` is empty, so the probe must aim at the
    /// same place or it would be testing nothing.
    static let tailscaleDefaultControlURL = "https://controlplane.tailscale.com"

    static func tailscale(_ config: TailscaleConfig, profileID: String, name: String) -> ProbeTargetFacts {
        var f = ProbeTargetFacts()
        f.kind = .tailscale
        f.profileID = profileID
        f.profileName = name
        f.controlURL = config.effectiveControlURL.isEmpty
            ? Self.tailscaleDefaultControlURL : config.effectiveControlURL
        f.isSelfHostedControl = config.preset == .headscale
        // Signing in happens in a browser (or with a setup key) and always
        // creates a session — so it is never something a probe may start.
        f.usesAccountSignIn = true
        if let url = URL(string: f.controlURL ?? ""), let h = url.host() {
            f.host = h
            f.port = url.port ?? 443
        }
        return f
    }
}
