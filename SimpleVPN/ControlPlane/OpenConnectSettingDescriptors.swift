// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectSettingDescriptors.swift
//  The OpenConnect SSL-VPN option catalog (anchors: oc.x → #oc-x in manual.html)
//  — one table shared by all seven SSL-VPN kinds (AnyConnect, FortiGate, F5 APM,
//  GlobalProtect, Juniper, Pulse, Array), because they are one editor driving one
//  tool with one set of flags.
//
//  In canonical group order (AGENTS.md "Config surfaces"). Note the MTU split
//  documented there: `oc.mtu` is the user-facing tunnel MTU and lives in Traffic
//  (it is the one someone is told to lower when transfers stall); `oc.base-mtu`
//  describes the network path UNDERNEATH the tunnel and stays in Advanced.
//
//  Moved out of `SubprocessTunnelView` so app-wide search can reach it;
//  `SubprocessTunnelView.specs` aliases this table.
//

import Foundation

@MainActor
enum OpenConnectSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "oc.reconnect-timeout", name: "Reconnect Timeout",
              summary: "How long (0–86400 seconds) to keep retrying a dropped tunnel before giving up.",
              group: .connection, default: Int?.none),

        // MARK: Sign-In

        .init(id: "oc.password", name: "Password",
              summary: "The password for this VPN. Used by password sign-in only — a client certificate or single sign-on doesn't send it.",
              group: .signIn, default: ""),
        .init(id: "oc.client-cert", name: "Client Certificate",
              summary: "A certificate file (PEM or .p12) that identifies YOU to the gateway, instead of a password. Used by certificate sign-in only.",
              group: .signIn, default: ""),
        .init(id: "oc.client-key", name: "Client Private Key",
              summary: "The private key for the client certificate, when it isn't inside the certificate file itself.",
              group: .signIn, default: ""),
        .init(id: "oc.key-password", name: "Key / PKCS#12 Passphrase",
              summary: "The passphrase protecting your client key or .p12 file. Stored in your login keychain.",
              group: .signIn, default: ""),
        .init(id: "oc.sso-browser", name: "Sign-In Browser",
              summary: "Which browser (and profile) opens the single sign-on page, so passkeys and saved passwords are where you keep them.",
              group: .signIn),
        .init(id: "oc.token-mode", name: "Verification-Code Token",
              summary: "Have OpenConnect produce the verification code (TOTP, HOTP, OIDC, RSA SecurID or a YubiKey) instead of you typing it. Used alongside password or certificate sign-in.",
              group: .signIn, default: ""),
        .init(id: "oc.token-secret", name: "Token Secret",
              summary: "The seed your verification codes are generated from. Stored in your login keychain and handed over in a private file — never on the command line. Not needed for a YubiKey, which holds its own.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "oc.mtu", name: "MTU",
              summary: "Largest tunnel packet size, 576–1500. Leave empty to auto-detect; lower it if transfers stall.",
              group: .traffic, default: Int?.none),

        // MARK: Security

        .init(id: "oc.cafile", name: "CA Certificate File",
              summary: "A PEM file of extra certificate authorities to trust for the VPN server, if it uses a private CA.",
              group: .security, default: ""),

        // MARK: Advanced

        .init(id: "oc.os", name: "Reported OS",
              summary: "The operating system OpenConnect claims to be, which some servers policy-check. Pick one only if your gateway refuses a Mac; anything else isn't a value OpenConnect accepts.",
              group: .advanced, default: ""),
        .init(id: "oc.no-dtls", name: "Disable DTLS",
              summary: "Force the slower-but-more-compatible TLS transport instead of UDP DTLS. Turn on only if DTLS is blocked or flaky.",
              group: .advanced, default: false),
        .init(id: "oc.disable-csd", name: "Skip Host Checker",
              summary: "Bypass the server's endpoint-posture/host-checker script. May be required to connect from an unmanaged Mac; some servers refuse without it.",
              group: .advanced, default: false),
        .init(id: "oc.base-mtu", name: "Base MTU",
              summary: "The MTU of the underlying network path (576–9000, allowing jumbo frames), used to size the tunnel. Leave empty to auto-detect.",
              group: .advanced, default: Int?.none),
        .init(id: "oc.force-dpd", name: "Dead-Peer Detection (seconds)",
              summary: "Send a liveness probe this often (0–3600 seconds) and reconnect fast if the server stops answering. Empty leaves the protocol default.",
              group: .advanced, default: Int?.none),
        .init(id: "oc.extra-args", name: "Extra Arguments",
              summary: "Raw OpenConnect flags (one per row) for site-specific needs not covered above.",
              group: .advanced, default: [String]()),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
