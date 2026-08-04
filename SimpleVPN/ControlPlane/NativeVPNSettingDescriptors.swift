// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNSettingDescriptors.swift
//  The OS-native personal-VPN option catalog (IKEv2 / IPsec / L2TP; anchors:
//  native.x → #native-x in manual.html), in canonical group order (AGENTS.md
//  "Config surfaces"): Connection → Sign-In → Traffic → Security → Advanced.
//
//  Moved out of `NativeVPNView` so app-wide search can reach it;
//  `NativeVPNView.specs` aliases this table.
//

import Foundation

@MainActor
enum NativeVPNSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "native.protocol", name: "Protocol",
              summary: "Which VPN protocol macOS runs for this connection. IKEv2 is the modern one; IPsec (IKEv1) suits older Cisco-style concentrators; L2TP is exported as a configuration profile you install.",
              group: .connection, default: VPNKind.ikev2),

        .init(id: "native.server", name: "Server Address",
              summary: "The address of the VPN server, as a name like vpn.example.com or an IP address.",
              group: .connection, default: ""),

        .init(id: "native.group", name: "Group / Local Identifier",
              summary: "The group name (sometimes \u{201C}tunnel group\u{201D}) that tells the concentrator which of its configurations answers you. Only if your administrator gave you one.",
              group: .connection, default: ""),

        .init(id: "native.on-demand", name: "Connect on Demand",
              summary: "Reconnect this VPN whenever any app opens a network connection. There are no per-network conditions — it applies on every network.",
              group: .connection, default: false),

        // Lifecycle, sibling of Connect on Demand — it answers "when does this
        // VPN go away", not "how is the tunnel built" (it was under Advanced).
        .init(id: "native.disconnect-sleep", name: "Disconnect on Sleep",
              summary: "Drop the VPN when the Mac sleeps instead of resuming it on wake. Off keeps it up across sleep.",
              group: .connection, default: false),

        // MARK: Sign-In

        .init(id: "native.auth-method", name: "Use a Shared Secret (PSK)",
              summary: "How you prove who you are: a shared secret everyone using this VPN has, or your own username and password.",
              group: .signIn, default: false),

        // `default: true`, matching the MODEL: `NativeVPNConfig.usesXAuth` is
        // `xauth ?? !username.isEmpty`, and every IPsec config that reaches this
        // row with a username — which is every Cisco `.pcf` import, they always
        // carry one — therefore rests at ON. Declaring `false` made the row
        // permanently bold and had VoiceOver say "changed from default" on a VPN
        // nobody had touched. `NativeVPNSecrets.plan`'s own `xauth:` parameter
        // default is `true` for the same reason.
        .init(id: "native.xauth", name: "Also Sign In With a Username and Password (XAuth)",
              summary: "Some concentrators want the group secret alone; others want a personal username and password as well. Turn this off and neither is sent.",
              group: .signIn, default: true),

        .init(id: "native.username", name: "Username",
              summary: "The account name to sign in to this VPN with.",
              group: .signIn, default: ""),

        .init(id: "native.password", name: "Password",
              summary: "Your personal password for this VPN. Stored in your Keychain and handed to macOS when the tunnel starts.",
              group: .signIn, default: ""),

        .init(id: "native.shared-secret", name: "Shared Secret",
              summary: "The pre-shared key (sometimes \u{201C}group secret\u{201D} or \u{201C}machine secret\u{201D}) — the same one for everyone using this VPN. Stored in your Keychain.",
              group: .signIn, default: ""),

        .init(id: "native.xauth-password", name: "Password (XAuth)",
              summary: "The personal password this concentrator asks for on top of the shared secret. Stored in your Keychain.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "native.include-all", name: "Send All Traffic",
              summary: "Route everything through the VPN (full tunnel). Off means only the server's routes go through it.",
              group: .traffic, default: false),
        .init(id: "native.exclude-local", name: "Allow Local Network Access",
              summary: "While sending all traffic through the VPN, still let your local network (printers, file shares) stay reachable.",
              group: .traffic, default: true),

        // MARK: Security
        //
        // The remote identifier is a SERVER-verification setting: it is the name
        // the server's certificate has to present, which is what stops a
        // different server answering for this address. It sat under Connection
        // next to the address it verifies.

        .init(id: "native.remote-id", name: "Remote Identifier",
              summary: "The identity the server must prove it has — checked against its certificate. Leave empty to require the server address itself.",
              group: .security, default: ""),

        .init(id: "native.encryption", name: "Encryption",
              summary: "The cipher for the IKE/child security associations. Leave Automatic unless your admin specifies one; AES-256-GCM is a strong modern default.",
              group: .security, default: ""),
        .init(id: "native.integrity", name: "Integrity / PRF",
              summary: "The hash protecting message integrity. Automatic is fine for most servers.",
              group: .security, default: ""),
        .init(id: "native.dh-group", name: "Diffie-Hellman Group",
              summary: "The key-exchange group. Higher numbers are stronger; 19–21 are elliptic-curve. Must match what the server offers.",
              group: .security, default: ""),
        .init(id: "native.pfs", name: "Perfect Forward Secrecy",
              summary: "Rekey the data channel with a fresh key exchange so a stolen key can't decrypt past traffic. Enable if the server requires it.",
              group: .security, default: false),
        .init(id: "native.ike-lifetime", name: "Key Lifetime (minutes)",
              summary: "How long each key lasts before the tunnel negotiates a fresh one, 10–1440. Leave empty for macOS's own (60 minutes, or 30 for the data channel); set it only if your admin specifies a value.",
              group: .security, default: Int?.none),

        // MARK: Advanced

        .init(id: "native.dpd", name: "Dead Peer Detection",
              summary: "How aggressively to probe whether the server is still there, to notice a dropped tunnel. Higher = faster detection, more chatter. Automatic leaves macOS's own choice (every 10 minutes) untouched.",
              group: .advanced, default: ""),
        .init(id: "native.mobike", name: "Disable MOBIKE",
              summary: "MOBIKE lets the tunnel survive network changes (Wi-Fi ↔ Ethernet). Only disable it if a picky server misbehaves with it on.",
              group: .advanced, default: false),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
