// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardSettingDescriptors.swift
//  The WireGuard option catalog: one EngineSettingSpec per exposed option, in
//  canonical group order (AGENTS.md "Config surfaces"). WireGuard's keys ARE its
//  sign-in, so they group there; the wg-quick Interface/Peer split survives only
//  in the .conf round-trip, not in the form.
//
//  Lived inside `WireGuardView` until app-wide search needed it: a catalog
//  private to a View can only be searched by that View, which is how five of six
//  editors ended up with no search at all. `WireGuardView.specs` is now a thin
//  alias for this table, so the form's ~60 `Self.specs["wg.x"]` call sites are
//  unchanged.
//

import Foundation

@MainActor
enum WireGuardSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "wg.endpoint", name: "Server Address",
              summary: "The server's public address and port, host:port (e.g. vpn.example.com:51820) — the Endpoint line of a wg-quick file.",
              group: .connection, default: ""),
        .init(id: "wg.listen-port", name: "Listen Port",
              summary: "UDP port WireGuard listens on locally, 0–65535. Leave empty (or 0) to let the system pick one.",
              group: .connection, default: Int?.none),

        // MARK: Sign-In

        // The single most important field in this editor, and the last one still
        // hand-rolled: no spec meant no manual anchor, no search hit, and no way
        // for the CLI or MDM to name it.
        .init(id: "wg.private-key", name: "Private Key",
              summary: "This device's own secret key (base64) — the other half of the public key you gave your provider. Kept in your Keychain and never shown again once saved.",
              group: .signIn, default: false),
        .init(id: "wg.public-key", name: "Peer Public Key",
              summary: "The server peer's public key (base64). Identifies and encrypts to the server. From your provider.",
              group: .signIn, default: ""),
        .init(id: "wg.preshared-key", name: "Pre-shared Key",
              summary: "Optional extra symmetric key (base64) added on top for post-quantum resistance. Only if your provider gives you one.",
              group: .signIn, default: false),

        // MARK: Traffic

        .init(id: "wg.address", name: "Addresses",
              summary: "The in-tunnel IP address(es) this device is assigned, with prefix (e.g. 10.0.0.2/32). From your provider.",
              group: .traffic, default: [String]()),
        .init(id: "wg.allowed-ips", name: "Allowed IPs",
              summary: "Which destinations go through this peer. 0.0.0.0/0, ::/0 sends everything (full tunnel); specific subnets make it split.",
              group: .traffic, default: [String]()),
        .init(id: "wg.dns", name: "DNS Servers",
              summary: "DNS servers to use while connected. Often points inside the tunnel so private names resolve.",
              group: .traffic, default: [String]()),
        .init(id: "wg.mtu", name: "MTU",
              summary: "Largest packet size on the tunnel, 1280–1500. Leave empty for the standard 1420; lower it (e.g. 1380) if some sites hang.",
              group: .traffic, default: Int?.none),

        // MARK: Advanced
        //
        // Both are routing escape hatches that this app's engine never reads, and
        // they are each other's siblings — the routing table sat under Traffic
        // beside the Allowed IPs it can silently make inert.

        .init(id: "wg.table", name: "Routing Table",
              summary: "“auto” installs routes for the allowed IPs; “off” installs none (you manage routing yourself). Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it.",
              group: .advanced, default: ""),
        .init(id: "wg.fwmark", name: "Firewall Mark",
              summary: "A firewall mark placed on the tunnel's own packets, for advanced policy routing. Rarely needed. Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it.",
              group: .advanced, default: ""),
        .init(id: "wg.keepalive", name: "Persistent Keepalive",
              summary: "Seconds between keepalive packets to hold the tunnel open through NAT/firewalls, 0–65535. 25 is typical behind NAT; empty or 0 = off.",
              group: .advanced, default: Int?.none),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
