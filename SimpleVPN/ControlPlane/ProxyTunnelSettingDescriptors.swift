// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelSettingDescriptors.swift
//  The Proxy Tunnel option catalog (anchors: px.x → #px-x in manual.html), in
//  canonical group order (AGENTS.md "Config surfaces"): Connection → Sign-In →
//  Traffic. No Security or Advanced content — DNS and MTU are user-facing traffic
//  knobs here — so both groups are omitted.
//
//  Copy rule (ProxyTunnelView's header): plain words. "tun2socks", "netstack",
//  "CONNECT method" and "5-tuple" do not appear in any name or summary.
//
//  Moved out of `ProxyTunnelView` so app-wide search can reach it;
//  `ProxyTunnelView.specs` aliases this table.
//

import Foundation

@MainActor
enum ProxyTunnelSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "px.kind", name: "Kind",
              summary: "Which kind of proxy this is: SOCKS5, HTTP CONNECT or HTTPS CONNECT. Match what your proxy's own documentation calls it.",
              group: .connection, default: ProxyTunnelConfig.Preset.socks5),
        .init(id: "px.address", name: "Proxy Address",
              summary: "The proxy that carries your traffic, as host or host:port. Pick the kind above to match your proxy (SOCKS5 or HTTP CONNECT).",
              group: .connection, default: ""),

        // MARK: Sign-In

        .init(id: "px.requires-auth", name: "Requires Sign-In",
              summary: "Turn on if your proxy asks for a username and password. Leave off for an open proxy.",
              group: .signIn, default: false),
        .init(id: "px.username", name: "Username",
              summary: "The username your proxy expects.",
              group: .signIn, default: ""),
        .init(id: "px.password", name: "Password",
              summary: "The password your proxy expects. Stored in your Keychain, handed to the proxy only in memory.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "px.default-route", name: "Send All Traffic",
              summary: "Route everything on this Mac through the proxy (full tunnel). Turn off to send only specific networks through it and leave the rest direct (split tunnel).",
              group: .traffic, default: true),
        .init(id: "px.included", name: "Networks Through the Proxy",
              summary: "When not sending all traffic, these networks (as CIDRs) go through the proxy and nothing else does.",
              group: .traffic, default: ""),
        .init(id: "px.excluded", name: "Networks Kept Direct",
              summary: "Networks to send straight out, never through the proxy — even when \u{201C}Send all traffic\u{201D} is on.",
              group: .traffic, default: ""),
        .init(id: "px.dns", name: "DNS Servers",
              summary: "Name servers to use while connected. Lookups to them go through the proxy too, so they don't leak. Leave empty to keep your Mac's own DNS.",
              group: .traffic, default: ""),
        .init(id: "px.mtu", name: "MTU",
              summary: "The tunnel's maximum packet size. 1500 suits almost everything; lower it only if a network in the path needs smaller packets.",
              group: .traffic, default: ProxyTunnelStartConfig.defaultMTU),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
