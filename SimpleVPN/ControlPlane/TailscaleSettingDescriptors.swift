// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleSettingDescriptors.swift
//  The Tailscale / Headscale option catalog (anchors: ts.x → #ts-x in
//  manual.html), in canonical group order (AGENTS.md "Config surfaces"). There is
//  no Security content and — with Share Networks under Traffic, where a decision
//  about which networks this Mac carries belongs — no Advanced content either, so
//  both groups are OMITTED rather than shown empty.
//
//  Copy rule (TailscaleView's header): no jargon. "Tailnet", "MagicDNS", "subnet
//  router" and "node" do not appear in any name or summary here.
//
//  Moved out of `TailscaleView` so app-wide search can reach it;
//  `TailscaleView.specs` aliases this table.
//

import Foundation

@MainActor
enum TailscaleSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "ts.preset", name: "Service",
              summary: "Tailscale's own coordination service, or a Headscale server you run yourself. It is the same engine either way — this only decides whether you're asked for a server address.",
              group: .connection, default: TailscaleConfig.Preset.tailscale),
        .init(id: "ts.control-url", name: "Server Address",
              summary: "The web address of your own Tailscale-compatible server (Headscale). Must start with https://.",
              group: .connection, default: ""),
        .init(id: "ts.hostname", name: "Name on the Network",
              summary: "What this Mac is called to the other machines on your network. Defaults to your Mac's name.",
              group: .connection, default: ""),

        // MARK: Sign-In

        .init(id: "ts.auth-key", name: "Setup Key",
              summary: "An optional key from your network's admin page that signs this Mac in without a browser. Leave empty and you'll sign in the usual way, once.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "ts.accept-routes", name: "Use Shared Networks",
              summary: "Some machines share the office or home network they sit on. With this on, those networks are reachable through this VPN too.",
              group: .traffic, default: true),
        .init(id: "ts.accept-dns", name: "Use This Network's DNS",
              summary: "Lets you reach the other machines by name instead of by address, and uses the DNS servers your network specifies.",
              group: .traffic, default: true),
        .init(id: "ts.exit-node", name: "Send Internet Traffic Elsewhere",
              summary: "Route everything — not just traffic to your own machines — through another machine on the network, the way a traditional VPN would.",
              group: .traffic, default: false),
        .init(id: "ts.exit-node-machine", name: "Machine",
              summary: "Which machine on your network carries your internet traffic. It has to be offering to, and be approved on the admin page — SimpleVPN can only list the ones that are while connected.",
              group: .traffic, default: ""),
        .init(id: "ts.exit-node-lan", name: "Allow Local Network Access",
              summary: "While your internet traffic goes through another machine, keep the network you are physically on — printers, file shares — directly reachable.",
              group: .traffic, default: true),
        // Sharing the networks this Mac can reach is a decision about which
        // traffic this tunnel carries, so it sits with the other traffic
        // decisions rather than alone under an "Advanced" heading.
        .init(id: "ts.advertise-routes", name: "Share Networks From This Mac",
              summary: "Offer the networks this Mac can reach (like your home LAN) to the other machines. They still have to be approved on the admin page.",
              group: .traffic, default: ""),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
