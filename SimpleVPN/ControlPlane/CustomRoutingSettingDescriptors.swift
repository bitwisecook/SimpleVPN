// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CustomRoutingSettingDescriptors.swift
//  The Custom Routing option catalog: one EngineSettingSpec per user-facing
//  control on the Custom Routing tab. This is the ONE config surface present in
//  every single VPN kind's editor, and until this catalog existed none of it was
//  descriptor-backed — twenty-five controls that search could not reach, the CLI
//  could not address, MDM could not force, and whose help buttons did not exist.
//
//  ids are the CLI/MDM/manual-anchor contract ("cr.route-rule" → manual
//  #cr-route-rule) and NEVER change; only display names and summaries may be
//  reworded. CustomRoutingTabView renders its rows from this table;
//  ManualAnchorParityTests pins spec-id ↔ manual-anchor parity in both directions.
//
//  Grouping note: Custom Routing is its own TAB, not one of the canonical five
//  groups (AGENTS.md "Config surfaces"), but every spec still declares the group
//  its subject belongs to so the taxonomy stays answerable for search, the CLI and
//  MDM: routes, resolvers, domains and the proxy itself are Traffic decisions; the
//  proxy's username and password are Sign-In.
//

import Foundation

@MainActor
enum CustomRoutingSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Traffic — routes

        .init(id: "cr.routes-default", name: "Unmatched Routes",
              summary: "What happens to the networks this VPN offers that no rule below mentions: Accept keeps them, Ignore drops them so only what a rule accepts is used.",
              group: .traffic, default: UnmatchedDisposition.accept),

        .init(id: "cr.route-rule", name: "Route Rules",
              summary: "An ordered list that edits the networks this VPN offers: accept one, ignore one, replace one with another, or add a network the VPN never offered.",
              group: .traffic, default: 0),

        // MARK: Traffic — DNS

        .init(id: "cr.dns-default", name: "Unmatched Resolvers",
              summary: "What happens to the DNS servers this VPN offers that no rule below mentions: Accept keeps them, Ignore drops them so only what a rule accepts is used.",
              group: .traffic, default: UnmatchedDisposition.accept),

        .init(id: "cr.dns-rule", name: "Resolver Rules",
              summary: "An ordered list that edits the DNS servers this VPN offers: accept one, ignore one, replace one with another, or add a server of your own.",
              group: .traffic, default: 0),

        .init(id: "cr.ignore-pushed-search", name: "Ignore All Pushed Search Domains",
              summary: "Drop every search domain this VPN offers. Search domains let you type a short name (\u{201C}wiki\u{201D}) and have it completed to a full one.",
              group: .traffic, default: false),

        .init(id: "cr.ignore-pushed-match", name: "Ignore All Pushed Match Domains",
              summary: "Drop every match domain this VPN offers. Match domains are the name suffixes whose lookups go to this VPN's DNS servers instead of your Mac's.",
              group: .traffic, default: false),

        .init(id: "cr.add-search-domains", name: "Search Domains",
              summary: "Search domains to add to whatever this VPN offers, and individual ones to leave out. Comma-separated.",
              group: .traffic, default: [String]()),

        .init(id: "cr.match-domains", name: "Match Domains",
              summary: "Name suffixes to send to this VPN's DNS servers on top of whatever it offers, and individual ones to leave out. Comma-separated.",
              group: .traffic, default: [String]()),

        // MARK: Traffic — proxy

        .init(id: "cr.proxy-mode", name: "Proxy",
              summary: "Whether to use the proxy this VPN offers, go direct and ignore it, or use a proxy of your own.",
              group: .traffic, default: ProxyCustomization.Mode.accept),

        .init(id: "cr.proxy-manual-url", name: "Manual Proxy Address",
              summary: "The proxy to use while connected, as http(s)://host:port or socks5://host:port. Ignored while a PAC URL is set — that wins.",
              group: .traffic, default: ""),

        .init(id: "cr.proxy-pac-url", name: "PAC URL",
              summary: "The address of a proxy auto-configuration script, which decides per-site which proxy to use. Takes precedence over the manual address above.",
              group: .traffic, default: ""),

        // MARK: Sign-In — the proxy's own credentials

        .init(id: "cr.proxy-auth", name: "Proxy Sign-In",
              summary: "The username and password the proxy asks for, if it does. Kept in your Keychain — the VPN's settings only ever carry a reference to it.",
              group: .signIn, default: false),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
