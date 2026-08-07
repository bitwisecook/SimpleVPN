// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderPickerCopy.swift
//  EVERY WORD THE PROVIDER ROWS SAY, in one place and testable without a view.
//
//  THE NAMING RULE THIS FILE EXISTS UNDER (ONTOLOGY.md §7, and it is enforced by a
//  test): THERE IS NO USER-FACING NOUN FOR "THE THING BEING INSTALLED". Not bundle,
//  not pack, not preset, not profile template. Every one of those words promises a
//  completeness this feature can never deliver, because the last mile is an account
//  SimpleVPN deliberately does not touch — and somebody who reads "Mullvad bundle"
//  and then cannot connect has been misled by the noun before they reached the error
//  message.
//
//  SO THE BUTTONS ARE NAMED AFTER THE COMPANIES AND THE ACTIONS ARE VERBS. "Mullvad"
//  is a row; "Get Mullvad's server list" is what pressing it does. That is not a
//  stylistic preference — it is the only phrasing that stays true when the answer is
//  "and now you still have to sign in to Mullvad yourself".
//
//  THE SECOND RULE: THE ROW STATES THE GAP BEFORE THE FETCH, NOT AFTER IT FAILS. The
//  four providers are genuinely different — one is WireGuard-only and needs a
//  configuration you already downloaded, one needs service credentials that are NOT
//  your account login, one is a plain username and password, and one CANNOT BE DONE
//  AT ALL. Copy that flattened them into "add a provider" would be lying about three
//  of the four.
//

import Foundation

nonisolated enum ProviderPickerCopy {

    // MARK: The section

    /// The heading over the four rows. A verb phrase naming what happens, with no
    /// noun for the thing — see this file's header.
    static let sectionTitle = "Add servers from a VPN provider"

    /// What the section is for, said before anything is pressed. Both halves matter:
    /// what it saves, and what it is not.
    static let sectionDetail = "If you already have an account with one of these, SimpleVPN can "
        + "fill in their servers so you don\u{2019}t type them by hand. It never signs you in \u{2014} "
        + "your account stays between you and them."

    /// Shown on the first-run page, where the reader has no VPNs at all and could
    /// reasonably think this is a way to GET one. It is not, and saying so here is
    /// cheaper than saying it after they have pressed something.
    static let firstRunDetail = "These fill in a provider\u{2019}s servers once you have their "
        + "configuration. They are not a way to buy or sign in to a VPN \u{2014} if you don\u{2019}t "
        + "have an account yet, get one from the provider first, then come back."

    // MARK: One row

    /// The row's title: the company's own spelling, and nothing else.
    static func title(_ p: VPNServiceProvider) -> String { p.displayName }

    /// What pressing it does, as a verb. Never "Install", "Set up" or "Add Mullvad" —
    /// all three promise a working VPN.
    static func actionTitle(_ p: VPNServiceProvider) -> String {
        p.blocked == nil ? "Get \(p.displayName)\u{2019}s server list" : "Import from \(p.displayName)"
    }

    /// The row's own sentence: what it can do, then what the user must still supply,
    /// or — for a provider that cannot be read — why not and what does work instead.
    ///
    /// The protocol is named because it decides what the user needs: a WireGuard
    /// provider wants a key and a tunnel address, an OpenVPN one wants a username and
    /// a password, and somebody who has one and not the other should be able to tell
    /// from the row.
    static func detail(_ p: VPNServiceProvider) -> String {
        if let blocked = p.blocked { return blocked }
        return "\(protocolClause(p)) \(p.stillNeeded)"
    }

    private static func protocolClause(_ p: VPNServiceProvider) -> String {
        switch p.kind {
        case .wireGuard: "Their servers are WireGuard."
        case .openVPN: "Their servers are OpenVPN."
        default: ""
        }
    }

    /// What the download will cost, said BEFORE it starts. Nord's list is about 9 MB
    /// and that is worth knowing on a tethered connection — see
    /// `VPNServiceProvider.approximateBytes` for where the number came from.
    static func downloadSize(_ p: VPNServiceProvider) -> String? {
        guard p.blocked == nil, p.approximateBytes > 0 else { return nil }
        return "About \(Int64(p.approximateBytes).formatted(.byteCount(style: .file))) to download."
    }

    // MARK: The first fetch — naming the host before contacting it

    /// The consent sheet's title. It asks about ONE provider: agreeing to Mullvad is
    /// not agreeing to Nord, and a sheet that said "allow server lists" would collect
    /// one yes for four companies.
    static func consentTitle(_ p: VPNServiceProvider) -> String {
        "Ask \(p.displayName) for their server list?"
    }

    /// THE HOST IS NAMED BEFORE IT IS CONTACTED. That is the whole point of the sheet
    /// and the reason it exists at all rather than a spinner.
    ///
    /// Three things, in the order somebody cares about them: who gets contacted, what
    /// they learn, and what SimpleVPN will NOT do — the last because "will this sign
    /// me in / send them my details?" is the question a person actually has.
    static func consentMessage(_ p: VPNServiceProvider, throughTunnel: Bool) -> String {
        let host = p.listURL?.host() ?? p.displayName
        var out = "SimpleVPN will make one request to \(host) and read the list of servers "
            + "\(p.displayName) publishes. "
        out += throughTunnel
            ? "You are connected to \(p.displayName) right now, so the request goes out through "
                + "their own network \u{2014} they learn nothing they are not already carrying."
            : "You are not connected to \(p.displayName), so they will see your real address and "
                + "roughly when you asked. You can connect first and try again instead."
        out += "\n\nNothing about you is sent: no account, no name, no sign-in. SimpleVPN cannot "
            + "sign you in to \(p.displayName) and will not ask them for anything else."
        if let size = downloadSize(p) { out += " \(size)" }
        return out
    }

    /// The confirming button says what it will do. Never "OK".
    static func consentConfirm(_ p: VPNServiceProvider) -> String { "Ask \(p.displayName)" }

    // MARK: Applying

    /// What the apply button will do, counted. A number rather than "Add servers",
    /// because the number is the thing somebody is deciding about.
    static func applyTitle(count: Int) -> String {
        count == 1 ? "Add 1 Server" : "Add \(count) Servers"
    }

    /// Said after an apply, and it is the sentence the whole feature is for: the
    /// servers are now in the ordinary list, where the ordinary sorting applies.
    static func applied(count: Int, provider: VPNServiceProvider, vpn: String) -> String {
        "Added \(count) \(provider.displayName) server\(count == 1 ? "" : "s") to \(vpn). "
            + "They are in the Servers list with everything else \u{2014} quickest first once "
            + "they have been checked, or nearest first until then."
    }

    /// The empty case. A filter that matches nothing must say so rather than showing
    /// a disabled button with no explanation.
    static let nothingMatches = "No servers in the places you picked. Choose more countries, "
        + "or clear the filter to see everything they publish."
}
