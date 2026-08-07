// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListUpdateReview.swift
//  A HELD LIST UPDATE, TURNED INTO SOMETHING A PERSON CAN DECIDE ABOUT.
//
//  `ProviderServerListDiff` already says WHAT changed and refuses to apply a change
//  that moved a server the user holds. What it does not do — and what the fetch has
//  had no way to offer since it was built — is present that diff so it can be
//  ACCEPTED. Without this, an update that moves an address or a key can only be
//  declined by doing nothing: fail-safe, and a dead end.
//
//  THE RANKING IS THE POINT, AND IT IS NOT ALPHABETICAL.
//
//  Docs/ServiceBundles.md §3 records the asymmetry this whole feature turns on. For
//  OpenVPN the shipped CA does the work: a substituted hostname reaches a machine
//  that cannot present the provider's certificate and the connection FAILS CLOSED.
//  For WireGuard nothing does — there is no certificate, THE PEER PUBLIC KEY IS THE
//  AUTHENTICATION, and it arrives in the same payload as the address it
//  authenticates. Swap both together and every packet goes to the attacker with no
//  error at all.
//
//  So the order is: a changed KEY on a server the user HOLDS, then a changed key on
//  one they do not, then a changed address, then a server that vanished, then the
//  new arrivals. Sorting these by hostname would put the one row that can hand
//  somebody the whole tunnel wherever the alphabet happened to leave it.
//
//  REMOVAL IS A CHANGE, NOT A TIDY-UP. Somebody who can SHRINK your list to the one
//  server they control has chosen your exit as surely as somebody who substitutes an
//  address, and a deletion is the change that leaves no evidence. Retired servers get
//  rows of their own here, and a list that lost more than a third of itself gets a
//  line saying the whole update is held for that reason alone.
//
//  AND IT IS ALL-OR-NOTHING. There are deliberately no per-row controls in this
//  model and none in the sheet built on it: accepting the good half of an update
//  while a poisoned row sits in the same payload is precisely the outcome
//  `ProviderServerListDiff.needsConfirmation` exists to prevent.
//
//  PURE. No fetch, no store, no view.
//

import Foundation

nonisolated enum ProviderListUpdateReview {

    // MARK: - One line of the diff

    /// What happened to one server. `moved` carries WHICH field moved rather than a
    /// bare "changed", because a changed peer key deserves different words — and a
    /// different position in the list — from a changed IPv6 address.
    enum Change: Sendable, Equatable {
        case moved(ProviderServerListDiff.Movement)
        case removed
        case added
    }

    /// One server's row in the review.
    struct Row: Sendable, Equatable, Identifiable {

        let hostname: String
        let change: Change
        /// Is this a server the user's own VPN already holds?
        ///
        /// Load-bearing rather than decorative: a key that moved under a relay
        /// somebody is actually using is the change this sheet exists for, and one
        /// that moved under a relay they have never selected is a fact about the
        /// provider's fleet.
        let held: Bool

        var id: String { hostname }

        /// Smaller is shown first. See this file's header for why this order and not
        /// the alphabet.
        var rank: Int {
            switch change {
            case .moved(let movement):
                if movement.contains(.peerKey) { return held ? 0 : 1 }
                return held ? 2 : 3
            case .removed: return held ? 4 : 5
            case .added: return 6
            }
        }

        /// Does this row, on its own, deserve the leading warning? Only a moved peer
        /// key does, and only on a server the user holds.
        var isTheDangerousOne: Bool {
            guard case .moved(let movement) = change else { return false }
            return movement.contains(.peerKey) && held
        }
    }

    // MARK: - Producing the review

    /// Every change in the diff as a row, ranked.
    ///
    /// `heldHostnames` is what the user's VPN actually shows, so "you have this one"
    /// is answered against the Servers table rather than against the fetched list.
    ///
    /// ADDED SERVERS ARE INCLUDED even though rule 1 would apply them quietly on
    /// their own. Once an update is held, the user is deciding about the WHOLE
    /// payload — that is what all-or-nothing means — and a sheet that showed only the
    /// frightening half would be asking them to accept arrivals it never mentioned.
    static func rows(_ diff: ProviderServerListDiff,
                     heldHostnames: Set<String>) -> [Row] {
        var out: [Row] = []
        for moved in diff.moved {
            out.append(Row(hostname: moved.after.hostname.value,
                           change: .moved(moved.movement),
                           held: heldHostnames.contains(moved.after.hostname.value)))
        }
        for gone in diff.retired {
            out.append(Row(hostname: gone.hostname.value, change: .removed,
                           held: heldHostnames.contains(gone.hostname.value)))
        }
        for fresh in diff.added {
            out.append(Row(hostname: fresh.hostname.value, change: .added,
                           held: heldHostnames.contains(fresh.hostname.value)))
        }
        // Hostname only as a TIE-BREAK, so two runs of one review agree; never as
        // the sort itself.
        return out.sorted { ($0.rank, $0.hostname) < ($1.rank, $1.hostname) }
    }

    /// Does this update contain the change that can hand somebody the whole tunnel
    /// silently — a moved peer key on a server the user holds?
    static func hasMovedKeyOnHeldServer(_ rows: [Row]) -> Bool {
        rows.contains { $0.isTheDangerousOne }
    }
}

// MARK: - The words

/// Every string the approval sheet says, pure so a test can assert what VoiceOver
/// hears without building a view.
///
/// ONTOLOGY.md binds all of it: the machine a VPN connects to is a **server**, the
/// thing a provider publishes is **their server list**, and there is no noun for
/// "the thing you install".
nonisolated enum ProviderListUpdateCopy {

    // MARK: The sheet

    static func title(_ provider: VPNServiceProvider) -> String {
        "\(provider.displayName)\u{2019}s server list has changed"
    }

    /// The standing statement, before any button: nothing has happened yet. It is
    /// the first thing somebody needs and the last thing a diff view usually says.
    static let nothingAppliedYet = "Nothing has been changed. This is what the new list "
        + "would do if you accept it."

    /// The counts, in one sentence.
    static func summary(_ diff: ProviderServerListDiff) -> String {
        var parts: [String] = []
        let keys = diff.moved.filter { $0.movement.contains(.peerKey) }.count
        let addresses = diff.moved.count - keys
        if keys > 0 {
            parts.append("\(keys) server\(keys == 1 ? "" : "s") changed public key")
        }
        if addresses > 0 {
            parts.append("\(addresses) changed address")
        }
        if !diff.retired.isEmpty {
            parts.append("\(diff.retired.count) no longer listed")
        }
        if !diff.added.isEmpty {
            parts.append("\(diff.added.count) new")
        }
        if diff.unchangedCount > 0 {
            parts.append("\(diff.unchangedCount) unchanged")
        }
        return parts.isEmpty ? "Nothing changed." : ConfigurationDropCopy.list(parts) + "."
    }

    // MARK: The warnings that lead

    /// THE ONE THAT MATTERS, and it is shown above everything else or not at all.
    ///
    /// It says what a public key IS before it says what changed, because "the peer
    /// key rotated" means nothing to somebody who has never had to know that
    /// WireGuard has no certificate behind it.
    static func movedKeyWarning(_ provider: VPNServiceProvider) -> String {
        "A server you use has a different public key in this list. WireGuard has no "
            + "certificate \u{2014} the public key IS how it decides a server is the right one, "
            + "and it arrived in the same download as the address it vouches for. If this is "
            + "not a change \(provider.displayName) has actually made, accepting it would send "
            + "your traffic somewhere else with nothing on screen to say so."
    }

    /// Rule 3's threshold, in words. Shown whether or not any server the user holds
    /// was among the losses, because that is exactly the point.
    static func lostTooManyWarning(_ provider: VPNServiceProvider,
                                   retired: Int, stored: Int) -> String {
        "This list has lost \(retired) of \(stored) servers. A list that shrinks is a way of "
            + "choosing your exit for you \u{2014} somebody who can take away every server but "
            + "one has picked it for you \u{2014} so the whole update is held until you say, "
            + "whether or not you were using any of them. Nothing is ever deleted: a server "
            + "\(provider.displayName) stops listing is kept and marked retired."
    }

    /// Why there is no per-row choice, said where somebody would look for one.
    static let allOrNothing = "This is one decision for the whole list. Accepting some rows and "
        + "not others would let a bad entry in beside the good ones, so there is nothing to tick."

    // MARK: One row

    static func rowTitle(_ row: ProviderListUpdateReview.Row) -> String { row.hostname }

    /// What happened to this server, in the user's terms. The row's caption AND its
    /// spoken value, so nothing here is sighted-only.
    static func sentence(_ row: ProviderListUpdateReview.Row) -> String {
        var out: String
        switch row.change {
        case .moved(let movement):
            let key = movement.contains(.peerKey)
            let address = movement.contains(.address)
            if key && address {
                out = "Its public key and its address both changed."
            } else if key {
                out = "Its public key changed."
            } else {
                out = "Its address changed."
            }
        case .removed:
            out = "No longer listed. It would be kept and marked retired, never deleted."
        case .added:
            out = "New in this list."
        }
        if row.held { out += " You have this server." }
        return out
    }

    static func spoken(_ row: ProviderListUpdateReview.Row) -> String {
        "\(row.hostname). \(sentence(row))"
    }

    /// The row's glyph. Never the only carrier: the same fact is in the sentence
    /// beside it, and its shape differs per change so Differentiate Without Color
    /// costs nothing here.
    static func symbol(_ row: ProviderListUpdateReview.Row) -> String {
        switch row.change {
        case .moved(let movement): movement.contains(.peerKey) ? "key.slash" : "arrow.triangle.swap"
        case .removed: "archivebox"
        case .added: "plus.circle"
        }
    }

    /// The group heading a run of rows sits under, so the list is a STRUCTURE to
    /// navigate rather than one long recitation (Docs/Accessibility.md rule 6).
    static func heading(_ row: ProviderListUpdateReview.Row) -> String {
        switch row.change {
        case .moved(let movement):
            if movement.contains(.peerKey) {
                return row.held ? "Changed public key \u{2014} on servers you have"
                                : "Changed public key"
            }
            return row.held ? "Changed address \u{2014} on servers you have" : "Changed address"
        case .removed: return row.held ? "No longer listed \u{2014} servers you have"
                                       : "No longer listed"
        case .added: return "New servers"
        }
    }

    // MARK: The buttons

    /// THE SAFE BUTTON, and it is the one that does nothing. It carries the cancel
    /// shortcut, so Escape does the safe thing; the accepting button deliberately
    /// carries no key equivalent at all, which is the same treatment the WireGuard
    /// with-keys export consent already uses for the same reason.
    static let keepTitle = "Keep What I Have"

    static func acceptTitle(_ provider: VPNServiceProvider) -> String {
        "Accept \(provider.displayName)\u{2019}s Changes"
    }

    static func keepHelp(_ provider: VPNServiceProvider) -> String {
        "Leave your servers exactly as they are. \(provider.displayName) can be asked again "
            + "whenever you like."
    }

    static func acceptHelp(_ provider: VPNServiceProvider) -> String {
        "Store this list, including every change above. Servers "
            + "\(provider.displayName) stopped listing are kept and marked retired."
    }

    // MARK: What is said afterwards

    static func accepted(_ provider: VPNServiceProvider, total: Int) -> String {
        "Accepted \(provider.displayName)\u{2019}s changes. Their list now has \(total) "
            + "server\(total == 1 ? "" : "s")."
    }

    static func declined(_ provider: VPNServiceProvider) -> String {
        "Kept what you had. Nothing from \(provider.displayName)\u{2019}s new list has been "
            + "stored, and your servers are exactly as they were."
    }
}
