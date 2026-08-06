// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ServersTableCopy.swift
//  Every word the Servers table says, and every decision behind those words, in
//  one pure place. Nothing here imports SwiftUI, so a test can assert what a cell
//  announces without building a table — which matters more than usual for a
//  `Table`, because a table's cells cannot be reached from a unit test at all.
//
//  Three rules are encoded here rather than left to each cell:
//
//  1. A HINT IS NOT A LABEL. A low-contrast word in an empty cell says what
//     belongs there. It is passed as a `TextField` `prompt:` — never as the
//     field's title, which `LabeledContent` renders as visible content and
//     VoiceOver announces as the field's NAME. So the accessible value of an
//     empty cell must SAY it is empty (`fieldValue`), never recite the hint;
//     otherwise a screen-reader user is told the address is "Address".
//  2. THE TOOLTIP IS NEVER THE ONLY CARRIER. One string per cell feeds both
//     `.help` and `.accessibilityValue` (Docs/Accessibility.md rule 5), so
//     nothing here is hover-only.
//  3. A DISABLED CONTROL SAYS WHY. `removeBlockedReason` / `probeBlockedReason`
//     return the sentence, and the same sentence goes to help and to VoiceOver.
//

import Foundation

/// The words and the small decisions behind the Servers table.
nonisolated enum ServersTableCopy {

    // MARK: Column headings

    /// Deliberately a real word rather than an empty heading: an unnamed column
    /// is an unnamed element, and the accessibility audit runs over this window.
    static let whereHeading = "Where"
    static let nameHeading = "Name"
    static let addressHeading = "Address"
    static let portHeading = "Port"
    /// Named for what the user asked for ("Check how quick each server is"), not
    /// for the machinery that fills it.
    static let speedHeading = "Speed"

    // MARK: Hints for empty cells (Q1c)

    /// The hint words. Same string as the heading on purpose — the hint's whole
    /// job is to say which column this is when the cell is empty. Passed as a
    /// `prompt:`, so it renders at placeholder contrast and is never a title.
    static let nameHint = nameHeading
    static let addressHint = addressHeading
    static let portHint = portHeading

    /// What VoiceOver should say a text cell's value IS. Empty means empty —
    /// never the hint.
    static func fieldValue(_ text: String, whenEmpty: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? whenEmpty : trimmed
    }

    static let noNameSet = "No name set"
    static let noAddressYet = "No address typed yet"
    static let noPortYet = "No port typed yet"

    // MARK: The address cell

    /// The address cell's whole story: the host, what it currently points to, and
    /// which of those the live tunnel is actually on.
    ///
    /// The addresses are the LAST REMEMBERED answer from the locator's cache, not
    /// a fresh lookup: this string is built to draw a row and to fill a tooltip,
    /// and firing DNS from either would put a name lookup on the path of pointer
    /// movement — a slow resolver would then make the tooltip arrive late or not
    /// at all. Several addresses is the normal case (A plus AAAA, round-robin
    /// pools), so all of them are listed.
    static func addressSummary(_ item: RankedEndpoint, inUse: String? = nil) -> String {
        var parts = [item.address + "."]
        if item.resolvedAddresses.isEmpty {
            parts.append("SimpleVPN hasn\u{2019}t looked this address up yet.")
        } else {
            parts.append("Points to \(sentenceList(item.resolvedAddresses)).")
        }
        if let inUse, !inUse.isEmpty {
            parts.append("In use now: \(inUse).")
        }
        return parts.joined(separator: " ")
    }

    /// "a", "a and b", "a, b and c" — read aloud without a shopping-list rhythm.
    static func sentenceList(_ items: [String]) -> String {
        switch items.count {
        case 0: ""
        case 1: items[0]
        case 2: "\(items[0]) and \(items[1])"
        default: items.dropLast().joined(separator: ", ") + " and " + items[items.count - 1]
        }
    }

    /// Is this row the server the live tunnel is actually on?
    ///
    /// Three ways to match, because the transport reports what it can: the
    /// resolved address it connected to, the address it dialled (which may be the
    /// hostname), or the host itself. Any match is the interesting fact; no match
    /// is silence rather than a guess.
    static func isInUse(_ item: RankedEndpoint, serverIP: String?,
                        serverEndpoint: String?) -> Bool {
        let ip = (serverIP ?? "").trimmingCharacters(in: .whitespaces)
        if !ip.isEmpty {
            if item.resolvedAddresses.contains(ip) { return true }
            if item.endpoint.host.caseInsensitiveCompare(ip) == .orderedSame { return true }
        }
        let dialled = (serverEndpoint ?? "").trimmingCharacters(in: .whitespaces)
        if !dialled.isEmpty {
            let host = hostPart(dialled)
            if item.endpoint.host.caseInsensitiveCompare(host) == .orderedSame { return true }
            if item.resolvedAddresses.contains(host) { return true }
        }
        return false
    }

    /// The host half of "host:port". An IPv6 literal (many colons) has no port to
    /// take off, so it is left whole. Same rule as `VPNProbeTarget.splitHostPort`,
    /// repeated here only so this file stays free of main-actor state.
    static func hostPart(_ address: String) -> String {
        let parts = address.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, let port = Int(parts[1]), (1...65535).contains(port) else {
            return address
        }
        return String(parts[0])
    }

    // MARK: The port cell

    /// A port cell with no port is not an empty field waiting to be filled — the
    /// address a profile advertises owns its port — so it says what actually
    /// happens instead of showing a hint. The word rather than the number, so a
    /// low-contrast value can never be mistaken for one the user set.
    static let portUnsetText = "default"

    static func portValue(_ port: Int?, defaultPort: Int) -> String {
        guard let port else {
            return "No port is set, so SimpleVPN uses this VPN\u{2019}s default, \(defaultPort)."
        }
        return String(port)
    }

    // MARK: The speed cell (Q1b)

    /// What the speed column has to say about one row. Ordered by how much it is
    /// worth knowing: being connected THROUGH a server beats any measurement of
    /// it, a measurement beats silence, and "we haven't asked" is distinct from
    /// "nothing answered".
    enum Speed: Equatable {
        /// The live tunnel is on this server right now.
        case inUse
        case checking
        case measured(String)
        case noAnswer
        case unchecked
        /// The `+` row: there is nothing to check until it has an address.
        case unsaved

        /// Does this state read as a number? Only then are figure widths right.
        var isMeasurement: Bool {
            if case .measured = self { return true }
            return false
        }

        var text: String {
            switch self {
            case .inUse: "In use"
            case .checking: "Checking\u{2026}"
            case .measured(let rtt): rtt
            case .noAnswer: "No answer"
            case .unchecked: "\u{2014}"
            case .unsaved: "\u{2014}"
            }
        }
    }

    static func speed(_ item: RankedEndpoint, probing: Bool, inUse: Bool) -> Speed {
        if inUse { return .inUse }
        if probing { return .checking }
        if let rtt = item.measurement?.rttText { return .measured(rtt) }
        if item.measurement?.reachable == false { return .noAnswer }
        return .unchecked
    }

    /// What VoiceOver says about the speed cell. The probe's own sentence lands
    /// HERE rather than inline in the row: it is the two-clause prose that used to
    /// swamp everything else on the line.
    static func speedValue(_ speed: Speed, detail: String?) -> String {
        var parts: [String]
        switch speed {
        case .inUse: parts = ["Connected through this server."]
        case .checking: parts = ["Checking how quick this server is."]
        case .measured(let rtt): parts = ["\(rtt) round trip."]
        case .noAnswer: parts = ["Nothing answered."]
        case .unchecked: parts = ["Not checked."]
        case .unsaved: parts = ["Add this server first, then you can check it."]
        }
        if let detail, !detail.isEmpty { parts.append(detail) }
        return parts.joined(separator: " ")
    }

    static let checkButtonLabel = "Check this server"
    static let checkButtonHelp = "Check how quick this server is."
    static let checkUnsavedHelp = "Add this server first, then you can check how quick it is."

    /// Why the per-row check can't run, or nil when it can. Explicit only: this
    /// button is the ONLY thing that starts a check from this table, and it never
    /// runs on appear.
    static func probeBlockedReason(probingEnabled: Bool, connected: Bool) -> String? {
        if !probingEnabled {
            return "Speed checks are off. Turn on \u{201C}Check how quick each server is\u{201D}"
                + " below to check a server."
        }
        if connected {
            return "You\u{2019}re connected through this VPN, so a check would go through the"
                + " tunnel it\u{2019}s asking about. Disconnect to check its servers."
        }
        return nil
    }

    // MARK: Add and remove

    static let addButtonLabel = "Add a server"
    static let addButtonHelp = "Add a server this VPN\u{2019}s configuration doesn\u{2019}t list."
    static let removeButtonLabel = "Remove the selected server"
    static let removeButtonHelp = "Remove the server selected above."
    static let discardDraftHelp = "Discard this new row."

    /// The lock on a row the user cannot remove — Mail's treatment of an account
    /// a profile provided. This used to be a footnote under the form; it is a
    /// glyph on the row it is about now.
    static let lockedHelp = "This server comes from this VPN\u{2019}s configuration."
        + " You can name it, but only the configuration can add or remove it."
    static let lockedLabel = "Provided by this VPN\u{2019}s configuration"

    /// Why `\u{2212}` can't remove, or nil when it can.
    static func removeBlockedReason(hasSelection: Bool, userAdded: Bool) -> String? {
        guard hasSelection else { return "Select a server in the table first." }
        guard userAdded else { return lockedHelp }
        return nil
    }

    // MARK: The empty table

    /// The empty state carries the action, because a list with no rows and no
    /// instruction is a dead end.
    static let emptyTitle = "No servers yet"
    static let emptyDetail = "This VPN\u{2019}s configuration doesn\u{2019}t name any."
        + " Use \u{201C}+\u{201D} below to add one, or import a configuration that lists them."

    // MARK: The footer

    static let lockFootnote = "Servers from this VPN\u{2019}s configuration carry a lock:"
        + " you can name them, but only the configuration can add or remove them."
    static let probeToggleTitle = "Check how quick each server is"
    static let probeToggleDetail = "When this is on, SimpleVPN measures each server when you open"
        + " a server list, and puts the quickest first. Off means no checks are made and the list"
        + " is ordered by which servers are nearest to you. This is the same switch as in Settings."
}
