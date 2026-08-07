// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigurationDropMerge.swift
//  WHAT A HANDFUL OF DROPPED CONFIGURATION FILES WOULD DO TO ONE VPN — worked out
//  in full BEFORE anything is written, so it can be shown and accepted rather than
//  discovered afterwards.
//
//  `ConfigurationKinship` answers the question for ONE file. This answers it for a
//  DROP, and a drop is a different question in four ways, every one of which came
//  out of the user's own sentence ("if a user downloads several"):
//
//   1. SEVERAL FILES, ONE ANSWER EACH. A drop of six IPVanish configs where five
//      match and one carries a different `<ca>` must report six outcomes, not one
//      averaged verdict. Averaging is how the odd one out gets waved through.
//   2. ALL-OR-NOTHING PER FILE. A file either contributes every server it names or
//      none of them. There is no half-merge, because a half-merge is a VPN whose
//      list came from a file the user was told was refused.
//   3. THE FILES SEE EACH OTHER. Two downloads naming the same relay are one
//      server, so each file is compared against what the earlier files in the same
//      drop have already contributed. Otherwise a drop of the same file twice adds
//      a duplicate row and calls it a feature.
//   4. THE WRONG KIND IS A DIFFERENCE, NOT A CRASH. A WireGuard `.conf` dropped on
//      an OpenVPN VPN is not a comparison that can be made at all, and saying so is
//      more use than an empty result.
//
//  THE ORDER IS PART OF THE ANSWER. Items come back with the ones that need a
//  DECISION first — a trust difference, then a file that is simply not this VPN —
//  and the quiet successes last. A list sorted by filename would bury the one file
//  that matters under five that do not, which is the same failure as averaging.
//
//  WHAT THIS FILE MAY NOT DO, and it is the whole reason the categories exist:
//  a difference in who the VPN TRUSTS — the `<ca>`, `verify-x509-name`, the cipher,
//  the port — never merges, however many of the other files did. The answer there
//  is "import it as its own VPN", which is what the user would have done by hand,
//  and it goes through the ordinary import pipeline rather than a private one.
//
//  PURE. It reads no files, touches no controller and builds no view: text in,
//  verdicts out. Reading the bytes is the sheet's job, which is what lets every
//  rule below be pinned by a test.
//

import Foundation

nonisolated enum ConfigurationDropMerge {

    // MARK: - What the files were dropped on

    /// The VPN under the drop, in the only two shapes there is a comparison for.
    ///
    /// The other kinds are absent on purpose rather than by omission: an SSH tunnel
    /// or an F5 BIG-IP APM has no configuration FILE to compare a dropped one
    /// against, so there is no "same VPN, elsewhere" question to ask about it. Those
    /// VPNs take no drop at all and the file falls through to the ordinary import.
    enum Existing: Sendable, Equatable {
        case openVPN(String)
        case wireGuard(WireGuardConfig)

        var detectedKind: DetectedConfigKind {
            switch self {
            case .openVPN: .openVPN
            case .wireGuard: .wireGuard
            }
        }
    }

    // MARK: - One file's fate

    /// What one dropped file resolved to.
    ///
    /// `unreadable` is its own case rather than a `differentVPN` with an apologetic
    /// sentence, because the two lead to different offers: a file that is not this
    /// VPN can still be imported as its own, and a file nobody can read cannot.
    enum Outcome: Sendable, Equatable {
        case unreadable
        case compared(ConfigurationKinship.Verdict)
    }

    /// One file, and what it would do.
    struct Item: Sendable, Equatable, Identifiable {
        /// Where it sat in the drop, so the caller can find its URL again. Files
        /// are re-ordered for display and two of them may share a name.
        let index: Int
        let filename: String
        let outcome: Outcome

        var id: Int { index }

        /// The servers this file contributes — all of them or none, never some.
        var servers: [VPNEndpoint] {
            guard case .compared(.sameVPNElsewhere(let servers, _)) = outcome else { return [] }
            return servers
        }

        /// The file names a sign-in different from the one already stored. Reported,
        /// never applied: something that works must not be replaced by a file.
        var signInDiffers: Bool {
            guard case .compared(.sameVPNElsewhere(_, let differs)) = outcome else { return false }
            return differs
        }

        /// The one category that must be impossible to get wrong from the UI.
        var refusedOnTrust: Bool {
            guard case .compared(.trustDiffers) = outcome else { return false }
            return true
        }

        /// Can this file be kept some other way? A trust difference and an unrelated
        /// configuration are both "not this VPN", and both are still a VPN somebody
        /// downloaded on purpose.
        var offersSeparateImport: Bool {
            switch outcome {
            case .compared(.trustDiffers), .compared(.differentVPN): true
            default: false
            }
        }

        /// Shown first if smaller. A decision outranks a success, and the decision
        /// that repoints trust outranks the one that merely says "different VPN".
        var rank: Int {
            switch outcome {
            case .compared(.trustDiffers): 0
            case .compared(.differentVPN): 1
            case .unreadable: 2
            case .compared(.sameVPNElsewhere): 3
            case .compared(.alreadyHaveIt): 4
            }
        }
    }

    // MARK: - The whole drop

    /// Every file's fate, plus the two things a caller acts on: what would be added,
    /// and what should be offered as its own VPN instead.
    struct Plan: Sendable, Equatable {

        let vpnName: String
        /// Ranked: decisions first, quiet successes last.
        let items: [Item]

        /// Every server the accepted half of this drop would add, in file order and
        /// already deduplicated across files.
        var serversToAdd: [VPNEndpoint] { items.sorted { $0.index < $1.index }.flatMap(\.servers) }

        /// The files that would be imported as their own VPNs instead, in file order
        /// — indices rather than names, because two downloads can share a name.
        var separateImports: [Int] {
            items.filter(\.offersSeparateImport).map(\.index).sorted()
        }

        var addsAnything: Bool { !serversToAdd.isEmpty }
        var refusesAnythingOnTrust: Bool { items.contains { $0.refusedOnTrust } }
        var anySignInDiffers: Bool { items.contains { $0.signInDiffers } }
    }

    // MARK: - Producing one

    /// Compare every dropped file against one VPN.
    ///
    /// `text` is optional so an unreadable file is a REPORTED outcome rather than a
    /// silently shorter list — a drop of six that quietly became five is the shape
    /// that makes somebody re-download a file they already had.
    ///
    /// `existingServers` must be what the VPN actually SHOWS (its configuration's own
    /// remotes plus everything annotated on top), not the stored annotations alone:
    /// a profile filled from a provider's list already holds hundreds of servers the
    /// dropped `.ovpn` never mentioned, and comparing against the file alone would
    /// offer every one of them again.
    static func plan(vpnName: String,
                     existing: Existing,
                     existingServers: [VPNEndpoint],
                     files: [(filename: String, text: String?)]) -> Plan {
        // The running list is what makes rule 3 true: file two is compared against
        // the VPN AND against whatever file one already contributed, so the same
        // relay in two downloads is one row and the second file says so.
        var known = existingServers
        var items: [Item] = []
        for (index, file) in files.enumerated() {
            let outcome = self.outcome(filename: file.filename, text: file.text,
                                       existing: existing, known: known)
            if case .compared(.sameVPNElsewhere(let servers, _)) = outcome { known += servers }
            items.append(Item(index: index, filename: file.filename, outcome: outcome))
        }
        // Stable within a rank: the drop's own order is the only order the user
        // supplied, and shuffling equals would make two runs of one drop disagree.
        return Plan(vpnName: vpnName,
                    items: items.sorted { ($0.rank, $0.index) < ($1.rank, $1.index) })
    }

    private static func outcome(filename: String, text: String?,
                                existing: Existing,
                                known: [VPNEndpoint]) -> Outcome {
        guard let text, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .unreadable
        }
        // CONTENT WINS OVER THE EXTENSION, which is `ConfigDetector`'s own rule and
        // is reused rather than restated — a second answer to "what kind of file is
        // this?" is a second answer, and `.conf` is honestly ambiguous between the
        // two kinds this feature cares about.
        let detected = ConfigDetector.detect(text: text, filename: filename)
        guard detected == existing.detectedKind else {
            return .compared(.differentVPN(ConfigurationDropCopy.wrongKind(detected,
                                                                           wanted: existing)))
        }
        switch existing {
        case .openVPN(let mine):
            return .compared(ConfigurationKinship.compare(dropped: text, against: mine,
                                                          existingEndpoints: known))
        case .wireGuard(let mine):
            let dropped = WireGuardConfig.parse(text, name: filename)
            return .compared(ConfigurationKinship.compare(droppedWireGuard: dropped,
                                                          against: mine,
                                                          existingEndpoints: known))
        }
    }
}

// MARK: - The words

/// Every string the drop sheet says, in one pure place so a test can assert what
/// VoiceOver hears without building a view — the same arrangement
/// `ProviderPickerCopy` and `ServersTableCopy` already use.
///
/// TWO VOCABULARY RULES BIND EVERY LINE HERE (ONTOLOGY.md): the machine a VPN
/// connects to is a **server**, never an endpoint or a host; and "credential" is
/// banned from UI copy, so what a file carries about who you are is a **sign-in**.
nonisolated enum ConfigurationDropCopy {

    // MARK: The action, wherever it is offered

    /// The menu item, in the `+` menu and on a VPN's own row. A verb naming what it
    /// does to WHICH thing — never "Merge…", which says nothing about what merges.
    ///
    /// It exists because the drag must not be the only way (Docs/Accessibility.md
    /// rule 7), which is the same rule that gives every reorderable list its Move Up
    /// and Move Down.
    static let menuTitle = "Add Servers from Configuration Files\u{2026}"

    /// Why the menu item cannot run. A reason, never a dead item.
    static let needsAVPN = "Choose a VPN in the list first \u{2014} these add servers "
        + "to one you already have."

    /// …and why a VPN of the wrong kind cannot take one. Said rather than hidden: an
    /// absent item is indistinguishable from a bug.
    static func wrongKindOfVPN(_ name: String) -> String {
        "\u{201C}\(name)\u{201D} has no configuration file to compare one against, so there "
            + "is nothing to add servers from. Import the file as its own VPN instead."
    }

    /// The drop highlight's own words, shown while a file is over a VPN's row.
    static func dropLabel(_ vpn: String) -> String { "Add servers to \u{201C}\(vpn)\u{201D}" }

    // MARK: The sheet

    static func title(vpn: String) -> String { "Add servers to \u{201C}\(vpn)\u{201D}" }

    static func subtitle(fileCount: Int) -> String {
        fileCount == 1
            ? "One configuration file, checked against this VPN."
            : "\(fileCount) configuration files, each checked against this VPN on its own."
    }

    /// The standing promise, said before any button: the servers move and nothing
    /// else does. It is the sentence that makes the sheet safe to accept.
    static let whatItWillNotDo = "Only servers are added. Your saved sign-in, this VPN\u{2019}s "
        + "settings and how it checks the server\u{2019}s identity are left exactly as they are."

    // MARK: One file's line

    /// What a file's row is titled — the file's own name, which is what the user
    /// dragged and the only handle they have on it.
    static func rowTitle(_ item: ConfigurationDropMerge.Item) -> String { item.filename }

    /// What that file would do, in one sentence. This is both the visible caption and
    /// the row's spoken value, so nothing here is sighted-only.
    static func sentence(_ item: ConfigurationDropMerge.Item) -> String {
        switch item.outcome {
        case .unreadable:
            return "SimpleVPN could not read this file, so it has been left out."
        case .compared(.alreadyHaveIt):
            return "Names a server this VPN already has, so there is nothing to add."
        case .compared(.sameVPNElsewhere(let servers, let signInDiffers)):
            var out = servers.count == 1
                ? "The same VPN, somewhere else. Adds one server: \(servers[0].host)."
                : "The same VPN, somewhere else. Adds \(servers.count) servers: "
                    + servers.prefix(3).map(\.host).joined(separator: ", ")
                    + (servers.count > 3 ? " and \(servers.count - 3) more." : ".")
            if servers.contains(where: { $0.peerPublicKey != nil }) {
                out += " Each one brings its own public key, which travels with its address."
            }
            if signInDiffers {
                out += " Its sign-in differs from the one you have saved; yours is left alone."
            }
            return out
        case .compared(.trustDiffers(let reasons)):
            return "Not added. It differs in " + list(reasons) + ". That decides who this VPN "
                + "trusts, so this is not the same VPN somewhere else \u{2014} it is a different "
                + "one wearing a familiar name. Import it on its own instead."
        case .compared(.differentVPN(let why)):
            return "Not added: " + why + " Import it on its own instead."
        }
    }

    /// The row read as one element: the file, then what happens to it.
    static func spoken(_ item: ConfigurationDropMerge.Item) -> String {
        "\(item.filename). \(sentence(item))"
    }

    /// The glyph beside a row. Never the only carrier of anything — every one of
    /// these rows says the same thing in words directly beside it.
    static func symbol(_ item: ConfigurationDropMerge.Item) -> String {
        switch item.outcome {
        case .unreadable: "questionmark.circle"
        case .compared(.alreadyHaveIt): "equal.circle"
        case .compared(.sameVPNElsewhere): "plus.circle"
        case .compared(.trustDiffers): "exclamationmark.shield"
        case .compared(.differentVPN): "arrow.uturn.forward.circle"
        }
    }

    // MARK: The whole drop, in one sentence

    /// What the sheet announces when it opens and what its heading says — counts
    /// first, because a person deciding about six files wants the shape before the
    /// detail, and the dangerous count is never folded into the others.
    static func summary(_ plan: ConfigurationDropMerge.Plan) -> String {
        var parts: [String] = []
        let adding = plan.serversToAdd.count
        if adding > 0 {
            parts.append("\(adding) server\(adding == 1 ? "" : "s") to add")
        }
        let refused = plan.items.filter(\.refusedOnTrust).count
        if refused > 0 {
            parts.append("\(refused) file\(refused == 1 ? "" : "s") refused because "
                + "\(refused == 1 ? "it decides" : "they decide") who this VPN trusts")
        }
        let other = plan.items.filter { $0.offersSeparateImport && !$0.refusedOnTrust }.count
        if other > 0 {
            parts.append("\(other) that \(other == 1 ? "is" : "are") not this VPN")
        }
        let same = plan.items.filter {
            if case .compared(.alreadyHaveIt) = $0.outcome { return true }
            return false
        }.count
        if same > 0 { parts.append("\(same) already here") }
        let unreadable = plan.items.filter {
            if case .unreadable = $0.outcome { return true }
            return false
        }.count
        if unreadable > 0 { parts.append("\(unreadable) unreadable") }
        guard !parts.isEmpty else { return "Nothing to add to \u{201C}\(plan.vpnName)\u{201D}." }
        return parts.joined(separator: ", ") + "."
    }

    // MARK: The buttons

    /// The applying button. Delegated to `ProviderPickerCopy` on purpose: adding
    /// servers from a file and adding them from a provider's list are the same act
    /// with two sources, and two phrasings for one act is how a vocabulary drifts.
    static func addTitle(count: Int) -> String { ProviderPickerCopy.applyTitle(count: count) }

    static func separateImportTitle(count: Int) -> String {
        count == 1 ? "Import as Its Own VPN" : "Import \(count) as Their Own VPNs"
    }

    /// Why the applying button is dead. A disabled button says why, in `.help` and in
    /// its spoken value both (Docs/Accessibility.md rule 5).
    static func nothingToAdd(_ plan: ConfigurationDropMerge.Plan) -> String {
        plan.refusesAnythingOnTrust
            ? "Nothing here can be added to this VPN. The files that were refused decide who "
                + "it trusts, and that is never merged \u{2014} import them on their own instead."
            : "Nothing here adds a server this VPN does not already have."
    }

    /// Said after the servers land, and it names where they went — the whole point
    /// being that they are now ordinary rows in the ordinary list.
    static func applied(count: Int, vpn: String) -> String {
        "Added \(count) server\(count == 1 ? "" : "s") to \(vpn). "
            + "They are in the Servers list with everything else."
    }

    /// Said when the sheet is dismissed without applying, because "did my cancel
    /// leave it half-done?" is the question a cancel has to answer.
    static func declined(_ vpn: String) -> String {
        "Nothing added. \(vpn) has exactly the servers it had before."
    }

    // MARK: Helpers

    /// Why a file cannot even be compared: it is not the same kind of configuration.
    static func wrongKind(_ found: DetectedConfigKind,
                          wanted: ConfigurationDropMerge.Existing) -> String {
        let mine = switch wanted {
        case .openVPN: "an OpenVPN"
        case .wireGuard: "a WireGuard"
        }
        let theirs = switch found {
        case .openVPN: "an OpenVPN"
        case .wireGuard: "a WireGuard"
        case .cisco: "a Cisco"
        }
        return "this is \(theirs) configuration and that VPN is \(mine) one, "
            + "so there is nothing to compare."
    }

    /// "a, b and c" — the house list, because "a, b, c" reads as a fragment when it
    /// is the middle of a sentence somebody has to act on.
    static func list(_ parts: [String]) -> String {
        switch parts.count {
        case 0: return ""
        case 1: return parts[0]
        default: return parts.dropLast().joined(separator: ", ") + " and " + parts[parts.count - 1]
        }
    }
}
