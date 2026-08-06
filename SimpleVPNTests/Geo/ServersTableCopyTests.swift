// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ServersTableCopyTests.swift
//  What the Servers table SAYS. A `Table`'s cells cannot be reached from a unit
//  test, so every string and every decision behind one lives in ServersTableCopy
//  and is pinned here instead:
//
//    • Mail's rule for an optional name — name if set, else `host:port`, and never
//      an empty placeholder as the thing that names a row.
//    • A hint is not a label: an empty cell's accessible VALUE says it is empty
//      rather than reciting the hint word, so nobody is told the address is
//      "Address".
//    • The resolved addresses come from what was remembered, all of them, with the
//      one carrying the session marked — and the same string reaches VoiceOver, so
//      none of it is hover-only.
//    • A disabled control says why, in the user's terms.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ServersTableCopyTests {

    private func item(_ host: String, port: Int? = nil, label: String? = nil,
                      userAdded: Bool? = nil, resolved: [String] = [],
                      rtt: Double? = nil, reachable: Bool? = nil,
                      detail: String? = nil) -> RankedEndpoint {
        var e = VPNEndpoint(host: host, port: port)
        e.label = label
        e.userAdded = userAdded
        return RankedEndpoint(
            endpoint: e,
            measurement: (rtt == nil && reachable == nil && detail == nil)
                ? nil
                : EndpointMeasurement(rttMS: rtt, reachable: reachable, detail: detail,
                                      measuredAt: Date()),
            resolvedAddresses: resolved)
    }

    // MARK: Mail's rule for an optional name

    @Test func anUnnamedServerIsNamedByItsAddress() {
        #expect(item("vpn.example.com", port: 1197).primaryLabel == "vpn.example.com:1197")
        #expect(item("vpn.example.com").primaryLabel == "vpn.example.com")
    }

    @Test func aNamedServerIsNamedByItsName() {
        #expect(item("vpn.example.com", port: 1197, label: "London").primaryLabel == "London")
    }

    @Test func aWhitespaceOnlyNameIsNoName() {
        // Otherwise the boldest thing about a row is a space the user typed once.
        #expect(item("vpn.example.com").primaryLabel == "vpn.example.com")
        #expect(item("vpn.example.com", label: "   ").primaryLabel == "vpn.example.com")
    }

    @Test func aOneLineLabelNeverRepeatsTheAddress() {
        let unnamed = EndpointRowLabel.oneLine(item("vpn.example.com", port: 1197))
        #expect(unnamed.contains("vpn.example.com:1197"))
        #expect(!unnamed.contains("(vpn.example.com:1197)"))

        let named = EndpointRowLabel.oneLine(item("vpn.example.com", port: 1197, label: "London"))
        #expect(named.contains("London"))
        #expect(named.contains("(vpn.example.com:1197)"))
    }

    // MARK: A hint is not an accessible label

    @Test func anEmptyCellAnnouncesThatItIsEmptyRatherThanItsHint() {
        let spoken = ServersTableCopy.fieldValue("", whenEmpty: ServersTableCopy.noNameSet)
        #expect(spoken == ServersTableCopy.noNameSet)
        #expect(spoken != ServersTableCopy.nameHint)
        #expect(ServersTableCopy.fieldValue("   ", whenEmpty: ServersTableCopy.noAddressYet)
                == ServersTableCopy.noAddressYet)
        #expect(ServersTableCopy.fieldValue(" London ", whenEmpty: ServersTableCopy.noNameSet)
                == "London")
    }

    @Test func everyHintNamesItsColumn() {
        // The hint's whole job: say which column this is when the cell is blank.
        #expect(ServersTableCopy.nameHint == ServersTableCopy.nameHeading)
        #expect(ServersTableCopy.addressHint == ServersTableCopy.addressHeading)
        #expect(ServersTableCopy.portHint == ServersTableCopy.portHeading)
    }

    @Test func noColumnHeadingIsBlank() {
        // An unnamed column is an unnamed element, and this window is audited.
        for heading in [ServersTableCopy.whereHeading, ServersTableCopy.nameHeading,
                        ServersTableCopy.addressHeading, ServersTableCopy.portHeading,
                        ServersTableCopy.speedHeading] {
            #expect(!heading.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    // MARK: The address cell (Q1a)

    @Test func anAddressWithNoRememberedAnswerSaysSo() {
        let text = ServersTableCopy.addressSummary(item("vpn.example.com", port: 1197))
        #expect(text.contains("vpn.example.com:1197"))
        #expect(text.contains("hasn\u{2019}t looked this address up yet"))
    }

    @Test func everyRememberedAddressIsShownNotJustTheFirst() {
        // A + AAAA and round-robin pools are the normal case, not the edge one.
        let text = ServersTableCopy.addressSummary(
            item("vpn.example.com", resolved: ["203.0.113.9", "203.0.113.10", "2001:db8::1"]))
        #expect(text.contains("203.0.113.9"))
        #expect(text.contains("203.0.113.10"))
        #expect(text.contains("2001:db8::1"))
    }

    @Test func theAddressCarryingTheSessionIsMarked() {
        let text = ServersTableCopy.addressSummary(
            item("vpn.example.com", resolved: ["203.0.113.9", "203.0.113.10"]),
            inUse: "203.0.113.10")
        #expect(text.contains("In use now: 203.0.113.10"))
    }

    @Test func aListOfAddressesReadsAsASentence() {
        #expect(ServersTableCopy.sentenceList([]) == "")
        #expect(ServersTableCopy.sentenceList(["a"]) == "a")
        #expect(ServersTableCopy.sentenceList(["a", "b"]) == "a and b")
        #expect(ServersTableCopy.sentenceList(["a", "b", "c"]) == "a, b and c")
    }

    // MARK: Which row is the live one

    @Test func theResolvedAddressTheTunnelReportsIdentifiesTheRow() {
        let row = item("vpn.example.com", resolved: ["203.0.113.9", "2001:db8::1"])
        #expect(ServersTableCopy.isInUse(row, serverIP: "203.0.113.9", serverEndpoint: nil))
        #expect(!ServersTableCopy.isInUse(row, serverIP: "198.51.100.7", serverEndpoint: nil))
    }

    @Test func theAddressTheTransportDialledIdentifiesTheRow() {
        let row = item("vpn.example.com", port: 1197)
        #expect(ServersTableCopy.isInUse(row, serverIP: nil,
                                         serverEndpoint: "vpn.example.com:1197"))
        #expect(ServersTableCopy.isInUse(row, serverIP: nil,
                                         serverEndpoint: "VPN.EXAMPLE.COM"))
        #expect(!ServersTableCopy.isInUse(row, serverIP: nil,
                                          serverEndpoint: "other.example.com:1197"))
    }

    @Test func nothingIsInUseWhenTheTunnelSaysNothing() {
        let row = item("vpn.example.com", resolved: ["203.0.113.9"])
        #expect(!ServersTableCopy.isInUse(row, serverIP: nil, serverEndpoint: nil))
        #expect(!ServersTableCopy.isInUse(row, serverIP: "  ", serverEndpoint: "  "))
    }

    @Test func anIPv6LiteralKeepsAllOfItsColons() {
        #expect(ServersTableCopy.hostPart("2001:db8::1") == "2001:db8::1")
        #expect(ServersTableCopy.hostPart("vpn.example.com:1197") == "vpn.example.com")
        #expect(ServersTableCopy.hostPart("vpn.example.com") == "vpn.example.com")
    }

    // MARK: The port cell

    @Test func aPortlessRowSaysWhatHappensRatherThanShowingAFakeValue() {
        let value = ServersTableCopy.portValue(nil, defaultPort: 1194)
        #expect(value.contains("1194"))
        #expect(value.contains("No port is set"))
        #expect(ServersTableCopy.portValue(1197, defaultPort: 1194) == "1197")
        // Never a number the user could mistake for one they set.
        #expect(Int(ServersTableCopy.portUnsetText) == nil)
    }

    // MARK: The speed cell (Q1b)

    @Test func beingConnectedThroughAServerBeatsAnyMeasurementOfIt() {
        let measured = item("vpn.example.com", rtt: 42, reachable: true)
        #expect(ServersTableCopy.speed(measured, probing: true, inUse: true) == .inUse)
        #expect(ServersTableCopy.speed(measured, probing: true, inUse: false) == .checking)
        #expect(ServersTableCopy.speed(measured, probing: false, inUse: false) == .measured("42 ms"))
    }

    @Test func nothingAnsweringIsDistinctFromNotHavingAsked() {
        #expect(ServersTableCopy.speed(item("a", reachable: false),
                                       probing: false, inUse: false) == .noAnswer)
        #expect(ServersTableCopy.speed(item("a"), probing: false, inUse: false) == .unchecked)
    }

    @Test func theProbesProseGoesToVoiceOverAndNotIntoTheRow() {
        // The two-clause explanation is exactly what used to swamp the row.
        let detail = "Nothing answered on UDP; the name resolved but the port stayed quiet."
        let row = item("a", reachable: false, detail: detail)
        let state = ServersTableCopy.speed(row, probing: false, inUse: false)
        #expect(state.text == "No answer")
        #expect(!state.text.contains(detail))
        #expect(ServersTableCopy.speedValue(state, detail: detail).contains(detail))
    }

    @Test func aCheckThatCannotRunExplainsItself() {
        #expect(ServersTableCopy.probeBlockedReason(probingEnabled: true, connected: false) == nil)

        let off = ServersTableCopy.probeBlockedReason(probingEnabled: false, connected: false)
        // Names the switch the user has to find, in the switch's own words.
        #expect(off?.contains(ServersTableCopy.probeToggleTitle) == true)

        let connected = ServersTableCopy.probeBlockedReason(probingEnabled: true, connected: true)
        #expect(connected?.contains("Disconnect") == true)
    }

    // MARK: Add and remove

    @Test func aServerFromTheConfigurationCannotBeRemovedAndTheButtonSaysWhy() {
        let reason = ServersTableCopy.removeBlockedReason(hasSelection: true, userAdded: false)
        #expect(reason == ServersTableCopy.lockedHelp)
        #expect(reason?.contains("configuration") == true)
    }

    @Test func aServerTheUserAddedCanBeRemoved() {
        #expect(ServersTableCopy.removeBlockedReason(hasSelection: true, userAdded: true) == nil)
    }

    @Test func removingNothingExplainsWhatToDoFirst() {
        let reason = ServersTableCopy.removeBlockedReason(hasSelection: false, userAdded: false)
        #expect(reason?.contains("Select") == true)
    }

    // MARK: The empty table carries the action

    @Test func theEmptyStateNamesThePlusButton() {
        #expect(ServersTableCopy.emptyDetail.contains("+"))
    }

    // MARK: House vocabulary

    @Test func theTableSpeaksTheHouseVocabulary() {
        // ONTOLOGY: "server" is ours; "endpoint", "gateway", "host" are never our
        // label. "credential" is banned from UI copy outright.
        let copy = [ServersTableCopy.whereHeading, ServersTableCopy.nameHeading,
                    ServersTableCopy.addressHeading, ServersTableCopy.portHeading,
                    ServersTableCopy.speedHeading, ServersTableCopy.addButtonLabel,
                    ServersTableCopy.addButtonHelp, ServersTableCopy.removeButtonLabel,
                    ServersTableCopy.removeButtonHelp, ServersTableCopy.discardDraftHelp,
                    ServersTableCopy.checkButtonLabel, ServersTableCopy.checkButtonHelp,
                    ServersTableCopy.checkUnsavedHelp, ServersTableCopy.lockedHelp,
                    ServersTableCopy.lockedLabel, ServersTableCopy.emptyTitle,
                    ServersTableCopy.emptyDetail, ServersTableCopy.lockFootnote,
                    ServersTableCopy.probeToggleTitle, ServersTableCopy.probeToggleDetail,
                    ServersTableCopy.noNameSet, ServersTableCopy.noAddressYet,
                    ServersTableCopy.noPortYet, ServersTableCopy.portUnsetText,
                    ServersTableCopy.probeBlockedReason(probingEnabled: false, connected: false) ?? "",
                    ServersTableCopy.probeBlockedReason(probingEnabled: true, connected: true) ?? ""]
        for line in copy {
            for banned in ["endpoint", "credential", "concentrator", "headend", "DNS", "resolve"] {
                #expect(!line.localizedCaseInsensitiveContains(banned),
                        "\u{201C}\(line)\u{201D} uses \u{201C}\(banned)\u{201D}")
            }
        }
    }
}
