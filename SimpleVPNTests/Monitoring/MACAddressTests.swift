// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MACAddressTests.swift
//  THE SPELLINGS, THE REFUSALS, AND — the reason this file is worth more than the type
//  it tests — A SCAN OF THE SOURCE THAT FAILS IF A HARDWARE ADDRESS BECOMES A `String`
//  AGAIN.
//
//  The bug `MACAddress` replaces was silent. `netstat` prints `42:0:5c:85:fa:1a` and
//  UTM records `EA:85:74:8B:18:97`; compared as strings they never matched, so guest
//  names simply never attached to the route diagram and the screen looked finished.
//  Nothing threw, nothing was empty, nothing logged. A type fixes it today; the two
//  source scans at the bottom of this file are what stop somebody re-introducing it
//  next year in a place nobody thought to look.
//

import Testing
import Foundation
@testable import SimpleVPN

/// Parse-or-die, for the tests that are about something else.
private func mac(_ text: String, _ location: SourceLocation = #_sourceLocation) throws -> MACAddress {
    try #require(MACAddress(text), "\(text) should parse", sourceLocation: location)
}

// MARK: - Every spelling something real writes

struct MACAddressParsingTests {

    /// THE SPELLINGS THIS MAC ACTUALLY PRODUCES, all one value.
    ///
    /// The first two were MEASURED on this machine (`netstat -rn`, and the
    /// `config.plist` of the one UTM machine here). The third and fourth are what
    /// VirtualBox and Parallels write into their XML. The fifth is IEEE 802's printed
    /// notation, which nothing here emits and a person pasting from a device label
    /// does.
    @Test func everySpellingOfOneAddressIsOneValue() throws {
        let canonical = try mac("ea:85:74:8b:18:97")
        for spelling in ["EA:85:74:8B:18:97",       // UTM config.plist — MEASURED
                         "ea:85:74:8b:18:97",       // netstat, no low octets here
                         "ea85748b1897",            // VirtualBox .vbox, Parallels .pvs
                         "EA85748B1897",
                         "ea-85-74-8b-18-97",       // IEEE 802 / Windows / device label
                         "EA-85-74-8B-18-97",
                         "  ea:85:74:8b:18:97  "] { // ragged vendor XML
            #expect(MACAddress(spelling) == canonical, "\(spelling) is the same address")
        }
    }

    /// THE SUPPRESSED LEADING ZERO, which is the specific half of the bug that bit.
    /// `ether_ntoa(3)` prints an octet below 0x10 as one digit, so `netstat` and `arp`
    /// both do; every other source here zero-pads.
    @Test func aSuppressedLeadingZeroIsTheSameAsAPaddedOne() throws {
        #expect(try mac("42:0:5c:85:fa:1a") == mac("42:00:5c:85:fa:1a"))
        #expect(try mac("42:0:5c:85:fa:1a") == mac("42:00:5C:85:FA:1A"))
        #expect(try mac("42:0:5c:85:fa:1a") == mac("42005c85fa1a"))
        #expect(try mac("a:e6:33:6c:f0:52") == mac("0A:E6:33:6C:F0:52"))
        // …and the hash agrees, which is what makes a Set membership test work.
        #expect(try Set([mac("42:0:5c:85:fa:1a")]).contains(mac("42:00:5C:85:FA:1A")))
    }

    @Test func theSixOctetsAreTheStorage() throws {
        #expect(try mac("0a:e6:33:6c:f0:52").octets == [0x0a, 0xe6, 0x33, 0x6c, 0xf0, 0x52])
        #expect(try mac("ff:ff:ff:ff:ff:ff").octets == [UInt8](repeating: 0xff, count: 6))
    }

    /// THE ALL-ZEROES ADDRESS IS A VALID ADDRESS AND NOT A FAILURE. It has to parse,
    /// and a failure has to be `nil`, or the two become indistinguishable at exactly
    /// the moment somebody writes `?? .zero`.
    @Test func theZeroAddressParsesAndIsNotHowFailureIsSpelled() throws {
        let zero = try mac("00:00:00:00:00:00")
        #expect(zero.octets == [0, 0, 0, 0, 0, 0])
        #expect(MACAddress("not an address") == nil)
        #expect(MACAddress("not an address") != zero)
    }

    @Test func sixOctetsInAndSixOctetsOnly() {
        #expect(MACAddress(octets: [0, 1, 2, 3, 4, 5]) != nil)
        #expect(MACAddress(octets: [0, 1, 2, 3, 4]) == nil)
        #expect(MACAddress(octets: [0, 1, 2, 3, 4, 5, 6]) == nil)
        // A FireWire link address is eight bytes and is not an Ethernet address; a
        // `sockaddr_dl` really does carry those, so this is a live filter.
        #expect(MACAddress(octets: [UInt8](repeating: 0xab, count: 8)) == nil)
        #expect(MACAddress(octets: []) == nil)
    }
}

// MARK: - What it refuses, and why each refusal is deliberate

struct MACAddressRejectionTests {

    /// AN IPv6 NEXT HOP IS NOT A HARDWARE ADDRESS. This is the trap on the neighbour
    /// cache's side of the routing table — `RouteGraphLayout.isGatewayAddress` guards
    /// the same confusion from the other side.
    @Test func addressesOfOtherKindsAreRefused() {
        for text in ["fe80::1%en0", "2001:db8::1", "::1", "::",
                     "10.0.7.254", "link#27", "255.255.255.255"] {
            #expect(MACAddress(text) == nil, "\(text) is not a hardware address")
        }
    }

    @Test func wrongLengthsAreRefused() {
        for text in ["ea:85:74:8b:18", "ea:85:74:8b:18:97:aa", "ea85748b18",
                     "ea85748b189777", "ea:85:74:8b:18:970", ":::::"] {
            #expect(MACAddress(text) == nil, "\(text) is the wrong length")
        }
    }

    @Test func nonHexIsRefused() {
        for text in ["gg:85:74:8b:18:97", "ea:85:74:8b:18:9z", "hello world!",
                     "ea:85:74:8b:18:-1", "0xea85748b1897"] {
            #expect(MACAddress(text) == nil, "\(text) is not hex")
        }
    }

    /// `Character.isHexDigit` says yes to `０`–`９` and other non-ASCII digits. A
    /// fullwidth address is not a spelling; it is a paste accident or worse.
    @Test func nonASCIIDigitsAreRefused() {
        #expect(MACAddress("\u{FF45}a:85:74:8b:18:97") == nil)
        #expect(MACAddress("\u{FF11}\u{FF12}3456789abc") == nil)
    }

    /// MIXED SEPARATORS ARE A CORRUPTED FIELD, NOT A SPELLING. Nothing writes one, so
    /// accepting it would only ever mean repairing a value that had already gone
    /// wrong — and attaching a repaired address to a guest's name is the exact
    /// failure this whole area is built to avoid.
    @Test func mixedSeparatorsAreRefused() {
        for text in ["ea:85-74:8b:18:97", "ea-85:74-8b-18-97", "ea:85:74:8b:18-97"] {
            #expect(MACAddress(text) == nil, "\(text) mixes separators")
        }
    }

    /// CISCO'S DOTTED-QUAD IS REFUSED ON PURPOSE. Nothing this app reads produces it:
    /// not `netstat`, not `arp`, not UTM, VirtualBox, Parallels or VMware. Supporting
    /// a format no source emits is supporting it on speculation, and the parser is the
    /// last place to widen without a reason. Add it the day a source arrives.
    @Test func ciscoDottedQuadIsRefusedBecauseNothingHereWritesIt() {
        #expect(MACAddress("ea85.748b.1897") == nil)
        #expect(MACAddress("0a00.2700.1a2b") == nil)
    }

    @Test func emptyAndWhitespaceAreRefused() {
        for text in ["", " ", "\t", "\n", "   \n  "] {
            #expect(MACAddress(text) == nil, "empty input is not an address")
        }
    }
}

// MARK: - Canonical, display, and the fact that comparison uses neither

struct MACAddressRenderingTests {

    /// ONE ADDRESS, ONE CANONICAL FORM — lower case, zero-padded, colons.
    @Test func canonicalIsPaddedLowerCaseColons() throws {
        #expect(try mac("A:E6:33:6C:F0:52").canonicalText == "0a:e6:33:6c:f0:52")
        #expect(try mac("ea85748b1897").canonicalText == "ea:85:74:8b:18:97")
        #expect(try mac("00:00:00:00:00:00").canonicalText == "00:00:00:00:00:00")
    }

    /// AND ONE BSD FORM, which is what `ether_ntoa(3)` prints and therefore what
    /// `netstat -rn` and `arp -n` print. `RouteTableSource` has to reproduce it
    /// exactly, because its live test diffs against those commands' own output.
    @Test func bsdTextIsWhatNetstatAndArpPrint() throws {
        #expect(try mac("0a:e6:33:6c:f0:52").bsdText == "a:e6:33:6c:f0:52")
        #expect(try mac("42:00:5c:85:fa:1a").bsdText == "42:0:5c:85:fa:1a")
        #expect(try mac("00:00:00:00:00:00").bsdText == "0:0:0:0:0:0")
        #expect(try mac("a0:99:9b:18:dc:93").bsdText == "a0:99:9b:18:dc:93")
    }

    /// COMPARISON DOES NOT GO THROUGH EITHER OF THEM. The two renderings of the same
    /// address are different strings; the address is one value.
    @Test func twoRenderingsOfOneAddressAreStillOneValue() throws {
        let address = try mac("0a:e6:33:6c:f0:52")
        #expect(address.canonicalText != address.bsdText)
        #expect(try mac(address.canonicalText) == address)
        #expect(try mac(address.bsdText) == address)
    }

    /// ORDER IS NUMERIC, NOT LEXICOGRAPHIC. A string sort put `a:…` after `10:…`;
    /// `VMXScrape`'s recorded addresses are `sorted()` on the way into a guest record,
    /// so this is a real ordering and not a formality.
    @Test func orderIsOverTheOctetsNotOverAnySpelling() throws {
        let sorted = try [mac("ff:00:00:00:00:00"), mac("0a:00:00:00:00:00"),
                          mac("10:00:00:00:00:00")].sorted()
        #expect(sorted.map(\.canonicalText) == ["0a:00:00:00:00:00",
                                                "10:00:00:00:00:00",
                                                "ff:00:00:00:00:00"])
    }

    /// AN ACCIDENTAL `"\(mac)"` MUST NOT PRINT AN ADDRESS. Without the
    /// `CustomDebugStringConvertible` conformance Swift's mirror would dump the packed
    /// storage, which is the address in decimal — a leak that would look like nothing
    /// in review.
    @Test func interpolatingOneByAccidentLeaksNothing() throws {
        let address = try mac("0a:e6:33:6c:f0:52")
        let accident = "\(address)"
        #expect(accident == "MACAddress(hidden)")
        for fragment in ["0a", "e6", "33", "6c", "f0", "52", "11986069127250"] {
            #expect(!accident.contains(fragment), "\(accident) leaks \(fragment)")
        }
    }
}

// MARK: - Codable

struct MACAddressCodableTests {

    @Test func itRoundTripsThroughItsCanonicalForm() throws {
        let address = try mac("a:e6:33:6c:f0:52")
        let data = try JSONEncoder().encode(address)
        #expect(String(decoding: data, as: UTF8.self) == "\"0a:e6:33:6c:f0:52\"")
        #expect(try JSONDecoder().decode(MACAddress.self, from: data) == address)
    }

    /// LENIENT IN, CANONICAL OUT — the same asymmetry `ProviderPeerKey` uses for
    /// base64. Anything already written in an older spelling still reads.
    @Test func itDecodesAnySpellingAndReEncodesOne() throws {
        for spelling in ["\"a:e6:33:6c:f0:52\"", "\"0A:E6:33:6C:F0:52\"",
                         "\"0ae6336cf052\"", "\"0a-e6-33-6c-f0-52\""] {
            let decoded = try JSONDecoder().decode(
                MACAddress.self, from: Data(spelling.utf8))
            #expect(decoded.canonicalText == "0a:e6:33:6c:f0:52")
        }
    }

    /// AND A FAILURE SAYS NOTHING ABOUT WHAT FAILED. A decoding error is a string that
    /// ends up in a log or a report; a hardware address must not ride one there.
    @Test func aDecodingFailureCarriesNoAddress() {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(MACAddress.self, from: Data("\"ea:85:74:8b:18\"".utf8))
        }
        do {
            _ = try JSONDecoder().decode(
                MACAddress.self, from: Data("\"ea:85:74:8b:18:97:aa\"".utf8))
            Issue.record("a seven-octet address should not decode")
        } catch {
            #expect(!"\(error)".contains("ea:85"), "the error quotes the address back")
        }
    }
}

// MARK: - The scans: a String hardware address must not come back

/// SOURCE-WALKING, LIKE `SettingAlignmentTests`, and for the same reason: what is
/// being checked is a property of how the code is WRITTEN, not of what it computes.
/// Every one of these offences is invisible at runtime — that is the whole character
/// of this bug — and obvious in a diff nobody is reading.
struct HardwareAddressTypeDisciplineTests {

    /// The repo root, from this file's own compile-time path.
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Monitoring/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// Every Swift source in every target we own. Not the tests: a test may hold a
    /// spelling as text, because a spelling is what it is testing.
    private static func productionSources() throws -> [String: String] {
        var out: [String: String] = [:]
        for directory in ["SimpleVPN", "Shared", "PacketTunnel", "CLI",
                          "OPNativeHelper", "OCAuthHelper"] {
            let root = repoRoot.appendingPathComponent(directory)
            guard let walk = FileManager.default.enumerator(
                at: root, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walk where url.pathExtension == "swift" {
                let relative = url.path.replacingOccurrences(
                    of: repoRoot.path + "/", with: "")
                out[relative] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            }
        }
        #expect(out.count > 100, "only \(out.count) sources found — the walk is wrong")
        return out
    }

    /// The identifier spellings this codebase uses, or plausibly would, for a hardware
    /// address. Extend it rather than working around it.
    private static let addressNames = [
        "mac", "macs", "MAC", "MACs", "macAddress", "macAddresses",
        "MacAddress", "MACAddress", "macText", "hwaddr", "hwAddr",
        "hardwareAddress", "etherAddress", "physicalAddress", "gatewayMAC",
        "recordedMACs", "neighbours", "linkAddress",
    ]

    /// The `String` shapes one could be smuggled in as. `[String: Set<String>]` is
    /// there because it is the exact shape the neighbour cache had when the bug was
    /// live.
    private static let stringTypes = ["String", "[String]", "Set<String>",
                                      "[String: Set<String>]", "[String: [String]]"]

    /// **NO HARDWARE ADDRESS IS DECLARED AS A `String`.**
    ///
    /// THIS IS THE TEST THAT MATTERS. `MACAddress` makes the comparison structural
    /// only for as long as nobody declares the next one as text — and the next one
    /// will be written by somebody parsing a fifth vendor's config file, in a hurry,
    /// who has never seen `42:0:5c:85:fa:1a` next to `EA:85:74:8B:18:97`. The symptom
    /// they will get is nothing at all.
    ///
    /// The scan is over the whole text rather than over declarations, so a function
    /// PARAMETER counts too — `place(neighbours: [String: Set<String>])` was where
    /// half of the original bug lived, and it is not a stored property.
    ///
    /// A *rendering* is fine and is what `canonicalText` and `bsdText` are for. None
    /// of the names below is a rendering's name, so no exception is needed; if one
    /// ever is, it belongs in `addressNames`' comment as a deliberate omission rather
    /// than as a special case here.
    @Test func noHardwareAddressIsHeldAsAString() throws {
        var offenders: [String] = []
        for (file, text) in try Self.productionSources() {
            for (number, line) in text.components(separatedBy: "\n").enumerated() {
                for name in Self.addressNames where Self.stringTypes.contains(where: {
                    line.contains("\(name): \($0)")
                }) {
                    offenders.append("\(file):\(number + 1) — \(name)")
                }
            }
        }
        #expect(offenders.isEmpty, """
            a hardware address is being held as a String again. Two spellings of one \
            address are different strings and equal MACAddresses, and when this was \
            last true nothing failed — guest names simply never attached. Use \
            MACAddress (Shared/MACAddress.swift): \(offenders.sorted().joined(separator: ", "))
            """)
    }

    /// **NOBODY NORMALISES A HARDWARE ADDRESS BY HAND.**
    ///
    /// There were two of these before the type existed — one in `NetworkTopology` for
    /// the colon spellings and one in `GuestInventory` for the unseparated one — and
    /// they disagreed about which spellings were legal, which is how the second came
    /// to exist at all. Parsing lives in exactly one place now.
    @Test func thereIsExactlyOneParserForAHardwareAddress() throws {
        var offenders: [String] = []
        for (file, text) in try Self.productionSources()
        where file != "Shared/MACAddress.swift" {
            for needle in ["normalisedMAC", "normalizedMAC", "normalisedMac",
                           "normaliseMAC", "normalizeMAC", "normalisedUnseparatedMAC",
                           "ether_ntoa(", "ether_aton("]
            where text.contains(needle) {
                offenders.append("\(file) — \(needle)")
            }
        }
        #expect(offenders.isEmpty, """
            hand-rolled hardware-address normalisation outside MACAddress: \
            \(offenders.sorted().joined(separator: ", "))
            """)
    }

    /// **RENDERING ONE IS A CLOSED SET OF PLACES, EACH WITH A REASON.**
    ///
    /// A hardware address names a physical device and is usable to track it. So
    /// `MACAddress` has no `description`: making one visible takes naming a rendering,
    /// and that makes every such place greppable — which is what this test greps.
    ///
    /// Adding a file here is not forbidden. It is required to be deliberate, and the
    /// three rules it must not break are: **never in the diagnostic report** (a thing
    /// the user SENDS — `DiagnosticReportInventory` already withholds guest names for
    /// a weaker version of this reason), **never in a log line**, and **never in an
    /// error string**.
    @Test func everyPlaceThatRendersAnAddressIsAccountedFor() throws {
        /// file → why it is allowed to render one.
        let permitted: [String: String] = [
            "SimpleVPN/Monitoring/GuestInventory.swift":
                "the evidence sentence on a guest's own card, on screen and nowhere else",
            "SimpleVPN/Monitoring/RouteTableSource.swift":
                "the gateway column must be byte-identical to what netstat prints",
            "SimpleVPN/Monitoring/NetworkMemory.swift":
                "the network-identity key already persisted in UserDefaults",
        ]
        var found: Set<String> = []
        for (file, text) in try Self.productionSources()
        where file != "Shared/MACAddress.swift" {
            if text.contains(".canonicalText") || text.contains(".bsdText") {
                found.insert(file)
            }
        }
        let unexpected = found.subtracting(permitted.keys)
        #expect(unexpected.isEmpty, """
            a hardware address is being rendered somewhere new: \
            \(unexpected.sorted().joined(separator: ", ")). That is allowed, but it \
            must not be the diagnostic report, a log line or an error string — add it \
            here with the reason.
            """)
        let vanished = Set(permitted.keys).subtracting(found)
        #expect(vanished.isEmpty, """
            these are listed as rendering an address and no longer do — drop them from \
            the list: \(vanished.sorted().joined(separator: ", "))
            """)
    }

    /// **AND NOTHING IN `Diagnostics/` TOUCHES ONE AT ALL.**
    ///
    /// Stated separately from the allow-list above because it is the rule with the
    /// consequence: the report and the debug bundle are the two things that LEAVE this
    /// Mac. `SecretScrubber` redacts addresses out of free text as defence in depth;
    /// this is the primary control, which is that none is ever put in.
    @Test func nothingInDiagnosticsHandlesAHardwareAddress() throws {
        var offenders: [String] = []
        for (file, text) in try Self.productionSources()
        where file.hasPrefix("SimpleVPN/Diagnostics/") {
            for needle in ["MACAddress", ".canonicalText", ".bsdText", "gatewayMAC",
                           "recordedMACs"] where text.contains(needle) {
                offenders.append("\(file) — \(needle)")
            }
        }
        #expect(offenders.isEmpty, """
            the diagnostic report is a thing the user SENDS and a hardware address \
            identifies a machine: \(offenders.sorted().joined(separator: ", "))
            """)
    }

    /// **AND THE ONE KEY THAT CARRIES AN ADDRESS IS LOGGED `private`.**
    ///
    /// `NetworkFingerprint.key` is `mac:` plus the gateway's hardware address whenever
    /// we have one — an identifier for a specific piece of somebody's furniture, in a
    /// log `DiagnosticReportLog` reads. Both `netmemory` lines that mention it must
    /// mark it `privacy: .private`; the KIND of key is logged `.public` beside it,
    /// which is the diagnostic content the address never was.
    @Test func theNetworkKeyIsNeverLoggedInTheClear() throws {
        let source = try String(
            contentsOf: Self.repoRoot.appendingPathComponent(
                "SimpleVPN/Monitoring/NetworkMemory.swift"), encoding: .utf8)
        // The offence is a KEY interpolated `.public`. `keyStrength` deliberately is
        // one, and is the reason this looks for the interpolation rather than for the
        // word.
        var offenders: [String] = []
        for (number, line) in source.components(separatedBy: "\n").enumerated() {
            for needle in [".key, privacy: .public", "old ?? \"none\", privacy: .public",
                           "new ?? \"none\", privacy: .public"]
            where line.contains(needle) {
                offenders.append("NetworkMemory.swift:\(number + 1)")
            }
        }
        #expect(offenders.isEmpty, """
            a network key — which is a hardware address when we have one — is logged \
            in the clear at \(offenders.joined(separator: ", "))
            """)
        #expect(source.contains("key=\\(fp.key, privacy: .private)"))
        #expect(source.contains("strength=\\(fp.keyStrength, privacy: .public)"))
    }
}
