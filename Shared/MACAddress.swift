// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MACAddress.swift
//  A HARDWARE ADDRESS AS SIX BYTES, so that two spellings of the same address
//  cannot fail to be the same value.
//
//  THE BUG THIS TYPE EXISTS TO MAKE IMPOSSIBLE. `netstat` and `arp` print an octet
//  without its leading zero and in lower case — `42:0:5c:85:fa:1a` — because that is
//  what `ether_ntoa(3)` does. UTM's `config.plist` records `EA:85:74:8B:18:97`,
//  zero-padded and upper case. VirtualBox writes `0800271A2B3C` with no separators at
//  all. Every one of those is a correct spelling of a hardware address, and NO TWO OF
//  THEM ARE EQUAL AS STRINGS. When they were compared as strings the guest names on
//  the route diagram simply never attached, and the symptom of that is *nothing* — no
//  error, no empty state, just a diagram that looks finished and is missing the very
//  thing it was built to show.
//
//  A normaliser fixes that only for as long as everybody remembers to call it. A TYPE
//  fixes it by construction: there is no `MACAddress` that has not been parsed, the
//  storage is the six octets rather than any spelling of them, and `==` and
//  `hashValue` are therefore structural. The spelling problem cannot come back without
//  someone first re-introducing a `String`.
//
//  Precedent: `ProviderHostname` and `ProviderPeerKey` (SimpleVPN/Providers/) are types
//  for exactly this reason — "did anybody check this?" is answered by the type system
//  at every later use instead of by a comment. `Docs/NetworkTypes.md` records the
//  conventions this file establishes and the rest of the family still to be built.
//
//  ── A HARDWARE ADDRESS IS AN IDENTIFIER FOR A DEVICE AND MUST NOT LEAK ────────────
//
//  It names a physical machine, it is stable for that machine's life, and it is
//  usable for tracking. So this type is DELIBERATELY NOT `CustomStringConvertible`:
//  rendering one is an act you have to perform on purpose, by naming the form you
//  want, and `grep canonicalText` therefore finds every place an address becomes
//  visible. The `debugDescription` below exists only so that an accidental
//  `"\(mac)"` prints nothing — without it Swift's mirror would dump the packed
//  storage, which is the address in decimal.
//
//  The standing rules, which `MACAddressTests` enforces by scanning the source:
//   • **never in the diagnostic report** — that is a thing the user SENDS, and
//     `DiagnosticReportInventory` already withholds guest NAMES for the weaker version
//     of this reason;
//   • **never in a log line** — `NetworkFingerprint.key` carries one, and the two
//     `netmemory` lines that log it mark it `privacy: .private` for that reason;
//   • **never in an error string**, including this file's own `Codable` failure.
//

import Foundation

/// A 48-bit IEEE 802 hardware address (an Ethernet MAC), parsed.
///
/// The only way to make one is to parse one, and parsing is total: it yields an
/// address or it yields nothing. There is no partially-parsed address, and there is
/// no all-zeroes address standing in for a failure — `00:00:00:00:00:00` parses
/// successfully because it is a legal address, and a *failure* is `nil`.
nonisolated struct MACAddress: Sendable, Hashable, Comparable, Codable,
                               CustomDebugStringConvertible {

    /// THE STORAGE, AND IT IS NOT A STRING: the six octets, most significant first,
    /// in the low 48 bits. Private because the packing is an implementation detail —
    /// `octets` is the way out — but the consequence is the point of the whole file:
    /// `Equatable`, `Hashable` and `Comparable` are synthesised over this one integer,
    /// so they are structural and no spelling participates.
    private let packed: UInt64

    /// The six octets, most significant first. `[0x0a, 0xe6, 0x33, 0x6c, 0xf0, 0x52]`.
    var octets: [UInt8] {
        (0..<6).map { UInt8(truncatingIfNeeded: packed >> (8 * (5 - $0))) }
    }

    /// Exactly six octets, or nothing. Six is not a convention here — a `sockaddr_dl`
    /// can carry a link address of another length (FireWire's is eight), and one of
    /// those is not a MAC and must not be silently truncated into one.
    init?(octets: some Collection<UInt8>) {
        guard octets.count == 6 else { return nil }
        packed = octets.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    /// Parse any spelling this Mac's own tools and virtualization products produce.
    ///
    /// ACCEPTED, and each one is here because something real writes it:
    ///
    /// | Spelling | Example | Who writes it |
    /// |---|---|---|
    /// | colon, leading zeros suppressed | `42:0:5c:85:fa:1a` | `netstat -rn`, `arp -n`, `ether_ntoa(3)` — MEASURED on this Mac |
    /// | colon, zero-padded, any case | `EA:85:74:8B:18:97` | UTM `config.plist` — MEASURED on this Mac |
    /// | bare hex, twelve digits | `0800271A2B3C` | VirtualBox `.vbox`, Parallels `config.pvs` |
    /// | hyphen, either padding, any case | `ea-85-74-8b-18-97` | nothing we read — see below |
    ///
    /// The hyphen form is the one concession to something no source here produces. It
    /// is IEEE 802's own printed notation and what Windows and most vendor labels use,
    /// so it is what a person PASTES; accepting it costs one character in a set and
    /// cannot widen what any of the file parsers admit, because a hyphen was never a
    /// legal character in any of their fields.
    ///
    /// REJECTED, deliberately, with a test pinning each:
    ///
    ///  • **Cisco dotted-quad** (`ea85.748b.1897`). Nothing this app reads emits it —
    ///    not `netstat`, not `arp`, not UTM, VirtualBox, Parallels or VMware — so
    ///    accepting it would be supporting a format on speculation. Add it when a
    ///    source that produces it arrives, and not before.
    ///  • **Mixed separators** (`ea:85-74:8b:18:97`). Two separators in one address is
    ///    not a spelling anything produces; it is a corrupted field, and repairing a
    ///    corrupted field is how a wrong address gets attached to a right name.
    ///  • Wrong length, non-hex characters, a non-ASCII digit that `isHexDigit` would
    ///    otherwise wave through, empty, and whitespace-only.
    ///
    /// Surrounding whitespace IS trimmed. These values come out of XML element text
    /// and hand-edited `.vmx` lines where a trailing space means nothing at all; the
    /// strictness that matters is about the value, not about its margins.
    init?(_ text: some StringProtocol) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let separators = trimmed.filter { $0 == ":" || $0 == "-" }
        var octets: [UInt8] = []
        octets.reserveCapacity(6)

        if separators.isEmpty {
            // Bare hex: twelve digits, no more and no fewer.
            guard trimmed.count == 12, Self.isASCIIHex(trimmed) else { return nil }
            var index = trimmed.startIndex
            while index < trimmed.endIndex {
                let next = trimmed.index(index, offsetBy: 2)
                guard let value = UInt8(trimmed[index..<next], radix: 16) else { return nil }
                octets.append(value)
                index = next
            }
        } else {
            // One separator character throughout — a set of size one, which is what
            // rejects a mixed spelling without a second pass.
            guard Set(separators).count == 1, let separator = separators.first
            else { return nil }
            // `omittingEmptySubsequences: false` so `fe80::1%en0` splits into three
            // groups and is refused, rather than collapsing into something six-shaped.
            let groups = trimmed.split(separator: separator, omittingEmptySubsequences: false)
            guard groups.count == 6 else { return nil }
            for group in groups {
                guard (1...2).contains(group.count), Self.isASCIIHex(group),
                      let value = UInt8(group, radix: 16) else { return nil }
                octets.append(value)
            }
        }
        self.init(octets: octets)
    }

    /// `Character.isHexDigit` is true for `０`–`９` and other non-ASCII digits, and
    /// `UInt8(_:radix:)`'s behaviour on those is not something to depend on.
    private static func isASCIIHex(_ s: some StringProtocol) -> Bool {
        s.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    // MARK: - Renderings, each named for what it is FOR

    /// THE CANONICAL FORM: lower case, zero-padded, colon-separated —
    /// `0a:e6:33:6c:f0:52`. One address has exactly one canonical form.
    ///
    /// It is not what comparison uses. Comparison uses the octets, and must continue
    /// to: the moment two addresses are compared through any string, the spelling is
    /// back in the equality relation and so is the bug. This form is for the places
    /// that need to show a person an address, or to key one durably.
    var canonicalText: String {
        octets.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    /// WHAT THE BSD TOOLS PRINT: lower case, leading zeros suppressed —
    /// `a:e6:33:6c:f0:52`. This is `ether_ntoa(3)`, and therefore `netstat -rn`,
    /// `arp -n` and everything that quotes them.
    ///
    /// It exists because two callers genuinely need to reproduce that spelling
    /// byte-for-byte rather than merely to be readable: `RouteTableSource.gatewayText`,
    /// whose whole contract is to match the text path it replaced, and
    /// `NetworkFingerprint.key`, which is a PERSISTED identity already written into
    /// `UserDefaults` in this spelling. Prefer `canonicalText` for anything new.
    var bsdText: String {
        octets.map { String($0, radix: 16) }.joined(separator: ":")
    }

    /// Numeric order over the octets, most significant first — the order the printed
    /// forms sort in anyway, but arrived at without one. `sorted()` on a list of a
    /// guest's recorded addresses used to be a string sort, which put `a:…` after
    /// `10:…`; this does not.
    static func < (a: MACAddress, b: MACAddress) -> Bool { a.packed < b.packed }

    /// Nothing useful, on purpose. An accidental `"\(mac)"` must not put a hardware
    /// address into a log line, and without this conformance Swift's default mirror
    /// would print the packed storage — the address, in decimal. Render one by naming
    /// the form you want.
    var debugDescription: String { "MACAddress(hidden)" }

    // MARK: - Codable

    /// A single canonical string, decoded leniently.
    ///
    /// Lenient IN, canonical OUT is the same asymmetry `ProviderPeerKey` uses for
    /// base64: anything already on disk in an older spelling still reads, and
    /// everything written from now on is one form. The failure message deliberately
    /// does not quote what failed — an error string is a place a hardware address
    /// gets copied into a report.
    init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let parsed = MACAddress(text) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "not a hardware address"))
        }
        self = parsed
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(canonicalText)
    }
}
