// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListParsingTests.swift
//  THAT A PROVIDER'S PAYLOAD IS READ HOSTILELY, and that the seam between a trusted
//  template and an untrusted list holds.
//
//  THE FIXTURES ARE REAL. Every one below was taken from a live payload on
//  2026-08-07 and the URL is named in the test. That matters more than usual here:
//  Mullvad's app API documentation page has no readable content and Nord's `/v1`
//  carries no published contract, so "the field is called `ipv4_addr_in`" is a fact
//  about what a server returned, not a fact from a specification. A fixture invented
//  from memory would test the parser against my recollection instead of against the
//  provider.
//
//  THE INJECTION TESTS ARE THE POINT. Half of this file hands the parsers payloads
//  that a hostile list would contain — a newline in a hostname, somebody else's
//  domain, a 31-byte key, a quoted directive — and asserts they produce NOTHING
//  rather than something slightly wrong. Docs/ServiceBundles.md §4.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderListParsingTests {

    // MARK: - Mullvad, against the real payload

    /// One relay object, copied verbatim from `https://api.mullvad.net/www/relays/all/`
    /// on 2026-08-07. Every field the parser reads is present exactly as Mullvad
    /// spells it.
    private static let mullvadRealRow = """
        [{"hostname":"al-tia-wg-001","country_code":"al","country_name":"Albania",
        "city_code":"tia","city_name":"Tirana","fqdn":"al-tia-wg-001.relays.mullvad.net",
        "active":true,"owned":false,"provider":"iRegister","ipv4_addr_in":"103.124.165.2",
        "ipv6_addr_in":"2a04:27c0:0:e::f001","network_port_speed":10,"stboot":true,
        "type":"wireguard","status_messages":[],
        "pubkey":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=","multihop_port":3494,
        "socks_name":"al-tia-wg-socks5-001.relays.mullvad.net","socks_port":1080,"daita":true}]
        """

    @Test("Mullvad's real relay shape parses, and every field lands where it should")
    func mullvadRealRelay() throws {
        let list = try ProviderListParser.mullvad(Data(Self.mullvadRealRow.utf8))
        #expect(list.servers.count == 1)
        #expect(list.dropped == 0)
        let s = try #require(list.servers.first)
        #expect(s.hostname.value == "al-tia-wg-001.relays.mullvad.net")
        #expect(s.ipv4 == "103.124.165.2")
        #expect(s.countryCode == "al")
        #expect(s.cityCode == "tia")
        #expect(s.cityName == "Tirana")
        #expect(s.active)
        #expect(s.peerKey?.base64 == "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=")
    }

    /// The IPv6 is re-serialised from a parsed address rather than echoed. Mullvad
    /// writes `2a04:27c0:0:e::f001`; whatever `IPv6Address` renders is what we store,
    /// and the assertion is that it PARSED — not that it is byte-identical, which
    /// would be a test of Apple's formatter.
    @Test("an IPv6 address survives as a parsed value, not as the payload's text")
    func mullvadIPv6IsParsed() throws {
        let list = try ProviderListParser.mullvad(Data(Self.mullvadRealRow.utf8))
        let v6 = try #require(list.servers.first?.ipv6)
        #expect(!v6.isEmpty)
        #expect(v6.contains(":"))
    }

    /// `bridge` rows really are in the live payload — 13 of the 580 read on
    /// 2026-08-07 — and they have no `pubkey`. They are not something a user points a
    /// tunnel at, so they are dropped and COUNTED, never quietly ignored.
    @Test("a bridge row is dropped and counted, not turned into a keyless server")
    func mullvadBridgeRowsDropped() throws {
        let json = """
            [{"hostname":"au-syd-br-001","country_code":"au","city_code":"syd",
            "city_name":"Sydney","fqdn":"au-syd-br-001.relays.mullvad.net","active":true,
            "type":"bridge","ipv4_addr_in":"146.70.141.154","ipv4_v2ray":"146.70.141.155",
            "ssh_fingerprint_sha256":"SHA256:wEmga6H8w6oCOz8s8YGzQs2WaGSPTFBEydyLuCAgHnE"},
            {"fqdn":"al-tia-wg-001.relays.mullvad.net","type":"wireguard","active":true,
            "pubkey":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="}]
            """
        let list = try ProviderListParser.mullvad(Data(json.utf8))
        #expect(list.servers.count == 1)
        #expect(list.dropped == 1)
    }

    /// For WireGuard the peer key IS the authentication, so a relay without one
    /// cannot be connected to. Dropping it is honest; defaulting it to an empty key
    /// would turn a missing field into a mysterious handshake failure much later.
    @Test("a WireGuard relay with no peer key is dropped rather than defaulted")
    func mullvadMissingKeyDropped() throws {
        let json = """
            [{"fqdn":"al-tia-wg-001.relays.mullvad.net","type":"wireguard","active":true}]
            """
        #expect(throws: ProviderListParser.Failure.empty) {
            try ProviderListParser.mullvad(Data(json.utf8))
        }
    }

    // MARK: - The suffix rule, which is the cheapest control in the feature

    /// A relay claiming to be somewhere else entirely. The suffix ships with the
    /// app, so a fetch cannot widen it: even a fully compromised list cannot point
    /// the user at a domain the provider does not own.
    @Test("a hostname outside the provider's own domain is refused")
    func hostnameOutsideSuffixRefused() {
        #expect(ProviderHostname("al-tia-wg-001.relays.mullvad.net.evil.example",
                                 allowedSuffix: ".relays.mullvad.net") == nil)
        #expect(ProviderHostname("evil.example", allowedSuffix: ".relays.mullvad.net") == nil)
        #expect(ProviderHostname("al-tia-wg-001.relays.mullvad.net",
                                 allowedSuffix: ".relays.mullvad.net") != nil)
    }

    /// THE INJECTION TEST. A newline in a hostname is how a list turns into two lines
    /// of an `.ovpn`, and the character class refuses it before anything downstream
    /// has to be clever. The same class refuses spaces, quotes and `#`.
    @Test("a hostname carrying a newline, a space or a quote cannot survive")
    func hostnameCannotCarryDirectives() {
        let suffix = ".relays.mullvad.net"
        for hostile in [
            "a\nremote evil.example 1194\nb.relays.mullvad.net",
            "a b.relays.mullvad.net",
            "a\"b.relays.mullvad.net",
            "a#b.relays.mullvad.net",
            "a\tb.relays.mullvad.net",
            "a\u{0}b.relays.mullvad.net",
            "A-UPPER.relays.mullvad.net",
        ] {
            #expect(ProviderHostname(hostile, allowedSuffix: suffix) == nil,
                    "should refuse \(hostile.debugDescription)")
        }
    }

    /// A hostile list cannot smuggle a directive through a Mullvad payload either —
    /// the same validator sits between the JSON and everything downstream.
    @Test("an injected hostname in a real-shaped Mullvad payload parses to nothing")
    func mullvadInjectionParsesToNothing() {
        let json = """
            [{"fqdn":"evil.example\\nremote 10.0.0.1 1194","type":"wireguard","active":true,
            "pubkey":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="}]
            """
        #expect(throws: ProviderListParser.Failure.empty) {
            try ProviderListParser.mullvad(Data(json.utf8))
        }
    }

    /// DNS limits, enforced so a megabyte "hostname" cannot reach a config file.
    @Test("label and total length limits are enforced")
    func hostnameLengthLimits() {
        let suffix = ".relays.mullvad.net"
        #expect(ProviderHostname(String(repeating: "a", count: 64) + suffix,
                                 allowedSuffix: suffix) == nil)
        #expect(ProviderHostname(String(repeating: "a", count: 63) + suffix,
                                 allowedSuffix: suffix) != nil)
        let long = Array(repeating: String(repeating: "a", count: 60), count: 5).joined(separator: ".")
        #expect(ProviderHostname(long + suffix, allowedSuffix: suffix) == nil)
        #expect(ProviderHostname("-lead.relays.mullvad.net", allowedSuffix: suffix) == nil)
        #expect(ProviderHostname("trail-.relays.mullvad.net", allowedSuffix: suffix) == nil)
        #expect(ProviderHostname("a..b.relays.mullvad.net", allowedSuffix: suffix) == nil)
    }

    // MARK: - Peer keys

    /// 32 bytes, or nothing. A 31-byte key would be a handshake that never completes
    /// and an error nobody can trace back to a list update.
    @Test("a peer key must be exactly 32 bytes and is re-encoded canonically")
    func peerKeyIsExactlyThirtyTwoBytes() throws {
        #expect(ProviderPeerKey("ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=") != nil)
        #expect(ProviderPeerKey("") == nil)
        #expect(ProviderPeerKey("not base64 at all, obviously not 44 chars!!!") == nil)
        // 31 bytes, correctly padded — the case a length-only check would let through.
        let short = Data(repeating: 0x41, count: 31).base64EncodedString()
        #expect(ProviderPeerKey(short) == nil)
        // 33 bytes.
        let long = Data(repeating: 0x41, count: 33).base64EncodedString()
        #expect(ProviderPeerKey(long) == nil)
        // The canonical re-encoding: what comes out is what `Data` writes, so two
        // spellings of one key can never look like two different keys to the diff.
        let key = try #require(ProviderPeerKey("ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="))
        #expect(key.base64.count == 44)
        #expect(ProviderPeerKey(key.base64) == key)
    }

    // MARK: - NordVPN, against the real payload

    /// Shaped from `https://api.nordvpn.com/v1/servers?limit=1` on 2026-08-07,
    /// including the real nesting the WireGuard key lives at. The entry was
    /// `technologies[6]` in that payload, which is exactly why the parser searches by
    /// `identifier` instead of by index.
    private static let nordRealRow = """
        [{"id":930488,"name":"United States #5063","station":"185.245.87.59",
        "ipv6_station":"","hostname":"us5063.nordvpn.com","load":64,"status":"online",
        "locations":[{"country":{"code":"US","name":"United States",
        "city":{"name":"Los Angeles"}}}],
        "technologies":[{"id":21,"name":"HTTP Proxy (SSL)","identifier":"proxy_ssl",
        "metadata":[{"name":"port","value":"89"}]},
        {"id":35,"name":"Wireguard","identifier":"wireguard_udp",
        "metadata":[{"name":"public_key","value":"V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="}]}]}]
        """

    @Test("Nord's real server shape parses, including the nested WireGuard key")
    func nordRealServer() throws {
        let list = try ProviderListParser.nordVPN(Data(Self.nordRealRow.utf8))
        let s = try #require(list.servers.first)
        #expect(s.hostname.value == "us5063.nordvpn.com")
        // BOTH values matter for Nord: its `.ovpn` dials the IP and name-checks the
        // hostname, so a substitution that fills in one and not the other is broken.
        #expect(s.ipv4 == "185.245.87.59")
        #expect(s.countryCode == "us")
        #expect(s.cityName == "Los Angeles")
        #expect(s.active)
        #expect(s.peerKey?.base64 == "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4=")
    }

    /// `ipv6_station` is the empty string on the server read on 2026-08-07, not null.
    /// An empty string that became `""` in a config file would be a `remote` line with
    /// no address; it has to come out as nil.
    @Test("Nord's empty ipv6_station becomes nil rather than an empty address")
    func nordEmptyIPv6() throws {
        let list = try ProviderListParser.nordVPN(Data(Self.nordRealRow.utf8))
        #expect(list.servers.first?.ipv6 == nil)
    }

    /// The key is found by searching for the identifier, so it survives Nord
    /// reordering its technologies — which is not hypothetical, since the array's
    /// contents differ per server.
    @Test("the WireGuard key is found by identifier, not by position")
    func nordKeyFoundByIdentifier() throws {
        let json = """
            [{"hostname":"us5063.nordvpn.com","station":"185.245.87.59","status":"online",
            "technologies":[{"id":35,"name":"Wireguard","identifier":"wireguard_udp",
            "metadata":[{"name":"public_key","value":"V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="}]},
            {"id":21,"identifier":"proxy_ssl","metadata":[{"name":"port","value":"89"}]}]}]
            """
        let list = try ProviderListParser.nordVPN(Data(json.utf8))
        #expect(list.servers.first?.peerKey?.base64 == "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4=")
    }

    @Test("a Nord server outside nordvpn.com is dropped and counted")
    func nordSuffixEnforced() {
        let json = """
            [{"hostname":"us5063.nordvpn.com.evil.example","station":"10.0.0.1","status":"online"}]
            """
        #expect(throws: ProviderListParser.Failure.empty) {
            try ProviderListParser.nordVPN(Data(json.utf8))
        }
    }

    // MARK: - IPVanish, against the real directory index

    /// Copied from `https://configs.ipvanish.com/configs/` on 2026-08-07 — the same
    /// index whose 3,576 `.ovpn` files all normalise to one SHA-256 once the hostname
    /// is replaced. The extra entries are there because they really are.
    private static let ipVanishRealIndex = """
        <a href="..">..</a><a href="ca.ipvanish.com.crt">ca</a>
        <a href="configs.zip">configs.zip</a><a href="guideCRT.txt">guide</a>
        <a href="ipvanish-AD-Andorra-la-Vella---Virtual-adv-c01.ovpn">x</a>
        <a href="ipvanish-AE-Dubai-dxb-c10.ovpn">x</a>
        <a href="ipvanish-AE-Dubai-dxb-c11.ovpn">x</a>
        """

    @Test("IPVanish's real directory index yields hostnames, countries and cities")
    func ipVanishRealDirectory() throws {
        let list = try ProviderListParser.ipVanish(Self.ipVanishRealIndex)
        #expect(list.servers.count == 3)
        let dubai = try #require(list.server("dxb-c10.ipvanish.com"))
        #expect(dubai.countryCode == "ae")
        #expect(dubai.cityName == "Dubai")
        #expect(dubai.cityCode == "dxb")
        // Reconstructed from the filename's last two components, not scraped from the
        // page — which is what makes an arbitrary `href` harmless.
        let andorra = try #require(list.server("adv-c01.ipvanish.com"))
        // IPVanish writes a space as `-` and an em dash as `---`, and the city is the
        // one field allowed to keep its case and its punctuation because it is a
        // label a person reads and never reaches a configuration file.
        #expect(andorra.cityName == "Andorra la Vella \u{2014} Virtual")
        #expect(andorra.countryCode == "ad")
        // Nothing WireGuard is published, so nothing pretends there is.
        #expect(list.servers.allSatisfy { $0.peerKey == nil })
    }

    /// A hostile index, and what "safe" means here is worth stating precisely,
    /// because the first version of this test asserted the wrong thing.
    ///
    /// Nothing in the HTML becomes a hostname directly: the filename is decomposed
    /// and only the two components we understand are recombined **under the
    /// provider's own suffix**. So a file named after somebody else's domain does not
    /// produce that domain — it produces a label inside `ipvanish.com`, which
    /// IPVanish controls and which will simply not resolve. The property being
    /// asserted is therefore CONFINEMENT, not the absence of a suspicious substring:
    /// `evil.example-c01.ipvanish.com` contains "evil" and is entirely harmless,
    /// and a test that banned the substring would be measuring the wrong thing.
    @Test("an href naming another domain is confined under the provider's suffix")
    func ipVanishHostileIndex() throws {
        let html = """
            <a href="ipvanish-XX-Evil-evil.example-c01.ovpn">x</a>
            <a href="https://evil.example/ipvanish-AE-Dubai-dxb-c10.ovpn">x</a>
            <a href="ipvanish-AE-Dubai-dxb-c11.ovpn">x</a>
            """
        let list = try ProviderListParser.ipVanish(html)
        #expect(list.servers.allSatisfy { $0.hostname.value.hasSuffix(".ipvanish.com") })
        // The other domain became a LABEL inside ipvanish.com, not a domain of its own.
        #expect(list.server("evil.example-c01.ipvanish.com") != nil)
        #expect(!list.servers.contains { $0.hostname.value.hasSuffix(".example") })
        // The path form is reduced to its last component, so it is the same server as
        // a bare filename would be — and it is under IPVanish's domain either way.
        #expect(list.server("dxb-c10.ipvanish.com") != nil)
        #expect(list.server("dxb-c11.ipvanish.com") != nil)
    }

    @Test("an index with no .ovpn files is empty, not a shrunken list")
    func ipVanishEmptyIndex() {
        #expect(throws: ProviderListParser.Failure.empty) {
            try ProviderListParser.ipVanish("<html><body>Forbidden</body></html>")
        }
    }

    // MARK: - Whole-payload failures

    /// The two ways a payload can be rejected outright, and they are deliberately
    /// distinct: `malformed` is "that was not JSON", `empty` is "it was, and there
    /// was nothing in it". A broken CDN and a hostile substitution both look like the
    /// second, and either way it must never replace a working list.
    @Test("a payload that is not the provider's shape is malformed, not empty")
    func malformedIsDistinctFromEmpty() {
        #expect(throws: ProviderListParser.Failure.malformed) {
            try ProviderListParser.mullvad(Data("not json".utf8))
        }
        #expect(throws: ProviderListParser.Failure.malformed) {
            try ProviderListParser.mullvad(Data(#"{"servers":[]}"#.utf8))
        }
        #expect(throws: ProviderListParser.Failure.empty) {
            try ProviderListParser.mullvad(Data("[]".utf8))
        }
        #expect(throws: ProviderListParser.Failure.malformed) {
            try ProviderListParser.nordVPN(Data("not json".utf8))
        }
    }

    /// A list sorts by hostname on construction, so a provider shuffling its JSON
    /// cannot make an unchanged list look like a changed one to the diff.
    @Test("a list is sorted by hostname, so payload order cannot fake a change")
    func listIsSorted() throws {
        let json = """
            [{"fqdn":"z-wg-001.relays.mullvad.net","type":"wireguard","active":true,
            "pubkey":"ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="},
            {"fqdn":"a-wg-001.relays.mullvad.net","type":"wireguard","active":true,
            "pubkey":"V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="}]
            """
        let list = try ProviderListParser.mullvad(Data(json.utf8))
        #expect(list.servers.map(\.hostname.value)
            == ["a-wg-001.relays.mullvad.net", "z-wg-001.relays.mullvad.net"])
    }
}
