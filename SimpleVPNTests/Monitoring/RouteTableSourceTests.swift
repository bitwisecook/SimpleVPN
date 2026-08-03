// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteTableSourceTests.swift
//  Proves the binary routing-table decoder can replace the `netstat -rn` text
//  path without changing a single answer. A decoder that reads raw kernel bytes
//  is only worth having if it is TRUSTED, so this tests it three ways:
//
//  1. AGAINST THE KERNEL. Take a snapshot, then ask the system itself where a
//     spread of addresses goes (`/sbin/route -n get`) and require the resolver to
//     agree. Tests may shell out; production may not — that asymmetry is the
//     whole point, the subprocess is the ORACLE, not the implementation.
//  2. AGAINST THE TEXT PATH. Build the old `RouteTableSnapshot(netstatText:)`
//     from live netstat output and compare the semantic fields — destination
//     prefix, interface, scoping, whether the gateway is a real next hop — plus
//     the resolver's actual answers.
//  3. AGAINST HAND-BUILT BYTES. The quirks that make binary route parsing
//     famously fiddly (truncated netmasks, sa_len == 0 placeholders, sockaddr_dl
//     gateways, embedded IPv6 scope ids, 4-byte alignment padding) are each
//     driven by a fixture assembled byte by byte in this file, so a regression
//     names the quirk it broke instead of just "the table looks wrong".
//
//  Two live-table facts the assertions have to allow for, both real and neither a
//  decoder bug:
//    • The table MOVES. ARP entries expire mid-test, VPNs push routes. Live
//      comparisons re-check disagreements against a fresh snapshot and tolerate a
//      small residue.
//    • SCOPED ROUTES. `RouteResolver` keeps RTF_IFSCOPE routes as candidates and
//      only de-prioritises them on a length tie, whereas the kernel ignores them
//      for traffic that is not bound to the interface. Where the winner is
//      scoped, the resolver and `route -n get` can legitimately differ; that is a
//      `RouteResolver` semantic (unchanged here, 28 tests pin it), so those
//      addresses are compared to the TEXT path instead.
//

import Foundation
import Darwin
import Testing
@testable import SimpleVPN

struct RouteTableSourceTests {

    // MARK: - 1. Live parity with the kernel

    @Test("Every address the kernel can route resolves to the same interface")
    func liveParityWithKernel() throws {
        let snapshot = try RouteTableSource.snapshot()
        #expect(!snapshot.isEmpty, "the machine running the tests has a routing table")

        var probes = ["1.1.1.1", "9.9.9.9", "8.8.8.8", "13.107.42.14"]
        // The local gateway: the real next hop of a v4 default route.
        if let gateway = snapshot.routes
            .first(where: { $0.family == .v4 && $0.isDefault && $0.hasRealGateway })?
            .gatewayAddress?.addressText {
            probes.append(gateway)
        }
        // Tailscale's CGNAT space, and an address inside whatever a tunnel has
        // been given — the routes a VPN pushes at us are exactly the interesting
        // ones and they are never in a fixture.
        probes.append("100.64.0.1")
        probes += snapshot.routes.filter {
            $0.family == .v4 && !$0.isDefault && !$0.prefix.isHost
                && $0.interfaceName.hasPrefix("utun")
        }.prefix(4).map(\.prefix.addressText)
        probes.append("2606:4700:4700::1111")
        // …plus a handful sampled from the table's own prefixes. Multicast is left
        // out: those addresses answer by group semantics rather than by the table.
        probes += snapshot.routes.filter { route in
            guard !route.isDefault else { return false }
            return route.family == .v4 ? route.prefix.bytes[0] < 224 : route.prefix.bytes[0] != 0xFF
        }.shuffled().prefix(24).map { Self.probeAddress(inside: $0.prefix) }

        var compared = 0
        var skipped = 0
        var unanswered = 0
        var disagreements: [(address: String, ours: String?, kernel: String)] = []
        // The kernel loops THIS MACHINE's own addresses back through lo0, via the
        // RTF_LOCAL entry it keeps alongside the on-link route ("10.0.5.27
        // ba:b8:… UHLWI lo0" sitting under "10.0.5.27/32 link#16 UCS en0").
        // RouteResolver ranks the unscoped on-link route first and answers en0.
        // Both snapshots contain both records and agree with each other, so this is
        // a resolver semantic, not a decoding one — and not this file's to assert.
        let ownAddresses = Self.localAddresses()

        for address in Set(probes) {
            guard !ownAddresses.contains(address) else { skipped += 1; continue }
            guard let kernel = Self.kernelInterface(for: address) else { unanswered += 1; continue }
            let resolution = RouteResolver(snapshot: snapshot).resolve(address)
            // Likewise a scoped winner: the kernel only uses RTF_IFSCOPE routes for
            // traffic bound to the interface, RouteResolver keeps them as candidates.
            if resolution?.winner?.isScoped == true { skipped += 1; continue }
            compared += 1
            if resolution?.interfaceName != kernel {
                disagreements.append((address, resolution?.interfaceName, kernel))
            }
        }

        // The table can move between the snapshot and the oracle; re-check against
        // a fresh one before calling it a decoding failure.
        if !disagreements.isEmpty {
            let fresh = try RouteTableSource.snapshot()
            disagreements = disagreements.filter { item in
                RouteResolver(snapshot: fresh).resolve(item.address)?.interfaceName != item.kernel
            }
        }

        #expect(compared >= 8, """
            too few comparable addresses: compared \(compared), skipped \(skipped) \
            (own/scoped), \(unanswered) not in the kernel's table
            """)
        #expect(disagreements.isEmpty, """
            binary snapshot disagrees with `route -n get`: \
            \(disagreements.map { "\($0.address): ours=\($0.ours ?? "nil") kernel=\($0.kernel)" })
            """)
    }

    // MARK: - 2. Parity with the text path it replaces

    @Test("Binary and netstat snapshots describe the same table")
    func parityWithNetstatText() throws {
        let binary = try RouteTableSource.snapshot()
        let text = RouteTableSnapshot(
            ipv4Text: Self.run("/usr/sbin/netstat", ["-rn", "-f", "inet"]) ?? "",
            ipv6Text: Self.run("/usr/sbin/netstat", ["-rn", "-f", "inet6"]) ?? "")

        #expect(!text.isEmpty, "netstat produced a table to compare against")

        // Every default route, both families, must match on all four semantic
        // fields — this is the part `RouteResolver` actually reasons over, and the
        // case (several simultaneous defaults) the whole resolver exists for.
        func defaults(_ snapshot: RouteTableSnapshot) -> [String] {
            snapshot.routes.filter(\.isDefault).map {
                "\($0.family)|\($0.interfaceName)|\($0.isScoped)|\($0.hasRealGateway)"
            }
        }
        #expect(defaults(binary) == defaults(text), """
            defaults differ:
              binary: \(defaults(binary))
              text:   \(defaults(text))
            """)

        // Whole-table comparison on the semantic tuple. Exact equality is not
        // required (and not asserted): ARP entries come and go while the two
        // captures are taken. A few percent of drift is the table living its life;
        // a systematic decoding error is not a few percent.
        func semantic(_ record: RouteRecord) -> String {
            "\(record.prefix)|\(record.zone ?? "-")|\(record.interfaceName)"
                + "|\(record.isScoped)|\(record.hasRealGateway)"
        }
        let ours = Set(binary.routes.map(semantic))
        let theirs = Set(text.routes.map(semantic))
        let drift = ours.symmetricDifference(theirs).count
        let tolerance = max(4, theirs.count / 20)
        #expect(drift <= tolerance, """
            \(drift) of \(theirs.count) records differ (tolerance \(tolerance))
              only binary: \(ours.subtracting(theirs).sorted().prefix(10))
              only text:   \(theirs.subtracting(ours).sorted().prefix(10))
            """)

        // The flag letters are a transcription of netstat's own bit→letter table,
        // so for routes both snapshots agree exist, the strings must be identical.
        // This is what pins RTF_IFSCOPE → 'I' (and not, say, RTF_IFREF → 'i').
        // Compared as a SET of flag strings per key, because a routing table
        // legitimately holds several rows that agree on everything else: a cloning
        // route and the clone it produced differ ONLY in their flags
        // ("fd7a:115c:a1e0::53/128 link#20 UCS utun1" alongside
        // "fd7a:115c:a1e0::53 link#20 UHWIi utun1"). Same churn tolerance: a clone
        // can expire between the two captures.
        func flagKey(_ record: RouteRecord) -> String {
            "\(record.prefix)|\(record.zone ?? "-")|\(record.interfaceName)|\(record.gateway)"
        }
        func flagSets(_ snapshot: RouteTableSnapshot) -> [String: Set<String>] {
            var sets: [String: Set<String>] = [:]
            for record in snapshot.routes { sets[flagKey(record), default: []].insert(record.flags) }
            return sets
        }
        let ourFlags = flagSets(binary), theirFlags = flagSets(text)
        let flagMismatches = theirFlags.compactMap { key, expected -> String? in
            guard let mine = ourFlags[key], mine != expected else { return nil }
            return "\(key): binary=\(mine.sorted()) netstat=\(expected.sorted())"
        }
        #expect(flagMismatches.count <= max(2, theirFlags.count / 50),
                "flag letters differ: \(flagMismatches.prefix(10))")

        // And the answers — the only thing any caller ever sees.
        var addresses = ["1.1.1.1", "8.8.8.8", "100.64.0.1", "2606:4700:4700::1111", "::1"]
        addresses += binary.routes.shuffled().prefix(20).map(\.prefix.addressText)
        for address in addresses {
            let fromBinary = RouteResolver(snapshot: binary).resolve(address)?.interfaceName
            let fromText = RouteResolver(snapshot: text).resolve(address)?.interfaceName
            #expect(fromBinary == fromText,
                    "\(address): binary=\(fromBinary ?? "nil") text=\(fromText ?? "nil")")
        }
    }

    @Test("The ARP table matches what arp(8) reports")
    func arpTableMatchesArpCommand() throws {
        let entries = try RouteTableSource.arpTable()
        let text = Self.run("/usr/sbin/arp", ["-an"]) ?? ""

        for entry in entries {
            #expect(!entry.mac.isEmpty)
            #expect(entry.mac.split(separator: ":").count == 6, "\(entry.ip) → \(entry.mac)")
            #expect(!entry.interface.isEmpty, "\(entry.ip) has no interface")
            #expect(IPPrefix.parseAddress(entry.ip) != nil, "\(entry.ip) is not an address")
        }

        // `arp -an` renders "? (10.0.0.4) at a0:99:9b:18:dc:93 on en0 …" — the same
        // unpadded hex NetworkMemory expects, so an entry we found must be in there
        // verbatim (modulo the cache moving under us).
        guard !text.isEmpty, !entries.isEmpty else { return }
        let missing = entries.filter { !text.contains("(\($0.ip)) at \($0.mac) on \($0.interface)") }
        #expect(missing.count <= max(2, entries.count / 20),
                "entries arp(8) does not corroborate: \(missing.prefix(5).map(\.ip))")
        // Incomplete entries are deliberately dropped, so we should never have MORE
        // than arp prints.
        let complete = text.split(separator: "\n").filter { !$0.contains("incomplete") }.count
        #expect(entries.count <= complete + 4, "\(entries.count) entries vs \(complete) from arp")
    }

    // MARK: - 3. Decoder unit tests over hand-built bytes

    @Test("A truncated netmask sockaddr still yields the right prefix length")
    func truncatedNetmask() throws {
        // 255.255.248.0 arrives as sa_len 7: the kernel stores bytes up to the last
        // significant one and nothing after it. The missing 4th byte is zero.
        let message = Fixture.routeMessage(
            flags: RTF_UP | RTF_STATIC,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("10.0.0.0")),
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: Fixture.loopbackIndex)),
                (RTAX_NETMASK, Fixture.sockaddrIn("255.255.248.0", length: 7, family: 0)),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].prefix.description == "10.0.0.0/21")
        #expect(records[0].destination == "10.0.0.0/21")
        #expect(records[0].interfaceName == "lo0")
        #expect(records[0].gateway == "link#\(Fixture.loopbackIndex)")
    }

    @Test("A netmask truncated to nothing is a default route")
    func maskTruncatedToZeroBytes() throws {
        // sa_len 4 = header only, no mask bytes at all → /0. This is how the kernel
        // spells the netmask of a default route when it bothers to send one.
        let message = Fixture.routeMessage(
            flags: RTF_UP | RTF_GATEWAY | RTF_STATIC,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("0.0.0.0")),
                (RTAX_GATEWAY, Fixture.sockaddrIn("10.0.7.254")),
                (RTAX_NETMASK, Fixture.sockaddrIn("0.0.0.0", length: 4, family: 0)),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].prefix.isDefault)
        #expect(records[0].destination == "default")
        #expect(records[0].gateway == "10.0.7.254")
        #expect(records[0].hasRealGateway)
    }

    @Test("A sa_len == 0 sockaddr is a placeholder that still consumes four bytes")
    func zeroLengthSockaddrPlaceholder() throws {
        // The gateway slot is present in rtm_addrs but empty. Advancing by 0 would
        // spin; advancing by sizeof(sockaddr) would eat the netmask. Only ROUNDUP(0)
        // == 4 lands on the netmask, so the prefix length is the proof.
        let message = Fixture.routeMessage(
            flags: RTF_UP,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("192.168.4.0")),
                (RTAX_GATEWAY, [0]),                       // sa_len 0 placeholder
                (RTAX_NETMASK, Fixture.sockaddrIn("255.255.255.0", length: 7, family: 0)),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].prefix.description == "192.168.4.0/24")
        #expect(records[0].gateway == "")
        #expect(!records[0].hasRealGateway)
    }

    @Test("Sockaddrs are padded up to four-byte boundaries, not to their struct size")
    func alignmentPadding() throws {
        // Three consecutive odd-length sockaddrs (7, 7, 11 bytes). Every one of them
        // has to be rounded up to 8, 8, 12 for the NEXT one to be found — reading
        // the interface name out of the trailing sockaddr_dl proves the whole walk.
        let message = Fixture.routeMessage(
            flags: RTF_UP,
            interfaceIndex: 0,                              // force the name to come from RTA_IFP
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("172.16.0.0", length: 7)),
                (RTAX_NETMASK, Fixture.sockaddrIn("255.240.0.0", length: 7, family: 0)),
                (RTAX_IFP, Fixture.sockaddrDL(index: 42, name: "utun9")),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].prefix.description == "172.16.0.0/12")
        #expect(records[0].interfaceName == "utun9")
    }

    @Test("A sockaddr_dl gateway is a MAC when it carries one and link#N when it does not")
    func linkLayerGateways() throws {
        let onLink = Fixture.routeMessage(
            flags: RTF_UP | RTF_CLONING | RTF_STATIC,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("10.0.0.0")),
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: 16)),
                (RTAX_NETMASK, Fixture.sockaddrIn("255.255.248.0", length: 7, family: 0)),
            ])
        let arpClone = Fixture.routeMessage(
            flags: RTF_UP | RTF_HOST | RTF_LLINFO | RTF_WASCLONED | RTF_IFSCOPE,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("10.0.0.13")),
                // Leading zeroes are NOT padded: netstat spells this "a:e6:33:6c:f0:52".
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: 16, mac: [0x0a, 0xe6, 0x33, 0x6c, 0xf0, 0x52])),
            ])
        let records = RouteTableSource.decodeRouteDump(onLink + arpClone)

        try #require(records.count == 2)
        #expect(records[0].gateway == "link#16")
        #expect(records[0].gatewayIsLink)
        #expect(!records[0].hasRealGateway)

        #expect(records[1].gateway == "a:e6:33:6c:f0:52")
        #expect(!records[1].hasRealGateway, "a MAC is not a next-hop address")
        #expect(records[1].prefix.description == "10.0.0.13/32", "RTF_HOST means a host route")
        #expect(records[1].destination == "10.0.0.13")
        #expect(records[1].isScoped)
        #expect(records[1].order == 1, "table order is the kernel's own tie-break")
    }

    @Test("An IPv6 scope id embedded in the address becomes a zone, not part of the network")
    func ipv6EmbeddedScopeID() throws {
        // KAME writes the interface index into the second 16-bit group of a
        // link-local address and leaves sin6_scope_id at 0. Left in place it makes
        // fe80::1%lo0 look like the network fe80:1:: — a different route entirely.
        let message = Fixture.routeMessage(
            flags: RTF_UP | RTF_HOST | RTF_LLINFO,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn6("fe80::1", embeddedScopeID: Fixture.loopbackIndex)),
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: Fixture.loopbackIndex)),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].zone == "lo0")
        #expect(records[0].prefix.addressText == "fe80::1")
        #expect(records[0].destination == "fe80::1%lo0")
    }

    @Test("An explicit sin6_scope_id is honoured, and a truncated IPv6 mask still measures")
    func ipv6ScopeIDFieldAndTruncatedMask() throws {
        let message = Fixture.routeMessage(
            flags: RTF_UP | RTF_CLONING,
            interfaceIndex: 0,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn6("fe80::", scopeID: UInt32(Fixture.loopbackIndex))),
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: Fixture.loopbackIndex)),
                // /64 = 8 significant bytes → sa_len 16, half the struct's 28.
                (RTAX_NETMASK, Fixture.sockaddrIn6("ffff:ffff:ffff:ffff::", length: 16, family: 0)),
                (RTAX_IFP, Fixture.sockaddrDL(index: Fixture.loopbackIndex, name: "lo0")),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].prefix.description == "fe80::/64")
        #expect(records[0].zone == "lo0")
        #expect(records[0].destination == "fe80::%lo0/64")
        #expect(records[0].interfaceName == "lo0")
    }

    @Test("A non-global IPv6 address without any scope keeps its bytes")
    func ipv6GlobalAddressIsUntouched() throws {
        let message = Fixture.routeMessage(
            flags: RTF_UP | RTF_GATEWAY | RTF_STATIC,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn6("2606:4700:4700::1111")),
                (RTAX_GATEWAY, Fixture.sockaddrIn6("fe80::1", embeddedScopeID: Fixture.loopbackIndex)),
                (RTAX_NETMASK, Fixture.sockaddrIn6("ffff:ffff:ffff::", length: 14, family: 0)),
            ])
        let records = RouteTableSource.decodeRouteDump(message)

        try #require(records.count == 1)
        #expect(records[0].zone == nil)
        #expect(records[0].prefix.description == "2606:4700:4700::/48")
        // The gateway's zone is rendered the way the text path spells it.
        #expect(records[0].gateway == "fe80::1%lo0")
        #expect(records[0].hasRealGateway)
    }

    @Test("Routes cloned from a protocol-cloning parent are hidden, ARP clones are not")
    func protocolClonesAreExcluded() throws {
        // A per-flow clone of the default route. netstat's table view hides these
        // and so must we: the kernel does not consult them for new lookups, so
        // keeping them pins traffic to whatever interface was primary at the time.
        let flowClone = Fixture.routeMessage(
            flags: RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_WASCLONED | RTF_IFSCOPE,
            parentFlags: RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_PRCLONING,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("140.82.114.26")),
                (RTAX_GATEWAY, Fixture.sockaddrIn("10.0.7.254")),
            ])
        let arpClone = Fixture.routeMessage(
            flags: RTF_UP | RTF_HOST | RTF_LLINFO | RTF_WASCLONED | RTF_IFSCOPE,
            parentFlags: RTF_UP | RTF_CLONING | RTF_STATIC,      // 'C', not 'c'
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [
                (RTAX_DST, Fixture.sockaddrIn("10.0.0.13")),
                (RTAX_GATEWAY, Fixture.sockaddrDL(index: 16, mac: [0x0a, 0xe6, 0x33, 0x6c, 0xf0, 0x52])),
            ])
        let records = RouteTableSource.decodeRouteDump(flowClone + arpClone)

        try #require(records.count == 1)
        #expect(records[0].prefix.description == "10.0.0.13/32")
        #expect(records[0].order == 0, "hidden records must not leave a hole in the ordering")

        #expect(RouteTableSource.isProtocolClone(flags: RTF_WASCLONED, parentFlags: RTF_PRCLONING))
        #expect(!RouteTableSource.isProtocolClone(flags: RTF_WASCLONED, parentFlags: RTF_CLONING))
        #expect(!RouteTableSource.isProtocolClone(flags: RTF_UP, parentFlags: RTF_PRCLONING))
    }

    @Test("Flag letters come out in netstat's order and spelling")
    func flagLetterTable() {
        // Straight out of live tables: a scoped default with a gateway, an ARP
        // clone, a cloning default, a multicast row.
        #expect(RouteTableSource.flagLetters(
            RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_PRCLONING | RTF_IFSCOPE | RTF_GLOBAL) == "UGScIg")
        #expect(RouteTableSource.flagLetters(
            RTF_UP | RTF_HOST | RTF_LLINFO | RTF_WASCLONED | RTF_IFSCOPE | RTF_IFREF) == "UHLWIi")
        #expect(RouteTableSource.flagLetters(
            RTF_UP | RTF_CLONING | RTF_STATIC | RTF_IFSCOPE | RTF_GLOBAL) == "UCSIg")
        #expect(RouteTableSource.flagLetters(
            RTF_UP | RTF_MULTICAST | RTF_CLONING | RTF_STATIC | RTF_IFSCOPE) == "UmCSI")
        #expect(RouteTableSource.flagLetters(RTF_UP | RTF_REJECT | RTF_STATIC) == "URS")
        #expect(RouteTableSource.flagLetters(RTF_UP | RTF_BLACKHOLE) == "UB")

        // The letters RouteResolver reads meaning out of, spelled unambiguously.
        #expect(RouteTableSource.flagLetters(RTF_IFSCOPE) == "I")
        #expect(RouteTableSource.flagLetters(RTF_IFREF) == "i", "IFREF is not scoping")
        #expect(RouteTableSource.flagLetters(0) == "")
    }

    @Test("Prefix length is counted from the mask, non-contiguous masks included")
    func maskLengths() {
        #expect(RouteTableSource.maskLength([255, 255, 255, 255], family: .v4) == 32)
        #expect(RouteTableSource.maskLength([255, 255, 248, 0], family: .v4) == 21)
        #expect(RouteTableSource.maskLength([255, 0, 0, 0], family: .v4) == 8)
        #expect(RouteTableSource.maskLength([0, 0, 0, 0], family: .v4) == 0)
        #expect(RouteTableSource.maskLength([254, 0, 0, 0], family: .v4) == 7)
        // Non-contiguous: not a prefix at all. Best-effort = how many bits it pins.
        #expect(RouteTableSource.maskLength([255, 0, 255, 0], family: .v4) == 16)
        #expect(RouteTableSource.maskLength([255, 253, 0, 0], family: .v4) == 15)
        #expect(RouteTableSource.maskLength(
            [255, 255, 255, 255, 255, 255, 255, 255] + [UInt8](repeating: 0, count: 8),
            family: .v6) == 64)
    }

    @Test("ROUNDUP matches the BSD macro, including the zero case")
    func roundUpMatchesBSD() {
        #expect(RouteTableSource.roundUp(0) == 4)       // the placeholder case
        #expect(RouteTableSource.roundUp(1) == 4)
        #expect(RouteTableSource.roundUp(4) == 4)
        #expect(RouteTableSource.roundUp(5) == 8)
        #expect(RouteTableSource.roundUp(7) == 8)
        #expect(RouteTableSource.roundUp(16) == 16)
        #expect(RouteTableSource.roundUp(28) == 28)
    }

    @Test("A malformed or truncated buffer stops the walk instead of running off it")
    func malformedBuffersAreSurvivable() {
        #expect(RouteTableSource.decodeRouteDump([]).isEmpty)
        #expect(RouteTableSource.decodeRouteDump([0, 0]).isEmpty)
        #expect(RouteTableSource.decodeRouteDump([UInt8](repeating: 0, count: 200)).isEmpty)

        // A well-formed message whose sa_len claims more than the record holds: the
        // sockaddr is clamped, not read past.
        var message = Fixture.routeMessage(
            flags: RTF_UP,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [(RTAX_DST, Fixture.sockaddrIn("10.1.2.3"))])
        message[message.count - 16] = 200                // stomp the dst sa_len
        #expect(RouteTableSource.decodeRouteDump(message).count <= 1)

        // A truncated tail (the last message cut in half) yields the whole records
        // and drops the fragment.
        let whole = Fixture.routeMessage(
            flags: RTF_UP | RTF_HOST,
            interfaceIndex: Fixture.loopbackIndex,
            addresses: [(RTAX_DST, Fixture.sockaddrIn("10.1.2.3"))])
        #expect(RouteTableSource.decodeRouteDump(whole + whole.prefix(20)).count == 1)
    }

    @Test("The ARP decoder reads plain rt_msghdr records and drops incomplete ones")
    func arpDecoderOverFixture() throws {
        let complete = Fixture.arpMessage(
            interfaceIndex: Fixture.loopbackIndex,
            ip: "10.0.0.13",
            link: Fixture.sockaddrDL(index: Fixture.loopbackIndex, name: "lo0",
                                     mac: [0x0a, 0xe6, 0x33, 0x6c, 0xf0, 0x52]))
        let incomplete = Fixture.arpMessage(
            interfaceIndex: Fixture.loopbackIndex,
            ip: "10.0.0.99",
            link: Fixture.sockaddrDL(index: Fixture.loopbackIndex, name: "lo0"))
        let entries = RouteTableSource.decodeARPTable(complete + incomplete)

        try #require(entries.count == 1)
        #expect(entries[0].ip == "10.0.0.13")
        #expect(entries[0].mac == "a:e6:33:6c:f0:52")
        #expect(entries[0].interface == "lo0")
    }

    // MARK: - 4. The change listener

    @Test("The listener starts and stops cleanly, repeatedly")
    func listenerLifecycle() throws {
        let listener = RouteChangeListener { }
        #expect(!listener.isRunning)

        try listener.start()
        #expect(listener.isRunning)
        try listener.start()                    // idempotent
        #expect(listener.isRunning)

        listener.stop()
        #expect(!listener.isRunning)
        listener.stop()                         // idempotent
        #expect(!listener.isRunning)

        // A second life on the same object must work — the socket is opened per start.
        try listener.start()
        #expect(listener.isRunning)
        listener.stop()
        #expect(!listener.isRunning)
    }

    @Test("A listener that is dropped while running tears itself down")
    func listenerDeinitWhileRunning() throws {
        // No retain cycle: the dispatch source holds a weak reference, so letting go
        // of the last strong one really does deinit (and close the socket).
        for _ in 0..<5 {
            let listener = RouteChangeListener { }
            try listener.start()
            #expect(listener.isRunning)
        }
        // If descriptors leaked, opening more sockets would eventually fail.
        let probe = RouteChangeListener { }
        try probe.start()
        #expect(probe.isRunning)
        probe.stop()
    }

    @Test("Only add/delete/change messages count as a table change")
    func listenerMessageFiltering() {
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_ADD), length: 24))
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_DELETE), length: 24))
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_CHANGE), length: 24))
        // Noise the table does not move for.
        #expect(!RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_GET), length: 24))
        #expect(!RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_IFINFO), length: 24))
        #expect(!RouteChangeListener.mentionsRouteChange([], length: 0))
        // Short read: the type still arrived, so the change is still noticed, and a
        // length that runs past what was read must not be trusted.
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_ADD), length: 4))
        // A second message whose HEADER arrived but whose body did not still counts:
        // the type is the only field being read, so there is nothing to be unsure
        // about — and missing a real RTM_ADD would leave a stale table on screen.
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_GET) + Fixture.routeSocketMessage(type: RTM_ADD),
            length: 30))
        // …but a length that runs past what was read is never trusted to step over.
        #expect(!RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_GET) + Fixture.routeSocketMessage(type: RTM_ADD),
            length: 26))
        // Two whole messages back to back: the second one is reached.
        #expect(RouteChangeListener.mentionsRouteChange(
            Fixture.routeSocketMessage(type: RTM_GET) + Fixture.routeSocketMessage(type: RTM_ADD),
            length: 48))
    }

    // MARK: - Oracles (subprocesses are allowed HERE and nowhere else)

    /// The system's own answer: `route -n get` writes to a routing socket and
    /// prints the route the kernel would actually use.
    static func kernelInterface(for address: String) -> String? {
        let arguments = address.contains(":")
            ? ["-n", "get", "-inet6", address] : ["-n", "get", address]
        guard let output = run("/sbin/route", arguments) else { return nil }
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("interface:") else { continue }
            return trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
        }
        return nil     // "not in table" — nothing to compare against
    }

    /// A HOST address inside a prefix, for probing.
    ///
    /// The network's base address is the wrong thing to ask about: the kernel will
    /// not clone an on-link cloning route for the network address itself, so
    /// `route -n get 10.0.0.0` falls through to the default route (utun8 here) while
    /// `route -n get 10.0.0.1` answers en0. That is a kernel quirk about base
    /// addresses, not a statement about the table, and both snapshots say en0.
    static func probeAddress(inside prefix: IPPrefix) -> String {
        guard !prefix.isHost else { return prefix.addressText }
        var bytes = prefix.bytes
        bytes[bytes.count - 1] |= 1                 // the lowest bit is a host bit here
        guard let host = IPPrefix(
            family: prefix.family, bytes: bytes, prefixLength: prefix.family.bitWidth)
        else { return prefix.addressText }
        return host.addressText
    }

    /// Every address this machine holds — in-process, no subprocess needed.
    static func localAddresses() -> Set<String> {
        var addresses: Set<String> = ["127.0.0.1", "::1"]
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return addresses }
        defer { freeifaddrs(head) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let sa = pointer.pointee.ifa_addr else { continue }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                var address = sockaddr_in()
                memcpy(&address, sa, MemoryLayout<sockaddr_in>.size)
                inet_ntop(AF_INET, &address.sin_addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
            case AF_INET6:
                var address = sockaddr_in6()
                memcpy(&address, sa, MemoryLayout<sockaddr_in6>.size)
                inet_ntop(AF_INET6, &address.sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
            default:
                continue
            }
            let text = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                              as: UTF8.self)
            if !text.isEmpty { addresses.insert(text) }
        }
        return addresses
    }

    static func run(_ path: String, _ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        guard (try? process.run()) != nil else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}

// MARK: - Byte-level fixtures

/// Builds routing messages the way the kernel lays them out: a fixed header, then
/// a packed array of sockaddrs in RTAX order, each padded up to four bytes. Every
/// length here is deliberately spelled out rather than taken from a struct — the
/// point is to reproduce the wire format, including its awkward parts.
enum Fixture {

    static let loopbackIndex = UInt16(if_nametoindex("lo0"))

    /// `rt_msghdr2` + sockaddrs — a NET_RT_DUMP2 record.
    static func routeMessage(
        flags: Int32, parentFlags: Int32 = 0, interfaceIndex: UInt16,
        addresses: [(Int32, [UInt8])]
    ) -> [UInt8] {
        var header = rt_msghdr2()
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET2)
        header.rtm_index = interfaceIndex
        header.rtm_flags = flags
        header.rtm_parentflags = parentFlags
        header.rtm_addrs = addresses.reduce(0) { $0 | (1 << $1.0) }
        var bytes = withUnsafeBytes(of: &header) { [UInt8]($0) }
        bytes += packed(addresses)
        return stampLength(bytes)
    }

    /// `rt_msghdr` + sockaddrs — a NET_RT_FLAGS/RTF_LLINFO record, which uses the
    /// SMALLER header. Getting this wrong shifts every ARP entry by 16 bytes.
    static func arpMessage(interfaceIndex: UInt16, ip: String, link: [UInt8]) -> [UInt8] {
        var header = rt_msghdr()
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_index = interfaceIndex
        header.rtm_flags = RTF_UP | RTF_HOST | RTF_LLINFO | RTF_WASCLONED
        header.rtm_addrs = (1 << RTAX_DST) | (1 << RTAX_GATEWAY)
        var bytes = withUnsafeBytes(of: &header) { [UInt8]($0) }
        bytes += packed([(RTAX_DST, sockaddrIn(ip)), (RTAX_GATEWAY, link)])
        return stampLength(bytes)
    }

    /// A bare routing-socket message: only the first four bytes matter to the
    /// listener, but it is padded to a plausible size so the walk has to skip it.
    static func routeSocketMessage(type: Int32, length: Int = 24) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: length)
        bytes[0] = UInt8(length & 0xFF)
        bytes[1] = UInt8((length >> 8) & 0xFF)
        bytes[2] = UInt8(RTM_VERSION)
        bytes[3] = UInt8(type)
        return bytes
    }

    /// Sockaddrs in ascending RTAX order, each padded to a 4-byte boundary.
    private static func packed(_ addresses: [(Int32, [UInt8])]) -> [UInt8] {
        var bytes: [UInt8] = []
        for (_, sockaddr) in addresses.sorted(by: { $0.0 < $1.0 }) {
            let declared = Int(sockaddr.first ?? 0)
            let padded = declared > 0 ? ((declared - 1) | 3) + 1 : 4
            bytes += sockaddr
            bytes += [UInt8](repeating: 0, count: max(0, padded - sockaddr.count))
        }
        return bytes
    }

    /// rtm_msglen is the first field of every routing message, host byte order.
    private static func stampLength(_ bytes: [UInt8]) -> [UInt8] {
        var bytes = bytes
        bytes[0] = UInt8(bytes.count & 0xFF)
        bytes[1] = UInt8((bytes.count >> 8) & 0xFF)
        return bytes
    }

    /// `sockaddr_in`: len(1) family(1) port(2) addr(4) zero(8).
    /// `length` truncates it the way the kernel truncates a netmask.
    static func sockaddrIn(_ text: String, length: Int? = nil, family: Int32 = AF_INET) -> [UInt8] {
        var address = in_addr()
        _ = inet_pton(AF_INET, text, &address)
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[0] = UInt8(length ?? 16)
        bytes[1] = UInt8(family)
        let raw = withUnsafeBytes(of: &address) { [UInt8]($0) }
        for i in 0..<4 { bytes[4 + i] = raw[i] }
        if let length { bytes = Array(bytes.prefix(length)) }
        return bytes
    }

    /// `sockaddr_in6`: len(1) family(1) port(2) flowinfo(4) addr(16) scope_id(4).
    /// `embeddedScopeID` writes the index into the address bytes the way KAME does.
    static func sockaddrIn6(
        _ text: String, scopeID: UInt32 = 0, embeddedScopeID: UInt16 = 0,
        length: Int? = nil, family: Int32 = AF_INET6
    ) -> [UInt8] {
        var address = in6_addr()
        _ = inet_pton(AF_INET6, text, &address)
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = UInt8(length ?? 28)
        bytes[1] = UInt8(family)
        let raw = withUnsafeBytes(of: &address) { [UInt8]($0) }
        for i in 0..<16 { bytes[8 + i] = raw[i] }
        if embeddedScopeID != 0 {
            bytes[10] = UInt8(embeddedScopeID >> 8)     // network order, in the address
            bytes[11] = UInt8(embeddedScopeID & 0xFF)
        }
        bytes[24] = UInt8(scopeID & 0xFF)
        bytes[25] = UInt8((scopeID >> 8) & 0xFF)
        bytes[26] = UInt8((scopeID >> 16) & 0xFF)
        bytes[27] = UInt8((scopeID >> 24) & 0xFF)
        if let length { bytes = Array(bytes.prefix(length)) }
        return bytes
    }

    /// `sockaddr_dl`: len(1) family(1) index(2) type(1) nlen(1) alen(1) slen(1)
    /// then the name followed by the link-layer address.
    static func sockaddrDL(index: UInt16, name: String = "", mac: [UInt8] = []) -> [UInt8] {
        let nameBytes = Array(name.utf8)
        var bytes: [UInt8] = [0, UInt8(AF_LINK),
                              UInt8(index & 0xFF), UInt8(index >> 8),
                              UInt8(IFT_ETHER), UInt8(nameBytes.count), UInt8(mac.count), 0]
        bytes += nameBytes
        bytes += mac
        bytes[0] = UInt8(bytes.count)
        return bytes
    }
}
