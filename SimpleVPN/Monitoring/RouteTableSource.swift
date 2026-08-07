// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteTableSource.swift
//  The routing table, read from the kernel as BINARY — no `netstat`, no text, no
//  subprocess. `sysctl(CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP2, 0)` hands back
//  the same `rt_msghdr2` records netstat itself renders, so this is the producer
//  netstat was standing in for: it builds `RouteRecord`/`IPPrefix` values (the
//  semantic layer `RouteResolver` reasons over) straight from the kernel's bytes,
//  with nothing in between to mis-parse.
//
//  Three things live here, all nonisolated and free of process spawning:
//    • `snapshot()`        — the whole table (both families), as a `RouteTableSnapshot`;
//    • `arpTable()`        — the ARP cache (NET_RT_FLAGS/RTF_LLINFO), sharing the
//                            same sockaddr walker, so `arp -n` can go away too;
//    • `RouteChangeListener` — a PF_ROUTE socket that says "the table moved" (it
//                            deliberately does NOT try to maintain the table
//                            incrementally; the callback triggers a fresh dump).
//
//  ── The classic sockaddr-array quirks, all of which bite ──────────────────────
//
//  A routing message is a fixed header followed by a PACKED ARRAY of sockaddrs,
//  present-only, in RTAX_* order, selected by the `rtm_addrs` bitmask. Walking it
//  wrong silently shifts every subsequent field by a few bytes, which is exactly
//  the class of bug that makes people go back to parsing text. The rules:
//
//  1. ALIGNMENT. Each sockaddr is padded up to a 4-byte (`uint32_t`) boundary —
//     the BSD `ROUNDUP` macro. Darwin is 4, not 8, even on arm64.
//  2. `sa_len == 0` IS A PLACEHOLDER. It occupies one 4-byte slot and carries no
//     data (`ROUNDUP(0) == sizeof(uint32_t)`). Advancing by 0 loops forever;
//     advancing by `sizeof(sockaddr)` walks off the record.
//  3. NETMASK SOCKADDRS ARE TRUNCATED. The kernel only stores up to the last
//     significant byte: 255.255.248.0 arrives as `sa_len == 7` (4 header-ish
//     bytes + 3 mask bytes), and a /48 IPv6 mask as `sa_len == 14`. The missing
//     trailing bytes are ZERO. A mask sockaddr's `sa_family` is not to be
//     trusted either — masks are read with the DESTINATION's family.
//  4. THE GATEWAY IS OFTEN NOT AN ADDRESS. It can be a `sockaddr_dl`: with a
//     link-layer address (an ARP/ND entry → "a0:99:9b:18:dc:93") or without
//     (an on-link route → "link#16"). Only AF_INET/AF_INET6 gateways are real
//     next hops, which is precisely what `RouteRecord.hasRealGateway` keys on.
//  5. IPv6 SCOPE IS SMUGGLED INTO THE ADDRESS. For link-local and link/interface
//     -local multicast, KAME stuffs the interface index into the SECOND 16-bit
//     group of the address bytes when `sin6_scope_id` is 0. It must be cleared
//     out of the address and surfaced as the zone ("fe80::1%lo0"), or every
//     link-local looks like a different network.
//
//  ── Flags ────────────────────────────────────────────────────────────────────
//
//  `RouteRecord.flags` is a netstat-style letter string because that is the
//  contract `RouteResolver` already reads (`I` = RTF_IFSCOPE, `G` = RTF_GATEWAY,
//  `R`/`B` = reject, `H` = host, `W` = was-cloned). The bit→letter table below is
//  a transcription of the `bits[]` table in Darwin's netstat (network_cmds,
//  netstat/route.c), IN ITS ORDER — netstat emits letters in table order, so
//  "UGScIg" comes out identical to the text path it replaces.
//

import Foundation
import Darwin

// MARK: - Errors

nonisolated enum RouteTableError: Error, Sendable, CustomStringConvertible {
    /// `sysctl` refused the routing dump.
    case sysctlFailed(code: Int32)
    /// The PF_ROUTE socket could not be opened.
    case socketFailed(code: Int32)

    var description: String {
        switch self {
        case .sysctlFailed(let code): "routing sysctl failed: \(String(cString: strerror(code))) (\(code))"
        case .socketFailed(let code): "PF_ROUTE socket failed: \(String(cString: strerror(code))) (\(code))"
        }
    }
}

// MARK: - Source

nonisolated enum RouteTableSource {

    /// One ARP cache entry. `NetworkMemory` wants exactly this and nothing more:
    /// the gateway's MAC is the strong half of the network fingerprint.
    typealias ARPEntry = (ip: String, mac: MACAddress, interface: String)

    // MARK: Snapshots

    /// The whole routing table, both families, in kernel order.
    ///
    /// IPv4 is dumped first and IPv6 second — the same order the text path built
    /// its snapshot in — because `RouteRecord.order` is the kernel's own
    /// tie-break for equal prefixes and `RouteResolver` leans on it.
    static func snapshot() throws -> RouteTableSnapshot {
        var routes = try records(family: AF_INET, startingOrder: 0)
        routes += try records(family: AF_INET6, startingOrder: routes.count)
        return RouteTableSnapshot(routes: routes)
    }

    /// One family's routes.
    static func snapshot(family: IPFamily) throws -> RouteTableSnapshot {
        RouteTableSnapshot(
            routes: try records(family: family == .v4 ? AF_INET : AF_INET6, startingOrder: 0))
    }

    /// The ARP cache, in-process — the replacement for `arp -n`.
    ///
    /// Note the different sysctl verb: NET_RT_FLAGS returns plain `rt_msghdr`
    /// records (NOT `rt_msghdr2`), which is why the walker is parameterised by
    /// header size. Incomplete entries (no link-layer address yet) are omitted:
    /// `arp` prints them as "(incomplete)" and no caller wants that as a MAC.
    static func arpTable() throws -> [ARPEntry] {
        let buffer = try dump(mib: [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO])
        return decodeARPTable(buffer)
    }

    /// `AF_INET`/`AF_INET6`/0 (both) → records, numbered from `startingOrder`.
    static func records(family: Int32, startingOrder: Int) throws -> [RouteRecord] {
        let buffer = try dump(mib: [CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP2, 0])
        return decodeRouteDump(buffer, startingOrder: startingOrder)
    }

    // MARK: sysctl plumbing

    /// Size-then-fetch, with slack and a retry: the table can grow between the
    /// two calls, and the kernel answers that with ENOMEM rather than a partial
    /// dump.
    static func dump(mib: [Int32]) throws -> [UInt8] {
        var mib = mib
        let count = u_int(mib.count)
        for _ in 0..<4 {
            var needed = 0
            guard sysctl(&mib, count, nil, &needed, nil, 0) == 0 else {
                throw RouteTableError.sysctlFailed(code: errno)
            }
            guard needed > 0 else { return [] }
            var buffer = [UInt8](repeating: 0, count: needed + needed / 8 + 4_096)
            var size = buffer.count
            var code: Int32 = 0
            let ok = buffer.withUnsafeMutableBytes { raw -> Bool in
                if sysctl(&mib, count, raw.baseAddress, &size, nil, 0) == 0 { return true }
                code = errno
                return false
            }
            if ok {
                buffer.removeLast(buffer.count - size)
                return buffer
            }
            guard code == ENOMEM else { throw RouteTableError.sysctlFailed(code: code) }
        }
        throw RouteTableError.sysctlFailed(code: ENOMEM)
    }

    // MARK: - Decoding (pure — the tests drive these with hand-built fixtures)

    /// One sockaddr as it actually arrived: its family and its bytes, which may be
    /// SHORTER than the family's struct (quirk 3). Everything downstream reads
    /// through `byte(_:)`, which reports zero past the end, so truncation needs no
    /// special-casing anywhere else.
    struct RawSockaddr: Sendable {
        let family: UInt8
        let bytes: [UInt8]

        /// Byte at `index`, or 0 when the sockaddr was truncated before it.
        func byte(_ index: Int) -> UInt8 { index < bytes.count ? bytes[index] : 0 }

        /// `count` bytes from `offset`, zero-filled past the truncation point.
        func slice(_ offset: Int, _ count: Int) -> [UInt8] {
            (0..<count).map { byte(offset + $0) }
        }

        var isEmpty: Bool { bytes.isEmpty }
    }

    /// BSD `ROUNDUP`: `(a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t)`.
    /// The zero case is quirk 2 — an absent sockaddr still eats a 4-byte slot.
    static func roundUp(_ length: Int) -> Int {
        let alignment = MemoryLayout<UInt32>.size          // 4 on Darwin, even on arm64
        return length > 0 ? ((length - 1) | (alignment - 1)) + 1 : alignment
    }

    /// Walk the packed sockaddr array, returning RTAX index → sockaddr.
    static func sockaddrs(
        in raw: UnsafeRawBufferPointer, from start: Int, to end: Int, mask: Int32
    ) -> [Int: RawSockaddr] {
        var found: [Int: RawSockaddr] = [:]
        var cursor = start
        for index in 0..<Int(RTAX_MAX) {
            guard mask & (1 << Int32(index)) != 0 else { continue }
            guard cursor < end else { break }
            let declared = Int(raw[cursor])
            // Clamp to the record: a malformed sa_len must not read a neighbour's bytes.
            let present = max(0, min(declared, end - cursor))
            let family = present >= 2 ? raw[cursor + 1] : 0
            let bytes = (0..<present).map { raw[cursor + $0] }
            found[index] = RawSockaddr(family: declared == 0 ? 0 : family, bytes: bytes)
            cursor += roundUp(declared)
        }
        return found
    }

    /// Decode a NET_RT_DUMP2 buffer into records.
    static func decodeRouteDump(_ buffer: [UInt8], startingOrder: Int = 0) -> [RouteRecord] {
        var records: [RouteRecord] = []
        var order = startingOrder
        let headerSize = MemoryLayout<rt_msghdr2>.stride

        buffer.withUnsafeBytes { raw in
            var offset = 0
            while offset + MemoryLayout<UInt16>.size <= raw.count {
                // rtm_msglen is the FIRST field of every routing message, host order.
                let messageLength = Int(raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                guard messageLength >= headerSize, offset + messageLength <= raw.count else { break }
                let header = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr2.self)
                defer { offset += messageLength }
                guard !isProtocolClone(flags: header.rtm_flags, parentFlags: header.rtm_parentflags)
                else { continue }
                let addresses = sockaddrs(
                    in: raw, from: offset + headerSize, to: offset + messageLength,
                    mask: header.rtm_addrs)
                if let record = makeRecord(
                    flags: header.rtm_flags, interfaceIndex: header.rtm_index,
                    addresses: addresses, order: order) {
                    records.append(record)
                    order += 1
                }
            }
        }
        return records
    }

    /// Decode a NET_RT_FLAGS/RTF_LLINFO buffer (plain `rt_msghdr` headers).
    static func decodeARPTable(_ buffer: [UInt8]) -> [ARPEntry] {
        var entries: [ARPEntry] = []
        let headerSize = MemoryLayout<rt_msghdr>.stride

        buffer.withUnsafeBytes { raw in
            var offset = 0
            while offset + MemoryLayout<UInt16>.size <= raw.count {
                let messageLength = Int(raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                guard messageLength >= headerSize, offset + messageLength <= raw.count else { break }
                let header = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
                let addresses = sockaddrs(
                    in: raw, from: offset + headerSize, to: offset + messageLength,
                    mask: header.rtm_addrs)
                defer { offset += messageLength }

                guard let destination = addresses[Int(RTAX_DST)],
                      destination.family == UInt8(AF_INET),
                      let ip = addressText(destination, family: .v4),
                      let link = addresses[Int(RTAX_GATEWAY)],
                      link.family == UInt8(AF_LINK) else { continue }
                let dl = LinkAddress(link)
                // No link-layer address yet = an unresolved entry (`arp` says
                // "(incomplete)"); a MAC-less "MAC" helps nobody.
                guard let mac = dl.mac else { continue }
                let interface = dl.name
                    ?? interfaceName(index: header.rtm_index)
                    ?? interfaceName(index: dl.index)
                    ?? ""
                entries.append((ip: ip, mac: mac, interface: interface))
            }
        }
        return entries
    }

    /// The one class of record netstat's table view hides, and it has to be hidden
    /// here too or the table lies.
    ///
    /// A route cloned from a PROTOCOL-cloning parent (`RTF_WASCLONED` with
    /// `RTF_PRCLONING` in `rtm_parentflags`) is a per-destination cache entry the
    /// kernel minted for a flow — "104.26.12.205/32 → 10.0.7.254 UGHWIig en0".
    /// It is not policy, it outlives the state that produced it, and the kernel
    /// does NOT consult it for a fresh lookup: with a VPN up, `route -n get` on
    /// such a destination answers utun, not en0. Keeping them would make the
    /// resolver answer with whatever interface was primary when the flow started.
    ///
    /// ARP/ND entries survive this test and stay in the table (exactly as netstat
    /// prints them): their parents are `RTF_CLONING` (`C`), not `RTF_PRCLONING`
    /// (`c`) — a link-layer clone really does describe where that host is.
    static func isProtocolClone(flags: Int32, parentFlags: Int32) -> Bool {
        flags & RTF_WASCLONED != 0 && parentFlags & RTF_PRCLONING != 0
    }

    // MARK: Record construction

    /// Build one `RouteRecord` directly — no text is produced and re-parsed
    /// anywhere in here; `IPPrefix` comes from the address and mask BYTES.
    static func makeRecord(
        flags: Int32, interfaceIndex: UInt16, addresses: [Int: RawSockaddr], order: Int
    ) -> RouteRecord? {
        guard let destination = addresses[Int(RTAX_DST)] else { return nil }
        let family: IPFamily
        switch Int32(destination.family) {
        case AF_INET: family = .v4
        case AF_INET6: family = .v6
        default: return nil     // AF_LINK/AF_UNSPEC destinations are not routes we model
        }

        let (destinationBytes, destinationZone) = addressBytes(destination, family: family)

        // Quirk 3: the mask is read with the DESTINATION's family, and whatever the
        // kernel truncated away is zero. An absent mask means /0 for a network route
        // and (with RTF_HOST) a full-width host route.
        let maskSockaddr = addresses[Int(RTAX_NETMASK)]
        let isHost = flags & RTF_HOST != 0
        let prefixLength: Int
        if isHost {
            prefixLength = family.bitWidth
        } else if let maskSockaddr, !maskSockaddr.isEmpty {
            prefixLength = maskLength(
                maskSockaddr.slice(addressOffset(family), family.byteCount), family: family)
        } else {
            prefixLength = 0
        }

        guard let prefix = IPPrefix(
            family: family, bytes: destinationBytes, prefixLength: prefixLength) else { return nil }

        let gateway = gatewayText(addresses[Int(RTAX_GATEWAY)])
        let interface = addresses[Int(RTAX_IFP)].flatMap { LinkAddress($0).name }
            ?? interfaceName(index: interfaceIndex)
            ?? ""

        return RouteRecord(
            order: order,
            destination: destinationText(prefix: prefix, zone: destinationZone),
            prefix: prefix,
            zone: destinationZone,
            gateway: gateway,
            flags: flagLetters(flags),
            interfaceName: interface)
    }

    /// Where a family's address sits inside its sockaddr:
    /// `sockaddr_in.sin_addr` at 4, `sockaddr_in6.sin6_addr` at 8.
    static func addressOffset(_ family: IPFamily) -> Int { family == .v4 ? 4 : 8 }

    /// Address bytes + zone. Quirk 5 lives here: KAME hides the interface index in
    /// the second 16-bit group of link-local/link-scoped-multicast IPv6 addresses
    /// when `sin6_scope_id` is 0. Clear it from the address and report it as zone,
    /// exactly as netstat's `in6_fillscopeid()` does.
    static func addressBytes(_ sockaddr: RawSockaddr, family: IPFamily) -> ([UInt8], String?) {
        var bytes = sockaddr.slice(addressOffset(family), family.byteCount)
        guard family == .v6 else { return (bytes, nil) }

        let isLinkLocal = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
        // ff01:: (interface-local) and ff02:: (link-local) multicast carry a scope
        // the same way — and only those two, exactly as KAME's IN6_IS_ADDR_MC_
        // NODELOCAL / _LINKLOCAL test. Wider scopes (ff05::, ff0e::) do not.
        let multicastScope = bytes[1] & 0x0F
        let isScopedMulticast = bytes[0] == 0xFF && (multicastScope == 0x01 || multicastScope == 0x02)
        guard isLinkLocal || isScopedMulticast else { return (bytes, nil) }

        // sin6_scope_id is at offset 24; absent when the sockaddr is truncated.
        var scopeID = UInt32(sockaddr.byte(24))
            | UInt32(sockaddr.byte(25)) << 8
            | UInt32(sockaddr.byte(26)) << 16
            | UInt32(sockaddr.byte(27)) << 24
        if scopeID == 0 {
            scopeID = UInt32(bytes[2]) << 8 | UInt32(bytes[3])   // network order, in the address
        }
        bytes[2] = 0
        bytes[3] = 0
        guard scopeID != 0 else { return (bytes, nil) }
        return (bytes, interfaceName(index: scopeID) ?? "\(scopeID)")
    }

    /// Leading-ones count over the mask bytes.
    ///
    /// A non-contiguous mask is not expressible as a prefix length at all. The
    /// kernel will accept one, so rather than dropping the route (which would make
    /// a destination silently unroutable) this falls back to the POPULATION COUNT —
    /// the closest single number to "how much of the address this mask pins" — and
    /// the record keeps its real destination bytes.
    static func maskLength(_ mask: [UInt8], family: IPFamily) -> Int {
        var length = 0
        var run = true                                  // still inside the leading 1s
        for byte in mask {
            let ones = byte.leadingOnes
            if run {
                // The byte must be a solid run of 1s followed by 0s to stay contiguous.
                let canonical = ones == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - ones))
                guard byte == canonical else { return popcountFallback(mask) }
                length += ones
                if ones != 8 { run = false }
            } else if byte != 0 {
                return popcountFallback(mask)
            }
        }
        return min(length, family.bitWidth)
    }

    private static func popcountFallback(_ mask: [UInt8]) -> Int {
        mask.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    /// Textual gateway, in netstat's vocabulary: an address for a real next hop,
    /// "link#N" for an on-link route, a MAC for an ARP/ND clone. `RouteRecord`
    /// distinguishes these by parsing, so the spelling is load-bearing.
    static func gatewayText(_ sockaddr: RawSockaddr?) -> String {
        guard let sockaddr, !sockaddr.isEmpty else { return "" }
        switch Int32(sockaddr.family) {
        case AF_INET: return addressText(sockaddr, family: .v4) ?? ""
        case AF_INET6: return addressText(sockaddr, family: .v6) ?? ""
        case AF_LINK:
            let dl = LinkAddress(sockaddr)
            // `bsdText`, because this column's contract is to be what `netstat`
            // prints — unpadded lower-case hex — and `RouteRecord` reads meaning out
            // of the spelling. The canonical form would be a nicer string and a wrong
            // answer.
            if let mac = dl.mac { return mac.bsdText }
            if dl.index != 0 { return "link#\(dl.index)" }
            return dl.name ?? ""
        default: return ""
        }
    }

    /// Presentation form of an address sockaddr, with any IPv6 zone appended.
    static func addressText(_ sockaddr: RawSockaddr, family: IPFamily) -> String? {
        let (bytes, zone) = addressBytes(sockaddr, family: family)
        guard let prefix = IPPrefix(family: family, bytes: bytes, prefixLength: family.bitWidth)
        else { return nil }
        return zone.map { "\(prefix.addressText)%\($0)" } ?? prefix.addressText
    }

    /// The destination column: "default", a bare address for a host route,
    /// "addr/len" otherwise — with the zone on the address ("fe80::%lo0/64"),
    /// which is where `IPPrefix.parseDestination` expects it.
    static func destinationText(prefix: IPPrefix, zone: String?) -> String {
        let address = zone.map { "\(prefix.addressText)%\($0)" } ?? prefix.addressText
        if prefix.isDefault { return "default" }
        if prefix.isHost { return address }
        return "\(address)/\(prefix.prefixLength)"
    }

    static func interfaceName(index: some BinaryInteger) -> String? {
        guard index > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1)
        guard if_indextoname(UInt32(index), &buffer) != nil else { return nil }
        let name = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                          as: UTF8.self)
        return name.isEmpty ? nil : name
    }

    // MARK: sockaddr_dl

    /// A `sockaddr_dl`, read by offset rather than by struct so a truncated one is
    /// harmless: sdl_len(0) sdl_family(1) sdl_index(2..3) sdl_type(4) sdl_nlen(5)
    /// sdl_alen(6) sdl_slen(7) sdl_data(8...) — name first, then the link address.
    struct LinkAddress {
        let index: UInt16
        let name: String?
        /// The link-layer address, when there is one and it is six bytes long.
        ///
        /// `MACAddress` rather than text, so nothing downstream re-derives a spelling.
        /// The six-byte requirement lives in the type, and it is a real filter and not
        /// a formality: `sdl_alen` can be 8 (FireWire) or 0 (an unresolved ARP entry,
        /// which `arp` prints as "(incomplete)"), and neither is an Ethernet address.
        let mac: MACAddress?

        init(_ sockaddr: RawSockaddr) {
            index = UInt16(sockaddr.byte(2)) | UInt16(sockaddr.byte(3)) << 8
            let nameLength = Int(sockaddr.byte(5))
            let addressLength = Int(sockaddr.byte(6))
            let nameBytes = sockaddr.slice(8, nameLength)
            name = nameLength > 0 && !nameBytes.contains(0)
                ? String(decoding: nameBytes, as: UTF8.self) : nil
            mac = MACAddress(octets: sockaddr.slice(8 + nameLength, addressLength))
        }
    }

    // MARK: Flags

    /// Darwin netstat's `bits[]` table (network_cmds, netstat/route.c), in order.
    /// netstat walks it top to bottom and appends a letter per set bit, so keeping
    /// the ORDER keeps the strings byte-identical to the text path's ("UGScIg",
    /// "UHLWIi", "UCSIg"…) — which matters because `RouteRecord` reads meaning out
    /// of the letters and the UI shows them raw.
    static let flagLetters: [(bit: Int32, letter: Character)] = [
        (RTF_UP, "U"),                 // route usable
        (RTF_GATEWAY, "G"),            // destination is a gateway
        (RTF_HOST, "H"),               // host entry
        (RTF_REJECT, "R"),             // host/net unreachable
        (RTF_DYNAMIC, "D"),            // created by redirect
        (RTF_MODIFIED, "M"),           // modified by redirect
        (RTF_DONE, "d"),               // message confirmed (routing messages only)
        (RTF_MULTICAST, "m"),          // route represents a multicast address
        (RTF_CLONING, "C"),            // generates new routes on use
        (RTF_XRESOLVE, "X"),           // external daemon resolves
        (RTF_LLINFO, "L"),             // generated by the link layer (ARP/ND)
        (RTF_STATIC, "S"),             // manually added
        (RTF_PROTO1, "1"),
        (RTF_PROTO2, "2"),
        (RTF_WASCLONED, "W"),          // generated through cloning
        (RTF_PRCLONING, "c"),          // protocol requires cloning
        (RTF_PROTO3, "3"),
        (RTF_BLACKHOLE, "B"),          // discard packets
        (RTF_BROADCAST, "b"),
        (RTF_IFSCOPE, "I"),            // interface-scoped — the one the resolver lives on
        (RTF_IFREF, "i"),              // holds a reference to the interface (NOT scoping)
        (RTF_PROXY, "Y"),
        (RTF_ROUTER, "r"),
        (RTF_GLOBAL, "g"),
    ]

    static func flagLetters(_ flags: Int32) -> String {
        String(flagLetters.compactMap { flags & $0.bit != 0 ? $0.letter : nil })
    }
}

// MARK: - Leading ones

private extension UInt8 {
    /// Number of leading 1 bits — the per-byte half of a prefix length.
    nonisolated var leadingOnes: Int { (~self).leadingZeroBitCount }
}

// MARK: - Live changes

/// "The routing table moved." Opens a PF_ROUTE socket, watches for RTM_ADD /
/// RTM_DELETE / RTM_CHANGE, coalesces the burst (a VPN coming up emits dozens in
/// a few milliseconds) and calls back once.
///
/// Deliberately dumb: it reads only `rtm_type` and never tries to apply deltas to
/// a cached table. Incremental maintenance of a routing table is a whole
/// consistency problem, and a fresh `RouteTableSource.snapshot()` is cheap.
nonisolated final class RouteChangeListener: @unchecked Sendable {
    // @unchecked Sendable: every mutable field is guarded by `lock`, and the
    // callback is @Sendable. The dispatch source holds only a WEAK self, so a
    // running listener never keeps its owner (or itself) alive.

    private let onChange: @Sendable () -> Void
    private let debounce: DispatchTimeInterval
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.RouteChangeListener")

    private let lock = NSLock()
    private var source: DispatchSourceRead?
    private var generation: UInt64 = 0

    /// - Parameters:
    ///   - debounce: quiet period after the last message before the callback fires.
    ///   - onChange: called on a background queue, never inline with `start()`.
    init(debounce: Duration = .milliseconds(300), onChange: @escaping @Sendable () -> Void) {
        let milliseconds = debounce.components.seconds * 1_000
            + debounce.components.attoseconds / 1_000_000_000_000_000
        self.debounce = .milliseconds(Int(max(0, milliseconds)))
        self.onChange = onChange
    }

    deinit { cancelSource() }

    var isRunning: Bool { lock.withLock { source != nil } }

    /// Idempotent: starting an already-running listener is a no-op.
    func start() throws {
        lock.lock()
        guard source == nil else { lock.unlock(); return }
        lock.unlock()

        let descriptor = socket(PF_ROUTE, SOCK_RAW, 0)
        guard descriptor >= 0 else { throw RouteTableError.socketFailed(code: errno) }
        // Non-blocking so draining can loop until EAGAIN without parking the queue.
        _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK)

        let readSource = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        readSource.setEventHandler { [weak self] in self?.drain(descriptor) }
        // Close only from the cancel handler: that is the one point at which the
        // source is guaranteed to be finished with the descriptor.
        readSource.setCancelHandler { close(descriptor) }

        lock.lock()
        if source == nil {
            source = readSource
            lock.unlock()
            readSource.resume()
        } else {
            lock.unlock()
            readSource.cancel()     // lost a start() race — drop this one
        }
    }

    /// Idempotent, and safe to call from anywhere. A callback already scheduled by
    /// the debounce is dropped.
    func stop() {
        cancelSource()
    }

    private func cancelSource() {
        let doomed: DispatchSourceRead? = lock.withLock {
            generation &+= 1                // invalidate any pending debounce
            defer { source = nil }
            return source
        }
        doomed?.cancel()
    }

    // MARK: Reading

    private func drain(_ descriptor: Int32) {
        var buffer = [UInt8](repeating: 0, count: 4_096)
        var interesting = false
        while true {
            let read = buffer.withUnsafeMutableBytes { raw in
                recv(descriptor, raw.baseAddress, raw.count, 0)
            }
            // 0 = closed, -1 = EAGAIN/EINTR/error — either way there is no more to take
            // right now; the source will fire again when there is.
            guard read > 0 else { break }
            if Self.mentionsRouteChange(buffer, length: read) { interesting = true }
        }
        if interesting { scheduleCallback() }
    }

    /// Parse ONLY `rtm_type`. Tolerates a short read: a message truncated by the
    /// buffer boundary still has its type if the first four bytes arrived, and the
    /// walk stops rather than trusting a length that runs past what was read.
    static func mentionsRouteChange(_ bytes: [UInt8], length: Int) -> Bool {
        bytes.withUnsafeBytes { raw in
            var offset = 0
            let end = min(length, raw.count)
            while offset + 4 <= end {
                let messageLength = Int(raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                let type = Int32(raw[offset + 3])       // rtm_type: msglen(2) version(1) type(1)
                if type == RTM_ADD || type == RTM_DELETE || type == RTM_CHANGE { return true }
                guard messageLength > 0, offset + messageLength <= end else { return false }
                offset += messageLength
            }
            return false
        }
    }

    private func scheduleCallback() {
        let scheduled: UInt64 = lock.withLock {
            generation &+= 1
            return generation
        }
        queue.asyncAfter(deadline: .now() + debounce) { [weak self] in
            guard let self else { return }
            // Fire only if nothing newer arrived and the listener is still running:
            // a trailing-edge debounce, so a burst collapses into exactly one call.
            let stillCurrent = lock.withLock { generation == scheduled && source != nil }
            guard stillCurrent else { return }
            onChange()
        }
    }
}
