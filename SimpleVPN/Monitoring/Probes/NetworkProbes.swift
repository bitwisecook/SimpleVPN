// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkProbes.swift
//  Native network diagnostics — no `ping`/`traceroute`/`dig` subprocesses:
//    • ICMP echo over an unprivileged datagram socket (SOCK_DGRAM/IPPROTO_ICMP,
//      which Darwin permits without root) → round-trip latency.
//    • TTL-stepped ICMP echoes → a traceroute (each hop's router replies
//      time-exceeded; the destination replies echo-reply).
//    • DNS queries built and parsed on the wire over UDP to a chosen server, so we
//      know *which* server answered — A / AAAA / PTR.
//    • Forward/reverse name resolution via getaddrinfo/getnameinfo (syscalls, not
//      shells).
//    • Path-MTU sizing: don't-fragment ICMP echoes binary-searched for the boundary
//      (the single sizer in the app — ConnectionDiagnostics forwards to it), plus the
//      TCP-family MSS/blackhole evidence that unprivileged code can honestly gather.
//  All blocking socket work runs on a detached task; callers await results.
//

import Foundation
import Darwin
import SystemConfiguration

nonisolated extension String {
    /// Decode a NUL-terminated C buffer filled by inet_ntop/getnameinfo/proc_name.
    /// `String(cString:)` on an array is deprecated because it hid this truncation;
    /// every C-buffer site in the app funnels through here instead.
    init(cBuffer: [CChar]) {
        self = String(decoding: cBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                      as: UTF8.self)
    }
}

nonisolated enum NetworkProbes {

    // MARK: - Address resolution

    /// A/AAAA for a host (numeric strings). Empty on failure.
    static func resolve(host: String) async -> (v4: [String], v6: [String]) {
        await Task.detached(priority: .userInitiated) {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                                 ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return ([], []) }
            defer { freeaddrinfo(first) }
            var v4: [String] = [], v6: [String] = []
            var node: UnsafeMutablePointer<addrinfo>? = first
            while let n = node {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(n.pointee.ai_addr, n.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    let s = String(cBuffer: buf)
                    if n.pointee.ai_family == AF_INET6 { if !v6.contains(s) { v6.append(s) } }
                    else if n.pointee.ai_family == AF_INET { if !v4.contains(s) { v4.append(s) } }
                }
                node = n.pointee.ai_next
            }
            return (v4, v6)
        }.value
    }

    /// Reverse (PTR) name for an IP, or nil. Uses getnameinfo (honours the system
    /// resolver, including VPN-pushed DNS).
    static func reverseLookup(ip: String) async -> String? {
        await Task.detached(priority: .userInitiated) {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            var rc: Int32 = -1
            if ip.contains(":") {
                var sa = sockaddr_in6(); sa.sin6_family = sa_family_t(AF_INET6)
                guard inet_pton(AF_INET6, ip, &sa.sin6_addr) == 1 else { return nil }
                rc = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in6>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }
            } else {
                var sa = sockaddr_in(); sa.sin_family = sa_family_t(AF_INET)
                guard inet_pton(AF_INET, ip, &sa.sin_addr) == 1 else { return nil }
                rc = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) } }
            }
            guard rc == 0 else { return nil }
            let name = String(cBuffer: host)
            return name.isEmpty ? nil : name
        }.value
    }

    // MARK: - Blocking-syscall plumbing

    /// A dedicated concurrent queue for the blocking socket syscalls below.
    /// Task.detached runs on Swift's cooperative pool (bounded to ~core count); a
    /// blocking recv there parks a pool thread for its whole timeout, and a 30-hop
    /// traceroute could hold one for ~a minute — starving other async work. This
    /// queue spawns its own threads for the blocking work instead.
    private static let probeQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.probes",
                                                  attributes: .concurrent)

    private static func onProbeQueue<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { cont in
            probeQueue.async { cont.resume(returning: work()) }
        }
    }

    // MARK: - Egress binding (Network Tools "Egress" picker)
    //
    // macOS has NO `SO_BINDTODEVICE`; the Darwin equivalent is `IP_BOUND_IF` /
    // `IPV6_BOUND_IF`, which pin a socket's egress to one interface INDEX regardless of
    // the route table — exactly what lets a diagnostic go out a chosen tunnel even when
    // routing wouldn't send it there. `boundIf == 0` means "unbound" (Automatic — the
    // normal, route-table-obeying diagnostic socket, i.e. today's behavior).

    /// Turn an interface BSD name ("utun4", "en0") into the index `IP_BOUND_IF` wants.
    /// 0 (never a valid index) ⇒ Automatic / not resolvable.
    static func interfaceIndex(_ bsdName: String?) -> UInt32 {
        guard let bsdName, !bsdName.isEmpty else { return 0 }
        return if_nametoindex(bsdName)
    }

    /// Pin `fd` to interface index `boundIf` (no-op when 0). Applies the v4 or v6 option
    /// per `v6`; a bind failure is non-fatal (the probe simply runs unbound).
    /// Internal (not private) so the VPN-server probes in `VPNProbe` bind through the
    /// exact same `IP_BOUND_IF`/`IPV6_BOUND_IF` mechanism the egress picker uses.
    static func bindEgress(_ fd: Int32, to boundIf: UInt32, v6: Bool) {
        guard boundIf != 0 else { return }
        var idx = boundIf
        let level = v6 ? IPPROTO_IPV6 : IPPROTO_IP
        let option = v6 ? IPV6_BOUND_IF : IP_BOUND_IF
        setsockopt(fd, level, option, &idx, socklen_t(MemoryLayout<UInt32>.size))
    }

    /// SO_RCVTIMEO timeval that preserves fractional seconds and is never {0,0}
    /// (POSIX reads a zero timeout as "block forever").
    private static func recvTimeval(_ seconds: TimeInterval) -> timeval {
        let s = max(seconds, 0.001)
        let sec = Int(s)
        let usec = Int((s - Double(sec)) * 1_000_000)
        return timeval(tv_sec: sec, tv_usec: suseconds_t(usec))
    }

    // MARK: - ICMP ping

    struct PingReply: Sendable { var rttMS: Double?; var from: String? }

    /// One ICMP echo to `host` (IPv4). rttMS nil = timed out / unreachable.
    static func pingOnce(host: String, seq: UInt16, timeout: TimeInterval = 2,
                         boundIf: UInt32 = 0) async -> PingReply {
        await Self.onProbeQueue {
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
                // Resolve a hostname to its first v4.
                return PingReply(rttMS: nil, from: nil)
            }
            let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)   // unprivileged on Darwin
            guard fd >= 0 else { return PingReply(rttMS: nil, from: nil) }
            defer { close(fd) }
            Self.bindEgress(fd, to: boundIf, v6: false)
            var tv = Self.recvTimeval(timeout)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            let ident = UInt16.random(in: 0...UInt16.max)
            let packet = Self.icmpEcho(id: ident, seq: seq)
            let start = Date()
            let sent = packet.withUnsafeBytes { buf in
                withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            guard sent > 0 else { return PingReply(rttMS: nil, from: nil) }

            var from = sockaddr_storage(); var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            var rbuf = [UInt8](repeating: 0, count: 1500)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { fp in
                    recvfrom(fd, &rbuf, rbuf.count, 0, fp, &fromLen)
                }
            }
            guard n > 0 else { return PingReply(rttMS: nil, from: nil) }
            let rtt = Date().timeIntervalSince(start) * 1000
            return PingReply(rttMS: rtt, from: Self.addrString(&from))
        }
    }

    // MARK: - Traceroute

    struct TraceHop: Sendable, Identifiable { var id: Int { ttl }; var ttl: Int; var ip: String?; var rttMS: Double? }

    /// TTL-stepped ICMP echoes. Each hop is the router that returned time-exceeded;
    /// stops at the destination's echo-reply or maxHops.
    static func traceroute(host: String, maxHops: Int = 30, timeout: TimeInterval = 2,
                           boundIf: UInt32 = 0) async -> [TraceHop] {
        await Self.onProbeQueue {
            var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET)
            guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else { return [] }
            var hops: [TraceHop] = []
            let ident = UInt16.random(in: 0...UInt16.max)
            for ttl in 1...maxHops {
                let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
                if fd < 0 { break }
                Self.bindEgress(fd, to: boundIf, v6: false)
                var t = Int32(ttl)
                setsockopt(fd, IPPROTO_IP, IP_TTL, &t, socklen_t(MemoryLayout<Int32>.size))
                var tv = Self.recvTimeval(timeout)
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                let packet = Self.icmpEcho(id: ident, seq: UInt16(ttl))
                let start = Date()
                _ = packet.withUnsafeBytes { buf in
                    withUnsafePointer(to: &addr) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }
                var from = sockaddr_storage(); var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
                var rbuf = [UInt8](repeating: 0, count: 1500)
                let n = withUnsafeMutablePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { fp in
                        recvfrom(fd, &rbuf, rbuf.count, 0, fp, &fromLen)
                    }
                }
                close(fd)
                if n > 0 {
                    let ip = Self.addrString(&from)
                    hops.append(TraceHop(ttl: ttl, ip: ip, rttMS: Date().timeIntervalSince(start) * 1000))
                    if ip == host { break }   // reached the destination
                } else {
                    hops.append(TraceHop(ttl: ttl, ip: nil, rttMS: nil))
                }
            }
            return hops
        }
    }

    // MARK: - DNS over UDP (we control which server answers)

    enum DNSType: UInt16 { case a = 1, aaaa = 28, ptr = 12 }
    struct DNSResult: Sendable { var server: String; var records: [String]; var elapsedMS: Double }

    /// System resolver addresses (includes VPN-pushed DNS) from SCDynamicStore.
    static func systemDNSServers() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "SimpleVPN.dns" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
              let servers = dns["ServerAddresses"] as? [String] else { return [] }
        return servers
    }

    /// Query `server` directly for `name`/`type` over UDP:53 and parse the answers.
    static func dnsQuery(name: String, type: DNSType, server: String, timeout: TimeInterval = 3,
                         boundIf: UInt32 = 0) async -> DNSResult? {
        await Self.onProbeQueue {
            let isV6 = server.contains(":")
            let fd = socket(isV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else { return nil }
            defer { close(fd) }
            Self.bindEgress(fd, to: boundIf, v6: isV6)
            var tv = Self.recvTimeval(timeout)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            let query = Self.dnsQueryPacket(name: name, type: type)
            let start = Date()
            let sent: Int = query.withUnsafeBytes { buf in
                if isV6 {
                    var sa = sockaddr_in6(); sa.sin6_family = sa_family_t(AF_INET6); sa.sin6_port = in_port_t(53).bigEndian
                    guard inet_pton(AF_INET6, server, &sa.sin6_addr) == 1 else { return -1 }
                    return withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
                } else {
                    var sa = sockaddr_in(); sa.sin_family = sa_family_t(AF_INET); sa.sin_port = in_port_t(53).bigEndian
                    guard inet_pton(AF_INET, server, &sa.sin_addr) == 1 else { return -1 }
                    return withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                }
            }
            guard sent > 0 else { return nil }
            var rbuf = [UInt8](repeating: 0, count: 2048)
            let n = recv(fd, &rbuf, rbuf.count, 0)
            guard n > 0 else { return nil }
            let records = Self.parseDNSAnswers(Array(rbuf[0..<n]), type: type)
            return DNSResult(server: server, records: records, elapsedMS: Date().timeIntervalSince(start) * 1000)
        }
    }

    private static func dnsQueryPacket(name: String, type: DNSType) -> [UInt8] {
        var p: [UInt8] = []
        let id = UInt16.random(in: 0...UInt16.max)
        p += [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]  // RD=1, qd=1
        // qname: for PTR, callers pass the reversed .arpa name already. `name` is
        // user-typed, so guard the DNS label limit (1–63 bytes): a longer label
        // would trap on UInt8(count) or set the high bits (a bogus pointer). Skip
        // over-length or empty labels rather than crash / emit a malformed query.
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count) else { continue }
            p.append(UInt8(bytes.count)); p += bytes
        }
        p.append(0)                                   // root
        p += [UInt8(type.rawValue >> 8), UInt8(type.rawValue & 0xff), 0, 1]  // qtype, qclass IN
        return p
    }

    /// Walk the answer section, decoding A/AAAA/PTR (with name-compression).
    private static func parseDNSAnswers(_ msg: [UInt8], type: DNSType) -> [String] {
        guard msg.count > 12 else { return [] }
        let anCount = Int(msg[6]) << 8 | Int(msg[7])
        var off = 12
        // Skip the single question: name + qtype + qclass.
        off = skipName(msg, off); off += 4
        var out: [String] = []
        for _ in 0..<anCount {
            guard off < msg.count else { break }
            off = skipName(msg, off)
            guard off + 10 <= msg.count else { break }
            let rtype = UInt16(msg[off]) << 8 | UInt16(msg[off + 1])
            let rdlen = Int(msg[off + 8]) << 8 | Int(msg[off + 9])
            let rdata = off + 10
            guard rdata + rdlen <= msg.count else { break }
            if rtype == DNSType.a.rawValue, rdlen == 4 {
                out.append("\(msg[rdata]).\(msg[rdata+1]).\(msg[rdata+2]).\(msg[rdata+3])")
            } else if rtype == DNSType.aaaa.rawValue, rdlen == 16 {
                var parts: [String] = []
                for i in stride(from: 0, to: 16, by: 2) { parts.append(String(format: "%x", Int(msg[rdata+i]) << 8 | Int(msg[rdata+i+1]))) }
                out.append(parts.joined(separator: ":"))
            } else if rtype == DNSType.ptr.rawValue {
                out.append(decodeName(msg, rdata).0)
            }
            off = rdata + rdlen
        }
        return out
    }

    private static func skipName(_ msg: [UInt8], _ start: Int) -> Int {
        var off = start
        while off < msg.count {
            let len = Int(msg[off])
            if len == 0 { return off + 1 }
            if len & 0xc0 == 0xc0 { return off + 2 }   // compression pointer terminates the name
            off += 1 + len
        }
        return off
    }

    private static func decodeName(_ msg: [UInt8], _ start: Int) -> (String, Int) {
        var labels: [String] = []
        var off = start, jumped = false, end = start
        var guardCount = 0
        while off < msg.count, guardCount < 128 {
            guardCount += 1
            let len = Int(msg[off])
            if len == 0 { if !jumped { end = off + 1 }; break }
            if len & 0xc0 == 0xc0 {
                // Compression pointer needs a second byte; if it's the last byte of
                // the datagram, reading msg[off+1] would trap (a trivially-crafted
                // remote crash). Bail out of the name instead.
                guard off + 1 < msg.count else { break }
                if !jumped { end = off + 2 }; jumped = true
                off = (len & 0x3f) << 8 | Int(msg[off + 1]); continue
            }
            let s = off + 1
            guard s + len <= msg.count else { break }
            labels.append(String(bytes: msg[s..<s+len], encoding: .utf8) ?? "")
            off += 1 + len
        }
        return (labels.joined(separator: "."), end)
    }

    // MARK: - Path MTU / MSS probing
    //
    // Two deliberately different techniques, never conflated:
    //
    //  • ICMP is a *real* path-MTU probe: don't-fragment echoes of increasing size
    //    binary-search the largest packet the path carries end to end.
    //  • TCP/TLS/HTTP cannot do DF probing from an unprivileged app. We do not own
    //    the segments (the kernel does), so we cannot set DF per segment, and Darwin
    //    has no IP_RECVERR, so the MTU inside an ICMP "fragmentation needed" error is
    //    unreadable from user space. What IS honestly measurable is (a) the
    //    negotiated MSS via TCP_MAXSEG and (b) whether an exchange *larger* than that
    //    MSS completes while a small one on the same path succeeds — the signature of
    //    a PMTU blackhole. Anything more precise would be an invented number.

    /// Which technique an MTU test should use.
    enum MTUProtocol: String, Sendable, CaseIterable, Identifiable {
        case icmp, tcp, tls, http
        var id: String { rawValue }
        var label: String { rawValue.uppercased() }
        /// ICMP has no port; the rest default to where the protocol normally lives.
        var defaultPort: Int? {
            switch self {
            case .icmp: return nil
            case .tcp, .tls: return 443
            case .http: return 80
            }
        }
        var isTCP: Bool { self != .icmp }
    }

    // MARK: ICMP don't-fragment sizer

    /// One rung of the DF search, kept so the UI can show what was actually probed
    /// rather than just a headline number.
    struct MTUStep: Sendable, Identifiable {
        var id: Int { payload }
        var payload: Int          // ICMP data bytes (as `ping -s`)
        var passed: Bool          // an echo reply came back
        var localTooBig: Bool     // the kernel refused to send it (EMSGSIZE)
    }

    struct PathMTUResult: Sendable {
        var target: String                 // the IPv4 actually probed
        var hasIPv4 = true                 // false ⇒ nothing to probe (see note below)
        var answersICMP = false            // a small DF echo came back at all
        var payload: Int?                  // largest DF data size that got through
        var pathMTU: Int?                  // payload + 28 (20 IP + 8 ICMP)
        /// The boundary was the *local* interface refusing to send (EMSGSIZE), not
        /// silence from the path. With a tunnel up that interface IS the utun, so this
        /// says "the tunnel's own MTU is the limit; nothing downstream is smaller".
        var limitedByLocalInterface = false
        var fragmentsCorrectly: Bool?      // an oversized echo *without* DF came back
        var fragmentTestPayload: Int?
        var steps: [MTUStep] = []
    }

    /// ICMP echo/IP overhead: 20-byte IP header + 8-byte ICMP header.
    static let icmpOverhead = 28

    /// Binary-search the largest don't-fragment ICMP echo that reaches `host`, then
    /// re-send the smallest failing size *with* fragmentation allowed to see whether
    /// the path drops oversized packets outright.
    ///
    /// IPv4 only: the unprivileged datagram ICMP socket Darwin grants us is
    /// SOCK_DGRAM/IPPROTO_ICMP. There is no unprivileged ICMPv6 equivalent we can
    /// rely on, so an IPv6-only target reports `hasIPv4 == false` rather than a
    /// fabricated number.
    ///
    /// Cost: ~13 round trips, each a few ms when the target answers. A rung that gets
    /// no answer costs two timeouts (probe plus one retry), so a badly behaved path can
    /// take tens of seconds — always call this from a cancellable background task.
    static func measurePathMTU(host: String, ceiling: Int = 1472,
                               timeout: TimeInterval = 1.5, boundIf: UInt32 = 0) async -> PathMTUResult {
        let ip = await resolve(host: host).v4.first ?? host
        var out = PathMTUResult(target: ip)
        guard isIPv4Literal(ip) else { out.hasIPv4 = false; return out }

        // One rung, on the probe queue. Silence is retried once: a single dropped
        // packet on a lossy path would otherwise be read as "too big" and drag the
        // whole binary search down with it.
        func probe(_ payload: Int, df: Bool = true) async -> SizedEcho {
            let first = await onProbeQueue { sizedEcho(ip: ip, payload: payload, df: df, timeout: timeout, boundIf: boundIf) }
            guard first == .silence else { return first }
            return await onProbeQueue { sizedEcho(ip: ip, payload: payload, df: df, timeout: timeout, boundIf: boundIf) }
        }

        // 1. Does the target answer ICMP at all? Without this anchor "no reply" is
        //    ambiguous — filtered ICMP looks exactly like "too big".
        let base = await probe(56)
        out.steps.append(MTUStep(payload: 56, passed: base == .reply, localTooBig: base == .tooBigLocally))
        guard base == .reply else { return out }
        out.answersICMP = true
        if Task.isCancelled { return out }

        // 2. Does the ceiling already fit? Then there is no boundary to find and
        //    nothing oversized to fragment-test.
        var lo = 56, hi = max(64, ceiling)
        let top = await probe(hi)
        out.steps.append(MTUStep(payload: hi, passed: top == .reply, localTooBig: top == .tooBigLocally))
        if top == .reply {
            out.payload = hi; out.pathMTU = hi + icmpOverhead
            return out
        }
        var boundaryWasLocal = (top == .tooBigLocally)

        // 3. Binary-search the boundary to the exact byte. Coarser resolution is
        //    tempting (each rung costs a round trip) but wrong here: stopping 4 bytes
        //    short of 1500 reads as "the tunnel is 1 byte too big" and would make the
        //    card cry wolf on a perfectly healthy path. ~13 rungs from 56…1472.
        while hi - lo > 1 {
            if Task.isCancelled { return out }
            let mid = (lo + hi) / 2
            let r = await probe(mid)
            out.steps.append(MTUStep(payload: mid, passed: r == .reply, localTooBig: r == .tooBigLocally))
            if r == .reply { lo = mid } else { hi = mid; boundaryWasLocal = (r == .tooBigLocally) }
        }
        out.payload = lo
        out.pathMTU = lo + icmpOverhead
        out.limitedByLocalInterface = boundaryWasLocal
        if Task.isCancelled { return out }

        // 4. Fragmentation check: the smallest size that failed with DF, re-sent
        //    letting it fragment. A reply proves the path carries fragments; silence
        //    means oversized packets are dropped outright — a blackhole, not sizing.
        let f = await probe(hi, df: false)
        out.fragmentTestPayload = hi
        out.fragmentsCorrectly = (f == .reply)
        return out
    }

    private enum SizedEcho: Sendable { case reply, silence, tooBigLocally, sendFailed }

    /// One sized ICMP echo, optionally with the don't-fragment bit set.
    /// Blocking — callers must run it on `probeQueue`.
    private static func sizedEcho(ip: String, payload: Int, df: Bool,
                                  timeout: TimeInterval, boundIf: UInt32 = 0) -> SizedEcho {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return .sendFailed }
        // A fresh socket per rung: the kernel owns the ICMP id on an unprivileged
        // datagram socket, so a late reply to the previous (smaller) echo cannot land
        // here and be miscounted as this larger one getting through.
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return .sendFailed }
        defer { close(fd) }
        bindEgress(fd, to: boundIf, v6: false)
        var tv = recvTimeval(timeout)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var dontFragment: Int32 = df ? 1 : 0
        setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &dontFragment, socklen_t(MemoryLayout<Int32>.size))

        let packet = icmpEcho(id: UInt16.random(in: 0...UInt16.max), seq: 1, dataBytes: payload)
        let sent = packet.withUnsafeBytes { buf in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, buf.baseAddress, buf.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        // EMSGSIZE with DF set = bigger than the outgoing interface's MTU. That is a
        // genuine answer about the first hop, not a failure of the probe.
        if sent < 0 { return errno == EMSGSIZE ? .tooBigLocally : .sendFailed }
        var rbuf = [UInt8](repeating: 0, count: 2048)
        let n = recv(fd, &rbuf, rbuf.count, 0)
        return n > 0 ? .reply : .silence
    }

    // MARK: TCP / TLS / HTTP (negotiated MSS + big-vs-small blackhole test)

    /// One request/response round trip. `responseBytes` matters as well as
    /// `completed`: a response larger than the MSS proves the *inbound* direction
    /// carried full-size segments, which a tiny 301 does not.
    struct MTUExchange: Sendable {
        var requestBytes: Int
        var responseBytes: Int
        var completed: Bool          // at least one response byte came back
        var elapsedMS: Double
    }

    struct TransportMTUResult: Sendable {
        var target: String
        var port: Int
        var proto: MTUProtocol
        var connected = false
        /// TCP_MAXSEG on the live connection: the *negotiated send* MSS — the peer's
        /// advertised MSS clamped by our route MTU (and by any mssfix the tunnel
        /// rewrote in flight), minus the space negotiated options take.
        ///
        /// Measured on a 1500-MTU link: 1448 from Cloudflare, 1424 from GitHub, 1388
        /// from example.com — i.e. mostly a property of the far end, not of our path.
        /// Consumers must not read it as a path MTU; `MTUAssessment` only ever treats
        /// `mss + 40` as an upper bound on what this connection emits.
        var mss: Int?
        var smallExchange: MTUExchange?
        var largeExchange: MTUExchange?
        var impliedMTU: Int? { mss.map { $0 + 40 } }   // 20 IP + 20 TCP, no options
    }

    /// TCP-family MTU evidence: connect, read the negotiated MSS, then (for TLS and
    /// HTTP, which have a request we can inflate) compare a small exchange against
    /// one deliberately larger than the MSS. Plain TCP exchanges no payload, so it
    /// yields the MSS only — see `MTUAssessment` for how that is reported.
    static func measureTransportMTU(host: String, port: Int, proto: MTUProtocol,
                                    timeout: TimeInterval = 6, boundIf: UInt32 = 0) async -> TransportMTUResult {
        let ip = await resolve(host: host).v4.first ?? host
        var out = TransportMTUResult(target: ip, port: port, proto: proto)
        guard proto.isTCP, isIPv4Literal(ip) else { return out }

        // Pass 1: connect and read the MSS. For TLS/HTTP also do the small exchange
        // on this same connection so "small works" is established on one path.
        let smallRequest = request(for: proto, host: host, padTo: nil, mss: nil)
        let first = await onProbeQueue {
            tcpExchange(ip: ip, port: port, request: smallRequest, readLimit: 16 * 1024, timeout: timeout, boundIf: boundIf)
        }
        out.connected = first.connected
        out.mss = first.mss
        if !smallRequest.isEmpty, first.connected {
            out.smallExchange = MTUExchange(requestBytes: smallRequest.count,
                                            responseBytes: first.responseBytes,
                                            completed: first.responseBytes > 0,
                                            elapsedMS: first.elapsedMS)
        }
        guard first.connected, !Task.isCancelled else { return out }

        // Pass 2: the same request inflated past the MSS, on a fresh connection.
        // Sized from the observed MSS so it spans at least two full segments.
        let largeRequest = request(for: proto, host: host, padTo: 2 * (first.mss ?? 1360) + 128, mss: first.mss)
        guard !largeRequest.isEmpty, largeRequest.count > smallRequest.count else { return out }
        let second = await onProbeQueue {
            tcpExchange(ip: ip, port: port, request: largeRequest, readLimit: 32 * 1024, timeout: timeout, boundIf: boundIf)
        }
        guard !Task.isCancelled else { return out }
        out.largeExchange = MTUExchange(requestBytes: largeRequest.count,
                                        responseBytes: second.responseBytes,
                                        completed: second.connected && second.responseBytes > 0,
                                        elapsedMS: second.elapsedMS)
        return out
    }

    private struct TCPProbeOutcome: Sendable {
        var connected = false
        var mss: Int?
        var responseBytes = 0
        var elapsedMS: Double = 0
    }

    /// Connect, read TCP_MAXSEG, write `request`, drain the reply.
    /// Blocking — callers must run it on `probeQueue`.
    private static func tcpExchange(ip: String, port: Int, request: [UInt8],
                                    readLimit: Int, timeout: TimeInterval,
                                    boundIf: UInt32 = 0) -> TCPProbeOutcome {
        var out = TCPProbeOutcome()
        let started = Date()
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(clamping: port)).bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return out }

        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return out }
        defer { close(fd) }
        bindEgress(fd, to: boundIf, v6: false)

        // Non-blocking connect + poll: Darwin does not apply SO_SNDTIMEO to connect(),
        // so this is the only way to bound how long a dead endpoint stalls us.
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc != 0 {
            guard errno == EINPROGRESS else { return out }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&pfd, 1, Int32(timeout * 1000)) > 0 else { return out }
            var soError: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0, soError == 0 else { return out }
        }
        out.connected = true
        _ = fcntl(fd, F_SETFL, flags)          // back to blocking for the transfer

        var maxseg: Int32 = 0
        var segLen = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &maxseg, &segLen) == 0, maxseg > 0 {
            out.mss = Int(maxseg)
        }
        out.elapsedMS = Date().timeIntervalSince(started) * 1000
        guard !request.isEmpty else { return out }

        var tv = recvTimeval(timeout)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        // Nagle off so the request hits the wire as we wrote it rather than being
        // coalesced differently from what we are trying to measure.
        var on: Int32 = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))

        var written = 0
        while written < request.count {
            let n = request[written...].withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
            if n <= 0 { return out }            // stalled mid-request; response stays 0
            written += n
        }
        out.elapsedMS = Date().timeIntervalSince(started) * 1000

        let deadline = Date().addingTimeInterval(timeout)
        var rbuf = [UInt8](repeating: 0, count: 8 * 1024)
        while out.responseBytes < readLimit, Date() < deadline {
            let n = recv(fd, &rbuf, rbuf.count, 0)
            if n <= 0 { break }                 // EOF, timeout, or error
            out.responseBytes += n
        }
        out.elapsedMS = Date().timeIntervalSince(started) * 1000
        return out
    }

    /// The bytes to send for a protocol. `padTo` inflates the request past the MSS;
    /// nil is the natural small form. Plain TCP returns empty — a bare connection has
    /// no payload we could legitimately inflate.
    private static func request(for proto: MTUProtocol, host: String,
                                padTo: Int?, mss: Int?) -> [UInt8] {
        switch proto {
        case .icmp, .tcp: return []
        case .tls:        return tlsClientHello(host: host, padTo: padTo)
        case .http:
            var head = "GET / HTTP/1.1\r\nHost: \(host)\r\n"
            head += "User-Agent: SimpleVPN-MTU-Probe/1\r\nAccept: */*\r\nConnection: close\r\n"
            if let padTo, padTo > head.utf8.count + 40 {
                // A long custom header is the least surprising way to make the request
                // itself exceed the MSS: servers ignore unknown headers.
                head += "X-SimpleVPN-Pad: " + String(repeating: "x", count: padTo - head.utf8.count - 21) + "\r\n"
            }
            return Array((head + "\r\n").utf8)
        }
    }

    /// A hand-built TLS 1.2 ClientHello. We only need the server to *answer* (a
    /// ServerHello or even an alert proves the bytes arrived), so no key exchange is
    /// attempted and nothing is trusted — this never becomes a real session.
    /// `padTo` uses the standard padding extension (RFC 7685) to reach a target size.
    ///
    /// Verified against live servers: example.com, github.com and google.com all reply
    /// with a full ~3 KB ServerHello + certificate to both the small and the padded
    /// form. Offering TLS 1.3 (supported_versions + key_share) was tried and changed
    /// nothing, so the extra machinery isn't carried. Some endpoints answer nothing at
    /// all — 1.1.1.1:443 is one — which the UI reports as inconclusive rather than
    /// guessing.
    private static func tlsClientHello(host: String, padTo: Int?) -> [UInt8] {
        func u16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }

        var exts: [UInt8] = []
        // SNI, but only for real names — the extension forbids IP literals.
        if !isIPv4Literal(host), !host.contains(":"), !host.isEmpty {
            let name = Array(host.utf8)
            var sni: [UInt8] = [0x00]            // host_name
            sni += u16(name.count) + name
            exts += [0x00, 0x00] + u16(sni.count + 2) + u16(sni.count) + sni
        }
        exts += [0x00, 0x0a] + u16(6) + u16(4) + [0x00, 0x1d, 0x00, 0x17]   // groups: x25519, secp256r1
        exts += [0x00, 0x0b] + u16(2) + [0x01, 0x00]                        // ec_point_formats: uncompressed
        exts += [0x00, 0x0d] + u16(10) + u16(8)                             // signature_algorithms
             +  [0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x02, 0x01]

        func assemble(_ extensions: [UInt8]) -> [UInt8] {
            var body: [UInt8] = [0x03, 0x03]                                // legacy_version TLS 1.2
            body += (0..<32).map { _ in UInt8.random(in: 0...255) }         // random
            body += [0x00]                                                  // no session id
            let suites: [UInt8] = [0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x2f]
            body += u16(suites.count) + suites
            body += [0x01, 0x00]                                            // compression: null
            body += u16(extensions.count) + extensions
            var hs: [UInt8] = [0x01, UInt8((body.count >> 16) & 0xff),
                               UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)]
            hs += body
            return [0x16, 0x03, 0x01] + u16(hs.count) + hs
        }

        var packet = assemble(exts)
        if let padTo, padTo > packet.count + 4 {
            let padBytes = padTo - packet.count - 4
            exts += [0x00, 0x15] + u16(padBytes) + [UInt8](repeating: 0, count: padBytes)
            packet = assemble(exts)
        }
        return packet
    }

    static func isIPv4Literal(_ s: String) -> Bool {
        var a = in_addr()
        return inet_pton(AF_INET, s, &a) == 1
    }

    // MARK: - ICMP packet + address helpers

    /// Echo request with `dataBytes` of payload after the 8-byte header (so the IP
    /// packet is dataBytes + 28, matching `ping -s`).
    private static func icmpEcho(id: UInt16, seq: UInt16, dataBytes: Int = 8) -> [UInt8] {
        var p = [UInt8](repeating: 0, count: 8 + max(0, dataBytes))
        p[0] = 8                       // type: echo request
        p[1] = 0                       // code
        p[4] = UInt8(id >> 8); p[5] = UInt8(id & 0xff)
        p[6] = UInt8(seq >> 8); p[7] = UInt8(seq & 0xff)
        // A varying pattern rather than zeros: some middleboxes treat long runs of
        // zeros differently, and we want a representative-size packet.
        for i in 8..<p.count { p[i] = UInt8(truncatingIfNeeded: i) }
        let ck = checksum(p)
        p[2] = UInt8(ck >> 8); p[3] = UInt8(ck & 0xff)
        return p
    }

    private static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0, i = 0
        while i + 1 < bytes.count { sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1]); i += 2 }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return UInt16(~sum & 0xffff)
    }

    private static func addrString(_ storage: inout sockaddr_storage) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t($0.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        return rc == 0 ? String(cBuffer: host) : nil
    }
}
