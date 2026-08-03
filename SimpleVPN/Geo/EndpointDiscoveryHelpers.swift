// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointDiscoveryHelpers.swift
//  Low-level plumbing for EndpointDiscovery: a timed subprocess runner, a tiny
//  HTTP probe, one-shot UDP/TCP request-response over Network.framework, and the
//  IKE_SA_INIT builder/parser. All nonisolated — callbacks land on background
//  queues and nothing here touches the main actor.
//

import Foundation
import Network
import Security

// MARK: - Regex

nonisolated extension EndpointDiscovery {
    /// First capture group of `pattern` in `text`, or nil.
    static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let m = re.firstMatch(in: text, range: range), m.numberOfRanges > 1,
              let r = Range(m.range(at: 1), in: text) else { return nil }
        return String(text[r])
    }
}

// MARK: - Subprocess with timeout

nonisolated extension EndpointDiscovery {
    struct ProcOut: Sendable { var status: Int32; var stdout: String; var stderr: String }

    static func runProcess(_ path: String, _ args: [String], timeout: TimeInterval) async -> ProcOut {
        await Task.detached(priority: .userInitiated) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            p.arguments = args
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            p.standardInput = FileHandle.nullDevice
            do { try p.run() } catch { return ProcOut(status: -1, stdout: "", stderr: "\(error)") }
            // Bound the wait — kill a hung connect.
            let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
            let o = out.fileHandleForReading.readDataToEndOfFile()
            let e = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            killer.cancel()
            return ProcOut(status: p.terminationStatus,
                           stdout: String(data: o, encoding: .utf8) ?? "",
                           stderr: String(data: e, encoding: .utf8) ?? "")
        }.value
    }
}

// MARK: - HTTP probe

nonisolated extension EndpointDiscovery {
    struct HTTPProbe: Sendable {
        var status: Int
        var headers: [String: String]
        var body: String          // truncated
    }

    /// GET a URL without following redirects or trusting the cert (a VPN gateway's
    /// cert is often private). Returns nil only on transport failure.
    static func httpProbe(_ urlString: String) async -> HTTPProbe? {
        guard let url = URL(string: urlString) else { return nil }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 6
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let delegate = DiscoveryURLDelegate()
        let session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var req = URLRequest(url: url)
        req.setValue("SimpleVPN-Discovery", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else { return nil }
            var headers: [String: String] = [:]
            for (k, v) in http.allHeaderFields {
                if let ks = k as? String, let vs = v as? String { headers[ks] = vs }
            }
            let body = String(data: data.prefix(16_384), encoding: .utf8) ?? ""
            return HTTPProbe(status: http.statusCode, headers: headers, body: body)
        } catch {
            return nil
        }
    }
}

/// Accept any cert (discovery is not a trust decision) and never follow redirects
/// (we want to *see* the 3xx to an IdP).
private nonisolated final class DiscoveryURLDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

// MARK: - TLS inspection box (thread-safe capture for the verify/challenge blocks)

nonisolated final class TLSInspectBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _subject: String?
    private var _wantsClientCert = false
    func setSubject(_ s: String) { lock.lock(); if _subject == nil { _subject = s }; lock.unlock() }
    func setWantsClientCert() { lock.lock(); _wantsClientCert = true; lock.unlock() }
    func subject() -> String? { lock.lock(); defer { lock.unlock() }; return _subject }
    func wantsClientCert() -> Bool { lock.lock(); defer { lock.unlock() }; return _wantsClientCert }
}

// MARK: - Network.framework one-shot exchanges

nonisolated extension EndpointDiscovery {

    /// Wait for a connection to become ready (true) or fail/time out (false).
    static func waitReady(_ conn: NWConnection, timeout: TimeInterval) async -> Bool {
        let flag = OnceFlag()
        return await withCheckedContinuation { cont in
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: flag.once { cont.resume(returning: true) }; conn.cancel()
                case .failed, .cancelled: flag.once { cont.resume(returning: false) }
                default: break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                flag.once { cont.resume(returning: false) }; conn.cancel()
            }
        }
    }

    /// Send one UDP datagram and return the first datagram received, or nil.
    static func udpExchange(host: String, port: Int, send payload: Data, timeout: TimeInterval) async -> Data? {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
        let flag = OnceFlag()
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            conn.stateUpdateHandler = { state in
                if case .ready = state {
                    conn.send(content: payload, completion: .contentProcessed { _ in })
                    conn.receiveMessage { data, _, _, _ in
                        flag.once { cont.resume(returning: data) }; conn.cancel()
                    }
                } else if case .failed = state {
                    flag.once { cont.resume(returning: nil) }
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                flag.once { cont.resume(returning: nil) }; conn.cancel()
            }
        }
    }

    /// Send bytes over TCP and return the first chunk received, or nil.
    static func tcpExchange(host: String, port: Int, send payload: Data, timeout: TimeInterval) async -> Data? {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let flag = OnceFlag()
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            conn.stateUpdateHandler = { state in
                if case .ready = state {
                    conn.send(content: payload, completion: .contentProcessed { _ in })
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 2048) { data, _, _, _ in
                        flag.once { cont.resume(returning: data) }; conn.cancel()
                    }
                } else if case .failed = state {
                    flag.once { cont.resume(returning: nil) }
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                flag.once { cont.resume(returning: nil) }; conn.cancel()
            }
        }
    }

    final class OnceFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func once(_ body: () -> Void) {
            lock.lock(); defer { lock.unlock() }
            guard !done else { return }
            done = true; body()
        }
    }
}

// MARK: - IKEv2 IKE_SA_INIT

nonisolated extension EndpointDiscovery {

    struct IKEParsed: Sendable {
        var encryption: String?
        var integrity: String?
        var prf: String?
        var dhGroup: String?
        var vendor: String?
    }

    /// Build a minimal IKE_SA_INIT: SA (one proposal, a broad transform set),
    /// KE (Group 14, 256 fixed bytes), Nonce. Enough for a responder to answer
    /// with its chosen proposal; a group mismatch still returns INVALID_KE.
    static func buildIKESAInit() -> Data {
        // --- SA payload: proposal #1, protocol IKE(1), 6 transforms ---
        var transforms = Data()
        func transform(last: Bool, type: UInt8, id: UInt16, keyLen: UInt16? = nil) -> Data {
            var t = Data()
            t.append(last ? 0 : 3)             // 0 = last, 3 = more
            t.append(0)
            var body = Data()
            body.append(type)
            body.append(0)
            body.append(UInt8(id >> 8)); body.append(UInt8(id & 0xff))
            if let kl = keyLen {               // key-length attribute (AF=1, type 14)
                body.append(0x80); body.append(0x0e)
                body.append(UInt8(kl >> 8)); body.append(UInt8(kl & 0xff))
            }
            let len = UInt16(4 + body.count)
            t.append(UInt8(len >> 8)); t.append(UInt8(len & 0xff))
            t.append(body)
            return t
        }
        // ENCR(1): AES-CBC-256, AES-CBC-128, AES-GCM16-256 ; PRF(2): SHA256 ;
        // INTEG(3): SHA256-128 ; DH(4): Group 14
        transforms.append(transform(last: false, type: 1, id: 12, keyLen: 256))
        transforms.append(transform(last: false, type: 1, id: 12, keyLen: 128))
        transforms.append(transform(last: false, type: 1, id: 20, keyLen: 256))
        transforms.append(transform(last: false, type: 2, id: 5))     // PRF_HMAC_SHA2_256
        transforms.append(transform(last: false, type: 3, id: 12))    // AUTH_HMAC_SHA2_256_128
        transforms.append(transform(last: true,  type: 4, id: 14))    // MODP2048

        var proposal = Data()
        proposal.append(0)                     // 0 = last proposal
        proposal.append(0)
        let propBodyLen = 8 + transforms.count // proposal fixed 8 + transforms (no SPI)
        proposal.append(UInt8(propBodyLen >> 8)); proposal.append(UInt8(propBodyLen & 0xff))
        proposal.append(1)                     // proposal #1
        proposal.append(1)                     // protocol IKE
        proposal.append(0)                     // SPI size 0
        proposal.append(6)                     // 6 transforms
        proposal.append(transforms)

        let saPayload = genericPayload(next: 34, body: proposal)   // next = KE (34)

        // --- KE payload: DH group 14, 256 bytes of fixed value ---
        var keBody = Data()
        keBody.append(0); keBody.append(14)    // DH group 14
        keBody.append(0); keBody.append(0)     // reserved
        keBody.append(Data(repeating: 0xAB, count: 256))
        let kePayload = genericPayload(next: 40, body: keBody)      // next = Nonce (40)

        // --- Nonce payload ---
        var nonce = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)
        let noncePayload = genericPayload(next: 0, body: Data(nonce))

        let payloads = saPayload + kePayload + noncePayload

        // --- IKE header (28 bytes) ---
        var initiatorSPI = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, initiatorSPI.count, &initiatorSPI)
        var hdr = Data()
        hdr.append(contentsOf: initiatorSPI)             // initiator SPI
        hdr.append(contentsOf: [UInt8](repeating: 0, count: 8))  // responder SPI = 0
        hdr.append(33)                                   // next payload = SA (33)
        hdr.append(0x20)                                 // version 2.0
        hdr.append(34)                                   // exchange type IKE_SA_INIT
        hdr.append(0x08)                                 // flags: initiator
        hdr.append(contentsOf: [0, 0, 0, 0])             // message ID 0
        let total = UInt32(28 + payloads.count)
        hdr.append(UInt8((total >> 24) & 0xff)); hdr.append(UInt8((total >> 16) & 0xff))
        hdr.append(UInt8((total >> 8) & 0xff)); hdr.append(UInt8(total & 0xff))

        return hdr + payloads
    }

    /// Wrap a payload body in the 4-byte generic payload header.
    private static func genericPayload(next: UInt8, body: Data) -> Data {
        var p = Data()
        p.append(next)
        p.append(0)                            // critical/reserved
        let len = UInt16(4 + body.count)
        p.append(UInt8(len >> 8)); p.append(UInt8(len & 0xff))
        p.append(body)
        return p
    }

    /// Walk the response payloads for the chosen SA transforms, vendor IDs and any
    /// INVALID_KE notify. Returns nil if it isn't a plausible IKE response.
    static func parseIKEResponse(_ data: Data) -> IKEParsed? {
        let b = [UInt8](data)
        guard b.count >= 28, b[17] == 0x20 else { return nil }   // version byte 2.0
        var result = IKEParsed()
        var next = Int(b[16])                                    // first payload type
        var off = 28
        while off + 4 <= b.count, next != 0 {
            let thisType = next
            let payloadNext = Int(b[off])
            let plen = Int(b[off + 2]) << 8 | Int(b[off + 3])    // generic payload length (bytes 2..3)
            guard plen >= 4, off + plen <= b.count else { break }
            let body = Array(b[(off + 4)..<(off + plen)])
            switch thisType {
            case 33: parseSA(body, into: &result)                // SA
            case 43: if let v = vendorName(body) { result.vendor = v }  // Vendor ID
            case 41:                                             // Notify
                if body.count >= 8 {
                    let notifyType = Int(body[6]) << 8 | Int(body[7])
                    if notifyType == 17 {                        // INVALID_KE_PAYLOAD
                        if body.count >= 10 {
                            let g = Int(body[8]) << 8 | Int(body[9])
                            result.dhGroup = "\(g)"
                        }
                    }
                }
            default: break
            }
            next = payloadNext
            off += plen
        }
        // A response with any recognised crypto or a vendor id counts.
        if result.encryption == nil && result.dhGroup == nil && result.vendor == nil { return nil }
        return result
    }

    private static func parseSA(_ body: [UInt8], into result: inout IKEParsed) {
        // body = proposals; walk transforms within the first proposal.
        var i = 0
        while i + 8 <= body.count {
            let propLen = Int(body[i + 2]) << 8 | Int(body[i + 3])
            let spiSize = Int(body[i + 6])
            let numTransforms = Int(body[i + 7])
            var t = i + 8 + spiSize
            var seen = 0
            while seen < numTransforms, t + 8 <= body.count {
                let tlen = Int(body[t + 2]) << 8 | Int(body[t + 3])
                let type = body[t + 4]
                let id = Int(body[t + 6]) << 8 | Int(body[t + 7])
                switch type {
                case 1: result.encryption = result.encryption ?? encrName(id)
                case 2: result.prf = result.prf ?? prfName(id)
                case 3: result.integrity = result.integrity ?? integName(id)
                case 4: result.dhGroup = result.dhGroup ?? "\(id)"
                default: break
                }
                guard tlen >= 8 else { break }
                t += tlen; seen += 1
            }
            guard propLen >= 8 else { break }
            i += propLen
        }
    }

    private static func encrName(_ id: Int) -> String {
        switch id {
        case 3: "3DES"; case 12: "AES-CBC"; case 13: "AES-CTR"
        case 18: "AES-GCM-8"; case 19: "AES-GCM-12"; case 20: "AES-GCM-16"
        case 28: "ChaCha20-Poly1305"; default: "ENCR#\(id)"
        }
    }
    private static func prfName(_ id: Int) -> String {
        switch id {
        case 2: "SHA1"; case 5: "SHA256"; case 6: "SHA384"; case 7: "SHA512"; default: "PRF#\(id)"
        }
    }
    private static func integName(_ id: Int) -> String {
        switch id {
        case 2: "SHA1-96"; case 12: "SHA256-128"; case 13: "SHA384-192"; case 14: "SHA512-256"
        default: "INTEG#\(id)"
        }
    }

    /// Recognise a few well-known vendor IDs by their published prefixes.
    private static func vendorName(_ body: [UInt8]) -> String? {
        let hex = body.map { String(format: "%02x", $0) }.joined()
        let known: [(String, String)] = [
            ("4048b7d56ebce88525e7de7f00d6c2d3", "IKE fragmentation"),
            ("afcad71368a1f1c96b8696fc77570100", "Dead Peer Detection"),
            ("1e2b516905991c7d7c96fcbfb587e461", "Windows / MS-Negotiation"),
            ("4a131c81070358455c5728f20e95452f", "RFC 3947 NAT-T"),
            ("8f8d83826d246b6fc7a8a6a428c11de8", "strongSwan"),
            ("882fe56d6fd20dbc2251613b2ebe5beb", "strongSwan"),
            ("409d0c99e6b5f1a20dc2d0a8c1b6c8e9", "Cisco"),
            ("1f07f70eaa6514d3b0fa96542a500", "Cisco VPN Concentrator"),
            ("12f5f28c457168a9702d9fe274cc", "Cisco Unity"),
            ("4865898919e0c2b1f2b1f3b0e0e8", "FortiGate"),
        ]
        for (prefix, name) in known where hex.hasPrefix(prefix) { return name }
        return nil
    }
}
