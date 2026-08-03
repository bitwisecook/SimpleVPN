// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeTLS.swift
//  One TLS handshake, held open just long enough to answer the questions the
//  staged probe asks of it:
//
//    • did it complete at all, and with what version and cipher
//    • what certificate chain did the VPN present (kept as DER so the result
//      value stays Sendable and the chain can be judged off the callback queue)
//    • did the VPN ASK for a client certificate — the single fact that explains
//      "the sign-in page never loads" on the certificate-gated corporate VPNs
//    • and, optionally, the first bytes of an HTTP response, for the existing
//      vendor classification in VPNProbe
//
//  The verify block always completes TRUE. That is not a trust decision: the
//  connection is thrown away without a byte of ours on it, and judging the
//  chain against the PROFILE's own authority (not the system's) is done
//  afterwards in ProbeCertificateInspector — where the answer can be an
//  actionable verdict instead of a silent handshake failure.
//

import Foundation
import Network
import Security

nonisolated struct ProbeTLSResult: Sendable {
    var tcpConnected = false
    var handshakeCompleted = false
    /// Set when the handshake didn't complete: Network.framework's own reason.
    var failureReason: String?
    /// The chain the VPN presented, leaf first, as DER.
    var chainDER: [Data] = []
    var negotiatedProtocol: String?
    var negotiatedCiphersuite: String?
    /// The VPN asked us for a client certificate during the handshake.
    var clientCertificateRequested = false
    /// First chunk of an HTTP response, when `httpRequest` was supplied.
    var httpHead = ""

    var leafDER: Data? { chainDER.first }
}

nonisolated enum ProbeTLS {

    /// Handshake with `host:port`. `sni` overrides the name sent in the Server
    /// Name Indication (the probe uses the address it would really dial, so the
    /// VPN answers with the certificate a real connection would see).
    static func handshake(host: String, port: Int, sni: String? = nil,
                          httpRequest: String? = nil,
                          timeout: TimeInterval = 8, boundIf: UInt32 = 0) async -> ProbeTLSResult {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            return ProbeTLSResult(failureReason: "That port number can\u{2019}t be used.")
        }
        // Resolve the egress interface (if any) BEFORE the handshake, so a probe of a
        // VPN server takes the physical path rather than looping through the tunnel it
        // is testing. nil ⇒ normal routing (honest fallback).
        let egress = await boundInterface(index: boundIf)
        let box = TLSResultBox()
        let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.probe.tls")

        let tls = NWProtocolTLS.Options()
        if let sni, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, sni)
        }
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                box.setChain(chain.map { SecCertificateCopyData($0) as Data })
            }
            complete(true)      // judged separately, against the profile's own CA
        }, queue)
        // Called only when the server sends a CertificateRequest. We present
        // nothing: the point is to learn that it asked, not to sign in.
        sec_protocol_options_set_challenge_block(tls.securityProtocolOptions, { _, complete in
            box.setChallenged()
            complete(nil)
        }, queue)

        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        if let egress { params.requiredInterface = egress }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let once = ResumeGate()

        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.setConnected()
                    if let md = connection.metadata(definition: NWProtocolTLS.definition)
                        as? NWProtocolTLS.Metadata {
                        let sec = md.securityProtocolMetadata
                        box.setNegotiated(
                            protocolName: name(for: sec_protocol_metadata_get_negotiated_tls_protocol_version(sec)),
                            ciphersuite: String(describing: sec_protocol_metadata_get_negotiated_tls_ciphersuite(sec)))
                    }
                    guard let httpRequest else {
                        once.fire { cont.resume() }
                        connection.cancel()
                        return
                    }
                    connection.send(content: Data(httpRequest.utf8), completion: .contentProcessed { _ in
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { data, _, _, _ in
                            if let data { box.setHead(String(decoding: data, as: UTF8.self)) }
                            once.fire { cont.resume() }
                            connection.cancel()
                        }
                    })
                case .failed(let error):
                    box.setFailure(error.localizedDescription)
                    once.fire { cont.resume() }
                case .cancelled:
                    once.fire { cont.resume() }
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                box.setFailureIfNone("The VPN didn\u{2019}t finish the secure handshake in time.")
                once.fire { cont.resume() }
                connection.cancel()
            }
        }
        return box.value()
    }

    /// Resolve an `IP_BOUND_IF` index to the `NWInterface` that `NWParameters`
    /// wants. The raw-socket probes bind by index directly; NWConnection can only
    /// be pinned with an `NWInterface`, so this bridges the two. A brief, bounded
    /// path lookup — nil (index 0, an unresolvable index, or no match in time)
    /// means "leave it to normal routing", which is the honest fallback.
    static func boundInterface(index: UInt32) async -> NWInterface? {
        guard index != 0, let name = RouteTableSource.interfaceName(index: index) else { return nil }
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.probe.iface")
        let gate = ResumeGate()
        let match: NWInterface? = await withCheckedContinuation { (cont: CheckedContinuation<NWInterface?, Never>) in
            monitor.pathUpdateHandler = { path in
                gate.fire { cont.resume(returning: path.availableInterfaces.first { $0.name == name }) }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 0.4) { gate.fire { cont.resume(returning: nil) } }
        }
        monitor.cancel()
        return match
    }

    /// Human-readable TLS version. Kept as a table rather than
    /// `String(describing:)` so the wording never shifts under a compiler update.
    static func name(for version: tls_protocol_version_t) -> String {
        switch version {
        case .TLSv10: "TLS 1.0"
        case .TLSv11: "TLS 1.1"
        case .TLSv12: "TLS 1.2"
        case .TLSv13: "TLS 1.3"
        case .DTLSv10: "DTLS 1.0"
        case .DTLSv12: "DTLS 1.2"
        @unknown default: "an unrecognised TLS version"
        }
    }

    /// Network.framework's callbacks arrive on its own queue; this is the handoff.
    private final class TLSResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result = ProbeTLSResult()
        func setConnected() {
            lock.lock(); defer { lock.unlock() }
            result.tcpConnected = true
            result.handshakeCompleted = true
        }
        func setChain(_ der: [Data]) {
            lock.lock(); defer { lock.unlock() }
            if result.chainDER.isEmpty { result.chainDER = der }
            result.tcpConnected = true   // a certificate means TCP already worked
        }
        func setChallenged() { lock.lock(); result.clientCertificateRequested = true; lock.unlock() }
        func setNegotiated(protocolName: String, ciphersuite: String) {
            lock.lock(); defer { lock.unlock() }
            result.negotiatedProtocol = protocolName
            result.negotiatedCiphersuite = ciphersuite
        }
        func setHead(_ s: String) { lock.lock(); result.httpHead = s; lock.unlock() }
        func setFailure(_ s: String) {
            lock.lock(); defer { lock.unlock() }
            if result.failureReason == nil && !result.handshakeCompleted { result.failureReason = s }
        }
        func setFailureIfNone(_ s: String) { setFailure(s) }
        func value() -> ProbeTLSResult { lock.lock(); defer { lock.unlock() }; return result }
    }

    private final class ResumeGate: @unchecked Sendable {
        private let lock = NSLock()
        private var fired = false
        func fire(_ body: () -> Void) {
            lock.lock(); defer { lock.unlock() }
            guard !fired else { return }
            fired = true
            body()
        }
    }
}
