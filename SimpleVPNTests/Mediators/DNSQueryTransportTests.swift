// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network
import Testing
@testable import SimpleVPN

/// Loopback peer; all mutable listener state is confined to queue.
nonisolated private final class DNSLoopbackPeer: @unchecked Sendable {
    let tcp: Bool
    let query: Data
    let wrongID: Bool
    private let listener: NWListener
    private let queue = DispatchQueue(label: "SimpleVPNTests.dns-peer")
    private var pending: CheckedContinuation<NWEndpoint.Port, Error>?
    private var connections: [NWConnection] = []
    private var received: Data?
    init(tcp: Bool, query: Data, wrongID: Bool = false) throws {
        self.tcp = tcp; self.query = query; self.wrongID = wrongID
        listener = try NWListener(using: tcp ? .tcp : .udp, on: .any)
    }
    func start() async throws -> NWEndpoint.Port {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.pending = continuation
                self.listener.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        if let port = self.listener.port { self.pending?.resume(returning: port); self.pending = nil }
                    case .failed(let error): self.pending?.resume(throwing: error); self.pending = nil
                    default: break
                    }
                }
                self.listener.newConnectionHandler = { connection in
                    self.connections.append(connection)
                    connection.start(queue: self.queue)
                    if self.tcp {
                        connection.receive(minimumIncompleteLength: self.query.count + 2, maximumLength: self.query.count + 2) { data, _, _, _ in
                            guard let data else { return }
                            self.received = Data(data.dropFirst(2))
                            self.respond(connection)
                        }
                    } else {
                        connection.receiveMessage { data, _, _, _ in self.received = data; self.respond(connection) }
                    }
                }
                self.listener.start(queue: self.queue)
            }
        }
    }
    private func respond(_ connection: NWConnection) {
        var reply = query; reply[2] = 0x81; reply[3] = 0x80
        if wrongID { reply[0] ^= 0xff }
        if tcp {
            let framed = Data([UInt8(reply.count >> 8), UInt8(reply.count & 255)]) + reply
            // Split the TCP length field so the receiver must accumulate framing.
            connection.send(content: Data(framed.prefix(1)), completion: .contentProcessed { _ in
                connection.send(content: Data(framed.dropFirst(1)), completion: .contentProcessed { _ in })
            })
        } else { connection.send(content: reply, completion: .contentProcessed { _ in }) }
    }
    func receivedQuery() async -> Data? {
        await withCheckedContinuation { continuation in queue.async { continuation.resume(returning: self.received) } }
    }
    func stop() { queue.async { self.listener.cancel(); self.connections.forEach { $0.cancel() }; self.connections.removeAll() } }
}

@MainActor
struct DNSQueryTransportTests {
    @Test(arguments: [false, true]) func relaysRealUDPAndFramedTCPWithoutChangingTheQuery(_ tcp: Bool) async throws {
        let query = DNSWireMessageTests.query()
        let peer = try DNSLoopbackPeer(tcp: tcp, query: query)
        defer { peer.stop() }
        let port = try await peer.start()
        let reply = try #require(await DNSQueryExchange.run(query: query, endpoint: .hostPort(host: "127.0.0.1", port: port), tcp: tcp))
        #expect(DNSWireMessage.response(reply, matches: query))
        #expect(await peer.receivedQuery() == query)
    }
    @Test func rejectsAnUpstreamResponseForAnotherTransaction() async throws {
        let query = DNSWireMessageTests.query()
        let peer = try DNSLoopbackPeer(tcp: false, query: query, wrongID: true)
        defer { peer.stop() }
        let port = try await peer.start()
        #expect(await DNSQueryExchange.run(query: query, endpoint: .hostPort(host: "127.0.0.1", port: port), tcp: false) == nil)
    }
    @Test func cancellingBeforeTheNetworkStartsResolvesTheContinuation() async {
        let task = Task {
            await DNSQueryExchange.run(query: DNSWireMessageTests.query(), endpoint: .hostPort(host: "127.0.0.1", port: 9), tcp: false)
        }
        task.cancel()
        #expect(await task.value == nil)
    }
}
