// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network

/// One bounded DNS transaction. Mutable state and its one-shot continuation live on queue.
nonisolated final class DNSQueryExchange: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.dns-exchange")
    private let connection: NWConnection
    private let query: Data
    private let tcp: Bool
    private var completion: (@Sendable (Data?) -> Void)?
    private var sent = false
    private var cancelled = false
    private var buffer = Data()
    init(query: Data, endpoint: NWEndpoint, tcp: Bool) {
        self.query = query; self.tcp = tcp
        connection = NWConnection(to: endpoint, using: tcp ? .tcp : .udp)
    }
    static func run(query: Data, endpoint: NWEndpoint, tcp: Bool) async -> Data? {
        let exchange = DNSQueryExchange(query: query, endpoint: endpoint, tcp: tcp)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                exchange.begin { continuation.resume(returning: $0) }
            }
        } onCancel: { exchange.cancel() }
    }
    func cancel() { queue.async { self.cancelled = true; self.finish(nil) } }
    private func begin(_ completion: @escaping @Sendable (Data?) -> Void) {
        queue.async {
            guard !self.cancelled else { completion(nil); return }
            self.completion = completion
            self.connection.stateUpdateHandler = { state in
                switch state {
                case .ready: self.send()
                case .failed, .cancelled: self.finish(nil)
                default: break
                }
            }
            self.queue.asyncAfter(deadline: .now() + 3) { self.finish(nil) }
            self.connection.start(queue: self.queue)
        }
    }
    private func send() {
        guard !sent else { return }; sent = true
        var payload = query
        if tcp { payload = Data([UInt8(query.count >> 8), UInt8(query.count & 255)]) + query }
        connection.send(content: payload, completion: .contentProcessed { error in
            if error != nil { self.finish(nil) }
            else { self.receive() }
        })
    }
    private func receive() {
        if !tcp {
            connection.receiveMessage { data, _, _, _ in
                self.finish(data.flatMap { DNSWireMessage.response($0, matches: self.query) ? $0 : nil })
            }
        } else {
            connection.receive(minimumIncompleteLength: 1, maximumLength: DNSWireMessage.maximumSize + 2) { data, _, complete, error in
                if let data { self.buffer.append(data) }
                guard self.buffer.count <= DNSWireMessage.maximumSize + 2, error == nil else { self.finish(nil); return }
                if self.buffer.count >= 2 {
                    let length = Int(self.buffer[0]) << 8 | Int(self.buffer[1])
                    if length >= 12, self.buffer.count >= length + 2 {
                        let reply = Data(self.buffer.dropFirst(2).prefix(length))
                        self.finish(DNSWireMessage.response(reply, matches: self.query) ? reply : nil)
                        return
                    }
                }
                if complete { self.finish(nil) } else { self.receive() }
            }
        }
    }
    private func finish(_ reply: Data?) {
        guard let completion else { return }; self.completion = nil
        connection.stateUpdateHandler = nil; connection.cancel()
        completion(reply)
    }
}
