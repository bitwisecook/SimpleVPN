// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Owned by the packet pump's serial queue. Only the first packets for a new
/// identity wait for signature verification. Other sources keep making progress.
nonisolated final class ApplicationPacketAdmission: @unchecked Sendable {
    typealias Resolver = @Sendable (Data, [VPNApplicationRoute]) async -> String?
    typealias Forward = @Sendable (Data, String?, UInt64) -> Void

    private struct Key: Hashable, Sendable {
        let token: Data
        let binary: Data
        let signer: String
    }
    private struct Pending {
        let owner: UInt64
        var packets: [Data]
        var bytes: Int
        let task: Task<Void, Never>
    }
    private struct Cached {
        let source: String?
        let expires: ContinuousClock.Instant
    }

    private let queue: DispatchQueue
    private let capture: VPNApplicationCapture
    private let tokens: [String: Data]
    private let resolve: Resolver
    private let forward: Forward
    private var pending: [Key: Pending] = [:]
    private var cache: [Key: Cached] = [:]
    private var pendingBytes = 0
    private var stopped = false

    init(queue: DispatchQueue, capture: VPNApplicationCapture, tokens: [String: Data],
         resolve: @escaping Resolver, forward: @escaping Forward) {
        self.queue = queue
        self.capture = capture
        self.tokens = tokens
        self.resolve = resolve
        self.forward = forward
    }

    func submit(_ packet: Data, token: Data?, signer: String, binary: Data) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !stopped else { return }
        guard let token, let owner = SourceProcessInstance.processGeneration(auditToken: token) else {
            forward(packet, nil, 0)
            return
        }
        let key = Key(token: token, binary: binary, signer: signer)
        if let known = cache[key], known.expires > .now {
            forward(packet, known.source, owner)
            return
        }
        guard pendingBytes + packet.count <= 1_048_576 else {
            forward(packet, nil, owner)
            return
        }
        if pending[key] != nil {
            guard pending[key]!.packets.count < 64 else { forward(packet, nil, owner); return }
            pending[key]!.packets.append(packet)
            pending[key]!.bytes += packet.count
            pendingBytes += packet.count
            return
        }
        guard pending.count < 32 else { forward(packet, nil, owner); return }
        let candidates = capture.candidates(token: token, signingIdentifier: signer, processTokens: tokens)
        guard !candidates.isEmpty else {
            remember(nil, for: key)
            forward(packet, nil, owner)
            return
        }
        let task = Task { [weak self, resolve, queue] in
            let answer = await resolve(token, candidates)
            let source = candidates.first { $0.id == answer }?.id
            guard !Task.isCancelled else { return }
            queue.async { [weak self] in self?.finish(key, source: source) }
        }
        pending[key] = Pending(owner: owner, packets: [packet], bytes: packet.count, task: task)
        pendingBytes += packet.count
    }

    private func remember(_ source: String?, for key: Key) {
        if cache.count >= 1024 { cache.removeAll(keepingCapacity: true) }
        cache[key] = Cached(source: source, expires: .now + .seconds(source == nil ? 1 : 15))
    }

    private func finish(_ key: Key, source: String?) {
        guard !stopped, let waiting = pending.removeValue(forKey: key) else { return }
        pendingBytes -= waiting.bytes
        remember(source, for: key)
        for packet in waiting.packets { forward(packet, source, waiting.owner) }
    }

    func stop() {
        dispatchPrecondition(condition: .onQueue(queue))
        stopped = true
        for entry in pending.values { entry.task.cancel() }
        pending.removeAll()
        cache.removeAll()
        pendingBytes = 0
    }
}
