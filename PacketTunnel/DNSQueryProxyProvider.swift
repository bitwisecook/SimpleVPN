// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension
import Network

/// Opt-in, system DNS query proxy. Native suffix settings cannot implement exact/glob names.
/// Unmatched queries retain their original resolver endpoint. No queried names are logged.
final class DNSQueryProxyProvider: NEDNSProxyProvider, NEAppProxyUDPFlowHandling, @unchecked Sendable {
    private let runtime = DNSQueryProxyRuntime()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        guard let data = options?["queryPolicy"] as? Data, data.count <= 1_048_576,
              let policy = try? JSONDecoder().decode(DNSQueryPolicy.self, from: data), policy.problem == nil else {
            completionHandler(NSError(domain: "SimpleVPN.DNS", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid DNS query policy."]))
            return
        }
        Task { await runtime.start(policy); completionHandler(nil) }
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        Task { await runtime.stop(); completionHandler() }
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard flow is NEAppProxyUDPFlow || flow is NEAppProxyTCPFlow else { return false }
        let box = DNSProxyFlowBox(flow)
        Task { await runtime.accept(box) }
        return true
    }
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        handleNewFlow(flow)
    }
}

/// NEAppProxyFlow's documented thread-safe close/read/write API crosses task cancellation.
private final class DNSProxyFlowBox: @unchecked Sendable {
    let flow: NEAppProxyFlow
    init(_ flow: NEAppProxyFlow) { self.flow = flow }
    func close() { flow.closeReadWithError(nil); flow.closeWriteWithError(nil) }
}

private actor DNSQueryProxyRuntime {
    private var forwarder = DNSQueryForwarder(policy: DNSQueryPolicy())
    private var stopped = true
    private struct Job {
        let flow: DNSProxyFlowBox
        let task: Task<Void, Never>
        let deadline: Task<Void, Never>
    }
    private var jobs: [UUID: Job] = [:]
    func start(_ policy: DNSQueryPolicy) { forwarder = DNSQueryForwarder(policy: policy); stopped = false }
    func stop() {
        stopped = true
        let active = jobs; jobs.removeAll()
        for job in active.values { job.task.cancel(); job.deadline.cancel(); job.flow.close() }
    }
    func accept(_ box: DNSProxyFlowBox) {
        guard !stopped, jobs.count < 64 else { box.close(); return }
        let id = UUID()
        let task = Task { await self.serve(box, id: id) }
        // Bound retained idle TCP/UDP flows; clients can open a new DNS flow.
        let deadline = Task {
            do { try await Task.sleep(for: .seconds(60)) } catch { return }
            self.finish(id)
        }
        jobs[id] = Job(flow: box, task: task, deadline: deadline)
    }
    private func finish(_ id: UUID) {
        guard let job = jobs.removeValue(forKey: id) else { return }
        job.task.cancel(); job.deadline.cancel(); job.flow.close()
    }
    private func serve(_ box: DNSProxyFlowBox, id: UUID) async {
        defer { finish(id) }
        do {
            try await box.flow.open(withLocalFlowEndpoint: nil)
            if let udp = box.flow as? NEAppProxyUDPFlow {
                while !Task.isCancelled {
                    let (packets, error) = await udp.readDatagrams()
                    guard error == nil, let packets, !packets.isEmpty, packets.count <= 64,
                          packets.reduce(0, { $0 + $1.0.count }) <= 262_144 else { return }
                    let router = forwarder
                    try await withThrowingTaskGroup(of: (Data, NWEndpoint)?.self) { group in
                        for (query, endpoint) in packets {
                            group.addTask {
                                await router.answer(query, original: endpoint, tcp: false).map { ($0, endpoint) }
                            }
                        }
                        for try await reply in group {
                            guard !Task.isCancelled else { group.cancelAll(); return }
                            if let reply { try await udp.writeDatagrams([reply]) }
                        }
                    }
                }
            } else if let tcp = box.flow as? NEAppProxyTCPFlow {
                var buffer = Data()
                while !Task.isCancelled {
                    if buffer.count < 2 {
                        guard let data = try await read(tcp), !data.isEmpty else { return }
                        buffer.append(data)
                    }
                    guard buffer.count >= 2 else { continue }
                    let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
                    guard length >= 12, buffer.count <= 2 * (DNSWireMessage.maximumSize + 2) else { return }
                    if buffer.count < length + 2 {
                        guard let data = try await read(tcp), !data.isEmpty else { return }
                        buffer.append(data); continue
                    }
                    let query = Data(buffer.dropFirst(2).prefix(length))
                    buffer.removeFirst(length + 2)
                    guard let reply = await forwarder.answer(query, original: tcp.remoteFlowEndpoint, tcp: true), !Task.isCancelled else { return }
                    var framed = Data([UInt8(reply.count >> 8), UInt8(reply.count & 255)])
                    framed.append(reply)
                    try await write(framed, to: tcp)
                }
            }
        } catch { /* Close only this flow; never log names or silently choose another resolver. */ }
    }
    private func read(_ flow: NEAppProxyTCPFlow) async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            flow.readData { data, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: data) }
            }
        }
    }
    private func write(_ data: Data, to flow: NEAppProxyTCPFlow) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            flow.write(data) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }
}
