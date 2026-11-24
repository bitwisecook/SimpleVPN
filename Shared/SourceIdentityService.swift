// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated enum SourceIdentityService {
    enum Failure: LocalizedError {
        case unavailable
        var errorDescription: String? { "macOS could not verify this signed application or process. It may have exited or may restrict inspection." }
    }

    private static let capacity = DispatchSemaphore(value: 16)

    private static func reserve() -> Bool { capacity.wait(timeout: .now()) == .success }

    static func signedApplication(at url: URL) async throws -> SourceSigningIdentity {
        guard url.isFileURL else { throw Failure.unavailable }
        // A transient bookmark carries the selected file's access to the sandboxed service.
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        guard let bookmark = try? url.bookmarkData(options: [.minimalBookmark], includingResourceValuesForKeys: nil, relativeTo: nil),
              case .identity(let identity) = try await request(.file(bookmark)) else { throw Failure.unavailable }
        return identity
    }

    static func runningProcess(pid: Int32) async throws -> SourceProcessInstance {
        guard let token = SourceProcessInstance.captureToken(pid: pid),
              case .process(let instance) = try await request(.process(token)), instance.pid == pid,
              instance.matches(auditToken: token) else { throw Failure.unavailable }
        return instance
    }

    static func matchedRoute(auditToken: Data, candidates: [VPNApplicationRoute], processTokens: [String: Data] = [:]) async -> String? {
        guard case .matched(let id) = await routeOutcome(auditToken: auditToken, candidates: candidates, processTokens: processTokens)
        else { return nil }
        return id
    }

    static func routeOutcome(auditToken: Data, candidates: [VPNApplicationRoute], processTokens: [String: Data] = [:]) async -> SourceIdentityWire.MatchOutcome {
        guard SourceProcessInstance.processGeneration(auditToken: auditToken) != nil,
              (1...SourceIdentityWire.maximumCandidates).contains(candidates.count) else { return .unavailable }
        let rules = candidates.map { route in
            var criteria = route.processCriteria
            if let canonical = criteria?.canonicalProxyEndpoint { criteria?.httpProxyEndpoint = canonical }
            return SourceIdentityWire.Candidate(id: route.id, signingIdentifier: route.signingIdentifier,
                                                designatedRequirement: route.designatedRequirement,
                                                selectedToken: processTokens[route.id], processCriteria: criteria)
        }
        guard rules.allSatisfy(\.isValid), Set(rules.map(\.id)).count == rules.count else { return .unavailable }
        if rules.contains(where: { $0.processCriteria != nil }) {
            // Older helpers ignore unknown Codable properties. A separate
            // request and reply discriminant makes that downgrade fail closed.
            guard case .processCriteriaMatch(let outcome) = try? await request(.matchProcessCriteria(auditToken, rules))
            else { return .unavailable }
            if case .matched(let id) = outcome, !rules.contains(where: { $0.id == id }) { return .unavailable }
            return outcome
        }
        // Legacy nil cannot distinguish a different signer from failed inspection.
        guard case .match(let id?) = try? await request(.match(auditToken, rules)),
              rules.contains(where: { $0.id == id }) else { return .unavailable }
        return .matched(id)
    }

    private static func request(_ request: SourceIdentityWire.Request) async throws -> SourceIdentityWire.Reply {
        try Task.checkCancellation()
        guard reserve() else { throw Failure.unavailable }
        defer { capacity.signal() }
        let data = try JSONEncoder().encode(request)
        guard data.count <= SourceIdentityWire.maximumBytes else { throw Failure.unavailable }
        let call = IdentityCall()
        let response: Data? = await withTaskCancellationHandler {
            await withCheckedContinuation { call.start(data, continuation: $0) }
        } onCancel: { call.cancel() }
        try Task.checkCancellation()
        guard let response, response.count <= SourceIdentityWire.maximumBytes else { throw Failure.unavailable }
        return try JSONDecoder().decode(SourceIdentityWire.Reply.self, from: response)
    }
}

/// Each request owns one cancellable connection. The queues and XPC service are
/// created only when a caller selects a source or a rule needs verification.
private nonisolated final class IdentityCall: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.source-identity-reply")
    private var connection: NSXPCConnection?
    private var continuation: CheckedContinuation<Data?, Never>?
    private var timer: DispatchSourceTimer?
    private var finished = false

    func start(_ data: Data, continuation: CheckedContinuation<Data?, Never>) {
        queue.async {
            guard !self.finished else { continuation.resume(returning: nil); return }
            self.continuation = continuation
            let link = NSXPCConnection(serviceName: SourceIdentityWire.service)
            self.connection = link
            link.setCodeSigningRequirement(SourceIdentityWire.serviceRequirement)
            link.remoteObjectInterface = NSXPCInterface(with: SourceIdentityVerifying.self)
            link.invalidationHandler = { self.cancel() }
            link.interruptionHandler = { self.cancel() }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            self.timer = timer
            timer.setEventHandler { self.finish(nil) }
            timer.schedule(deadline: .now() + 3)
            timer.resume()
            link.resume()
            guard let proxy = link.remoteObjectProxyWithErrorHandler({ _ in self.cancel() }) as? SourceIdentityVerifying else {
                self.finish(nil); return
            }
            proxy.inspect(data) { reply in self.queue.async { self.finish(reply) } }
        }
    }

    func cancel() { queue.async { self.finish(nil) } }

    private func finish(_ reply: Data?) {
        guard !finished else { return }
        finished = true
        timer?.cancel()
        timer = nil
        connection?.invalidationHandler = nil
        connection?.interruptionHandler = nil
        connection?.invalidate()
        connection = nil
        continuation?.resume(returning: reply)
        continuation = nil
    }
}
