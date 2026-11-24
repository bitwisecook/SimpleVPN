// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

private final class IdentityEndpoint: NSObject, SourceIdentityVerifying {
    private static let workers = DispatchSemaphore(value: 4)
    private let selectionAllowed: Bool
    init(selectionAllowed: Bool) { self.selectionAllowed = selectionAllowed }

    func inspect(_ request: Data, withReply reply: @escaping @Sendable (Data?) -> Void) {
        guard request.count <= SourceIdentityWire.maximumBytes, Self.workers.wait(timeout: .now()) == .success else { reply(nil); return }
        let selectionAllowed = self.selectionAllowed
        DispatchQueue.global(qos: .userInitiated).async {
            defer { Self.workers.signal() }
            guard let query = try? JSONDecoder().decode(SourceIdentityWire.Request.self, from: request) else { reply(nil); return }
            let result: SourceIdentityWire.Reply?
            switch query {
            case .file(let bookmark): result = selectionAllowed ? SourceVerifier.selectedFile(bookmark).map(SourceIdentityWire.Reply.identity) : nil
            case .process(let token): result = selectionAllowed ? SourceVerifier.process(token).map(SourceIdentityWire.Reply.process) : nil
            case .match(let token, let candidates):
                guard candidates.allSatisfy({ $0.processCriteria == nil }) else { reply(nil); return }
                if case .matched(let id) = SourceVerifier.match(token, candidates: candidates) { result = .match(id) }
                else { result = .match(nil) }
            case .matchProcessCriteria(let token, let candidates):
                result = .processCriteriaMatch(SourceVerifier.match(token, candidates: candidates))
            }
            reply(result.flatMap { try? JSONEncoder().encode($0) })
        }
    }
}

private final class ServiceDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Service listeners are initialized by xpc_main inside resume().
        // Require the signed caller on every accepted connection before resume.
        connection.setCodeSigningRequirement(SourceIdentityWire.hostRequirement)
        connection.exportedInterface = NSXPCInterface(with: SourceIdentityVerifying.self)
        // Only a regular user's client can request a file or PID selection.
        connection.exportedObject = IdentityEndpoint(selectionAllowed: geteuid() != 0 && geteuid() == connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }
}

private let delegate = ServiceDelegate()
private let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
