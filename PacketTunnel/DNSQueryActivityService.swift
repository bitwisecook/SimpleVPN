// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// The system extension runs outside the login session. Its declared Mach service
/// returns counters only to the signed app running as the policy's configuring user.
final class DNSQueryActivityService: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    static let shared = DNSQueryActivityService()
    private let listener = NSXPCListener(machServiceName: DNSQueryActivityWire.serviceName)
    private let lock = NSLock()
    private struct Active {
        let session: UUID
        let ownerUID: UInt32
        let generation: Data
        let forwarder: DNSQueryForwarder
    }
    private var active: Active?

    private override init() {
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func start(_ forwarder: DNSQueryForwarder, generation: Data, ownerUID: UInt32) -> UUID {
        let session = UUID()
        lock.withLock { active = Active(session: session, ownerUID: ownerUID, generation: generation, forwarder: forwarder) }
        return session
    }

    func stop(_ session: UUID) {
        lock.withLock { if active?.session == session { active = nil } }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let uid = connection.effectiveUserIdentifier
        guard lock.withLock({ active?.ownerUID == uid }) else { return false }
        connection.setCodeSigningRequirement(DNSQueryActivityWire.clientRequirement)
        connection.exportedInterface = NSXPCInterface(with: DNSQueryActivityReading.self)
        connection.exportedObject = Endpoint(service: self, uid: uid)
        connection.resume()
        return true
    }

    private final class Endpoint: NSObject, DNSQueryActivityReading {
        let service: DNSQueryActivityService
        let uid: UInt32
        init(service: DNSQueryActivityService, uid: UInt32) {
            self.service = service
            self.uid = uid
        }
        func readCounts(_ generation: Data, withReply reply: @escaping @Sendable (Data?) -> Void) {
            guard generation.count == 32,
                  let run = service.lock.withLock({ service.active }),
                  run.ownerUID == uid, run.generation == generation else { reply(nil); return }
            let service = self.service
            Task {
                let rows = await run.forwarder.activityCounts()
                guard service.lock.withLock({ service.active?.session == run.session }) else { reply(nil); return }
                reply(try? JSONEncoder().encode(DNSQueryActivity(session: run.session, generation: generation, rows: rows)))
            }
        }
    }
}
