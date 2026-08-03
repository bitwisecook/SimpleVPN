// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ControlServer.swift
//  Hosts the control surface for OUT-OF-PROCESS interfaces (the `simplevpn` CLI
//  today; anything local later) on a UNIX-domain socket. Protocol: JSON lines —
//  one ControlRequestEnvelope per line in, one ControlReplyEnvelope per line out,
//  plus bare ControlEvent objects pushed after a {"watch":true} subscription.
//
//  SECURITY: same-user only by construction — the socket lives in the user's own
//  ~/Library/Application Support/SimpleVPN/ with mode 0600. Nothing here
//  authenticates beyond that because filesystem permissions ARE the boundary
//  (the app is per-user; root can do anything anyway). Credential material never
//  crosses this socket: the wire vocabulary simply has no command that carries a
//  secret (typed-credential connect is in-process only — executeTypedConnect).
//
//  ISOLATION (the PFRouteMonitor lesson): accept/read/write run on a private
//  dispatch queue, so every member here is explicitly `nonisolated`, the
//  lock-guarded mutable state is `nonisolated(unsafe)`, and handlers are
//  @Sendable. Each parsed request hops to the MainActor dispatcher and the reply
//  hops back to the queue for writing — the dispatcher is the only main-actor
//  touchpoint.
//

import Foundation
import Darwin

final class ControlServer: @unchecked Sendable {
    // @unchecked Sendable: all mutable state is guarded by `lock`; sources hold weak self.
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.control-server")
    nonisolated(unsafe) private var acceptSource: DispatchSourceRead?
    nonisolated(unsafe) private var listenFD: Int32 = -1
    nonisolated(unsafe) private var connections: [Int32: Connection] = [:]
    /// Main-actor entry — resolved per request via a MainActor hop.
    nonisolated(unsafe) private weak var dispatcher: ControlPlaneDispatcher?

    /// One accepted client: its read source, partial-line buffer, and (when it
    /// subscribed) the watch task streaming events back. All fields are guarded
    /// by the OUTER `lock` — `nonisolated(unsafe)` opts them out of the target's
    /// MainActor default (member-level, because a class-level `nonisolated`
    /// wouldn't propagate — the PFRouteMonitor lesson).
    private final class Connection {
        nonisolated(unsafe) var source: DispatchSourceRead?
        nonisolated(unsafe) var buffer = Data()
        nonisolated(unsafe) var watchTask: Task<Void, Never>?
        nonisolated init() {}
    }

    nonisolated init() {}
    deinit { stop() }

    // MARK: Lifecycle

    /// Bind + listen + accept. Idempotent; safe to call at app launch.
    @MainActor
    func start(dispatcher: ControlPlaneDispatcher) {
        lock.lock()
        guard listenFD < 0 else { lock.unlock(); return }
        self.dispatcher = dispatcher
        lock.unlock()

        let path = ControlSocket.path()
        try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        unlink(path)   // a stale socket from a crashed run would break bind()

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let ok = withUnsafeMutableBytes(of: &addr.sun_path) { raw -> Bool in
            let bytes = Array(path.utf8)
            guard bytes.count < raw.count else { return false }   // sun_path is 104 bytes
            raw.copyBytes(from: bytes)
            return true
        }
        guard ok,
              (withUnsafePointer(to: &addr) {
                  $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                  }
              }) == 0,
              listen(fd, 8) == 0 else {
            close(fd)
            return
        }
        chmod(path, 0o600)   // same-user only — this IS the auth boundary

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let onAccept: @Sendable () -> Void = { [weak self] in self?.acceptOne(fd) }
        source.setEventHandler(handler: onAccept)
        source.setCancelHandler(handler: { close(fd); unlink(path) })

        lock.lock()
        listenFD = fd
        acceptSource = source
        lock.unlock()
        source.resume()
    }

    nonisolated func stop() {
        let (doomedAccept, doomedConnections): (DispatchSourceRead?, [Int32: Connection]) = lock.withLock {
            defer { acceptSource = nil; listenFD = -1; connections = [:] }
            return (acceptSource, connections)
        }
        doomedAccept?.cancel()
        for (_, c) in doomedConnections {
            c.watchTask?.cancel()
            c.source?.cancel()
        }
    }

    // MARK: Accept / read (on `queue`)

    nonisolated private func acceptOne(_ listenFD: Int32) {
        let fd = accept(listenFD, nil, nil)
        guard fd >= 0 else { return }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)

        let connection = Connection()
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let onRead: @Sendable () -> Void = { [weak self] in self?.readSome(fd) }
        let onCancel: @Sendable () -> Void = { close(fd) }
        source.setEventHandler(handler: onRead)
        source.setCancelHandler(handler: onCancel)
        connection.source = source
        lock.withLock { connections[fd] = connection }
        source.resume()
    }

    nonisolated private func readSome(_ fd: Int32) {
        var scratch = [UInt8](repeating: 0, count: 16_384)
        let n = scratch.withUnsafeMutableBytes { raw in
            recv(fd, raw.baseAddress, raw.count, 0)
        }
        guard n > 0 else { dropConnection(fd); return }

        let lines: [Data] = lock.withLock {
            guard let c = connections[fd] else { return [] }
            c.buffer.append(contentsOf: scratch[0..<n])
            // A runaway line with no newline is a misbehaving client, not a request.
            if c.buffer.count > 1_048_576 { c.buffer.removeAll() ; return [] }
            var out: [Data] = []
            while let nl = c.buffer.firstIndex(of: 0x0A) {
                out.append(c.buffer.subdata(in: c.buffer.startIndex..<nl))
                c.buffer.removeSubrange(c.buffer.startIndex...nl)
            }
            return out
        }
        for line in lines where !line.isEmpty { handle(line, from: fd) }
    }

    nonisolated private func dropConnection(_ fd: Int32) {
        let doomed: Connection? = lock.withLock {
            defer { connections[fd] = nil }
            return connections[fd]
        }
        doomed?.watchTask?.cancel()
        doomed?.source?.cancel()
    }

    // MARK: Requests (hop to MainActor, reply on `queue`)

    nonisolated private func handle(_ line: Data, from fd: Int32) {
        guard let request = try? JSONDecoder().decode(ControlRequestEnvelope.self, from: line) else {
            // Not decodable → we may not even have an id to echo. Best effort.
            let id = (try? JSONDecoder().decode(BareID.self, from: line))?.id ?? 0
            send(ControlReplyEnvelope(id: id, reply: .failed("bad request — expected {\"id\":n,\"cmd\":…}/{\"id\":n,\"query\":…}/{\"id\":n,\"watch\":true}")), to: fd)
            return
        }
        Task { @MainActor [weak self] in
            guard let self, let dispatcher = self.dispatcher else { return }
            if request.watch == true {
                self.startWatch(request.id, on: fd, dispatcher: dispatcher)
                self.send(ControlReplyEnvelope(id: request.id, reply: .ok), to: fd)
            } else if let command = request.command {
                let reply = await dispatcher.execute(command)
                self.send(ControlReplyEnvelope(id: request.id, reply: reply), to: fd)
            } else if let query = request.query {
                self.send(ControlReplyEnvelope(id: request.id, reply: dispatcher.query(query)), to: fd)
            } else {
                self.send(ControlReplyEnvelope(id: request.id, reply: .failed("empty request")), to: fd)
            }
        }
    }

    nonisolated private struct BareID: Decodable { var id: Int }

    @MainActor
    private func startWatch(_ id: Int, on fd: Int32, dispatcher: ControlPlaneDispatcher) {
        let stream = dispatcher.subscribe()
        let task = Task { [weak self] in
            for await event in stream {
                guard let self, !Task.isCancelled else { return }
                self.sendEvent(event, to: fd)
            }
        }
        lock.withLock { connections[fd]?.watchTask?.cancel(); connections[fd]?.watchTask = task }
    }

    // MARK: Writes (serialized on `queue`)

    nonisolated private func send(_ envelope: ControlReplyEnvelope, to fd: Int32) {
        guard let data = try? JSONEncoder().encode(envelope) else { return }
        write(data, to: fd)
    }

    nonisolated private func sendEvent(_ event: ControlEvent, to fd: Int32) {
        guard let data = try? JSONEncoder().encode(event) else { return }
        write(data, to: fd)
    }

    nonisolated private func write(_ payload: Data, to fd: Int32) {
        let line = payload + Data([0x0A])
        let work: @Sendable () -> Void = { [weak self] in
            let stillOpen: Bool = self?.lock.withLock { self?.connections[fd] != nil } ?? false
            guard stillOpen else { return }
            line.withUnsafeBytes { raw in
                var sent = 0
                while sent < raw.count {
                    let n = Darwin.send(fd, raw.baseAddress!.advanced(by: sent), raw.count - sent, 0)
                    if n <= 0 { break }   // client gone / buffer full — reader will reap it
                    sent += n
                }
            }
        }
        queue.async(execute: work)
    }
}
