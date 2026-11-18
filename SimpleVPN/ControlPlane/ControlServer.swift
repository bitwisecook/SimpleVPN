// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ControlServer.swift
//  Hosts the control surface for OUT-OF-PROCESS interfaces (the `simplevpn` CLI
//  today; anything local later) on a UNIX-domain socket. Protocol: JSON lines —
//  one ControlRequestEnvelope per line in, one ControlReplyEnvelope per line out,
//  plus bare ControlEvent objects pushed after a {"watch":true} subscription.
//
//  SECURITY: the socket lives in the user's Application Support with mode 0600.
//  getpeereid verifies the effective user on every accepted socket. Credential material never
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
    nonisolated(unsafe) private var socketLockFD: Int32 = -1
    nonisolated(unsafe) private var connections: [Int32: Connection] = [:]
    /// Main-actor entry — resolved per request via a MainActor hop.
    nonisolated(unsafe) private weak var dispatcher: ControlPlaneDispatcher?

    /// One accepted client: its read source, partial-line buffer, and (when it
    /// subscribed) the watch task streaming events back. All fields are guarded
    /// by the OUTER `lock` — `nonisolated(unsafe)` opts them out of the target's
    /// MainActor default (member-level, because a class-level `nonisolated`
    /// wouldn't propagate — the PFRouteMonitor lesson).
    private nonisolated final class Connection: @unchecked Sendable {
        let fd: Int32
        nonisolated(unsafe) var source: DispatchSourceRead?
        nonisolated(unsafe) var buffer = Data()
        nonisolated(unsafe) var watchTask: Task<Void, Never>?
        init(fd: Int32) { self.fd = fd }
    }

    nonisolated init() {}
    deinit { stop() }

    // MARK: Lifecycle

    /// Bind + listen + accept. Idempotent; safe to call at app launch.
    @MainActor
    func start(dispatcher: ControlPlaneDispatcher) {
        lock.lock()
        defer { lock.unlock() }
        guard listenFD < 0 else { return }
        let path = ControlSocket.path()
        do {
            try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { return }
        // A test host or second installation must not unlink a live listener.
        let owner = open(path + ".lock", O_RDWR | O_CREAT | O_EXLOCK | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard owner >= 0 else { return }
        defer { if socketLockFD != owner { close(owner) } }
        unlink(path)
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
              chmod(path, 0o600) == 0, configureDescriptor(fd), listen(fd, 8) == 0 else {
            close(fd)
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let onAccept: @Sendable () -> Void = { [weak self] in self?.acceptOne(fd) }
        source.setEventHandler(handler: onAccept)
        source.setCancelHandler(handler: { close(fd) })

        self.dispatcher = dispatcher
        listenFD = fd
        socketLockFD = owner
        acceptSource = source
        source.resume()
    }

    nonisolated func stop() {
        let (doomedAccept, doomedConnections): (DispatchSourceRead?, [Int32: Connection]) = lock.withLock {
            if socketLockFD >= 0 {
                unlink(ControlSocket.path())
                close(socketLockFD)
                socketLockFD = -1
            }
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

    nonisolated private func configureDescriptor(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL, 0)
        return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
            && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0
    }

    nonisolated private func acceptOne(_ listenFD: Int32) {
        let fd = accept(listenFD, nil, nil)
        guard fd >= 0 else { return }
        var uid = uid_t(), gid = gid_t()
        guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid(), configureDescriptor(fd) else {
            close(fd)
            return
        }

        var noSignal: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            close(fd)
            return
        }
        let connection = Connection(fd: fd)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let onRead: @Sendable () -> Void = { [weak self, weak connection] in
            if let connection { self?.readSome(connection) }
        }
        let onCancel: @Sendable () -> Void = { close(fd) }
        source.setEventHandler(handler: onRead)
        source.setCancelHandler(handler: onCancel)
        connection.source = source
        let active = lock.withLock {
            guard self.listenFD == listenFD else { return false }
            connections[fd] = connection
            return true
        }
        if !active { source.cancel() }
        source.resume()
    }

    nonisolated private func readSome(_ client: Connection) {
        var scratch = [UInt8](repeating: 0, count: 16_384)
        let n = scratch.withUnsafeMutableBytes { raw in
            recv(client.fd, raw.baseAddress, raw.count, 0)
        }
        if n < 0 && (errno == EAGAIN || errno == EINTR) { return }
        guard n > 0 else { dropConnection(client); return }

        let lines: [Data]? = lock.withLock {
            guard let c = connections[client.fd], c === client else { return [] }
            c.buffer.append(contentsOf: scratch[0..<n])
            // A runaway line with no newline is a misbehaving client, not a request.
            if c.buffer.count > 1_048_576 { return nil }
            var out: [Data] = []
            while let nl = c.buffer.firstIndex(of: 0x0A) {
                out.append(c.buffer.subdata(in: c.buffer.startIndex..<nl))
                c.buffer.removeSubrange(c.buffer.startIndex...nl)
            }
            return out
        }
        guard let lines else { dropConnection(client); return }
        for line in lines where !line.isEmpty { handle(line, from: client) }
    }

    nonisolated private func dropConnection(_ client: Connection) {
        let doomed: Connection? = lock.withLock {
            guard connections[client.fd] === client else { return nil }
            return connections.removeValue(forKey: client.fd)
        }
        doomed?.watchTask?.cancel()
        doomed?.source?.cancel()
    }

    // MARK: Requests (hop to MainActor, reply on `queue`)

    nonisolated private func handle(_ line: Data, from client: Connection) {
        guard let request = try? JSONDecoder().decode(ControlRequestEnvelope.self, from: line) else {
            // Not decodable → we may not even have an id to echo. Best effort.
            let id = (try? JSONDecoder().decode(BareID.self, from: line))?.id ?? 0
            send(ControlReplyEnvelope(id: id, reply: .failed("bad request — expected {\"id\":n,\"cmd\":…}/{\"id\":n,\"query\":…}/{\"id\":n,\"watch\":true}")), to: client)
            return
        }
        Task { @MainActor [weak self] in
            guard let self, self.isCurrent(client), let dispatcher = self.dispatcher else { return }
            if request.watch == true {
                self.startWatch(on: client, dispatcher: dispatcher)
                self.send(ControlReplyEnvelope(id: request.id, reply: .ok), to: client)
            } else if let command = request.command {
                let reply = await dispatcher.execute(command)
                self.send(ControlReplyEnvelope(id: request.id, reply: reply), to: client)
            } else if let query = request.query {
                self.send(ControlReplyEnvelope(id: request.id, reply: dispatcher.query(query)), to: client)
            } else {
                self.send(ControlReplyEnvelope(id: request.id, reply: .failed("empty request")), to: client)
            }
        }
    }

    nonisolated private struct BareID: Decodable { var id: Int }

    @MainActor
    private func startWatch(on client: Connection, dispatcher: ControlPlaneDispatcher) {
        let stream = dispatcher.subscribe()
        let task = Task { [weak self, weak client] in
            for await event in stream {
                guard let self, let client, !Task.isCancelled else { return }
                self.sendEvent(event, to: client)
            }
        }
        let obsolete: Task<Void, Never>? = lock.withLock {
            guard connections[client.fd] === client else { return task }
            let previous = client.watchTask
            client.watchTask = task
            return previous
        }
        obsolete?.cancel()
    }

    nonisolated private func isCurrent(_ client: Connection) -> Bool {
        lock.withLock { connections[client.fd] === client }
    }

    // MARK: Writes (serialized on `queue`)

    nonisolated private func send(_ envelope: ControlReplyEnvelope, to client: Connection) {
        guard let data = try? JSONEncoder().encode(envelope) else { return }
        write(data, to: client)
    }

    nonisolated private func sendEvent(_ event: ControlEvent, to client: Connection) {
        guard let data = try? JSONEncoder().encode(event) else { return }
        write(data, to: client)
    }

    nonisolated private func write(_ payload: Data, to client: Connection) {
        let line = payload + Data([0x0A])
        let work: @Sendable () -> Void = { [weak self] in
            guard let self, self.isCurrent(client) else { return }
            line.withUnsafeBytes { raw in
                var sent = 0
                while sent < raw.count {
                    let n = Darwin.send(client.fd, raw.baseAddress!.advanced(by: sent), raw.count - sent, 0)
                    if n < 0 && errno == EINTR { continue }
                    // This is a framed protocol. A slow or disconnected client
                    // must never receive the next frame appended to a fragment.
                    guard n > 0 else { self.dropConnection(client); return }
                    sent += n
                }
            }
        }
        queue.async(execute: work)
    }
}
