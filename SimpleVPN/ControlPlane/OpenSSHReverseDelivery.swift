// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation
import SSHProxyCodec
@preconcurrency import Network

/// A reverse SSH server may select only an endpoint previously registered by this session.
/// OpenSSH connects to that endpoint over a private Unix socket. Its kernel-reported PID
/// must match the supervised master before a handler can authorize the saved local target.
nonisolated final class OpenSSHReverseDelivery: @unchecked Sendable {
    static let adapter = "ssh-openssh-reverse"
    struct Mapping: Sendable {
        let remote: String
        let host: String
        let port: Int
    }

    enum LocalTarget: Sendable {
        case dynamic
        case fixed(String, Int)
    }
    struct Local: Sendable {
        let bind: String
        let port: UInt16
        let target: LocalTarget
    }
    struct Layout: Sendable {
        var reverse: [Mapping] = []
        var local: [Local] = []
        var adapter: String { local.isEmpty ? OpenSSHReverseDelivery.adapter : "ssh-openssh" }
    }

    @MainActor static func layout(for config: SubprocessTunnelConfig) -> Layout? {
        guard config.kind == .ssh, config.sshMode != .netTunnel,
              SubprocessTunnelManager.sshPinnedKey(config) == nil else { return nil }
        // Only options that cannot open another forwarding channel, run a command
        // or transfer our authenticated session to a different master.
        let allowedOptions: Set<String> = ["ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
            "pubkeyacceptedalgorithms", "userknownhostsfile", "globalknownhostsfile", "hostkeyalias",
            "addressfamily", "ipqos", "tcpkeepalive", "serveralivecountmax", "rekeylimit",
            "checkhostip", "verifyhostkeydns", "updatehostkeys", "batchmode", "compression"]
        for option in config.sshExtraOptions where !option.trimmingCharacters(in: .whitespaces).isEmpty {
            guard !option.contains(where: { $0.isNewline }), !option.utf8.contains(0),
                  let keyword = option.split(whereSeparator: { $0 == "=" || $0.isWhitespace }).first,
                  allowedOptions.contains(keyword.lowercased()) else { return nil }
        }
        var layout = Layout()
        let lines = config.sshMode == .socks ? ["D " + String(config.socksPort)] : config.forwards
        for line in lines where !line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard layout.local.count + layout.reverse.count < 64,
                  let row = SubprocessTunnelManager.parseForward(line) else { return nil }
            if row.flag == "D" {
                let fields = SSHTunnelEngine.forwardFields(row.spec)
                guard (1...2).contains(fields.count), let text = fields.last, let port = UInt16(text), port > 0 else { return nil }
                layout.local.append(Local(bind: fields.count == 2 ? fields[0] : "127.0.0.1", port: port, target: .dynamic))
                continue
            }
            guard let (listening, host, port, bind) = SSHTunnelEngine.localForwardParts(row.spec) else { return nil }
            if row.flag == "L" {
                layout.local.append(Local(bind: bind, port: UInt16(listening), target: .fixed(host, port)))
            } else if row.flag == "R", let split = row.spec.lastIndex(of: ":") {
                let beforePort = row.spec[..<split]
                let suffix = ":" + NetworkEndpoint.authority(host: host)
                guard beforePort.hasSuffix(suffix) else { return nil }
                layout.reverse.append(Mapping(remote: String(beforePort.dropLast(suffix.count)), host: host, port: port))
            } else { return nil }
        }
        return layout.local.isEmpty && layout.reverse.isEmpty ? nil : layout
    }

    @MainActor static func mappings(for config: SubprocessTunnelConfig) -> [Mapping]? {
        guard let layout = layout(for: config), layout.local.isEmpty else { return nil }
        return layout.reverse
    }

    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.reverse-delivery", qos: .userInitiated)
    private var listeners: [DispatchSourceRead] = []
    private let directory: String
    private let policy: SSHForwardPolicy
    private var stopped = false
    private var master: Process?
    private var masterBirth: Birth?

    private struct Birth: Equatable {
        let seconds: UInt64
        let microseconds: UInt64

        init?(child pid: pid_t) {
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
                  info.pbi_pid == UInt32(pid), info.pbi_ppid == UInt32(getpid()) else { return nil }
            seconds = info.pbi_start_tvsec
            microseconds = info.pbi_start_tvusec
        }
    }
    private var flows: [UUID: ReverseStream] = [:]
    private var totals = SSHChannelCounters()
    private(set) var forwardArguments: [String] = []

    private var publicListeners: [NWListener] = []
    private var privatePaths: [String] = []
    let needsRemoteAcknowledgement: Bool

    convenience init(mappings: [Mapping], source: String) throws {
        try self.init(layout: Layout(reverse: mappings), source: source)
    }

    init(layout: Layout, source: String) throws {
        policy = try SSHForwardPolicy(source: source, adapter: layout.adapter)
        needsRemoteAcknowledgement = !layout.reverse.isEmpty
        var template = Array("/private/tmp/svpn-reverse.XXXXXX".utf8CString)
        guard let path = mkdtemp(&template) else { throw POSIXError(.EIO) }
        directory = String(cString: path)
        do {
            for (index, mapping) in layout.reverse.enumerated() {
                let path = directory + "/s\(index)"
                let fd = try Self.listen(path)
                let listener = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
                listener.setEventHandler { [weak self] in self?.accept(fd, mapping: mapping) }
                listener.setCancelHandler { close(fd) }
                privatePaths.append(path)
                listeners.append(listener)
                forwardArguments += ["-R", mapping.remote + ":" + path]
                listener.resume()
            }
            for (index, local) in layout.local.enumerated() {
                let path = directory + "/l\(index)"
                privatePaths.append(path)
                switch local.target {
                case .dynamic: forwardArguments += ["-D", path]
                case .fixed(let host, let port):
                    forwardArguments += ["-L", path + ":" + NetworkEndpoint.authority(host: host, port: port)]
                }
                let parameters = NWParameters.tcp
                let host = local.bind.isEmpty || local.bind == "*" ? "0.0.0.0" : local.bind
                parameters.requiredLocalEndpoint = .hostPort(host: .init(host), port: .init(rawValue: local.port)!)
                let listener = try NWListener(using: parameters)
                listener.newConnectionHandler = { [weak self] connection in
                    guard let self else { connection.cancel(); return }
                    queue.async { self.openLocal(connection, target: local.target, path: path) }
                }
                publicListeners.append(listener)
            }
        } catch {
            stop()
            throw error
        }
    }

    func startListeners() async throws {
        do {
            for listener in publicListeners { try await SSHTunnelEngine.startAndAwaitReady(listener) }
        } catch { stop(); throw error }
    }

    private func openLocal(_ connection: NWConnection, target: LocalTarget, path: String) {
        guard !stopped, flows.count < 128, let master, let masterBirth,
              Birth(child: master.processIdentifier) == masterBirth, master.isRunning else { connection.cancel(); return }
        var gate: ((Data, Bool) -> ForwardGateResult)?
        func admit(_ host: String, _ port: Int, _ mode: String) -> Bool {
            totals.requested &+= 1
            if policy.permits(target: host, port: port, mode: mode) { return true }
            totals.denied &+= 1
            return false
        }
        switch target {
        case .fixed(let host, let port):
            guard admit(host, port, "local") else { connection.cancel(); return }
        case .dynamic:
            let parser = DynamicForwardGate()
            gate = { [weak self] data, eof in
                guard let self else { return .close }
                return parser.filter(data, eof: eof) { host, port in
                    self.totals.requested &+= 1
                    if self.policy.permits(target: host, port: port, mode: "dynamic") { return true }
                    self.totals.denied &+= 1
                    return false
                }
            }
        }
        guard let fd = Self.connectPrivate(path, master: master.processIdentifier) else { connection.cancel(); return }
        guard let flow = ReverseStream(fd: fd, target: connection, queue: queue) else { close(fd); connection.cancel(); return }
        let id = UUID()
        flows[id] = flow
        flow.start(filter: gate, onOpen: { [weak self] in
            if case .fixed = target { self?.totals.opened &+= 1 }
        }, admitted: { [weak self] in self?.totals.opened &+= 1 }, transferred: { [weak self] incoming, count in
            if incoming { self?.totals.bytesReceived &+= UInt64(count) }
            else { self?.totals.bytesSent &+= UInt64(count) }
        }, finished: { [weak self] in self?.flows.removeValue(forKey: id) })
    }

    private static func connectPrivate(_ path: String, master: pid_t) -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        var peer: pid_t = -1
        var size = socklen_t(MemoryLayout<pid_t>.size)
        let fits = withUnsafeMutableBytes(of: &address.sun_path) { raw in
            guard path.utf8.count < raw.count else { return false }
            raw.copyBytes(from: path.utf8)
            return true
        }
        guard fits, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              withUnsafePointer(to: &address, { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                  Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
              } }) == 0, getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &size) == 0, peer == master
        else { close(fd); return nil }
        return fd
    }

    private static func listen(_ path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.ENFILE) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let ok = withUnsafeMutableBytes(of: &address.sun_path) { raw in
            guard path.utf8.count < raw.count else { return false }
            raw.copyBytes(from: path.utf8)
            return true
        }
        guard ok, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              withUnsafePointer(to: &address, { pointer in
                  pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                      bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                  }
              }) == 0 else {
            close(fd)
            throw SSHForwardError("Could not open a private SSH delivery socket.")
        }
        guard Darwin.listen(fd, 16) == 0 else {
            close(fd)
            unlink(path)
            throw SSHForwardError("Could not listen for protected SSH deliveries.")
        }
        return fd
    }

    func authorize(_ process: Process) -> Bool {
        queue.sync {
            guard !stopped, let birth = Birth(child: process.processIdentifier), process.isRunning else { return false }
            master = process
            masterBirth = birth
            return true
        }
    }

    func snapshot() async -> SSHChannelCounters {
        await withCheckedContinuation { reply in
            queue.async {
                var result = self.totals
                result.rules = self.policy.counters
                result.active = self.flows.count
                reply.resume(returning: result)
            }
        }
    }

    private func accept(_ fd: Int32, mapping: Mapping) {
        for _ in 0..<16 {
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { return }
            var peer: pid_t = -1
            var size = socklen_t(MemoryLayout<pid_t>.size)
            guard let master, let masterBirth,
                  getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peer, &size) == 0,
                  peer == master.processIdentifier, Birth(child: peer) == masterBirth, master.isRunning else { close(client); continue }
            totals.requested &+= 1
            guard flows.count < 128,
                  policy.permits(target: mapping.host, port: mapping.port, mode: "remote", direction: "inbound"),
                  let stream = ReverseStream(fd: client, mapping: mapping, queue: queue) else {
                totals.denied &+= 1
                close(client)
                continue
            }
            let id = UUID()
            flows[id] = stream
            stream.start(onOpen: { [weak self] in self?.totals.opened &+= 1 },
                         transferred: { [weak self] incoming, count in
                             if incoming { self?.totals.bytesReceived &+= UInt64(count) }
                             else { self?.totals.bytesSent &+= UInt64(count) }
                         }, finished: { [weak self] in self?.flows.removeValue(forKey: id) })
        }
    }

    func stop() {
        queue.sync {
            guard !stopped else { return }
            stopped = true
            master = nil
            masterBirth = nil
            for listener in listeners { listener.cancel() }
            listeners.removeAll()
            for flow in Array(flows.values) { flow.stop() }
            // Only unlink the exact sockets created by this session.
            for listener in publicListeners { listener.cancel() }
            for path in privatePaths { unlink(path) }
            rmdir(directory)
        }
    }
}

// Each direction holds at most one 16 KiB chunk. Read readiness is suspended until
// the target finishes its send. DispatchIO writes apply the same backpressure to
// Network.framework receives. Both half-closes are forwarded independently.
private nonisolated final class ReverseStream: @unchecked Sendable {
    private let fd: Int32
    private let writerFD: Int32
    private let readSource: DispatchSourceRead
    private let writer: DispatchIO
    private let target: NWConnection
    private let queue: DispatchQueue
    private var paused = true
    private var stopped = false
    private var readEOF = false
    private var writeEOF = false
    private var ready = false
    private var transferred: ((Bool, Int) -> Void)?
    private var finished: (() -> Void)?

    private var filter: ((Data, Bool) -> ForwardGateResult)?
    private var admitted: (() -> Void)?
    private var awaitingAdmission = false

    convenience init?(fd: Int32, mapping: OpenSSHReverseDelivery.Mapping, queue: DispatchQueue) {
        guard let port = NWEndpoint.Port(rawValue: UInt16(mapping.port)) else { return nil }
        self.init(fd: fd, target: NWConnection(host: NWEndpoint.Host(mapping.host), port: port, using: .tcp), queue: queue)
    }
    init?(fd: Int32, target: NWConnection, queue: DispatchQueue) {
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else { return nil }
        let copy = fcntl(fd, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else { return nil }
        self.fd = fd
        writerFD = copy
        self.queue = queue
        readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        readSource.setCancelHandler { close(fd) }
        writer = DispatchIO(type: .stream, fileDescriptor: copy, queue: queue) { _ in close(copy) }
        self.target = target
    }

    func start(filter: ((Data, Bool) -> ForwardGateResult)? = nil, onOpen: @escaping @Sendable () -> Void, admitted: (() -> Void)? = nil, transferred: @escaping (Bool, Int) -> Void,
               finished: @escaping () -> Void) {
        self.filter = filter
        awaitingAdmission = filter != nil
        self.admitted = admitted
        self.transferred = transferred
        self.finished = finished
        readSource.setEventHandler { [weak self] in self?.readClient() }
        target.stateUpdateHandler = { [weak self] state in
            guard let self, !stopped else { return }
            switch state {
            case .ready:
                guard !ready else { return }
                ready = true
                onOpen()
                resumeReader()
                readTarget()
            case .failed, .cancelled: stop()
            default: break
            }
        }
        target.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            if let self, !ready || awaitingAdmission { stop() }
        }
    }

    private func resumeReader() {
        if paused { paused = false; readSource.resume() }
    }

    private func readClient() {
        guard !stopped, !readEOF else { return }
        var data = Data(count: 16 * 1024)
        let count = data.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        if count < 0 {
            if errno != EAGAIN && errno != EINTR { stop() }
            return
        }
        paused = true
        readSource.suspend()
        if count == 0 {
            target.send(content: nil, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { [weak self] error in
                            guard let self, !stopped else { return }
                            readEOF = true
                            if error != nil || writeEOF { stop() }
                        })
        } else {
            data.count = count
            target.send(content: data, completion: .contentProcessed { [weak self] error in
                guard let self, !stopped else { return }
                if error != nil { stop(); return }
                transferred?(true, count)
                resumeReader()
            })
        }
    }

    private func readTarget() {
        target.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, eof, error in
            guard let self, !stopped else { return }
            guard error == nil else { stop(); return }
            var data = data ?? Data()
            if let filter {
                switch filter(data, eof) {
                case .wait: readTarget(); return
                case .close: stop(); return
                case .reject(let reply):
                    target.send(content: reply, completion: .contentProcessed { [weak self] _ in self?.stop() })
                    return
                case .send(let bytes, let permitted):
                    data = bytes
                    if permitted { self.filter = nil; awaitingAdmission = false; admitted?() }
                }
            }
            guard !data.isEmpty else { completeTargetRead(eof); return }
            let count = data.count
            let chunk = data.withUnsafeBytes { DispatchData(bytes: $0) }
            writer.write(offset: 0, data: chunk, queue: queue) { [weak self] done, _, error in
                guard let self, !stopped else { return }
                if error != 0 { stop(); return }
                if done {
                    transferred?(false, count)
                    completeTargetRead(eof)
                }
            }
        }
    }

    private func completeTargetRead(_ eof: Bool) {
        if eof {
            writeEOF = true
            shutdown(writerFD, SHUT_WR)
            if readEOF { stop() }
        } else { readTarget() }
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        readSource.cancel()
        resumeReader()
        writer.close(flags: .stop)
        target.cancel()
        finished?()
    }
}

private enum ForwardGateResult {
    case wait, close, reject(Data), send(Data, permitted: Bool)
}

/// The private OpenSSH SOCKS listener only sees a CONNECT after policy admission.
/// Method negotiation may proceed without opening a remote SSH channel.
private nonisolated final class DynamicForwardGate {
    private var pending = Data()
    private var greeted = false
    func filter(_ data: Data, eof: Bool, admit: (String, Int) -> Bool) -> ForwardGateResult {
        pending.append(data)
        var greeting = Data()
        if !greeted {
            do {
                guard let value = try LocalSOCKS.greeting(pending) else { return eof ? .close : .wait }
                guard value.accepted else { return .reject(LocalSOCKS.selection(accepted: false)) }
                greeting = Data(pending.prefix(value.consumed))
                pending = Data(pending.dropFirst(value.consumed))
                greeted = true
            } catch { return .close }
        }
        switch LocalSOCKS.request(pending) {
        case .incomplete:
            if eof { return .close }
            return greeting.isEmpty ? .wait : .send(greeting, permitted: false)
        case .invalid(let status): return .reject(greeting.isEmpty ? LocalSOCKS.response(status) : LocalSOCKS.selection(accepted: true) + LocalSOCKS.response(status))
        case .connect(let host, let port, _):
            guard admit(host, port) else {
                let reply = LocalSOCKS.response(2)
                return .reject(greeting.isEmpty ? reply : LocalSOCKS.selection(accepted: true) + reply)
            }
            return .send(greeting + pending, permitted: true)
        }
    }
}
