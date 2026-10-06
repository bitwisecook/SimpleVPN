// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin

/// Private provider IPC. Never included in telemetry, diagnostics or preferences.
nonisolated struct SSHAgentSigningRequest: Codable, Sendable {
    var id: UUID
    var request: Data
}
nonisolated struct SSHAgentSigningResponse: Codable, Sendable {
    var id: UUID
    var response: Data
}

/// A local agent-protocol socket for libssh, with the signing operation carried
/// over the app's NETunnelProviderSession instead of a cross-user filesystem.
nonisolated final class SSHAgentSigningBroker: @unchecked Sendable {
    private let condition = NSCondition()
    private var stopped = false
    private var pending: SSHAgentSigningRequest?
    private var answer: Data?
    private var client: Int32
    private var server: Int32
    private let timeout: TimeInterval

    init(timeout: TimeInterval = 120) throws {
        var pair: [Int32] = [-1,-1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw NSError(domain:"SimpleVPN.SSHAgent",code:1,userInfo:[NSLocalizedDescriptionKey:"The signing broker could not start."])
        }
        client=pair[0]; server=pair[1]; self.timeout=timeout
        var noSignal: Int32=1
        for fd in pair {
            _=setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,socklen_t(MemoryLayout<Int32>.size))
        }
        DispatchQueue.global(qos:.userInitiated).async { [self] in serve() }
    }
    /// libssh owns the duplicate. Shutdown of the original interrupts it too.
    func descriptor() -> Int32 {
        condition.lock(); defer { condition.unlock() }
        return stopped ? -1 : dup(client)
    }
    func snapshot() -> SSHAgentSigningRequest? {
        condition.lock(); defer { condition.unlock() }
        return stopped ? nil : pending
    }
    @discardableResult func reply(_ response: SSHAgentSigningResponse) -> Bool {
        condition.lock(); defer { condition.unlock() }
        guard !stopped, answer == nil, pending?.id == response.id,
              Self.validFrame(response.response), [UInt8(5),12,14].contains(response.response[4]) else { return false }
        answer=response.response; condition.broadcast(); return true
    }
    func stop() {
        condition.lock(); defer { condition.unlock() }
        guard !stopped else { return }
        stopped=true; pending=nil; answer=nil
        _=shutdown(client,SHUT_RDWR); _=shutdown(server,SHUT_RDWR)
        condition.broadcast()
        // The reader owns server close; client cannot be reused while borrowed.
        Darwin.close(client); client = -1
    }
    private func serve() {
        defer { condition.lock(); Darwin.close(server); server = -1; condition.unlock() }
        while true {
            guard let header=read(count:4) else { return }
            let length=header.reduce(0){($0 << 8)|Int($1)}
            guard (1...262144).contains(length), let body=read(count:length) else { return }
            guard body.first == 11 || body.first == 13 else { _=write(Data([0,0,0,1,5])); return }
            condition.lock()
            guard !stopped else { condition.unlock(); return }
            pending = .init(id:UUID(),request:header+body)
            let deadline=Date().addingTimeInterval(timeout)
            while !stopped && answer == nil {
                if !condition.wait(until:deadline) { break }
            }
            let response=answer
            pending=nil; answer=nil
            let ended=stopped
            condition.unlock()
            guard !ended else { return }
            guard write(response ?? Data([0,0,0,1,5])) else { return }
        }
    }
    private static func validFrame(_ data: Data) -> Bool {
        guard (5...262148).contains(data.count) else { return false }
        return data.prefix(4).reduce(0){($0 << 8)|Int($1)} == data.count-4
    }
    private func read(count: Int) -> Data? {
        var data=Data(count:count), offset=0
        while offset<count {
            let got=data.withUnsafeMutableBytes { Darwin.recv(server,$0.baseAddress!.advanced(by:offset),count-offset,0) }
            if got<0 && errno == EINTR { continue }; guard got>0 else { return nil }; offset+=got
        }
        return data
    }
    private func write(_ data: Data) -> Bool {
        var offset=0
        while offset<data.count {
            let sent=data.withUnsafeBytes { Darwin.send(server,$0.baseAddress!.advanced(by:offset),data.count-offset,0) }
            if sent<0 && errno == EINTR { continue }; guard sent>0 else { return false }; offset+=sent
        }
        return true
    }
}
