// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation
import Security

/// Delivers one answer per hop to the signed CLI launched by this SSH session.
/// The filesystem endpoint holds no credential. Both ancestry and the peer's
/// kernel-issued audit token are checked before any bytes enter its socket.
nonisolated final class SSHAskpass: @unchecked Sendable {
    struct Credential {
        let identity: String
        let password: String
    }
    static let directoryKey = "SIMPLEVPN_ASKPASS_DIR"
    static let hopKey = "SIMPLEVPN_ASKPASS_HOP"
    private static func identityKey(_ hop: String) -> String { "SIMPLEVPN_ASKPASS_ID_" + hop }
    private static let limit = 4096
    private let directory: String
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.askpass")
    private var listeners: [DispatchSourceRead] = []
    private var answers: [String: Data] = [:]
    private var master: Process?
    private(set) var environment: [String: String] = [:]
    private let requirement: SecRequirement

    init(target: Credential?, jump: Credential?) throws {
        var requirement: SecRequirement?
        let rule = #"anchor apple generic and identifier "simplevpn" and certificate leaf[subject.OU] = "QVUFB5676H""#
        guard SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess,
              let requirement else { throw POSIXError(.EACCES) }
        self.requirement = requirement
        var template = Array("/private/tmp/svpn-ap.XXXXXX".utf8CString)
        guard let path = mkdtemp(&template) else { throw POSIXError(.EACCES) }
        directory = String(cString: path)
        do {
            for (hop, credential) in [("target", target), ("jump", jump)] {
                guard let credential else { continue }
                let bytes = Data(credential.password.utf8)
                guard !bytes.isEmpty, bytes.count <= Self.limit,
                      !bytes.contains(0), !bytes.contains(10), !bytes.contains(13) else { throw POSIXError(.EINVAL) }
                let fd = try Self.endpoint(directory + "/" + hop, listener: true)
                // Reject partial writes as a framing error in the helper.
                var frame = Data([UInt8(bytes.count >> 8), UInt8(truncatingIfNeeded: bytes.count)])
                frame.append(bytes)
                answers[hop] = frame
                let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
                source.setEventHandler { [weak self] in self?.answer(fd, hop: hop) }
                source.setCancelHandler { close(fd) }
                listeners.append(source)
                environment[Self.identityKey(hop)] = credential.identity
            }
        } catch {
            // Dispatch sources must be resumed before their final release.
            for source in listeners { source.cancel(); source.resume() }
            listeners.removeAll()
            Self.unlinkEndpoints(directory)
            throw error
        }
        environment[Self.directoryKey] = directory
        environment[Self.hopKey] = "target"
    }

    func authorize(_ child: Process) {
        queue.sync {
            guard master == nil else { return }
            master = child
            for source in listeners { source.resume() }
        }
    }
    deinit {
        for source in listeners {
            source.cancel()
            if master == nil { source.resume() }
        }
        Self.unlinkEndpoints(directory)
    }
    private static func unlinkEndpoints(_ dir: String) {
        unlink(dir + "/target")
        unlink(dir + "/jump")
        rmdir(dir)
    }

    private static func endpoint(_ path: String, listener: Bool) throws -> Int32 {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let fits = withUnsafeMutableBytes(of: &address.sun_path) { raw in
            guard path.utf8.count < raw.count, !path.utf8.contains(0) else { return false }
            raw.copyBytes(from: path.utf8)
            return true
        }
        guard fits else { throw POSIXError(.ENAMETOOLONG) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.ENFILE) }
        var timeout = timeval(tv_sec: 8, tv_usec: 0)
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETNOSIGPIPE, 1) == 0,
              setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0,
              withUnsafePointer(to: &address, { ptr in ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                  listener ? bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) : connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
              } }) == 0, !listener || (fcntl(fd, F_SETFL, O_NONBLOCK) == 0 && listen(fd, 8) == 0)
        else { close(fd); throw POSIXError(.EACCES) }
        return fd
    }

    private static func parent(_ pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout.size(ofValue: info))
        guard pid > 1, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
              info.pbi_pid == UInt32(pid) else { return nil }
        return pid_t(exactly: info.pbi_ppid)
    }
    private func authorized(_ fd: Int32, hop: String, master: Process) -> Bool {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout.size(ofValue: token))
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
              length == MemoryLayout.size(ofValue: token),
              let pid = pid_t(exactly: token.val.5), let parent = Self.parent(pid) else { return false }
        if hop == "jump" {
            var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            guard Self.parent(parent) == master.processIdentifier,
                  proc_pidpath(parent, &path, UInt32(path.count)) > 0,
                  path.withUnsafeBufferPointer({ String(cString: $0.baseAddress!) }) == "/usr/bin/ssh" else { return false }
        } else if parent != master.processIdentifier { return false }
        let audit = withUnsafeBytes(of: token) { Data($0) }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: audit as Any,
                          kSecGuestAttributeDynamicCode as String: true] as CFDictionary
        return master.isRunning && SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess
            && code.map { SecCodeCheckValidity($0, [], requirement) } == errSecSuccess
    }
    private func answer(_ fd: Int32, hop: String) {
        for _ in 0..<8 {
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { return }
            defer { close(client) }
            guard let master, answers[hop] != nil, authorized(client, hop: hop, master: master),
                  fcntl(client, F_SETNOSIGPIPE, 1) == 0, fcntl(client, F_SETFL, O_NONBLOCK) == 0,
                  let bytes = answers.removeValue(forKey: hop) else { continue }
            _ = bytes.withUnsafeBytes { send(client, $0.baseAddress, $0.count, 0) }
        }
    }

    static func response(prompt: String, environment: [String: String]) -> Data? {
        guard environment["SSH_ASKPASS_PROMPT"] != "confirm",
              let hop = environment[hopKey], hop == "target" || hop == "jump",
              let identity = environment[identityKey(hop)], !identity.isEmpty,
              let path = environment[directoryKey] else { return nil }
        let text = prompt.trimmingCharacters(in: .whitespaces)
        guard [identity + "'s password:", "(" + identity + ") Password:", "(" + identity + ") password:"].contains(text),
              let fd = try? endpoint(path + "/" + hop, listener: false) else { return nil }
        defer { close(fd) }
        var bytes = Data()
        var chunk = [UInt8](repeating: 0, count: 512)
        while bytes.count <= limit + 2 {
            let count = read(fd, &chunk, chunk.count)
            if count == 0 {
                guard bytes.count > 2, bytes.count <= limit + 2,
                      Int(bytes[0]) * 256 + Int(bytes[1]) == bytes.count - 2 else { return nil }
                return Data(bytes.dropFirst(2))
            }
            if count < 0 { if errno == EINTR { continue }; return nil }
            bytes.append(contentsOf: chunk.prefix(count))
        }
        return nil
    }
}
