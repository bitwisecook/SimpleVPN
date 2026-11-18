// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation

/// OpenSSH launches the bundled CLI for askpass. Each local ssh process receives
/// a hop identifier. The private FIFO holds a single answer in kernel memory.
nonisolated final class SSHAskpass {
    struct Credential {
        let identity: String
        let password: String
    }

    static let directoryKey = "SIMPLEVPN_ASKPASS_DIR"
    static let hopKey = "SIMPLEVPN_ASKPASS_HOP"
    private static func identityKey(_ hop: String) -> String { "SIMPLEVPN_ASKPASS_ID_" + hop }
    private static let limit = 4096

    private let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("simplevpn-askpass-" + UUID().uuidString)
    private var ownsDirectory = false
    private var descriptors: [Int32] = []
    private(set) var environment: [String: String] = [:]

    init(target: Credential?, jump: Credential?) throws {
        guard mkdir(directory.path, 0o700) == 0 else { throw POSIXError(.EACCES) }
        ownsDirectory = true
        for (hop, credential) in [("target", target), ("jump", jump)] {
            guard let credential else { continue }
            let bytes = Data(credential.password.utf8)
            guard !bytes.isEmpty, bytes.count <= Self.limit,
                  !bytes.contains(0), !bytes.contains(10), !bytes.contains(13) else {
                throw POSIXError(.EINVAL)
            }
            let path = directory.appendingPathComponent(hop).path
            guard mkfifo(path, 0o600) == 0 else { throw POSIXError(.EACCES) }
            let fd = open(path, O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw POSIXError(.EIO) }
            descriptors.append(fd)
            let count = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard count == bytes.count else { throw POSIXError(.EIO) }
            environment[Self.identityKey(hop)] = credential.identity
        }
        environment[Self.directoryKey] = directory.path
        environment[Self.hopKey] = "target"
    }

    deinit {
        for fd in descriptors { close(fd) }
        if ownsDirectory { try? FileManager.default.removeItem(at: directory) }
    }

    static func response(prompt: String, environment: [String: String]) -> Data? {
        guard environment["SSH_ASKPASS_PROMPT"] != "confirm",
              let hop = environment[hopKey], hop == "target" || hop == "jump",
              let identity = environment[identityKey(hop)], !identity.isEmpty,
              let path = environment[directoryKey] else { return nil }
        let text = prompt.trimmingCharacters(in: .whitespaces)
        guard [identity + "'s password:", "(" + identity + ") Password:", "(" + identity + ") password:"].contains(text) else {
            return nil
        }
        let fd = open(URL(fileURLWithPath: path).appendingPathComponent(hop).path,
                      O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFIFO,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: limit)
        let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard count > 0 else { return nil }
        return Data(buffer.prefix(count))
    }
}
