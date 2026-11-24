// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated struct SSHChannelCounters: Sendable {
    struct Rule: Identifiable, Sendable {
        let id: String
        var entered: UInt64 = 0
        var denied: UInt64 = 0
    }
    var requested: UInt64 = 0
    var opened: UInt64 = 0
    var denied: UInt64 = 0
    var active = 0
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
    var rules: [Rule] = []
}

/// Runs only on the SSH session queue. The helper compiles once at activation.
/// Each channel sees the target from its actual SOCKS request or local forward.
nonisolated final class SSHForwardPolicy {
    private enum Field: String, Decodable {
        case target = "ssh.target"
        case port = "ssh.port"
        case direction = "ssh.direction"
        case mode = "ssh.mode"
    }
    private struct Image: Decodable {
        let id: String
        let event: String
        let fields: [Field]
        let code: Data
    }
    private final class Handler {
        let plan: OpaquePointer
        let event: String
        let fields: [Field]
        init(_ image: Image) throws {
            guard let length = UInt32(exactly: image.code.count),
                  let plan = image.code.withUnsafeBytes({ rc_rich_new($0.bindMemory(to: UInt8.self).baseAddress, length) })
            else { throw SSHForwardError("The routing core rejected an SSH channel handler.") }
            self.plan = plan
            event = image.event
            fields = image.fields
        }
        deinit { rc_rich_free(plan) }
    }

    private let handlers: [Handler]
    private(set) var counters: [SSHChannelCounters.Rule]

    init(source: String, adapter: String = "ssh-libssh") throws {
        if source.isEmpty { handlers = []; counters = []; return }
        guard source.utf8.count <= 32768, !source.utf8.contains(0) else {
            throw SSHForwardError("Use at most 32 KiB of handler code, without NUL characters.")
        }
        let (reply, status) = try RoutingEventValidation.run(source, arguments: ["--export-live-event", adapter, "-"])
        guard status == 0 else {
            throw SSHForwardError(String(decoding: reply.prefix(1024), as: UTF8.self))
        }
        let images = try JSONDecoder().decode([Image].self, from: reply)
        guard images.count <= 128 else { throw SSHForwardError("Too many SSH channel handlers.") }
        handlers = try images.map(Handler.init)
        counters = images.map { .init(id: $0.id) }
    }

    func permits(target: String, port: Int, mode: String, direction: String = "outbound") -> Bool {
        guard (1...65535).contains(port), target.utf8.count <= 4096, !target.utf8.contains(0) else { return false }
        var instructions: UInt32 = UInt32(RC_MAX_INSTRUCTIONS)
        var byteBudget: UInt32 = 128 * 1024
        var buffer: [UInt8] = []
        let event = direction == "inbound" ? "ssh.reverse_delivery" : "ssh.forward_open"
        for (index, handler) in handlers.enumerated() where handler.event == event {
            buffer.removeAll(keepingCapacity: true)
            for field in handler.fields {
                if field == .port {
                    buffer.append(2)
                    withUnsafeBytes(of: Int64(port).littleEndian) { buffer.append(contentsOf: $0) }
                } else {
                    let value = field == .target ? target : field == .direction ? direction : mode
                    buffer.append(3)
                    withUnsafeBytes(of: UInt32(value.utf8.count).littleEndian) { buffer.append(contentsOf: $0) }
                    buffer.append(contentsOf: value.utf8)
                }
            }
            counters[index].entered &+= 1
            var edits = RCFrame()
            let result = buffer.withUnsafeBufferPointer {
                rc_rich_eval(handler.plan, $0.baseAddress, UInt32($0.count), &edits, instructions, byteBudget)
            }
            if let message = result.message { rc_rich_message_free(message, result.message_len) }
            guard result.status == 0, result.instructions <= instructions, result.remaining_bytes <= byteBudget,
                  edits.written == 0 else {
                counters[index].denied &+= 1
                return false
            }
            instructions -= result.instructions
            byteBudget = result.remaining_bytes
        }
        return true
    }
}
