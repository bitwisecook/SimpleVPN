// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Bounded DNS question parsing. Compression pointers are followed with cycle detection.
nonisolated enum DNSWireMessage {
    static let maximumSize = 65_535
    struct Question: Equatable {
        let name: String
        let type: UInt16
        let dnsClass: UInt16
        let wireEnd: Int
    }
    static func questionName(_ data: Data) -> String? { question(data)?.name }
    static func question(_ data: Data, response: Bool = false) -> Question? {
        let bytes = [UInt8](data)
        guard bytes.count >= 17, bytes.count <= maximumSize,
              bytes[2] & 0x78 == 0, (bytes[2] & 0x80 != 0) == response,
              bytes[4] == 0, bytes[5] == 1 else { return nil }
        var cursor = 12, end: Int?, labels: [String] = [], visited: Set<Int> = [], length = 0
        for _ in 0..<128 {
            guard cursor < bytes.count, visited.insert(cursor).inserted else { return nil }
            let size = Int(bytes[cursor]); cursor += 1
            if size == 0 {
                let questionEnd = end ?? cursor
                guard questionEnd + 4 <= bytes.count else { return nil }
                let type = UInt16(bytes[questionEnd]) << 8 | UInt16(bytes[questionEnd + 1])
                let dnsClass = UInt16(bytes[questionEnd + 2]) << 8 | UInt16(bytes[questionEnd + 3])
                return Question(name: labels.isEmpty ? "." : labels.joined(separator: ".").lowercased(), type: type, dnsClass: dnsClass, wireEnd: questionEnd + 4)
            }
            if size & 0xc0 == 0xc0 {
                guard cursor < bytes.count else { return nil }
                end = end ?? (cursor + 1)
                let target = ((size & 0x3f) << 8) | Int(bytes[cursor])
                guard target < cursor - 1 else { return nil }
                cursor = target
                continue
            }
            guard size <= 63, cursor + size <= bytes.count else { return nil }
            let label = bytes[cursor..<(cursor + size)]
            guard label.allSatisfy({ $0 > 32 && $0 < 127 && $0 != 46 }),
                  let text = String(bytes: label, encoding: .ascii) else { return nil }
            length += size + (labels.isEmpty ? 0 : 1)
            guard length <= 253 else { return nil }
            labels.append(text); cursor += size
        }
        return nil
    }
    static func failure(for query: Data) -> Data? {
        guard query.count >= 12 else { return nil }
        let parsed = question(query)
        var reply = [UInt8](query.prefix(parsed?.wireEnd ?? 12))
        reply[2] = 0x80 | (reply[2] & 0x01) // response; preserve RD, no fabricated question
        reply[3] = 0x82 | (reply[3] & 0x10) // RA + SERVFAIL; preserve CD
        if parsed == nil { reply[4] = 0; reply[5] = 0 }
        for index in 6..<12 { reply[index] = 0 }
        return Data(reply)
    }
    static func response(_ reply: Data, matches query: Data) -> Bool {
        guard reply.count >= 12, query.count >= 12 else { return false }
        guard reply[0] == query[0], reply[1] == query[1], reply[2] & 0x80 != 0,
              reply[2] & 0x78 == query[2] & 0x78 else { return false }
        if reply[4] == 0, reply[5] == 0, reply[3] & 0x0f != 0 { return true }
        guard let expected = question(query), let actual = question(reply, response: true) else { return false }
        return expected.name == actual.name && expected.type == actual.type && expected.dnsClass == actual.dnsClass
    }
}
