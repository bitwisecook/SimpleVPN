// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation

/// Compare one explicitly configured proxy variable on an already verified process.
/// Only the verdict leaves this helper. macOS can withhold the initial environment.
nonisolated enum SourceProxyEnvironment {
    static func match(token: Data, key: String, expected: String) -> SourceCriterionVerdict {
        guard key == "HTTP_PROXY" || key == "http_proxy",
              let endpoint = SourceProcessCriteria.canonicalEndpoint(expected),
              let identity = SourceProcessInstance.decoded(token),
              audit_token_to_euid(identity) == geteuid(),
              audit_token_to_ruid(identity) == geteuid(),
              audit_token_to_rgid(identity) == audit_token_to_egid(identity) else { return .unavailable }
        let pid = audit_token_to_pid(identity)
        guard SourceProcessInstance.captureToken(pid: pid) == token else { return .unavailable }
        // KERN_PROCARGS2 returns a launch snapshot and can omit the environment.
        // Use a bounded temporary buffer, never serialize the argv or environment.
        var mib = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4, size <= 1_048_576 else { return .unavailable }
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: size, alignment: MemoryLayout<Int32>.alignment)
        defer {
            _ = memset_s(buffer.baseAddress!, buffer.count, 0, buffer.count)
            buffer.deallocate()
        }
        guard sysctl(&mib, 3, buffer.baseAddress, &size, nil, 0) == 0,
              size <= buffer.count, SourceProcessInstance.captureToken(pid: pid) == token else { return .unavailable }
        return compare(UnsafeRawBufferPointer(rebasing: buffer[..<size]), key: key, endpoint: endpoint)
    }

    static func compare(_ blob: UnsafeRawBufferPointer, key: String, endpoint: String) -> SourceCriterionVerdict {
        guard blob.count > MemoryLayout<Int32>.size, key == "HTTP_PROXY" || key == "http_proxy" else { return .unavailable }
        let argc = Int(blob.loadUnaligned(as: Int32.self))
        guard argc > 0, argc <= blob.count else { return .unavailable }
        var index = MemoryLayout<Int32>.size
        func nextString() -> Range<Int>? {
            guard index < blob.count, let end = blob[index...].firstIndex(of: 0) else { return nil }
            let start = index
            index = end + 1
            return start..<end
        }
        guard let executable = nextString(), !executable.isEmpty else { return .unavailable }
        while index < blob.count && blob[index] == 0 { index += 1 }
        for _ in 0..<argc {
            guard nextString() != nil else { return .unavailable }
        }
        let prefix = Array((key + "=").utf8)
        var observed: SourceCriterionVerdict?
        while index < blob.count {
            guard let field = nextString() else { return .unavailable }
            if field.isEmpty { break }
            let bytes = blob[field]
            guard bytes.starts(with: prefix) else { continue }
            let value = bytes.dropFirst(prefix.count)
            guard observed == nil, value.count <= 512, !value.contains(64),
                  let text = String(bytes: value, encoding: .ascii),
                  let actual = SourceProcessCriteria.canonicalEndpoint(text) else { return .unavailable }
            observed = actual == endpoint ? .matched : .different
        }
        // A withheld environment and an absent variable are indistinguishable on
        // some OS versions. Neither can establish a different proxy endpoint.
        return observed ?? .unavailable
    }
}
