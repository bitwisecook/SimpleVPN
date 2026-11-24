// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation
import Security

nonisolated struct SourceSigningIdentity: Codable, Equatable, Sendable {
    let signingIdentifier: String
    let designatedRequirement: String
    let teamIdentifier: String?
}

nonisolated struct SourceProcessAncestor: Codable, Equatable, Sendable {
    let pid: Int32
    let name: String
    let generation: UInt64
}

nonisolated struct SourceProcessInstance: Codable, Equatable, Sendable {
    let pid: Int32
    let pidVersion: Int32
    let auditToken: Data
    let signingIdentity: SourceSigningIdentity
    let ancestors: [SourceProcessAncestor]

    /// Obtain only a task name right. It cannot read or modify process memory.
    static func captureToken(pid: pid_t) -> Data? {
        guard pid > 0 else { return nil }
        var name: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &name) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, name) }
        var token = audit_token_t()
        let expectedCount = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        var count = expectedCount
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(name, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS, count == expectedCount, audit_token_to_pid(token) == pid else { return nil }
        return withUnsafeBytes(of: token) { Data($0) }
    }

    static func decoded(_ bytes: Data) -> audit_token_t? {
        guard bytes.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = bytes.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        return audit_token_to_pid(token) > 0 && audit_token_to_pidversion(token) > 0 ? token : nil
    }

    static func processGeneration(auditToken: Data) -> UInt64? {
        guard let token = decoded(auditToken) else { return nil }
        return UInt64(UInt32(audit_token_to_pid(token))) << 32 | UInt64(UInt32(audit_token_to_pidversion(token)))
    }

    func matches(auditToken other: Data) -> Bool {
        guard let token = Self.decoded(other) else { return false }
        return other == auditToken && audit_token_to_pid(token) == pid && audit_token_to_pidversion(token) == pidVersion
    }
}

@objc(SourceIdentityVerifying)
nonisolated protocol SourceIdentityVerifying {
    func inspect(_ request: Data, withReply reply: @escaping @Sendable (Data?) -> Void)
}

nonisolated enum SourceIdentityWire {
    static let service = "com.bragi0.SimpleVPN.SourceIdentity"
    static let signer = "anchor apple generic and certificate leaf[subject.OU] = \"QVUFB5676H\""
    static let serviceRequirement = signer + " and identifier \"" + service + "\""
    static let hostRequirement = signer + " and (identifier \"com.bragi0.SimpleVPN\" or identifier \"com.bragi0.SimpleVPN.PacketTunnel\")"
    static let maximumBytes = 512 * 1024
    static let maximumCandidates = 64

    private static let applePublisher = "anchor apple"
    private static let teamPublisher = "anchor apple generic and certificate leaf[subject.OU] = \""

    private static func isTeam(_ team: Substring) -> Bool {
        (1...64).contains(team.utf8.count) && team.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) }
    }

    static func boundRequirement(canonicalDR: String, team: String?) -> String? {
        let publisher: String
        if let team {
            guard isTeam(team[...]) else { return nil }
            publisher = teamPublisher + team + "\""
        } else {
            publisher = applePublisher
        }
        let result = "(" + canonicalDR + ") and " + publisher
        return result.utf8.count <= 4096 ? result : nil
    }

    static func isBoundRequirement(_ text: String, temporary: Bool) -> Bool {
        captureRequirement(text, temporary: temporary) != nil
    }

    /// NEAppRule compares the executable's declared designated requirement.
    /// Only the verifier evaluates the extra publisher binding stored by SimpleVPN.
    static func captureRequirement(_ text: String, temporary: Bool) -> String? {
        guard !text.isEmpty, text.utf8.count <= 4096, !text.utf8.contains(0) else { return nil }
        if temporary, text.hasPrefix("cdhash H\""), text.hasSuffix("\"") {
            let hex = text.utf8.dropFirst(9).dropLast()
            return hex.count == 40 && hex.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } ? text : nil
        }
        guard text.hasPrefix("("), let separator = text.range(of: ") and ", options: .backwards) else { return nil }
        let publisher = text[separator.upperBound...]
        guard publisher == applePublisher || (publisher.hasPrefix(teamPublisher) && publisher.hasSuffix("\"")
            && isTeam(publisher.dropFirst(teamPublisher.count).dropLast())) else { return nil }
        // Validate the body independently. Security.framework's canonical serialization
        // ensures punctuation/comments in imported text cannot escape the outer group.
        let body = String(text[text.index(after: text.startIndex)..<separator.lowerBound])
        guard let normalized = canonicalRequirement(body), body.utf8.elementsEqual(normalized.utf8) else { return nil }
        return normalized
    }

    private static func canonicalRequirement(_ text: String) -> String? {
        var compiled: SecRequirement?
        var canonical: CFString?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &compiled) == errSecSuccess, let compiled,
              SecRequirementCopyString(compiled, SecCSFlags(), &canonical) == errSecSuccess, let canonical else { return nil }
        return canonical as String
    }

    struct Candidate: Codable, Sendable {
        let id: String
        let signingIdentifier: String
        let designatedRequirement: String

        var selectedToken: Data?
        var processCriteria: SourceProcessCriteria?

        var isValid: Bool {
            !id.isEmpty && id.utf8.count <= 128 && !signingIdentifier.isEmpty && signingIdentifier.utf8.count <= 512
                && !designatedRequirement.isEmpty && designatedRequirement.utf8.count <= 4096
                && !designatedRequirement.utf8.contains(0) && !signingIdentifier.utf8.contains(0)
                && (selectedToken.map { SourceProcessInstance.decoded($0) != nil } ?? true)
                && (processCriteria?.isValid ?? true)
        }
    }

    enum MatchOutcome: Codable, Equatable, Sendable {
        case matched(String)
        case different
        case unavailable
    }

    // Evaluate only candidates whose signer and optional generation are already
    // verified. An unknown contextual match cannot authorize a broader fallback.
    static func chooseVerified(
        _ candidates: [Candidate], evaluate: (SourceProcessCriteria) -> SourceCriterionVerdict
    ) -> MatchOutcome {
        var contextual: String?
        var fallback: String?
        for candidate in candidates {
            guard let criteria = candidate.processCriteria else {
                guard fallback == nil else { return .unavailable }
                fallback = candidate.id
                continue
            }
            switch evaluate(criteria) {
            case .different: continue
            case .unavailable: return .unavailable
            case .matched:
                guard contextual == nil else { return .unavailable }
                contextual = candidate.id
            }
        }
        return (contextual ?? fallback).map(MatchOutcome.matched) ?? .different
    }

    enum Request: Codable, Sendable {
        case file(Data)
        case process(Data)
        case match(Data, [Candidate])
        case matchProcessCriteria(Data, [Candidate])
    }

    enum Reply: Codable, Sendable {
        case identity(SourceSigningIdentity)
        case process(SourceProcessInstance)
        case match(String?)
        case processCriteriaMatch(MatchOutcome)
    }
}
