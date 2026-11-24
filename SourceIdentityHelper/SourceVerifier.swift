// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation
import Security

nonisolated enum SourceVerifier {
    // A persistent rule requires a signer trusted by Apple. A temporary rule
    // can additionally pin locally built code to its current generation and cdhash.
    private static let flags = SecCSFlags()
    private static func requirement(_ text: String) -> SecRequirement? {
        var result: SecRequirement?
        return SecRequirementCreateWithString(text as CFString, SecCSFlags(), &result) == errSecSuccess ? result : nil
    }

    private static func dynamic(_ data: Data) -> SecCode? {
        guard SourceProcessInstance.decoded(data) != nil else { return nil }
        var code: SecCode?
        // Ask Security.framework to inspect the running code from the kernel.
        // Disk-backed evaluation would require opening the executable again,
        // which a sandboxed helper cannot do for arbitrary user applications.
        let attributes = [
            kSecGuestAttributeAudit as String: data as Any,
            kSecGuestAttributeDynamicCode as String: true
        ] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, flags, &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, flags, nil) == errSecSuccess else { return nil }
        return code
    }

    private static func designatedRequirement(_ code: SecStaticCode) -> String? {
        var requirement: SecRequirement?
        var text: CFString?
        guard SecCodeCopyDesignatedRequirement(code, flags, &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, flags, &text) == errSecSuccess, let text,
              (text as String).utf8.count <= 4096 else { return nil }
        return text as String
    }

    private static func identity(_ code: SecStaticCode) -> SourceSigningIdentity? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let info = info as? [String: Any], let id = info[kSecCodeInfoIdentifier as String] as? String,
              !id.isEmpty, id.utf8.count <= 512, let text = designatedRequirement(code) else { return nil }
        // A signer can supply a custom designated requirement, including "always".
        // Bind each persistent selection to its independently verified publisher.
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        guard let bound = SourceIdentityWire.boundRequirement(canonicalDR: text, team: team) else { return nil }
        return .init(signingIdentifier: id, designatedRequirement: bound, teamIdentifier: team)
    }

    static func selectedFile(_ bookmark: Data) -> SourceSigningIdentity? {
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: bookmark,
                                 options: [.withoutUI, .withoutMounting, .withoutImplicitStartAccessing],
                                 relativeTo: nil, bookmarkDataIsStale: &stale), !stale else { return nil }
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        return file(url)
    }

    private static func file(_ url: URL) -> SourceSigningIdentity? {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), url.path.utf8.count < Int(PATH_MAX), !url.path.utf8.contains(0) else { return nil }
        var info = stat()
        guard stat(url.path, &info) == 0, [S_IFREG, S_IFDIR].contains(info.st_mode & S_IFMT) else { return nil }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, flags, &code) == errSecSuccess, let code,
              let result = identity(code), let bound = requirement(result.designatedRequirement),
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), bound) == errSecSuccess else { return nil }
        return result
    }

    private static func signature(_ dynamic: SecCode, allowAdHoc: Bool) -> (identity: SourceSigningIdentity, needsToken: Bool)? {
        var code: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamic, flags, &code) == errSecSuccess, let code else { return nil }
        if let result = identity(code), let bound = requirement(result.designatedRequirement),
           SecCodeCheckValidity(dynamic, flags, bound) == errSecSuccess { return (result, false) }
        // An ad-hoc program controls its signing identifier and can embed an
        // arbitrary DR. Construct the exact hash requirement from Security.framework.
        var signing: CFDictionary?
        guard allowAdHoc,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signing) == errSecSuccess,
              let fields = signing as? [String: Any], let bits = fields[kSecCodeInfoFlags as String] as? NSNumber,
              bits.uint32Value & SecCodeSignatureFlags.adhoc.rawValue != 0,
              let hash = fields[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
              let id = fields[kSecCodeInfoIdentifier as String] as? String, !id.isEmpty, id.utf8.count <= 512 else { return nil }
        let pin = "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
        guard designatedRequirement(code) == pin, let req = requirement(pin), SecCodeCheckValidity(dynamic, flags, req) == errSecSuccess else { return nil }
        return (.init(signingIdentifier: id, designatedRequirement: pin, teamIdentifier: nil), true)
    }

    static func match(_ data: Data, candidates: [SourceIdentityWire.Candidate]) -> SourceIdentityWire.MatchOutcome {
        guard (1...SourceIdentityWire.maximumCandidates).contains(candidates.count), candidates.allSatisfy(\.isValid),
              Set(candidates.map(\.id)).count == candidates.count, let code = dynamic(data) else { return .unavailable }
        let pinned = candidates.filter { $0.selectedToken == data }
        guard let (actual, needsToken) = signature(code, allowAdHoc: !pinned.isEmpty) else { return .unavailable }
        let eligible = pinned.isEmpty ? candidates.filter { !needsToken && $0.selectedToken == nil } : pinned
        let verified = eligible.filter {
            $0.signingIdentifier.utf8.elementsEqual(actual.signingIdentifier.utf8)
                && $0.designatedRequirement.utf8.elementsEqual(actual.designatedRequirement.utf8)
        }
        guard !verified.isEmpty else { return .different }
        guard verified.contains(where: { $0.processCriteria != nil }) else {
            return verified.count == 1 ? .matched(verified[0].id) : .unavailable
        }
        let context = ProcessContext(token: data, ancestorPaths: verified.compactMap { $0.processCriteria?.ancestorPath })
        let result = SourceIdentityWire.chooseVerified(verified, evaluate: context.matches)
        guard context.stillCurrent(), dynamic(data) != nil else { return .unavailable }
        return result
    }

    /// Obtain the kernel's executable path for this exact PID version. argv[0],
    /// a process title and a bundle's on-disk path can all differ from it.
    private static func executablePath(_ data: Data) -> String? {
        guard var token = SourceProcessInstance.decoded(data) else { return nil }
        // PROC_PIDPATHINFO_MAXSIZE is a compound C macro unavailable in Swift.
        var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = buffer.withUnsafeMutableBytes { proc_pidpath_audittoken(&token, $0.baseAddress, UInt32($0.count)) }
        guard count > 0, let end = buffer.firstIndex(of: 0), end <= Int(count), buffer.first == 47 else { return nil }
        return String(bytes: buffer[..<end], encoding: .utf8)
    }

    private struct ParentLink {
        let child: Data
        let parentPID: pid_t
        let parent: Data?
        let path: String?

        func stillCurrent() -> Bool {
            guard let token = SourceProcessInstance.decoded(child) else { return false }
            let childPID = audit_token_to_pid(token)
            guard processInfo(childPID)?.pbi_ppid == UInt32(parentPID),
                  SourceProcessInstance.captureToken(pid: childPID) == child else { return false }
            if let parent {
                guard SourceProcessInstance.captureToken(pid: parentPID) == parent else { return false }
                if let path {
                    guard let current = executablePath(parent), current.utf8.elementsEqual(path.utf8) else { return false }
                }
            }
            return true
        }
    }

    private struct Lineage {
        var links = [ParentLink]()
        var complete = false
        var unreadablePath = false

        func matches(_ expected: String) -> SourceCriterionVerdict {
            if links.contains(where: { $0.path?.utf8.elementsEqual(expected.utf8) == true }) { return .matched }
            return complete && !unreadablePath ? .different : .unavailable
        }
    }

    private static func lineage(_ initial: Data, lookingFor paths: [String]) -> Lineage {
        var result = Lineage()
        var remaining = paths
        guard let origin = SourceProcessInstance.decoded(initial) else { return result }
        var visited = Set([initial])
        var child = initial
        for _ in 0..<8 {
            guard let token = SourceProcessInstance.decoded(child) else { break }
            let childPID = audit_token_to_pid(token)
            guard SourceProcessInstance.captureToken(pid: childPID) == child,
                  let childInfo = processInfo(childPID),
                  let ppid = pid_t(exactly: childInfo.pbi_ppid), ppid > 0 else { break }
            if ppid == 1 {
                result.links.append(.init(child: child, parentPID: ppid, parent: nil, path: nil))
                result.complete = true
                break
            }
            guard let parent = SourceProcessInstance.captureToken(pid: ppid),
                  let parentToken = SourceProcessInstance.decoded(parent),
                  visited.insert(parent).inserted else { break }
            guard audit_token_to_euid(origin) == audit_token_to_euid(parentToken),
                  audit_token_to_ruid(origin) == audit_token_to_ruid(parentToken) else {
                // A same-user chain ends at a credential boundary. Do not read
                // the executable path or ancestry of the other user's process.
                result.links.append(.init(child: child, parentPID: ppid, parent: parent, path: nil))
                result.complete = true
                break
            }
            guard let parentInfo = processInfo(ppid),
                  (parentInfo.pbi_start_tvsec, parentInfo.pbi_start_tvusec) < (childInfo.pbi_start_tvsec, childInfo.pbi_start_tvusec)
            else { break }
            let path = executablePath(parent)
            result.links.append(.init(child: child, parentPID: ppid, parent: parent, path: path))
            if let path {
                remaining.removeAll { $0.utf8.elementsEqual(path.utf8) }
                if remaining.isEmpty { break }
            } else {
                result.unreadablePath = true
            }
            child = parent
        }
        return result
    }

    /// Request-local snapshots keep per-candidate comparisons cheap without
    /// extending the lifetime of process metadata past this verification.
    private final class ProcessContext {
        let token: Data
        let ancestorPaths: [String]
        private var usedPath = false
        private lazy var path = executablePath(token)
        private var ancestors: Lineage?

        init(token: Data, ancestorPaths: [String]) {
            self.token = token
            self.ancestorPaths = ancestorPaths
        }

        func matches(_ criteria: SourceProcessCriteria) -> SourceCriterionVerdict {
            if criteria.executablePath != nil || criteria.executableName != nil {
                usedPath = true
                guard let path else { return .unavailable }
                if let expected = criteria.executablePath, !path.utf8.elementsEqual(expected.utf8) { return .different }
                if let expected = criteria.executableName {
                    guard let name = path.split(separator: "/").last else { return .unavailable }
                    if !name.utf8.elementsEqual(expected.utf8) { return .different }
                }
            }
            if let expected = criteria.ancestorPath {
                if ancestors == nil { ancestors = lineage(token, lookingFor: ancestorPaths) }
                guard let verdict = ancestors?.matches(expected) else { return .unavailable }
                if verdict != .matched { return verdict }
            }
            if criteria.httpProxyEndpoint != nil {
                guard let expected = criteria.canonicalProxyEndpoint else { return .unavailable }
                return SourceProxyEnvironment.match(token: token, key: criteria.httpProxyVariable ?? "HTTP_PROXY", expected: expected)
            }
            return .matched
        }

        func stillCurrent() -> Bool {
            if usedPath {
                guard let path, let current = executablePath(token), path.utf8.elementsEqual(current.utf8) else { return false }
            }
            return ancestors?.links.allSatisfy { $0.stillCurrent() } ?? true
        }
    }

    private static func processInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size, info.pbi_pid == UInt32(pid) else { return nil }
        return info
    }

    private static func ancestry(of initial: Data, uid: uid_t) -> [SourceProcessAncestor] {
        var ancestors: [SourceProcessAncestor] = []
        var child = initial
        var visited = Set<Data>([initial])
        for _ in 0..<8 {
            guard let childToken = SourceProcessInstance.decoded(child) else { break }
            let pid = audit_token_to_pid(childToken)
            guard let info = processInfo(pid), let ppid = pid_t(exactly: info.pbi_ppid), ppid > 1,
                  let parent = SourceProcessInstance.captureToken(pid: ppid), let value = SourceProcessInstance.decoded(parent),
                  audit_token_to_euid(value) == uid, visited.insert(parent).inserted,
                  let parentInfo = processInfo(ppid),
                  processInfo(pid)?.pbi_ppid == info.pbi_ppid,
                  SourceProcessInstance.captureToken(pid: pid) == child, SourceProcessInstance.captureToken(pid: ppid) == parent,
                  let generation = SourceProcessInstance.processGeneration(auditToken: parent) else { break }
            let name = withUnsafeBytes(of: parentInfo.pbi_comm) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
            ancestors.append(.init(pid: ppid, name: name, generation: generation))
            child = parent
        }
        return ancestors
    }

    static func process(_ bytes: Data) -> SourceProcessInstance? {
        guard let token = SourceProcessInstance.decoded(bytes),
              audit_token_to_euid(token) == geteuid(), let code = dynamic(bytes), let (signingIdentity, _) = signature(code, allowAdHoc: true) else { return nil }
        let ancestors = ancestry(of: bytes, uid: audit_token_to_euid(token))
        guard dynamic(bytes) != nil else { return nil }
        let pid = audit_token_to_pid(token)
        return .init(pid: pid, pidVersion: audit_token_to_pidversion(token), auditToken: bytes,
                     signingIdentity: signingIdentity, ancestors: ancestors)
    }
}
