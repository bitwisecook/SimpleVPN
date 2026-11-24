// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Darwin
import Foundation
import Testing
@testable import SimpleVPN

struct SourceIdentityServiceTests {
    @Test func invalidAndUnattributedTokensDoNotCreateAGeneration() {
        for data in [Data(), Data(repeating: 0, count: 32), Data(repeating: 1, count: 31)] {
            #expect(SourceProcessInstance.processGeneration(auditToken: data) == nil)
        }
    }

    @Test func persistentRequirementsCannotEscapeThePublisherClause() {
        let apple = "(always) and anchor apple"
        let team = "(always) and anchor apple generic and certificate leaf[subject.OU] = \"ABC123\""
        let hash = "cdhash H\"" + String(repeating: "ab", count: 20) + "\""
        #expect(SourceIdentityWire.isBoundRequirement(apple, temporary: false))
        #expect(SourceIdentityWire.isBoundRequirement(team, temporary: false))
        #expect(SourceIdentityWire.captureRequirement(team, temporary: false) == "always")
        #expect(!SourceIdentityWire.isBoundRequirement(hash, temporary: false))
        #expect(SourceIdentityWire.isBoundRequirement(hash, temporary: true))
        for loose in ["always", "(always) or (always) and anchor apple", "/*(*/always or (always) and anchor apple",
                      "(always) and anchor apple or always", team + " or always", apple + "\0"] {
            #expect(!SourceIdentityWire.isBoundRequirement(loose, temporary: false))
        }
    }

    @Test func signedServiceVerifiesAnAppleToolAndRejectsUnsignedInput() async throws {
        let identity = try await SourceIdentityService.signedApplication(at: URL(fileURLWithPath: "/bin/sleep"))
        #expect(!identity.signingIdentifier.isEmpty)
        #expect(SourceIdentityWire.isBoundRequirement(identity.designatedRequirement, temporary: false))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("synthetic fixture".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        await #expect(throws: SourceIdentityService.Failure.self) { try await SourceIdentityService.signedApplication(at: file) }
    }

    @Test func verifiesAnApplicationSelectedOutsideTheSystemApplicationsDirectory() async throws {
        let manager = FileManager.default
        let folder = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try manager.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? manager.removeItem(at: folder) }
        let copy = folder.appendingPathComponent("Selected.app")
        try manager.copyItem(at: URL(fileURLWithPath: "/System/Applications/Calculator.app"), to: copy)
        let signature = try await SourceIdentityService.signedApplication(at: copy)
        #expect(signature.signingIdentifier == "com.apple.calculator")
        #expect(SourceIdentityWire.captureRequirement(signature.designatedRequirement, temporary: false)
            == "identifier \"com.apple.calculator\" and anchor apple")
    }

    @Test func localBuildNeedsAnExactProcessSelectionAndCodeHash() async throws {
        let manager = FileManager.default
        let folder = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try manager.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? manager.removeItem(at: folder) }
        let file = folder.appendingPathComponent("local-tool")
        try manager.copyItem(at: URL(fileURLWithPath: "/bin/sleep"), to: file)
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", "--identifier", "test.local-tool", file.path]
        try signer.run()
        signer.waitUntilExit()
        try #require(signer.terminationStatus == 0)
        await #expect(throws: SourceIdentityService.Failure.self) { try await SourceIdentityService.signedApplication(at: file) }
        let process = Process()
        process.executableURL = file
        process.arguments = ["30"]
        try process.run()
        defer { if process.isRunning { process.terminate(); process.waitUntilExit() } }
        let instance = try await SourceIdentityService.runningProcess(pid: process.processIdentifier)
        let identity = instance.signingIdentity
        #expect(identity.signingIdentifier == "test.local-tool")
        #expect(SourceIdentityWire.isBoundRequirement(identity.designatedRequirement, temporary: true))
        #expect(!SourceIdentityWire.isBoundRequirement(identity.designatedRequirement, temporary: false))
        let route = VPNApplicationRoute(id: "local", name: "Local", signingIdentifier: identity.signingIdentifier,
                                        designatedRequirement: identity.designatedRequirement, port: "work")
        let token = instance.auditToken
        #expect(await SourceIdentityService.matchedRoute(auditToken: token, candidates: [route]) == nil)
        #expect(await SourceIdentityService.matchedRoute(auditToken: token, candidates: [route], processTokens: [route.id: token]) == route.id)
        var other = token
        other[0] ^= 1
        #expect(await SourceIdentityService.matchedRoute(auditToken: token, candidates: [route], processTokens: [route.id: other]) == nil)
    }

    @Test func selectedInstanceUsesItsGenerationAndAuthenticatedSigner() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        defer { if process.isRunning { process.terminate(); process.waitUntilExit() } }
        let instance = try await SourceIdentityService.runningProcess(pid: process.processIdentifier)
        let real = instance.signingIdentity
        let generation = try #require(SourceProcessInstance.processGeneration(auditToken: instance.auditToken))
        #expect(instance.matches(auditToken: instance.auditToken))
        #expect(generation >> 32 == UInt64(process.processIdentifier))
        #expect(instance.ancestors.count <= 8)
        let trusted = VPNApplicationRoute(id: "trusted", name: "Fixture", signingIdentifier: real.signingIdentifier,
                                         designatedRequirement: real.designatedRequirement, port: "work")
        var loose = trusted
        loose.id = "loose"
        loose.designatedRequirement = "always"
        #expect(await SourceIdentityService.matchedRoute(auditToken: instance.auditToken, candidates: [loose, trusted]) == trusted.id)
        #expect(await SourceIdentityService.matchedRoute(auditToken: instance.auditToken, candidates: [loose]) == nil)
        process.terminate()
        process.waitUntilExit()
        #expect(await SourceIdentityService.matchedRoute(auditToken: instance.auditToken, candidates: [trusted]) == nil)
    }
}

@Suite struct VerifiedProcessContextTests {
    @Test func missingOrOverlappingContextCannotWidenTheCapture() throws {
        let common = SourceIdentityWire.Candidate(id: "fallback", signingIdentifier: "fixture", designatedRequirement: "fixture")
        let one = SourceIdentityWire.Candidate(id: "one", signingIdentifier: "fixture", designatedRequirement: "fixture", processCriteria: .init(executableName: "one"))
        let two = SourceIdentityWire.Candidate(id: "two", signingIdentifier: "fixture", designatedRequirement: "fixture", processCriteria: .init(executableName: "two"))
        #expect(SourceIdentityWire.chooseVerified([common, one, two]) { _ in .different } == .matched("fallback"))
        #expect(SourceIdentityWire.chooseVerified([common, one, two]) { _ in .matched } == .unavailable)
        #expect(SourceIdentityWire.chooseVerified([common, one, two]) { $0.executableName == "one" ? .matched : .unavailable } == .unavailable)
        #expect(SourceIdentityWire.chooseVerified([common, one, two]) { $0.executableName == "one" ? .matched : .different } == .matched("one"))
        #expect(SourceIdentityWire.chooseVerified([one]) { _ in .different } == .different)
    }

    @Test func constrainedXPCRequestsRequireANewHelper() throws {
        enum PreviousRequest: Decodable { case match(Data, [SourceIdentityWire.Candidate]) }
        let rule = SourceIdentityWire.Candidate(id: "bounded", signingIdentifier: "fixture", designatedRequirement: "fixture", processCriteria: .init(executableName: "tool"))
        let request = try JSONEncoder().encode(SourceIdentityWire.Request.matchProcessCriteria(Data(), [rule]))
        #expect(throws: (any Error).self) { try JSONDecoder().decode(PreviousRequest.self, from: request) }
        let reply = try JSONEncoder().encode(SourceIdentityWire.Reply.processCriteriaMatch(.unavailable))
        guard case .processCriteriaMatch(.unavailable) = try JSONDecoder().decode(SourceIdentityWire.Reply.self, from: reply) else {
            Issue.record("Lost the explicit unavailable outcome")
            return
        }
    }

    @Test func processPathAndAncestryMatchOnlyTheAuthenticatedGeneration() async throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        defer { if child.isRunning { child.terminate(); child.waitUntilExit() } }
        let instance = try await SourceIdentityService.runningProcess(pid: child.processIdentifier)
        let ownToken = try #require(SourceProcessInstance.captureToken(pid: getpid()))
        var ownAudit = try #require(SourceProcessInstance.decoded(ownToken))
        var pathBuffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = pathBuffer.withUnsafeMutableBytes { proc_pidpath_audittoken(&ownAudit, $0.baseAddress, UInt32($0.count)) }
        try #require(count > 0)
        let parent = try #require(pathBuffer.withUnsafeBufferPointer { String(validatingCString: $0.baseAddress!) })
        let signer = instance.signingIdentity
        var route = VPNApplicationRoute(id: "verified", name: "test", signingIdentifier: signer.signingIdentifier,
                                        designatedRequirement: signer.designatedRequirement, port: "work")
        route.processCriteria = .init(executableName: "sleep", executablePath: "/bin/sleep", ancestorPath: parent)
        #expect(await SourceIdentityService.matchedRoute(auditToken: instance.auditToken, candidates: [route]) == route.id)
        route.processCriteria = .init(executableName: "Sleep")
        #expect(await SourceIdentityService.matchedRoute(auditToken: instance.auditToken, candidates: [route]) == nil)
        route.processCriteria = .init(executablePath: "/usr/bin/sleep")
        #expect(await SourceIdentityService.routeOutcome(auditToken: instance.auditToken, candidates: [route]) == .different)
        route.processCriteria = .init(executableName: "sleep")
        child.terminate()
        child.waitUntilExit()
        #expect(await SourceIdentityService.routeOutcome(auditToken: instance.auditToken, candidates: [route]) == .unavailable)
    }
}

@Suite struct SourceProxyCriteriaTests {
    @Test func unknownConstraintsCannotBeDiscardedByAnOlderReader() throws {
        let criteria = SourceProcessCriteria(executableName: "curl", httpProxyEndpoint: "1.2.3.4:8888")
        let encoded = try JSONEncoder().encode(criteria)
        #expect(try JSONDecoder().decode(SourceProcessCriteria.self, from: encoded) == criteria)
        let future = Data(#"{"executableName":"curl","unknownRestriction":"required"}"#.utf8)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(SourceProcessCriteria.self, from: future) }
        #expect(SourceProcessCriteria.canonicalEndpoint("http://[2001:0db8::01]:8888/") == "[2001:db8::1]:8888")
        for unsafe in ["http://user:example@host:80", "host:80/path", "host:0", "host:65536", "host%2ecom:80"] {
            #expect(SourceProcessCriteria.canonicalEndpoint(unsafe) == nil)
        }
    }

    @Test func curlWithoutReadableProxyEvidenceCannotUseAnotherRule() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        // -q disables curlrc. Reading config from an open pipe keeps the process
        // alive without giving it any URL or sending traffic.
        process.arguments = ["-q", "--config", "-"]
        process.environment = ["HTTP_PROXY": "1.2.3.4:8888"]
        let input = Pipe()
        process.standardInput = input
        try process.run()
        defer {
            if process.isRunning { process.terminate(); process.waitUntilExit() }
            try? input.fileHandleForWriting.close()
        }
        let instance = try await SourceIdentityService.runningProcess(pid: process.processIdentifier)
        let identity = instance.signingIdentity
        var rule = VPNApplicationRoute(id: "work", name: "curl", signingIdentifier: identity.signingIdentifier,
                                       designatedRequirement: identity.designatedRequirement, port: "work")
        rule.processCriteria = .init(executableName: "curl", executablePath: "/usr/bin/curl", httpProxyEndpoint: "1.2.3.4:8888")
        let expected = await SourceIdentityService.routeOutcome(auditToken: instance.auditToken, candidates: [rule])
        rule.processCriteria?.httpProxyEndpoint = "1.2.3.5:8888"
        let other = await SourceIdentityService.routeOutcome(auditToken: instance.auditToken, candidates: [rule])
        switch expected {
        case .matched("work"): #expect(other == .different)
        case .unavailable: #expect(other == .unavailable)
        default: Issue.record("Incorrect proxy verdict for a controlled curl launch")
        }
    }
}
