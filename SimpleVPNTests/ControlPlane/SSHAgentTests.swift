// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHAgentTests.swift
//  The SSH-agent state machine, against a fake agent.
//
//  WHY FAKES ARE THE RIGHT TOOL HERE, not a shortcut: the states this has to get
//  right are the ones a machine can't be put into on demand. "SSH_AUTH_SOCK
//  points at a socket whose agent has quit", "the agent answers but holds
//  nothing", "the agent sends a truncated reply" — each is a real failure users
//  hit, and each has to produce a DIFFERENT sentence, because libssh reports all
//  of them (plus "the server said no") as one indistinguishable refusal. The live
//  half — a real ssh-agent, a real server, a real signature — is
//  SSHAgentLiveTests.swift; this file is the exhaustive half.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - A fake agent

/// An environment with no agent at all.
nonisolated private struct EmptyEnvironment: SSHAgentEnvironment {
    var inheritedSocketPath: String? = nil
    func socketExists(atPath path: String) -> Bool { false }
    func connect(toSocketAt path: String) throws -> any SSHAgentTransport {
        throw SSHAgentTransportError("no such file or directory")
    }
}

/// A scripted agent: which paths exist, whether connecting works, and what the
/// reply bytes are.
nonisolated private struct FakeEnvironment: SSHAgentEnvironment {
    var inheritedSocketPath: String?
    var existingPaths: Set<String> = []
    /// nil = connect succeeds; non-nil = it fails with this reason.
    var connectFailure: String?
    /// The bytes the agent answers with, framed exactly as it would frame them.
    var reply: Data = SSHAgentFake.identitiesAnswer([])
    /// Set when the transport should die mid-answer.
    var truncateReply = false

    func socketExists(atPath path: String) -> Bool { existingPaths.contains(path) }

    func connect(toSocketAt path: String) throws -> any SSHAgentTransport {
        if let connectFailure { throw SSHAgentTransportError(connectFailure) }
        return FakeTransport(reply: truncateReply ? nil : reply)
    }
}

nonisolated private final class FakeTransport: SSHAgentTransport, @unchecked Sendable {
    let reply: Data?
    init(reply: Data?) { self.reply = reply }
    func roundTrip(_ request: Data) throws -> Data {
        // Every caller must send exactly the framed REQUEST_IDENTITIES message.
        #expect(request == SSHAgentWire.requestIdentities())
        guard let reply else { throw SSHAgentTransportError("the agent closed the connection") }
        return reply
    }
    func close() {}
}

/// Builds the agent's side of the wire, so the parser is tested against bytes
/// rather than against our own parser run backwards.
nonisolated private enum SSHAgentFake {
    static func string(_ data: Data) -> Data {
        var out = Data()
        var length = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(data)
        return out
    }

    /// An OpenSSH public-key blob: a type name followed by (fake) key material.
    /// The blob is what the agent puts INSIDE the answer's key string, so callers
    /// wrap it with `string(_:)` — the nesting is the part a parser gets wrong.
    static func blob(type: String) -> Data {
        string(Data(type.utf8)) + string(Data(repeating: 0xAB, count: 32))
    }

    static func identitiesAnswer(_ keys: [(type: String, comment: String)]) -> Data {
        var payload = Data([SSHAgentWire.identitiesAnswerType])
        var count = UInt32(keys.count).bigEndian
        withUnsafeBytes(of: &count) { payload.append(contentsOf: $0) }
        for key in keys {
            payload.append(string(blob(type: key.type)))
            payload.append(string(Data(key.comment.utf8)))
        }
        return frame(payload)
    }

    static func failure() -> Data { frame(Data([SSHAgentWire.failureType])) }

    static func frame(_ payload: Data) -> Data {
        var out = Data()
        var length = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }
}

// MARK: - Where the agent is

struct SSHAgentSocketResolutionTests {

    @Test func nothingConfiguredAndNothingInheritedMeansNoAgent() {
        let probe = SSHAgentProbe(environment: EmptyEnvironment())
        #expect(probe.resolvedSocketPath(configured: nil) == nil)
        #expect(probe.probe() == .noAgent)
    }

    /// The inherited socket is used when the user hasn't chosen one — that is the
    /// macOS ssh-agent case, and the only one that works with no configuration.
    @Test func theInheritedSocketIsUsedWhenNothingIsConfigured() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/var/run/com.apple.launchd.AAA/Listeners"))
        #expect(probe.resolvedSocketPath(configured: nil) == "/var/run/com.apple.launchd.AAA/Listeners")
        #expect(probe.resolvedSocketPath(configured: "   ") == "/var/run/com.apple.launchd.AAA/Listeners")
    }

    /// AN EXPLICIT PATH WINS. This is the whole reason the setting exists: a
    /// windowed app inherits macOS's own agent, which is not where 1Password's or
    /// Secretive's keys are, so the user's choice must not be second to the
    /// environment.
    @Test func anExplicitPathBeatsTheInheritedOne() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/var/run/com.apple.launchd.AAA/Listeners"))
        #expect(probe.resolvedSocketPath(configured: "/tmp/vendor/agent.sock")
                == "/tmp/vendor/agent.sock")
    }

    @Test func aTildePathIsExpanded() {
        let probe = SSHAgentProbe(environment: EmptyEnvironment())
        let resolved = probe.resolvedSocketPath(configured: "~/Library/x/agent.sock")
        #expect(resolved?.hasPrefix("/") == true)
        #expect(resolved?.contains("~") == false)
    }

    /// The vendor table is data, not prose: the paths are the ones the current
    /// versions document, and only sockets that exist are offered.
    @Test func vendorSuggestionsOnlyNameSocketsThatAreThere() {
        let onePassword = SSHAgentProbe.vendorAgents.first { $0.name == "1Password" }
        #expect(onePassword?.socketPath
                == "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")
        let secretive = SSHAgentProbe.vendorAgents.first { $0.name == "Secretive" }
        #expect(secretive?.socketPath
                == "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh")

        // The table carries each vendor's own documentation, in ONE place so the
        // links are auditable rather than scattered through views and prose. (That
        // they resolve was checked by hand when they were written — 1Password's
        // developer.1password.com now 301s to www.1password.dev, which is why the
        // table names the destination and not the redirect.)
        for vendor in SSHAgentProbe.vendorAgents {
            #expect(vendor.documentation.hasPrefix("https://"), "\(vendor.name) has no doc link")
            #expect(!vendor.name.isEmpty)
            #expect(vendor.socketPath.hasPrefix("~/"))
        }

        #expect(SSHAgentProbe(environment: EmptyEnvironment()).vendorAgentsPresent().isEmpty)
        let present = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: nil,
            existingPaths: [onePassword!.expandedPath]))
        #expect(present.vendorAgentsPresent().map(\.name) == ["1Password"])
    }
}

// MARK: - What the agent said

struct SSHAgentStateTests {

    /// A path we were told about that isn't there: the classic stale
    /// SSH_AUTH_SOCK, left behind by an agent that has quit.
    @Test func aStaleSocketPathReadsAsMissingRatherThanUnreachable() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/gone/agent.sock"))
        #expect(probe.probe() == .socketMissing(path: "/tmp/gone/agent.sock"))
    }

    /// The socket file is there but nothing answers — an agent killed without
    /// tidying up, or one wedged mid-request.
    @Test func aDeadSocketReadsAsUnreachableWithTheReasonKept() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/dead.sock",
            existingPaths: ["/tmp/dead.sock"],
            connectFailure: "connection refused"))
        #expect(probe.probe() == .unreachable(path: "/tmp/dead.sock", reason: "connection refused"))
    }

    /// A RUNNING AGENT WITH NOTHING IN IT is its own state, not a kind of
    /// failure: a locked vault and a fresh login both look like this, and the fix
    /// ("unlock it / add a key") is nothing like the fix for a missing agent.
    @Test func anAgentHoldingNoKeysIsRunningWithZeroIdentities() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/empty.sock",
            existingPaths: ["/tmp/empty.sock"],
            reply: SSHAgentFake.identitiesAnswer([])))
        let state = probe.probe()
        #expect(state == .running(path: "/tmp/empty.sock", identities: []))
        #expect(state.canSignIn == false)
        #expect(state.summary == "Your SSH agent is running but holds no keys.")
    }

    @Test func anAgentWithKeysReportsThemInOrderWithTypesAndComments() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/full.sock",
            existingPaths: ["/tmp/full.sock"],
            reply: SSHAgentFake.identitiesAnswer([
                (type: "ssh-ed25519", comment: "alex@mac"),
                (type: "sk-ssh-ed25519@openssh.com", comment: "yubikey"),
                (type: "ssh-rsa-cert-v01@openssh.com", comment: ""),
            ])))
        let state = probe.probe()
        #expect(state.identities.count == 3)
        #expect(state.canSignIn)
        #expect(state.identities[0] == SSHAgentIdentity(keyType: "ssh-ed25519", comment: "alex@mac"))
        #expect(state.identities[1].isSecurityKey)
        #expect(state.identities[2].isCertificate)
        // A key with no comment still has something to call itself.
        #expect(state.identities[2].label == "ssh-rsa-cert-v01@openssh.com")
        // The count is what the editor promises to say.
        #expect(state.summary.hasPrefix("Your SSH agent has 3 keys: alex@mac, yubikey,"))
    }

    @Test func oneKeyIsSingular() {
        let probe = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/one.sock",
            existingPaths: ["/tmp/one.sock"],
            reply: SSHAgentFake.identitiesAnswer([(type: "ssh-ed25519", comment: "only")])))
        #expect(probe.probe().summary == "Your SSH agent has 1 key: only.")
    }

    /// An agent that refuses to list, and one that dies mid-answer, are both
    /// "there but no use" — with the reason kept so the user isn't guessing.
    @Test func aRefusalOrATruncatedAnswerIsUnreachableNotEmpty() {
        let refusing = SSHAgentProbe(environment: FakeEnvironment(
            inheritedSocketPath: "/tmp/refuse.sock",
            existingPaths: ["/tmp/refuse.sock"],
            reply: SSHAgentFake.failure()))
        #expect(refusing.probe() == .unreachable(path: "/tmp/refuse.sock",
                                                 reason: "the agent refused to list its keys"))

        var dying = FakeEnvironment(inheritedSocketPath: "/tmp/dying.sock",
                                    existingPaths: ["/tmp/dying.sock"])
        dying.truncateReply = true
        if case .unreachable(let path, _) = SSHAgentProbe(environment: dying).probe() {
            #expect(path == "/tmp/dying.sock")
        } else {
            Issue.record("an agent that closed mid-answer must not read as running")
        }
    }
}

// MARK: - The wire format, defensively

struct SSHAgentWireTests {

    @Test func theRequestIsTheOneOpenSSHDefines() {
        // uint32 length = 1, then the single byte 11 (REQUEST_IDENTITIES).
        #expect(Array(SSHAgentWire.requestIdentities()) == [0, 0, 0, 1, 11])
    }

    @Test func aWellFormedAnswerRoundTrips() throws {
        let bytes = SSHAgentFake.identitiesAnswer([(type: "ssh-ed25519", comment: "a@b")])
        let ids = try SSHAgentWire.parseIdentitiesAnswer(bytes)
        #expect(ids == [SSHAgentIdentity(keyType: "ssh-ed25519", comment: "a@b")])
    }

    /// Everything here arrives from another process, so a length that overruns the
    /// buffer has to be an error rather than an out-of-bounds read.
    @Test func malformedAnswersThrowInsteadOfReadingPastTheBuffer() {
        // Truncated frame.
        #expect(throws: SSHAgentTransportError.self) {
            _ = try SSHAgentWire.parseIdentitiesAnswer(Data([0, 0, 0]))
        }
        // Right frame, wrong message type.
        #expect(throws: SSHAgentTransportError.self) {
            _ = try SSHAgentWire.parseIdentitiesAnswer(SSHAgentFake.frame(Data([99])))
        }
        // Says two keys, sends none.
        var lying = Data([SSHAgentWire.identitiesAnswerType])
        lying.append(contentsOf: [0, 0, 0, 2])
        #expect(throws: SSHAgentTransportError.self) {
            _ = try SSHAgentWire.parseIdentitiesAnswer(SSHAgentFake.frame(lying))
        }
        // A key blob whose length runs past the end.
        var overrun = Data([SSHAgentWire.identitiesAnswerType])
        overrun.append(contentsOf: [0, 0, 0, 1])
        overrun.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])
        #expect(throws: SSHAgentTransportError.self) {
            _ = try SSHAgentWire.parseIdentitiesAnswer(SSHAgentFake.frame(overrun))
        }
        // An implausible key count must not be allocated on the peer's word.
        var absurd = Data([SSHAgentWire.identitiesAnswerType])
        absurd.append(contentsOf: [0x00, 0x10, 0x00, 0x00])
        #expect(throws: SSHAgentTransportError.self) {
            _ = try SSHAgentWire.parseIdentitiesAnswer(SSHAgentFake.frame(absurd))
        }
    }

    @Test func framedLengthReadsTheBigEndianPrefixAndWaitsForFourBytes() {
        #expect(SSHAgentWire.framedLength(Data([0, 0, 1])) == nil)
        #expect(SSHAgentWire.framedLength(Data([0, 0, 1, 0])) == 256)
    }
}

// MARK: - The three failure modes

struct SSHAgentDiagnosisTests {

    /// libssh's "denied" is ambiguous, so the message comes from the AGENT's
    /// state. These three are the failures users actually hit, and each names a
    /// different thing to do.
    @Test func deniedMeansThreeDifferentThingsAndSaysWhichOne() {
        let noAgent = SSHAgentDiagnosis.message(for: .denied, state: .noAgent, username: "alex")
        #expect(noAgent.contains("No SSH agent is running"))
        #expect(noAgent.contains("SSH Agent Socket"))

        let empty = SSHAgentDiagnosis.message(
            for: .denied, state: .running(path: "/tmp/a.sock", identities: []), username: "alex")
        #expect(empty.contains("holds no keys"))
        #expect(empty.contains("ssh-add"))
        #expect(!empty.contains("No SSH agent is running"))

        let refused = SSHAgentDiagnosis.message(
            for: .denied,
            state: .running(path: "/tmp/a.sock",
                            identities: [SSHAgentIdentity(keyType: "ssh-ed25519", comment: "work")]),
            username: "alex")
        #expect(refused.contains("server refused"))
        #expect(refused.contains("work"), "the keys that were offered must be named")
        #expect(refused.contains("alex"), "the username is half the fix")
        // The three are genuinely different sentences, which is the whole point.
        #expect(Set([noAgent, empty, refused]).count == 3)
    }

    /// A stale socket and a dead one get their own wording: one is "your agent has
    /// quit", the other is "your agent isn't answering".
    @Test func staleAndUnreachableSocketsAreDistinguished() {
        let stale = SSHAgentDiagnosis.message(
            for: .denied, state: .socketMissing(path: "/tmp/gone.sock"), username: "alex")
        #expect(stale.contains("/tmp/gone.sock"))
        #expect(stale.contains("gone"))

        let dead = SSHAgentDiagnosis.message(
            for: .denied,
            state: .unreachable(path: "/tmp/dead.sock", reason: "connection refused"),
            username: "alex")
        #expect(dead.contains("connection refused"))
        #expect(dead != stale)
    }

    /// A hardware key in the agent gets the extra sentence that saves the support
    /// ticket: it has to be plugged in and touched.
    @Test func aSecurityKeyInTheAgentAddsTheTouchAdvice() {
        let message = SSHAgentDiagnosis.message(
            for: .denied,
            state: .running(path: "/tmp/a.sock", identities: [
                SSHAgentIdentity(keyType: "sk-ssh-ed25519@openssh.com", comment: "yubi")]),
            username: "alex")
        #expect(message.contains("touched"))
    }

    /// The two outcomes libssh CAN distinguish are reported as themselves rather
    /// than folded into "denied".
    @Test func partialAndTransportFailuresAreNotToldAsDenials() {
        let partial = SSHAgentDiagnosis.message(for: .partial, state: .noAgent, username: "alex")
        #expect(partial.contains("accepted"))
        #expect(partial.contains("another sign-in step"))

        let broken = SSHAgentDiagnosis.message(for: .transport("socket closed"),
                                               state: .noAgent, username: "alex")
        #expect(broken.contains("socket closed"))
    }

    /// The bridge's error codes are the contract between Objective-C and this
    /// mapping — a renumbering would silently turn every failure into "denied".
    @Test func bridgeErrorCodesClassifyAsThemselves() {
        func error(_ code: SSHBridgeErrorCode) -> NSError {
            NSError(domain: "SSHBridge", code: code.rawValue,
                    userInfo: [NSLocalizedDescriptionKey: "detail"])
        }
        #expect(SSHAgentDiagnosis.classify(error(.agentDenied)) == .denied)
        #expect(SSHAgentDiagnosis.classify(error(.agentPartial)) == .partial)
        #expect(SSHAgentDiagnosis.classify(error(.agentTransport)) == .transport("detail"))
        // Anything from elsewhere is a transport-level unknown, never a silent denial.
        let foreign = NSError(domain: "Elsewhere", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "who knows"])
        #expect(SSHAgentDiagnosis.classify(foreign) == .transport("who knows"))
    }
}

// MARK: - The config surface

@MainActor
struct SSHAgentSettingTests {

    /// The argv the subprocess path would run, same helper shape as
    /// SSHSettingDescriptorTests.
    private static func sshArgs(_ c: SubprocessTunnelConfig) -> [String] {
        SubprocessTunnelManager.command(for: c, password: nil)?.1 ?? []
    }

    @Test func theAgentSocketIsARealSpecInTheSignInGroup() {
        let spec = SSHSettings.catalog["ssh.agent-socket"]
        #expect(spec.name == "SSH Agent Socket")
        #expect(spec.group == .signIn)
        #expect(!spec.summary.isEmpty)
        #expect(spec.manualAnchor == "ssh-agent-socket")
        // Searchable and addressable like every other setting.
        #expect(SettingSurface.owning("ssh.agent-socket") == .ssh)
        // Related links: the method and the socket are useless apart.
        #expect(spec.related.contains("ssh.auth-method"))
        #expect(SettingRelations.related["ssh.auth-method"]?.contains("ssh.agent-socket") == true)
    }

    /// A path both connect paths would choke on is refused with its fix, not
    /// handed to libssh (which rejects an empty IdentityAgent) or interpolated
    /// into an `-o IdentityAgent="…"` line it could break open.
    @Test func agentSocketPathsAreValidatedBeforeTheyReachEitherConnectPath() {
        #expect(SubprocessTunnelConfig.agentSocketProblem("") == nil)
        #expect(SubprocessTunnelConfig.agentSocketProblem("   ") == nil)
        #expect(SubprocessTunnelConfig.agentSocketProblem("~/Library/x/agent.sock") == nil)
        #expect(SubprocessTunnelConfig.agentSocketProblem("/tmp/a b/agent.sock") == nil)
        #expect(SubprocessTunnelConfig.agentSocketProblem("agent.sock")?
            .contains("full path") == true)
        #expect(SubprocessTunnelConfig.agentSocketProblem("/tmp/\"evil\"/agent.sock")?
            .contains("quote") == true)
        let tooLong = "/tmp/" + String(repeating: "x", count: 200) + "/agent.sock"
        #expect(SubprocessTunnelConfig.agentSocketProblem(tooLong)?.contains("too long") == true)
        // And the block is wired into the one gate connect() and the editor share.
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.sshAgentSocket = "/tmp/\"evil\"/agent.sock"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c)?.contains("quote") == true)
    }

    @Test func aBlankAgentSocketNormalizesBackToNil() {
        var c = SubprocessTunnelConfig()
        c.sshAgentSocket = "   "
        #expect(c.normalized().sshAgentSocket == nil)
        c.sshAgentSocket = " ~/x/agent.sock "
        #expect(c.normalized().sshAgentSocket == "~/x/agent.sock")
    }

    /// Configs written before this field existed still decode — the same
    /// tolerance every libssh-era field has.
    @Test func configsSavedBeforeTheAgentSocketExistedStillDecode() throws {
        let json = """
        {"id":"\(UUID().uuidString)","kind":"ssh","name":"old","server":"h","username":"u",
         "sshMode":"socks","socksPort":1080,"setSystemProxy":false,"forwards":[],
         "identityFile":"","compression":false,"useJumpHost":false,"jumpHost":"",
         "jumpUsername":"","jumpIdentityFile":"","serverAliveInterval":30,
         "strictHostKey":"accept-new","sshExtraOptions":[],"authMode":"password",
         "realm":"","trustedCertSHA256":"","caFile":"","spoofOS":"",
         "proxyMode":"systemDefault","proxyURL":"","proxyUsername":"","disableDTLS":false,
         "disableCSD":false,"csdWrapper":"","browser":{},"samlBrowser":"","extraArgs":[],
         "usergroup":"","tokenMode":"","clientCertFile":"","clientKeyFile":"",
         "ocCompression":"","enablePFS":false,"disableIPv6":false,"noHTTPKeepalive":false,
         "localHostname":"","userAgent":"","versionString":"","preferInProcess":false}
        """
        let decoded = try JSONDecoder().decode(SubprocessTunnelConfig.self,
                                              from: Data(json.utf8))
        #expect(decoded.sshAgentSocket == nil)
        #expect(SubprocessTunnelManager.sshAgentSocket(decoded) == nil)
    }

    /// `/usr/bin/ssh` has no flag for this — only the config keyword — and the
    /// value must be QUOTED, because every vendor path contains a space. Verified
    /// against the shipped OpenSSH with
    /// `ssh -G -o 'IdentityAgent="/tmp/a b/agent.sock"'`.
    @Test func theSubprocessPathPassesAQuotedIdentityAgent() {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.server = "h"
        c.username = "u"
        c.sshAuthMethod = "agent"
        c.sshAgentSocket = "/tmp/a b/agent.sock"
        let argv = Self.sshArgs(c)
        #expect(argv.contains("IdentityAgent=\"/tmp/a b/agent.sock\""))
        // Agent sign-in pins publickey and offers no identity file.
        #expect(argv.contains("PreferredAuthentications=publickey"))
        #expect(!argv.contains("-i"))

        // A method that never asks an agent doesn't pass the option at all.
        c.sshAuthMethod = "password"
        #expect(!Self.sshArgs(c)
            .contains { $0.hasPrefix("IdentityAgent=") })

        // Automatic DOES, because automatic tries the agent.
        c.sshAuthMethod = nil
        #expect(Self.sshArgs(c)
            .contains { $0.hasPrefix("IdentityAgent=") })
    }

    /// The in-process engine gets the same path, tilde-expanded once, on the
    /// config it actually authenticates with.
    @Test func theInProcessEngineIsGivenTheResolvedSocketPath() {
        var c = SubprocessTunnelConfig()
        c.sshAgentSocket = "~/Library/x/agent.sock"
        let resolved = SubprocessTunnelManager.sshAgentSocket(c)
        #expect(resolved?.hasPrefix("/") == true)
        #expect(resolved?.hasSuffix("/Library/x/agent.sock") == true)

        var config = SSHTunnelEngine.Config(host: "h", port: 22, username: "u",
                                            password: nil, identityFile: nil, socksPort: 1080)
        config.authMethod = "agent"
        config.agentSocketPath = resolved
        // Pinning the agent method means exactly one attempt: the agent's own
        // failure is what the user is told about, not a password prompt's.
        #expect((try? SSHTunnelEngine.authPlan(config)) == [.agent])
    }
}
