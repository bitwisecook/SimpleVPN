// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHAgentLiveTests.swift
//  AGENT SIGN-IN AGAINST A REAL AGENT AND A REAL SERVER. The fakes in
//  SSHAgentTests.swift prove the state machine; this file proves the claim that
//  matters and cannot be faked: that `ssh_userauth_agent` really reaches an
//  agent SimpleVPN pointed it at, that the SERVER really accepts the signature
//  the agent made, and that our own agent-protocol reader agrees with what
//  `ssh-add -l` says.
//
//  NO PRIVILEGE, NO NETWORK, NOTHING TOUCHED OUTSIDE /tmp. Each test starts its
//  OWN `/usr/bin/ssh-agent` on its own socket in a fresh temporary directory
//  (never the user's `SSH_AUTH_SOCK` — a test must not add keys to, or read, the
//  developer's real agent) and its own user-space `sshd` from
//  Tools/ssh-live-test-fixture.sh. Both are killed when the test ends.
//
//  WITHOUT THE FIXTURE EVERY TEST HERE SKIPS, exactly like SSHLiveIntegrationTests
//  — `liveAgentMode` always runs and prints which mode the run was in, so a green
//  suite can never be mistaken for a proven one. To create it:
//
//      ./Tools/ssh-live-test-fixture.sh
//      TEST_RUNNER_SIMPLEVPN_SSH_TEST_DIR=/tmp/simplevpn-ssh-live \
//        xcodebuild -project SimpleVPN.xcodeproj -scheme SimpleVPN \
//        -destination 'platform=macOS' test -only-testing:SimpleVPNTests
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - A real ssh-agent, owned by the test

/// One `/usr/bin/ssh-agent` on a socket of our choosing, with whichever keys the
/// test adds. Never the developer's agent: `ssh-add` here can only ever see the
/// socket this object made.
nonisolated final class LiveSSHAgent: @unchecked Sendable {
    enum Failure: Error, CustomStringConvertible {
        case noAgentBinary
        case launchFailed(String)
        case neverListened
        case addFailed(String)
        var description: String {
            switch self {
            case .noAgentBinary: "no /usr/bin/ssh-agent on this machine"
            case .launchFailed(let s): "ssh-agent wouldn't launch: \(s)"
            case .neverListened: "ssh-agent never created its socket"
            case .addFailed(let s): "ssh-add failed: \(s)"
            }
        }
    }

    static let agentPath = "/usr/bin/ssh-agent"
    static let addPath = "/usr/bin/ssh-add"
    static var isAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: agentPath)
            && FileManager.default.isExecutableFile(atPath: addPath)
    }

    let socketPath: String
    private let directory: URL
    private let process = Process()
    private let lock = NSLock()
    private var reaped = false

    init() throws {
        guard Self.isAvailable else { throw Failure.noAgentBinary }
        // DELIBERATELY /tmp AND A SHORT NAME, not NSTemporaryDirectory(): the test
        // host's temporary directory is a long sandboxed path
        // (/var/folders/…/T/), and an AF_UNIX path is capped at 104 bytes — the
        // first version of this file put the socket there and ssh-agent silently
        // never bound it. (The same ceiling users hit with vendor agents, which is
        // why `agentSocketProblem` reports it rather than failing at connect.)
        directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("svpn-agent-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        socketPath = directory.appendingPathComponent("agent.sock").path

        // -D keeps it in the foreground so the Process owns its lifetime; -a binds
        // the socket where we say, which is the same thing a vendor agent does and
        // the reason `ssh.agent-socket` exists at all.
        let log = directory.appendingPathComponent("agent.log")
        _ = FileManager.default.createFile(atPath: log.path, contents: nil)
        process.executableURL = URL(fileURLWithPath: Self.agentPath)
        process.arguments = ["-D", "-a", socketPath]
        if let handle = try? FileHandle(forWritingTo: log) {
            process.standardOutput = handle
            process.standardError = handle
        }
        do { try process.run() } catch { throw Failure.launchFailed("\(error)") }

        let appeared = Loopback.wait(upTo: 10) {
            FileManager.default.fileExists(atPath: self.socketPath)
        }
        guard appeared else {
            let text = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
            stop()
            throw Failure.launchFailed("socket never appeared at \(socketPath): \(text)")
        }
    }

    /// `ssh-add` the key, talking to THIS agent only.
    func add(keyPath: String) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: Self.addPath)
        p.arguments = [keyPath]
        p.environment = ["SSH_AUTH_SOCK": socketPath, "PATH": "/usr/bin:/bin"]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        do { try p.run() } catch { throw Failure.addFailed("\(error)") }
        let text = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw Failure.addFailed(text) }
    }

    /// What `ssh-add -l` says this agent holds — the independent witness our own
    /// protocol reader is checked against.
    func sshAddListing() -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: Self.addPath)
        p.arguments = ["-l"]
        p.environment = ["SSH_AUTH_SOCK": socketPath, "PATH": "/usr/bin:/bin"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return "" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        guard !reaped else { return }
        reaped = true
        if process.processIdentifier > 0 {
            kill(process.processIdentifier, SIGTERM)
            process.waitUntilExit()
        }
        try? FileManager.default.removeItem(at: directory)
    }

    deinit { stop() }
}

// MARK: - The tests

/// Whether the live half can run at all: a fixture on disk AND the OpenSSH agent
/// tools. A file-scope constant rather than a static member because `.enabled(if:)`
/// is evaluated in a nonisolated context, and this suite's members are not.
nonisolated let sshAgentLiveTestsEnabled = LiveSSHFixture.isAvailable && LiveSSHAgent.isAvailable

// Real ssh-agent, real sshd, real sockets — see the note on SSHLiveIntegrationTests.
// An agent that never answers is indistinguishable from a slow one until a deadline
// says otherwise.
@Suite(.serialized, .timeLimit(.minutes(1)))
struct SSHAgentLiveTests {

    private static var enabled: Bool { sshAgentLiveTestsEnabled }

    /// Always runs, so a run that proved nothing says so out loud.
    @Test func liveAgentMode() {
        let mode = Self.enabled
            ? "ENABLED — real ssh-agent + real sshd"
            : (LiveSSHAgent.isAvailable ? "SKIPPED — \(LiveSSHFixture.status)"
                                        : "SKIPPED — no /usr/bin/ssh-agent")
        print("   SSH agent live tests: \(mode)")
        #expect(true)
    }

    private func fixture() throws -> LiveSSHFixture {
        try #require(LiveSSHFixture.shared, "the live SSH fixture is required for this test")
    }

    private func connected(to server: LiveSSHServer, _ fixture: LiveSSHFixture) throws -> SSHSession {
        let session = SSHSession()
        try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                            kexAlgorithms: nil, compression: false)
        try session.verifyHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex,
                                  strict: "yes")
        return session
    }

    /// THE PROOF. A key that exists only inside an agent signs us in to a real
    /// sshd, through `ssh_userauth_agent`, at a socket SimpleVPN chose — the whole
    /// feature, end to end, with no private key in our hands at any point.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func aKeyHeldOnlyByAnAgentSignsInToARealServer() throws {
        let fixture = try fixture()
        let agent = try LiveSSHAgent()
        defer { agent.stop() }
        try agent.add(keyPath: fixture.clientKeyPath)

        // Our own reader agrees with ssh-add about what the agent is holding.
        let state = SSHAgentProbe().probe(configuredSocketPath: agent.socketPath)
        #expect(state.identities.count == 1, "probe saw \(state.identities)")
        #expect(state.identities.first?.keyType == "ssh-ed25519")
        let listing = agent.sshAddListing()
        #expect(listing.contains("ED25519"), "ssh-add -l said: \(listing)")
        print("   agent holds: \(state.summary)")
        print("   ssh-add -l: \(listing.trimmingCharacters(in: .whitespacesAndNewlines))")

        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }

        // The fixture's sshd offers publickey ONLY, so this cannot pass by
        // falling back to anything else.
        #expect(try session.authMethods(forUser: fixture.user) == ["publickey"])
        try session.useAgentSocketPath(agent.socketPath)
        try session.authAgent(forUser: fixture.user)

        // And the authenticated session really works: open a channel through it.
        session.enterDataMode()
        print("   agent sign-in succeeded against sshd on port \(server.port)")
    }

    /// The engine's own path — the config field, the plan, the bridge call and the
    /// diagnosis — not just the bridge in isolation.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func theEngineSignsInThroughTheConfiguredAgentSocket() throws {
        let fixture = try fixture()
        let agent = try LiveSSHAgent()
        defer { agent.stop() }
        try agent.add(keyPath: fixture.clientKeyPath)
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        var config = SSHTunnelEngine.Config(host: "127.0.0.1", port: Int(server.port),
                                            username: fixture.user, password: nil,
                                            identityFile: nil, socksPort: 1080)
        config.authMethod = "agent"
        config.agentSocketPath = agent.socketPath
        #expect(try SSHTunnelEngine.authPlan(config) == [.agent])

        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        try SSHTunnelEngine.authAgent(session, config)
    }

    /// FAILURE MODE 3 — the server refuses what the agent offered. The agent holds
    /// a real, valid key that is simply not in `authorized_keys`, so this is the
    /// server's "no" and nothing else: the message must name the keys and point at
    /// the server, never at the agent.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func aKeyTheServerDoesntKnowIsReportedAsTheServerRefusingIt() throws {
        let fixture = try fixture()
        let agent = try LiveSSHAgent()
        defer { agent.stop() }
        try agent.add(keyPath: fixture.unauthorizedKeyPath)
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        let state = SSHAgentProbe().probe(configuredSocketPath: agent.socketPath)
        #expect(state.identities.count == 1)

        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        try session.useAgentSocketPath(agent.socketPath)
        var thrown: (any Error)?
        do { try session.authAgent(forUser: fixture.user) } catch { thrown = error }
        let error = try #require(thrown, "an unauthorized key must not sign in")
        // libssh cannot tell this from "no agent" — the probe is what does.
        #expect(SSHAgentDiagnosis.classify(error) == .denied)
        let message = SSHAgentDiagnosis.message(for: .denied, state: state, username: fixture.user)
        #expect(message.contains("server refused"))
        #expect(message.contains(fixture.user))
        print("   refused-by-server message: \(message)")
    }

    /// FAILURE MODE 2 — a running agent holding nothing. libssh says exactly what
    /// it says for "no agent"; the probe is the only thing that knows the
    /// difference, and this proves it does against a real empty agent.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func anEmptyAgentIsReportedAsHavingNoKeysRatherThanAsMissing() throws {
        let fixture = try fixture()
        let agent = try LiveSSHAgent()
        defer { agent.stop() }
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        let state = SSHAgentProbe().probe(configuredSocketPath: agent.socketPath)
        #expect(state == .running(path: agent.socketPath, identities: []))

        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        try session.useAgentSocketPath(agent.socketPath)
        #expect(throws: (any Error).self) { try session.authAgent(forUser: fixture.user) }
        let message = SSHAgentDiagnosis.message(for: .denied, state: state, username: fixture.user)
        #expect(message.contains("holds no keys"))
        #expect(!message.contains("No SSH agent is running"))
        print("   empty-agent message: \(message)")
    }

    /// FAILURE MODE 1 — a stale socket path. The agent is stopped while the path
    /// stays configured, which is what a quit vendor agent leaves behind.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func aStoppedAgentIsReportedAsGoneAndStillRefusesToSignIn() throws {
        let fixture = try fixture()
        let agent = try LiveSSHAgent()
        try agent.add(keyPath: fixture.clientKeyPath)
        #expect(SSHAgentProbe().probe(configuredSocketPath: agent.socketPath).canSignIn)
        let stalePath = agent.socketPath
        agent.stop()   // the socket goes with the directory, exactly like a quit agent

        let state = SSHAgentProbe().probe(configuredSocketPath: stalePath)
        #expect(state.canSignIn == false)
        #expect(state.socketPath == stalePath)

        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        try session.useAgentSocketPath(stalePath)
        #expect(throws: (any Error).self) { try session.authAgent(forUser: fixture.user) }
        let message = SSHAgentDiagnosis.message(for: .denied, state: state, username: fixture.user)
        #expect(message.contains(stalePath))
        print("   stale-socket message: \(message)")
    }

    /// The socket the user chose is the one that is used — not the one the process
    /// inherited. Two live agents, and the key is only in the second: signing in
    /// can only work if the configured path won.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func theConfiguredSocketWinsOverTheInheritedOne() throws {
        let fixture = try fixture()
        let empty = try LiveSSHAgent()
        defer { empty.stop() }
        let holding = try LiveSSHAgent()
        defer { holding.stop() }
        try holding.add(keyPath: fixture.clientKeyPath)

        #expect(SSHAgentProbe().probe(configuredSocketPath: empty.socketPath).identities.isEmpty)
        #expect(SSHAgentProbe().probe(configuredSocketPath: holding.socketPath).identities.count == 1)

        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        // Pointed at the empty one first, then at the one holding the key: the LAST
        // word is what libssh uses, and it must be a path we set rather than the
        // environment's.
        try session.useAgentSocketPath(empty.socketPath)
        try session.useAgentSocketPath(holding.socketPath)
        try session.authAgent(forUser: fixture.user)
    }

    /// An empty path is refused rather than quietly meaning "the default" —
    /// libssh treats "" as an error, and a config that lost its value must not
    /// silently fall back to somebody else's agent.
    @Test(.enabled(if: sshAgentLiveTestsEnabled))
    func anEmptyAgentSocketPathIsRejected() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }
        #expect(throws: (any Error).self) { try session.useAgentSocketPath("") }
        #expect(throws: (any Error).self) { try session.useAgentSocketPath("   ") }
    }
}
