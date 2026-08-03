// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthenticatedProbe.swift
//  Runs a planned ladder against a real VPN: the network half of the staged
//  probe. Every stage is one short exchange, and the state that has to survive
//  between stages (the TLS result, the gateway's IKE reply, a live SSH session)
//  lives in the actor rather than in globals.
//
//  What this file may and may not do is decided elsewhere — the ordering and
//  the stop rule are in ProbeLadder.swift, and the account boundary is enforced
//  by ProbeLadderEngine, which simply never calls `execute` for a step marked
//  `requiresAccountCredentials` unless the user opted in. This file therefore
//  contains no "should I sign in?" logic at all, and can't accidentally grow
//  any: the sign-in stages here are the ONLY place account credentials are
//  touched, and they arrive through `ProbeSignInMaterial`, which is nil for
//  every automatic run.
//
//  Nothing here writes anything anywhere: no known_hosts entry, no keychain
//  item, no session. Sockets are opened, one packet is exchanged, they close.
//

import Foundation

/// Account credentials for an opted-in sign-in test. Only ever non-nil when the
/// user clicked "Test sign-in too"; resolved through the SAME credential
/// machinery a connect uses, so Touch ID / 1Password approve once, at the
/// moment of a genuine need.
nonisolated struct ProbeSignInMaterial: Sendable {
    var username: String
    var password: String
    var otp: String
    var privateKeyPassphrase: String

    /// Never rendered — but the redactor is told about these so an error
    /// message that quotes them back at us can't reach the screen.
    var secrets: [String] {
        [password, otp, privateKeyPassphrase].filter { $0.count >= 4 }
    }
}

nonisolated enum AuthenticatedProbe {

    /// Plan, then run. `progress` fires after every step so the ladder fills in
    /// live rather than appearing all at once at the end.
    ///
    /// - `egressBoundIf`: the `IP_BOUND_IF` index every probe socket is pinned to.
    ///   nil ⇒ resolve the current PHYSICAL (non-tunnel) egress here, so the
    ///   handshake probes travel the real underlying path and can't loop back
    ///   through the very VPN they're testing — even while it owns the default
    ///   route. 0/unresolvable falls back to normal routing.
    /// - `seed`: an earlier ladder to resume from. Its leading run of settled
    ///   steps (passed / not-applicable) is carried forward and only the first
    ///   unsettled rung onward is re-run — the incremental re-check.
    static func run(facts: ProbeTargetFacts,
                    includeAccountSteps: Bool = false,
                    signIn: ProbeSignInMaterial? = nil,
                    egressBoundIf: UInt32? = nil,
                    seed: ProbeLadder? = nil,
                    progress: (@Sendable ([ProbeStep]) -> Void)? = nil) async -> ProbeLadder {
        var ladder = ProbeLadderPlan.ladder(for: facts)
        // A nonisolated async func runs on its caller's actor (the main one here),
        // so keep the routing-table sysctl off it — same reasoning as NetworkMemory.
        let boundIf: UInt32
        if let egressBoundIf {
            boundIf = egressBoundIf
        } else {
            boundIf = await Task.detached { NetworkIdentity.physicalEgressBoundIf() }.value
        }
        let runner = ProbeStageRunner(facts: facts, signIn: signIn, egressBoundIf: boundIf)
        ladder.includedAccountSteps = includeAccountSteps
        // Only a same-shaped seed can be resumed; a plan that changed shape (the
        // profile was edited) re-runs whole.
        let seedSteps = seed.flatMap { $0.steps.map(\.stage) == ladder.steps.map(\.stage) ? $0.steps : nil }
        ladder.steps = await ProbeLadderEngine.run(
            plan: ladder.steps,
            includeAccountSteps: includeAccountSteps,
            seed: seedSteps,
            progress: progress) { stage in
                await runner.execute(stage)
            }
        await runner.finish()
        ladder.finishedAt = .now
        return ladder
    }
}

// MARK: - The stage runner

actor ProbeStageRunner {

    private let facts: ProbeTargetFacts
    private let signIn: ProbeSignInMaterial?
    /// The physical-egress interface index every probe socket binds to (0 ⇒ unbound).
    private let egressBoundIf: UInt32

    // Carried between stages.
    private var tls: ProbeTLSResult?
    private var ssh: SSHProbeSession?
    private var sshHandshake: SSHProbeSession.Handshake?
    private var sshMethods: [String] = []
    private var ikeSPI: [UInt8] = []
    private var ikeReply: [UInt8]?

    private let timeout: TimeInterval = 4

    init(facts: ProbeTargetFacts, signIn: ProbeSignInMaterial?, egressBoundIf: UInt32 = 0) {
        self.facts = facts
        self.signIn = signIn
        self.egressBoundIf = egressBoundIf
    }

    func finish() {
        ssh?.disconnect()
        ssh = nil
    }

    func execute(_ stage: ProbeStage) async -> ProbeStepOutcome {
        switch stage {
        case .dnsResolve: return await resolveName()
        case .reachability: return await reachability()

        case .openVPNReset: return await openVPNAnonymousReset()
        case .openVPNStaticKey: return await openVPNSignedReset()
        case .openVPNClientCertificate, .sslClientCertificate: return clientCertificate()
        case .openVPNServerCertificate: return .notApplicable("Nothing to check here.")
        case .openVPNSignIn, .sslSignIn: return signInNotImplemented()

        case .sshBanner: return await sshBanner()
        case .sshKeyExchange: return await sshKeyExchange()
        case .sshHostKey: return await sshHostKey()
        case .sshAuthMethods: return await sshAuthenticationMethods()
        case .sshPublicKey: return await sshPublicKey()
        case .sshPasswordSignIn: return await sshPasswordSignIn()

        case .ikeReachability: return await ikeReachability()
        case .ikeSAInit: return ikeProposal()
        case .ikeNATTraversal: return await ikeNATTraversal()
        case .ikeAuth: return .notApplicable("Nothing to check here.")

        case .tlsHandshake: return await tlsHandshake()
        case .vendorClassification: return vendorClassification()
        case .clientCertificateRequested: return clientCertificateRequested()

        case .wireGuardHandshake: return await wireGuardHandshake()

        case .controlPlaneReachability: return await controlPlaneReachability()
        case .controlPlaneTLS: return await controlPlaneTLS()
        case .controlPlaneIdentity: return await controlPlaneIdentity()
        }
    }

    // MARK: Shared

    private func resolveName() async -> ProbeStepOutcome {
        let host = facts.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            return .failed("This VPN has no address to look up.",
                           remedy: .probeRemedy(.nameLookupFailed, vpnName: facts.profileName))
        }
        if NetworkProbes.isIPv4Literal(host) {
            return .ok("The VPN is set up with an address, so there was nothing to look up.",
                       evidence: ["Address: \(host)"])
        }
        let addresses = await NetworkProbes.resolve(host: host)
        let all = addresses.v4 + addresses.v6
        guard !all.isEmpty else {
            return .failed("\(host) didn\u{2019}t resolve to an address on this network.",
                           evidence: ["Looked up: \(host)"],
                           remedy: .probeRemedy(.nameLookupFailed, vpnName: facts.profileName,
                                                detail: "getaddrinfo returned no records for \(host)"))
        }
        return .ok("\(host) resolves here.",
                   evidence: ["Addresses: \(all.prefix(6).joined(separator: ", "))"])
    }

    private var isDatagram: Bool {
        switch facts.kind {
        case .wireGuard, .ikev2, .ipsec, .l2tp: return true
        case .openVPN: return facts.transport != .tcp
        default: return false
        }
    }

    private func reachability() async -> ProbeStepOutcome {
        if isDatagram { return await datagramReachability() }
        return await streamReachability()
    }

    private func streamReachability() async -> ProbeStepOutcome {
        let result = await VPNProbe.tcpExchange(host: facts.host, port: facts.port,
                                                payload: [], timeout: timeout, boundIf: egressBoundIf)
        switch result {
        case .reply, .connectedNoReply:
            return .ok("The VPN accepts connections on port \(facts.port).",
                       evidence: ["TCP \(facts.host):\(facts.port) connected"])
        case .refused:
            return .failed("Nothing is listening on port \(facts.port).",
                           evidence: ["TCP \(facts.host):\(facts.port) refused"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        case .silence, .failed:
            return .failed("Traffic to port \(facts.port) went nowhere \u{2014} no answer, and no refusal either.",
                           evidence: ["TCP \(facts.host):\(facts.port) timed out after \(Int(timeout))s"],
                           remedy: .probeRemedy(.portFiltered, vpnName: facts.profileName))
        }
    }

    /// UDP has no handshake, so "reachable" can only mean "nothing refused it".
    /// Said plainly rather than dressed up as a connection.
    private func datagramReachability() async -> ProbeStepOutcome {
        let payload = facts.kind == .openVPN
            ? VPNProbe.openVPNResetPacket(sessionID: (0..<8).map { _ in UInt8.random(in: 0...255) })
            : [UInt8](repeating: 0, count: 32)
        let result = await VPNProbe.udpExchange(host: facts.host, port: facts.port,
                                                payload: payload, timeout: timeout, boundIf: egressBoundIf)
        switch result {
        case .reply:
            return .ok("The VPN answered on port \(facts.port).",
                       evidence: ["UDP \(facts.host):\(facts.port) replied"])
        case .refused:
            return .failed("Nothing is listening on port \(facts.port).",
                           evidence: ["UDP \(facts.host):\(facts.port) refused (ICMP port unreachable)"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        case .failed:
            return .failed("This Mac couldn\u{2019}t send anything to \(facts.host).",
                           evidence: ["No route to \(facts.host):\(facts.port)"],
                           remedy: .probeRemedy(.portFiltered, vpnName: facts.profileName))
        case .silence, .connectedNoReply:
            return .ok("The traffic left this Mac and nothing refused it.",
                       evidence: ["UDP \(facts.host):\(facts.port) sent, no reply yet \u{2014} normal for a VPN that only answers a signed hello"])
        }
    }

    // MARK: OpenVPN

    private func openVPNAnonymousReset() async -> ProbeStepOutcome {
        let session = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let tcp = facts.transport == .tcp
        let payload = VPNProbe.openVPNResetPacket(sessionID: session)
        let wire = tcp ? VPNProbe.openVPNTCPFramed(payload) : payload
        let result = tcp
            ? await VPNProbe.tcpExchange(host: facts.host, port: facts.port, payload: wire, timeout: timeout, boundIf: egressBoundIf)
            : await VPNProbe.udpExchange(host: facts.host, port: facts.port, payload: wire, timeout: timeout, boundIf: egressBoundIf)

        switch result {
        case .reply(let bytes):
            guard let reply = VPNProbe.parseOpenVPNReply(bytes, sentSessionID: session, framed: tcp),
                  reply.isServerReset else {
                return .failed("Something answered, but not the way OpenVPN does.",
                               evidence: ["\(bytes.count) bytes back, not a valid control packet"],
                               remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
            }
            return .ok("The VPN answered an unsigned hello, so it isn\u{2019}t using a shared handshake key.",
                       evidence: ["Replied \(reply.opcodeName)",
                                  "Server session id \(VPNProbe.hex(reply.serverSessionID))"])
        case .refused:
            return .failed("Nothing is listening there.",
                           evidence: ["Connection refused"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        default:
            // Silence is the EXPECTED answer when tls-auth/tls-crypt is on, so
            // it isn't a failure — the next rung is the one that can tell.
            let expected = facts.tlsKey != nil
            return ProbeStepOutcome(
                status: .ok,
                detail: expected
                    ? "No answer, which is exactly right: this VPN only replies to a hello signed with its shared key."
                    : "No answer to an unsigned hello. That means either a shared key is in use, or the traffic isn\u{2019}t arriving.",
                evidence: ["No reply within \(Int(timeout))s"])
        }
    }

    private func openVPNSignedReset() async -> ProbeStepOutcome {
        guard let key = facts.tlsKey else {
            return .notApplicable("This VPN doesn\u{2019}t use a shared handshake key.")
        }
        let session = (0..<8).map { _ in UInt8.random(in: 0...255) }
        guard let payload = OpenVPNControlPacket.signedReset(key: key, sessionID: session) else {
            return .failed("This Mac couldn\u{2019}t build the signed hello.",
                           evidence: ["Cipher setup failed for \(key.mode.rawValue)"])
        }
        let tcp = facts.transport == .tcp
        let wire = tcp ? VPNProbe.openVPNTCPFramed(payload) : payload
        let result = tcp
            ? await VPNProbe.tcpExchange(host: facts.host, port: facts.port, payload: wire, timeout: timeout, boundIf: egressBoundIf)
            : await VPNProbe.udpExchange(host: facts.host, port: facts.port, payload: wire, timeout: timeout, boundIf: egressBoundIf)

        switch result {
        case .reply(let raw):
            var bytes = raw
            if tcp, bytes.count > 2 { bytes = Array(bytes.dropFirst(2)) }    // strip the length prefix
            switch OpenVPNControlPacket.checkReply(bytes, key: key) {
            case .verified(let opcode, let serverSession):
                return .ok("The VPN accepted the shared key and answered.",
                           evidence: key.evidence + [
                            "Reply verified with the receiving key",
                            "Reply opcode \(opcode), server session id \(VPNProbe.hex(serverSession))",
                           ])
            case .wrapperMismatch:
                return .failed("The VPN answered, but its reply doesn\u{2019}t verify with this key.",
                               evidence: key.evidence + ["Reply arrived; the signature over it didn\u{2019}t match"],
                               remedy: .probeRemedy(.staticKeyRejected, vpnName: facts.profileName),
                               securityFinding: true)
            case .malformed:
                return .failed("Something answered, but not in OpenVPN\u{2019}s language.",
                               evidence: ["\(bytes.count) bytes back that aren\u{2019}t a control packet"],
                               remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
            }
        case .refused:
            return .failed("Nothing is listening there.", evidence: ["Connection refused"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        default:
            return .failed("The VPN ignored a hello signed with this key.",
                           evidence: key.evidence + ["No reply within \(Int(timeout))s"],
                           remedy: .probeRemedy(.staticKeyRejected, vpnName: facts.profileName))
        }
    }

    // MARK: Certificates (local, and honest about being local)

    private func clientCertificate() -> ProbeStepOutcome {
        guard let certPEM = facts.clientCertificatePEM, !certPEM.isEmpty,
              let certFacts = ProbeCertificateInspector.facts(pem: certPEM) else {
            return .notApplicable("This VPN doesn\u{2019}t use a client certificate.")
        }
        let (matches, locked) = ProbeCertificateInspector.keyMatchesCertificate(
            keyPEM: facts.clientKeyPEM, certificatePEM: certPEM)
        let chains = ProbeCertificateInspector.chains(leafPEM: certPEM, toAnchorsPEM: facts.caPEM)
        let verdict = CertificateVerdict.classify(
            notBefore: certFacts.notBefore, notAfter: certFacts.notAfter,
            keyMatchesCertificate: matches, privateKeyLocked: locked,
            chainsToTrustedAnchor: chains)

        var evidence = certFacts.evidence(role: "Your certificate")
        if let caPEM = facts.caPEM, let caFacts = ProbeCertificateInspector.facts(pem: caPEM) {
            evidence += ["Trusted authority: \(caFacts.displayName)"]
            if let notAfter = caFacts.notAfter {
                evidence += ["Authority valid until: \(CertificateFacts.format(notAfter))"]
            }
        } else {
            evidence += ["No certificate authority in this profile, so the chain couldn\u{2019}t be checked"]
        }
        switch matches {
        case .some(true): evidence.append("Private key matches the certificate")
        case .some(false): evidence.append("Private key does NOT match the certificate")
        case .none: evidence.append(locked ? "Private key is password-protected, so the pair couldn\u{2019}t be checked"
                                           : "No private key in this profile to check against")
        }

        switch verdict {
        case .ok(let days):
            let when = days.map { $0 <= 30 ? " It expires in \($0) day\($0 == 1 ? "" : "s")." : "" } ?? ""
            return .ok("Your certificate is valid and matches this VPN\u{2019}s authority." + when,
                       evidence: evidence)
        case .keyLocked:
            return ProbeStepOutcome(status: .ok,
                                    detail: "Your certificate is valid. Its key is password-protected, so the pair couldn\u{2019}t be checked.",
                                    evidence: evidence,
                                    remedy: .probeRemedy(.clientKeyLocked, vpnName: facts.profileName))
        case .expired(let on):
            return .failed("Your certificate expired\(on.map { " on \(CertificateFacts.format($0))" } ?? "").",
                           evidence: evidence,
                           remedy: .probeRemedy(.clientCertificateExpired, vpnName: facts.profileName),
                           securityFinding: false)
        case .notYetValid(let from):
            return .failed("Your certificate isn\u{2019}t valid until \(from.map(CertificateFacts.format) ?? "a future date").",
                           evidence: evidence,
                           remedy: .probeRemedy(.clientCertificateNotYetValid, vpnName: facts.profileName))
        case .keyMismatch:
            return .failed("The private key in this profile doesn\u{2019}t belong to its certificate.",
                           evidence: evidence,
                           remedy: .probeRemedy(.clientKeyMismatch, vpnName: facts.profileName),
                           securityFinding: true)
        case .chainUntrusted:
            return .failed("Your certificate wasn\u{2019}t issued by the authority this profile trusts.",
                           evidence: evidence,
                           remedy: .probeRemedy(.clientCertificateUntrusted, vpnName: facts.profileName),
                           securityFinding: true)
        case .missing, .unreadable, .hostnameMismatch, .pinMismatch:
            return .failed("Your certificate couldn\u{2019}t be read.", evidence: evidence,
                           remedy: .probeRemedy(.clientCertificateUntrusted, vpnName: facts.profileName))
        }
    }

    // MARK: SSH

    private func sshBanner() async -> ProbeStepOutcome {
        let result = await VPNProbe.tcpExchange(host: facts.host, port: facts.port,
                                                payload: [], timeout: timeout, boundIf: egressBoundIf)
        guard case .reply(let bytes) = result else {
            return .failed("The server sent no greeting.",
                           evidence: ["SSH servers always greet first; nothing arrived"],
                           remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
        }
        let text = String(decoding: bytes.prefix(512), as: UTF8.self)
        guard let banner = VPNProbe.parseSSHBanner(text) else {
            return .failed("Something answered, but it isn\u{2019}t an SSH server.",
                           evidence: ["The greeting didn\u{2019}t start with \u{201C}SSH-\u{201D}"],
                           remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
        }
        return .ok("An SSH server answered \u{2014} \(banner.software).",
                   evidence: ["Greeting: SSH-\(banner.protocolVersion)-\(banner.software)"
                              + (banner.comment.map { " \($0)" } ?? "")])
    }

    private func sshKeyExchange() async -> ProbeStepOutcome {
        let session = SSHProbeSession()
        ssh = session
        switch await session.connect(host: facts.host, port: facts.port) {
        case .success(let handshake):
            sshHandshake = handshake
            var evidence: [String] = []
            for key in ["kex", "hostkey", "cipher", "mac", "compression"] {
                if let value = handshake.methods[key] { evidence.append("\(key): \(value)") }
            }
            return .ok("This Mac and the server agreed on how to encrypt the connection.",
                       evidence: evidence)
        case .failure(let error):
            let reason = error.message
            return .failed("The server and this Mac couldn\u{2019}t agree on how to encrypt the connection.",
                           evidence: [reason],
                           remedy: .probeRemedy(.noUsableAuthMethod, vpnName: facts.profileName,
                                                detail: reason))
        }
    }

    private func sshHostKey() async -> ProbeStepOutcome {
        guard let session = ssh, let handshake = sshHandshake else {
            return .failed("There was no connection left to check.")
        }
        let result = await session.checkHostKey(knownHostsPath: facts.knownHostsPath,
                                                pin: facts.pinnedHostKeySHA256)
        let verdict = SSHHostKeyPolicy.classify(result, strict: facts.strictHostKey,
                                                pinned: facts.pinnedHostKeySHA256?.isEmpty == false)
        var evidence: [String] = []
        if let type = handshake.keyType { evidence.append("Host key type: \(type)") }
        if let fp = handshake.fingerprint { evidence.append("Fingerprint (SHA-256): \(fp)") }
        evidence.append(facts.pinnedHostKeySHA256?.isEmpty == false
                        ? "Compared against the fingerprint pinned in this VPN"
                        : "Compared against \(facts.knownHostsPath ?? "known_hosts")")
        evidence.append("Strict host key checking: \(facts.strictHostKey)")

        switch verdict {
        case .trusted:
            return .ok("The server is the one on record.", evidence: evidence)
        case .changed:
            return .failed("This server\u{2019}s identity has CHANGED since it was last seen.",
                           evidence: evidence,
                           remedy: .probeRemedy(.hostKeyChanged, vpnName: facts.profileName),
                           securityFinding: true)
        case .unknownAcceptable:
            return ProbeStepOutcome(
                status: .ok,
                detail: "This server hasn\u{2019}t been seen before. This VPN is set to accept new servers, so a real connection would record it \u{2014} this check deliberately didn\u{2019}t.",
                evidence: evidence + ["Nothing was written to known_hosts by this check"])
        case .unknownRefused:
            return .failed("This server isn\u{2019}t on record, and this VPN refuses servers it doesn\u{2019}t know.",
                           evidence: evidence,
                           remedy: .probeRemedy(.hostKeyUnknown, vpnName: facts.profileName),
                           securityFinding: true)
        case .unavailable:
            return .failed("The server\u{2019}s identity couldn\u{2019}t be checked.", evidence: evidence)
        }
    }

    private func sshAuthenticationMethods() async -> ProbeStepOutcome {
        guard let session = ssh else { return .failed("There was no connection left to ask.") }
        guard !facts.username.isEmpty else {
            return .notApplicable("This VPN has no username set, so there was nobody to ask about.")
        }
        switch await session.authMethods(user: facts.username) {
        case .success(let methods):
            sshMethods = methods
            guard !methods.isEmpty else {
                return .ok("The server let this username straight in with no sign-in at all.",
                           evidence: ["No authentication required for \(facts.username)"])
            }
            return .ok("The server will accept: \(plainMethods(methods)).",
                       evidence: ["Offered for \(facts.username): \(methods.joined(separator: ", "))"])
        case .failure(let error):
            let reason = error.message
            return ProbeStepOutcome(status: .failed,
                                    detail: "The server wouldn\u{2019}t say how it wants you to sign in.",
                                    evidence: [reason],
                                    remedy: .probeRemedy(.noUsableAuthMethod, vpnName: facts.profileName,
                                                         detail: reason))
        }
    }

    private func plainMethods(_ methods: [String]) -> String {
        methods.map {
            switch $0 {
            case "publickey": "a key"
            case "password": "a password"
            case "keyboard-interactive": "a password or a one-time code"
            case "gssapi-with-mic": "a Kerberos sign-in"
            default: $0
            }
        }.joined(separator: ", ")
    }

    private func sshPublicKey() async -> ProbeStepOutcome {
        guard let session = ssh, let path = facts.identityFilePath, !path.isEmpty else {
            return .notApplicable("This VPN has no key file set.")
        }
        guard sshMethods.isEmpty || sshMethods.contains("publickey") else {
            return .notApplicable("This server doesn\u{2019}t accept keys, so there was nothing to try.")
        }
        switch SSHPrivateKeyFile.protection(ofFileAt: path) {
        case .unreadable:
            return .failed("The key file couldn\u{2019}t be read.",
                           evidence: ["Key file: \(path)"],
                           remedy: .probeRemedy(.publicKeyRejected, vpnName: facts.profileName))
        case .passphraseProtected where (signIn?.privateKeyPassphrase ?? "").isEmpty:
            return ProbeStepOutcome(
                status: .skipped,
                detail: "Your key is password-protected, and its password wasn\u{2019}t available to this check.",
                evidence: ["Key file: \(path)", "Encrypted private key"],
                remedy: .probeRemedy(.clientKeyLocked, vpnName: facts.profileName))
        default:
            break
        }
        let result = await session.tryPublicKey(user: facts.username, keyPath: path,
                                                passphrase: signIn?.privateKeyPassphrase)
        switch result {
        case .success:
            return .ok("The server accepted your key.",
                       evidence: ["Key file: \(path)", "Accepted for \(facts.username)"])
        case .failure(let error):
            let reason = error.message
            return .failed("The server didn\u{2019}t accept your key.",
                           evidence: ["Key file: \(path)", reason],
                           remedy: .probeRemedy(.publicKeyRejected, vpnName: facts.profileName,
                                                detail: reason))
        }
    }

    // MARK: Sign-in (only ever reached on an explicit opt-in)

    /// The one sign-in that CAN be tested on its own, and only on an opt-in.
    /// SSH separates authentication from opening a channel, so a password can be
    /// offered and the session dropped without anything having been run.
    private func sshPasswordSignIn() async -> ProbeStepOutcome {
        guard let session = ssh else { return .failed("There was no connection left to sign in on.") }
        guard let material = signIn, !material.password.isEmpty else {
            return .skipped("No password was available for the sign-in test. Enter it on this VPN\u{2019}s page first.")
        }
        guard !facts.username.isEmpty else {
            return .notApplicable("This VPN has no username set.")
        }
        if !sshMethods.isEmpty, !sshMethods.contains("password") {
            // keyboard-interactive is a conversation, not a single password, and
            // this bridge can't hold one — say so rather than guessing.
            let interactive = sshMethods.contains("keyboard-interactive")
            return .notApplicable(interactive
                ? "This server signs people in with a question-and-answer prompt, which can\u{2019}t be tested separately from connecting."
                : "This server doesn\u{2019}t accept passwords, so there was nothing to try.")
        }
        switch await session.tryPassword(user: facts.username, password: material.password) {
        case .success:
            return .ok("The server accepted the sign-in.",
                       evidence: ["Signed in as \(facts.username); no session was opened and the connection was dropped straight away"])
        case .failure(let error):
            return .failed("The server rejected the sign-in.",
                           evidence: ["Tried as \(facts.username)",
                                      ProbeEvidence.sanitise(UserFacingError.redact(error.message,
                                                                                    secrets: material.secrets))],
                           remedy: .probeRemedy(.noUsableAuthMethod, vpnName: facts.profileName))
        }
    }

    /// The honest answer for the sign-in rungs that CANNOT be tested on their own.
    ///
    /// OpenVPN carries its sign-in inside the TLS session it builds within its
    /// own control channel; the SSL-VPN kinds carry theirs inside a vendor login
    /// flow that OpenConnect drives. Reaching either means becoming a real
    /// connection attempt — which is the thing the user would have pressed
    /// Connect for. Faking a pass here would be worse than saying nothing, so
    /// this says nothing, clearly.
    private func signInNotImplemented() -> ProbeStepOutcome {
        .notApplicable("Signing in happens inside the connection itself for this kind of VPN, so it can\u{2019}t be tested separately. Everything the sign-in depends on has been checked above \u{2014} press Connect to try the sign-in itself.")
    }

    // MARK: IKEv2 / IPsec

    private var ikeProposalValue: ProbeIKE.Proposal {
        ProbeIKE.Proposal.from(encryption: facts.requestedEncryption,
                               integrity: facts.requestedIntegrity,
                               group: facts.requestedDHGroup)
    }

    private func ikeReachability() async -> ProbeStepOutcome {
        let spi = (0..<8).map { _ in UInt8.random(in: 0...255) }
        ikeSPI = spi
        let payload = ProbeIKE.saInit(initiatorSPI: spi, proposal: ikeProposalValue)
        let port = facts.port == 0 ? VPNProbe.ikeDefaultPort : facts.port
        let result = await VPNProbe.udpExchange(host: facts.host, port: port,
                                                payload: payload, timeout: timeout, boundIf: egressBoundIf)
        switch result {
        case .reply(let bytes):
            ikeReply = bytes
            return .ok("The gateway answered on port \(port).",
                       evidence: ["UDP \(facts.host):\(port) replied with \(bytes.count) bytes"])
        case .refused:
            return .failed("Nothing is listening on port \(port).",
                           evidence: ["UDP \(facts.host):\(port) refused"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        default:
            return .failed("The gateway never answered on port \(port).",
                           evidence: ["UDP \(facts.host):\(port) silent for \(Int(timeout))s",
                                      "Offered: \(ikeProposalValue.label)"],
                           remedy: .probeRemedy(.portFiltered, vpnName: facts.profileName))
        }
    }

    private func ikeProposal() -> ProbeStepOutcome {
        guard let raw = ikeReply,
              let reply = ProbeIKE.parse(raw, initiatorSPI: ikeSPI) else {
            return .failed("The answer wasn\u{2019}t a recognisable IPsec reply.",
                           remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
        }
        let proposal = ikeProposalValue
        var evidence = ["Offered: \(proposal.label)"]
        guard reply.matchesInitiator else {
            return .failed("An IPsec-shaped reply arrived, but not to this request.",
                           evidence: evidence + ["The gateway\u{2019}s reply didn\u{2019}t carry our identifier"],
                           remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
        }
        evidence.append("Protocol: \(reply.isIKEv2 ? "IKEv2" : "IKEv1")")
        for notify in reply.notifies { evidence.append("Gateway said: \(ProbeIKE.notifyName(notify))") }

        if let encryption = reply.chosenEncryption {
            evidence.append("Gateway chose: "
                            + ProbeIKE.encryptionName(id: encryption.id, keyBits: encryption.keyLengthBits)
                            + (reply.chosenIntegrity.map { " \u{00B7} " + ProbeIKE.integrityName($0) } ?? "")
                            + (reply.chosenPRF.map { " \u{00B7} PRF " + ProbeIKE.prfName($0) } ?? "")
                            + (reply.chosenGroup.map { " \u{00B7} " + ProbeIKE.groupName($0) } ?? ""))
            return .ok("The gateway accepted this VPN\u{2019}s encryption settings.", evidence: evidence)
        }
        if let wanted = reply.requestedGroup {
            evidence.append("The gateway wants \(ProbeIKE.groupName(wanted))")
            return .failed("The gateway wants a different Diffie\u{2011}Hellman group from the one this VPN asks for.",
                           evidence: evidence,
                           remedy: .probeRemedy(.proposalRejected, vpnName: facts.profileName,
                                                detail: "INVALID_KE_PAYLOAD requests group \(wanted)"))
        }
        if reply.notifies.contains(ProbeIKE.noProposalChosen) {
            return .failed("The gateway rejected every encryption option this VPN offers.",
                           evidence: evidence,
                           remedy: .probeRemedy(.proposalRejected, vpnName: facts.profileName,
                                                detail: "NO_PROPOSAL_CHOSEN"))
        }
        if reply.cookieRequested {
            return ProbeStepOutcome(
                status: .ok,
                detail: "The gateway is busy and asked for a repeat request \u{2014} it is there and speaking IPsec.",
                evidence: evidence)
        }
        return .failed("The gateway answered but didn\u{2019}t agree on encryption.",
                       evidence: evidence,
                       remedy: .probeRemedy(.proposalRejected, vpnName: facts.profileName))
    }

    private func ikeNATTraversal() async -> ProbeStepOutcome {
        let spi = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let payload = ProbeIKE.saInit(initiatorSPI: spi, proposal: ikeProposalValue,
                                      nonESPMarker: true)
        let result = await VPNProbe.udpExchange(host: facts.host, port: VPNProbe.ikeNATTPort,
                                                payload: payload, timeout: timeout, boundIf: egressBoundIf)
        let offeredDetection = ikeReply
            .flatMap { ProbeIKE.parse($0, initiatorSPI: ikeSPI) }?
            .natDetectionOffered ?? false
        switch result {
        case .reply(let bytes):
            let parsed = ProbeIKE.parse(bytes, initiatorSPI: spi, nonESPMarker: true)
            return .ok("The gateway also answers on the port used behind a router.",
                       evidence: ["UDP \(facts.host):\(VPNProbe.ikeNATTPort) replied",
                                  "The gateway offers address-translation detection: \(offeredDetection || (parsed?.natDetectionOffered ?? false) ? "yes" : "no")"])
        case .refused, .silence, .connectedNoReply, .failed:
            return ProbeStepOutcome(
                status: .failed,
                detail: "Port \(VPNProbe.ikeNATTPort) isn\u{2019}t answering. Behind almost any home or office router, an IPsec VPN needs it.",
                evidence: ["UDP \(facts.host):\(VPNProbe.ikeNATTPort) no answer",
                           "The gateway offers address-translation detection: \(offeredDetection ? "yes" : "no")"],
                remedy: .probeRemedy(.portFiltered, vpnName: facts.profileName))
        }
    }

    // MARK: TLS-riding VPNs

    private func tlsHandshake() async -> ProbeStepOutcome {
        let result = await ProbeTLS.handshake(host: facts.host, port: facts.port,
                                              sni: facts.host,
                                              httpRequest: httpProbeRequest, timeout: 8,
                                              boundIf: egressBoundIf)
        tls = result
        guard result.handshakeCompleted else {
            return .failed("The secure handshake didn\u{2019}t complete.",
                           evidence: [result.failureReason ?? "No further detail"],
                           remedy: .probeRemedy(.portFiltered, vpnName: facts.profileName,
                                                detail: result.failureReason ?? ""))
        }
        var evidence: [String] = []
        if let p = result.negotiatedProtocol { evidence.append("Protocol: \(p)") }
        if let c = result.negotiatedCiphersuite { evidence.append("Cipher: \(c)") }

        let chain = result.chainDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard let leaf = chain.first else {
            return ProbeStepOutcome(status: .ok,
                                    detail: "The secure handshake completed, but no certificate was captured to check.",
                                    evidence: evidence)
        }
        let leafFacts = ProbeCertificateInspector.facts(certificate: leaf)
        evidence += leafFacts.evidence(role: "The VPN\u{2019}s certificate")

        let expectedName = facts.expectedServerName ?? facts.host
        let hostnameMatches = CertificateHostname.matches(host: expectedName, names: leafFacts.names)
        var pinMatches: Bool?
        if let pin = facts.pinnedServerCertificateSHA256, !pin.isEmpty {
            let actual = ProbeCertificateInspector.sha256(of: leaf)
            pinMatches = normaliseFingerprint(actual) == normaliseFingerprint(pin)
            evidence.append("Pinned fingerprint check: \(pinMatches == true ? "matches" : "does not match")")
        }
        var chainsToProfileCA: Bool?
        if let anchors = facts.caPEM.map({ CertificateImport.certificates(inPEM: $0) }), !anchors.isEmpty {
            chainsToProfileCA = ProbeCertificateInspector.chains(chain: chain, anchors: anchors)
            evidence.append("Chains to the authority in this profile: \(chainsToProfileCA == true ? "yes" : "no")")
        } else {
            evidence.append("This profile names no certificate authority, so only the dates and the name were checked")
        }

        let verdict = CertificateVerdict.classify(
            notBefore: leafFacts.notBefore, notAfter: leafFacts.notAfter,
            chainsToTrustedAnchor: chainsToProfileCA,
            hostnameMatches: hostnameMatches, expectedHostname: expectedName,
            pinMatches: pinMatches)

        switch verdict {
        case .ok(let days):
            let when = days.map { $0 <= 30 ? " Its certificate expires in \($0) day\($0 == 1 ? "" : "s")." : "" } ?? ""
            return .ok("A secure connection was made and the VPN\u{2019}s certificate checks out." + when,
                       evidence: evidence)
        default:
            let failure = verdict.serverFailure ?? .serverCertificateUntrusted
            return .failed(describe(verdict, name: expectedName),
                           evidence: evidence,
                           remedy: .probeRemedy(failure, vpnName: facts.profileName),
                           securityFinding: failure == .serverCertificatePinMismatch
                                          || failure == .serverCertificateUntrusted)
        }
    }

    private func describe(_ verdict: CertificateVerdict, name: String) -> String {
        switch verdict {
        case .expired(let on):
            "The VPN\u{2019}s certificate expired\(on.map { " on \(CertificateFacts.format($0))" } ?? "")."
        case .notYetValid(let from):
            "The VPN\u{2019}s certificate isn\u{2019}t valid until \(from.map(CertificateFacts.format) ?? "a future date")."
        case .hostnameMismatch:
            "The VPN\u{2019}s certificate isn\u{2019}t for \(name)."
        case .pinMismatch:
            "The VPN presented a different certificate from the one this profile pins."
        case .chainUntrusted:
            "The VPN\u{2019}s certificate wasn\u{2019}t issued by the authority this profile trusts."
        default:
            "The VPN\u{2019}s certificate couldn\u{2019}t be checked."
        }
    }

    private func normaliseFingerprint(_ s: String) -> String {
        s.lowercased().filter { $0.isHexDigit }
    }

    private var httpProbeRequest: String {
        "GET / HTTP/1.1\r\nHost: \(facts.host)\r\nUser-Agent: SimpleVPN-Probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    }

    private func vendorClassification() -> ProbeStepOutcome {
        guard let tls else { return .failed("There was no connection to classify.") }
        let leafFacts = tls.leafDER
            .flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
            .map { ProbeCertificateInspector.facts(certificate: $0) }
        let guess = VPNProbe.classifySSLVPN(head: tls.httpHead,
                                            certSubject: leafFacts?.commonName,
                                            certIssuer: leafFacts?.issuerCommonName)
        guard let guess else {
            return ProbeStepOutcome(
                status: .ok,
                detail: "A secure service answered, but it didn\u{2019}t identify itself as a make of VPN we recognise.",
                evidence: [VPNProbe.headerValue("server", in: tls.httpHead).map { "Server header: \($0)" }
                           ?? "No identifying header"])
        }
        if guess.kind == facts.kind {
            return .ok("This is a \(guess.vendor), which is what this VPN is set up as.",
                       evidence: ["Recognised from \u{201C}\(guess.evidence)\u{201D}"])
        }
        return ProbeStepOutcome(
            status: .failed,
            detail: "This looks like a \(guess.vendor), but this VPN is set up as \(facts.kind.displayName).",
            evidence: ["Recognised from \u{201C}\(guess.evidence)\u{201D}"],
            remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
    }

    private func clientCertificateRequested() -> ProbeStepOutcome {
        guard let tls else { return .failed("There was no connection to ask.") }
        let have = facts.hasClientCertificate
        switch (tls.clientCertificateRequested, have) {
        case (true, true):
            return .ok("The VPN asks for a certificate, and this profile has one.",
                       evidence: ["The VPN sent a certificate request during the handshake"])
        case (true, false):
            return .failed("The VPN asks every client for a certificate, and this profile hasn\u{2019}t got one.",
                           evidence: ["The VPN sent a certificate request during the handshake"],
                           remedy: .probeRemedy(.clientCertificateUntrusted, vpnName: facts.profileName))
        case (false, true):
            return ProbeStepOutcome(
                status: .ok,
                detail: "The VPN didn\u{2019}t ask for a certificate at this stage. Some ask only after the sign-in page.",
                evidence: ["No certificate request during the handshake"])
        case (false, false):
            return .ok("The VPN doesn\u{2019}t need a certificate to reach its sign-in.",
                       evidence: ["No certificate request during the handshake"])
        }
    }

    // MARK: WireGuard

    private func wireGuardHandshake() async -> ProbeStepOutcome {
        guard let privateKey = facts.wireGuardPrivateKey, !privateKey.isEmpty,
              let peer = facts.wireGuardPeerPublicKey, !peer.isEmpty else {
            return .notApplicable("This VPN is missing a key, so no handshake could be tried.")
        }
        let session: WireGuardHandshake.Session
        do {
            session = try WireGuardHandshake.makeInitiation(
                privateKey: privateKey, peerPublicKey: peer,
                presharedKey: facts.wireGuardPresharedKey)
        } catch {
            let what: String
            switch error as? WireGuardHandshake.HandshakeError {
            case .badPrivateKey: what = "Your own key isn\u{2019}t a valid WireGuard key."
            case .badPeerPublicKey: what = "The other end\u{2019}s public key isn\u{2019}t a valid WireGuard key."
            case .badPresharedKey: what = "The shared key isn\u{2019}t a valid WireGuard key."
            default: what = "The handshake couldn\u{2019}t be built from these keys."
            }
            return .failed(what,
                           evidence: ["A WireGuard key is 32 bytes written as 44 characters ending in \u{201C}=\u{201D}"],
                           remedy: .probeRemedy(.handshakeUnanswered, vpnName: facts.profileName))
        }
        var evidence = ["Handshake: Noise IKpsk2, Curve25519",
                        "Preshared key in use: \(facts.wireGuardPresharedKey?.isEmpty == false ? "yes" : "no")"]
        if let ours = WireGuardHandshake.publicKey(forPrivateKey: privateKey) {
            evidence.append("This Mac\u{2019}s public key: \(ours)")
        }
        evidence.append("The VPN\u{2019}s public key: \(peer)")

        let result = await VPNProbe.udpExchange(host: facts.host, port: facts.port,
                                                payload: session.message, timeout: timeout, boundIf: egressBoundIf)
        switch result {
        case .reply(let bytes):
            switch WireGuardHandshake.check(response: bytes, session: session) {
            case .accepted:
                return .ok("The VPN completed the handshake \u{2014} these keys are the right ones.",
                           evidence: evidence + ["Handshake response accepted and decrypted"])
            case .cookieReply:
                return ProbeStepOutcome(
                    status: .ok,
                    detail: "The VPN recognised our handshake but is rate-limiting right now, so it asked us to try again with a cookie.",
                    evidence: evidence + ["Cookie reply \u{2014} which only a VPN that verified our message sends"])
            case .notOurs:
                return .failed("Something answered, but not to this handshake.",
                               evidence: evidence + ["The reply didn\u{2019}t carry our identifier"],
                               remedy: .probeRemedy(.handshakeUnanswered, vpnName: facts.profileName))
            case .authenticationFailed:
                return .failed("The VPN\u{2019}s answer didn\u{2019}t verify with these keys.",
                               evidence: evidence + ["Handshake response failed authentication"],
                               remedy: .probeRemedy(.handshakeUnanswered, vpnName: facts.profileName),
                               securityFinding: true)
            case .malformed:
                return .failed("Something answered, but not in WireGuard\u{2019}s language.",
                               evidence: evidence + ["\(bytes.count) bytes back, not a handshake response"],
                               remedy: .probeRemedy(.noProtocolAnswer, vpnName: facts.profileName))
            }
        case .refused:
            return .failed("Nothing is listening on port \(facts.port).",
                           evidence: evidence + ["UDP refused"],
                           remedy: .probeRemedy(.portClosed, vpnName: facts.profileName))
        default:
            return .failed("The VPN never answered the handshake.",
                           evidence: evidence + [
                            "No reply within \(Int(timeout))s",
                            "A WireGuard VPN answers a handshake from a peer it knows, so silence means the keys, the address or the network",
                           ],
                           remedy: .probeRemedy(.handshakeUnanswered, vpnName: facts.profileName))
        }
    }

    // MARK: Tailscale / Headscale control plane

    private var controlURL: URL? {
        facts.controlURL.flatMap { URL(string: $0) }
    }

    private func controlPlaneReachability() async -> ProbeStepOutcome {
        guard let url = controlURL, let host = url.host() else {
            return .failed("This VPN has no coordination server address.",
                           remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
        }
        let port = url.port ?? (url.scheme == "http" ? 80 : 443)
        let result = await VPNProbe.tcpExchange(host: host, port: port, payload: [], timeout: timeout, boundIf: egressBoundIf)
        switch result {
        case .reply, .connectedNoReply:
            return .ok("The coordination server is reachable.",
                       evidence: ["TCP \(host):\(port) connected",
                                  facts.isSelfHostedControl ? "Self-hosted server" : "Tailscale\u{2019}s own service"])
        case .refused:
            return .failed("Nothing is listening at the coordination server\u{2019}s address.",
                           evidence: ["TCP \(host):\(port) refused"],
                           remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
        default:
            return .failed("The coordination server didn\u{2019}t answer.",
                           evidence: ["TCP \(host):\(port) timed out"],
                           remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
        }
    }

    private func controlPlaneTLS() async -> ProbeStepOutcome {
        guard let url = controlURL, let host = url.host() else {
            return .failed("This VPN has no coordination server address.")
        }
        guard url.scheme != "http" else {
            return .notApplicable("This coordination server is set up without encryption, so there is no certificate to check.")
        }
        let port = url.port ?? 443
        let result = await ProbeTLS.handshake(host: host, port: port, sni: host, timeout: 8,
                                              boundIf: egressBoundIf)
        tls = result
        guard result.handshakeCompleted else {
            return .failed("The secure handshake with the coordination server didn\u{2019}t complete.",
                           evidence: [result.failureReason ?? "No further detail"],
                           remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
        }
        var evidence: [String] = []
        if let p = result.negotiatedProtocol { evidence.append("Protocol: \(p)") }
        if let c = result.negotiatedCiphersuite { evidence.append("Cipher: \(c)") }
        guard let leaf = result.leafDER.flatMap({ SecCertificateCreateWithData(nil, $0 as CFData) }) else {
            return ProbeStepOutcome(status: .ok,
                                    detail: "A secure connection was made, but no certificate was captured to check.",
                                    evidence: evidence)
        }
        let leafFacts = ProbeCertificateInspector.facts(certificate: leaf)
        evidence += leafFacts.evidence(role: "Server certificate")
        let matches = CertificateHostname.matches(host: host, names: leafFacts.names)
        let verdict = CertificateVerdict.classify(notBefore: leafFacts.notBefore,
                                                  notAfter: leafFacts.notAfter,
                                                  hostnameMatches: matches, expectedHostname: host)
        if case .ok = verdict {
            return .ok("A secure connection was made and the server\u{2019}s certificate checks out.",
                       evidence: evidence)
        }
        return .failed(describe(verdict, name: host), evidence: evidence,
                       remedy: .probeRemedy(verdict.serverFailure ?? .serverCertificateUntrusted,
                                            vpnName: facts.profileName))
    }

    /// A Tailscale-compatible control server publishes its public keys at
    /// `/key`. Asking for them identifies the server without registering this
    /// Mac, without a browser, and without starting the engine.
    private func controlPlaneIdentity() async -> ProbeStepOutcome {
        guard let url = controlURL?.appending(path: "key") else {
            return .failed("This VPN has no coordination server address.")
        }
        var request = URLRequest(url: url.appending(queryItems: [URLQueryItem(name: "v", value: "106")]))
        request.timeoutInterval = timeout
        request.setValue("SimpleVPN-Probe/1", forHTTPHeaderField: "User-Agent")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let body = String(decoding: data.prefix(512), as: UTF8.self)
            guard (200..<300).contains(status) else {
                return .failed("The coordination server answered, but not the way one should.",
                               evidence: ["HTTP \(status) from \(url.path())"],
                               remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
            }
            guard body.contains("publicKey") || body.contains("PublicKey") else {
                return .failed("Something answered at that address, but it isn\u{2019}t a coordination server.",
                               evidence: ["HTTP \(status), and the reply didn\u{2019}t contain a server key"],
                               remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName))
            }
            return .ok("It answered as a Tailscale-compatible coordination server.",
                       evidence: ["HTTP \(status) from \(url.path())",
                                  "The server published its public key"])
        } catch {
            return .failed("The coordination server didn\u{2019}t answer.",
                           evidence: [error.localizedDescription],
                           remedy: .probeRemedy(.controlPlaneUnreachable, vpnName: facts.profileName,
                                                detail: error.localizedDescription))
        }
    }
}
