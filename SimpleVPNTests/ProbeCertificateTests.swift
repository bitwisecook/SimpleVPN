// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeCertificateTests.swift
//  The judgement half of the certificate and host-key rungs: given the facts,
//  what is wrong and in what order does a person fix it. Pure — no certificate,
//  no keychain, no server — which is exactly why the precedence can be pinned
//  down here instead of being discovered on somebody's Monday morning.
//

import Testing
import Foundation
@testable import SimpleVPN

struct CertificateVerdictTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private var yesterday: Date { now.addingTimeInterval(-86_400) }
    private var tomorrow: Date { now.addingTimeInterval(86_400) }
    private var nextYear: Date { now.addingTimeInterval(365 * 86_400) }

    @Test func aGoodCertificateReportsHowLongItHasLeft() {
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: nextYear, now: now,
                                                  keyMatchesCertificate: true,
                                                  chainsToTrustedAnchor: true, hostnameMatches: true)
        guard case .ok(let days) = verdict else { Issue.record("expected ok"); return }
        #expect(days == 365)
    }

    @Test func expiredBeatsEverythingElse() {
        // Expired AND untrusted AND wrong name: renewing it is the one action
        // that could fix all three, so that is what gets said.
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: yesterday, now: now,
                                                  chainsToTrustedAnchor: false, hostnameMatches: false)
        #expect(verdict == .expired(on: yesterday))
    }

    @Test func aPinMismatchOutranksEvenExpiry() {
        // A different certificate from the pinned one is a security question,
        // and it must not be softened into "yours has expired".
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: yesterday, now: now,
                                                  pinMatches: false)
        #expect(verdict == .pinMismatch)
    }

    @Test func notYetValidIsDistinctFromExpired() {
        let verdict = CertificateVerdict.classify(notBefore: tomorrow, notAfter: nextYear, now: now)
        #expect(verdict == .notYetValid(from: tomorrow))
        // …and its advice is about the clock, not about renewal.
        #expect(UserFacingError.probeRemedy(.clientCertificateNotYetValid)
            .steps.contains { $0.text.contains("Date & Time") })
    }

    @Test func aMismatchedKeyBeatsAnUntrustedChain() {
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: nextYear, now: now,
                                                  keyMatchesCertificate: false,
                                                  chainsToTrustedAnchor: false)
        #expect(verdict == .keyMismatch)
    }

    @Test func anUntrustedChainBeatsAWrongName() {
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: nextYear, now: now,
                                                  chainsToTrustedAnchor: false, hostnameMatches: false,
                                                  expectedHostname: "vpn.example.org")
        #expect(verdict == .chainUntrusted)
    }

    @Test func aLockedKeyIsNotAFailure() {
        // Nothing could be checked about the pair — that is a gap in what we
        // know, not evidence that anything is wrong.
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: nextYear, now: now,
                                                  keyMatchesCertificate: nil, privateKeyLocked: true,
                                                  chainsToTrustedAnchor: true)
        #expect(verdict == .keyLocked)
        #expect(!verdict.isFailure)
    }

    @Test func unaskedQuestionsNeverProduceAVerdict() {
        // nil means "not asked". A profile with no certificate authority in it
        // must not be told its certificate doesn't chain.
        let verdict = CertificateVerdict.classify(notBefore: yesterday, notAfter: nextYear, now: now,
                                                  keyMatchesCertificate: nil,
                                                  chainsToTrustedAnchor: nil, hostnameMatches: nil,
                                                  pinMatches: nil)
        #expect(!verdict.isFailure)
    }

    @Test func missingDatesAreNotTreatedAsExpiry() {
        let verdict = CertificateVerdict.classify(notBefore: nil, notAfter: nil, now: now)
        guard case .ok(let days) = verdict else { Issue.record("expected ok"); return }
        #expect(days == nil)
    }
}

// MARK: - Hostname matching

struct CertificateHostnameTests {

    @Test func exactNamesMatchRegardlessOfCase() {
        #expect(CertificateHostname.matches(host: "VPN.Example.ORG", names: ["vpn.example.org"]))
        #expect(CertificateHostname.matches(host: "vpn.example.org.", names: ["vpn.example.org"]))
    }

    @Test func aWildcardCoversOneLabelOnly() {
        #expect(CertificateHostname.matches(host: "vpn.example.org", names: ["*.example.org"]))
        #expect(!CertificateHostname.matches(host: "a.vpn.example.org", names: ["*.example.org"]))
        #expect(!CertificateHostname.matches(host: "example.org", names: ["*.example.org"]))
    }

    @Test func aWildcardCannotSwallowTheRegistry() {
        #expect(!CertificateHostname.matches(host: "example.org", names: ["*.org"]))
        #expect(!CertificateHostname.matches(host: "anything.com", names: ["*.com"]))
    }

    @Test func anyOfTheCertificatesNamesWillDo() {
        #expect(CertificateHostname.matches(host: "gw.example.org",
                                            names: ["vpn.example.org", "gw.example.org"]))
    }

    @Test func aCertificateWithNoNamesMatchesNothing() {
        #expect(!CertificateHostname.matches(host: "vpn.example.org", names: []))
        #expect(!CertificateHostname.matches(host: "", names: ["vpn.example.org"]))
    }

    @Test func decoratedSubjectAlternativeNamesAreUnderstood() {
        // Security.framework hands some SANs back with their type prefixed.
        #expect(CertificateHostname.matches(host: "vpn.example.org",
                                            names: ["DNS Name: vpn.example.org"]))
    }
}

// MARK: - SSH host keys

struct SSHHostKeyPolicyTests {

    @Test func aKeyOnRecordAndUnchangedIsTrusted() {
        #expect(SSHHostKeyPolicy.classify(.match, strict: "yes", pinned: false) == .trusted)
        #expect(SSHHostKeyPolicy.classify(.match, strict: "no", pinned: true) == .trusted)
    }

    @Test func aCHANGEDKeyIsRefusedWhateverTheSetting() {
        // This is the one classification that no configuration may soften: a
        // changed host key is the signature of interception.
        for strict in ["yes", "accept-new", "no"] {
            #expect(SSHHostKeyPolicy.classify(.mismatch, strict: strict, pinned: false) == .changed)
            #expect(SSHHostKeyPolicy.classify(.mismatch, strict: strict, pinned: true) == .changed)
        }
        #expect(SSHHostKeyVerdict.changed.isFailure)
        #expect(SSHHostKeyVerdict.changed.isSecurityFinding)
    }

    @Test func anUnknownServerFollowsTheProfilesStrictness() {
        #expect(SSHHostKeyPolicy.classify(.notFound, strict: "yes", pinned: false) == .unknownRefused)
        #expect(SSHHostKeyPolicy.classify(.notFound, strict: "accept-new", pinned: false) == .unknownAcceptable)
        #expect(SSHHostKeyPolicy.classify(.notFound, strict: "no", pinned: false) == .unknownAcceptable)
    }

    @Test func aPinnedFingerprintWithNothingToCompareIsRefused() {
        #expect(SSHHostKeyPolicy.classify(.notFound, strict: "no", pinned: true) == .unknownRefused)
    }

    @Test func anUnaskableQuestionIsNotAnAccusation() {
        let verdict = SSHHostKeyPolicy.classify(.unavailable, strict: "yes", pinned: false)
        #expect(verdict == .unavailable)
        #expect(verdict.failure == nil)
    }

    @Test func strictnessIsCaseInsensitive() {
        #expect(SSHHostKeyPolicy.classify(.notFound, strict: "YES", pinned: false) == .unknownRefused)
    }
}

// MARK: - Private key files

struct SSHPrivateKeyFileTests {

    @Test func recognisesAnEncryptedPKCS8Key() {
        #expect(SSHPrivateKeyFile.protection(ofPEM:
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")
                == .passphraseProtected)
    }

    @Test func recognisesLegacyOpenSSLEncryption() {
        #expect(SSHPrivateKeyFile.protection(ofPEM: """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,0123

        AAAA
        -----END RSA PRIVATE KEY-----
        """) == .passphraseProtected)
    }

    @Test func recognisesAnUnprotectedOpenSSHKey() {
        // "none" as the cipher name appears in the base64 as AAAABG5vbmU.
        #expect(SSHPrivateKeyFile.protection(ofPEM:
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----")
                == .open)
    }

    @Test func treatsAnOpenSSHKeyWithACipherAsProtected() {
        #expect(SSHPrivateKeyFile.protection(ofPEM:
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAKYWVzMjU2LWN0cg\n-----END OPENSSH PRIVATE KEY-----")
                == .passphraseProtected)
    }

    @Test func somethingThatIsNotAKeyIsUnreadable() {
        #expect(SSHPrivateKeyFile.protection(ofPEM: "ssh-ed25519 AAAAC3Nz jim@mac") == .unreadable)
    }

    @Test func aMissingFileIsUnreadableRatherThanUnprotected() {
        #expect(SSHPrivateKeyFile.protection(ofFileAt: "/nowhere/id_ed25519", read: { _ in nil })
                == .unreadable)
    }
}

// MARK: - Reading a profile's material

struct ProbeTargetFactsTests {

    private static let certPEM = """
    <cert>
    -----BEGIN CERTIFICATE-----
    AAAA
    -----END CERTIFICATE-----
    </cert>
    """

    @Test func openVPNFactsComeOutOfTheProfileText() {
        let ovpn = """
        client
        remote vpn.example.org 1194 udp
        verify-x509-name "CN=gw.example.org, O=Example" subject
        auth-user-pass
        <ca>
        -----BEGIN CERTIFICATE-----
        BBBB
        -----END CERTIFICATE-----
        </ca>
        \(Self.certPEM)
        """
        let facts = ProbeTargetFacts.openVPN(profileID: "p", name: "Work",
                                             host: "vpn.example.org", port: 1194,
                                             transport: .udp, ovpn: ovpn, requiresOTP: true)
        #expect(facts.hasCA)
        #expect(facts.hasClientCertificate)
        #expect(facts.expectedServerName == "gw.example.org")
        #expect(facts.usesAccountSignIn)
        #expect(facts.accountSkipReason == ProbeLadderEngine.otpAccountSkipReason)
    }

    @Test func readsAPlainVerifyX509Name() {
        #expect(ProbeTargetFacts.verifyX509Name(in: "verify-x509-name vpn.example.org name")
                == "vpn.example.org")
        #expect(ProbeTargetFacts.verifyX509Name(in: "tls-remote vpn.example.org")
                == "vpn.example.org")
        #expect(ProbeTargetFacts.verifyX509Name(in: "client\n") == nil)
    }

    @Test func anAutologinProfileHasNoSignInRung() {
        let facts = ProbeTargetFacts.openVPN(profileID: "p", name: "Work", host: "h", port: 1194,
                                             transport: .udp, ovpn: "client\n", requiresOTP: false)
        #expect(!facts.usesAccountSignIn)
        #expect(!ProbeLadderPlan.steps(for: facts).contains { $0.requiresAccountCredentials })
    }

    @Test func sslVPNFactsReadTheirFilesThroughTheInjectedReader() {
        var config = SubprocessTunnelConfig()
        config.kind = .fortinet
        config.name = "Office"
        config.clientCertFile = "/certs/client.pem"
        config.caFile = "/certs/ca.pem"
        config.trustedCertSHA256 = "sha256:ABCD"
        let facts = ProbeTargetFacts.subprocess(config, host: "vpn.example.org", port: 443,
                                                requiresOTP: false) { path in
            path.contains("client") ? "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
                                    : "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"
        }
        #expect(facts.hasClientCertificate)
        #expect(facts.hasCA)
        #expect(facts.pinnedServerCertificateSHA256 == "sha256:ABCD")
        #expect(facts.expectedServerName == "vpn.example.org")
    }

    @Test func sshFactsCarryTheHostKeySettings() {
        var config = SubprocessTunnelConfig()
        config.kind = .ssh
        config.username = "jim"
        config.identityFile = "~/.ssh/id_ed25519"
        config.strictHostKey = "yes"
        let facts = ProbeTargetFacts.subprocess(config, host: "bastion.example.org", port: 22,
                                                requiresOTP: false) { _ in nil }
        #expect(facts.username == "jim")
        #expect(facts.identityFilePath == "~/.ssh/id_ed25519")
        #expect(facts.strictHostKey == "yes")
        #expect(facts.knownHostsPath?.hasSuffix("known_hosts") == true)
    }

    @Test func wireGuardFactsHaveNoAccountAtAll() {
        var config = WireGuardConfig()
        config.privateKey = "AAAA"
        config.peerPublicKey = "BBBB"
        let facts = ProbeTargetFacts.wireGuard(config, profileID: "w", host: "wg.example.org",
                                               port: 51_820)
        #expect(!facts.usesAccountSignIn)
        #expect(facts.wireGuardPrivateKey == "AAAA")
    }

    @Test func nativeFactsCarryTheIKESettings() {
        var config = NativeVPNConfig()
        config.kind = .ikev2
        config.server = "gw.example.org"
        config.ikeEncryption = "aes256gcm"
        config.ikeIntegrity = "sha384"
        config.ikeDHGroup = "20"
        let facts = ProbeTargetFacts.native(config, host: "gw.example.org")
        #expect(facts.port == VPNProbe.ikeDefaultPort)
        let proposal = ProbeIKE.Proposal.from(encryption: facts.requestedEncryption,
                                              integrity: facts.requestedIntegrity,
                                              group: facts.requestedDHGroup)
        #expect(proposal.keyExchangeGroup == .ecp384)
        #expect(!proposal.isAutomatic)
    }
}
