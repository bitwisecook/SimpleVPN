// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeLadderPlan.swift
//  Which rungs each protocol's ladder has, in the order the real connection
//  climbs them, decided purely from what the profile contains.
//
//  Pure: given a `ProbeTargetFacts` it produces `[ProbeStep]` and touches
//  nothing else. That is what makes "this profile has no certificate, so the
//  certificate step is not applicable" a testable statement rather than a
//  runtime accident.
//
//  Two properties every ladder here keeps:
//    • Ordered by dependency. A step only appears after everything it needs.
//    • Split at the account boundary. The LAST rung of every ladder that has a
//      sign-in is marked `requiresAccountCredentials`, so the automatic run
//      stops short of it and the user has to ask for it by name. See the rule
//      at the top of ProbeLadder.swift for why that is not negotiable.
//

import Foundation

nonisolated enum ProbeLadderPlan {

    static func steps(for facts: ProbeTargetFacts) -> [ProbeStep] {
        switch facts.kind {
        case .openVPN: openVPN(facts)
        case .wireGuard: wireGuard(facts)
        // Both SSH kinds take the SSH ladder: the transport being probed is the
        // same handshake (banner, kex, host key, offered sign-in methods) whatever
        // the tunnel does with the session afterwards. Without this the network
        // tunnel fell into `default:` and was probed as an SSL VPN — TLS and
        // certificate rungs against a port that speaks neither.
        case .ssh, .sshNetworkTunnel: ssh(facts)
        case .ikev2, .ipsec, .l2tp: ike(facts)
        case .tailscale: tailscale(facts)
        default: sslVPN(facts)      // the OpenConnect-driven SSL-VPN kinds
        }
    }

    static func ladder(for facts: ProbeTargetFacts) -> ProbeLadder {
        ProbeLadder(kind: facts.kind, host: facts.host, port: facts.port,
                    profileName: facts.profileName, steps: steps(for: facts))
    }

    // MARK: Shared rungs

    private static func dnsStep() -> ProbeStep {
        ProbeStep(.dnsResolve,
                  title: "Find the VPN\u{2019}s address",
                  detail: "Turns the VPN\u{2019}s name into an address this Mac can reach.")
    }

    private static func reachabilityStep(_ facts: ProbeTargetFacts) -> ProbeStep {
        ProbeStep(.reachability,
                  title: "Reach the VPN",
                  detail: "Checks that traffic to the VPN gets out of this network.")
    }

    /// The sign-in rung. Always last, always behind the account boundary.
    private static func signInStep(_ stage: ProbeStage, _ facts: ProbeTargetFacts,
                                   title: String, detail: String) -> ProbeStep {
        ProbeStep(stage, title: title, detail: detail,
                  blocking: false, requiresAccountCredentials: true,
                  accountSkipReason: facts.accountSkipReason)
    }

    // MARK: OpenVPN

    static func openVPN(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep(), reachabilityStep(facts)]

        steps.append(ProbeStep(.openVPNReset,
                               title: "Get a first reply",
                               detail: "Says hello the way an OpenVPN client does, with nothing signed.",
                               blocking: false))

        if facts.tlsKey != nil {
            steps.append(ProbeStep(.openVPNStaticKey,
                                   title: "Prove the shared key",
                                   detail: "Says hello again, signed with this VPN\u{2019}s shared key \u{2014} the check the plain hello can\u{2019}t make.",
                                   blocking: false))
        } else {
            steps.append(ProbeStep(.openVPNStaticKey,
                                   title: "Prove the shared key",
                                   detail: "This VPN doesn\u{2019}t use a shared handshake key.",
                                   blocking: false,
                                   preset: .notApplicable("This VPN doesn\u{2019}t use a shared handshake key, so there is nothing to prove here.")))
        }

        if facts.hasClientCertificate {
            steps.append(ProbeStep(.openVPNClientCertificate,
                                   title: "Check your certificate",
                                   detail: "Checks the certificate and key this VPN identifies you with \u{2014} dates, the pair, and the authority behind it.",
                                   blocking: false))
        } else {
            steps.append(ProbeStep(.openVPNClientCertificate,
                                   title: "Check your certificate",
                                   detail: "This VPN signs you in with a username instead of a certificate.",
                                   blocking: false,
                                   preset: .notApplicable("This VPN doesn\u{2019}t use a client certificate.")))
        }

        // Honest limit, stated in the ladder rather than hidden in a comment:
        // OpenVPN's certificate exchange happens INSIDE its own control channel,
        // which cannot be opened without becoming a real connection attempt.
        steps.append(ProbeStep(.openVPNServerCertificate,
                               title: "Check the VPN\u{2019}s certificate",
                               detail: "Not something that can be checked from outside.",
                               blocking: false,
                               preset: .notApplicable(
                                "OpenVPN shows its certificate inside the tunnel it is building, so it can only be seen by actually connecting. Everything up to that point has been checked.")))

        if facts.usesAccountSignIn {
            steps.append(signInStep(.openVPNSignIn, facts,
                                    title: "Sign in",
                                    detail: "Sends the username and password this VPN is set up with."))
        }
        return steps
    }

    // MARK: SSH

    static func ssh(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep(), reachabilityStep(facts)]

        steps.append(ProbeStep(.sshBanner,
                               title: "See what\u{2019}s answering",
                               detail: "Reads the greeting the server sends before anything else."))
        steps.append(ProbeStep(.sshKeyExchange,
                               title: "Agree on encryption",
                               detail: "Completes the key exchange \u{2014} the point where an incompatible or ancient server stops."))
        steps.append(ProbeStep(.sshHostKey,
                               title: "Confirm the server\u{2019}s identity",
                               detail: "Compares the server\u{2019}s fingerprint with the one on record for it."))
        steps.append(ProbeStep(.sshAuthMethods,
                               title: "Find out how to sign in",
                               detail: "Asks which ways of signing in the server will accept.",
                               blocking: false))

        if facts.identityFilePath?.isEmpty == false {
            steps.append(ProbeStep(.sshPublicKey,
                                   title: "Prove your key",
                                   detail: "Offers the key this VPN is set up with. A key is reusable, so this costs nothing and consumes nothing.",
                                   blocking: false))
        } else {
            steps.append(ProbeStep(.sshPublicKey,
                                   title: "Prove your key",
                                   detail: "No key file is set for this VPN.",
                                   blocking: false,
                                   preset: .notApplicable("This VPN has no key file set, so it signs in with a password instead.")))
        }

        steps.append(signInStep(.sshPasswordSignIn, facts,
                                title: "Sign in with a password",
                                detail: "Sends the password this VPN is set up with."))
        return steps
    }

    // MARK: IKEv2 / IPsec

    static func ike(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep()]
        steps.append(ProbeStep(.ikeReachability,
                               title: "Reach the gateway",
                               detail: "Checks that this network lets IPsec traffic out at all."))
        steps.append(ProbeStep(.ikeSAInit,
                               title: "Agree on encryption",
                               detail: "Offers exactly what this VPN is set up to use, and reports what the gateway picked. A mismatch here is the classic silent IPsec failure."))
        steps.append(ProbeStep(.ikeNATTraversal,
                               title: "Check the way through your router",
                               detail: "Most home and office routers need IPsec to switch to a second port; this checks that it is open.",
                               blocking: false))

        // Honest limit: completing IKE_AUTH means finishing a real key agreement
        // and leaving a half-open security association on the gateway — a session
        // nobody asked for. It is deliberately not done.
        steps.append(ProbeStep(.ikeAuth,
                               title: "Prove your identity",
                               detail: "Not something that can be checked without starting a real connection.",
                               blocking: false,
                               preset: .notApplicable(
                                "Proving your identity to an IPsec gateway means finishing the key agreement, which leaves a live session on it. That isn\u{2019}t something a check should do behind your back.")))
        return steps
    }

    // MARK: SSL-VPN

    static func sslVPN(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep(), reachabilityStep(facts)]

        steps.append(ProbeStep(.tlsHandshake,
                               title: "Make a secure connection",
                               detail: "Completes the encrypted handshake and checks the VPN\u{2019}s certificate against what this profile trusts."))
        steps.append(ProbeStep(.vendorClassification,
                               title: "Recognise the VPN",
                               detail: "Confirms the thing answering is the kind of VPN this profile expects.",
                               blocking: false))
        steps.append(ProbeStep(.clientCertificateRequested,
                               title: "See whether a certificate is required",
                               detail: "Many company VPNs refuse to show a sign-in page at all until a certificate is presented.",
                               blocking: false))

        if facts.hasClientCertificate {
            steps.append(ProbeStep(.sslClientCertificate,
                                   title: "Check your certificate",
                                   detail: "Checks the certificate and key this VPN identifies you with.",
                                   blocking: false))
        } else {
            steps.append(ProbeStep(.sslClientCertificate,
                                   title: "Check your certificate",
                                   detail: "No certificate is set for this VPN.",
                                   blocking: false,
                                   preset: .notApplicable("This VPN has no client certificate set.")))
        }

        if facts.usesAccountSignIn {
            steps.append(signInStep(.sslSignIn, facts,
                                    title: "Sign in",
                                    detail: "Sends the username and password to the VPN\u{2019}s sign-in page."))
        }
        return steps
    }

    // MARK: WireGuard

    static func wireGuard(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep(), reachabilityStep(facts)]

        let haveKeys = (facts.wireGuardPrivateKey?.isEmpty == false)
            && (facts.wireGuardPeerPublicKey?.isEmpty == false)
        steps.append(ProbeStep(.wireGuardHandshake,
                               title: "Complete the handshake with your keys",
                               detail: haveKeys
                                ? "Runs the real handshake with this VPN\u{2019}s own keys. WireGuard has no password to spend, so this is a complete test."
                                : "This VPN is missing a key.",
                               preset: haveKeys ? nil
                                : .notApplicable("This VPN needs both your own key and the other end\u{2019}s public key before a handshake can be tried. Add them in Manage VPNs.")))
        // No sign-in rung at all: WireGuard authenticates with keys and has no
        // account to protect, so the ladder simply ends here — complete.
        return steps
    }

    // MARK: Tailscale / Headscale

    static func tailscale(_ facts: ProbeTargetFacts) -> [ProbeStep] {
        var steps = [dnsStep()]
        steps.append(ProbeStep(.controlPlaneReachability,
                               title: "Reach the coordination server",
                               detail: "This VPN checks in with a coordination server before it can build any tunnel."))
        steps.append(ProbeStep(.controlPlaneTLS,
                               title: "Make a secure connection",
                               detail: "Completes the encrypted handshake with the coordination server and checks its certificate."))
        steps.append(ProbeStep(.controlPlaneIdentity,
                               title: "Confirm it\u{2019}s the right kind of server",
                               detail: "Asks the server to identify itself as a Tailscale-compatible coordination server.",
                               blocking: false))
        return steps
    }
}
