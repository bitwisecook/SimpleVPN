// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeRemedies.swift
//  What to DO about each way a ladder step can fail, in the same shape as every
//  other failure the app explains (UserFacingError: a title, one sentence,
//  numbered steps that name real buttons, and an optional action button).
//
//  Kept apart from the probes themselves so the advice is pure data — a table
//  from "what broke" to "what fixes it" — testable without a socket, and
//  editable without touching protocol code.
//

import Foundation

/// The distinct failures the ladder can find. One case per piece of advice, not
/// one per protocol: "the certificate expired" reads the same whether it was an
/// OpenVPN profile or an SSL-VPN.
nonisolated enum ProbeFailure: String, Sendable, CaseIterable, Equatable {
    case nameLookupFailed
    case portClosed
    case portFiltered
    case noProtocolAnswer
    case staticKeyRejected
    case staticKeyMissing
    case clientCertificateExpired
    case clientCertificateNotYetValid
    case clientCertificateUntrusted
    case clientKeyMismatch
    case clientKeyLocked
    case serverCertificateExpired
    case serverCertificateUntrusted
    case serverCertificateNameMismatch
    case serverCertificatePinMismatch
    case hostKeyChanged
    case hostKeyUnknown
    case publicKeyRejected
    case noUsableAuthMethod
    case proposalRejected
    case controlPlaneUnreachable
    case handshakeUnanswered
}

nonisolated extension UserFacingError {

    /// Advice for one ladder failure. `detail` is the already-redacted technical
    /// evidence; it only ever appears inside the details disclosure.
    static func probeRemedy(_ failure: ProbeFailure, vpnName: String = "this VPN",
                            detail: String = "", occurred: Date = .now) -> UserFacingError {
        let redacted = redact(detail)
        switch failure {

        case .nameLookupFailed:
            return UserFacingError(
                title: "This network can\u{2019}t look up the VPN\u{2019}s address",
                explanation: "The VPN\u{2019}s name didn\u{2019}t resolve to an address here, so nothing else could be tried.",
                steps: [
                    .init("Check that ordinary web pages load on this network."),
                    .init("If they do, this network\u{2019}s DNS may be blocking the VPN\u{2019}s name \u{2014} try a different Wi\u{2011}Fi or a phone hotspot."),
                    .init("If the address was typed by hand, open **Manage VPNs** and check it for typos."),
                ],
                action: .networkSettings, canRetry: true, category: .network,
                symbol: "questionmark.circle.fill", technicalDetail: redacted, occurred: occurred)

        case .portClosed:
            return UserFacingError(
                title: "Nothing is listening where \(vpnName) expects it",
                explanation: "The address answered, but it actively refused the port this VPN uses.",
                steps: [
                    .init("Check the port in **Manage VPNs \u{25B8} Options \u{25B8} Connection**."),
                    .init("If this VPN offers other locations, try one of those."),
                    .init("If the port is right, the VPN service itself may be down \u{2014} ask whoever runs it."),
                ],
                action: .manageVPNs, canRetry: true, category: .network,
                symbol: "bolt.horizontal.circle", technicalDetail: redacted, occurred: occurred)

        case .portFiltered:
            return UserFacingError(
                title: "This network is swallowing the VPN\u{2019}s traffic",
                explanation: "Nothing came back at all \u{2014} not even a refusal. That\u{2019}s what a firewall in the way looks like.",
                steps: [
                    .init("On a restrictive network (hotel, airport, office guest Wi\u{2011}Fi), switch this VPN to **TCP on port 443** in **Options \u{25B8} Connection** \u{2014} that usually gets through."),
                    .init("Or try a phone hotspot to confirm it\u{2019}s this network and not the VPN."),
                ],
                action: .manageVPNs, canRetry: true, category: .network,
                symbol: "hand.raised.slash", technicalDetail: redacted, occurred: occurred)

        case .noProtocolAnswer:
            return UserFacingError(
                title: "Something answered, but it isn\u{2019}t \(vpnName)",
                explanation: "The port is open and a service replied \u{2014} just not in this VPN\u{2019}s language.",
                steps: [
                    .init("Check the address, port and protocol in **Manage VPNs \u{25B8} Options \u{25B8} Connection**."),
                    .init("If they\u{2019}re right, something on this network may be intercepting the connection."),
                ],
                action: .manageVPNs, canRetry: true, category: .configuration,
                symbol: "questionmark.diamond", technicalDetail: redacted, occurred: occurred)

        case .staticKeyRejected:
            return UserFacingError(
                title: "The VPN ignored a correctly-signed hello",
                explanation: "This VPN signs its handshake with a shared key. Ours was signed and sent, and the VPN said nothing \u{2014} which is exactly what it does when the key, its direction, or its signing algorithm doesn\u{2019}t match.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and check the **TLS Key** on the **Certificates** tab \u{2014} it must be the file your VPN\u{2019}s administrator supplied."),
                    .init("Check the key\u{2019}s mode: **TLS-Crypt** and **TLS-Auth** are not interchangeable."),
                    .init("For TLS-Auth, check the key direction \u{2014} a client normally uses **1**."),
                    .init("If none of that is wrong, ask whoever runs the VPN for a fresh copy of the key file."),
                ],
                action: .manageVPNs, canRetry: true, category: .configuration,
                symbol: "key.slash", technicalDetail: redacted, occurred: occurred)

        case .staticKeyMissing:
            return UserFacingError(
                title: "\(vpnName) expects a shared key this profile doesn\u{2019}t have",
                explanation: "The VPN only answers a handshake signed with a key file, and there isn\u{2019}t one in this profile.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and drop the key file onto **TLS Key** on the **Certificates** tab."),
                    .init("Your VPN\u{2019}s administrator supplies that file \u{2014} it is usually called something like ta.key."),
                ],
                action: .manageVPNs, canRetry: true, category: .configuration,
                symbol: "key", technicalDetail: redacted, occurred: occurred)

        case .clientCertificateExpired:
            return UserFacingError(
                title: "Your certificate for \(vpnName) has expired",
                explanation: "The VPN identifies you with a certificate, and this one is past its expiry date. It will be refused however correct everything else is.",
                steps: [
                    .init("Ask whoever runs the VPN for a new certificate."),
                    .init("Open **Manage VPNs**, select \(vpnName), and drop the new file onto **Client Certificate** on the **Certificates** tab."),
                ],
                action: .manageVPNs, category: .credentials,
                symbol: "calendar.badge.exclamationmark", technicalDetail: redacted, occurred: occurred)

        case .clientCertificateNotYetValid:
            return UserFacingError(
                title: "Your certificate for \(vpnName) isn\u{2019}t valid yet",
                explanation: "The certificate\u{2019}s start date is in the future \u{2014} usually because this Mac\u{2019}s clock is wrong, occasionally because it was issued early.",
                steps: [
                    .init("Check **System Settings \u{25B8} General \u{25B8} Date & Time** and turn on **Set time and date automatically**."),
                    .init("If the clock is right, the certificate genuinely isn\u{2019}t usable yet \u{2014} ask whoever issued it."),
                ],
                canRetry: true, category: .configuration,
                symbol: "clock.badge.exclamationmark", technicalDetail: redacted, occurred: occurred)

        case .clientCertificateUntrusted:
            return UserFacingError(
                title: "Your certificate doesn\u{2019}t match this VPN\u{2019}s authority",
                explanation: "The certificate in this profile wasn\u{2019}t issued by the certificate authority the profile also carries, so the VPN will not accept it.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and look at the **Certificates** tab."),
                    .init("Check that the **Certificate Authority** and the **Client Certificate** came from the same place \u{2014} mixing two VPNs\u{2019} files is the usual cause."),
                    .init("If in doubt, re-import the original configuration file your administrator gave you."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "seal.slash", technicalDetail: redacted, occurred: occurred)

        case .clientKeyMismatch:
            return UserFacingError(
                title: "The private key doesn\u{2019}t belong to the certificate",
                explanation: "This profile\u{2019}s certificate and private key are from different pairs, so nothing can be proved with them.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and open the **Certificates** tab."),
                    .init("Replace both the **Client Certificate** and the **Private Key** from the same bundle \u{2014} or drop the original .p12 file, which carries both."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "key.slash", technicalDetail: redacted, occurred: occurred)

        case .clientKeyLocked:
            return UserFacingError(
                title: "The private key is password-protected",
                explanation: "The key can\u{2019}t be used until its password is supplied, so this check couldn\u{2019}t run on its own.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and enter the key\u{2019}s password under **Options \u{25B8} Security**."),
                    .init("Then run this check again."),
                ],
                action: .manageVPNs, canRetry: true, category: .credentials,
                symbol: "lock.fill", technicalDetail: redacted, occurred: occurred)

        case .serverCertificateExpired:
            return UserFacingError(
                title: "\(vpnName) is using an expired certificate",
                explanation: "The VPN\u{2019}s own certificate is past its expiry date. This is the VPN\u{2019}s problem, not this Mac\u{2019}s.",
                steps: [
                    .init("Tell whoever runs the VPN \u{2014} their certificate needs renewing."),
                    .init("Don\u{2019}t work around it by turning certificate checks off; an expired certificate and an impersonator look the same from here."),
                ],
                category: .configuration,
                symbol: "checkmark.seal.trianglebadge.exclamationmark.fill",
                technicalDetail: redacted, occurred: occurred)

        case .serverCertificateUntrusted:
            return UserFacingError(
                title: "This VPN\u{2019}s identity couldn\u{2019}t be confirmed",
                explanation: "The certificate the VPN presented wasn\u{2019}t issued by the authority this profile trusts.",
                steps: [
                    .init("Check the **Certificate Authority** on this VPN\u{2019}s **Certificates** tab is the one your administrator supplied."),
                    .init("If it is, something may be intercepting the connection \u{2014} common on captive Wi\u{2011}Fi and on networks that inspect traffic."),
                    .init("Contact whoever runs the VPN before loosening any certificate setting."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "exclamationmark.shield.fill", technicalDetail: redacted, occurred: occurred)

        case .serverCertificateNameMismatch:
            return UserFacingError(
                title: "The VPN\u{2019}s certificate is for a different name",
                explanation: "The certificate is valid, but it doesn\u{2019}t cover the address this profile connects to.",
                steps: [
                    .init("Check the address in **Manage VPNs \u{25B8} Options \u{25B8} Connection** matches the one your administrator gave you."),
                    .init("If the profile pins a name to check, confirm it in **Options \u{25B8} Security**."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "exclamationmark.shield", technicalDetail: redacted, occurred: occurred)

        case .serverCertificatePinMismatch:
            return UserFacingError(
                title: "This VPN isn\u{2019}t the one you pinned",
                explanation: "This profile records the exact certificate this VPN should present, and what answered presented a different one.",
                steps: [
                    .init("If the VPN\u{2019}s certificate was renewed recently, ask your administrator to confirm the new fingerprint, then update it in **Manage VPNs**."),
                    .init("If nothing changed, stop \u{2014} treat this as interception and report it."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "exclamationmark.shield.fill", technicalDetail: redacted, occurred: occurred)

        case .hostKeyChanged:
            return UserFacingError(
                title: "This server\u{2019}s identity has CHANGED",
                explanation: "The fingerprint it presents is not the one recorded for it. That happens when a server is rebuilt \u{2014} and it is also exactly what interception looks like.",
                steps: [
                    .init("Do not sign in until you know why."),
                    .init("Ask whoever runs the server whether its host key was replaced, and get the new fingerprint from them directly."),
                    .init("Only once it matches, update the recorded fingerprint for \(vpnName)."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "exclamationmark.shield.fill", technicalDetail: redacted, occurred: occurred)

        case .hostKeyUnknown:
            return UserFacingError(
                title: "This server hasn\u{2019}t been seen before",
                explanation: "There is no recorded fingerprint for it, and this VPN is set to refuse servers it doesn\u{2019}t already know.",
                steps: [
                    .init("Get the server\u{2019}s fingerprint from whoever runs it \u{2014} not from the server itself."),
                    .init("Add it in **Manage VPNs**, or relax **Strict host key checking** to **accept-new** if you trust this network."),
                ],
                action: .manageVPNs, category: .configuration,
                symbol: "questionmark.diamond", technicalDetail: redacted, occurred: occurred)

        case .publicKeyRejected:
            return UserFacingError(
                title: "The server didn\u{2019}t accept this key",
                explanation: "The key in this profile isn\u{2019}t one the server recognises for this account.",
                steps: [
                    .init("Check the key file in **Manage VPNs \u{25B8} Options \u{25B8} Connection** points at the right key."),
                    .init("Check the username is the one the key was installed for."),
                    .init("Ask whoever runs the server to confirm your public key is in that account\u{2019}s authorized_keys."),
                ],
                action: .manageVPNs, canRetry: true, category: .credentials,
                symbol: "key.slash", technicalDetail: redacted, occurred: occurred)

        case .noUsableAuthMethod:
            return UserFacingError(
                title: "The server won\u{2019}t accept how this VPN signs in",
                explanation: "None of the ways this profile is set up to sign in are offered by the server.",
                steps: [
                    .init("Open **Manage VPNs** and check this VPN\u{2019}s sign-in settings against what the server actually offers (listed in the details below)."),
                    .init("If it only offers keys, add a key file; if only passwords, remove the key requirement."),
                ],
                action: .manageVPNs, category: .credentials,
                symbol: "person.badge.key", technicalDetail: redacted, occurred: occurred)

        case .proposalRejected:
            return UserFacingError(
                title: "This VPN and your Mac can\u{2019}t agree on encryption",
                explanation: "The gateway refused every encryption combination this profile asks for. This is the classic silent IPsec failure \u{2014} it looks like a timeout from the outside.",
                steps: [
                    .init("Open **Manage VPNs**, select \(vpnName), and look at the IKE settings."),
                    .init("Set the encryption, integrity and Diffie\u{2011}Hellman group to exactly what your administrator specifies \u{2014} the details below show what was offered."),
                    .init("Leaving them on **Automatic** lets macOS pick its own defaults, which many gateways reject."),
                ],
                action: .manageVPNs, canRetry: true, category: .configuration,
                symbol: "lock.rotation", technicalDetail: redacted, occurred: occurred)

        case .controlPlaneUnreachable:
            return UserFacingError(
                title: "The coordination server isn\u{2019}t answering",
                explanation: "This VPN checks in with a coordination server before it can build any tunnel, and that server didn\u{2019}t respond.",
                steps: [
                    .init("Check the server\u{2019}s web address in **Manage VPNs**."),
                    .init("Open that address in a browser \u{2014} if it doesn\u{2019}t load there either, the server is down or blocked on this network."),
                ],
                action: .manageVPNs, canRetry: true, category: .network,
                symbol: "antenna.radiowaves.left.and.right.slash",
                technicalDetail: redacted, occurred: occurred)

        case .handshakeUnanswered:
            return UserFacingError(
                title: "\(vpnName) didn\u{2019}t answer a properly-signed hello",
                explanation: "The handshake was built with this profile\u{2019}s own keys and sent, and nothing came back. Either the keys aren\u{2019}t the ones the VPN knows, or this network is dropping the traffic.",
                steps: [
                    .init("Check the keys in **Manage VPNs** against what your administrator gave you."),
                    .init("Confirm the address and port \u{2014} a silent VPN and a wrong port look identical."),
                    .init("Try another network to rule out filtering."),
                ],
                action: .manageVPNs, canRetry: true, category: .configuration,
                symbol: "antenna.radiowaves.left.and.right.slash",
                technicalDetail: redacted, occurred: occurred)
        }
    }
}
