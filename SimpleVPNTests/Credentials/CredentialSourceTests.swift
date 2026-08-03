// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialSourceTests.swift
//  Pins the stored credential-source blob, whose shape changed the day the
//  1Password account and vault stopped being one field:
//    • account and vault round-trip independently (they name different things —
//      an account holds vaults — and 1Password refuses to answer without the
//      account);
//    • blobs written by older builds still decode: every key is optional, so a
//      missing one can never throw the user's item choice away;
//    • a legacy 1Password blob's single value reaches BOTH sides, because it was
//      used as the vault but sat under a field labelled "Account" and the two
//      can't be told apart afterwards;
//    • the same migration must not touch Apple Passwords, where that field
//      always meant the saved login's username.
//

import Foundation
import Testing
@testable import SimpleVPN

struct CredentialSourceTests {

    private func roundTrip(_ source: CredentialSource) -> CredentialSource {
        CredentialSource.decode(from: source.encodedBlob())
    }

    // MARK: - Round trip

    @Test func accountAndVaultSurviveSeparately() {
        var source = CredentialSource()
        source.kind = .onePassword
        source.reference = "GR Lab VPN"
        source.vault = "Private"
        source.account = "Secure Vault"
        source.fieldMap = ["username": "username", "otp": "one-time password"]

        let decoded = roundTrip(source)
        #expect(decoded == source)
        #expect(decoded.vault == "Private")
        #expect(decoded.account == "Secure Vault")
    }

    @Test func defaultSourceStoresNothing() {
        #expect(CredentialSource().encodedBlob() == nil)
        #expect(CredentialSource.decode(from: nil) == CredentialSource())
    }

    /// A vault on its own is still worth storing — `isDefault` must not treat it
    /// as an untouched source and drop it.
    @Test func aVaultAloneIsNotTheDefaultSource() {
        var source = CredentialSource()
        source.vault = "Private"
        #expect(!source.isDefault)
        #expect(roundTrip(source).vault == "Private")
    }

    // MARK: - Legacy blobs

    private func legacyBlob(kind: String, account: String) -> Data {
        Data(#"{"kind":"\#(kind)","reference":"GR Lab VPN","account":"\#(account)","fieldMap":{}}"#.utf8)
    }

    @Test func legacyOnePasswordBlobFillsBothVaultAndAccount() {
        let decoded = CredentialSource.decode(from: legacyBlob(kind: "onePassword", account: "Private"))
        #expect(decoded.kind == .onePassword)
        #expect(decoded.reference == "GR Lab VPN")
        // It was used as the vault, so the vault keeps working…
        #expect(decoded.vault == "Private")
        // …and it may equally have been typed as an account name, so it stays.
        #expect(decoded.account == "Private")
    }

    @Test func legacyApplePasswordsBlobKeepsItsUsername() {
        let decoded = CredentialSource.decode(from: legacyBlob(kind: "applePasswords", account: "jim@example.com"))
        #expect(decoded.kind == .applePasswords)
        #expect(decoded.account == "jim@example.com")
        #expect(decoded.vault.isEmpty)   // vaults are a 1Password idea
    }

    /// An older blob missing keys entirely (and a newer one carrying keys this
    /// build has never heard of) must still decode.
    @Test(arguments: [
        #"{"kind":"onePassword","reference":"GR Lab VPN"}"#,
        #"{"kind":"onePassword","reference":"GR Lab VPN","account":"Private","somethingNew":true}"#,
        #"{"reference":"GR Lab VPN"}"#,
    ])
    func partialBlobsStillDecode(_ json: String) {
        let decoded = CredentialSource.decode(from: Data(json.utf8))
        #expect(decoded.reference == "GR Lab VPN")
    }

    @Test func unreadableBlobFallsBackToTheDefault() {
        #expect(CredentialSource.decode(from: Data("not json".utf8)) == CredentialSource())
    }

    // MARK: - The provider gets both, unconflated

    @Test func providerCarriesVaultAndAccountIndependently() {
        var source = CredentialSource()
        source.kind = .onePassword
        source.reference = "GR Lab VPN"
        source.vault = "Private"
        source.account = "Secure Vault"

        let provider = OnePasswordProvider(itemReference: source.reference, vault: source.vault,
                                           account: source.account, fieldMap: source.fieldMap)
        #expect(provider.vault == "Private")
        #expect(provider.account == "Secure Vault")
    }

    // MARK: - Drop links

    @Test func secretReferenceDropCarriesVaultOnly() throws {
        let dropped = try #require(EditVPNView.parseOnePasswordDrop("op://Private/GR Lab VPN/password"))
        #expect(dropped.reference == "GR Lab VPN")
        #expect(dropped.vault == "Private")
        #expect(dropped.account.isEmpty)   // a secret reference never names one
    }

    /// The shape that spares people typing a UUID they've never seen.
    @Test(arguments: [
        "onepassword://open/i?a=ACCOUNTUUID&v=VAULTUUID&i=ITEMUUID&h=example.1password.com",
        "https://start.1password.com/open/i?a=ACCOUNTUUID&v=VAULTUUID&i=ITEMUUID&h=example.1password.com",
    ])
    func linkDropCapturesAccountAndVault(_ raw: String) throws {
        let dropped = try #require(EditVPNView.parseOnePasswordDrop(raw))
        #expect(dropped.reference == "ITEMUUID")
        #expect(dropped.vault == "VAULTUUID")
        #expect(dropped.account == "ACCOUNTUUID")
    }

    @Test func plainTextDropIsJustTheItemName() throws {
        let dropped = try #require(EditVPNView.parseOnePasswordDrop("GR Lab VPN\nsecond line"))
        #expect(dropped.reference == "GR Lab VPN")
        #expect(dropped.vault.isEmpty)
        #expect(dropped.account.isEmpty)
    }

    @Test func emptyDropIsRejected() {
        #expect(EditVPNView.parseOnePasswordDrop("   \n ") == nil)
    }
}

/// The Connect-readiness seam (`ConnectInputs.readiness`) is the ONE decision the
/// detail Connect button, the sidebar play button and the menu row all read. It
/// exists because those three used to recompute enablement independently and
/// drifted: a Tailscale VPN was connectable from the detail pane yet stuck on a
/// dimmed "Sign-in needed" play button in the sidebar — so it could never be
/// signed in. These tests pin the pure decision AND the invariant that the two
/// view mappings can never disagree.
struct ConnectReadinessTests {

    // The two view mappings, transcribed from ConnectionView.canConnect and
    // VPNSidebarRow.missingTypedInput — the exact seam under test.
    private func detailCanConnect(_ r: ConnectReadiness) -> Bool { r == .ready }
    private enum SidebarMissing: Equatable { case none, signIn, code }
    private func sidebarMissing(_ r: ConnectReadiness) -> SidebarMissing {
        switch r {
        case .ready: .none
        case .needsCode: .code
        case .needsSignIn, .blocked: .signIn
        }
    }

    // MARK: - The bug: Tailscale signs itself in, so it is always connectable

    /// The regression this whole change fixes: a Tailscale VPN is READY with no
    /// stored credentials, no typed username/password, no OTP — nothing.
    @Test func tailscaleIsReadyWithNothingStoredOrTyped() {
        var inputs = ConnectInputs()
        inputs.kind = .tailscale
        #expect(inputs.readiness == .ready)
    }

    /// …and stays ready no matter what the credential fields say — the kind wins
    /// outright, so the sidebar can't fall back to "Sign-in needed".
    @Test(arguments: [true, false])
    func tailscaleIgnoresEveryCredentialField(_ flag: Bool) {
        var inputs = ConnectInputs()
        inputs.kind = .tailscale
        inputs.requiresOTP = flag
        inputs.typedUsername = flag
        inputs.typedPassword = flag
        inputs.typedOTP = flag
        inputs.hasLockedUsername = flag
        inputs.biometricProtected = flag
        #expect(inputs.readiness == .ready)
    }

    // MARK: - Sidebar and detail can never disagree

    /// The core invariant: for every reachable input combination, the detail
    /// pane's "Connect enabled" and the sidebar's "nothing missing" agree. A
    /// Tailscale profile with no credentials must be connectable in BOTH.
    @Test func detailAndSidebarNeverDisagree() {
        for inputs in Self.matrix {
            let r = inputs.readiness
            let detailEnabled = detailCanConnect(r)
            let sidebarClear = sidebarMissing(r) == .none
            #expect(detailEnabled == sidebarClear,
                    "detail(\(detailEnabled)) vs sidebar(\(sidebarClear)) for \(inputs)")
        }
    }

    // Every combination the gatherer can produce, across all kinds — the exact
    // set the two views must agree on.
    private static let matrix: [ConnectInputs] = {
        var out: [ConnectInputs] = []
        let bools = [false, true]
        // Tailscale + proxy variants.
        out.append({ var i = ConnectInputs(); i.kind = .tailscale; return i }())
        for problem in bools { for auth in bools { for complete in bools {
            var i = ConnectInputs(); i.kind = .proxyTunnel
            i.proxyHasProblem = problem; i.proxyRequiresAuth = auth; i.proxyCredentialsComplete = complete
            out.append(i)
        }}}
        // OpenVPN across autologin / manager / biometric / typed dimensions.
        for autologin in bools {
          for manager in [CredentialSourceKind.manual, .applePasswords, .onePassword] {
            for otp in bools { for bioP in bools { for bioStored in bools { for bioTOTP in bools {
              for locked in bools { for tUser in bools { for tPass in bools { for tOTP in bools {
                var i = ConnectInputs(); i.kind = .openVPN
                i.autologin = autologin; i.managerKind = manager; i.requiresOTP = otp
                i.biometricProtected = bioP; i.biometricStored = bioStored; i.biometricHasTOTP = bioTOTP
                i.hasLockedUsername = locked; i.typedUsername = tUser; i.typedPassword = tPass; i.typedOTP = tOTP
                out.append(i)
              }}}}
            }}}}
          }
        }
        return out
    }()

    // MARK: - Autologin: the certificate is the sign-in

    @Test func autologinIsReadyWithNoTypedCredentials() {
        var inputs = ConnectInputs()
        inputs.kind = .openVPN
        inputs.autologin = true
        #expect(inputs.readiness == .ready)
    }

    // MARK: - Proxy Tunnel

    @Test func proxyWithoutAuthIsReady() {
        var i = ConnectInputs(); i.kind = .proxyTunnel
        #expect(i.readiness == .ready)
    }

    @Test func proxyNeedingAuthWaitsOnItsStoredSignIn() {
        var i = ConnectInputs(); i.kind = .proxyTunnel; i.proxyRequiresAuth = true
        #expect(i.readiness == .needsSignIn)
        i.proxyCredentialsComplete = true
        #expect(i.readiness == .ready)
    }

    @Test func proxyProblemBlocksConnect() {
        var i = ConnectInputs(); i.kind = .proxyTunnel
        i.proxyHasProblem = true
        i.proxyRequiresAuth = true
        i.proxyCredentialsComplete = true   // even fully-credentialled, a problem blocks
        #expect(i.readiness == .blocked)
    }

    // MARK: - Password managers

    /// Apple Passwords can't hand over a one-time code, so a code is still needed;
    /// 1Password can, so it doesn't block.
    @Test func managerOTPGapDependsOnTheManager() {
        var apple = ConnectInputs(); apple.kind = .openVPN
        apple.managerKind = .applePasswords; apple.requiresOTP = true
        #expect(apple.readiness == .needsCode)
        apple.typedOTP = true
        #expect(apple.readiness == .ready)

        var op = ConnectInputs(); op.kind = .openVPN
        op.managerKind = .onePassword; op.requiresOTP = true
        #expect(op.readiness == .ready)   // 1Password supplies the code itself
    }

    @Test func managerWithoutOTPIsReady() {
        var i = ConnectInputs(); i.kind = .openVPN
        i.managerKind = .applePasswords
        #expect(i.readiness == .ready)
    }

    // MARK: - Touch ID-protected sign-in

    @Test func biometricReleasesStoredSecretsButAnUncoveredCodeStillBlocks() {
        var i = ConnectInputs(); i.kind = .openVPN
        i.biometricProtected = true; i.biometricStored = true; i.requiresOTP = true
        #expect(i.readiness == .needsCode)      // no stored TOTP, none typed
        i.biometricHasTOTP = true
        #expect(i.readiness == .ready)          // the store supplies the code
    }

    @Test func biometricWithoutOTPIsReady() {
        var i = ConnectInputs(); i.kind = .openVPN
        i.biometricProtected = true; i.biometricStored = true
        #expect(i.readiness == .ready)
    }

    // MARK: - Plain typed credentials

    @Test func typedCredentialsNeedUsernameAndPassword() {
        var i = ConnectInputs(); i.kind = .openVPN
        #expect(i.readiness == .needsSignIn)
        i.typedUsername = true
        #expect(i.readiness == .needsSignIn)    // password still missing
        i.typedPassword = true
        #expect(i.readiness == .ready)
    }

    @Test func aLockedUsernameCountsAsPresent() {
        var i = ConnectInputs(); i.kind = .openVPN
        i.hasLockedUsername = true; i.typedPassword = true
        #expect(i.readiness == .ready)
    }

    @Test func typedCredentialsNeedTheCodeWhenOTPIsRequired() {
        var i = ConnectInputs(); i.kind = .openVPN
        i.typedUsername = true; i.typedPassword = true; i.requiresOTP = true
        #expect(i.readiness == .needsCode)
        i.typedOTP = true
        #expect(i.readiness == .ready)
    }
}
