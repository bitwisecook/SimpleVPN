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
