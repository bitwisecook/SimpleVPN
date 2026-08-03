// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordListTests.swift
//  Pins the wire shape of the helper's `list` reply — the one that feeds the
//  vault and item pickers — and the two things that shape must never get wrong:
//    • an EMPTY list is not a missing list: `{"vaults":[]}` means "this account
//      has no vaults", and must not decode as a malformed reply (which is why
//      the shim emits the key even when the array is empty);
//    • a list failure is classified as a LIST failure — an account 1Password
//      can't match asks for the account name, never "pick the item again",
//      because there is no item in play yet.
//  Nothing here spawns the helper: these are pure decode + classification.
//
//  Also covers what a 1Password drag actually delivers. The text flavour is an
//  op:// reference (vault but no account); only the URL flavour carries the
//  account, and without it the SDK refuses to answer — so the URL flavour has
//  to win whenever both are offered.
//

import Foundation
import Testing
@testable import SimpleVPN

struct OnePasswordListTests {

    private func reply(_ json: String) -> Data { Data(json.utf8) }

    // MARK: - Vault lists

    @Test func vaultListDecodes() throws {
        let vaults = try OnePasswordNative.vaults(
            fromListReply: reply(#"{"vaults":[{"id":"v1","title":"Private"},{"id":"v2","title":"Shared"}]}"#),
            account: "Secure Vault")
        #expect(vaults.count == 2)
        #expect(vaults[0].id == "v1")
        #expect(vaults[0].title == "Private")
        #expect(vaults[1].title == "Shared")
    }

    /// An account with no visible vaults is a real answer, not a broken one.
    @Test func emptyVaultListIsNotAFailure() throws {
        let vaults = try OnePasswordNative.vaults(
            fromListReply: reply(#"{"vaults":[]}"#), account: "")
        #expect(vaults.isEmpty)
    }

    // MARK: - Item lists

    @Test func itemListDecodesWithCategories() throws {
        let items = try OnePasswordNative.items(
            fromListReply: reply("""
                {"items":[{"id":"i1","title":"GR Lab VPN","category":"Login"},
                          {"id":"i2","title":"Router","category":"Password"}]}
                """),
            account: "Secure Vault")
        #expect(items.count == 2)
        #expect(items[0].id == "i1")
        #expect(items[0].title == "GR Lab VPN")
        #expect(items[0].category == "Login")
        #expect(items[1].category == "Password")
    }

    @Test func emptyItemListIsNotAFailure() throws {
        let items = try OnePasswordNative.items(
            fromListReply: reply(#"{"items":[]}"#), account: "")
        #expect(items.isEmpty)
    }

    /// Asking for items and being handed vaults is a contract break, not an
    /// empty vault — the picker must not quietly show nothing.
    @Test func wrongListKindIsABadResponse() {
        #expect(throws: OnePasswordNativeError.badResponse) {
            try OnePasswordNative.items(
                fromListReply: reply(#"{"vaults":[{"id":"v1","title":"Private"}]}"#),
                account: "")
        }
        #expect(throws: OnePasswordNativeError.badResponse) {
            try OnePasswordNative.vaults(
                fromListReply: reply(#"{"items":[]}"#), account: "")
        }
    }

    @Test func garbageIsABadResponse() {
        #expect(throws: OnePasswordNativeError.badResponse) {
            try OnePasswordNative.vaults(fromListReply: reply("not json"), account: "")
        }
    }

    // MARK: - Error passthrough

    @Test func listErrorSurvivesAsItsKind() {
        #expect(throws: OnePasswordNativeError.itemNotFound(#"no vault named "Nope""#)) {
            try OnePasswordNative.items(
                fromListReply: reply(#"{"error":{"kind":"itemNotFound","message":"no vault named \"Nope\""}}"#),
                account: "")
        }
        #expect(throws: OnePasswordNativeError.integrationDisabled) {
            try OnePasswordNative.vaults(
                fromListReply: reply(#"{"error":{"kind":"integrationDisabled","message":"turned off"}}"#),
                account: "")
        }
    }

    /// The account is only known on the Swift side, so the helper's name-less
    /// complaint has to be completed here — otherwise the user is told an
    /// account is wrong without being told which one.
    @Test func accountNotFoundFromAListCarriesTheAccountAsked() throws {
        let data = reply(#"{"error":{"kind":"accountNotFound","message":"Account not found"}}"#)
        var thrown: OnePasswordNativeError?
        do {
            _ = try OnePasswordNative.vaults(fromListReply: data, account: "Wrong Name")
        } catch let e as OnePasswordNativeError {
            thrown = e
        }
        let error = try #require(thrown)
        #expect(error == .accountNotFound(account: "Wrong Name", detail: "Account not found"))
    }

    /// Regression: browsing failures must not be dressed up as item failures.
    /// A vault list hasn't named an item at all, so "pick the item again" would
    /// send the user to a field that isn't the problem.
    @Test func accountNotFoundFromAListClassifiesAsAnAccountProblem() throws {
        let data = reply(#"{"error":{"kind":"accountNotFound","message":"Account not found"}}"#)
        var thrown: Error?
        do {
            _ = try OnePasswordNative.items(fromListReply: data, account: "Wrong Name")
        } catch {
            thrown = error
        }
        let classified = UserFacingError.classify(try #require(thrown))
        #expect(classified.category == .credentials)
        #expect(classified.title.lowercased().contains("account name"))
        #expect(!classified.title.lowercased().contains("item"))
    }

    // MARK: - Listing items needs a vault

    /// 1Password's item list is per-vault; asking without one is refused here
    /// rather than spawning a helper that can only fail.
    @Test func listingItemsWithoutAVaultIsRejectedLocally() async {
        await #expect(throws: OnePasswordNativeError.badRequest("no vault chosen")) {
            try await OnePasswordNative.listItems(vault: "   ", account: "Secure Vault")
        }
    }

    // MARK: - Item lookup (name → item refs + the vault each lives in)

    /// The endpoint that removed the last reason to shell out to `op`: the SDK
    /// has no search, so the shim fans out and ranks, and this pins the reply
    /// it hands back.
    @Test func lookupReplyDecodesWithVaultCoordinates() throws {
        let matches = try OnePasswordNative.matches(
            fromLookupReply: reply(#"""
            {"matches":[
              {"itemID":"i1","title":"GR Lab VPN","category":"Login","vaultID":"v1","vaultTitle":"Private","score":0},
              {"itemID":"i2","title":"GR Lab VPN (old)","category":"Login","vaultID":"v2","vaultTitle":"Shared","score":1}
            ]}
            """#),
            account: "Secure Vault")
        #expect(matches.count == 2)
        #expect(matches[0].itemID == "i1")
        // The whole point: a match names the VAULT, which an item title alone
        // can't — that is what makes an op:// secret reference possible.
        #expect(matches[0].vaultID == "v1")
        #expect(matches[0].vaultTitle == "Private")
        #expect(matches[0].score == 0)
        // Vault-qualified ids, so two vaults' items can't collide in a list.
        #expect(matches[0].id == "v1/i1")
        #expect(matches[1].id == "v2/i2")
    }

    /// An empty match list is an ANSWER ("nothing matches"), not a malformed
    /// reply — same rule the vault/item lists follow.
    @Test func emptyLookupIsAnAnswerNotAFailure() throws {
        #expect(try OnePasswordNative.matches(
            fromLookupReply: reply(#"{"matches":[]}"#), account: "").isEmpty)
    }

    @Test func lookupWithoutMatchesKeyIsMalformed() {
        #expect(throws: OnePasswordNativeError.badResponse) {
            _ = try OnePasswordNative.matches(fromLookupReply: reply("{}"), account: "")
        }
    }

    /// A lookup failure is classified like every other: an unmatched account
    /// asks for the account name.
    @Test func lookupErrorsClassifyByKind() {
        #expect(throws: OnePasswordNativeError.accountNotFound(
            account: "Secure Vault", detail: "Account not found")) {
            _ = try OnePasswordNative.matches(
                fromLookupReply: reply(#"{"error":{"kind":"accountNotFound","message":"Account not found"}}"#),
                account: "Secure Vault")
        }
    }

    // MARK: - Drop payload flavours

    @Test func urlFlavourCapturesTheAccount() throws {
        let dropped = try #require(OnePasswordDropItem.parse([
            OnePasswordDropItem(
                raw: "onepassword://open/i?a=ACCOUNTUUID&v=VAULTUUID&i=ITEMUUID",
                flavor: .url)
        ]))
        #expect(dropped.reference == "ITEMUUID")
        #expect(dropped.vault == "VAULTUUID")
        #expect(dropped.account == "ACCOUNTUUID")
    }

    @Test func plainSecretReferenceStillWorksWithoutAnAccount() throws {
        let dropped = try #require(OnePasswordDropItem.parse([
            OnePasswordDropItem(raw: "op://Private/GR Lab VPN/password", flavor: .text)
        ]))
        #expect(dropped.reference == "GR Lab VPN")
        #expect(dropped.vault == "Private")
        #expect(dropped.account.isEmpty)
    }

    /// The whole point of accepting two flavours: the URL one names the account
    /// and the text one never can, so a drop offering both must take the URL.
    @Test func urlFlavourWinsWhenBothArrive() throws {
        let dropped = try #require(OnePasswordDropItem.parse([
            OnePasswordDropItem(raw: "op://Private/GR Lab VPN/password", flavor: .text),
            OnePasswordDropItem(
                raw: "https://start.1password.com/open/i?a=ACCOUNTUUID&v=VAULTUUID&i=ITEMUUID",
                flavor: .url),
        ]))
        #expect(dropped.account == "ACCOUNTUUID")
        #expect(dropped.reference == "ITEMUUID")
    }

    /// A dragged FILE is not a 1Password item — accepting it would put
    /// "file:///Users/…" in the item field and look like the drop worked.
    @Test func fileURLsAreRefused() {
        #expect(OnePasswordDropItem.parse([
            OnePasswordDropItem(raw: "file:///Users/jim/secrets.txt", flavor: .url)
        ]) == nil)
    }

    /// …but a file drag that also carries usable text is still a good drop.
    @Test func fileURLDoesNotSinkAUsableTextFlavour() throws {
        let dropped = try #require(OnePasswordDropItem.parse([
            OnePasswordDropItem(raw: "file:///Users/jim/secrets.txt", flavor: .url),
            OnePasswordDropItem(raw: "op://Private/GR Lab VPN/password", flavor: .text),
        ]))
        #expect(dropped.reference == "GR Lab VPN")
    }

    @Test func emptyDropIsRefused() {
        #expect(OnePasswordDropItem.parse([]) == nil)
        #expect(OnePasswordDropItem.parse([
            OnePasswordDropItem(raw: "  \n ", flavor: .text)
        ]) == nil)
    }
}
