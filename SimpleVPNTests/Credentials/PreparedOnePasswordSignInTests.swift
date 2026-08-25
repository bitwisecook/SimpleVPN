// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

struct PreparedOnePasswordSignInTests {
    @Test func codeCacheExpiresBeforeTheCurrentThirtySecondWindow() {
        let now = Date(timeIntervalSince1970: 1_000)
        let expiry = PreparedOnePasswordSignIn.expiry(
            now: now, hasVerificationCode: true)
        #expect(expiry == Date(timeIntervalSince1970: 1_018))
    }

    @Test func passwordOnlyCacheLivesForThirtySeconds() {
        let now = Date(timeIntervalSince1970: 1_000)
        #expect(PreparedOnePasswordSignIn.expiry(
            now: now, hasVerificationCode: false) == now.addingTimeInterval(30))
    }

    @Test func cacheMatchesOnlyTheSameLinkedCoordinatesBeforeExpiry() {
        var source = CredentialSource()
        source.kind = .onePassword
        source.reference = "ITEM"
        source.accountReference = "ACCOUNT"
        source.vault = "VAULT"
        let cache = PreparedOnePasswordSignIn(
            reference: "ITEM", account: "ACCOUNT", vault: "VAULT",
            credentials: RawCredentials(username: "james", password: "secret"),
            expiresAt: Date(timeIntervalSince1970: 200))

        #expect(cache.matches(source, account: "ACCOUNT",
                              now: Date(timeIntervalSince1970: 199)))
        #expect(!cache.matches(source, account: "OTHER",
                               now: Date(timeIntervalSince1970: 199)))
        #expect(!cache.matches(source, account: "ACCOUNT",
                               now: Date(timeIntervalSince1970: 200)))
    }
}
