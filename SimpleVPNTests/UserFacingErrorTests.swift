// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  UserFacingErrorTests.swift
//  Pins the failure classifier — the thing standing between a non-technical
//  user and a raw SDK string:
//    • the EXACT message that shipped in the bug report ("desktop app
//      connection channel is closed…") must land on the integration-disabled
//      advice, and that advice must name the setting 1Password has TODAY
//      ("Integrate with 1Password SDKs"), not the one its own message suggests;
//    • every other known 1Password failure mode maps by loose substring, since
//      the SDK's strings are prose and drift between releases;
//    • "Account not found" — the SDK's answer when it can't match the account
//      name (the empty string included) — must ask for the ACCOUNT rather than
//      send the user back to re-pick the item;
//    • anything unrecognised still comes back friendly, with the raw text
//      preserved in technicalDetail and nowhere else;
//    • no classification may ever return an empty title or no steps — an empty
//      sheet is worse than the alert it replaced;
//    • redaction: nothing that looks like a password or a one-time code can
//      reach the details disclosure.
//

import Foundation
import Testing
@testable import SimpleVPN

struct UserFacingErrorTests {

    /// Verbatim from the user's screenshot — the reason this classifier exists.
    private static let screenshotMessage =
        "error initializing client: desktop app connection channel is closed. "
        + "Make sure Settings > Developer > Integrate with other apps is enabled, "
        + "or contact 1Password support"

    private func classify(_ message: String) -> UserFacingError {
        UserFacingError.classify(message: message)
    }

    // MARK: - The reported bug

    @Test func screenshotStringBecomesIntegrationAdvice() {
        let e = classify(Self.screenshotMessage)
        #expect(e.category == .onePassword)
        #expect(e.title == "1Password isn\u{2019}t letting SimpleVPN connect")
        #expect(e.action == .openOnePassword)
        #expect(e.canRetry)
        // The steps must name the CURRENT setting, not the SDK's stale one.
        let steps = e.steps.map(\.text).joined(separator: "\n")
        #expect(steps.contains("Integrate with 1Password SDKs"))
        #expect(!steps.contains("Integrate with other apps"))
        #expect(steps.contains("Developer"))
        // …and the raw string is only ever in the details.
        #expect(e.technicalDetail.contains("connection channel is closed"))
        #expect(!e.explanation.contains("connection channel is closed"))
        #expect(!e.title.contains("error initializing client"))
    }

    /// Same message arriving as the typed helper error (kind "other").
    @Test func screenshotStringAsTypedNativeError() {
        let e = UserFacingError.classify(OnePasswordNativeError.other(Self.screenshotMessage))
        #expect(e.title == "1Password isn\u{2019}t letting SimpleVPN connect")
        #expect(e.technicalDetail.contains("desktop app connection channel is closed"))
    }

    // MARK: - Substring table

    @Test(arguments: [
        "1Password: integration is disabled for this app",
        "1password integration not enabled",
        "desktop app connection channel is closed",
        "Make sure Settings > Developer > Integrate with other apps is enabled (1Password)",
    ])
    func integrationDisabledVariants(_ message: String) {
        #expect(classify(message).title == "1Password isn\u{2019}t letting SimpleVPN connect")
    }

    @Test(arguments: [
        "1Password desktop app is not running",
        "could not reach 1Password: connection refused",
        "1password: failed to connect to the desktop app",
        "1Password is locked",
    ])
    func appNotRunningVariants(_ message: String) {
        let e = classify(message)
        #expect(e.title == "1Password isn\u{2019}t open")
        #expect(e.action == .openOnePassword)
        #expect(e.steps.contains { $0.text.contains("Open **1Password**") })
    }

    @Test(arguments: [
        "1Password desktop application not found",
        "the 1Password app is not installed",
    ])
    func appNotInstalledVariants(_ message: String) {
        let e = classify(message)
        #expect(e.title == "1Password isn\u{2019}t installed on this Mac")
        if case .openURL = e.action {} else { Issue.record("expected a download link, got \(String(describing: e.action))") }
    }

    @Test(arguments: [
        "1Password: request not authorized by the user",
        "1password authorization required",
        "the 1Password prompt was denied",
        "1Password request rejected",
        "1password: operation cancelled",
    ])
    func approvalVariants(_ message: String) {
        let e = classify(message)
        #expect(e.title == "1Password needs you to approve SimpleVPN")
        #expect(e.category == .approval)
        #expect(e.canRetry)
        // The "first click fails, second works" reality has to be said out loud.
        let steps = e.steps.map(\.text).joined(separator: "\n")
        #expect(steps.contains("Connect** again"))
    }

    @Test(arguments: [
        "1Password: item not found in vault",
        "op://Private/GR Lab/password: no matching field",
        "1password couldn't find that item",
    ])
    func itemNotFoundVariants(_ message: String) {
        let e = classify(message)
        #expect(e.title == "SimpleVPN couldn\u{2019}t find your VPN\u{2019}s login in 1Password")
        #expect(e.action == .manageVPNs)
        #expect(e.steps.contains { $0.text.contains("Manage VPNs") })
    }

    // MARK: - Account, not item

    /// Verbatim from the SDK when `WithDesktopAppIntegration` gets an account
    /// name it can't match — including the empty string every build shipped
    /// before the account got its own field. It says "not found", but sending
    /// the user off to re-pick the item would never fix it.
    // nonisolated: `@Test(arguments:)` evaluates its list off the main actor.
    private nonisolated static let accountNotFoundMessage =
        "error initializing client: An error occurred when processing SDK request: "
        + "Error { msg: Account not found, inner: None }"

    @Test func accountNotFoundAsksForTheAccountName() {
        let e = classify(Self.accountNotFoundMessage)
        #expect(e.title == "SimpleVPN needs your 1Password account name")
        #expect(e.action == .manageVPNs)
        #expect(e.canRetry)
        let steps = e.steps.map(\.text).joined(separator: "\n")
        #expect(steps.contains("sidebar"))
        #expect(steps.contains("Account"))
        // The raw SDK text stays in the details and nowhere else.
        #expect(e.technicalDetail.contains("Account not found"))
        #expect(!e.title.contains("error initializing client"))
    }

    /// The regression: "Account not found" must never land on the item advice.
    @Test func accountNotFoundIsNotItemNotFound() {
        #expect(classify(Self.accountNotFoundMessage).title
                != "SimpleVPN couldn\u{2019}t find your VPN\u{2019}s login in 1Password")
    }

    @Test(arguments: [
        OnePasswordNativeError.accountNotFound(
            account: "", detail: UserFacingErrorTests.accountNotFoundMessage),
        OnePasswordNativeError.accountNotFound(
            account: "Secure Vault", detail: UserFacingErrorTests.accountNotFoundMessage),
        OnePasswordNativeError(
            kind: "accountNotFound", message: UserFacingErrorTests.accountNotFoundMessage),
    ])
    func typedAccountNotFoundClassifies(_ native: OnePasswordNativeError) {
        let e = UserFacingError.classify(native)
        #expect(e.title == "SimpleVPN needs your 1Password account name")
        #expect(e.technicalDetail.contains("Account not found"))
    }

    /// The account we tried is named back at the user — an empty one can't be.
    @Test func attemptedAccountNameIsSurfaced() {
        let e = UserFacingError.classify(
            OnePasswordNativeError.accountNotFound(account: "Wrong Name", detail: "x"))
        #expect(e.technicalDetail.contains("Wrong Name"))
    }

    @Test(arguments: [
        "1Password request timed out",
        "1password: context deadline exceeded",
    ])
    func timeoutVariants(_ message: String) {
        let e = classify(message)
        #expect(e.title == "1Password didn\u{2019}t answer")
        #expect(e.canRetry)
    }

    @Test func sessionExpiredIsAnApprovalCase() {
        let e = classify("1Password desktop session expired")
        #expect(e.title == "Your 1Password approval expired")
        #expect(e.canRetry)
    }

    @Test func rateLimitedSaysWait() {
        let e = classify("1Password: rate limit exceeded")
        #expect(e.title == "1Password asked SimpleVPN to slow down")
    }

    @Test func ambiguousItemPointsAtTheVault() {
        let e = classify("1Password: more than one item matches \u{201C}VPN\u{201D}")
        #expect(e.title == "More than one 1Password item matches")
        #expect(e.action == .manageVPNs)
    }

    /// A 1Password failure we've never seen before is still a 1Password failure.
    @Test func unknownOnePasswordMessageStaysOnePasswordFlavoured() {
        let e = classify("1Password returned gibberish 0x9f from the shim")
        #expect(e.category == .onePassword)
        #expect(e.title == "1Password couldn\u{2019}t give SimpleVPN the sign-in")
        #expect(e.technicalDetail.contains("gibberish"))
    }

    // MARK: - Typed helper errors

    @Test func everyTypedNativeErrorClassifies() {
        let cases: [OnePasswordNativeError] = [
            .appNotInstalled, .appNotRunning, .integrationDisabled, .userCancelled,
            .sessionExpired, .itemNotFound("op://v/i/f"),
            .accountNotFound(account: "", detail: "Account not found"),
            .ambiguous("VPN"),
            .rateLimited, .badRequest("op://"), .badResponse, .other("boom"),
        ]
        for native in cases {
            let e = UserFacingError.classify(native)
            #expect(!e.title.isEmpty)
            #expect(!e.steps.isEmpty)
            #expect(!e.explanation.isEmpty)
        }
    }

    @Test func typedIntegrationDisabledMatchesTheStringPath() {
        #expect(UserFacingError.classify(OnePasswordNativeError.integrationDisabled).title
                == classify(Self.screenshotMessage).title)
    }

    // MARK: - Non-1Password

    @Test func unrecognisedTechnicalErrorIsGenericButFriendly() {
        let raw = "Error Domain=NEVPNErrorDomain Code=1 \"permission denied\" UserInfo={x=1}"
        let e = classify(raw)
        #expect(e.title == "Something went wrong")
        #expect(!e.steps.isEmpty)
        #expect(e.category == .generic)
        // Raw text ONLY in the details.
        #expect(e.technicalDetail.contains("NEVPNErrorDomain"))
        #expect(!e.explanation.contains("NEVPNErrorDomain"))
        #expect(!e.title.contains("NEVPNErrorDomain"))
    }

    /// Messages the app itself wrote are already plain language — they lead
    /// rather than hiding behind a canned title.
    @Test func ourOwnProseLeadsWithItsFirstSentence() {
        let e = classify("Saved. It\u{2019}ll take effect next time you connect Work VPN.")
        #expect(e.title == "Saved")
        #expect(e.explanation.contains("next time you connect"))
    }

    @Test func managedConfigurationIsNotAOnePasswordProblem() {
        let e = classify("This connection\u{2019}s settings are locked by your organization.")
        #expect(e.category == .configuration)
        #expect(!e.canRetry)
        #expect(!e.steps.isEmpty)
    }

    @Test func offlineOffersNetworkSettings() {
        let e = classify("The Internet connection appears to be offline.")
        #expect(e.category == .network)
        #expect(e.action == .networkSettings)
    }

    // MARK: - Invariants

    @Test(arguments: [
        "", " ", "\n", "x", "error initializing client", "1Password",
        "Error Domain=X Code=-1", "connection refused",
        "1password: desktop app connection channel is closed",
        "The VPN did not respond",
    ])
    func neverEmptyTitleOrSteps(_ message: String) {
        let e = classify(message)
        #expect(!e.title.trimmingCharacters(in: .whitespaces).isEmpty)
        #expect(!e.steps.isEmpty)
        #expect(e.steps.allSatisfy { !$0.text.trimmingCharacters(in: .whitespaces).isEmpty })
        #expect(!e.symbol.isEmpty)
    }

    @Test func technicalDetailAlwaysPreservesTheOriginal() {
        let raw = "some unrecognised failure from a subsystem"
        #expect(classify(raw).technicalDetail == raw)
    }

    // MARK: - Redaction

    @Test func knownSecretsAreStrippedFromTheDetail() {
        let e = UserFacingError.classify(
            message: "auth rejected for hunter2trombone at 09:31",
            secrets: ["hunter2trombone"])
        #expect(!e.technicalDetail.contains("hunter2trombone"))
    }

    @Test func secretShapedKeyValuePairsAreStripped() {
        let detail = UserFacingError.redact(
            "request failed: password=hunter2 token: abc123def otp = 123456")
        #expect(!detail.contains("hunter2"))
        #expect(!detail.contains("abc123def"))
        #expect(detail.contains("password"))   // the key stays; the value doesn't
    }

    @Test func oneTimeCodeShapedNumbersAreStripped() {
        let detail = UserFacingError.redact("rejected code 483920 on port 1197")
        #expect(!detail.contains("483920"))
        #expect(detail.contains("1197"))       // a port is not a one-time code
    }

    @Test func hugeDetailIsTruncated() {
        let detail = UserFacingError.redact(String(repeating: "a", count: 5000))
        #expect(detail.count <= 2001)
    }
}
