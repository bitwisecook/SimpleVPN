// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordPreflightTests.swift
//  The setup check's state machine, pinned against what the live SDK really
//  does (no SDK is called here — every input is the exact string or typed kind
//  that came back from one):
//    • the verbatim client-init failure ("desktop app connection channel is
//      closed…") means the "Integrate with 1Password SDKs" checkbox is OFF, and
//      must produce the walkthrough rather than a generic failure;
//    • "Account not found" means the integration IS working — only the name is
//      missing — so it must never be shown as a problem with 1Password itself;
//    • a dismissed prompt and a silent call both mean "1Password is asking you
//      something", which is the only outcome pointing at another app;
//    • the verified flag: set by a success, cleared by a real call that says the
//      integration is off (people do turn it back off), and honoured so the
//      walkthrough is a one-time event.
//

import Foundation
import Testing
@testable import SimpleVPN

struct OnePasswordPreflightTests {

    /// Verbatim from the live SDK: what a client-init against a 1Password with
    /// the SDK integration switched off comes back with.
    private static let channelClosed =
        "error initializing client: desktop app connection channel is closed. "
        + "Make sure Settings > Developer > Integrate with other apps is enabled, "
        + "or contact 1Password support"

    private func scratchDefaults(_ name: String = #function) -> UserDefaults {
        let suite = "OnePasswordPreflightTests.\(name)"
        UserDefaults.standard.removePersistentDomain(forName: suite)
        return UserDefaults(suiteName: suite)!
    }

    // MARK: - Outcome mapping

    /// The reported failure, arriving the way it really does (kind "other",
    /// carrying the SDK's prose), is the setting being off — not a mystery.
    @Test func channelClosedMeansTheIntegrationIsOff() {
        #expect(OnePasswordPreflight.outcome(for: OnePasswordNativeError.other(Self.channelClosed))
                == .integrationOff)
        // Same conclusion when the helper already named the kind.
        #expect(OnePasswordPreflight.outcome(for: OnePasswordNativeError.integrationDisabled)
                == .integrationOff)
        // And when it arrives as some other error type carrying the same words.
        struct Wrapped: LocalizedError {
            let message: String
            var errorDescription: String? { message }
        }
        #expect(OnePasswordPreflight.outcome(for: Wrapped(message: Self.channelClosed))
                == .integrationOff)
    }

    /// The integration is fine; 1Password just doesn't know which account to
    /// ask. This is a nudge, and mapping it to anything else sends people to
    /// re-tick a setting that was never wrong.
    @Test func accountNotFoundMeansTheIntegrationWorks() {
        let error = OnePasswordNativeError.accountNotFound(account: "", detail: "Account not found")
        #expect(OnePasswordPreflight.outcome(for: error) == .needsAccount)
        #expect(OnePasswordPreflight.outcome(
            for: OnePasswordNativeError(kind: "accountNotFound", message: "Account not found"))
                == .needsAccount)
    }

    /// Both ways of learning that 1Password is asking the user something.
    @Test func dismissedPromptAndSilenceBothMeanWaiting() {
        #expect(OnePasswordPreflight.outcome(for: OnePasswordNativeError.userCancelled)
                == .waitingForApproval)
        #expect(OnePasswordPreflight.outcome(for: OnePasswordPreflight.Timeout())
                == .waitingForApproval)
    }

    /// A call that never answers times out rather than hanging the card — which
    /// is what turns into "1Password is asking for your approval".
    @Test func aSilentCallTimesOut() async {
        do {
            _ = try await OnePasswordPreflight.withTimeout(.milliseconds(20)) {
                try await Task.sleep(for: .seconds(5))
                return 1
            }
            Issue.record("a call that never answers must time out")
        } catch {
            #expect(OnePasswordPreflight.outcome(for: error) == .waitingForApproval)
        }
    }

    /// The timeout must not fire for a call that answers.
    @Test func anAnswerBeatsTheClock() async throws {
        let value = try await OnePasswordPreflight.withTimeout(.seconds(5)) { 42 }
        #expect(value == 42)
    }

    @Test func missingAppIsItsOwnState() {
        #expect(OnePasswordPreflight.outcome(for: OnePasswordNativeError.appNotInstalled)
                == .notInstalled)
    }

    /// Anything else still lands somewhere actionable: the classified failure,
    /// so the card can show real advice for a problem this file never met.
    @Test func unfamiliarFailuresKeepTheirAdvice() throws {
        let state = OnePasswordPreflight.outcome(for: OnePasswordNativeError.appNotRunning)
        guard case .failed(let error) = state else {
            Issue.record("expected a classified failure, got \(state)")
            return
        }
        #expect(!error.title.isEmpty)
        #expect(!error.steps.isEmpty)
        #expect(OnePasswordPreflight.headline(for: state) == error.title)
    }

    // MARK: - The verified flag

    @Test func successIsRememberedAndSkipsTheWalkthrough() {
        let store = scratchDefaults()
        #expect(!OnePasswordPreflight.isVerified(in: store))
        #expect(OnePasswordPreflight.shouldRun(verified: false))

        OnePasswordPreflight.remember(.ready(vaults: []), in: store)
        #expect(OnePasswordPreflight.isVerified(in: store))
        #expect(!OnePasswordPreflight.shouldRun(verified: true))
    }

    /// The point of clearing: someone turns the setting off again, and the
    /// walkthrough has to come back rather than insisting all is well.
    @Test func integrationOffClearsTheRememberedSuccess() {
        let store = scratchDefaults()
        OnePasswordPreflight.remember(.ready(vaults: []), in: store)
        OnePasswordPreflight.remember(.integrationOff, in: store)
        #expect(!OnePasswordPreflight.isVerified(in: store))
    }

    /// Same rule from a REAL call (a connect, a browse) — the other way the app
    /// learns the setting was turned back off.
    @Test func aFailedRealCallReArmsTheWalkthrough() {
        let store = scratchDefaults()
        OnePasswordPreflight.markVerified(in: store)
        OnePasswordPreflight.noteFailure(OnePasswordNativeError.other(Self.channelClosed), in: store)
        #expect(!OnePasswordPreflight.isVerified(in: store))
    }

    /// …and only for that failure. A missing account, a missing item or a
    /// dismissed prompt say nothing about the setting, and forgetting on those
    /// would put the walkthrough in front of people who don't need it.
    @Test func otherFailuresLeaveTheRememberedSuccessAlone() {
        let store = scratchDefaults()
        OnePasswordPreflight.markVerified(in: store)
        let harmless: [OnePasswordNativeError] = [
            .accountNotFound(account: "Work", detail: "Account not found"),
            .itemNotFound("no such item"),
            .userCancelled,
            .rateLimited,
        ]
        for error in harmless {
            OnePasswordPreflight.noteFailure(error, in: store)
            #expect(OnePasswordPreflight.isVerified(in: store), "cleared by \(error)")
        }
    }

    // NOTE: `run` itself is deliberately not exercised here — it spawns the
    // helper and would talk to whatever 1Password is on the machine running the
    // tests. Everything it decides (the mapping, the timeout, the flag) is
    // tested above through the pieces it is assembled from.

    // MARK: - What the card says

    /// The walkthrough must name the setting 1Password has TODAY, never the one
    /// its own message suggests, and must end by pointing back at the button.
    @Test func theWalkthroughNamesTodaysSetting() {
        let steps = OnePasswordPreflight.steps(for: .integrationOff)
        #expect(steps.count == 4)
        let text = steps.map { $0.text + ($0.note ?? "") }.joined(separator: "\n")
        #expect(text.contains("Integrate with 1Password SDKs"))
        #expect(!text.contains("Integrate with other apps"))
        #expect(text.contains("Developer Integrations"))
        #expect(text.contains("Check Again"))
        #expect(!OnePasswordPreflight.headline(for: .integrationOff).isEmpty)
    }

    /// Every state a person can be shown says something, and only the two that
    /// need no instructions have no steps.
    @Test func everyStateSaysSomething() {
        let states: [OnePasswordPreflight.State] = [
            .notInstalled, .integrationOff, .needsAccount, .waitingForApproval, .ready(vaults: []),
        ]
        for state in states {
            #expect(!OnePasswordPreflight.headline(for: state).isEmpty)
            #expect(!OnePasswordPreflight.symbol(for: state).isEmpty)
        }
        #expect(OnePasswordPreflight.steps(for: .ready(vaults: [])).isEmpty)
        // The account ask is one shared sentence, not a second wording.
        #expect(OnePasswordPreflight.steps(for: .needsAccount).isEmpty)
        #expect(OnePasswordPreflight.headline(for: .needsAccount) == OnePasswordPreflight.accountNudge)
    }
}
