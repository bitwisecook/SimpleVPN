// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthAbstractionTests.swift
//  THE UNIFIED AUTHENTICATION ABSTRACTION, pinned.
//
//  Twelve sources and four non-vault mechanisms were built first, deliberately, so the
//  abstraction could be derived from what they converged on rather than guessed at.
//  These tests hold the things that consolidation is only worth doing if they stay
//  true:
//
//   1. THE ON-DISK CONTRACT DID NOT MOVE. `AuthKind` replaced `CredentialField` AND
//      `CredentialRole`, and every profile's stored `fieldMap` is keyed on those raw
//      values. A renamed case is fine; a renamed RAW VALUE silently unmaps somebody's
//      1Password fields, and nothing would say so.
//   2. THREE AXES, NOT FOUR. Delivery is an attribute of a (kind, source) pair, and the
//      three mechanisms that never hand over bytes are expressible — which was the
//      whole architectural reason for a plan rather than a secret.
//   3. `.unchecked` CAN SAY WHY. The Passbolt finding: for a server-shaped instance
//      `.unchecked` is the honest ceiling for ever, not a to-do, and the old bare case
//      could not tell that from 1Password's "the check is owed".
//   4. EVERY BLOCK HAS A LEVEL. Failure attribution follows the three configuration
//      levels plus the fourth locus, so a caller sends somebody to the right screen
//      without matching on a vendor or a string.
//   5. THE CAPABILITY TABLE CANNOT DRIFT FROM THE CODE. `AuthSourceCatalog` reads each
//      vault's transports and cardinality from the adapter that owns them, and one test
//      walks the lot.
//
//  Nothing here needs a vault, a token, a security key or a network.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - Axis 1: kind

struct AuthKindTests {

    /// THE RAW VALUES ARE AN ON-DISK CONTRACT and this test is the only thing standing
    /// between a tidy-up and somebody's 1Password field mapping quietly unmapping
    /// itself. `CredentialSource.fieldMap` is persisted in `providerConfiguration`
    /// keyed by exactly these strings.
    @Test func rawValuesAreTheStoredFieldMapKeys() {
        #expect(AuthKind.username.rawValue == "username")
        #expect(AuthKind.password.rawValue == "password")
        // "otp" and NOT "verificationCode", even though every user-facing string says
        // "verification code" (house glossary). The blob on disk wins over the prose.
        #expect(AuthKind.otp.rawValue == "otp")
        #expect(AuthKind.passkey.rawValue == "passkey")
        #expect(AuthKind.certificate.rawValue == "certificate")
        #expect(AuthKind.privateKeyPassphrase.rawValue == "privateKeyPassphrase")
        #expect(AuthKind.sshKey.rawValue == "sshKey")
    }

    /// The union of the two enums it replaced, and no case lost on the way. Four from
    /// `CredentialField`, seven from `CredentialRole` (overlapping by three), plus the
    /// two possession kinds the non-vault mechanisms needed.
    @Test func everyKindTheTwoOldEnumsHad() {
        let names = Set(AuthKind.allCases.map(\.rawValue))
        for old in ["username", "password", "otp", "passkey", "certificate",
                    "privateKeyPassphrase", "sshKey"] {
            #expect(names.contains(old), "lost \(old) from the old palette")
        }
        #expect(names.contains("keyInAgent"))
        #expect(names.contains("tokenPIN"))
    }

    /// A username is shown on screen and must not be redacted; everything else is a
    /// secret, including the two that are only ever NAMED.
    @Test func onlyTheUsernameIsNotASecret() {
        #expect(!AuthKind.username.isSecret)
        for kind in AuthKind.allCases where kind != .username {
            #expect(kind.isSecret, "\(kind.rawValue) must be treated as a secret")
        }
    }

    /// SPENT BY THE ATTEMPT, not by success — the property that decides what must never
    /// be silently retried. A one-time code is gone whether or not it worked; a PIN
    /// spends a retry counter and three wrong ones block the token.
    @Test func onlyTheSpendableKindsAreSpendable() {
        #expect(AuthKind.otp.isSpentByAttempt)
        #expect(AuthKind.tokenPIN.isSpentByAttempt)
        #expect(!AuthKind.password.isSpentByAttempt)
        #expect(!AuthKind.keyInAgent.isSpentByAttempt)
    }

    /// Copy lives on the app side and every kind has some — a slot with no name is a
    /// row VoiceOver reads as nothing.
    @Test func everyKindIsNamedAndSymbolised() {
        for kind in AuthKind.allCases {
            #expect(!kind.title.isEmpty)
            #expect(!kind.hint.isEmpty)
            #expect(!kind.systemImage.isEmpty)
        }
        // House glossary: "verification code", never "OTP" or "one-time password".
        #expect(AuthKind.otp.title == "Verification code")
    }
}

// MARK: - Axis 2: transport

struct AuthTransportTests {

    /// The five vault shapes kept their raw values: the diagnostic report prints them,
    /// so they are part of what a maintainer reads in a submitted issue.
    @Test func theVaultTransportRawValuesSurvived() {
        for name in ["signedIPC", "appSocket", "cli", "localDaemon", "file"] {
            #expect(AuthTransport.allCases.map(\.rawValue).contains(name))
        }
    }

    /// The four shapes that were always there and had no name, which is exactly why
    /// their mechanisms sat outside the seam.
    @Test func theNonVaultShapesAreNamed() {
        for shape: AuthTransport in [.osKeychain, .osAutoFill, .agent, .hardware] {
            #expect(AuthTransport.allCases.contains(shape))
        }
    }

    /// COST, not side effects. A socket, a file and the OS answer for free; a CLI, a
    /// loopback daemon, a vendor SDK helper and `ykman` all cost a process — and a
    /// process is what can put somebody else's dialog on screen.
    @Test func livenessCostIsTheSubprocessQuestion() {
        #expect(!AuthTransport.appSocket.livenessNeedsSubprocess)
        #expect(!AuthTransport.file.livenessNeedsSubprocess)
        #expect(!AuthTransport.osKeychain.livenessNeedsSubprocess)
        #expect(!AuthTransport.agent.livenessNeedsSubprocess)
        #expect(AuthTransport.cli.livenessNeedsSubprocess)
        #expect(AuthTransport.localDaemon.livenessNeedsSubprocess)
        #expect(AuthTransport.signedIPC.livenessNeedsSubprocess)
        #expect(AuthTransport.hardware.livenessNeedsSubprocess)
    }
}

// MARK: - The Passbolt misfit #1: `.unchecked` can say why

struct AuthProbeCeilingTests {

    /// THE DISTINCTION THE BARE `.unchecked` COULD NOT MAKE. One of these is a to-do
    /// and three of them are permanent, and a row that promises "SimpleVPN checks this
    /// when you pick it" is telling the truth about exactly one.
    @Test func onlyTheOwedCheckWillEverHappen() {
        #expect(AuthProbeCeiling.checkOwedOnUse.willBeProbed)
        #expect(!AuthProbeCeiling.wouldSignInToServer.willBeProbed)
        #expect(!AuthProbeCeiling.wouldPromptTheUser.willBeProbed)
        #expect(!AuthProbeCeiling.wouldSpendSingleUseCode.willBeProbed)
    }

    /// The server case is the FOURTH LOCUS doing its job: what cannot be established is
    /// the channel to the instance, which is neither the tool nor the address nor the
    /// entry.
    @Test func theServerCeilingSitsAtTheReachLocus() {
        #expect(AuthProbeCeiling.wouldSignInToServer.locus == .reach)
        #expect(AuthProbeCeiling.wouldPromptTheUser.locus == .instance)
        #expect(AuthProbeCeiling.checkOwedOnUse.locus == .transport)
    }

    /// Every ceiling has a sentence, and none of them is the wrong one. The specific
    /// regression: "SimpleVPN checks this when you pick it" was said about a server
    /// nothing would ever check.
    @Test func everyCeilingHasAnHonestSentence() {
        for ceiling in AuthProbeCeiling.allCases {
            #expect(!ceiling.fallbackNote.isEmpty)
        }
        #expect(AuthProbeCeiling.checkOwedOnUse.fallbackNote.contains("checks this when you pick it"))
        // The server sentence must NOT promise a check.
        let server = AuthProbeCeiling.wouldSignInToServer.fallbackNote
        #expect(!server.contains("checks this when you pick it"))
        #expect(server.lowercased().contains("sign in"))
    }

    /// PASSBOLT, the case that named the problem: a server-shaped instance whose tool is
    /// present and whose passphrase is available reaches `.unchecked` and NEVER
    /// `.ready`, and the ceiling now says the reason out loud.
    @Test func passboltDeclaresTheServerCeiling() async {
        let adapter = PassboltVaultAdapter()
        // `deepScan` adds nothing, on purpose: the only deeper check is a real login.
        let deep = await adapter.deepScan(quick: .unchecked(.wouldSignInToServer))
        #expect(deep == .unchecked(.wouldSignInToServer))
        guard case .unchecked(let ceiling) = deep else {
            Issue.record("a server-shaped instance must stay unchecked")
            return
        }
        #expect(!ceiling.willBeProbed)
        #expect(ceiling.locus == .reach)
    }

    /// AND A ROW IS NEVER SILENTLY "READY TO USE" WHEN IT IS UNPROVEN. The old code did
    /// `if let note = copy.uncheckedNote { … }`, so a vendor without its own wording —
    /// the KeePass file adapter has none — fell through with the state left at `.ready`.
    /// An unproven source announced itself to VoiceOver as ready.
    @Test func anUncheckedRowAlwaysSaysItIsUnchecked() {
        for vendor in LocalVaultVendor.allCases {
            let option = SignInSourceCatalog.vaultOption(
                vendor, availability: .unchecked(.checkOwedOnUse))
            guard let option else {
                Issue.record("\(vendor.rawValue) offered no row for an unchecked state")
                continue
            }
            guard case .unchecked(let note) = option.state else {
                Issue.record("\(vendor.rawValue) rendered an unchecked state as \(option.state)")
                continue
            }
            #expect(!note.isEmpty)
            // And the sentence VoiceOver reads must not be the ready one.
            #expect(option.accessibilityStateValue != "Ready to use")
        }
    }
}

// MARK: - The Passbolt misfit #2: the fourth locus

struct AuthLocusTests {

    /// Three of the four ARE the configuration levels. The fourth deliberately has no
    /// level, and that nil is the finding: a `.reach` problem has no field anybody can
    /// go and correct, which is what makes it different from the other three.
    @Test func threeLociAreLevelsAndTheFourthIsNot() {
        #expect(AuthLocus.transport.configLevel == .transport)
        #expect(AuthLocus.instance.configLevel == .instance)
        #expect(AuthLocus.entry.configLevel == .perVPN)
        #expect(AuthLocus.reach.configLevel == nil)
    }

    /// Every locus can say where to go, and the reach one honestly says "nowhere in
    /// SimpleVPN" rather than sending somebody to a screen where nothing would help.
    @Test func everyLocusNamesItsFix() {
        for locus in AuthLocus.allCases {
            #expect(!locus.whereToFixIt.isEmpty)
        }
        #expect(AuthLocus.reach.whereToFixIt.contains("nothing in SimpleVPN"))
        #expect(AuthLocus.transport.whereToFixIt.contains("Sign-In Sources"))
    }

    /// EVERY BLOCK IS ATTRIBUTED, and the switch is exhaustive so a new one has to
    /// decide. The specific pairs that matter: a missing binary is level 1 and a moved
    /// database is level 2 — different fixes, different owners.
    @Test func everyBlockHasALevel() {
        #expect(LocalVaultBlock.toolMissing.locus == .transport)
        #expect(LocalVaultBlock.toolOutsideAllowList.locus == .transport)
        #expect(LocalVaultBlock.notSignedIn.locus == .transport)
        #expect(LocalVaultBlock.integrationOff.locus == .transport)
        #expect(LocalVaultBlock.planExcludesTool.locus == .transport)
        #expect(LocalVaultBlock.vaultFileMissing.locus == .instance)
        #expect(LocalVaultBlock.noVaultFile.locus == .instance)
        #expect(LocalVaultBlock.noServerConfigured.locus == .instance)
        #expect(LocalVaultBlock.vaultLocked.locus == .instance)
        #expect(LocalVaultBlock.vaultPasswordRejected.locus == .instance)
    }

    /// The one block whose fix is NOT on this Mac. Telling somebody to change something
    /// here would send them round a loop for ever: the answer is a subscription.
    @Test func onlyThePlanBlockIsFixedElsewhere() {
        #expect(!LocalVaultBlock.planExcludesTool.fixIsOnThisMac)
        #expect(LocalVaultBlock.toolMissing.fixIsOnThisMac)
        #expect(LocalVaultBlock.vaultLocked.fixIsOnThisMac)
    }
}

// MARK: - The Passbolt misfit #3: shared copy must not leak one vendor's shape

struct AuthSharedCopyTests {

    /// SHARED COPY MUST NOT SAY "FILE" OR "DATABASE" ABOUT SOMETHING THAT IS NEITHER.
    ///
    /// The instance-shaped block sentences were true of every multi-instance vendor
    /// until one of them stopped being a file. A password store is a FOLDER and a
    /// Passbolt instance is a SERVER, so "the database file is not where SimpleVPN was
    /// told to look" describes a thing that does not exist — and a diagnostic report
    /// saying it sends a maintainer looking for a file.
    @Test func theReportUsesEachVendorsOwnNoun() {
        let store = DiagnosticReportInventory.stateWords(
            .blocked(.noVaultFile), vendor: .passwordStore)
        #expect(store.contains("store"))
        #expect(!store.contains("database"))

        let kdbx = DiagnosticReportInventory.stateWords(
            .blocked(.noVaultFile), vendor: .keePassFile)
        #expect(kdbx.contains("database"))

        let moved = DiagnosticReportInventory.stateWords(
            .blocked(.vaultFileMissing), vendor: .passwordStore)
        #expect(moved.contains("store"))
        #expect(!moved.contains("database"))
    }

    /// Every vendor has its own noun, its own plural and its own removal reassurance,
    /// and none of them is the word "instance" — which is the word this whole vocabulary
    /// exists to keep off the screen.
    @Test func everyVendorOwnsItsWords() {
        for vendor in LocalVaultVendor.allCases {
            #expect(!vendor.instanceNoun.isEmpty)
            #expect(!vendor.instanceNounPlural.isEmpty)
            #expect(!vendor.instanceRemovalReassurance.isEmpty)
            #expect(!vendor.instanceNoun.contains("instance"))
            #expect(!vendor.instanceNounPlural.contains("instance"))
        }
        // The three multi-instance vendors are the three whose nouns differ, and that
        // difference is exactly what the shared copy used to flatten.
        #expect(LocalVaultVendor.keePassFile.instanceNoun == "database")
        #expect(LocalVaultVendor.passwordStore.instanceNoun == "store")
        #expect(LocalVaultVendor.passbolt.instanceNoun == "server")
    }

    /// A SERVER'S REMOVAL REASSURANCE MUST NOT MENTION A FILE. "The file itself is left
    /// exactly as it is" reads, about a server, as though SimpleVPN could have changed
    /// somebody's server — a much worse implication than the vagueness it was avoiding.
    @Test func removingAServerDoesNotTalkAboutAFile() {
        let warning = SignInSourceSteps.removalWarning(
            vendor: .passbolt, name: "Work", usedBy: ["GR Lab"])
        #expect(!warning.lowercased().contains("file"))
        #expect(warning.contains("server"))
        // And the file-shaped vendor still says "file", because for it that is true.
        #expect(SignInSourceSteps.removalWarning(
            vendor: .keePassFile, name: "Work", usedBy: []).contains("file"))
    }
}

// MARK: - Failure classification (checklist question 10)

struct AuthCauseTests {

    /// The five the checklist asked every source to distinguish, plus the two that kept
    /// coming up in the answers.
    @Test func theCausesCoverWhatTwelveFeedsNeeded() {
        let names = Set(AuthCause.allCases.map(\.rawValue))
        for expected in ["sourceUnavailable", "wrongCredential", "userCancelled",
                         "serverRejected", "timedOut", "notFound", "ambiguous"] {
            #expect(names.contains(expected))
        }
    }

    /// HONEST AMBIGUITIES, RECORDED RATHER THAN HIDDEN. A gateway answering AUTH_FAILED
    /// does not say whether the password was wrong or the account was disabled; a vendor
    /// dialog that closes does not say whether the user cancelled or ran out of time.
    @Test func theTwoRealAmbiguitiesAreDeclared() {
        #expect(AuthCause.wrongCredential.isAmbiguousWith(.serverRejected))
        #expect(AuthCause.serverRejected.isAmbiguousWith(.wrongCredential))
        #expect(AuthCause.userCancelled.isAmbiguousWith(.timedOut))
        // And things that are NOT ambiguous stay unambiguous — "your vault isn't
        // running" and "your password is wrong" are opposite advice.
        #expect(!AuthCause.sourceUnavailable.isAmbiguousWith(.wrongCredential))
        #expect(!AuthCause.notFound.isAmbiguousWith(.ambiguous))
    }

    /// THE UNATTENDED RETRY GATE. Retrying a wrong password achieves nothing; retrying
    /// after a one-time code was spent is worse than nothing. Only a timeout is worth
    /// another go without the user changing something.
    @Test func onlyATimeoutIsWorthRetryingUnattended() {
        #expect(AuthCause.timedOut.isWorthRetryingUnattended)
        for cause in AuthCause.allCases where cause != .timedOut {
            #expect(!cause.isWorthRetryingUnattended, "\(cause.rawValue) must not auto-retry")
        }
    }

    /// ONE translation of a cancellation, at the seam, instead of every caller
    /// re-recognising `CancellationError` — which the biometric store, the vendor
    /// helpers and the security-key capture all throw when the user says no.
    @Test func cancellationIsRecognisedOnce() {
        let failure = AuthFailure.from(CancellationError(), locus: .entry)
        #expect(failure.cause == .userCancelled)
        #expect(failure.isCancellation)
        #expect(failure.locus == .entry)
    }

    /// An `AuthFailure` passed through `from(_:locus:)` keeps its own attribution rather
    /// than being flattened to "source unavailable at whatever level the caller
    /// guessed".
    @Test func anAlreadyAttributedFailureIsNotReattributed() {
        let original = AuthFailure(locus: .reach, cause: .serverRejected, detail: "no")
        #expect(AuthFailure.from(original, locus: .transport) == original)
    }

    /// The sentence names where to go — except for `.reach`, which has nowhere.
    @Test func theSentenceNamesTheScreenExceptForReach() {
        let entry = AuthFailure(locus: .entry, cause: .notFound)
        #expect(entry.sentence.contains("sign-in settings"))
        let reach = AuthFailure(locus: .reach, cause: .timedOut)
        #expect(!reach.sentence.contains("Fix it in"))
    }
}

// MARK: - Axis 3 and the plan

struct AuthPlanTests {

    /// THREE SHAPES, and the delivery is readable without unpacking the payload.
    @Test func aPlanKnowsItsDelivery() {
        #expect(AuthPlan.value(RawCredentials()).delivery == .value)
        #expect(AuthPlan.possession(.agentSocket(path: "/tmp/x")).delivery == .possession)
        #expect(AuthPlan.typedByDevice(
            AuthCaptureTicket(mechanism: .yubicoOTP, delivery: .codeOnly, wait: 30))
            .delivery == .typedByDevice)
    }

    /// A POSSESSION IS A NAME AND HAS NOTHING TO LEAK. Every case's loggable form is a
    /// description rather than the value, so a caller cannot interpolate the payload
    /// into a log by reaching for the obvious thing.
    @Test func aPossessionHasNothingSecretToLog() {
        let socket = AuthPossession.agentSocket(path: "/Users/someone/.ssh/agent.sock")
        #expect(!socket.loggableSummary.contains("someone"))
        let uri = AuthPossession.pkcs11Object(uri: "pkcs11:token=Foo;object=Bar", module: nil)
        #expect(!uri.loggableSummary.contains("Foo"))
        #expect(AuthPossession.securityKeySlot(slot: 2, serial: "123").loggableSummary
            .contains("slot 2"))
    }

    /// FOCUS IS DERIVED, NEVER PASSED IN. A security key types into whatever field has
    /// focus, so two call sites disagreeing about which field is about to receive a
    /// one-time credential is the failure this removes.
    @Test func theCaptureTicketDerivesItsFocusFromTheDelivery() {
        #expect(AuthCaptureTicket(mechanism: .yubicoOTP, delivery: .appendedToPassword,
                                  wait: 30).focus == .password)
        #expect(AuthCaptureTicket(mechanism: .yubicoOTP, delivery: .separateField,
                                  wait: 30).focus == .otp)
        #expect(AuthCaptureTicket(mechanism: .yubicoOTP, delivery: .codeOnly,
                                  wait: 30).focus == .otp)
    }

    /// Only the two mechanisms that really are keystrokes need the focus guarantee; the
    /// two that are computed and read back do not.
    @Test func onlyTheTypingMechanismsAreKeystrokeCaptures() {
        #expect(AuthCaptureTicket(mechanism: .yubicoOTP, delivery: .codeOnly,
                                  wait: 30).isKeystrokeCapture)
        #expect(AuthCaptureTicket(mechanism: .staticPassword, delivery: .codeOnly,
                                  wait: 30).isKeystrokeCapture)
        #expect(!AuthCaptureTicket(mechanism: .oathCode, delivery: .codeOnly,
                                   wait: 30).isKeystrokeCapture)
        #expect(!AuthCaptureTicket(mechanism: .challengeResponse, delivery: .codeOnly,
                                   wait: 30).isKeystrokeCapture)
    }
}

// MARK: - The capability table

@MainActor
struct AuthSourceCatalogTests {

    /// EVERY MECHANISM IS DECLARED: three that need no vendor, twelve vaults, and the
    /// four non-vault ones (the keychain counts twice — with and without Touch ID — for
    /// a reason stated in the catalog).
    @Test func everySourceIsInTheTable() {
        let ids = Set(AuthSourceCatalog.all.map(\.id))
        #expect(ids.contains(.typed))
        #expect(ids.contains(.appKeychain(biometric: false)))
        #expect(ids.contains(.appKeychain(biometric: true)))
        #expect(ids.contains(.systemAutoFill))
        #expect(ids.contains(.sshAgent))
        #expect(ids.contains(.pkcs11Token))
        #expect(ids.contains(.securityKey))
        for vendor in LocalVaultVendor.allCases {
            #expect(ids.contains(.vault(vendor)), "\(vendor.rawValue) is not in the table")
        }
        // TEN VAULT VENDORS, and the count is load-bearing: the vendor list is CLOSED,
        // and an eleventh is a real ongoing cost (a wire format that changes under us, a
        // manual page, a maturity row nobody can clear, one more arm in every exhaustive
        // switch) that needs a reason beyond "it exists". Twelve `CredentialSourceKind`
        // cases = these ten plus `.manual` and `.applePasswords`, which have no vendor.
        #expect(LocalVaultVendor.allCases.count == 10)
        #expect(CredentialSourceKind.allCases.count == 12)
    }

    /// THE TABLE CANNOT DRIFT FROM THE CODE. Each vault row reads its transports and
    /// cardinality from the adapter that owns them, so a vendor cannot be described here
    /// with a channel it does not use.
    @Test func vaultRowsAgreeWithTheirAdapters() {
        for adapter in LocalVaultRegistry.all {
            let row = AuthSourceCatalog.vault(adapter.vendor)
            #expect(row.transports == adapter.transports)
            #expect(row.cardinality == adapter.vendor.cardinality)
            // Every vault serves a username and a password — that is what makes it one.
            #expect(row.supplies.contains(.username))
            #expect(row.supplies.contains(.password))
            #expect(row.delivery == .value)
        }
    }

    /// `suppliesOTP` IS THE ONE PLACE THE PROMISE IS MADE. The table reads it rather
    /// than restating it, because restating it is how a promise ends up true in one file
    /// and false in another — and being wrong costs a failed sign-in AND a burned code.
    @Test func theCodePromiseIsReadNotRestated() {
        for adapter in LocalVaultRegistry.all {
            let row = AuthSourceCatalog.vault(adapter.vendor)
            #expect(row.supplies.contains(.otp) == adapter.storedKind.suppliesOTP,
                    "\(adapter.vendor.rawValue) disagrees with its own suppliesOTP")
        }
    }

    /// APPLE PASSWORDS WITHHOLDS, and that is a first-class set rather than an omission.
    /// It stores verification codes and exposes none of them to other apps — by design,
    /// for ever. "Absent from supplies" would read as an oversight.
    @Test func applePasswordsWithholdsTheCodeRatherThanLackingIt() {
        let row = AuthSourceCatalog.applePasswords
        #expect(row.withholds.contains(.otp))
        #expect(!row.supplies.contains(.otp))
        #expect(row.transports == [.osAutoFill])
    }

    /// LASTPASS IS THE ONLY PERMANENT WITHHOLDING among the vaults. Its own tool's JSON
    /// has no field for a code and there is no `totp` subcommand — arithmetic, not
    /// caution. Everything else is "unproven" or "unknowable in advance", and neither of
    /// those is withholding.
    @Test func onlyLastPassWithholdsAmongTheVaults() {
        for vendor in LocalVaultVendor.allCases {
            let withholds = AuthSourceCatalog.vault(vendor).withholds
            #expect(withholds.contains(.otp) == (vendor == .lastPass),
                    "\(vendor.rawValue) withholding claim is wrong")
        }
    }

    /// THE THREE MECHANISMS THAT NEVER HAND OVER BYTES — the architectural reason the
    /// unified call returns a plan. Each PROVES rather than SUPPLIES the thing that
    /// matters, and none of them is `.value`.
    @Test func theNonValueMechanismsProveRatherThanSupply() {
        let agent = AuthSourceCatalog.sshAgent
        #expect(agent.proves == [.keyInAgent])
        #expect(agent.supplies.isEmpty)
        #expect(agent.delivery == .possession)
        #expect(agent.transports == [.agent])

        let token = AuthSourceCatalog.pkcs11Token
        // The certificate is a NAME the engine resolves; the PIN is the one thing we do
        // hand over, and only ever on stdin.
        #expect(token.proves == [.certificate])
        #expect(token.supplies == [.tokenPIN])
        #expect(token.delivery == .possession)

        let key = AuthSourceCatalog.securityKey
        #expect(key.delivery == .typedByDevice)
        #expect(key.transports == [.hardware])
        // A deeper probe would spend a code to find out whether codes work.
        #expect(key.probeCeiling == .wouldSpendSingleUseCode)
        #expect(key.probeCeiling?.willBeProbed == false)
    }

    /// The one source that fetches nothing, and says so: macOS fills our fields and we
    /// never read anything. `fetchesAnything` being false is what stops a caller
    /// treating it as a provider that failed.
    @Test func systemAutoFillFetchesNothingItselfBeyondTheFileKeychain() {
        // The narrow `SecItem` path over the FILE keychain is real, which is why
        // username and password are supplied — but never a code.
        #expect(AuthSourceCatalog.applePasswords.supplies == [.username, .password])
        #expect(AuthSourceCatalog.typed.supplies.contains(.tokenPIN))
        #expect(AuthSourceCatalog.keychain.supplies.contains(.otp))
    }

    /// A stored per-VPN kind resolves to its descriptor — except `.manual`, which is
    /// ambiguous ON PURPOSE: it means typing OR the keychain OR Touch ID, and only the
    /// controller knows which.
    @Test func storedKindsMapToDescriptorsExceptManual() {
        #expect(AuthSourceCatalog.descriptor(forStored: .manual) == nil)
        #expect(AuthSourceCatalog.descriptor(forStored: .applePasswords)?.id == .systemAutoFill)
        #expect(AuthSourceCatalog.descriptor(forStored: .onePassword)?.id
            == .vault(.onePassword))
        #expect(AuthSourceCatalog.descriptor(forStored: .passbolt)?.id == .vault(.passbolt))
    }
}

// MARK: - Satisfaction: the levels, in order

@MainActor
struct AuthSatisfactionTests {

    private func availability() -> SignInSourceAvailability {
        SignInSourceAvailability(
            settings: SignInSourceSettingsStore(
                store: UserDefaults(suiteName: "AuthSatisfactionTests.\(UUID().uuidString)")!))
    }

    /// A VPN set to type it each time is `.typedInstead(.byChoice)` — not broken, not
    /// unavailable, and not something to warn about. All three of those used to be
    /// indistinguishable from a Bool that said "no".
    @Test func typingIsNotAFailure() {
        let satisfaction = availability().satisfaction(for: CredentialSource())
        #expect(satisfaction == .typedInstead(.byChoice))
        #expect(!satisfaction.needsAttention)
        #expect(satisfaction.locus == nil)
    }

    /// A password app chosen with NOTHING LINKED is one picker away from working, and
    /// that is a different sentence from a broken app.
    @Test func nothingLinkedIsItsOwnState() {
        var source = CredentialSource()
        source.kind = .applePasswords
        #expect(availability().satisfaction(for: source) == .typedInstead(.nothingLinked))
        source.reference = "vpn.example.com"
        #expect(availability().satisfaction(for: source) == .unproven(.checkOwedOnUse))
    }

    /// THE ORDER IS THE DIAGNOSIS. On a Mac with no vendor tool at all, a profile that
    /// also names no instance and no entry is reported at LEVEL 1 — because telling
    /// somebody to choose a database they cannot read yet is the wrong sentence.
    @Test func levelOneIsReportedBeforeLevelTwo() {
        var source = CredentialSource()
        source.kind = .keeper
        source.reference = "Work/VPN"
        let satisfaction = availability().satisfaction(for: source)
        // Nothing Keeper is installed in a fresh defaults suite on this machine.
        #expect(satisfaction == .broken(locus: .transport, block: .toolMissing))
        #expect(satisfaction.needsAttention)
        #expect(!satisfaction.connectsUnattended)
    }

    /// UNPROVEN CONNECTS. Refusing to try would make every unproven source permanently
    /// unusable — including all eleven the development machine cannot verify.
    @Test func unprovenStillConnects() {
        #expect(AuthSatisfaction.unproven(.checkOwedOnUse).connectsUnattended)
        #expect(AuthSatisfaction.unproven(.wouldSignInToServer).connectsUnattended)
        #expect(AuthSatisfaction.ready.connectsUnattended)
        #expect(!AuthSatisfaction.broken(locus: .instance, block: .noVaultFile)
            .connectsUnattended)
    }

    /// Only the keychain can connect with nothing typed among the typed-instead reasons
    /// — it already HAS the answer. The other three need a human at the keyboard.
    @Test func onlyTheKeychainConnectsAmongTheTypedReasons() {
        #expect(AuthTypedReason.savedInKeychain.connectsUnattended)
        for reason in AuthTypedReason.allCases where reason != .savedInKeychain {
            #expect(!reason.connectsUnattended)
        }
    }
}
