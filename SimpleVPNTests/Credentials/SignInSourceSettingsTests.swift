// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceSettingsTests.swift
//  The per-vendor configuration surface, pinned in three parts:
//
//   1. VALUE VERSUS SUGGESTION. This project shipped, once, the bug where
//      `TextField("example", text:)` made the example the field's TITLE — so it
//      rendered where the value goes and VoiceOver read it as the field's NAME. 26
//      sites were fixed. A pre-filled DETECTED path is the same bug with higher
//      stakes: if it can appear as a value, nobody can tell a setting they made
//      from a guess we made, and "reset to detected" stops meaning anything. So the
//      distinction is a pure function (`VendorFieldPresentation`) and these tests
//      assert every clause of it — including that what VoiceOver hears SAYS which
//      one it is, since grey-versus-black is not available to a screen reader.
//
//   2. ENABLE/DISABLE IS ONE SWITCH WITH NO HALF STATE. Off means not offered AND
//      not hinted. The trap is specific: with only the chooser filtered, switching
//      Keeper off would MOVE it to the "other password apps on this Mac" list —
//      still advertised, in a worse place.
//
//   3. MDM. An administrator can allow, forbid and pin. A locked row is visibly
//      locked and says why; it never silently reverts, which reads as a bug in this
//      app rather than as policy.
//
//  Everything here runs against an isolated `UserDefaults` suite and injected
//  facts: no vendor app, no keychain, no /Applications.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Value versus suggestion

struct VendorFieldPresentationTests {

    private var keeperField: VendorConfigField {
        SignInSourceSettings.fields(for: .keeper)[0]
    }

    /// Always `.ok` — these tests are about presentation, not about the filesystem.
    private func alwaysOK(_ path: String) -> VendorFieldValidation { .ok }

    // MARK: Nothing set

    /// THE BUG, asserted directly: with nothing set, the detected path must NOT be
    /// the field's value. It is a placeholder, and the field is empty.
    @Test func aDetectedPathIsNeverTheFieldsValue() {
        let shown = VendorFieldPresentation.make(
            field: keeperField, setValue: "", detected: "/opt/homebrew/bin/keeper",
            pinned: nil, validate: alwaysOK)

        #expect(shown.value.isEmpty,
                "a detected path must never be written into the field's value")
        #expect(!shown.isSet)
        #expect(shown.prompt == "/opt/homebrew/bin/keeper",
                "the suggestion belongs in the placeholder and nowhere else")
        #expect(shown.detectedPath == "/opt/homebrew/bin/keeper")
        // …and SimpleVPN really does use it, which is why showing it at all is
        // honest rather than decorative.
        #expect(shown.effectivePath == "/opt/homebrew/bin/keeper")
    }

    /// What VoiceOver hears must SAY that nothing is set — the visual cue (grey
    /// placeholder text) does not reach a screen reader at all, so if the spoken
    /// value were silent or just the path, a VoiceOver user could not tell a
    /// suggestion from a setting.
    @Test func voiceOverIsToldWhenAPathIsMerelySuggested() {
        let shown = VendorFieldPresentation.make(
            field: keeperField, setValue: "", detected: "/opt/homebrew/bin/keeper",
            pinned: nil, validate: alwaysOK)

        #expect(shown.accessibilityValue.contains("Not set"))
        #expect(shown.accessibilityValue.contains("SimpleVPN uses the one it found"))
        #expect(shown.accessibilityValue.contains("/opt/homebrew/bin/keeper"))
    }

    /// Nothing set and nothing found: the placeholder falls back to the EXAMPLE, and
    /// the spoken value says there is no detection rather than implying one.
    @Test func withNoDetectionThePlaceholderIsTheExample() {
        let shown = VendorFieldPresentation.make(
            field: keeperField, setValue: "", detected: nil, pinned: nil, validate: alwaysOK)

        #expect(shown.value.isEmpty)
        #expect(shown.prompt == keeperField.example)
        #expect(shown.effectivePath == nil)
        #expect(shown.accessibilityValue.contains("hasn\u{2019}t found one"))
        #expect(!shown.accessibilityValue.contains(keeperField.example),
                "the example is a placeholder, not something to read out as a value")
    }

    // MARK: Something set

    /// A committed value IS the value, and the spoken form is the path plus its
    /// state — never the words "not set".
    @Test func aSetPathIsTheValueAndReadsAsOne() {
        let shown = VendorFieldPresentation.make(
            field: keeperField, setValue: "/Users/me/venv/bin/keeper",
            detected: "/opt/homebrew/bin/keeper", pinned: nil,
            validate: { _ in .sanctioned })

        #expect(shown.value == "/Users/me/venv/bin/keeper")
        #expect(shown.isSet)
        #expect(shown.effectivePath == "/Users/me/venv/bin/keeper")
        #expect(shown.accessibilityValue.hasPrefix("/Users/me/venv/bin/keeper"))
        #expect(!shown.accessibilityValue.contains("Not set"))
        // The detection is still remembered — that is what makes a reset possible —
        // but it is not the value and not the placeholder.
        #expect(shown.detectedPath == "/opt/homebrew/bin/keeper")
        #expect(shown.prompt == keeperField.example)
    }

    /// Whitespace around a typed path is not a value of its own.
    @Test func surroundingWhitespaceIsNotAValue() {
        let blank = VendorFieldPresentation.make(
            field: keeperField, setValue: "   ", detected: "/opt/homebrew/bin/keeper",
            pinned: nil, validate: alwaysOK)
        #expect(!blank.isSet)
        #expect(blank.value.isEmpty)

        let padded = VendorFieldPresentation.make(
            field: keeperField, setValue: "  /opt/homebrew/bin/keeper  ", detected: nil,
            pinned: nil, validate: alwaysOK)
        #expect(padded.value == "/opt/homebrew/bin/keeper")
    }

    // MARK: Reset

    /// "Use what SimpleVPN found" is offered exactly when it would change something.
    @Test func resetIsOfferedOnlyWhenItWouldChangeSomething() {
        let differs = VendorFieldPresentation.make(
            field: keeperField, setValue: "/Users/me/venv/bin/keeper",
            detected: "/opt/homebrew/bin/keeper", pinned: nil, validate: alwaysOK)
        #expect(differs.canResetToDetected)

        let same = VendorFieldPresentation.make(
            field: keeperField, setValue: "/opt/homebrew/bin/keeper",
            detected: "/opt/homebrew/bin/keeper", pinned: nil, validate: alwaysOK)
        #expect(!same.canResetToDetected)

        let nothingFound = VendorFieldPresentation.make(
            field: keeperField, setValue: "/Users/me/venv/bin/keeper",
            detected: nil, pinned: nil, validate: alwaysOK)
        #expect(!nothingFound.canResetToDetected)
    }

    // MARK: Pinned by policy

    /// A pinned path is shown AS the value, marked as the organization's, and cannot
    /// be reset. Showing the user's stale value while silently running the pinned one
    /// is the silent-revert failure that makes policy read as a bug.
    @Test func aPinnedPathIsShownAsTheValueAndSaysWhose() {
        let shown = VendorFieldPresentation.make(
            field: keeperField, setValue: "/Users/me/venv/bin/keeper",
            detected: "/opt/homebrew/bin/keeper", pinned: "/opt/corp/bin/keeper",
            validate: alwaysOK)

        #expect(shown.value == "/opt/corp/bin/keeper")
        #expect(shown.isSet)
        #expect(shown.isLockedByPolicy)
        #expect(shown.effectivePath == "/opt/corp/bin/keeper")
        #expect(shown.accessibilityValue.contains("Set by your organization"))
        #expect(!shown.canResetToDetected)
    }

    // MARK: Validation wording

    /// The escape hatch must not read as an error. "Outside the folders we search"
    /// is a statement about our own caution, and the user has just made the decision
    /// that resolves it.
    @Test func anExplicitPathOutsideTheAllowListIsNotAProblem() {
        #expect(!VendorFieldValidation.sanctioned.isProblem)
        #expect(!VendorFieldValidation.sanctioned.sentence.lowercased().contains("problem"))
        #expect(VendorFieldValidation.sanctioned.sentence.contains("because you chose it"))
    }

    /// A world-writable directory IS a problem, and its sentence says what to do
    /// rather than just refusing.
    @Test func aWorldWritableDirectoryReadsAsAProblemWithAWayOut() {
        let validation = VendorFieldValidation.unsafeDirectory
        #expect(validation.isProblem)
        #expect(validation.sentence.hasPrefix("Problem:"))
        #expect(validation.sentence.contains("Move the program"))
    }

    /// "Not set" is not a problem — it is the default, and most people will leave it
    /// that way.
    @Test func notSetIsNotAProblem() {
        #expect(!VendorFieldValidation.notSet(detected: nil).isProblem)
        #expect(!VendorFieldValidation.notSet(detected: "/x").isProblem)
    }

    /// Every fault names itself as one, so the visible label and the spoken value
    /// both announce their role (Docs/Accessibility.md rule 5).
    @Test func everyFaultSaysProblem() {
        for validation: VendorFieldValidation in [
            .notAbsolute, .missing, .notExecutable, .unsafeDirectory, .notASocket, .badEndpoint,
        ] {
            #expect(validation.isProblem)
            #expect(validation.sentence.hasPrefix("Problem:"), "\(validation) doesn't announce itself")
        }
    }
}

// MARK: - The store, over an isolated defaults suite

@MainActor
struct SignInSourceSettingsStoreTests {

    /// A defaults domain of its own per test, removed afterwards — nothing here
    /// touches the real com.bragi0.SimpleVPN domain.
    private func store() -> (SignInSourceSettingsStore, UserDefaults) {
        let suite = "SignInSourceSettingsTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        return (SignInSourceSettingsStore(store: defaults), defaults)
    }

    @Test func vendorsAreOnByDefault() {
        let (settings, _) = store()
        for vendor in LocalVaultVendor.allCases {
            #expect(settings.isEnabled(vendor))
        }
        #expect(settings.disabledVendors.isEmpty)
    }

    /// The scan defaults ON — it is local-only, needs no macOS permission, and every
    /// sign-in source is inert without it.
    @Test func theScanIsOnByDefault() {
        let (settings, _) = store()
        #expect(settings.discoveryEnabled)
    }

    @Test func switchingAVendorOffIsRemembered() {
        let (settings, _) = store()
        settings.setEnabled(false, for: .keeper)
        #expect(!settings.isEnabled(.keeper))
        #expect(settings.disabledVendors == [.keeper])
        #expect(settings.isEnabled(.onePassword), "one vendor's switch must not move another's")
    }

    /// The pane writes the key `LocalToolRunner` resolves. Not a copy of it — the
    /// same key, so there is one notion of "the path the user set" rather than a
    /// settings mirror somebody has to keep in step.
    @Test func theToolPathSettingIsTheKeyTheRunnerReads() {
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        #expect(field.defaultsKey == "signin.tool.keeper.path")
        #expect(field.defaultsKey == SignInSourceSettings.toolPathKey("keeper"))
    }

    @Test func clearingAFieldRemovesItRatherThanStoringEmptiness() {
        let (settings, defaults) = store()
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        settings.setValue("/opt/homebrew/bin/keeper", for: field)
        #expect(settings.value(for: field) == "/opt/homebrew/bin/keeper")
        settings.clear(field)
        #expect(settings.value(for: field).isEmpty)
        #expect(defaults.object(forKey: field.defaultsKey) == nil)
    }

    /// A relative path is refused with the reason that matters: a bare name would be
    /// resolved by rules SimpleVPN doesn't control, which is the whole thing the
    /// execution allow-list exists to prevent.
    @Test func aRelativePathIsRejected() {
        let (settings, _) = store()
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        #expect(settings.validate("keeper", field: field) == .notAbsolute)
        #expect(settings.validate("../keeper", field: field) == .notAbsolute)
    }

    @Test func aMissingPathIsReportedAsMissing() {
        let (settings, _) = store()
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        #expect(settings.validate("/nowhere/at/all/keeper", field: field) == .missing)
    }

    /// A real, safe executable outside the searched folders validates as SANCTIONED
    /// — the escape hatch working, reported as such.
    @Test func aSafeExecutableOutsideTheSearchedFoldersIsSanctioned() throws {
        let (settings, _) = store()
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("creds-settings-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        chmod(dir.path, 0o755)
        let path = dir.appendingPathComponent("keeper").path
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, 0o755)

        #expect(settings.validate(path, field: field) == .sanctioned)
    }

    /// …and a world-writable directory is refused even here, where the user has
    /// typed the path themselves.
    @Test func aWorldWritableDirectoryIsRefusedEvenWhenTyped() throws {
        let (settings, _) = store()
        let field = SignInSourceSettings.fields(for: .keeper)[0]
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("creds-open-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        chmod(dir.path, 0o777)
        let path = dir.appendingPathComponent("keeper").path
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, 0o755)

        #expect(settings.validate(path, field: field) == .unsafeDirectory)
    }

    /// A socket field wants a socket, and says so when handed an ordinary file —
    /// "there's no connection point there" rather than a generic failure.
    @Test func aSocketFieldRejectsAnOrdinaryFile() throws {
        let (settings, _) = store()
        let field = SignInSourceSettings.fields(for: .keePassXC)[0]
        let file = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("creds-socket-\(UUID().uuidString)")
        try Data("x".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        #expect(settings.validate(file.path, field: field) == .notASocket)
    }

    /// 1Password has no path to get wrong: its channel is the app's own signed IPC.
    /// A field here would be a question with no answer.
    @Test func onePasswordHasNoPathField() {
        #expect(SignInSourceSettings.fields(for: .onePassword).isEmpty)
    }

    /// `ykman` gets its row HERE, writing the SAME `signin.tool.ykman.path` key the
    /// security-key feed already resolves through `LocalToolRunner`. One place answers
    /// "where is that tool" — a second override mechanism per feed is how a user ends
    /// up with two fields for one path, one of which does nothing.
    @Test func aToolThatIsNotAPasswordAppStillGetsItsPathRowHere() throws {
        let field = try #require(SignInSourceSettings.standaloneToolFields
            .first { $0.kind.detectionTool == "ykman" })
        #expect(field.vendor == nil)
        #expect(field.defaultsKey == "signin.tool.ykman.path")
        #expect(field.defaultsKey == SignInSourceSettings.toolPathKey("ykman"))
        #expect(field.settingID == "creds.ykman.tool-path")
        // …and it is in the catalog, so it is searchable and documented like the rest.
        #expect(CredentialSourceSettings.all.contains { $0.id == field.settingID })
        // It belongs to no vendor, so no vendor's switch can hide it.
        #expect(CredentialSourceSettings.vendor(forSettingID: field.settingID) == nil)
    }

    /// Every field, vendor-owned or not, names its owner — the specs' display names
    /// are built from it, so a blank one ships a row called " location".
    @Test func everyFieldNamesItsOwner() {
        for field in SignInSourceSettings.allFields {
            #expect(!field.ownerTitle.isEmpty, "\(field.settingID) has no owner name")
            if let vendor = field.vendor {
                #expect(field.ownerTitle == vendor.displayTitle)
            }
        }
    }

    /// Every field's setting id is in the `creds.` namespace and has a spec (and so
    /// a manual anchor, and so a working help button).
    @Test func everyFieldHasASpecInTheCredsNamespace() {
        for field in SignInSourceSettings.allFields {
            #expect(field.settingID.hasPrefix("creds."))
            #expect(CredentialSourceSettings.all.contains { $0.id == field.settingID },
                    "\(field.settingID) has no spec")
        }
    }

    /// The generated catalog really covers every vendor, so adding one cannot ship a
    /// vendor with no switch.
    @Test func everyVendorHasAnEnableSpec() {
        for vendor in LocalVaultVendor.allCases {
            let id = SignInSourceSettings.enabledSettingID(vendor)
            #expect(CredentialSourceSettings.all.contains { $0.id == id },
                    "\(vendor) has no enable setting")
            #expect(CredentialSourceSettings.vendor(forSettingID: id) == vendor)
        }
    }

    /// Slugs are the MDM/CLI/manual-anchor contract: unique, lowercase, and free of
    /// anything that would break an anchor.
    @Test func vendorSlugsAreStableIdentifiers() {
        let slugs = LocalVaultVendor.allCases.map(\.settingSlug)
        #expect(Set(slugs).count == slugs.count)
        for slug in slugs {
            #expect(slug == slug.lowercased())
            #expect(!slug.contains("."))
            #expect(!slug.isEmpty)
            #expect(LocalVaultVendor.vendor(withSlug: slug) != nil)
        }
    }

    /// Every `creds.*` setting is in the Sign-In group — they are all about how you
    /// identify yourself, which is that group's definition.
    @Test func everyCredsSettingIsInTheSignInGroup() {
        for spec in CredentialSourceSettings.all {
            #expect(spec.canonicalGroup == .signIn, "\(spec.id) isn't in Sign-In")
        }
    }

    /// The surface is registered app-level: it belongs to no VPN kind, which is what
    /// stops a global search hit from being routed into an editor with no such row.
    @Test func theCredentialSourcesSurfaceIsAppLevel() {
        #expect(SettingSurface.credentialSources.isAppLevel)
        #expect(SettingSurface.credentialSources.kinds.isEmpty)
        #expect(SettingSurface.owning("creds.keeper.tool-path") == .credentialSources)
        #expect(SettingsRouter.isAppLevel(settingID: "creds.keeper.tool-path"))
        // …and a VPN setting is NOT app-level, so the branch really discriminates.
        #expect(!SettingsRouter.isAppLevel(settingID: "wg.mtu"))
    }

    /// Global search finds them. "Searchable" was a requirement, and registering the
    /// surface is what makes it true.
    @Test func credentialSettingsAreFoundByGlobalSearch() {
        let search = SettingsSearch.global()
        search.query = "password apps"
        #expect(search.matches.contains { $0.id == SignInSourceSettings.discoverySettingID })
    }
}

// MARK: - MDM

@MainActor
struct ManagedSignInSourcePolicyTests {

    /// `objectIsForced` cannot be faked in a test suite (only a real managed
    /// preference is forced), so what is asserted here is everything ADJACENT to it:
    /// that an unmanaged Mac reads as unmanaged, that the key names are the
    /// documented ones, and that the summary wording is right. The forced-value
    /// reading itself is the same one-line mechanism `ManagedPolicy` has shipped
    /// with since M7.
    @Test func anUnmanagedMacIsFree() {
        let defaults = UserDefaults(suiteName: "ManagedSignInSourcePolicyTests.\(UUID().uuidString)")!
        #expect(!ManagedSignInSourcePolicy.isManaged(defaults))
        #expect(ManagedSignInSourcePolicy.allowed(defaults) == nil)
        #expect(ManagedSignInSourcePolicy.forbidden(defaults).isEmpty)
        #expect(ManagedSignInSourcePolicy.pinnedPaths(defaults).isEmpty)
        #expect(!ManagedSignInSourcePolicy.discoveryForbidden(defaults))
        #expect(ManagedSignInSourcePolicy.activeSummary(defaults).isEmpty)
        for vendor in LocalVaultVendor.allCases {
            #expect(ManagedSignInSourcePolicy.decision(for: vendor, store: defaults) == nil)
        }
    }

    /// A local default with a policy key's name is NOT policy. Reading it as such
    /// would let anyone lock themselves out of their own settings with `defaults
    /// write`.
    @Test func aLocalDefaultIsNotPolicy() {
        let defaults = UserDefaults(suiteName: "ManagedSignInSourcePolicyTests.\(UUID().uuidString)")!
        defaults.set(["keeper"], forKey: ManagedSignInSourcePolicy.forbiddenKey)
        defaults.set(true, forKey: ManagedSignInSourcePolicy.disableDiscoveryKey)
        #expect(ManagedSignInSourcePolicy.forbidden(defaults).isEmpty)
        #expect(!ManagedSignInSourcePolicy.discoveryForbidden(defaults))
        #expect(!ManagedSignInSourcePolicy.isManaged(defaults))
    }

    /// The key names are the ones Docs/MDM.md documents. An administrator's payload
    /// is a contract; renaming a key silently is how a fleet stops being managed.
    @Test func theKeyNamesAreTheDocumentedOnes() {
        #expect(ManagedSignInSourcePolicy.allowedKey == "SignInSourcesAllowed")
        #expect(ManagedSignInSourcePolicy.forbiddenKey == "SignInSourcesForbidden")
        #expect(ManagedSignInSourcePolicy.pinnedPathsKey == "SignInSourceToolPaths")
        #expect(ManagedSignInSourcePolicy.disableDiscoveryKey == "DisableCredentialToolDiscovery")
    }
}
