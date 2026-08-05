// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceInstanceTests.swift
//  THE THREE LEVELS, pinned — and the migration pinned FIRST, because it is the
//  part that can lose somebody's setup.
//
//  The conflation being fixed: "which vault" used to live in level 1's
//  single-valued app defaults (`signin.keepassfile.database`, one key file, one
//  slot), and the per-VPN reference held no instance id — so a profile could not
//  say whether it meant the work database or the personal one.
//
//  What these tests hold:
//
//   1. MIGRATION IS LOSSLESS. A fixture of the CURRENT on-disk shape becomes
//      instance #1 with a name somebody will recognise, the legacy keys are left
//      exactly where they are (an administrator may be pinning one), and every
//      existing profile — whose blob has no instance id at all — still resolves to
//      that same database.
//   2. NOTHING IS EVER SILENTLY THE WRONG VAULT. A profile naming an instance that
//      has gone is `.chosenIsGone`, not "the first one instead".
//   3. CARDINALITY IS DECLARED, per vendor, and a singular vendor gets no
//      meaningless list.
//   4. LEVEL 3 STILL CARRIES NO SECRET, with the new field included in the grep.
//   5. AVAILABILITY IS PER INSTANCE: one database missing while another is ready.
//
//  Everything runs against an isolated `UserDefaults` suite: no KeePassXC, no
//  database, no /Applications.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Migration, from a fixture of what is really on disk today

@MainActor
struct SourceInstanceMigrationTests {

    /// EXACTLY the keys a shipped build writes today. Written raw, as a fixture,
    /// rather than through any new API — the point is to migrate what is out there.
    private func legacyDomain(database: String? = "/Users/me/Documents/Passwords.kdbx",
                              keyFile: String? = nil,
                              slot: String? = nil) -> UserDefaults {
        let defaults = UserDefaults(suiteName: "SourceInstanceMigrationTests.\(UUID().uuidString)")!
        if let database { defaults.set(database, forKey: "signin.keepassfile.database") }
        if let keyFile { defaults.set(keyFile, forKey: "signin.keepassfile.keyfile") }
        if let slot { defaults.set(slot, forKey: "signin.keepassfile.securitykey-slot") }
        return defaults
    }

    /// The keys in the fixture are the ones the shipped build declares — asserted,
    /// so a rename of a defaults key cannot silently make this fixture fictional.
    @Test func theFixtureUsesTheKeysTheShippedBuildWrites() {
        #expect(SignInSourceSettings.keePassDatabaseKey == "signin.keepassfile.database")
        #expect(SignInSourceSettings.keePassKeyFileKey == "signin.keepassfile.keyfile")
        #expect(SignInSourceSettings.keePassSecurityKeySlotKey
                == "signin.keepassfile.securitykey-slot")
    }

    /// THE MIGRATION. The old single-valued settings become one named instance, and
    /// nothing is lost: path, key file and slot all arrive.
    @Test func theSingleValuedSettingsBecomeInstanceOne() throws {
        let defaults = legacyDomain(keyFile: "/Users/me/Documents/Passwords.keyx", slot: "2")
        let settings = SignInSourceSettingsStore(store: defaults)

        let instances = settings.instances(for: .keePassFile)
        #expect(instances.count == 1)
        let first = try #require(instances.first)
        #expect(first.values["database"] == "/Users/me/Documents/Passwords.kdbx")
        #expect(first.values["key-file"] == "/Users/me/Documents/Passwords.keyx")
        #expect(first.values["security-key-slot"] == "2")
    }

    /// A NAME somebody will recognise, taken from the file they chose. A path is not
    /// a name, so the folder is dropped and the extension with it.
    @Test func theMigratedInstanceIsNamedAfterTheirFile() {
        let settings = SignInSourceSettingsStore(store: legacyDomain())
        #expect(settings.instances(for: .keePassFile).first?.name == "Passwords")
        // …and the pure function behind it, for the shapes a real Mac produces.
        #expect(SourceInstanceMigration.defaultName(
            vendor: .keePassFile, values: ["database": "/Volumes/Share/Team Vault.kdbx"])
                == "Team Vault")
        // Nothing file-shaped set at all: the vendor's own title, never an empty row.
        #expect(SourceInstanceMigration.defaultName(
            vendor: .keePassFile, values: ["security-key-slot": "1"])
                == LocalVaultVendor.keePassFile.displayTitle)
    }

    /// The id is OPAQUE and is not the path — a database that moves is the same
    /// database, and a profile keyed on its path would silently point at nothing.
    @Test func theInstanceIdIsOpaqueAndIsNotAPath() throws {
        let settings = SignInSourceSettingsStore(store: legacyDomain())
        let id = try #require(settings.instances(for: .keePassFile).first?.id)
        #expect(!id.rawValue.contains("/"))
        #expect(!id.rawValue.contains("Passwords"))
        #expect(id.isWellFormed)
        // An id with a dot in it would change the meaning of a defaults key.
        #expect(!SourceInstanceID(rawValue: "a.b").isWellFormed)
        #expect(!SourceInstanceID(rawValue: "").isWellFormed)
    }

    /// LOSSLESS IN ONE DIRECTION: the legacy keys are read and LEFT. Deleting them
    /// would throw away the very key an existing MDM payload pins, and a downgrade
    /// would find nothing.
    @Test func theLegacyKeysAreLeftExactlyWhereTheyWere() {
        let defaults = legacyDomain(slot: "1")
        _ = SignInSourceSettingsStore(store: defaults)
        #expect(defaults.string(forKey: SignInSourceSettings.keePassDatabaseKey)
                == "/Users/me/Documents/Passwords.kdbx")
        #expect(defaults.string(forKey: SignInSourceSettings.keePassSecurityKeySlotKey) == "1")
    }

    /// Migration runs ONCE. A value the user has since cleared must not be
    /// resurrected by a second pass over the legacy keys.
    @Test func migrationIsIdempotentAndDoesNotResurrectARemovedInstance() throws {
        let defaults = legacyDomain()
        let settings = SignInSourceSettingsStore(store: defaults)
        let id = try #require(settings.instances(for: .keePassFile).first?.id)
        settings.instanceStore.remove(id, for: .keePassFile)
        #expect(settings.instances(for: .keePassFile).isEmpty)

        // A second store over the same domain (a relaunch) must not bring it back.
        let relaunched = SignInSourceSettingsStore(store: defaults)
        #expect(relaunched.instances(for: .keePassFile).isEmpty)
    }

    /// A Mac with nothing configured gets no instances — and no phantom row.
    @Test func aMacWithNothingConfiguredHasNoInstances() {
        let defaults = UserDefaults(suiteName: "SourceInstanceMigrationTests.\(UUID().uuidString)")!
        let settings = SignInSourceSettingsStore(store: defaults)
        #expect(settings.instances(for: .keePassFile).isEmpty)
        #expect(settings.instanceStore.defaultInstance(for: .keePassFile) == nil)
    }

    /// EVERY EXISTING PROFILE BINDS TO IT. A blob written before instances existed
    /// carries no instance id, and must resolve to the migrated database rather than
    /// to "choose one".
    @Test func aProfileWrittenBeforeInstancesExistedBindsToTheMigratedOne() throws {
        let settings = SignInSourceSettingsStore(store: legacyDomain())
        let instances = settings.instances(for: .keePassFile)
        let legacyBlob = Data(
            #"{"kind":"keePassFile","reference":"VPN/Work","account":"alice","fieldMap":{}}"#.utf8)
        let source = CredentialSource.decode(from: legacyBlob)
        #expect(source.instanceID.isEmpty)

        let resolution = SourceInstanceResolver.resolve(
            source.selection, vendor: .keePassFile, instances: instances)
        #expect(resolution.instance?.id == instances.first?.id)
        #expect(resolution.isUsable)
        // …and the whole configuration path agrees, which is what a connect reads.
        let configuration = KeePassFileConfiguration.current(store: settings)
        #expect(configuration.databasePath == "/Users/me/Documents/Passwords.kdbx")
        #expect(configuration.name == "Passwords")
    }

    /// …and adding a second database later does NOT displace it: the migrated one
    /// stays first, so an unmigrated profile keeps reading the database it always
    /// read.
    @Test func addingASecondDatabaseDoesNotMoveTheFirst() throws {
        let settings = SignInSourceSettingsStore(store: legacyDomain())
        let migrated = try #require(settings.instances(for: .keePassFile).first)
        settings.instanceStore.add(named: "Personal", for: .keePassFile)
        let after = settings.instances(for: .keePassFile)
        #expect(after.count == 2)
        #expect(after.first?.id == migrated.id)
        #expect(SourceInstanceResolver.resolve(SignInSourceSelection(kind: .keePassFile),
                                              vendor: .keePassFile, instances: after)
                .instance?.id == migrated.id)
    }

    /// A ROUND TRIP through the on-disk shape: write, read back through a fresh
    /// store over the same domain, and get the same instances with the same ids.
    @Test func instancesRoundTripThroughTheDefaultsDomain() throws {
        let defaults = legacyDomain()
        let settings = SignInSourceSettingsStore(store: defaults)
        let added = try #require(settings.instanceStore.add(named: "Personal", for: .keePassFile))
        let field = try #require(SignInSourceSettings.instanceFields(for: .keePassFile)
            .first { if case .vaultFile = $0.kind { return true } else { return false } })
        settings.setValue("/Users/me/Personal.kdbx", for: field,
                          instance: SourceInstance(id: added.id, vendor: .keePassFile,
                                                   name: "Personal"))

        let relaunched = SignInSourceSettingsStore(store: defaults)
        let back = relaunched.instances(for: .keePassFile)
        #expect(back.map(\.id) == settings.instances(for: .keePassFile).map(\.id))
        #expect(back.last?.name == "Personal")
        #expect(back.last?.values["database"] == "/Users/me/Personal.kdbx")
        #expect(back.first?.values["database"] == "/Users/me/Documents/Passwords.kdbx")
    }

    /// A malformed list on disk is dropped rather than allowed to name a defaults
    /// key — an id with a dot in it would change what key its values live under.
    @Test func aMalformedStoredInstanceIsDropped() {
        let defaults = UserDefaults(suiteName: "SourceInstanceMigrationTests.\(UUID().uuidString)")!
        defaults.set(Data(#"[{"id":"a.b","name":"Bad"},{"id":"good","name":"Fine"}]"#.utf8),
                     forKey: SignInSourceSettings.instanceListKey(.keePassFile))
        let settings = SignInSourceSettingsStore(store: defaults)
        #expect(settings.instances(for: .keePassFile).map(\.name) == ["Fine"])
    }
}

// MARK: - Which instance a profile means

@MainActor
struct SourceInstanceResolutionTests {

    private func instances(_ names: [String]) -> [SourceInstance] {
        names.map { SourceInstance(id: .fresh(), vendor: .keePassFile, name: $0) }
    }

    /// A singular vendor is `.sole`: there is nothing to name and nothing to get
    /// wrong.
    @Test(arguments: LocalVaultVendor.allCases.filter { !$0.cardinality.allowsSeveral })
    func aSingularVendorIsSole(_ vendor: LocalVaultVendor) {
        let resolution = SourceInstanceResolver.resolve(
            SignInSourceSelection(kind: .manual, instance: SourceInstanceID(rawValue: "x")),
            vendor: vendor, instances: [])
        #expect(resolution == .sole)
        #expect(resolution.isUsable)
        #expect(resolution.sentence(vendor: vendor).contains(vendor.displayTitle))
    }

    /// Nothing set up is "choose a database" — an enablement state, not a crash and
    /// not a guess.
    @Test func nothingConfiguredIsAClearChooseOne() {
        let resolution = SourceInstanceResolver.resolve(
            SignInSourceSelection(kind: .keePassFile), vendor: .keePassFile, instances: [])
        #expect(resolution == .noneConfigured)
        #expect(!resolution.isUsable)
        #expect(resolution.sentence(vendor: .keePassFile).contains("database"))
    }

    /// A profile naming a database that has GONE is never quietly served a different
    /// one. Reading the wrong vault because a list changed order is the worst
    /// outcome available here.
    @Test func aVanishedInstanceIsNeverSilentlyReplaced() {
        let list = instances(["Work", "Personal"])
        let stale = SourceInstanceID(rawValue: "no-longer-here")
        let resolution = SourceInstanceResolver.resolve(
            SignInSourceSelection(kind: .keePassFile, instance: stale),
            vendor: .keePassFile, instances: list)
        #expect(resolution == .chosenIsGone(stale))
        #expect(!resolution.isUsable)
        #expect(resolution.instance == nil)
        #expect(resolution.sentence(vendor: .keePassFile).contains("Choose"))
    }

    @Test func anExistingNamedInstanceWins() throws {
        let list = instances(["Work", "Personal"])
        let wanted = try #require(list.last)
        let resolution = SourceInstanceResolver.resolve(
            SignInSourceSelection(kind: .keePassFile, instance: wanted.id),
            vendor: .keePassFile, instances: list)
        #expect(resolution.instance?.name == "Personal")
        #expect(resolution.sentence(vendor: .keePassFile).contains("Personal"))
    }
}

// MARK: - Cardinality is declared, with a reason

struct SourceCardinalityTests {

    /// Pinned per vendor. Each of these is a decision recorded in
    /// `LocalVaultVendor.cardinality`'s own documentation — a new vendor has to make
    /// it, because this test names every case.
    @Test func everyVendorDeclaresItsCardinality() {
        #expect(LocalVaultVendor.onePassword.cardinality == .single)
        #expect(LocalVaultVendor.keePassXC.cardinality == .single)
        #expect(LocalVaultVendor.keeper.cardinality == .single)
        #expect(LocalVaultVendor.bitwarden.cardinality == .single)
        // The case that named the problem: a `.kdbx` is a file, and "work" and
        // "personal" are entirely ordinary.
        #expect(LocalVaultVendor.keePassFile.cardinality == .multiple)
    }

    /// A singular vendor is not given a meaningless list to manage.
    @Test func aSingularVendorHasNoInstanceFieldsAndNoList() {
        for vendor in LocalVaultVendor.allCases where !vendor.cardinality.allowsSeveral {
            #expect(SignInSourceSettings.instanceFields(for: vendor).isEmpty,
                    "\(vendor) declares itself singular but has level-2 fields")
        }
    }

    /// …and the multi-instance vendor's fields really are the level-2 ones, with its
    /// tool path staying at level 1 where it belongs (one `keepassxc-cli` on this
    /// Mac, whatever the database).
    @Test func theKeePassFileFieldsSplitAcrossTheRightLevels() {
        let transport = SignInSourceSettings.transportFields(for: .keePassFile).map(\.settingID)
        let instance = SignInSourceSettings.instanceFields(for: .keePassFile).map(\.settingID)
        #expect(transport == ["creds.keepassfile.tool-path"])
        #expect(instance == ["creds.keepassfile.database", "creds.keepassfile.key-file",
                             "creds.keepassfile.security-key-slot"])
        // Every field is at exactly one level, and the two lists together are all of
        // them — a field at no level would be invisible to both surfaces.
        #expect(transport.count + instance.count
                == SignInSourceSettings.fields(for: .keePassFile).count)
    }

    /// The level of a field is a property of its KIND, decided in one exhaustive
    /// switch rather than per declaration.
    @Test func fieldKindsDeclareTheirLevel() {
        #expect(VendorConfigFieldKind.toolBinary(tool: "bw").level == .transport)
        #expect(VendorConfigFieldKind.unixSocket.level == .transport)
        #expect(VendorConfigFieldKind.daemonEndpoint.level == .transport)
        #expect(VendorConfigFieldKind.pkcs11Module.level == .transport)
        #expect(VendorConfigFieldKind.vaultFile(extensions: ["kdbx"]).level == .instance)
        #expect(VendorConfigFieldKind.keyFile.level == .instance)
        #expect(VendorConfigFieldKind.securityKeySlot.level == .instance)
    }

    /// The instance key is the setting id's last component — part of the on-disk
    /// contract, like the id itself.
    @Test func theInstanceKeyIsStable() throws {
        let field = try #require(SignInSourceSettings.instanceFields(for: .keePassFile).first)
        #expect(field.instanceKey == "database")
        #expect(SignInSourceSettings.instanceValueKey(
            .keePassFile, SourceInstanceID(rawValue: "abc"), field)
                == "signin.instance.keepassfile.abc.database")
        #expect(SignInSourceSettings.instanceListKey(.keePassFile) == "signin.instances.keepassfile")
    }
}

// MARK: - Level 3: the profile's own field

struct SignInSourceSelectionTests {

    /// The instance id round-trips, and the blob still carries NOTHING SECRET — the
    /// existing grep, extended to the new field.
    @Test func theStoredSelectionRoundTripsAndCarriesNoSecret() throws {
        var source = CredentialSource()
        source.kind = .keePassFile
        source.reference = "VPN/Work"
        source.account = "alice"
        source.instanceID = "9f8e7d6c-1234-4321-abcd-0123456789ab"

        let blob = try #require(source.encodedBlob())
        let text = String(decoding: blob, as: UTF8.self)
        #expect(CredentialSource.decode(from: blob) == source)
        #expect(CredentialSource.decode(from: blob).instanceID == source.instanceID)
        // An id, an entry path and a username. Nothing that opens anything: not the
        // database password, not a key file's contents, and not even a PATH — a
        // profile must not carry where somebody keeps their passwords either.
        #expect(!text.lowercased().contains("password"))
        #expect(!text.contains("keyfile"))
        #expect(!text.contains(".kdbx"))
        #expect(!text.contains("/Users/"))
    }

    /// The three-level view and the on-disk carrier are the same value seen twice.
    @Test func theSelectionViewIsTheStoredSource() {
        var source = CredentialSource()
        source.selection = SignInSourceSelection(
            kind: .keePassFile, instance: SourceInstanceID(rawValue: "abc"),
            entry: "VPN/Work", account: "alice")
        #expect(source.kind == .keePassFile)
        #expect(source.instanceID == "abc")
        #expect(source.reference == "VPN/Work")
        #expect(source.account == "alice")
        #expect(source.selection.instance == SourceInstanceID(rawValue: "abc"))
        #expect(source.selection.level == .perVPN)
    }

    /// An instance id alone is worth storing — `isDefault` must not treat a source
    /// that names a database as untouched and drop it.
    @Test func anInstanceIdAloneIsNotTheDefaultSource() {
        var source = CredentialSource()
        source.instanceID = "abc"
        #expect(!source.isDefault)
        #expect(CredentialSource.decode(from: source.encodedBlob()).instanceID == "abc")
    }

    /// A blob with no instance id decodes to "the one SimpleVPN set up" rather than
    /// throwing the user's item choice away.
    @Test func aBlobWithoutAnInstanceIdStillDecodes() {
        let decoded = CredentialSource.decode(
            from: Data(#"{"kind":"keePassFile","reference":"VPN/Work"}"#.utf8))
        #expect(decoded.reference == "VPN/Work")
        #expect(decoded.instanceID.isEmpty)
        #expect(decoded.selection.instance == nil)
    }
}

// MARK: - Availability, per instance

@MainActor
struct SourceInstanceAvailabilityTests {

    /// ONE DATABASE MISSING WHILE ANOTHER IS READY — the state the old
    /// single-valued shape could not express at all.
    @Test func oneDatabaseCanBeMissingWhileAnotherIsReady() {
        let work = SourceInstance(id: .fresh(), vendor: .keePassFile, name: "Work")
        let personal = SourceInstance(id: .fresh(), vendor: .keePassFile, name: "Personal")
        var facts = SignInSourceFacts()
        facts.instances = [.keePassFile: [work, personal]]
        facts.vaultInstances = [work.id: .blocked(.vaultFileMissing), personal.id: .ready]
        // The vendor row is the BEST of them, so a ready personal database is still
        // on offer.
        facts.vaults = [.keePassFile: .ready]

        #expect(facts.availability(.keePassFile, instance: work.id) == .blocked(.vaultFileMissing))
        #expect(facts.availability(.keePassFile, instance: personal.id) == .ready)
        #expect(facts.availability(.keePassFile) == .ready)
        // And the four-state model still applies per instance, banners included.
        #expect(!LocalVaultBlock.vaultFileMissing.wantsEnablementBanner)
        #expect(LocalVaultBlock.noVaultFile.wantsEnablementBanner)
    }

    /// The best-of rule, as a rank, so "offered when any vault can answer" is one
    /// comparison rather than a chain of ifs.
    @Test func theRankOrdersUselessToUsable() {
        #expect(LocalVaultAvailability.notInstalled.rank < LocalVaultAvailability.blocked(.noVaultFile).rank)
        #expect(LocalVaultAvailability.blocked(.noVaultFile).rank < LocalVaultAvailability.unchecked.rank)
        #expect(LocalVaultAvailability.unchecked.rank < LocalVaultAvailability.ready.rank)
    }

    /// A switched-off vendor is `.notInstalled` at level 2 as well: off means not
    /// offered ANYWHERE, per instance included.
    @Test func aSwitchedOffVendorIsNotOfferedPerInstanceEither() {
        let work = SourceInstance(id: .fresh(), vendor: .keePassFile, name: "Work")
        var facts = SignInSourceFacts()
        facts.instances = [.keePassFile: [work]]
        facts.vaultInstances = [work.id: .ready]
        facts.vaults = [.keePassFile: .ready]
        facts.disabledVendors = [.keePassFile]
        #expect(facts.availability(.keePassFile, instance: work.id) == .notInstalled)
        // …and the pane can still see past the switch, which is what lets it say
        // "installed, and you switched it off".
        #expect(facts.rawAvailability(.keePassFile, instance: work.id) == .ready)
    }

    /// A singular vendor answers from its vendor row whatever it is asked about.
    @Test func aSingularVendorAnswersFromItsVendorRow() {
        var facts = SignInSourceFacts()
        facts.vaults = [.keeper: .blocked(.notSignedIn)]
        #expect(facts.availability(.keeper, instance: SourceInstanceID(rawValue: "x"))
                == .blocked(.notSignedIn))
    }

    /// THE PROVIDER CARRIES WHICH DATABASE. Without this the profile could name one
    /// and the fetch could read another — the exact failure the instance id exists to
    /// prevent.
    @Test func theProviderBuiltForAProfileCarriesItsDatabase() throws {
        let adapter = KeePassFileVaultAdapter()
        var source = CredentialSource()
        source.kind = .keePassFile
        source.reference = "VPN/Work"
        source.instanceID = "9f8e-personal"
        let provider = try #require(adapter.provider(for: source) as? KeePassFileProvider)
        #expect(provider.entryPath == "VPN/Work")
        #expect(provider.instance == SourceInstanceID(rawValue: "9f8e-personal"))
        // …and a profile that names none asks for the default, not for "any".
        source.instanceID = ""
        let defaulted = try #require(adapter.provider(for: source) as? KeePassFileProvider)
        #expect(defaulted.instance == nil)
    }

    /// A profile naming a vanished database cannot serve — said HERE, before a
    /// connect discovers it.
    @Test func aSourceNamingAVanishedDatabaseCannotServe() {
        let sources = SignInSourceAvailability(
            settings: SignInSourceSettingsStore(
                store: UserDefaults(suiteName: "SourceInstanceAvailabilityTests.\(UUID().uuidString)")!))
        var source = CredentialSource()
        source.kind = .keePassFile
        source.reference = "VPN/Work"
        source.instanceID = "gone"
        #expect(!sources.canServe(source))
    }
}

// MARK: - The two-step reading, and removing a database somebody uses

struct SignInSourceStepsTests {

    /// The chooser asks TWO questions in order, and says so — a flat list of
    /// entries with no mention of which database they are in is the thing this
    /// replaces.
    @Test func theStepsAreNumberedAndNameTheDatabase() {
        #expect(SignInSourceSteps.count == 2)
        let one = SignInSourceSteps.stepOneTitle(vendor: .keePassFile)
        #expect(one.contains("Step 1 of 2"))
        #expect(one.contains("database"))
        let two = SignInSourceSteps.stepTwoTitle(vendor: .keePassFile, instanceName: "Work")
        #expect(two.contains("Step 2 of 2"))
        #expect(two.contains("Work"))
        // With nothing chosen yet, step two still reads as step two rather than
        // pretending a database has been picked.
        #expect(SignInSourceSteps.stepTwoTitle(vendor: .keePassFile, instanceName: nil)
                == "Step 2 of 2: which entry")
        // Never the word "instance" at a user.
        #expect(!one.lowercased().contains("instance"))
        #expect(!two.lowercased().contains("instance"))
    }

    /// What VoiceOver hears carries the step number and what it is waiting for —
    /// the visual numbering is not available to it.
    @Test func eachStepSpeaksItsNumberAndItsState() {
        #expect(SignInSourceSteps.spokenStep(1, of: .keePassFile, chosen: nil)
                == "Step 1 of 2. No database chosen yet.")
        #expect(SignInSourceSteps.spokenStep(1, of: .keePassFile, chosen: "Work")
                == "Step 1 of 2. Work.")
        #expect(SignInSourceSteps.spokenStep(2, of: .keePassFile, chosen: nil)
                .contains("No entry chosen yet"))
    }

    /// REMOVING ONE THAT PROFILES STILL USE WARNS AND NAMES THEM. A silently
    /// orphaned profile fails at connect time, days later, with no clue that a
    /// setting somewhere else caused it.
    @Test func removingADatabaseNamesTheVPNsThatUseIt() {
        let warning = SignInSourceSteps.removalWarning(
            vendor: .keePassFile, name: "Work", usedBy: ["GR Lab", "Office"])
        #expect(warning.contains("Work"))
        #expect(warning.contains("GR Lab"))
        #expect(warning.contains("Office"))
        #expect(warning.contains("use it"))
        // …and it says what is NOT happening: the file itself is untouched.
        #expect(warning.contains("left exactly as it is"))

        let one = SignInSourceSteps.removalWarning(
            vendor: .keePassFile, name: "Work", usedBy: ["GR Lab"])
        #expect(one.contains("\u{201C}GR Lab\u{201D} uses it"))

        let none = SignInSourceSteps.removalWarning(
            vendor: .keePassFile, name: "Work", usedBy: [])
        #expect(!none.contains("uses it"))
    }

    /// A suggested name for a new one, so adding is never blocked on thinking of a
    /// name — and never collides with the name already there.
    @Test func aNewDatabaseGetsASuggestedName() {
        let existing = [SourceInstance(id: .fresh(), vendor: .keePassFile, name: "Database 2")]
        let suggested = SourceInstanceMigration.suggestedName(vendor: .keePassFile,
                                                             existing: existing)
        #expect(suggested != "Database 2")
        #expect(suggested.hasPrefix("Database"))
    }
}

// MARK: - The pane's per-instance fields, and MDM

@MainActor
struct SourceInstanceSettingsTests {

    private func settings() -> (SignInSourceSettingsStore, UserDefaults) {
        let defaults = UserDefaults(suiteName: "SourceInstanceSettingsTests.\(UUID().uuidString)")!
        return (SignInSourceSettingsStore(store: defaults), defaults)
    }

    private var databaseField: VendorConfigField {
        SignInSourceSettings.instanceFields(for: .keePassFile)[0]
    }

    /// Add, rename, remove — each landing on the list and only on that instance.
    @Test func addRenameRemoveTouchOnlyTheInstanceNamed() throws {
        let (store, _) = settings()
        let work = try #require(store.instanceStore.add(named: "Work", for: .keePassFile))
        let personal = try #require(store.instanceStore.add(named: "Personal", for: .keePassFile))
        store.setValue("/Users/me/Work.kdbx", for: databaseField,
                       instance: store.instance(work.id, for: .keePassFile))
        store.setValue("/Users/me/Personal.kdbx", for: databaseField,
                       instance: store.instance(personal.id, for: .keePassFile))

        store.instanceStore.rename(work.id, to: "Office", for: .keePassFile)
        #expect(store.instance(work.id, for: .keePassFile)?.name == "Office")
        #expect(store.instance(personal.id, for: .keePassFile)?.name == "Personal")
        #expect(store.instance(work.id, for: .keePassFile)?.values["database"]
                == "/Users/me/Work.kdbx")

        store.instanceStore.remove(work.id, for: .keePassFile)
        #expect(store.instances(for: .keePassFile).map(\.id) == [personal.id])
        #expect(store.instance(personal.id, for: .keePassFile)?.values["database"]
                == "/Users/me/Personal.kdbx")
    }

    /// Removing one takes its values with it — a stale path left behind would come
    /// back the moment an id was reused.
    @Test func removingAnInstanceClearsItsValues() throws {
        let (store, defaults) = settings()
        let work = try #require(store.instanceStore.add(named: "Work", for: .keePassFile))
        store.setValue("/Users/me/Work.kdbx", for: databaseField,
                       instance: store.instance(work.id, for: .keePassFile))
        let key = SignInSourceSettings.instanceValueKey(.keePassFile, work.id, databaseField)
        #expect(defaults.string(forKey: key) == "/Users/me/Work.kdbx")
        store.instanceStore.remove(work.id, for: .keePassFile)
        #expect(defaults.object(forKey: key) == nil)
    }

    /// The value-versus-suggestion contract, PER INSTANCE. The landmine cannot come
    /// back through this door: the value is what the user set, the prompt is an
    /// example, and there is never a detected database path (finding one would mean
    /// reading somebody's file tree).
    @Test func aPerInstanceFieldKeepsTheValueVersusSuggestionRule() throws {
        let (store, _) = settings()
        let work = try #require(store.instanceStore.add(named: "Work", for: .keePassFile))
        let instance = try #require(store.instance(work.id, for: .keePassFile))

        let empty = store.presentation(for: databaseField, instance: instance)
        #expect(empty.value.isEmpty)
        #expect(!empty.isSet)
        #expect(empty.prompt == databaseField.example)
        #expect(empty.detectedPath == nil)
        #expect(!empty.canResetToDetected)

        store.setValue("/Users/me/Work.kdbx", for: databaseField, instance: instance)
        let set = store.presentation(for: databaseField,
                                     instance: store.instance(work.id, for: .keePassFile))
        #expect(set.value == "/Users/me/Work.kdbx")
        #expect(set.isSet)
        #expect(set.accessibilityValue.hasPrefix("/Users/me/Work.kdbx"))
    }

    /// The first database somebody chooses IS the first instance — a person who has
    /// never seen a list must not have to make one first.
    @Test func choosingADatabaseWithNoListYetCreatesTheFirstOne() {
        let (store, _) = settings()
        store.setValue("/Users/me/Work.kdbx", for: databaseField, instance: nil)
        #expect(store.instances(for: .keePassFile).count == 1)
        #expect(store.instances(for: .keePassFile).first?.values["database"]
                == "/Users/me/Work.kdbx")
    }

    /// LEVEL 1 is unchanged and still singular: a tool path is per Mac, whatever the
    /// database.
    @Test func theTransportConfigIsPerMacAndPerVendor() {
        let (store, _) = settings()
        let config = store.transportConfig(for: .keePassFile)
        #expect(config.vendor == .keePassFile)
        #expect(config.isEnabled)
        #expect(config.level == .transport)
        // The tool path is the only level-1 field this vendor has, and it is shared
        // with every database.
        #expect(SignInSourceSettings.transportFields(for: .keePassFile).map(\.instanceKey)
                == ["tool-path"])
    }

    // MARK: MDM

    /// `objectIsForced` cannot be faked in a test suite, so what is asserted is
    /// everything adjacent: the documented key names, and that an unmanaged Mac is
    /// free at level 2 as well as level 1.
    @Test func theLevelTwoPolicyKeysAreTheDocumentedOnes() {
        #expect(ManagedSignInSourcePolicy.forbidAddingInstancesKey
                == "SignInSourceForbidAddingInstances")
        #expect(ManagedSignInSourcePolicy.pinnedInstancesKey == "SignInSourceInstances")
        // …and they are part of "is this Mac managed", or a fleet with only these
        // set would read as unmanaged.
        #expect(ManagedSignInSourcePolicy.allKeys.contains(
            ManagedSignInSourcePolicy.forbidAddingInstancesKey))
        #expect(ManagedSignInSourcePolicy.allKeys.contains(
            ManagedSignInSourcePolicy.pinnedInstancesKey))
    }

    @Test func anUnmanagedMacMayAddItsOwnDatabases() {
        let (store, defaults) = settings()
        #expect(!ManagedSignInSourcePolicy.addingInstancesForbidden(defaults))
        #expect(ManagedSignInSourcePolicy.pinnedInstances(.keePassFile, defaults) == nil)
        #expect(ManagedSignInSourcePolicy.instanceSummary(defaults).isEmpty)
        #expect(store.instanceStore.addLockReason(.keePassFile) == nil)
        #expect(store.instanceStore.editLockReason(.keePassFile) == nil)
    }

    /// A local default with a policy key's name is NOT policy — otherwise anybody
    /// could forbid themselves from adding a database with `defaults write`.
    @Test func aLocalDefaultIsNotLevelTwoPolicy() {
        let (_, defaults) = settings()
        defaults.set(true, forKey: ManagedSignInSourcePolicy.forbidAddingInstancesKey)
        defaults.set(["keepassfile": [["name": "Corp"]]],
                     forKey: ManagedSignInSourcePolicy.pinnedInstancesKey)
        #expect(!ManagedSignInSourcePolicy.addingInstancesForbidden(defaults))
        #expect(ManagedSignInSourcePolicy.pinnedInstances(.keePassFile, defaults) == nil)
    }

    /// A singular vendor cannot be given a list to add to, and says so rather than
    /// offering a dead button.
    @Test func aSingularVendorSaysWhyThereIsNothingToAdd() {
        let (store, _) = settings()
        let reason = store.instanceStore.addLockReason(.keeper)
        #expect(reason?.contains("only one") == true)
        #expect(store.instances(for: .keeper).isEmpty)
    }
}
