// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceTests.swift
//  The sign-in chooser's two pure decisions, pinned:
//
//   1. WHICH SOURCES ARE HONESTLY ON OFFER on this Mac (`SignInSourceCatalog`).
//      The rules are only worth anything if they cannot be dishonest, so the
//      tests are written as the lies they must prevent: a password app that is
//      not installed must not be offered; one that IS installed but switched off
//      must be offered WITH its fix rather than hidden or offered dead; and an
//      app nothing on macOS lets us read must NEVER appear as a source we can
//      fetch from — only as a pointer that says so in words.
//
//   2. FIRST TIME versus EVERY OTHER TIME (`SignInFlow`). A pure function of
//      (is anything stored?, has it connected?, is the chosen source available?),
//      so "don't re-ask a returning user" and "never discover a dead source as a
//      connect failure" are properties rather than hopes.
//
//  Nothing here touches 1Password, KeePassXC, Keeper, /Applications or the
//  keychain: the facts are injected. That is the point — this machine has only
//  1Password installed, so live probing could never cover these rules.
//

import Foundation
import Testing
@testable import SimpleVPN

struct SignInSourceCatalogTests {

    // MARK: Helpers

    /// A Mac with nothing but macOS on it.
    private func bareMac(biometrics: Bool = true, allowsSave: Bool = true) -> SignInSourceFacts {
        var facts = SignInSourceFacts()
        facts.biometricsAvailable = biometrics
        facts.allowsPasswordSave = allowsSave
        facts.vaults = Dictionary(uniqueKeysWithValues:
            LocalVaultVendor.allCases.map { ($0, LocalVaultAvailability.notInstalled) })
        return facts
    }

    private func ids(_ options: [SignInSourceOption]) -> [SignInSourceID] { options.map(\.id) }

    // MARK: - The floor: the two rows that always exist

    /// A Mac with no password app at all still gets a usable list — a chooser
    /// that can be empty is a dead end.
    @Test func aBareMacStillOffersTypingAndTheKeychain() {
        let options = SignInSourceCatalog.options(bareMac())
        #expect(ids(options).contains(.typeEachTime))
        #expect(ids(options).contains(.saveInSimpleVPN))
        #expect(ids(options).contains(.applePasswords))
        // …and nothing that isn't there.
        #expect(!ids(options).contains(.vault(.onePassword)))
        #expect(!ids(options).contains(.vault(.keePassXC)))
        #expect(!ids(options).contains(.vault(.keeper)))
        #expect(options.allSatisfy { $0.role == .fetches })
    }

    /// Typing is always first: it is the row that cannot fail, so it is the row
    /// someone stuck can always reach.
    @Test func typingLeadsTheList() {
        #expect(SignInSourceCatalog.options(bareMac()).first?.id == .typeEachTime)
    }

    // MARK: - Ordering: what works here, not what we prefer

    /// A source that ALREADY WORKS is offered ahead of one waiting on a toggle, and
    /// an UNPROVEN one sits between them. The order is a fact about this Mac — how
    /// many steps until it works — and never an opinion about the product.
    ///
    /// `.unchecked` above `.needsSetup` is the deliberate part: "we will know once you
    /// try" is nearer to working than "go and switch this on", and ranking it below
    /// would imply we know it is worse, which is exactly the certainty an unchecked
    /// row exists to disclaim.
    @Test func aWorkingSourceIsOfferedBeforeOneThatNeedsSetup() {
        var facts = bareMac()
        // KeePassXC is EARLIER in the enum than Keeper, so enum order alone would put
        // the blocked one first — which is what this rule overturns.
        facts.vaults[.keePassXC] = .blocked(.integrationOff)
        facts.vaults[.keeper] = .ready
        let rows = SignInSourceCatalog.vendorRows(facts).map(\.id)
        #expect(rows == [.vault(.keeper), .vault(.keePassXC)])
    }

    /// …and unproven sits between the two.
    @Test func anUnprovenSourceSitsBetweenWorkingAndBlocked() {
        var facts = bareMac()
        facts.vaults[.onePassword] = .blocked(.integrationOff)
        facts.vaults[.keePassXC] = .ready
        facts.vaults[.keeper] = .unchecked(.checkOwedOnUse)
        let rows = SignInSourceCatalog.vendorRows(facts).map(\.id)
        #expect(rows == [.vault(.keePassXC), .vault(.keeper), .vault(.onePassword)])
    }

    /// The three that need no detection are never reordered by it: typing first, the
    /// keychain second, Apple Passwords third, whatever is installed. A detected
    /// product must not push "type it each time" down the list — it is the answer for
    /// somebody who wants no integration at all.
    @Test func detectionNeverReordersTheThreeThatAlwaysWork() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .ready }
        let rows = SignInSourceCatalog.fetchable(facts).map(\.id)
        #expect(Array(rows.prefix(3)) == [.typeEachTime, .saveInSimpleVPN, .applePasswords])
    }

    /// Maturity breaks a tie between two equally ready sources, so a proven adapter is
    /// offered ahead of an unproven one — and the ranking is OUR confidence in OUR
    /// code, never a claim about the vendor.
    @Test func maturityBreaksATieBetweenTwoReadySources() {
        var facts = bareMac()
        let vendors: [LocalVaultVendor] = [.onePassword, .keePassXC, .keeper, .bitwarden,
                                           .dashlane, .keePassFile, .passwordStore,
                                           .lastPass, .protonPass, .passbolt]
        for vendor in vendors { facts.vaults[vendor] = .ready }
        let rows = SignInSourceCatalog.vendorRows(facts)
        // Ranks are non-decreasing down the list: no untested row may appear above a
        // tested one when both are ready.
        let ranks = rows.map { SignInSourceCatalog.maturityRank($0) }
        #expect(ranks == ranks.sorted())
    }

    /// An untested source STILL carries its notice. First run is exactly where
    /// somebody meets an untried adapter, so ordering it lower must never be mistaken
    /// for having warned them.
    @Test func anUntestedRowKeepsItsNoticeWhereverItIsOrdered() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .ready }
        for row in SignInSourceCatalog.vendorRows(facts) where row.maturity.needsNotice {
            #expect(row.maturityNotice != nil,
                    "\(row.id) is not tested but carries no notice")
        }
    }

    /// A source that is NOT INSTALLED gets no row at all — a first-run screen listing
    /// ten products somebody does not own is noise, not helpfulness.
    @Test func anAbsentSourceIsOmittedRatherThanRankedLast() {
        var facts = bareMac()
        facts.vaults[.keeper] = .ready
        let rows = SignInSourceCatalog.vendorRows(facts).map(\.id)
        #expect(rows == [.vault(.keeper)])
    }

    // MARK: - "Check Again": the affordance that makes it a walkthrough

    /// The button appears exactly where a re-probe could settle something, and NOT on a
    /// row that already works — offering to re-check a working source would invite
    /// spawning a vendor's tool for no reason. `readinessRank` is the shared rule, so
    /// the button and the ordering can never disagree about what "waiting" means.
    @Test func onlyARowWaitingOnSomethingWantsARecheck() {
        #expect(SignInSourceCatalog.readinessRank(.ready) == 0)
        #expect(SignInSourceCatalog.readinessRank(.unchecked(note: "n")) > 0)
        #expect(SignInSourceCatalog.readinessRank(.needsSetup(headline: "h", steps: [])) > 0)
    }

    /// A re-check ALWAYS produces a sentence, including when nothing changed. Silence
    /// after pressing a button reads as "the button did nothing", which sends somebody
    /// pressing it again — and each of these four says what to do next without naming a
    /// status code.
    @Test func everyRecheckOutcomeHasASpokenAnswer() {
        let outcomes: [LocalVaultAvailability] = [
            .notInstalled, .blocked(.integrationOff), .unchecked(.checkOwedOnUse), .ready,
        ]
        for outcome in outcomes {
            let said = outcome.spokenChange
            #expect(!said.isEmpty)
            // Plain language only: no raw case names leaking into speech.
            #expect(!said.contains("integrationOff"))
            #expect(!said.contains("notInstalled"))
            #expect(!said.lowercased().contains("credential"))
        }
    }

    /// A profile that forbids saving the password (`auth-nocache`) must not be
    /// offered the keychain row — offering a setting the engine refuses is the
    /// definition of a dead option.
    @Test func aProfileThatForbidsSavingLosesTheKeychainRow() {
        let options = SignInSourceCatalog.options(bareMac(allowsSave: false))
        #expect(!ids(options).contains(.saveInSimpleVPN))
        #expect(ids(options).contains(.typeEachTime))
    }

    // MARK: - The keychain row's promise

    /// The load-bearing wording: the Apple keychain holds it, macOS protects it,
    /// SimpleVPN never sees it again. All three, in the text a hover and
    /// VoiceOver both read.
    @Test func theKeychainRowSaysWhoActuallyHoldsTheSecret() {
        let option = SignInSourceCatalog.saveInSimpleVPN(biometricsAvailable: false)
        let text = option.explanation
        #expect(text.contains("Apple keychain"))
        #expect(text.contains("macOS protects it"))
        #expect(text.lowercased().contains("never sees it again"))
        // …and it does not claim SimpleVPN is the protection.
        #expect(!text.contains("SimpleVPN protects"))
    }

    /// A fingerprint is promised only where one can be given.
    @Test(arguments: [true, false])
    func theFingerprintPromiseFollowsTheMac(_ biometrics: Bool) {
        let option = SignInSourceCatalog.saveInSimpleVPN(biometricsAvailable: biometrics)
        #expect(option.explanation.lowercased().contains("fingerprint") == biometrics)
    }

    // MARK: - 1Password: installed, running, switched on — three different answers

    @Test func onePasswordIsNotOfferedWhenItIsNotInstalled() {
        #expect(SignInSourceCatalog.vaultOption(.onePassword, availability: .notInstalled) == nil)
    }

    /// The case the brief cares most about: installed but the integration is off.
    /// Offered — with the enablement banner naming the exact current toggle —
    /// never hidden, never a dead row. 1Password is explicitly NOT exempt from the
    /// banner.
    @Test func onePasswordInstalledButSwitchedOffIsOfferedWithItsFix() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.onePassword, availability: .blocked(.integrationOff)))
        guard case .needsSetup(let headline, _) = option.state else {
            Issue.record("expected a setup state, got \(option.state)"); return
        }
        #expect(headline.contains("one setting"))
        let guidance = try #require(option.guidance)
        // ONE current-version line naming the toggle, not a version matrix.
        let location = try #require(guidance.settingLocation)
        #expect(location.contains("Settings"))
        #expect(location.contains("Developer"))
        #expect(location.contains(UserFacingError.sdkIntegrationSetting))
        // The vendor's own page carries the depth. NOTE: SimpleVPN talks to
        // 1Password through its SDK integration, not the `op` CLI, so the SDK
        // page is the honest link.
        #expect(guidance.doc == VendorDocs.onePasswordSDKs)
        // Still a real choice: it maps to a stored source.
        #expect(option.storedKind == .onePassword)
        #expect(option.role == .fetches)
    }

    @Test func onePasswordNotRunningSaysSoRatherThanBlamingTheSetting() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.onePassword, availability: .blocked(.appNotRunning)))
        guard case .needsSetup(let headline, let steps) = option.state else {
            Issue.record("expected a setup state"); return
        }
        #expect(headline.lowercased().contains("isn\u{2019}t running"))
        #expect(steps.joined().contains("Open **1Password**"))
    }

    /// An old 1Password cannot be fixed by approving anything — say "update".
    @Test func anOldOnePasswordIsToldToUpdate() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.onePassword, availability: .blocked(.needsUpdate)))
        guard case .needsSetup(let headline, _) = option.state else {
            Issue.record("expected a setup state"); return
        }
        #expect(headline.lowercased().contains("updating"))
    }

    /// Never checked ⇒ offered, and honest that picking it may raise a prompt.
    @Test func anUncheckedOnePasswordWarnsAboutTheOneTimePrompt() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.onePassword, availability: .unchecked(.checkOwedOnUse)))
        guard case .unchecked(let note) = option.state else {
            Issue.record("expected an unchecked state"); return
        }
        #expect(note.lowercased().contains("allow"))
    }

    @Test func aProvenOnePasswordIsJustReady() throws {
        let option = try #require(SignInSourceCatalog.vaultOption(.onePassword, availability: .ready))
        #expect(option.state == .ready)
    }

    // MARK: - KeePassXC

    @Test func keePassXCIsNotOfferedWhenItIsNotInstalled() {
        #expect(SignInSourceCatalog.vaultOption(.keePassXC, availability: .notInstalled) == nil)
    }

    /// Installed with no socket = the browser-integration switch is off. Same
    /// treatment as 1Password's off switch: offered, with the banner.
    @Test func keePassXCWithoutItsSocketIsOfferedWithTheSwitchOnSteps() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.keePassXC, availability: .blocked(.integrationOff)))
        guard case .needsSetup = option.state else {
            Issue.record("expected a setup state"); return
        }
        let guidance = try #require(option.guidance)
        #expect(guidance.settingLocation?.contains("Browser Integration") == true)
        #expect(guidance.doc == VendorDocs.keePassXC)
        #expect(option.storedKind == .keePassXC)
    }

    // MARK: - Keeper: a source, not a hint, once Commander is there

    /// The correction that reshaped this feature: Keeper Commander is a real
    /// local path, so a Mac with Commander signed in offers Keeper as something
    /// SimpleVPN fetches from.
    @Test func keeperWithCommanderSignedInIsAFetchableSource() throws {
        var facts = bareMac()
        facts.vaults[.keeper] = .ready
        let option = try #require(SignInSourceCatalog.options(facts).first { $0.id == .vault(.keeper) })
        #expect(option.role == .fetches)
        #expect(option.storedKind == .keeper)
        #expect(option.state == .ready)
        #expect(option.explanation.contains("Keeper Commander"))
        // It must not claim to hand over the verification code (see
        // CredentialSourceKind.keeper.suppliesOTP — that promise is unproven).
        #expect(!CredentialSourceKind.keeper.suppliesOTP)
    }

    /// Commander present but nobody signed in: offered WITH the exact commands,
    /// never a dead option and never silence.
    @Test func keeperWithoutASessionIsOfferedWithTheSignInCommands() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.keeper, availability: .blocked(.notSignedIn)))
        guard case .needsSetup(let headline, _) = option.state else {
            Issue.record("expected a setup state"); return
        }
        #expect(headline.lowercased().contains("isn\u{2019}t signed in"))
        let guidance = try #require(option.guidance)
        let commands = guidance.example.map(\.text).joined(separator: " ")
        #expect(commands.contains("keeper shell"))
        #expect(commands.contains("this-device register"))
        #expect(commands.contains("persistent-login on"))
        #expect(guidance.doc == VendorDocs.keeperCommanderLogin)
    }

    /// The Keeper APP with no Commander is the third class: app found, tool
    /// missing. It is OFFERED, with the install command and the vendor's page —
    /// not hidden, and not a permanent-sounding pointer. This is the state the
    /// enablement banner exists for.
    @Test func theKeeperAppWithoutCommanderIsOfferedWithTheInstallCommand() throws {
        var facts = bareMac()
        facts.vaults[.keeper] = .blocked(.toolMissing)
        facts.otherApps = [.init(bundleID: "com.callpod.KeeperDesktop", name: "Keeper")]
        let options = SignInSourceCatalog.options(facts)
        let row = try #require(options.first { $0.id == .vault(.keeper) })
        #expect(row.role == .fetches)
        guard case .needsSetup(let headline, _) = row.state else {
            Issue.record("expected a setup state"); return
        }
        #expect(headline.lowercased().contains("isn\u{2019}t installed"))
        let guidance = try #require(row.guidance)
        #expect(guidance.example.contains { $0.text.contains("keepercommander") })
        #expect(guidance.doc == VendorDocs.keeperCommander)
        // …and the app is not ALSO listed as a pointer.
        #expect(options.filter { $0.title == "Keeper" }.count == 1)
    }

    /// SimpleVPN never installs a vendor tool: every command is something the
    /// USER runs, and no wording offers to do it for them.
    @Test func noGuidanceOffersToInstallAnythingForTheUser() {
        for vendor in LocalVaultVendor.allCases {
            let copy = LocalVaultCopyBook.copy(for: vendor)
            for (_, guidance) in copy.guidance {
                let text = ([guidance.benefit, guidance.settingLocation ?? ""]
                            + guidance.example.map(\.caption)).joined(separator: " ").lowercased()
                #expect(!text.contains("we\u{2019}ll install"))
                #expect(!text.contains("simplevpn will install"))
                #expect(!text.contains("install it for you"))
            }
        }
        // The one place it is mentioned says the opposite, explicitly.
        let install = LocalVaultCopyBook.keeper.guidance[.toolMissing]?.example.first
        #expect(install?.caption.contains("never installs it for you") == true)
    }

    /// Only the two "you can turn this on" states carry a banner. A row that
    /// already works must not sprout setup instructions, and "your app isn't
    /// running" is not an enablement problem.
    @Test func guidanceAppearsOnlyWhereSomethingCanBeTurnedOn() {
        #expect(LocalVaultBlock.toolMissing.wantsEnablementBanner)
        #expect(LocalVaultBlock.integrationOff.wantsEnablementBanner)
        #expect(LocalVaultBlock.notSignedIn.wantsEnablementBanner)
        #expect(!LocalVaultBlock.appNotRunning.wantsEnablementBanner)
        #expect(!LocalVaultBlock.needsUpdate.wantsEnablementBanner)
        for vendor in LocalVaultVendor.allCases {
            #expect(SignInSourceCatalog.vaultOption(vendor, availability: .ready)?.guidance == nil)
            #expect(SignInSourceCatalog.vaultOption(vendor, availability: .unchecked(.checkOwedOnUse))?.guidance == nil)
            for block in [LocalVaultBlock.toolMissing, .integrationOff, .notSignedIn] {
                let option = SignInSourceCatalog.vaultOption(vendor, availability: .blocked(block))
                // A vendor that cannot be in a state simply has no copy for it;
                // one that CAN must carry the banner data.
                if !LocalVaultCopyBook.copy(for: vendor).blocks.keys.contains(block) { continue }
                #expect(option?.guidance != nil,
                        "\(vendor.rawValue) is blocked on \(block.rawValue) with no way out on screen")
            }
        }
    }

    /// Every banner is short, current-version-only, and offline-usable: a benefit
    /// line, at most a handful of commands, one setting line, one link. A version
    /// matrix for someone else's software is out of scope, so nothing may hedge
    /// about older releases.
    @Test func everyBannerIsShortAndCurrentVersionOnly() throws {
        for vendor in LocalVaultVendor.allCases {
            for (block, guidance) in LocalVaultCopyBook.copy(for: vendor).guidance {
                let what = "\(vendor.rawValue)/\(block.rawValue)"
                #expect(!guidance.benefit.isEmpty, "\(what) has no benefit line")
                #expect(guidance.example.count <= 3, "\(what) reads as a manual, not an example")
                // Either a command to run or a setting to flip — a banner with
                // neither is just a link.
                #expect(!guidance.example.isEmpty || guidance.settingLocation != nil,
                        "\(what) is a banner with nothing to do but click a link")
                #expect(guidance.doc.url.scheme == "https", "\(what) links somewhere odd")
                let all = ([guidance.benefit, guidance.settingLocation ?? ""]
                           + guidance.example.map { "\($0.caption) \($0.text)" }).joined(separator: " ")
                for hedge in ["older version", "earlier version", "in older", "used to be",
                              "if you are running"] {
                    #expect(!all.lowercased().contains(hedge), "\(what) documents a superseded release")
                }
                // Spoken as content, never hover-only.
                #expect(guidance.spokenSummary.contains(guidance.doc.title),
                        "\(what) never speaks its documentation link")
                for command in guidance.example {
                    #expect(guidance.spokenSummary.contains(command.text),
                            "\(what) hides a command from VoiceOver")
                }
            }
        }
    }

    /// The link table is one auditable list of live https URLs. (Resolution is
    /// checked by hand and recorded in the work notes — a unit test must not need
    /// the network, least of all in a VPN app.)
    @Test func theDocLinkTableIsWellFormedAndUnique() {
        #expect(VendorDocs.all.count == Set(VendorDocs.all).count)
        for page in VendorDocs.all {
            #expect(page.url.scheme == "https", "\(page.title): \(page.url)")
            #expect(page.url.host?.isEmpty == false, "\(page.title) has no host")
            #expect(!page.title.isEmpty)
        }
    }

    /// The addresses that were shipping as REDIRECTS rather than as final URLs.
    ///
    /// A link table checked with `curl -L` reports 200 for a chain of redirects, so
    /// three entries passed the audit while being 301/307s: 1Password moved its
    /// developer documentation off `developer.1password.com/docs/…`, and Keeper 307s
    /// its `/en/` locale prefix away. A redirect works today and is somebody else's
    /// decision tomorrow, so what ships is the address the server actually serves.
    ///
    /// Asserted on SHAPE, offline — deliberately. Reaching the network from the unit
    /// suite would make the gate flaky and, in a VPN app, would make it depend on the
    /// very thing under test. Re-measure by hand with
    /// `curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' <url>` and accept
    /// only a bare 200.
    @Test func theLinkTableCarriesFinalURLsRatherThanRedirects() {
        for page in VendorDocs.all {
            let url = page.url.absoluteString
            #expect(!url.contains("developer.1password.com"),
                    "\(page.title) uses the old 1Password host, which 301s to www.1password.dev")
            #expect(!url.contains("docs.keeper.io/en/"),
                    "\(page.title) carries Keeper's /en/ prefix, which 307s to the unprefixed path")
        }
        // The two 1Password pages, at the addresses that answer 200 directly. Note
        // the ABSENCE of a trailing slash: www.1password.dev 308s `/sdks/` to
        // `/sdks`, so the slash is itself a redirect.
        #expect(VendorDocs.onePasswordSDKs.url.absoluteString == "https://www.1password.dev/sdks")
        #expect(VendorDocs.onePasswordCLIIntegration.url.absoluteString
                == "https://www.1password.dev/cli/app-integration")
        #expect(VendorDocs.keeperCommander.url.absoluteString
                == "https://docs.keeper.io/keeperpam/commander-cli/overview")
    }

    /// Commander present ⇒ the Keeper row is the source, and the app is NOT also
    /// listed as a pointer. Two rows for one app, one of them lying, is exactly
    /// the confusion the two classes exist to prevent.
    @Test func keeperIsNeverBothASourceAndAPointer() {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: "com.callpod.KeeperDesktop", name: "Keeper")]
        facts.vaults[.keeper] = .ready
        let options = SignInSourceCatalog.options(facts)
        #expect(options.filter { $0.title == "Keeper" }.count == 1)
        #expect(options.first { $0.title == "Keeper" }?.role == .fetches)
    }

    // MARK: - Pointers: honest about being unreadable

    /// Every vendor we cannot read appears ONLY as a pointer: no stored kind, and
    /// wording that says SimpleVPN can't read it. This is the test that stops a
    /// future edit from quietly promoting a vendor we never integrated with.
    @Test(arguments: [
        ("com.bitwarden.desktop", "Bitwarden"),
        ("com.lastpass.LastPass", "LastPass"),
        ("com.dashlane.Dashlane", "Dashlane"),
        ("in.sinew.Enpass-Desktop", "Enpass"),
        ("com.nordpass.macos", "NordPass"),
        ("me.proton.pass.electron", "Proton Pass"),
        ("com.siber.roboform", "RoboForm"),
    ])
    func anUnreadableAppIsAPointerAndOnlyAPointer(_ bundleID: String, _ name: String) throws {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: bundleID, name: name)]
        let options = SignInSourceCatalog.options(facts)
        let row = try #require(options.first { $0.title == name })
        #expect(row.role == .hint)
        #expect(row.storedKind == nil)
        #expect(row.summary.contains("can\u{2019}t read"))
        #expect(row.appBundleID == bundleID)
        // And it never sneaks into the pickable half.
        #expect(!SignInSourceCatalog.fetchable(facts).contains { $0.title == name })
    }

    /// A pointer for an app that ships an AutoFill extension offers the stronger
    /// path (macOS fills the field) — while still saying we can't read it, and
    /// still telling the user it has to be switched on first.
    @Test func anAutoFillCapableAppOffersTheFieldFillPath() throws {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: "com.markmcguill.strongbox.mac", name: "Strongbox",
                                 shipsAutoFillExtension: true)]
        let row = try #require(SignInSourceCatalog.options(facts).first { $0.title == "Strongbox" })
        #expect(row.role == .hint)
        #expect(row.fillsThroughAutoFill)
        #expect(row.summary.contains("can fill the fields itself"))
        #expect(row.explanation.contains(SignInSourceCatalog.autoFillSettingsPath))
        // The claim is conditional, because no API can tell us it is switched on.
        #expect(row.explanation.contains("switch it on"))
    }

    /// An app we DO read is never listed as a pointer, whatever the sweep found.
    @Test(arguments: ["com.1password.1password", "org.keepassxc.keepassxc",
                      "com.agilebits.onepassword7"])
    func anAppWeCanReadIsNeverAPointer(_ bundleID: String) {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: bundleID, name: "Something")]
        #expect(SignInSourceCatalog.pointers(facts).isEmpty)
    }

    /// Pointers are alphabetical: this is a "where to look" list, and any other
    /// order would be claiming something about apps we can't read.
    @Test func pointersAreAlphabetical() {
        var facts = bareMac()
        facts.otherApps = [
            .init(bundleID: "com.nordpass.macos", name: "NordPass"),
            .init(bundleID: "com.bitwarden.desktop", name: "Bitwarden"),
            .init(bundleID: "com.lastpass.LastPass", name: "LastPass"),
        ]
        #expect(SignInSourceCatalog.pointers(facts).map(\.title) == ["Bitwarden", "LastPass", "NordPass"])
    }

    // MARK: - The two classes are structurally distinguishable

    /// The invariant behind the whole design: exactly the fetchable rows carry a
    /// stored kind, and exactly the pointers don't. A user can never click a
    /// pointer expecting an integration, because there is nothing to click into.
    @Test func onlyFetchableRowsCanBeChosen() {
        var facts = bareMac()
        facts.vaults[.onePassword] = .ready
        facts.vaults[.keePassXC] = .blocked(.integrationOff)
        facts.otherApps = [.init(bundleID: "com.bitwarden.desktop", name: "Bitwarden"),
                           .init(bundleID: "com.keepassium.mac", name: "KeePassium",
                                 shipsAutoFillExtension: true)]
        for option in SignInSourceCatalog.options(facts) {
            #expect((option.storedKind != nil) == (option.role == .fetches),
                    "\(option.title) is a \(option.role) with storedKind \(String(describing: option.storedKind))")
            #expect(option.isSelectable == (option.role == .fetches))
        }
    }

    /// Every row says something in every accessible channel: a title, a visible
    /// one-liner, an explanation (which is both the hover AND the VoiceOver
    /// hint), and a spoken state. A blank one of these is a row that reads as
    /// nothing to a VoiceOver user.
    @Test func everyRowCarriesLabelSummaryExplanationAndState() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .ready }
        facts.otherApps = [.init(bundleID: "com.bitwarden.desktop", name: "Bitwarden")]
        for option in SignInSourceCatalog.options(facts) {
            #expect(!option.title.isEmpty)
            #expect(!option.summary.isEmpty)
            #expect(!option.explanation.isEmpty)
            #expect(!option.accessibilityStateValue.isEmpty)
            #expect(!option.symbol.isEmpty)
            #expect(!SignInSourceCatalog.announcement(for: option).isEmpty)
        }
    }

    /// A pointer's spoken state must repeat, in words, that SimpleVPN can't read
    /// it — the styling difference is invisible to VoiceOver.
    @Test func aPointersSpokenStateSaysItCannotBeRead() {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: "com.bitwarden.desktop", name: "Bitwarden")]
        let row = SignInSourceCatalog.pointers(facts)[0]
        #expect(row.accessibilityStateValue.contains("can\u{2019}t read"))
        #expect(SignInSourceCatalog.pointerAccessibilityLabel(row).contains("Bitwarden"))
    }

    // MARK: - Vocabulary (AGENTS.md glossary is binding on visible AND spoken text)

    /// No internal vocabulary anywhere a user can read or hear it. "credential",
    /// "provider", "OTP", "log in" are all house-forbidden.
    @Test func noRowUsesForbiddenVocabulary() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .blocked(.notSignedIn) }
        facts.otherApps = [.init(bundleID: "com.bitwarden.desktop", name: "Bitwarden",
                                 shipsAutoFillExtension: true)]
        var strings: [String] = [SignInSourceCatalog.title, SignInSourceCatalog.subtitle,
                                 SignInSourceCatalog.fetchableHeading,
                                 SignInSourceCatalog.pointerHeading,
                                 SignInSourceCatalog.pointerCaption,
                                 SignInSourceCatalog.autoFillFootnote,
                                 SignInFlow.recoveryLine]
        for option in SignInSourceCatalog.options(facts) {
            strings += [option.title, option.summary, option.explanation,
                        option.accessibilityStateValue,
                        SignInSourceCatalog.announcement(for: option)]
            if case .needsSetup(let headline, let steps) = option.state {
                strings += [headline] + steps
            }
            if case .unchecked(let note) = option.state { strings.append(note) }
        }
        for kind in CredentialSourceKind.allCases {
            strings.append(SignInFlow.unavailableHeadline(kind))
        }
        let forbidden = ["credential", "log in", "login", "logon", "authenticate", "one-time passcode"]
        for text in strings {
            // Another product's OWN names keep their spelling (glossary: "keep
            // their vocabulary") — Keeper's command really is
            // `this-device persistent-login on`, and renaming it in our copy
            // would make the instruction wrong. Those are the `code` spans, and
            // only those.
            let lower = Self.withoutCodeSpans(text).lowercased()
            for word in forbidden {
                #expect(!lower.contains(word), "\u{201C}\(text)\u{201D} contains \u{201C}\(word)\u{201D}")
            }
            // "OTP" as a bare word (a parenthetical gloss would be fine, but
            // nothing here has one).
            #expect(!Self.withoutCodeSpans(text).contains("OTP"), "\u{201C}\(text)\u{201D} says OTP")
        }
    }

    /// Everything between backticks is a command the user types verbatim, so it
    /// is exempt from our glossary and only from our glossary.
    private static func withoutCodeSpans(_ text: String) -> String {
        var out = ""
        var inCode = false
        for character in text {
            if character == "`" { inCode.toggle(); continue }
            if !inCode { out.append(character) }
        }
        return out
    }

    /// Verification codes are called verification codes, wherever they come up.
    @Test func codesAreCalledVerificationCodes() {
        let typed = SignInSourceCatalog.typeEachTime()
        #expect(typed.explanation.contains("verification code"))
        let apple = SignInSourceCatalog.applePasswords()
        #expect(apple.explanation.contains("Verification codes"))
    }

    // MARK: - Apple Passwords promises AutoFill, not a fetch

    /// THE FALSE PROMISE THIS PINS. The row used to say "macOS fills the username and
    /// password in for you", which SimpleVPN cannot deliver: Safari's and the
    /// Passwords app's items live in the data-protection keychain under the
    /// `com.apple.cfnetwork` access group, which this app's entitlement does not
    /// contain — so they are unreachable by construction, not merely absent.
    ///
    /// What is true is AutoFill: the key in the field, driven by the user, decided by
    /// macOS. The copy must promise that and stop there — including not promising
    /// that the menu will HAVE a match, which is macOS's business and which nobody
    /// has yet watched happen in our fields.
    @Test func applePasswordsPromisesOnlyWhatAutoFillDelivers() {
        let apple = SignInSourceCatalog.applePasswords()
        // It names the affordance, and says whose decision the contents are.
        #expect(apple.summary.contains("click the key"))
        #expect(apple.explanation.contains("AutoFill"))
        #expect(apple.explanation.contains("macOS\u{2019}s decision"))
        // It says plainly that SimpleVPN does not read Apple Passwords.
        #expect(apple.explanation.contains("doesn\u{2019}t read Apple Passwords"))
        // …and it does NOT claim we fill the fields, which was the old promise.
        #expect(!apple.explanation.contains("macOS fills the username and password in for you"))
        #expect(!apple.summary.lowercased().contains("simplevpn gets"))
    }

    /// Nothing may imply SAVING into Apple Passwords. SimpleVPN has no way to write
    /// there at all — the only public path needs associated domains plus a file served
    /// by the VPN operator, and it is deprecated with no macOS replacement. The row
    /// points at the keychain row instead, which is the true version of that offer.
    @Test func nothingPromisesToSaveIntoApplePasswords() {
        let apple = SignInSourceCatalog.applePasswords()
        #expect(apple.explanation.contains("saves nothing anywhere"))
        #expect(apple.explanation.contains("Save it securely in SimpleVPN"))
        // And the row that DOES save says where: the Apple keychain, protected by
        // macOS — not Apple Passwords.
        let keychain = SignInSourceCatalog.saveInSimpleVPN(biometricsAvailable: false)
        #expect(keychain.summary.contains("Apple keychain"))
        #expect(!keychain.summary.contains("Apple Passwords"))
        #expect(!keychain.explanation.contains("Apple Passwords"))
    }

    /// Apple Passwords still never supplies a verification code — it exposes none of
    /// them to other apps. Correct before this change and unchanged by it.
    @Test func applePasswordsStillSuppliesNoVerificationCode() {
        #expect(!CredentialSourceKind.applePasswords.suppliesOTP)
        #expect(SignInSourceCatalog.applePasswords().storedKind == .applePasswords)
    }

    // MARK: - Mapping a stored source back to its row

    /// A returning VPN's summary line has to name the way it signs in, including
    /// the manual/remembered distinction the stored kind alone cannot express.
    @Test func aStoredSourceMapsBackToARow() throws {
        var facts = bareMac()
        facts.vaults[.onePassword] = .ready
        #expect(SignInSourceCatalog.option(for: .manual, remembers: false, facts: facts)?.id == .typeEachTime)
        #expect(SignInSourceCatalog.option(for: .manual, remembers: true, facts: facts)?.id == .saveInSimpleVPN)
        #expect(SignInSourceCatalog.option(for: .onePassword, remembers: true, facts: facts)?.id
                == .vault(.onePassword))
        // Even for a source whose app has since gone: the summary must still be
        // able to say what this VPN is set to.
        let gone = try #require(SignInSourceCatalog.option(for: .keeper, remembers: true, facts: bareMac()))
        #expect(gone.title == "Keeper")
    }

    /// Every stored kind has a row, so no VPN can be in a state the summary
    /// cannot describe. `allCases`, not a hand-list: a new kind must join.
    @Test func everyStoredKindHasARow() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .ready }
        facts.otherApps = []
        for kind in CredentialSourceKind.allCases {
            #expect(SignInSourceCatalog.option(for: kind, remembers: true, facts: facts) != nil,
                    "no row describes \(kind.rawValue)")
        }
    }

    // MARK: - Switched off means not offered AND not hinted

    /// A vendor the user switched off disappears from the chooser entirely — and it
    /// disappears through `availability(_:)`, which is the single choke point every
    /// caller already goes through. Filtering at each call site instead is how one
    /// of them gets missed.
    @Test func aSwitchedOffVendorIsNotOffered() {
        var facts = bareMac()
        facts.vaults[.keeper] = .ready
        facts.vaults[.onePassword] = .ready
        #expect(ids(SignInSourceCatalog.options(facts)).contains(.vault(.keeper)))

        facts.disabledVendors = [.keeper]
        let after = ids(SignInSourceCatalog.options(facts))
        #expect(!after.contains(.vault(.keeper)))
        #expect(after.contains(.vault(.onePassword)), "one switch must not turn off another vendor")
        #expect(facts.availability(.keeper) == .notInstalled,
                "a switched-off vendor must be indistinguishable from an absent one")
    }

    /// THE TRAP, and it is specific. With only the chooser filtered, switching Keeper
    /// off would MOVE the Keeper app into "Other password apps on this Mac" — still
    /// advertised, now in a worse place. Off has to mean not hinted either.
    @Test func aSwitchedOffVendorIsNotHintedAsAnotherAppEither() {
        var facts = bareMac()
        facts.vaults[.keeper] = .ready
        facts.otherApps = [InstalledPasswordApp(bundleID: "com.callpod.KeeperDesktop",
                                                name: "Keeper")]
        facts.disabledVendors = [.keeper]

        let all = SignInSourceCatalog.options(facts)
        #expect(!ids(all).contains(.vault(.keeper)))
        #expect(!ids(all).contains(.otherApp(bundleID: "com.callpod.KeeperDesktop")),
                "switching a vendor off must not demote it to a pointer row")
        #expect(SignInSourceCatalog.pointers(facts).isEmpty)
    }

    /// The Settings pane is the ONE place allowed to see past the switch, because
    /// "installed, and you turned it off" is exactly what it has to be able to say.
    @Test func thePaneCanStillSeeAnInstalledButSwitchedOffVendor() {
        var facts = bareMac()
        facts.vaults[.keeper] = .ready
        facts.disabledVendors = [.keeper]
        #expect(facts.availability(.keeper) == .notInstalled)
        #expect(facts.rawAvailability(.keeper) == .ready)
        #expect(!facts.isEnabled(.keeper))
        #expect(facts.isEnabled(.onePassword))
    }

    /// Every vendor row offers a way to configure it — including the ones that
    /// already work. Someone who wants to switch a working vendor off, or point it at
    /// a different copy of its tool, should not have to go looking.
    @Test func everyVendorRowIsConfigurable() {
        var facts = bareMac()
        for vendor in LocalVaultVendor.allCases { facts.vaults[vendor] = .ready }
        for option in SignInSourceCatalog.fetchable(facts) {
            guard case .vault(let vendor) = option.id else {
                #expect(option.configurableVendor == nil,
                        "\(option.id.rawValue) has nothing to configure")
                continue
            }
            #expect(option.configurableVendor == vendor)
        }
    }

    // MARK: - "Installed, just not where we look"

    /// THE LIE THIS STATE EXISTS TO PREVENT. `.toolMissing` says "isn't installed",
    /// which is false when we can see the thing — and it sends someone off to install
    /// a second copy of what they already have.
    @Test func aToolFoundOutsideTheAllowListDoesNotClaimToBeMissing() throws {
        var facts = bareMac()
        facts.vaults[.keeper] = .blocked(.toolOutsideAllowList)
        facts.toolsFoundOutsideAllowList[.keeper] = "/Users/me/venv/bin/keeper"

        let option = try #require(SignInSourceCatalog.options(facts)
            .first { $0.id == .vault(.keeper) })
        guard case .needsSetup(let headline, _) = option.state else {
            Issue.record("expected a needs-setup row")
            return
        }
        #expect(headline.contains("is installed"))
        #expect(!headline.contains("isn\u{2019}t installed"))
        #expect(headline.contains("not somewhere SimpleVPN will run it"))
    }

    /// …and the guidance NAMES THE PATH. Without it the advice is "your tool is
    /// somewhere else", which helps nobody; with it, the fix is a paste.
    @Test func theGuidanceNamesThePathItFound() throws {
        var facts = bareMac()
        facts.vaults[.keeper] = .blocked(.toolOutsideAllowList)
        facts.toolsFoundOutsideAllowList[.keeper] = "/Users/me/venv/bin/keeper"

        let option = try #require(SignInSourceCatalog.options(facts)
            .first { $0.id == .vault(.keeper) })
        let guidance = try #require(option.guidance)
        #expect(guidance.benefit.contains("/Users/me/venv/bin/keeper"))
        // The path is the first thing to copy, and there is a second way out that
        // needs no setting at all.
        #expect(guidance.example.first?.text == "/Users/me/venv/bin/keeper")
        #expect(guidance.example.contains { $0.text.hasPrefix("brew install") })
        #expect(guidance.settingLocation?.contains("Sign-In Sources") == true)
        // Spoken in full: the commands and the link are content, not decoration.
        #expect(guidance.spokenSummary.contains("/Users/me/venv/bin/keeper"))
    }

    /// The state earns a banner. It is something the user can fix in one field, which
    /// is the definition the banner exists for — not a dead end and not an update.
    @Test func theOutsideAllowListStateWantsABanner() {
        #expect(LocalVaultBlock.toolOutsideAllowList.wantsEnablementBanner)
        // …and the two that are NOT enablement problems still aren't.
        #expect(!LocalVaultBlock.appNotRunning.wantsEnablementBanner)
        #expect(!LocalVaultBlock.needsUpdate.wantsEnablementBanner)
    }

    /// With no path known (the master switch off, say) the row still renders rather
    /// than crashing or promising a paste it cannot supply.
    @Test func theRowSurvivesWithNoPathToName() throws {
        var facts = bareMac()
        facts.vaults[.keeper] = .blocked(.toolOutsideAllowList)
        let option = try #require(SignInSourceCatalog.options(facts)
            .first { $0.id == .vault(.keeper) })
        #expect(option.guidance == nil || option.guidance?.example.isEmpty == false)
        #expect(option.accessibilityStateValue.contains("is installed"))
    }

    /// Every vendor has copy — a vendor added to the enum without wording would
    /// render a row with a placeholder title.
    @Test func everyVendorHasCopyAndAnAdapter() {
        for vendor in LocalVaultVendor.allCases {
            let copy = LocalVaultCopyBook.copy(for: vendor)
            #expect(!copy.title.isEmpty)
            #expect(!copy.summary.isEmpty)
            #expect(!copy.explanation.isEmpty)
            #expect(copy.storedKind != .manual)
            #expect(LocalVaultRegistry.adapter(for: vendor) != nil)
            #expect(LocalVaultRegistry.adapter(for: copy.storedKind)?.vendor == vendor)
        }
    }
}

// MARK: - First time versus every other time

struct SignInFlowTests {

    /// A brand-new VPN with nothing stored and no successful connect is the ONLY
    /// case that asks.
    @Test func aBrandNewVPNIsAsked() {
        #expect(SignInFlow.step(SignInFlowInputs()) == .chooseHowToSignIn)
    }

    /// The returning requirement, stated twice over because either fact alone is
    /// enough: a VPN that has connected, or one with a sign-in on file, is never
    /// asked again.
    @Test(arguments: [true, false])
    func aReturningVPNIsNeverAskedAgain(_ viaStoredRatherThanConnected: Bool) {
        var inputs = SignInFlowInputs()
        if viaStoredRatherThanConnected { inputs.hasStoredSignIn = true }
        else { inputs.hasConnectedBefore = true }
        #expect(SignInFlow.step(inputs) == .connectStraightThrough)
        #expect(!SignInFlow.showsChooser(inputs))
    }

    /// Nothing to collect wins outright — a Tailscale or WireGuard VPN is never
    /// asked how it signs in, because the question is meaningless.
    @Test func aVPNWithNothingToCollectIsNeverAsked() {
        var inputs = SignInFlowInputs()
        inputs.collectsNothing = true
        #expect(SignInFlow.step(inputs) == .nothingToCollect)
        // …even when everything else would have asked.
        inputs.chosenKind = .onePassword
        inputs.chosenSourceAvailable = false
        #expect(SignInFlow.step(inputs) == .nothingToCollect)
    }

    /// The recovery path: a chosen password app that isn't available outranks
    /// "already set up", because the alternative is finding out five seconds into
    /// a failed connect.
    @Test func anUnavailableChosenSourceOutranksEverything() {
        var inputs = SignInFlowInputs()
        inputs.hasConnectedBefore = true
        inputs.hasStoredSignIn = true
        inputs.chosenKind = .onePassword
        inputs.chosenSourceAvailable = false
        #expect(SignInFlow.step(inputs) == .recoverUnavailableSource(.onePassword))
    }

    /// Manual is always available, so it can never trigger recovery — there is
    /// no app to be missing.
    @Test func manualNeverTriggersRecovery() {
        var inputs = SignInFlowInputs()
        inputs.chosenKind = .manual
        inputs.chosenSourceAvailable = false   // nonsense input, defensively handled
        #expect(SignInFlow.step(inputs) == .chooseHowToSignIn)
    }

    /// Recovery clears once the source is back, without anything being re-asked.
    @Test func recoveryEndsWhenTheAppComesBack() {
        var inputs = SignInFlowInputs()
        inputs.hasConnectedBefore = true
        inputs.chosenKind = .keePassXC
        inputs.chosenSourceAvailable = false
        #expect(SignInFlow.step(inputs) == .recoverUnavailableSource(.keePassXC))
        inputs.chosenSourceAvailable = true
        #expect(SignInFlow.step(inputs) == .connectStraightThrough)
    }

    /// Dismissing the card hides it for this run — but only when there is no
    /// recovery to report, which must never be dismissible into silence.
    @Test func dismissingHidesTheChooserButNotARecovery() {
        var inputs = SignInFlowInputs()
        inputs.dismissedForNow = true
        #expect(SignInFlow.step(inputs) == .connectStraightThrough)
        inputs.chosenKind = .keeper
        inputs.chosenSourceAvailable = false
        #expect(SignInFlow.step(inputs) == .recoverUnavailableSource(.keeper))
    }

    /// Every source has a recovery sentence naming the app and both ways out —
    /// `allCases` so a new kind cannot ship with a blank explanation.
    @Test func everySourceHasARecoverySentence() {
        for kind in CredentialSourceKind.allCases {
            let headline = SignInFlow.unavailableHeadline(kind)
            #expect(!headline.isEmpty)
            if kind != .manual, kind != .applePasswords {
                #expect(headline.contains(kind.displayName),
                        "\u{201C}\(headline)\u{201D} never names \(kind.displayName)")
            }
        }
        #expect(SignInFlow.recoveryLine.lowercased().contains("type"))
        #expect(SignInFlow.recoveryLine.lowercased().contains("another way"))
    }

    /// The whole decision, over every reachable combination: it always answers,
    /// and it never asks a VPN that is already set up.
    @Test func theDecisionIsTotalAndNeverReAsks() {
        let bools = [false, true]
        for stored in bools { for connected in bools { for available in bools {
            for dismissed in bools { for nothing in bools {
                for kind in CredentialSourceKind.allCases {
                    var inputs = SignInFlowInputs()
                    inputs.hasStoredSignIn = stored
                    inputs.hasConnectedBefore = connected
                    inputs.chosenSourceAvailable = available
                    inputs.dismissedForNow = dismissed
                    inputs.collectsNothing = nothing
                    inputs.chosenKind = kind
                    let step = SignInFlow.step(inputs)
                    if step == .chooseHowToSignIn {
                        #expect(!stored && !connected && !nothing,
                                "asked an already-set-up VPN: \(inputs)")
                    }
                }
            }}
        }}}
    }
}

// MARK: - Finding the tools (pure parts of the live probes)

struct LocalToolRunnerTests {

    /// $PATH IS NOT CONSULTED. This is the security property the whole CLI-backed
    /// design rests on: anything that can prepend a directory to PATH would
    /// otherwise choose which binary this app executes — and that binary is about
    /// to be asked for a password. The allow-list is the documented install
    /// locations, nothing else.
    @Test func theToolSearchNeverTrustsPath() {
        let dirs = LocalToolRunner.searchDirectories(home: URL(fileURLWithPath: "/Users/tester"))
        #expect(!dirs.contains("/attacker/bin"))
        #expect(dirs.first == "/opt/homebrew/bin")
        #expect(dirs.contains("/usr/local/bin"))
        #expect(dirs.contains("/usr/bin"))
        // pipx / pip --user, which is the documented install for a Python tool.
        #expect(dirs.contains("/Users/tester/.local/bin"))
        // No duplicates, so a tool isn't probed twice in the same place.
        #expect(Set(dirs).count == dirs.count)
    }

    /// Even with a hostile PATH in the environment, resolution is unchanged —
    /// asserted rather than assumed, because "we removed the PATH lookup" is the
    /// kind of thing a later refactor puts back for convenience.
    @Test func aHostilePathCannotIntroduceADirectory() {
        setenv("PATH", "/tmp/attacker/bin:/usr/bin", 1)
        defer { unsetenv("PATH") }
        let dirs = LocalToolRunner.searchDirectories(home: URL(fileURLWithPath: "/Users/tester"))
        #expect(!dirs.contains("/tmp/attacker/bin"))
    }

    /// A tool NAME is a name. A separator in it would escape the allow-list.
    @Test(arguments: ["../../tmp/evil", "/tmp/evil", "tmp/evil", "", ".", ".."])
    func aToolNameThatIsReallyAPathIsRefused(_ name: String) {
        #expect(LocalToolRunner.locate(name) == nil)
    }

    /// `run` refuses anything that didn't come from the allow-list, so a caller
    /// cannot hand it a relative name and let the child resolve it.
    @Test func runRefusesAnUnapprovedExecutable() async {
        let result = await LocalToolRunner.run(executable: "ls", arguments: [])
        #expect(!result.succeeded)
        let outside = await LocalToolRunner.run(executable: "/tmp/not-a-tool", arguments: [])
        #expect(!outside.succeeded)
    }

    /// The child gets a built environment, not ours: no DYLD_*, no PYTHONPATH, no
    /// inherited PATH, no proxy variables that could redirect a vendor's traffic.
    /// HOME is passed because a vendor tool legitimately keeps its session there.
    @Test func theChildEnvironmentIsBuiltNotInherited() {
        setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib", 1)
        setenv("PYTHONPATH", "/tmp/evil", 1)
        defer { unsetenv("DYLD_INSERT_LIBRARIES"); unsetenv("PYTHONPATH") }
        let env = LocalToolRunner.childEnvironment(home: URL(fileURLWithPath: "/Users/tester"))
        #expect(env["DYLD_INSERT_LIBRARIES"] == nil)
        #expect(env["PYTHONPATH"] == nil)
        #expect(env["HOME"] == "/Users/tester")
        #expect(env["PATH"]?.contains("/tmp") == false)
    }

    /// An absolute path the user set for themselves wins — someone who installed
    /// Commander somewhere unusual must be able to say so — but only if it is a
    /// real executable, and never a relative one.
    @Test func anExplicitUserPathWinsButIsStillChecked() {
        let store = UserDefaults(suiteName: "SignInSourceTests.\(UUID().uuidString)")!
        store.set("/bin/ls", forKey: "signin.tool.faketool.path")
        #expect(LocalToolRunner.userConfiguredPath(for: "faketool", store: store) == "/bin/ls")
        store.set("relative/ls", forKey: "signin.tool.faketool.path")
        #expect(LocalToolRunner.userConfiguredPath(for: "faketool", store: store) == nil)
        store.set("/definitely/not/here", forKey: "signin.tool.faketool.path")
        #expect(LocalToolRunner.userConfiguredPath(for: "faketool", store: store) == nil)
    }

    /// A directory anyone can write to must never supply a binary we exec.
    @Test func aWorldWritableDirectoryIsNeverTrusted() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("signin-tool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o777])
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("keeper")
        try Data("#!/bin/sh\n".utf8).write(to: tool)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool.path)
        #expect(!LocalToolRunner.isSafeExecutable(atPath: tool.path))
    }

    @Test func aDirectoryIsNotAnExecutable() {
        #expect(!LocalToolRunner.isSafeExecutable(atPath: "/usr/bin"))
        #expect(LocalToolRunner.isSafeExecutable(atPath: "/bin/ls"))
    }

    /// A tool that isn't there is not "there" — the detection floor every "only
    /// offer what exists" rule stands on.
    @Test func aMissingToolIsNotLocated() {
        #expect(LocalToolRunner.locate("simplevpn-no-such-tool-\(UUID().uuidString)") == nil)
    }

    @Test func aRealToolIsLocated() {
        #expect(LocalToolRunner.locate("ls") != nil)
    }

    /// Diagnostics must not carry secrets. A vendor CLI that echoes a password
    /// into its own error output must not have it end up in a bundle.
    @Test func stderrScrubbingHidesAnythingSecretShaped() {
        let scrubbed = LocalToolRunner.scrub("error: bad password Tr0ub4dor&3xample99 for user jim")
        #expect(!scrubbed.contains("Tr0ub4dor&3xample99"))
        #expect(scrubbed.contains("error:"))
        #expect(scrubbed.contains("jim"))   // plain words survive
    }

    @Test func stderrScrubbingKeepsPathsReadable() {
        let scrubbed = LocalToolRunner.scrub("cannot open /Users/jim/Library/Keeper/config.json")
        #expect(scrubbed.contains("/Users/jim/Library/Keeper/config.json"))
    }

    @Test func stderrScrubbingIsOneShortLine() {
        let scrubbed = LocalToolRunner.scrub(String(repeating: "word ", count: 200) + "\nsecond line")
        #expect(scrubbed.count <= 201)
        #expect(!scrubbed.contains("second line"))
    }
}

// MARK: - Keeper: parsing a record, and the channel seam

struct KeeperRecordParsingTests {

    /// The legacy flat shape.
    @Test func aFlatRecordIsRead() throws {
        let json = #"{"record_uid":"abc","title":"GR Lab","login":"jim","password":"s3cret"}"#
        let record = try #require(KeeperRecordParser.parse(Data(json.utf8)))
        #expect(record.login == "jim")
        #expect(record.password == "s3cret")
        #expect(record.totpSeed == nil)
    }

    /// The typed (v3) shape — a Commander version bump must not silently stop
    /// finding the password.
    @Test func aTypedRecordIsRead() throws {
        let json = """
        {"type":"login","title":"GR Lab","fields":[
          {"type":"login","value":["jim"]},
          {"type":"password","value":["s3cret"]},
          {"type":"oneTimeCode","value":["otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP"]}]}
        """
        let record = try #require(KeeperRecordParser.parse(Data(json.utf8)))
        #expect(record.login == "jim")
        #expect(record.password == "s3cret")
        #expect(record.totpSeed?.hasPrefix("otpauth://") == true)
    }

    /// Some builds wrap the answer in an array.
    @Test func anArrayWrappedRecordIsRead() throws {
        let json = #"[{"login":"jim","password":"s3cret"}]"#
        let record = try #require(KeeperRecordParser.parse(Data(json.utf8)))
        #expect(record.password == "s3cret")
    }

    /// A bare six-digit code is a CODE, not a seed. Storing it as a seed would
    /// freeze one code for ever, which is worse than having none.
    @Test func aBareCodeIsNotMistakenForASeed() throws {
        let json = #"{"login":"jim","password":"s3cret","totp":"123456"}"#
        let record = try #require(KeeperRecordParser.parse(Data(json.utf8)))
        #expect(record.totpSeed == nil)
    }

    @Test func nonsenseIsNotARecord() {
        #expect(KeeperRecordParser.parse(Data("not json".utf8)) == nil)
        #expect(KeeperRecordParser.parse(Data(#"{"title":"no secrets here"}"#.utf8)) == nil)
    }

    /// Custom fields as a label→value map (another shape Commander emits).
    @Test func customFieldMapsAreRead() throws {
        let json = #"{"title":"x","custom_fields":{"login":"jim","password":"s3cret"}}"#
        let record = try #require(KeeperRecordParser.parse(Data(json.utf8)))
        #expect(record.login == "jim")
        #expect(record.password == "s3cret")
    }

    // MARK: Service Mode config (read-only, tolerantly)

    @Test func serviceModeConfigIsParsedTolerantly() throws {
        let a = try #require(KeeperServiceMode.parse(Data(#"{"port":9123,"api_key":"K"}"#.utf8)))
        #expect(a == KeeperServiceMode.Service(port: 9123, apiKey: "K"))
        let b = try #require(KeeperServiceMode.parse(Data(#"{"service_port":"9124","token":"K2"}"#.utf8)))
        #expect(b.port == 9124)
        #expect(b.apiKey == "K2")
    }

    /// Half a config is no config: falling back to the CLI is right, guessing is
    /// not.
    @Test(arguments: [#"{"port":9123}"#, #"{"api_key":"K"}"#, #"{}"#, #"{"port":0,"api_key":"K"}"#])
    func anIncompleteServiceConfigIsIgnored(_ json: String) {
        #expect(KeeperServiceMode.parse(Data(json.utf8)) == nil)
    }
}

/// The provider's own decisions, over an injected channel — no Keeper, no
/// Commander, no Python anywhere near this test.
struct KeeperProviderTests {

    private struct StubChannel: KeeperChannel {
        var reachable = true
        var record: KeeperRecord?
        var error: (any Error)?
        func isReachable() async -> Bool { reachable }
        func record(reference: String) async throws -> KeeperRecord {
            if let error { throw error }
            guard let record else { throw KeeperProvider.KeeperError.noRecord }
            return record
        }
    }

    @Test func aRecordBecomesAUsernameAndPassword() async throws {
        let provider = KeeperProvider(
            reference: "Work/VPN/GR Lab",
            channel: StubChannel(record: KeeperRecord(login: "jim", password: "s3cret")))
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.username == "jim")
        #expect(raw.password == "s3cret")
        #expect(raw.otp == nil)
    }

    /// The code is computed locally from the record's seed — a fetch, not a
    /// second round trip.
    @Test func aSeedInTheRecordProducesACodeLocally() async throws {
        let provider = KeeperProvider(
            reference: "r",
            channel: StubChannel(record: KeeperRecord(
                login: "jim", password: "p",
                totpSeed: "otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP")))
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password, .otp])
        #expect(raw.otp?.count == 6)
        // …and not when the connect doesn't ask for one.
        let without = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(without.otp == nil)
    }

    @Test func aRecordWithNoPasswordIsAnHonestFailure() async {
        let provider = KeeperProvider(reference: "r",
                                      channel: StubChannel(record: KeeperRecord(login: "jim")))
        await #expect(throws: KeeperProvider.KeeperError.noPassword("r")) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// A named account that doesn't match the record is refused, never silently
    /// used: the wrong identity is a security answer, not a convenience one.
    @Test func aMismatchedAccountIsRefused() async {
        let provider = KeeperProvider(
            reference: "r", account: "someone-else",
            channel: StubChannel(record: KeeperRecord(login: "jim", password: "p")))
        await #expect(throws: KeeperProvider.KeeperError.wrongAccount("someone-else")) {
            try await provider.resolve(profile: "p", fields: [.username, .password])
        }
    }

    @Test func anEmptyReferenceIsNeverFetched() async {
        let provider = KeeperProvider(reference: "   ", channel: StubChannel())
        #expect(await provider.isAvailable(for: "p") == false)
        await #expect(throws: KeeperProvider.KeeperError.noRecord) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// Every error is a sentence a person can act on — no exit codes, no stderr
    /// dumps, and nothing secret-shaped.
    @Test func everyKeeperErrorExplainsItself() {
        let errors: [KeeperProvider.KeeperError] = [
            .noRecord, .notSignedIn, .noPassword("GR Lab"),
            .wrongAccount("jim"), .unreadable("its answer couldn\u{2019}t be read."),
        ]
        for error in errors {
            let text = error.errorDescription ?? ""
            #expect(!text.isEmpty)
            #expect(!text.lowercased().contains("errno"))
        }
        #expect(KeeperProvider.KeeperError.notSignedIn.errorDescription?
            .contains("persistent-login on") == true)
    }
}

// MARK: - The adapter seam

struct LocalVaultAdapterTests {

    /// One adapter per vendor, one vendor per stored kind — the registry is what
    /// keeps a new password app from needing another branch in the connect path.
    @Test func theRegistryCoversEveryVendorExactlyOnce() {
        #expect(LocalVaultRegistry.all.count == LocalVaultVendor.allCases.count)
        let vendors = LocalVaultRegistry.all.map(\.vendor)
        #expect(Set(vendors).count == vendors.count)
        let kinds = LocalVaultRegistry.all.map(\.storedKind)
        #expect(Set(kinds).count == kinds.count)
        #expect(!kinds.contains(.manual))
    }

    /// TRANSPORT IS NOT VENDOR. Every adapter declares how it is reached, and the
    /// declaration is what stops the next three vendors becoming three copies:
    /// Strongbox, KeePassium and a KeePassXC database are one `.file` adapter
    /// away, and a vendor with two ways in (Keeper: its local daemon, then its
    /// CLI) names both in preference order.
    @Test func everyAdapterDeclaresHowItIsReached() {
        for adapter in LocalVaultRegistry.all {
            #expect(!adapter.transports.isEmpty, "\(adapter.vendor.rawValue) declares no transport")
            #expect(Set(adapter.transports).count == adapter.transports.count,
                    "\(adapter.vendor.rawValue) lists a transport twice")
        }
        // The preference order is load-bearing: a running daemon costs no Python
        // start-up, so it must come first.
        #expect(KeeperVaultAdapter().transports == [.localDaemon, .cli])
        // The two app-to-app channels are not CLIs, and must not be described as
        // ones — the enablement banner's wording keys off the difference.
        #expect(OnePasswordVaultAdapter().transports == [.signedIPC])
        #expect(KeePassXCVaultAdapter().transports == [.appSocket])
    }

    /// A source with nothing linked yields no fetcher — which is what makes the
    /// readiness decision fall back to the typed fields instead of enabling
    /// Connect for a lookup that cannot happen.
    @Test func anEmptySourceYieldsNoFetcher() {
        for adapter in LocalVaultRegistry.all {
            var source = CredentialSource()
            source.kind = adapter.storedKind
            source.reference = "   "
            #expect(adapter.provider(for: source) == nil,
                    "\(adapter.vendor.rawValue) built a fetcher for a source pointing at nothing")
        }
    }

    @Test func aLinkedSourceYieldsAFetcher() {
        for adapter in LocalVaultRegistry.all {
            var source = CredentialSource()
            source.kind = adapter.storedKind
            source.reference = "GR Lab"
            #expect(adapter.provider(for: source) != nil, "\(adapter.vendor.rawValue)")
        }
    }

    /// An absent vendor is never deep-scanned into existence: `deepScan` may
    /// refine a state, never invent a vendor (which would make rows appear and
    /// disappear under the pointer).
    @Test func aDeepScanNeverResurrectsAnAbsentVendor() async {
        for adapter in LocalVaultRegistry.all {
            let refined = await adapter.deepScan(quick: .notInstalled)
            #expect(refined == .notInstalled, "\(adapter.vendor.rawValue)")
        }
    }

    /// Availability's own contract: only `.notInstalled` hides a row.
    @Test func onlyNotInstalledHidesARow() {
        #expect(!LocalVaultAvailability.notInstalled.isOffered)
        for state: LocalVaultAvailability in [.ready, .unchecked(.checkOwedOnUse), .blocked(.appNotRunning),
                                              .blocked(.integrationOff), .blocked(.needsUpdate),
                                              .blocked(.notSignedIn)] {
            #expect(state.isOffered)
        }
        #expect(LocalVaultAvailability.ready.isReady)
        #expect(!LocalVaultAvailability.unchecked(.checkOwedOnUse).isReady)
    }
}
