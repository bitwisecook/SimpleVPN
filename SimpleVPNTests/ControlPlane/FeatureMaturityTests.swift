// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FeatureMaturityTests.swift
//  What "one source of truth" has to MEAN, pinned as properties rather than hoped
//  for. Three things are being defended:
//
//   1. TOTALITY — every VPN kind has exactly one line in the registry, so a new
//      kind cannot arrive with no claim attached (and cannot arrive silently
//      claimed as tested, since the fallback is `.untested`).
//   2. ONE-LINE FLIPS — flipping a single registry entry is the WHOLE change.
//      Proved twice over: once dynamically, by flipping one entry in a copy of the
//      table and asserting every derived surface follows and no other kind moves;
//      and once structurally, by walking the view sources and asserting NO view
//      contains a maturity decision at all. Between them, "no view edits" is a
//      fact about the code rather than a promise in a comment.
//   3. ORTHOGONALITY — maturity and availability are different axes. A source that
//      is `.ready` this second can still be `.untested`, and the four-state
//      availability model must never leak into a maturity answer or vice versa.
//
//  Plus the traps the registry exists to avoid getting wrong: `sshNetworkTunnel`
//  is not `ssh`, WireGuard is partly verified rather than tested, and the seven
//  OpenConnect protocols clear one at a time.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - The registry

struct FeatureMaturityRegistryTests {

    /// The user's list, written out once here so the test and the registry are two
    /// independent statements of it. If they ever disagree, one of them is a typo.
    private static let testedKinds: Set<VPNKind> = [.openVPN, .tailscale, .ssh]

    @Test func everyVPNKindHasExactlyOneRegistryLine() {
        let missing = VPNKind.allCases.filter { FeatureMaturityRegistry.vpnKinds[$0] == nil }
        let names = missing.map(\.rawValue).sorted().joined(separator: ", ")
        #expect(missing.isEmpty,
                "no maturity claim for: \(names). Add one line to FeatureMaturityRegistry.vpnKinds")
        #expect(FeatureMaturityRegistry.vpnKinds.count == VPNKind.allCases.count)
    }

    @Test func exactlyThreeKindsAreClaimedAsTested() {
        let tested = Set(VPNKind.allCases.filter { $0.maturity.isTested })
        #expect(tested == Self.testedKinds)
        #expect(FeatureMaturityRegistry.noticedKinds.count == 13)
    }

    /// The same totality for password apps, and the reason it exists: Bitwarden's
    /// adapter landed AFTER this registry did. A new vendor must arrive with a claim
    /// attached, not inherit one by omission.
    @Test func everyPasswordAppVendorHasExactlyOneRegistryLine() {
        let missing = LocalVaultVendor.allCases
            .filter { FeatureMaturityRegistry.signInSources[.vault($0)] == nil }
        let names = missing.map(\.rawValue).sorted().joined(separator: ", ")
        #expect(missing.isEmpty,
                "no maturity claim for: \(names). Add one line to FeatureMaturityRegistry.signInSources")
    }

    /// And if one ever IS missed, the default is the honest one — a vendor adapter
    /// nobody has claimed is untested, never silently proven.
    @Test func anUnclaimedVendorDefaultsToUntested() {
        let empty: [SignInSourceID: FeatureMaturity] = [:]
        for vendor in LocalVaultVendor.allCases {
            #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(vendor), in: empty)
                    == .untested)
        }
        // A pointer row makes no claim, so it still gets no notice.
        #expect(FeatureMaturityRegistry
            .maturity(ofSource: .otherApp(bundleID: "com.example.x"), in: empty) == .tested)
    }

    /// A missing entry must never read as "proven". The safe default is the
    /// pessimistic one.
    @Test func anUnregisteredKindIsUntestedNotTested() {
        let empty: [VPNKind: FeatureMaturity] = [:]
        for kind in VPNKind.allCases {
            #expect(FeatureMaturityRegistry.maturity(of: kind, in: empty) == .untested)
            #expect(MaturityNotice.forKind(kind, in: empty) != nil)
        }
    }

    /// THE TRAP. `.ssh` and `.sshNetworkTunnel` are deliberately separate kinds
    /// (VPNKind.swift: different transport, editor and mediator classification), so
    /// "SSH is tested" must not reach the netstack one.
    @Test func sshBeingTestedDoesNotLeakOntoSSHNetworkTunnel() {
        #expect(VPNKind.ssh.maturity == .tested)
        #expect(VPNKind.ssh.maturityNotice == nil)
        #expect(VPNKind.sshNetworkTunnel.maturity == .untested)
        let notice = VPNKind.sshNetworkTunnel.maturityNotice
        #expect(notice != nil)
        #expect(notice?.subject == "SSH Network Tunnel")
        // And the notice must name the netstack kind, never the plain SSH one.
        #expect(notice?.title.contains("SSH Network Tunnel") == true)
    }

    /// WireGuard has a real result behind it (a completed handshake against
    /// vendored wireguard-go) and no live tunnel. Neither "tested" nor a plain
    /// "untested" would be honest.
    @Test func wireGuardIsPartlyVerifiedAndStillCarriesANotice() {
        let maturity = VPNKind.wireGuard.maturity
        #expect(maturity != .tested)
        #expect(maturity.needsNotice)
        guard case .partlyVerified(let checked) = maturity else {
            Issue.record("WireGuard must be partly verified, not \(maturity)")
            return
        }
        #expect(!checked.isEmpty)
        let notice = VPNKind.wireGuard.maturityNotice
        #expect(notice?.badgeText == "Partly tested")
        // The clause that says what WAS proven has to reach the user, or the
        // distinction is invisible and we may as well have said "untested".
        #expect(notice?.detail.contains(checked) == true)
    }

    /// Seven protocols, seven different gateways. A FortiGate result says nothing
    /// about GlobalProtect, so clearing one must leave the other six alone.
    @Test func theSevenOpenConnectKindsClearIndependently() {
        let sslVPNs = VPNKind.allCases.filter(\.isSSLVPN)
        #expect(sslVPNs.count == 7)
        #expect(sslVPNs.allSatisfy { $0.maturity == .untested })

        var flipped = FeatureMaturityRegistry.vpnKinds
        flipped[.fortinet] = .tested
        #expect(MaturityNotice.forKind(.fortinet, in: flipped) == nil)
        for other in sslVPNs where other != .fortinet {
            #expect(MaturityNotice.forKind(other, in: flipped) != nil,
                    "\(other.rawValue) must not clear because FortiGate did")
        }
    }
}

// MARK: - "One line, no view edits", proved two ways

struct MaturityOneLineFlipTests {

    /// THE DYNAMIC HALF. For each kind that carries a notice, flip that ONE entry
    /// and assert: its notice disappears, its badge/spoken value go quiet, and
    /// every other kind is bit-for-bit unchanged. Nothing else in the table, and
    /// nothing else in the derivation, participates.
    @Test func flippingOneEntryToTestedIsTheWholeChange() {
        let before = VPNKind.allCases.map { MaturityNotice.forKind($0) }

        for kind in FeatureMaturityRegistry.noticedKinds {
            var flipped = FeatureMaturityRegistry.vpnKinds
            flipped[kind] = .tested

            #expect(MaturityNotice.forKind(kind, in: flipped) == nil,
                    "\(kind.rawValue) still carries a notice after being flipped to tested")
            #expect(FeatureMaturityRegistry.maturity(of: kind, in: flipped).needsNotice == false)

            for (index, other) in VPNKind.allCases.enumerated() where other != kind {
                #expect(MaturityNotice.forKind(other, in: flipped) == before[index],
                        "flipping \(kind.rawValue) changed \(other.rawValue)")
            }
        }
    }

    /// The same property for sign-in sources.
    @Test func flippingOneSourceToTestedIsTheWholeChange() {
        let noticed = FeatureMaturityRegistry.signInSources
            .filter { $0.value.needsNotice }.keys
        #expect(!noticed.isEmpty, "the point of the registry is that some rows are unproven")

        for id in noticed {
            var flipped = FeatureMaturityRegistry.signInSources
            flipped[id] = .tested
            #expect(MaturityNotice.forSignInSource(id: id, title: "Any", in: flipped) == nil)
            for other in noticed where other != id {
                #expect(MaturityNotice.forSignInSource(id: other, title: "Any", in: flipped) != nil,
                        "flipping \(id.rawValue) cleared \(other.rawValue)")
            }
        }
    }

    /// THE STRUCTURAL HALF, and the one that actually pins "no view edits": walk
    /// every view source and assert none of them contains a maturity DECISION.
    ///
    /// Views may say `maturityNotice`, `MaturityBanner`, `MaturityBadge` and read a
    /// notice's fields — all derivations, all of which follow a registry flip for
    /// free. What they may NOT do is name the `FeatureMaturity` type or its
    /// registry, compare a maturity against a case, ask `isTested`/`needsNotice`,
    /// or hard-code one of the badge words as a string literal. Any of those and a
    /// flip needs a view edit, which is the thing this whole design exists to
    /// prevent. If this fails, move the decision back into the registry.
    ///
    /// (`.untestedKind` / `.untestedSource` are `DiagnosticReportRequest.Reason`
    /// cases, not maturities, and are expected in the views that raise a report.)
    @Test func noViewContainsAMaturityDecision() throws {
        let forbidden = [
            "FeatureMaturity",     // the type, or the registry, named in a view
            "partlyVerified",
            "isTested",
            "needsNotice",
            "maturity ==",
            "maturity !=",
            "\"Untested\"",
            "\"Partly tested\"",
        ]
        var offences: [String] = []
        for (name, source) in try Self.viewSources() {
            for needle in forbidden where source.contains(needle) {
                offences.append("\(name): \(needle)")
            }
        }
        let found = offences.sorted().joined(separator: ", ")
        #expect(offences.isEmpty,
                "a maturity decision leaked into a view, so flipping a kind to tested would now need a view edit: \(found)")
    }

    /// And the registry file is where those literals DO live — so the test above
    /// can never pass by the decision having evaporated entirely.
    @Test func theRegistryFileIsWhereTheDecisionsLive() throws {
        let source = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/ControlPlane/FeatureMaturity.swift"),
                                encoding: .utf8)
        for kind in FeatureMaturityRegistry.noticedKinds {
            #expect(source.contains(".\(Self.caseName(kind)):"),
                    "\(kind.rawValue) is not written as a line in FeatureMaturity.swift")
        }
    }

    // MARK: Source walking (same shape as SettingRenderingTests)

    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // ControlPlane/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// Everything that draws: `UI/` plus `App/` (which holds the Manage VPNs row).
    private static func viewSources() throws -> [String: String] {
        var out: [String: String] = [:]
        for directory in ["SimpleVPN/UI", "SimpleVPN/App"] {
            let root = repoRoot.appendingPathComponent(directory)
            let e = try #require(FileManager.default.enumerator(at: root,
                                                               includingPropertiesForKeys: nil))
            for case let url as URL in e where url.pathExtension == "swift" {
                out[url.lastPathComponent] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            }
        }
        #expect(!out.isEmpty, "no view sources found")
        return out
    }

    /// The Swift case name for a kind — the raw value and the case name differ for
    /// most of them (`"cisco"` vs `ciscoAnyConnect`), and the registry is written
    /// in case names.
    private static func caseName(_ kind: VPNKind) -> String {
        switch kind {
        case .openVPN: "openVPN"
        case .wireGuard: "wireGuard"
        case .ikev2: "ikev2"
        case .ipsec: "ipsec"
        case .l2tp: "l2tp"
        case .ssh: "ssh"
        case .fortinet: "fortinet"
        case .f5apm: "f5apm"
        case .ciscoAnyConnect: "ciscoAnyConnect"
        case .globalProtect: "globalProtect"
        case .juniper: "juniper"
        case .pulse: "pulse"
        case .arrayNetworks: "arrayNetworks"
        case .tailscale: "tailscale"
        case .proxyTunnel: "proxyTunnel"
        case .sshNetworkTunnel: "sshNetworkTunnel"
        }
    }
}

// MARK: - The wording

struct MaturityNoticeCopyTests {

    /// A notice exists exactly when there is something to say, and the badge/symbol
    /// come from the maturity rather than from the subject — which is what lets one
    /// component serve sixteen kinds and every sign-in source.
    @Test func aNoticeExistsExactlyWhenTheClaimIsUnproven() {
        for kind in VPNKind.allCases {
            let notice = MaturityNotice.forKind(kind)
            #expect((notice != nil) == kind.maturity.needsNotice)
            guard let notice else { continue }
            #expect(notice.subject == kind.displayName)
            #expect(notice.maturity == kind.maturity)
            #expect(notice.badgeText == kind.maturity.badgeText)
            #expect(notice.symbolName == kind.maturity.symbolName)
            #expect(notice.key == "kind.\(kind.rawValue)")
        }
    }

    /// Honest, and not alarming. Every notice must: name the subject, say the code
    /// is written, admit it might work, and ask for a report — and must NOT read as
    /// a defect ("broken", "don't use", "unsupported", "at your own risk").
    @Test func everyNoticeIsHonestWithoutBeingAlarming() {
        for kind in FeatureMaturityRegistry.noticedKinds {
            let notice = MaturityNotice.forKind(kind)!
            let text = notice.spokenSummary
            #expect(text.contains(kind.displayName), "\(kind.rawValue) notice doesn't name itself")
            #expect(text.contains("written and reviewed"),
                    "\(kind.rawValue) notice doesn't say the code exists and was reviewed")
            #expect(text.contains("may well work"),
                    "\(kind.rawValue) notice doesn't admit it may work")
            #expect(text.lowercased().contains("telling us"),
                    "\(kind.rawValue) notice doesn't ask for the report that clears it")
            for scare in ["broken", "unsupported", "do not use", "don\u{2019}t use",
                          "at your own risk", "unsafe", "dangerous"] {
                #expect(!text.lowercased().contains(scare),
                        "\(kind.rawValue) notice reads as a defect: \u{201C}\(scare)\u{201D}")
            }
        }
    }

    /// The badge word alone is meaningless spoken aloud, so the list-row value is a
    /// full clause naming the subject. A tested subject says nothing at all.
    @Test func theSpokenValueIsAClauseNotABadgeWord() {
        for kind in VPNKind.allCases {
            guard let notice = MaturityNotice.forKind(kind) else { continue }
            #expect(notice.spokenValue.contains(kind.displayName))
            #expect(notice.spokenValue.count > notice.badgeText.count)
        }
        #expect(VPNKind.openVPN.maturityNotice == nil)
    }

    /// Untested and partly-tested must be distinguishable without colour: different
    /// words AND different symbols.
    @Test func maturityStatesDifferInWordsAndInShape() {
        let untested = FeatureMaturity.untested
        let partly = FeatureMaturity.partlyVerified(checked: "x")
        #expect(untested.badgeText != partly.badgeText)
        #expect(untested.symbolName != partly.symbolName)
        #expect(FeatureMaturity.tested.badgeText != untested.badgeText)
        #expect(!untested.symbolName.isEmpty)
    }

    /// Collapse keys are derived from identifiers, never from display names — a
    /// rename must not silently un-collapse somebody's banner, and a key must never
    /// carry user data.
    @Test func collapseKeysAreStableIdentifiers() {
        for kind in FeatureMaturityRegistry.noticedKinds {
            let key = MaturityNotice.forKind(kind)!.key
            #expect(key == "kind.\(kind.rawValue)")
            #expect(!key.contains(" "))
        }
        let source = MaturityNotice.forSignInSource(id: .vault(.keeper), title: "Keeper")
        #expect(source?.key == "source.keeper")
    }
}

// MARK: - Maturity is not availability

struct MaturityVersusAvailabilityTests {

    private func facts(_ availability: LocalVaultAvailability) -> SignInSourceFacts {
        var facts = SignInSourceFacts()
        facts.vaults = Dictionary(uniqueKeysWithValues:
            LocalVaultVendor.allCases.map { ($0, availability) })
        return facts
    }

    /// The combination that must not be a contradiction: a vendor we can fetch from
    /// RIGHT NOW whose code nobody has ever proven. This is the normal state of a
    /// newly written adapter, and the app has to be able to say both things.
    @Test func aReadySourceCanStillBeUntested() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.keePassXC, availability: .ready))
        #expect(option.state == .ready)                 // availability axis
        #expect(option.maturity == .untested)           // maturity axis
        #expect(option.maturityNotice != nil)
        // And the two are spoken as separate clauses, in that order.
        let spoken = option.spokenStateAndMaturity
        #expect(spoken.hasPrefix(option.accessibilityStateValue))
        #expect(spoken.contains("Untested"))
    }

    /// And the mirror image: a vendor that is blocked on this Mac but whose code IS
    /// proven gets a fix, not a maturity notice.
    @Test func aBlockedSourceCanStillBeTested() throws {
        let option = try #require(
            SignInSourceCatalog.vaultOption(.onePassword, availability: .blocked(.appNotRunning)))
        #expect(option.state != .ready)                 // availability axis says "not now"
        #expect(option.maturity == .tested)             // maturity axis says "it works"
        #expect(option.maturityNotice == nil)
        #expect(option.spokenStateAndMaturity == option.accessibilityStateValue)
    }

    /// Changing what this Mac has must not move a maturity answer by so much as a
    /// character. Different axes, no coupling.
    @Test func availabilityNeverMovesAMaturityAnswer() {
        let states: [LocalVaultAvailability] =
            [.ready, .unchecked(.checkOwedOnUse), .blocked(.toolMissing), .blocked(.notSignedIn)]
        for vendor in LocalVaultVendor.allCases {
            let expected = FeatureMaturityRegistry.maturity(ofSource: .vault(vendor))
            for state in states {
                guard let option = SignInSourceCatalog.vaultOption(vendor, availability: state)
                else { continue }
                #expect(option.maturity == expected,
                        "\(vendor.rawValue)'s maturity changed with its availability")
            }
        }
        // A vendor the user switched off is filtered out of the list entirely — but
        // if it were asked, its maturity would still be its maturity.
        var off = facts(.ready)
        off.disabledVendors = [.keePassXC]
        #expect(off.availability(.keePassXC) == .notInstalled)     // availability axis
        #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(.keePassXC)) == .untested)
    }

    /// A pointer row makes no reliability claim of its own ("SimpleVPN can't read
    /// this app"), so it must not sprout a notice.
    @Test func pointerRowsCarryNoMaturityNotice() {
        let app = InstalledPasswordApp(bundleID: "com.example.vault", name: "Example Vault")
        let option = SignInSourceCatalog.pointer(to: app)
        #expect(option.role == .hint)
        #expect(option.maturity == .tested)   // "no notice", not "proven"
        #expect(option.maturityNotice == nil)
    }

    /// The two rows that always work are exercised by everything else in the app;
    /// Apple Passwords is not, and the copy in SignInSources.swift already says as
    /// much in prose. This pins the machine-readable version of that honesty.
    @Test func theAlwaysWorksRowsAreTestedAndApplePasswordsIsNot() {
        #expect(SignInSourceCatalog.typeEachTime().maturityNotice == nil)
        #expect(SignInSourceCatalog.saveInSimpleVPN(biometricsAvailable: true)
            .maturityNotice == nil)
        let apple = SignInSourceCatalog.applePasswords()
        #expect(apple.maturity == .untested)
        #expect(apple.maturityNotice?.subject == "Apple Passwords")
    }
}

// MARK: - The report seam

@MainActor
struct DiagnosticReportSeamTests {

    /// A stand-in for the real presenter, to prove the coordinator hands over
    /// without any call site changing.
    private final class Spy: DiagnosticReportPresenting {
        var seen: [DiagnosticReportRequest] = []
        func presentReport(_ request: DiagnosticReportRequest) { seen.append(request) }
    }

    /// Anything conforming to the seam receives the request unchanged. Written
    /// against the PROTOCOL rather than the concrete coordinator on purpose: the
    /// real one opens a window, which a unit test must not do, and the durable
    /// contract is that a request survives the hand-over intact.
    @Test func aPresenterReceivesEveryRequestUnchanged() {
        let spy = Spy()
        let presenter: any DiagnosticReportPresenting = spy
        let request = DiagnosticReportRequest(kind: .fortinet, profileID: "abc",
                                             reason: .untestedKind)
        presenter.presentReport(request)
        #expect(spy.seen == [request])
    }

    /// Every banner's report button reaches the one live presenter. The binding
    /// below IS the assertion: if the coordinator ever stops conforming, this
    /// stops compiling, which is a stronger guarantee than a runtime check (and
    /// an `is` test here is statically true, so the compiler rejects it).
    @Test func theLiveCoordinatorImplementsTheSeam() {
        let live: any DiagnosticReportPresenting = DiagnosticReportCoordinator.shared
        #expect(live === DiagnosticReportCoordinator.shared)
    }

    /// The reason vocabulary is stored in issue bodies, so renaming a case
    /// silently reclassifies past reports.
    @Test func theReasonVocabularyIsStable() {
        #expect(DiagnosticReportRequest.Reason.untestedKind.rawValue == "untestedKind")
        #expect(DiagnosticReportRequest.Reason.untestedSource.rawValue == "untestedSource")
        #expect(DiagnosticReportRequest.Reason.connectFailure.rawValue == "connectFailure")
        #expect(DiagnosticReportRequest.Reason.userInitiated.rawValue == "userInitiated")
    }
}
