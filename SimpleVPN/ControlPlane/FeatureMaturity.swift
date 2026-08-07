// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FeatureMaturity.swift
//  THE registry of what has actually been exercised, and the only place the
//  answer is written down. SimpleVPN ships sixteen VPN kinds and a growing list
//  of sign-in sources, and it can genuinely be tried against three of the kinds
//  and one of the password apps. Pretending otherwise — one uniform editor per
//  kind, every row looking equally proven — implies a confidence nobody has
//  earned, so the app says so instead.
//
//  THE ONE RULE THIS FILE EXISTS TO ENFORCE: flipping something to tested is a
//  ONE-LINE change here, and NO view changes anywhere. Every banner, badge,
//  spoken sentence and report body is derived from these two tables. If you find
//  yourself editing a view to change a maturity claim, the derivation has been
//  broken and `FeatureMaturityTests` should have caught it.
//
//  MATURITY IS NOT AVAILABILITY. They are orthogonal axes and conflating them
//  would be the obvious mistake:
//   • AVAILABILITY (`LocalVaultAvailability`, four states) is about THIS Mac right
//     now — is the tool installed, running, signed in, reachable. It changes when
//     the user installs something. It is a live probe.
//   • MATURITY is about OUR CONFIDENCE in the code — has anyone ever seen it work
//     end to end. It changes when a human reports a result, and only ever in this
//     file. It is a constant.
//  A source can be `.ready` (fetchable this second) AND `.untested` (nobody has
//  proven it), and that combination is not a contradiction — it is the normal
//  state of a newly written adapter on the machine of the person who wrote it.
//  Neither table consults the other; nothing here reads a probe.
//
//  HONESTY, NOT ALARM. "Untested" is not "broken" and must never read as a
//  defect: the code is written and reviewed, we simply have no gateway or vault
//  here to run it against, and it may well work. The wording below is deliberately
//  calm, says what would clear the label, and asks for the one thing that actually
//  clears it — somebody telling us what happened.
//

import Foundation

// MARK: - The three states

/// How much confidence there is in a feature, and nothing else.
///
/// Three states, not two, because WireGuard is honestly neither: its handshake is
/// exercised against real vendored wireguard-go in the test suite, but no live
/// tunnel has ever carried a packet. Calling that "tested" would be a lie and
/// calling it "untested" would throw away a real result, so it gets its own state
/// carrying the one clause that says what WAS checked.
nonisolated enum FeatureMaturity: Sendable, Equatable, Hashable {
    /// Exercised end to end against the real thing, by a human, on a real server.
    case tested
    /// Part of the path is genuinely proven; `checked` is the clause that says
    /// which part, in plain English, ready to drop into a sentence.
    case partlyVerified(checked: String)
    /// Written and reviewed; never run against the real thing.
    case untested

    var isTested: Bool { self == .tested }
    /// Does this warrant a banner and a badge? Everything that is not `.tested`.
    var needsNotice: Bool { !isTested }

    /// The badge word. Short enough for a list row, honest enough to stand alone.
    var badgeText: String {
        switch self {
        case .tested: "Tested"
        case .partlyVerified: "Partly tested"
        case .untested: "Untested"
        }
    }

    /// Paired with the badge word so colour is never the only carrier
    /// (Differentiate Without Color, AGENTS.md). A test tube for "never run"; a
    /// half-full flask for "some of it has been".
    var symbolName: String {
        switch self {
        case .tested: "checkmark.seal"
        case .partlyVerified: "flask.fill"
        case .untested: "testtube.2"
        }
    }
}

// MARK: - The registry

/// The two tables. One line per VPN kind, one line per sign-in source.
///
/// Deliberately dictionaries rather than `switch`es: a dictionary literal is one
/// grep-able line per subject, a diff that flips one is unambiguous, and
/// `FeatureMaturityTests` asserts totality so a new kind cannot be quietly
/// omitted (a missing entry is treated as `.untested`, which is the safe default
/// — never silently "tested").
nonisolated enum FeatureMaturityRegistry {

    // MARK: VPN kinds

    /// Tested here: `openVPN` (GR Lab, the first target config), `tailscale` and
    /// `ssh`. Everything else needs a gateway this project does not have.
    ///
    /// The seven OpenConnect SSL-VPN kinds each need a DIFFERENT real gateway —
    /// a FortiGate result says nothing about GlobalProtect — so they clear one
    /// line at a time and must never be flipped as a group.
    ///
    /// `sshNetworkTunnel` IS NOT `ssh`. See VPNKind.swift: different transport,
    /// different editor, different mediator classification. "SSH is tested" is a
    /// claim about the `-D`/`-L` subprocess kind and does not reach the netstack
    /// one, which has its own utun, its own routes and its own userspace TCP/IP.
    static let vpnKinds: [VPNKind: FeatureMaturity] = [
        .openVPN:          .tested,
        .tailscale:        .tested,
        .ssh:              .tested,
        .wireGuard:        .partlyVerified(checked: "its handshake has been completed against real wireguard-go, so the keys and the crypto are known good"),
        .ikev2:            .untested,
        .ipsec:            .untested,
        .l2tp:             .untested,
        .fortinet:         .untested,
        .f5apm:            .untested,
        .ciscoAnyConnect:  .untested,
        .globalProtect:    .untested,
        .juniper:          .untested,
        .pulse:            .untested,
        .arrayNetworks:    .untested,
        .proxyTunnel:      .untested,
        .sshNetworkTunnel: .untested,
    ]

    /// Sign-in sources, keyed by the chooser row's own id so a row and its
    /// maturity can never drift apart.
    ///
    /// Only 1Password is installed on the machine this was written on, so it is
    /// the only vault claimed as tested. Typing and the Apple keychain are
    /// exercised constantly by every other feature. Apple Passwords is NOT
    /// claimed: macOS decides what its AutoFill menu offers in our fields and
    /// nobody has watched that happen (SignInSources.swift says the same thing in
    /// its own copy — this is that honesty made machine-readable).
    ///
    /// Pointer rows (`.otherApp`) are absent on purpose: a row that says "we
    /// can't read this app" makes no reliability claim, so there is nothing to
    /// qualify. `maturity(ofSource:)` returns `.tested` for them, meaning "no
    /// notice", not "proven".
    static let signInSources: [SignInSourceID: FeatureMaturity] = [
        .typeEachTime:              .tested,
        .saveInSimpleVPN:           .tested,
        .applePasswords:            .untested,
        .vault(.onePassword):       .tested,
        .vault(.keePassXC):         .untested,
        .vault(.keeper):            .untested,
        // Newly written, and exactly the case this registry exists for: the wire
        // formats were taken from Bitwarden's own published client source and are
        // covered by fixture tests, but no real vault has ever answered — Bitwarden
        // is not installed on the machine this was built on.
        .vault(.bitwarden):         .untested,
        // Dashlane. WHAT WAS PROVEN: the argument list (`--output json`, never
        // `clipboard`), the JSON reader against fixtures shaped from Dashlane's own
        // `passwords.ts`, the picker, the `dcli status` parse for all three of its
        // states, the four availability states, and the refusal to spawn a fetch
        // against a locked vault. WHAT WAS NOT: anything at all involving a real
        // Dashlane. `dcli` is not installed on the machine this was built on, no
        // device has ever been registered, no vault has ever answered, no Touch ID
        // sheet has ever been raised by it, and nobody has connected a VPN with it.
        .vault(.dashlane):          .untested,
        // The KeePass file source, covering KeePassXC-as-a-file, Strongbox and
        // KeePassium. Header parsing is proven against real KDBX3 and KDBX4 bytes
        // built from KeePassXC's own format constants, but no database has ever
        // been unlocked: none of the three apps, and no keepassxc-cli, exists on
        // the machine this was built on.
        .vault(.keePassFile):       .untested,
        // The GPG round trip IS proven — a throwaway key, a throwaway store and the
        // real reader, in both pinentry modes — but no real store belonging to a real
        // person has ever been read, and nobody has connected a VPN with it.
        .vault(.passwordStore):     .untested,
        // LastPass. WHAT WAS PROVEN: every flag, every state transition and every
        // failure sentence is driven by fixtures taken from `lastpass/lastpass-cli`'s
        // own source — `cmd-status.c` for the exit codes, `agent.c` for the agent and
        // the on-disk key, `cmd-show.c` for the "Multiple matches found." exit-zero
        // trap, `json-format.c` for the reply shape and for the absence of any
        // verification code, `lpass.c` for the alias expansion the clipboard guard
        // exists to catch. WHAT WAS NOT: no `lpass` and no LastPass account exists on
        // the machine this was built on, so no real vault has ever answered, no agent
        // has ever been asked for a key, and nobody has connected a VPN with it.
        .vault(.lastPass):          .untested,
        // Proton Pass. PROVEN: the addressing rules, the ID shape (Proton's own
        // `is_id` — 88 characters ending "=="), the exact-title match, the
        // duplicate-title refusal, the four availability states, and every failure
        // classification — all against fixtures whose strings are quoted from Proton's
        // own GPL-3 source (see SimpleVPNTests/Credentials/ProtonPassTests.swift, which
        // cites the file and line per fixture). NOT PROVEN, and it is the larger half:
        // no `pass-cli` has ever run here, no Proton account exists, and no item has
        // ever been read — the machine this was built on has neither the tool nor the
        // app. The entitlement state in particular has never been observed: Proton
        // checks the plan inside `pass-cli login`, which SimpleVPN deliberately never
        // runs, so that sentence is recognised from the vendor's source rather than
        // from a transcript.
        .vault(.protonPass):        .untested,
        // WHAT WAS PROVEN: the argument building, the config-file key probe, the JSON
        // parsing, the passphrase store's three tiers and the whole failure taxonomy,
        // against fixtures taken from `go-passbolt-cli`'s own source and its own
        // testdata — including that `--tlsSkipVerify` can never be emitted, that no
        // secret can reach argv or the child's environment, and that a cancelled Touch
        // ID sheet is never mistaken for a rejected sign-in.
        // WHAT WAS NOT: anything involving a server, and anything involving a real
        // fingerprint. Passbolt is not installed on the machine this was built on and
        // there is no Passbolt server here, so no sign-in has ever completed, no
        // certificate has ever been verified for real, no Touch ID prompt has ever been
        // answered, and no resource has ever come back. Even the states this feed most
        // wants confirmed — a private certificate authority, and two servers where one
        // is broken — are fixture-level only.
        .vault(.passbolt):          .untested,
    ]

    // MARK: Features that are neither a VPN kind nor a sign-in source

    /// A capability whose confidence is worth stating and which belongs to no kind
    /// and no vault. The third table, added because the whole-configuration
    /// export/import has exactly the shape this registry exists for: one half of it
    /// is proven here by construction, and the other half cannot be.
    nonisolated enum AppFeature: String, Sendable, CaseIterable {
        /// Settings ▸ General ▸ Export & Import (Docs/SecretsAndSync.md §5, step 1).
        case configurationTransfer

        var title: String {
            switch self {
            case .configurationTransfer: "Exporting and importing settings"
            }
        }
    }

    /// WHAT WAS PROVEN for `configurationTransfer`, and it is most of it: the file
    /// format in both encodings, the round trip of every VPN kind, that no secret
    /// reaches either encoding even when the exporter is handed one, that a
    /// verification-weakening file is refused, and the diff the confirmation shows.
    /// All of it in `ConfigDocumentTests`.
    ///
    /// WHAT WAS NOT: applying an imported file to REAL profiles. Adding a VPN goes
    /// through `NETunnelProviderManager.saveToPreferences`, which needs the system
    /// extension approved and a live macOS prompt, so no test can reach it — and no
    /// file written on one Mac has ever been imported on another, because there is
    /// one Mac here. `.partlyVerified` rather than `.untested` precisely because
    /// pretending the format is unproven would be as dishonest in the other
    /// direction.
    static let features: [AppFeature: FeatureMaturity] = [
        .configurationTransfer: .partlyVerified(
            checked: "the file itself is proven \u{2014} both encodings round-trip every kind of VPN, "
                + "no secret can reach either of them, and a file that would weaken certificate or "
                + "host-key checking is refused"),
    ]

    // MARK: VPN providers

    /// Reading a VPN company's published server list (`Docs/ServiceBundles.md`).
    ///
    /// A FOURTH table rather than four `AppFeature` cases, for the reason the
    /// sign-in table exists separately: these are per-vendor claims about somebody
    /// else's service, they will be cleared one at a time by different people, and a
    /// Mullvad result says nothing whatever about IPVanish.
    ///
    /// Mullvad is `.partlyVerified` and the other two are `.untested`, and the
    /// asymmetry is exactly the honest one. WHAT WAS PROVEN FOR MULLVAD: the live
    /// list was fetched from `api.mullvad.net/www/relays/all/` while this was
    /// written, all 580 relays parsed, and every field the parser reads is pinned by
    /// a test against a row copied verbatim out of that payload. WHAT WAS NOT: no
    /// tunnel has ever been raised to a relay chosen this way, because that needs a
    /// Mullvad account and a registered key, and SimpleVPN registers nothing.
    ///
    /// NordVPN and IPVanish had their payloads read here too — Nord's `/v1/servers`
    /// and two of its CDN configs, and all 3,576 of IPVanish's `.ovpn` files — but
    /// neither account exists on the machine this was built on, so nobody has
    /// connected anything with either list. Proton VPN is absent on purpose: its row
    /// states an absence rather than making a claim (`maturity(ofProvider:)` returns
    /// `.tested`, meaning "no notice", for a provider that offers nothing).
    static let providers: [VPNServiceProviderID: FeatureMaturity] = [
        .mullvad: .partlyVerified(
            checked: "its published list has been fetched and read for real \u{2014} every relay in it "
                + "parsed, and every field SimpleVPN uses is pinned by a test against Mullvad\u{2019}s "
                + "own payload"),
        .nordVPN: .untested,
        .ipVanish: .untested,
    ]

    // MARK: Lookups

    /// A kind's maturity. An unregistered kind is `.untested` — the safe default:
    /// a new kind arrives unproven, and the test suite fails until it is listed.
    ///
    /// `table` exists so `FeatureMaturityTests` can hand in a table with ONE entry
    /// flipped and prove that the flip is the whole change — that every banner,
    /// badge and spoken sentence follows without a view edit. Production code never
    /// passes it, and there is no setter: a maturity claim is still written in
    /// exactly one place.
    static func maturity(of kind: VPNKind,
                         in table: [VPNKind: FeatureMaturity]? = nil) -> FeatureMaturity {
        (table ?? vpnKinds)[kind] ?? .untested
    }

    /// A sign-in source's maturity.
    ///
    /// The default for an unclaimed row depends on what KIND of row it is, and the
    /// asymmetry is deliberate:
    ///  • a VENDOR row (`.vault`) defaults to `.untested`. A newly written adapter
    ///    arrives unproven, and the one mistake that actually matters here is
    ///    claiming otherwise by omission — Bitwarden's adapter landed after this
    ///    registry did, and this is the default that would have kept the app honest
    ///    in the gap.
    ///  • anything else defaults to `.tested`, i.e. NO notice: pointer rows say in
    ///    their own words that we can't read that app, and a future row that makes
    ///    no reliability claim must not sprout a banner just because nobody added a
    ///    line for it.
    /// `FeatureMaturityRegistryTests` asserts every vendor is listed regardless, so
    /// the vendor default is a safety net rather than a place to leave things.
    static func maturity(ofSource id: SignInSourceID,
                         in table: [SignInSourceID: FeatureMaturity]? = nil) -> FeatureMaturity {
        if let claim = (table ?? signInSources)[id] { return claim }
        if case .vault = id { return .untested }
        return .tested
    }

    /// A feature's maturity. Unlisted is `.untested`, the same safe default as a
    /// VPN kind's: a new capability arrives unproven.
    static func maturity(ofFeature feature: AppFeature,
                         in table: [AppFeature: FeatureMaturity]? = nil) -> FeatureMaturity {
        (table ?? features)[feature] ?? .untested
    }

    /// A provider's maturity.
    ///
    /// The default is `.tested` — meaning NO NOTICE, not "proven" — and that is the
    /// same asymmetry the sign-in table draws for a pointer row. A provider absent
    /// from the table is one SimpleVPN cannot read at all (Proton VPN), so its row
    /// makes no reliability claim and has nothing to qualify; sprouting an "untested"
    /// banner on a row whose whole content is "this does not work here" would be
    /// noise on top of a refusal. `FeatureMaturityProviderTests` asserts every
    /// provider we INTEND to read (`blocked == nil`) is listed regardless, so this
    /// default cannot be used to leave a real adapter unclaimed — and the predicate
    /// is deliberately intent rather than `canFetch`, which is additionally false
    /// while a CA fingerprint is still to be pinned.
    static func maturity(ofProvider id: VPNServiceProviderID,
                         in table: [VPNServiceProviderID: FeatureMaturity]? = nil)
        -> FeatureMaturity {
        (table ?? providers)[id] ?? .tested
    }

    /// Every kind that still carries a notice, in `VPNKind.allCases` order. Used by
    /// the tests, and available to anything that wants to state how much of this app
    /// is unproven in one place (a diagnostic report, an About-window line) without
    /// deriving that list for itself.
    static var noticedKinds: [VPNKind] {
        VPNKind.allCases.filter { maturity(of: $0).needsNotice }
    }
}

// MARK: - Convenience on the subjects themselves

// The app target defaults to MainActor isolation; a maturity claim is a constant
// and every consumer (views, tests, the report body) should be able to read it
// from anywhere, so both extensions are explicitly nonisolated.
nonisolated extension VPNKind {
    /// This kind's maturity. One hop to the registry — never a switch of its own.
    var maturity: FeatureMaturity { FeatureMaturityRegistry.maturity(of: self) }

    /// The notice to show for this kind, or nil when it is tested.
    var maturityNotice: MaturityNotice? { MaturityNotice.forKind(self) }
}

nonisolated extension VPNServiceProvider {
    /// This provider's maturity. One hop to the registry, like every other subject.
    var maturity: FeatureMaturity { FeatureMaturityRegistry.maturity(ofProvider: id) }

    /// The notice for this provider, or nil when there is nothing to qualify.
    var maturityNotice: MaturityNotice? { MaturityNotice.forProvider(self) }
}

nonisolated extension SignInSourceOption {
    /// This row's maturity.
    ///
    /// A computed property over the registry rather than a stored field, and
    /// deliberately so: the catalog that builds these options is pure data over
    /// live probes (availability), and a stored maturity would invite somebody to
    /// set it from a probe result. There is exactly one place a maturity claim is
    /// written, and it is `FeatureMaturityRegistry`.
    var maturity: FeatureMaturity { FeatureMaturityRegistry.maturity(ofSource: id) }

    /// The notice for this row, or nil when it is tested.
    var maturityNotice: MaturityNotice? {
        MaturityNotice.forSignInSource(id: id, title: title)
    }

    /// What VoiceOver reads as the row's value: its live state, then — when there
    /// is one — its maturity. Two different facts about the row, in one sentence,
    /// in that order: what it can do NOW matters more than how proven it is.
    var spokenStateAndMaturity: String {
        guard let notice = maturityNotice else { return accessibilityStateValue }
        return "\(accessibilityStateValue). \(notice.spokenValue)"
    }
}

// MARK: - The copy, derived once

/// Everything a banner or a badge needs to say, derived from a maturity and its
/// subject. Built HERE rather than in a view so the wording exists once, is
/// unit-testable without SwiftUI, and can be dropped verbatim into a report body.
nonisolated struct MaturityNotice: Sendable, Equatable {
    /// What is unproven, named the way the user sees it ("Palo Alto
    /// GlobalProtect", "Keeper").
    var subject: String
    var maturity: FeatureMaturity
    /// Stable key for remembering that THIS subject's banner was collapsed —
    /// derived from the subject's own identifier, never from its display name, so
    /// renaming "IKEv2" doesn't silently un-collapse it. Never a user's data.
    var key: String
    /// The banner's bold first line.
    var title: String
    /// The paragraph under it: what untested means, what to expect, that it may
    /// well work, and what clears the label.
    var detail: String
    /// The list-row badge and the collapsed banner: one or two words.
    var badgeText: String { maturity.badgeText }
    var symbolName: String { maturity.symbolName }

    /// The whole banner as one sentence, for the container's accessibility label
    /// — the banner holds buttons, so it is a `.contain` element whose own label
    /// has to carry everything a sighted reader gets.
    var spokenSummary: String { "\(title). \(detail)" }

    /// The short form appended to a row's `accessibilityValue` in a list, where
    /// there is no room for the paragraph. Still a full clause, never just the
    /// badge word on its own — "Untested" alone means nothing spoken aloud.
    var spokenValue: String {
        switch maturity {
        case .tested: ""
        case .partlyVerified:
            "Only partly tested \u{2014} \(subject) has not been proven end to end here"
        case .untested:
            "Untested \u{2014} nobody has confirmed \(subject) working yet"
        }
    }

    // MARK: Factories — one per class of subject

    /// A VPN kind. nil when the kind is tested: there is nothing to say, and a
    /// nil is what makes "no banner" the structural default rather than a
    /// condition somebody has to remember to write.
    static func forKind(_ kind: VPNKind,
                        in table: [VPNKind: FeatureMaturity]? = nil) -> MaturityNotice? {
        let maturity = FeatureMaturityRegistry.maturity(of: kind, in: table)
        guard maturity.needsNotice else { return nil }
        let name = kind.displayName
        switch maturity {
        case .tested:
            return nil
        case .partlyVerified(let checked):
            return MaturityNotice(
                subject: name, maturity: maturity, key: "kind.\(kind.rawValue)",
                title: "\(name) is only partly tested",
                detail: "Part of it is proven: \(checked). But no \(name) tunnel has ever carried "
                    + "real traffic in SimpleVPN \u{2014} there is no \(name) server here to try. "
                    + "The rest of the code is written and reviewed, and it may well work. If a "
                    + "connect fails it should say so and stop, not disturb anything else on this "
                    + "Mac. Telling us what happened is what gets this notice removed.")
        case .untested:
            return MaturityNotice(
                subject: name, maturity: maturity, key: "kind.\(kind.rawValue)",
                title: "\(name) has never been tested",
                detail: "The \(name) code is written and reviewed, but nobody has connected "
                    + "SimpleVPN to a real \(name) server \u{2014} there isn\u{2019}t one here to "
                    + "try. So this may well work, and it may not. If it fails it should say why "
                    + "and stop, rather than disturb anything else on this Mac. Whichever happens, "
                    + "telling us is what gets this notice removed \u{2014} a single report is "
                    + "usually enough.")
        }
    }

    /// A feature that belongs to no VPN kind and no vault. Same shape as the two
    /// factories below it, so a banner or a caption is derived rather than written:
    /// flipping the claim stays a one-line change in the registry.
    static func forFeature(_ feature: FeatureMaturityRegistry.AppFeature,
                           in table: [FeatureMaturityRegistry.AppFeature: FeatureMaturity]? = nil)
        -> MaturityNotice? {
        let maturity = FeatureMaturityRegistry.maturity(ofFeature: feature, in: table)
        guard maturity.needsNotice else { return nil }
        let name = feature.title
        switch maturity {
        case .tested:
            return nil
        case .partlyVerified(let checked):
            return MaturityNotice(
                subject: name, maturity: maturity, key: "feature.\(feature.rawValue)",
                title: "\(name) is only partly tested",
                detail: "Part of it is proven: \(checked). What has never been done here is the other "
                    + "half \u{2014} taking a file written on one Mac and applying it on another, because "
                    + "there is only one Mac. It should work, and if it doesn\u{2019}t it will say why and "
                    + "change nothing. Telling us what happened is what gets this notice removed.")
        case .untested:
            return MaturityNotice(
                subject: name, maturity: maturity, key: "feature.\(feature.rawValue)",
                title: "\(name) has never been tested",
                detail: "The code is written and reviewed, but nobody has used it for real yet. It may "
                    + "well work. If it doesn\u{2019}t it should say why and change nothing. Telling us what "
                    + "happened is what gets this notice removed.")
        }
    }

    /// A VPN provider whose published server list SimpleVPN reads.
    ///
    /// The copy differs from the sign-in factory in one deliberate way: it names
    /// **what was read** rather than what was installed, because that is the honest
    /// distinction here. Reading a provider's list is not connecting to that
    /// provider, and a notice that blurred the two would let "we fetched Mullvad's
    /// list" quietly become "Mullvad works".
    static func forProvider(_ provider: VPNServiceProvider,
                            in table: [VPNServiceProviderID: FeatureMaturity]? = nil)
        -> MaturityNotice? {
        let maturity = FeatureMaturityRegistry.maturity(ofProvider: provider.id, in: table)
        guard maturity.needsNotice else { return nil }
        let name = provider.displayName
        switch maturity {
        case .tested:
            return nil
        case .partlyVerified(let checked):
            return MaturityNotice(
                subject: name, maturity: maturity, key: "provider.\(provider.id.rawValue)",
                title: "\(name)\u{2019}s server list is only partly tested",
                detail: "Part of it is proven: \(checked). What has never happened here is a "
                    + "connection to a \(name) server chosen from that list \u{2014} that needs a "
                    + "\(name) account, and SimpleVPN never signs in to a provider. The list may "
                    + "well be exactly right. Telling us what happened is what gets this notice "
                    + "removed.")
        case .untested:
            return MaturityNotice(
                subject: name, maturity: maturity, key: "provider.\(provider.id.rawValue)",
                title: "\(name)\u{2019}s server list has never been tested",
                detail: "The code that reads \(name)\u{2019}s published server list is written and "
                    + "reviewed, but nobody has connected to a \(name) server with it \u{2014} "
                    + "there is no \(name) account on the machine this was built on. It may well "
                    + "work. If the list comes back wrong, nothing else changes: your existing "
                    + "servers are untouched and you can still type one in. Telling us what "
                    + "happened is what gets this notice removed.")
        }
    }

    /// A sign-in source row. `title` comes from the row itself so the notice
    /// names the vendor exactly as the row does.
    static func forSignInSource(id: SignInSourceID, title: String,
                                in table: [SignInSourceID: FeatureMaturity]? = nil)
        -> MaturityNotice? {
        let maturity = FeatureMaturityRegistry.maturity(ofSource: id, in: table)
        guard maturity.needsNotice else { return nil }
        switch maturity {
        case .tested:
            return nil
        case .partlyVerified(let checked):
            return MaturityNotice(
                subject: title, maturity: maturity, key: "source.\(id.rawValue)",
                title: "\(title) is only partly tested",
                detail: "Part of it is proven: \(checked). The rest is written and reviewed but "
                    + "has never fetched a real sign-in here. It may well work. If it doesn\u{2019}t, "
                    + "you can always type your sign-in instead \u{2014} nothing else breaks. "
                    + "Telling us what happened is what gets this notice removed.")
        case .untested:
            return MaturityNotice(
                subject: title, maturity: maturity, key: "source.\(id.rawValue)",
                title: "Reading from \(title) has never been tested",
                detail: "The code that talks to \(title) is written and reviewed, but nobody has "
                    + "fetched a real sign-in from it \u{2014} \(title) isn\u{2019}t installed on "
                    + "the machine this was built on. It may well work. If it doesn\u{2019}t, "
                    + "nothing is lost: you can type your sign-in instead, or pick another source. "
                    + "Telling us what happened is what gets this notice removed.")
        }
    }
}
