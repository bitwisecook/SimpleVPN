// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceAvailability.swift
//  The live half of the sign-in chooser: what is ACTUALLY on this Mac right now.
//  The rules that turn these facts into rows are pure and live in
//  SignInSources.swift; this file only gathers.
//
//  Two speeds, because sources appear and disappear while the app is running
//  (1Password gets quit, KeePassXC gets launched, someone signs in to Keeper
//  Commander in Terminal):
//
//   • `refresh()` — cheap and synchronous: bundle lookups, a socket stat, a file
//     check per CLI. Safe to call on a poll while the chooser is on screen, and
//     it is what makes the list render with no flicker: every row that will ever
//     appear is decided here, before the first frame.
//   • `deepScan()` — the expensive pass (a 1Password helper spawn, a Keeper
//     `whoami`). Once per launch, or when the user asks. It only ever REFINES a
//     row's state; it never adds or removes rows, so nothing moves under the
//     pointer.
//
//  The installed-app sweep is cached for the process: apps are not installed
//  twice a second, and the sweep reads a few hundred Info.plists.
//

import Foundation
import AppKit
import os

@Observable
final class SignInSourceAvailability {

    /// App-wide: every surface asking "what can this Mac do?" gets one answer,
    /// and one set of probes.
    static let shared = SignInSourceAvailability()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "sign-in-sources")

    /// The gathered facts. `allowsPasswordSave` is per-VPN, so callers overlay it
    /// with `facts(allowsPasswordSave:)` rather than it being stored here.
    private(set) var facts = SignInSourceFacts()
    /// True once the cheap pass has run at least once.
    ///
    /// It is `facts.scanned` — one flag, read from whichever of the two a caller
    /// happens to hold. It used to live only here, which meant a snapshot of the facts
    /// travelled to a view WITHOUT it and every vendor in that snapshot read as
    /// `.notInstalled`; see `SignInSourceFacts.scanned`.
    var scanned: Bool { facts.scanned }
    private var deepScanned = false
    private var deepScanning = false

    /// Per-vendor enable/disable and the configured paths. Injectable so a test can
    /// drive the filtering without touching the real defaults domain.
    let settings: SignInSourceSettingsStore

    init(settings: SignInSourceSettingsStore = .shared) {
        self.settings = settings
    }

    /// Vendors whose tool discovery found but the execution allow-list declines to
    /// run. One entry per vendor, carrying the path worth showing.
    private static func toolsOutsideAllowList() -> [LocalVaultVendor: String] {
        var out: [LocalVaultVendor: String] = [:]
        for vendor in LocalVaultVendor.allCases {
            for tool in ToolCatalog.tools(for: vendor) {
                if let path = LocalVaultRegistry.toolFoundOutsideAllowList(tool.name) {
                    out[vendor] = path
                    break
                }
            }
        }
        return out
    }

    /// This VPN's view of the facts: everything gathered, plus the one fact only
    /// the profile knows.
    func facts(allowsPasswordSave: Bool) -> SignInSourceFacts {
        var out = facts
        out.allowsPasswordSave = allowsPasswordSave
        return out
    }

    // MARK: The cheap pass

    /// Re-read everything a file check can answer. Cheap enough for a 2-second
    /// poll; no subprocesses, no prompts, no network.
    func refresh() {
        var next = SignInSourceFacts()
        // Set FIRST and unconditionally: every return path below publishes `next`, and
        // a fact set that has been gathered but forgot to say so is the bug this flag
        // exists to make impossible.
        next.scanned = true
        next.biometricsAvailable = Self.cachedBiometrics()
        // Which vendors the user (or their organization) has switched off.
        next.disabledVendors = settings.disabledVendors
        // THE MASTER SWITCH, honoured absolutely. Off means SimpleVPN does not look
        // for password managers on this Mac at all — no vendor probes, no
        // inventory, no discovery map — and the chooser is left with the ways in
        // that need no detection: typing it, the Apple keychain, Apple Passwords.
        // Anything less than that would be a scan wearing a different name.
        guard settings.discoveryEnabled else {
            if next != facts { facts = next }
            return
        }
        // LEVEL 2 first: the configured vaults, then a cheap scan of each. The
        // vendor row is the best of them (`quickScanAll(instances:)` says why), so a
        // missing work database never hides a ready personal one.
        next.instances = Dictionary(uniqueKeysWithValues: LocalVaultVendor.allCases.map {
            ($0, settings.instances(for: $0))
        }.filter { !$0.1.isEmpty })
        let probed = LocalVaultRegistry.quickScanAll(instances: next.instances)
        next.vaults = probed.vendors
        next.vaultInstances = probed.instances
        // For the vendors whose tool is installed somewhere we won't run from: the
        // path, so the banner can name it instead of claiming it isn't installed.
        next.toolsFoundOutsideAllowList = Self.toolsOutsideAllowList()
        // The pointer list is swept once, in the deep pass: it reads a few
        // hundred Info.plists, which is not something to do on a 2-second poll —
        // and apps are not installed twice a second. Carried across untouched.
        next.otherApps = facts.otherApps
        // Keep whatever the deep scan has already established: it knows things a
        // file check cannot (an old 1Password, a signed-out Commander), and
        // throwing that away on a poll would make rows flip back and forth.
        if deepScanned {
            for (vendor, deep) in facts.vaults where Self.deepWins(quick: next.vaults[vendor], deep: deep) {
                next.vaults[vendor] = deep
            }
        }
        // Only publish a CHANGE. Observation doesn't diff, so assigning an equal
        // value on every tick of a 2-second poll would redraw the chooser twice a
        // second for ever — and a list that redraws under the pointer is how a
        // radio row gets clicked by accident.
        if next != facts { facts = next }
    }

    /// A deep answer outranks a cheap one only while the cheap one still agrees
    /// the vendor is here at all: a quit 1Password must be able to overrule a
    /// remembered "ready".
    private static func deepWins(quick: LocalVaultAvailability?, deep: LocalVaultAvailability) -> Bool {
        // `.unscanned` on either side is not an answer, so it can neither be
        // overruled nor do the overruling — the cheap pass has not run.
        guard let quick, quick.isAnswered, deep.isAnswered,
              quick != .notInstalled, deep != .notInstalled else { return false }
        // The cheap pass owns "the app isn't running" / "the socket is gone";
        // the deep pass owns "too old", "not signed in" and "signed in but locked"
        // — the three a file check cannot see. Without `vaultLocked` here, a
        // Bitwarden row would flip back to "we haven't checked" on the next 2-second
        // poll and its unlock instructions would blink in and out.
        switch deep {
        case .blocked(.needsUpdate), .blocked(.notSignedIn), .blocked(.vaultLocked), .ready:
            return quick != .blocked(.appNotRunning) && quick != .blocked(.integrationOff)
        default:
            return false
        }
    }

    // MARK: The expensive pass

    /// Re-run the expensive probes while a vendor is waiting on the user, so
    /// following an enablement banner flips its row to ready WITHOUT restarting
    /// the app. Only while something is actually blocked or unproven, and no more
    /// often than `interval`: a Keeper `whoami` starts Python, which is not
    /// something to do every two seconds.
    ///
    /// The cheap facts (an app quitting, a socket appearing, a CLI being
    /// installed) are already picked up by `refresh()` on the caller's poll; this
    /// covers only what needs a subprocess.
    func recheckIfDue(interval: TimeInterval = 15) async {
        guard deepScanned, !deepScanning else { return }
        // Nothing to re-check when everything is either working or absent.
        guard facts.vaults.values.contains(where: { availability in
            switch availability {
            case .blocked, .unchecked: true
            // `.unscanned` cannot appear in this dictionary (it is the ABSENCE of an
            // entry, not an entry), and a subprocess is the wrong answer to it anyway:
            // what an unscanned Mac needs is the cheap pass, which the caller's poll
            // already runs.
            case .ready, .notInstalled, .unscanned: false
            }
        }) else { return }
        let now = Date()
        if let last = lastDeepScan, now.timeIntervalSince(last) < interval { return }
        await deepScan(force: true)
    }

    private var lastDeepScan: Date?

    /// Run the probes that cost a subprocess. Idempotent per launch unless
    /// `force` — the chooser calls it once when it appears, and "Check Again"
    /// forces it.
    func deepScan(force: Bool = false) async {
        if deepScanning { return }
        if deepScanned && !force { return }
        deepScanning = true
        defer { deepScanning = false }
        if !scanned { refresh() }
        // The master switch again: this pass is the expensive one (an Applications
        // sweep and a vendor subprocess), so it must not happen at all when the
        // user has said not to look.
        guard settings.discoveryEnabled else { return }
        if facts.otherApps.isEmpty { facts.otherApps = Self.installedApps() }
        // A switched-off vendor is not probed. Spawning a vendor's tool — which may
        // put ITS OWN approval or Touch ID dialog on screen — for a source we have
        // been told not to offer would be an unexplained prompt out of nowhere.
        let refined = await LocalVaultRegistry.deepScanAll(
            quick: facts.vaults, skipping: facts.disabledVendors)
        facts.vaults = refined
        // The version probe rides here too: it costs a subprocess, and it only ever
        // runs against a path the execution allow-list already accepts.
        await refreshToolVersions()
        deepScanned = true
        lastDeepScan = Date()
        Self.log.log("sign-in sources: \(Self.summary(refined), privacy: .public)")
        ToolDiscovery.logSummary(discoveries)
    }

    // MARK: The discovery map

    /// What was found for every tool in the catalogue — one answer, shared by the
    /// Settings pane, the enablement banners and any diagnostic report, so there is
    /// no second scan to drift from this one.
    ///
    /// Versions are filled in by `refreshToolVersions()` (deep pass only) and are
    /// only ever asked of a binary the execution allow-list accepts.
    private(set) var discoveries: [String: DiscoveredTool] = [:]

    /// Ask each runnable tool its version. Sequential, and only for `chosen` paths —
    /// a tool we would refuse to run keeps its `.unknown(why:)` and says why instead.
    ///
    /// A version is measured ONCE per path, not once per pass. `recheckIfDue` runs
    /// this every fifteen seconds while a vendor is waiting on the user, and probing
    /// the whole catalogue each time would spawn a dozen processes a minute for a
    /// number that cannot have changed — one of which starts a Python interpreter.
    /// `ToolDiscovery.cachedMap()` carries a known version forward while its path is
    /// unchanged, so this loop finds nothing left to do on the second pass.
    private func refreshToolVersions() async {
        for tool in ToolCatalog.all {
            let map = ToolDiscovery.cachedMap()
            guard let entry = map[tool.name], entry.chosen != nil, !entry.versionProbed
            else { continue }
            let version = await ToolDiscovery.probeVersion(tool, discovered: entry)
            ToolDiscovery.recordVersion(tool: tool.name, version: version)
        }
        // Republish so the pane redraws with whatever was learned. One map, read from
        // the cache, so this can never disagree with what the banners see.
        discoveries = ToolDiscovery.cachedMap()
    }

    /// One log line, vendor states only — never a path, an account or a secret.
    private static func summary(_ vaults: [LocalVaultVendor: LocalVaultAvailability]) -> String {
        LocalVaultVendor.allCases.map { vendor in
            let state: String
            switch vaults[vendor] ?? .notInstalled {
            // Logged distinctly on purpose. The bug this case was added for was
            // diagnosed from a log line that said "absent" about a vendor that was
            // running perfectly — "unscanned" would have ended that hunt at the
            // first line.
            case .unscanned: state = "unscanned"
            case .notInstalled: state = "absent"
            case .blocked(let block): state = "blocked:\(block.rawValue)"
            // The ceiling rides the log line: "unchecked" alone cannot tell a
            // maintainer whether a check is coming.
            case .unchecked(let ceiling): state = "unchecked:\(ceiling.rawValue)"
            case .ready: state = "ready"
            }
            return "\(vendor.rawValue)=\(state)"
        }.joined(separator: " ")
    }

    // MARK: Is the source this VPN is SET to usable right now?

    /// THE LEVELS-1-2-3 HALF of the satisfaction decision: everything answerable from
    /// this Mac's facts plus the profile's stored source, and nothing that needs the
    /// profile itself.
    ///
    /// It replaced `canServe(_:) -> Bool`, and the change is not cosmetic. A Bool could
    /// say "no" and nothing else, so every caller that wanted to help had to go back to
    /// the block enum and match on it — and one caller did not bother, deriving its own
    /// answer from different inputs instead (see `VPNController+Auth.swift`). An
    /// `AuthSatisfaction` names the LEVEL, so the fix and its screen follow from the
    /// type.
    ///
    /// `VPNController.authSatisfaction(for:)` is the whole answer: it adds the facts
    /// only a profile knows — whether "type it this time" is in force, whether a Touch
    /// ID item exists, and whether this VPN needs a verification code at all.
    func satisfaction(for source: CredentialSource) -> AuthSatisfaction {
        satisfaction(for: source, facts: facts)
    }

    /// The same, against a SNAPSHOT of the facts. A view holding one (and a test
    /// driving fixtures) gets the same derivation rather than a second one — which is
    /// the whole point of the type.
    func satisfaction(for source: CredentialSource,
                      facts live: SignInSourceFacts) -> AuthSatisfaction {
        switch source.kind {
        case .manual:
            // Nothing at this layer to say: whether typing, the keychain or Touch ID
            // will serve is entirely the profile's business.
            return .typedInstead(.byChoice)
        case .applePasswords:
            // No vendor channel to probe. What it needs is a server to match, which is
            // level 3.
            guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else {
                return .typedInstead(.nothingLinked)
            }
            return .unproven(.checkOwedOnUse)
        case .onePassword, .keePassXC, .keeper, .bitwarden, .dashlane, .keePassFile,
             .passwordStore, .lastPass, .protonPass, .passbolt:
            break
        }
        guard let adapter = LocalVaultRegistry.adapter(for: source.kind) else {
            // A stored kind with no adapter can only mean a profile written by a build
            // that had one. Nothing to fix at any level.
            return .typedInstead(.nothingLinked)
        }
        let vendor = adapter.vendor

        // LEVEL 0 — HAS ANYBODY LOOKED? Answered before level 1, and it RETURNS rather
        // than falling through, because levels 2 and 3 read the same unscanned facts:
        // an empty instance list would come back as "you haven't chosen a database",
        // which is the same false verdict one level down.
        //
        // `.unproven(.checkOwedOnUse)` is the honest answer and it is deliberately not
        // `needsAttention`: the check is owed, it is cheap, it is local, and it is paid
        // by the next `refresh()` — that is exactly what the ceiling means. It also
        // still `connectsUnattended`, so a reconnect that fires before any view has
        // appeared goes through with a source that works.
        //
        // WHAT THIS PREVENTS, concretely: the connect surface read these facts without
        // gathering them and told a user that their perfectly healthy 1Password was
        // unavailable — while the connect it was warning about succeeded.
        //
        // LEVEL 1 — can we reach the vendor at all? The order matters: asking "is the
        // entry named?" before "is the tool installed?" produces the wrong sentence for
        // a Mac with neither.
        switch live.availability(vendor) {
        case .unscanned:
            return .unproven(.checkOwedOnUse)
        case .notInstalled:
            return .broken(locus: .transport, block: .toolMissing)
        case .blocked(let block):
            return .broken(locus: block.locus, block: block)
        case .unchecked, .ready:
            break
        }

        // LEVEL 2 — WHICH vault, not just which vendor. A profile naming a database
        // that is no longer set up must say so HERE, before a connect discovers it, and
        // must never be quietly pointed at a different one.
        let selection = source.selection
        switch SourceInstanceResolver.resolve(
            selection, vendor: vendor, instances: live.instances(for: vendor)) {
        case .noneConfigured:
            return .broken(locus: .instance,
                           block: vendor == .passbolt ? .noServerConfigured : .noVaultFile)
        case .chosenIsGone:
            return .broken(locus: .instance, block: .vaultFileMissing)
        case .sole, .resolved:
            break
        }
        let perInstance = live.availability(vendor, instance: selection.instance)
        if case .blocked(let block) = perInstance {
            return .broken(locus: block.locus, block: block)
        }

        // LEVEL 3 — is an entry named, and can the adapter build a fetcher for it?
        guard adapter.provider(for: source) != nil else {
            return .typedInstead(.nothingLinked)
        }
        if case .unchecked(let ceiling) = perInstance { return .unproven(ceiling) }
        if case .unchecked(let ceiling) = live.availability(vendor) {
            return .unproven(ceiling)
        }
        return .ready
    }

    // MARK: Caches

    /// Whether this Mac can ask for a fingerprint. Fixed for the process (a Mac
    /// does not grow a Touch ID sensor mid-session).
    private static let biometrics = DeviceOwnerAuth.isAvailable
    private static func cachedBiometrics() -> Bool { biometrics }

    /// The installed-app sweep, once per process. Deliberately NOT touched by
    /// `refresh()` — see the comment there.
    private static var sweptApps: [InstalledPasswordApp]?
    private static func installedApps() -> [InstalledPasswordApp] {
        if let sweptApps { return sweptApps }
        let found = InstalledPasswordAppScanner.scan()
        sweptApps = found
        return found
    }
}

// MARK: - Finding the password apps on this Mac

/// Which password apps are installed, and which of them ship a macOS AutoFill
/// extension.
///
/// TWO passes, because neither alone is enough. Launch Services answers exact
/// bundle ids wherever the app lives (including a renamed .app), but cannot be
/// asked "anything starting with com.keepersecurity."; a directory sweep catches
/// the distributions whose ids we haven't seen. Both are needed and both are
/// cheap once.
///
/// THE AUTOFILL CLAIM IS DETECTED, NOT ASSUMED: we look inside the bundle for an
/// `.appex` whose extension point is Apple's credential-provider one. What we
/// still cannot know is whether the user has SWITCHED IT ON — there is no public
/// API for that (`ASCredentialIdentityStore` reports the state of the CALLING
/// app's own extension, and SimpleVPN ships none), so every sentence about
/// AutoFill says "if you have switched it on in System Settings" rather than
/// claiming it works.
enum InstalledPasswordAppScanner {

    /// Apple's extension point for a password AutoFill provider.
    static let credentialProviderExtensionPoint =
        "com.apple.authentication-services-credential-provider-ui"

    static func scan() -> [InstalledPasswordApp] {
        var found: [String: InstalledPasswordApp] = [:]

        // Pass 1 — exact ids through Launch Services.
        for entry in PasswordAppCatalog.entries {
            for bundleID in entry.bundleIDs {
                guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
                else { continue }
                found[bundleID] = InstalledPasswordApp(
                    bundleID: bundleID, name: entry.name,
                    shipsAutoFillExtension: shipsCredentialProvider(at: url))
            }
        }

        // Pass 2 — a shallow sweep of the Applications folders for prefix hits.
        for url in applicationBundles() {
            guard let bundleID = bundleIdentifier(at: url),
                  found[bundleID] == nil,
                  let name = PasswordAppCatalog.name(forBundleID: bundleID)
            else { continue }
            found[bundleID] = InstalledPasswordApp(
                bundleID: bundleID, name: name,
                shipsAutoFillExtension: shipsCredentialProvider(at: url))
        }

        return found.values.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    /// Where user-installed apps live. Shallow plus one level of subfolders (Mac
    /// App Store apps sit at the top level; a few vendors ship a folder).
    private static func applicationBundles() -> [URL] {
        let fm = FileManager.default
        var roots = [URL(fileURLWithPath: "/Applications")]
        roots.append(fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications"))
        var out: [URL] = []
        for root in roots {
            guard let entries = try? fm.contentsOfDirectory(
                at: root, includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { continue }
            for entry in entries {
                if entry.pathExtension == "app" { out.append(entry); continue }
                guard let nested = try? fm.contentsOfDirectory(
                    at: entry, includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { continue }
                out += nested.filter { $0.pathExtension == "app" }
            }
        }
        return out
    }

    private static func bundleIdentifier(at appURL: URL) -> String? {
        let plist = appURL.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any]
        else { return nil }
        return dict["CFBundleIdentifier"] as? String
    }

    /// Does this bundle carry a password-AutoFill extension?
    static func shipsCredentialProvider(at appURL: URL) -> Bool {
        let fm = FileManager.default
        let plugIns = appURL.appendingPathComponent("Contents/PlugIns")
        guard let entries = try? fm.contentsOfDirectory(
            at: plugIns, includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { return false }
        for appex in entries where appex.pathExtension == "appex" {
            let plist = appex.appendingPathComponent("Contents/Info.plist")
            guard let data = try? Data(contentsOf: plist),
                  let dict = try? PropertyListSerialization.propertyList(
                    from: data, options: [], format: nil) as? [String: Any],
                  let extensionInfo = dict["NSExtension"] as? [String: Any],
                  let point = extensionInfo["NSExtensionPointIdentifier"] as? String
            else { continue }
            if point == credentialProviderExtensionPoint { return true }
        }
        return false
    }
}
