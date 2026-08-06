// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportInventory.swift
//  The gatherers behind the report's inventory sections. Each one turns facts
//  something ELSE already established into `ReportValue`s — it does not go and
//  find out for itself.
//
//  THAT IS THE RULE, and it has two reasons:
//   • Re-probing would change what the user just saw. A report that re-runs the
//     probe ladder is reporting a different connection attempt from the one being
//     complained about, on a network that may since have changed.
//   • Every one of these facts already has exactly one owner —
//     `ToolDiscovery` for where a tool is, `SignInSourceAvailability` for whether
//     a vendor can answer, `ProbeLadderStore` for what the ladder measured,
//     `ManagedPolicy` for what an administrator decided. A second answer here
//     would be a second answer to drift from the first.
//
//  The one thing gathered fresh is a bundle's own version number, read from its
//  `Info.plist`. It is a file read, it is not a probe, and nothing else in the app
//  knows it.
//

import Foundation
import AppKit

// MARK: - Password-manager apps and their versions

nonisolated enum DiagnosticReportInventory {

    /// An installed application's own version, from its bundle. Never executed,
    /// never asked over IPC — a `CFBundleShortVersionString` is a file read.
    nonisolated struct AppVersion: Sendable, Equatable {
        var shortVersion: String?
        var buildVersion: String?

        /// `8.10.60 (81060023)`, or nil when the bundle would not answer.
        var displayValue: String? {
            switch (shortVersion, buildVersion) {
            case (let short?, let build?) where short != build: "\(short) (\(build))"
            case (let short?, _): short
            case (nil, let build?): "build \(build)"
            default: nil
            }
        }
    }

    /// Read a bundle's version by bundle identifier. Returns an empty result
    /// (rather than a guess) when Launch Services doesn't know the id, the bundle
    /// has moved, or its `Info.plist` is unreadable.
    static func appVersion(bundleID: String) -> AppVersion {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else {
            return AppVersion()
        }
        let plist = url.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any]
        else { return AppVersion() }
        return AppVersion(shortVersion: dict["CFBundleShortVersionString"] as? String,
                          buildVersion: dict["CFBundleVersion"] as? String)
    }

    // MARK: The password-manager inventory (its own section, off by default)

    /// One row per password app found on this Mac, with its version and whether it
    /// ships an AutoFill extension.
    ///
    /// `otherApps` is the list `SignInSourceAvailability` already swept; the
    /// vendors SimpleVPN can actually read are added from `LocalVaultVendor`, so a
    /// 1Password or KeePassXC install is not silently missing from a section
    /// titled "password managers on this Mac".
    static func passwordManagerFields(facts: SignInSourceFacts) -> [DiagnosticReportField] {
        var out: [DiagnosticReportField] = []

        for vendor in LocalVaultVendor.allCases {
            let copy = LocalVaultCopyBook.copy(for: vendor)
            var detail: [ReportValue] = [.words("state: \(stateWords(facts.rawAvailability(vendor), vendor: vendor))")]
            if !facts.isEnabled(vendor) {
                detail.append(.words("switched off in SimpleVPN\u{2019}s settings"))
            }
            // The app's own version, for whichever of the vendor's bundle ids is
            // present. A vendor ships several (direct download, App Store), so
            // the one that answers is the one installed.
            var appVersionValue: ReportValue = .absent(reason: "its app isn\u{2019}t installed, or macOS wouldn\u{2019}t say")
            for bundleID in vendorBundleIDs(vendor) {
                if let display = appVersion(bundleID: bundleID).displayValue {
                    appVersionValue = .version(display)
                    detail.append(.words("bundle id: \(bundleID)"))
                    break
                }
            }
            out.append(DiagnosticReportField(label: "\(copy.title) (app)",
                                             value: appVersionValue, detail: detail))
        }

        for app in facts.otherApps {
            var detail: [ReportValue] = [.words("bundle id: \(app.bundleID)")]
            detail.append(.words(app.shipsAutoFillExtension
                ? "ships a macOS AutoFill extension (whether it is switched on is not something an app can ask)"
                : "no macOS AutoFill extension"))
            switch PasswordAppCatalog.localReadPath(forBundleID: app.bundleID) {
            case .none:
                detail.append(.words("SimpleVPN has no local way to read it"))
            case .officialCLI(let tool):
                detail.append(.words("the vendor ships a command-line tool (\(tool)); no adapter yet"))
            case .keePassFormat:
                detail.append(.words("stores KeePass .kdbx \u{2014} the format SimpleVPN already reads"))
            }
            let version = appVersion(bundleID: app.bundleID).displayValue
            out.append(DiagnosticReportField(
                label: "\(app.name) (app)",
                value: version.map { ReportValue.version($0) }
                    ?? .absent(reason: "its Info.plist wouldn\u{2019}t answer"),
                detail: detail))
        }

        return out
    }

    /// The bundle ids to try for a vendor SimpleVPN can read. Taken from the
    /// pointer catalogue where it has them, plus the integrated vendors' own —
    /// which the pointer catalogue deliberately excludes (they are sources, not
    /// pointers), and which are therefore the ones that would otherwise be
    /// missing from the inventory.
    static func vendorBundleIDs(_ vendor: LocalVaultVendor) -> [String] {
        switch vendor {
        case .onePassword: ["com.1password.1password", "com.agilebits.onepassword7", "com.1password.1password-launcher"]
        case .keePassXC: ["org.keepassxc.keepassxc"]
        case .keeper: PasswordAppCatalog.entry(forBundleID: "com.callpod.KeeperDesktop")?.bundleIDs ?? []
        case .bitwarden: PasswordAppCatalog.entry(forBundleID: "com.bitwarden.desktop")?.bundleIDs ?? ["com.bitwarden.desktop"]
        // The Dashlane app is not a read path (`dcli` is), but whether it is installed
        // is exactly the kind of fact that explains a report: someone with the app and
        // no tool sees a different row from someone with neither.
        case .dashlane: PasswordAppCatalog.entry(forBundleID: "com.dashlane.Dashlane")?.bundleIDs ?? ["com.dashlane.Dashlane"]
        // A .kdbx file is not owned by one app: KeePassXC, Strongbox and
        // KeePassium all read the same format, and the source works with none of
        // them installed. So report every app that could be managing it — which
        // app the person actually uses is exactly what a maintainer wants to know.
        case .keePassFile:
            ["org.keepassxc.keepassxc", "com.markmcguill.strongbox.mac", "com.keepassium.mac"]
        // A password store has no app at all: it is a folder of files read with gpg.
        // An empty list is the honest answer, and the tools section is where its real
        // inventory (gpg, and whether `pass` happens to be installed) shows up.
        case .passwordStore: []
        // The LastPass app is not a read path — `lpass` is — but which app is
        // installed is exactly the fact that tells a maintainer whether the person
        // uses LastPass at all, so it is reported.
        case .lastPass:
            PasswordAppCatalog.entry(forBundleID: "com.lastpass.LastPass")?.bundleIDs
                ?? ["com.lastpass.LastPass"]
        // The Proton Pass desktop app. It is NOT the read path — it has no local API
        // — but which of Proton's two distributions is installed is exactly the kind
        // of fact a maintainer wants, and its absence alongside a present `pass-cli`
        // is itself informative.
        case .protonPass: PasswordAppCatalog.entry(forBundleID: "me.proton.pass.electron")?.bundleIDs
            ?? ["me.proton.pass.electron", "ch.protonmail.pass"]
        // Passbolt has no macOS app to look for: it is a server, reached with a
        // browser extension or its own command-line program. An empty list is the
        // honest answer, and the tools section is where its real inventory (which of
        // `passbolt` / `go-passbolt-cli` is installed, and where) shows up.
        case .passbolt: []
        }
    }

    // MARK: Tools, CLIs and local APIs

    /// Every tool in the discovery catalogue: found or not, EVERY path, which one
    /// SimpleVPN would run, and its version when it was allowed to ask.
    ///
    /// This is the section that stops a maintainer chasing a phantom: "not
    /// installed" and "installed in ~/.bun/bin, which SimpleVPN won't run from"
    /// look identical from the outside and need completely different answers.
    static func toolFields(discoveries: [String: DiscoveredTool]) -> [DiagnosticReportField] {
        ToolCatalog.all.map { tool in
            guard let found = discoveries[tool.name] else {
                return DiagnosticReportField(
                    label: "\(tool.title) (\(tool.name))",
                    value: .absent(reason: "SimpleVPN isn\u{2019}t looking for password managers on this Mac"))
            }
            guard found.isFound else {
                return DiagnosticReportField(label: "\(tool.title) (\(tool.name))",
                                             value: .words("not found anywhere SimpleVPN looked"))
            }
            var detail: [ReportValue] = []
            for hit in found.paths {
                detail.append(.path("\(hit.path) \u{2014} from \(hit.locationClass.title); \(usabilityWords(hit.usability))"))
            }
            switch found.version {
            case .known(let v): detail.append(.version("version: \(v)"))
            case .unknown(let why): detail.append(.words("version unknown: \(why)"))
            }
            let headline: ReportValue = found.chosen.map { ReportValue.path("would run \($0)") }
                ?? .words("found, but nowhere SimpleVPN will run it from")
            return DiagnosticReportField(label: "\(tool.title) (\(tool.name))",
                                         value: headline, detail: detail)
        }
    }

    /// The four-state answer per vendor, plus WHY when it is blocked. The states
    /// that matter most here are the two that read as "broken" but are not:
    /// installed-but-not-enabled, and installed-outside-the-allow-list.
    @MainActor
    static func vendorStateFields(facts: SignInSourceFacts) -> [DiagnosticReportField] {
        LocalVaultVendor.allCases.flatMap { vendor -> [DiagnosticReportField] in
            [vendorStateField(vendor, facts: facts)] + instanceStateFields(vendor, facts: facts)
        }
    }

    /// One row per CONFIGURED VAULT, for a vendor that can have several (level 2 —
    /// see SignInSourceInstances.swift). Reported separately from the vendor's own
    /// row because they answer different questions: the vendor row says whether this
    /// vendor can get you in at all, and these say which of your vaults is actually
    /// readable. A maintainer looking at "KeePass database file: ready" needs to know
    /// that the work database is on an unmounted volume and the personal one is fine.
    ///
    /// NO PATHS. A report says a vault's NAME and its state; where somebody keeps
    /// their passwords is not something to put in a bundle they email to us. (The
    /// per-vault state sentence names the KIND of problem — "the database file is not
    /// where SimpleVPN was told to look" — which is what a maintainer needs.)
    @MainActor
    static func instanceStateFields(_ vendor: LocalVaultVendor,
                                    facts: SignInSourceFacts) -> [DiagnosticReportField] {
        guard vendor.cardinality.allowsSeveral else { return [] }
        let copy = LocalVaultCopyBook.copy(for: vendor)
        let instances = facts.instances(for: vendor)
        guard !instances.isEmpty else {
            return [DiagnosticReportField(
                label: "\(copy.title): \(vendor.instanceNounPlural)",
                value: .words("none set up"))]
        }
        return instances.enumerated().map { index, instance in
            var detail: [ReportValue] = [
                .state(index == 0
                    ? "the one a VPN gets when it names none (the default)"
                    : "chosen by name"),
            ]
            for field in SignInSourceSettings.instanceFields(for: vendor) {
                // Whether it is SET, never what it is set to.
                detail.append(.flag(!instance.value(for: field).isEmpty))
            }
            return DiagnosticReportField(
                label: "\(copy.title): \(instance.name)",
                value: .state(stateWords(facts.rawAvailability(vendor, instance: instance.id),
                                         vendor: vendor)),
                detail: detail)
        }
    }

    @MainActor
    static func vendorStateField(_ vendor: LocalVaultVendor,
                                 facts: SignInSourceFacts) -> DiagnosticReportField {
            let copy = LocalVaultCopyBook.copy(for: vendor)
            // HOW SimpleVPN reaches it, from the adapter itself — the shape of the
            // channel is what decides how detection and failure behave, so it is
            // the first thing worth knowing about a vendor that isn't answering.
            let transports = LocalVaultRegistry.adapter(for: vendor)?.transports ?? []
            var detail: [ReportValue] = [
                .state("reached over: " + (transports.isEmpty
                    ? "no adapter is built for it yet"
                    : transports.map(\.rawValue).joined(separator: ", "))),
            ]
            if let path = facts.toolsFoundOutsideAllowList[vendor] {
                detail.append(.path("its tool is installed at \(path), which SimpleVPN won\u{2019}t run from unless you set it explicitly"))
            }
            if !facts.isEnabled(vendor) {
                detail.append(.words("switched off, so SimpleVPN neither offers it nor mentions it"))
            }
            return DiagnosticReportField(
                label: copy.title,
                value: .state(stateWords(facts.rawAvailability(vendor), vendor: vendor)),
                detail: detail)
    }

    // A `pkcs11Fields()` GATHERER USED TO BE HERE, listing the PKCS#11 provider
    // modules installed on this Mac. Smartcard sign-in is gone, so the report no
    // longer reveals which security software somebody has installed for a feature
    // SimpleVPN cannot use — which is a small privacy improvement as well as dead
    // code removed.

    /// Security keys plugged in right now. IORegistry only: no HID input is read,
    /// nothing is executed, and no Input Monitoring permission is involved.
    @MainActor
    static func securityKeyFields() -> [DiagnosticReportField] {
        let keys = IORegistrySecurityKeyScanner().scan()
        guard !keys.isEmpty else { return [] }
        return keys.map { key in
            DiagnosticReportField(label: "Security key: \(key.familyName)",
                                  value: .words(key.interfaceSummary))
        }
    }

    // MARK: Virtual machines and containers

    /// What virtualization this Mac runs, which guest networks were live, and — the
    /// line that decides whether any of it is actionable — whether a routing
    /// exclusion could help each one.
    ///
    /// Reported from a snapshot something else took (`VirtualizationDiscovery`),
    /// never re-scanned here: the same rule as every other gatherer in this file.
    ///
    /// A maintainer reading "Docker Desktop is installed and my container has no
    /// network" needs to be told, in the report itself, that no routing setting can
    /// fix that — otherwise the first day goes on excluded routes that were never
    /// going to do anything.
    static func virtualizationFields(snapshot: VirtualizationSnapshot) -> [DiagnosticReportField] {
        guard snapshot.detectionEnabled else {
            return [DiagnosticReportField(
                label: "Looking for virtual machines at all",
                value: .flag(false),
                detail: [.words("off, so this section is empty by design rather than because you run none")])]
        }

        var out: [DiagnosticReportField] = []

        for product in snapshot.installed {
            var detail: [ReportValue] = [
                .state("networking: \(product.networking.title)"),
                .words(classWords(product.networking)),
            ]
            if !product.verifiedLocally {
                detail.append(.words(
                    "nobody has run SimpleVPN against this product \u{2014} its behaviour here is "
                    + "reasoned from the vendor\u{2019}s documentation, not measured"))
            }
            for evidence in product.evidence { detail.append(.path(evidence)) }
            out.append(DiagnosticReportField(
                label: "\(product.title) (installed)",
                value: .state(product.networking.rawValue),
                detail: detail))
        }

        // The live half. Separate rows, because "installed" and "running on
        // 192.168.64.0/24" are different facts and a guest subnet only exists once a
        // guest has booted.
        if snapshot.guestNetworks.isEmpty {
            out.append(DiagnosticReportField(
                label: "Live guest networks",
                value: .words("none \u{2014} nothing was running with a network of its own"),
                detail: [.words(
                    "a guest subnet is assigned when a guest boots, so this is expected when no "
                    + "virtual machine or container was running")]))
        } else {
            for network in snapshot.guestNetworks {
                var detail: [ReportValue] = [
                    .path("host end: \(network.hostAddress) on \(network.interfaceName)"),
                    .words("attributed to: \(network.attribution)"),
                ]
                if !network.attachedGuestInterfaces.isEmpty {
                    detail.append(.count(network.attachedGuestInterfaces.count))
                }
                out.append(DiagnosticReportField(
                    label: "Live guest network on \(network.interfaceName)",
                    value: .path(network.subnet),
                    detail: detail))
            }
        }

        // UTM's per-VM modes. UTM is the product whose class cannot be read off
        // "installed", so the report says it per machine or it says nothing useful.
        for guest in snapshot.utmGuests {
            out.append(DiagnosticReportField(
                label: "UTM virtual machine: \(guest.name)",
                value: .state(guest.mode),
                detail: [
                    .state("networking: \(guest.networking.title)"),
                    .words(classWords(guest.networking)),
                ]))
        }

        return out
    }

    /// What a guest-networking class MEANS for a fix. Exhaustive on purpose: a new
    /// class must be given its sentence here, because the whole value of this
    /// section is telling the two apart.
    static func classWords(_ networking: GuestNetworkClass) -> String {
        switch networking {
        case .routedSubnet:
            "a VPN that captures this subnet cuts its guests off, and keeping the subnet out of the "
            + "tunnel is the fix"
        case .userspace:
            "there is no host interface and no subnet to keep out, so ROUTING SETTINGS CANNOT HELP "
            + "this one \u{2014} look at the guest\u{2019}s MTU and its DNS instead"
        case .perGuest:
            "which of the two it is depends on each virtual machine\u{2019}s own setting, so the "
            + "per-machine rows below are the ones that answer it"
        }
    }

    // MARK: Switched off, or decided for you

    /// Everything that could make a feature inert, in one place, so a maintainer
    /// never debugs a switch. Covers both halves: what the user turned off, and
    /// what an administrator decided.
    @MainActor
    static func switchedOffFields(settings: SignInSourceSettingsStore,
                                  facts: SignInSourceFacts) -> [DiagnosticReportField] {
        var out: [DiagnosticReportField] = []

        // --- The user's own switches -------------------------------------
        out.append(DiagnosticReportField(
            label: "Looking for password managers at all",
            value: .flag(settings.discoveryEnabled),
            detail: settings.discoveryEnabled
                ? []
                : [.words("off, so no vendor is probed and the tool inventory above is empty by design")]))

        let disabled = LocalVaultVendor.allCases
            .filter { !facts.isEnabled($0) }
            .map { LocalVaultCopyBook.copy(for: $0).title }
        out.append(DiagnosticReportField(
            label: "Sign-in sources switched off",
            value: disabled.isEmpty ? .words("none") : .words(disabled.joined(separator: ", "))))

        out.append(DiagnosticReportField(label: "Public IP lookup",
                                         value: .flag(PublicIPMonitor.lookupEnabled)))
        out.append(DiagnosticReportField(label: "Location access",
                                         value: .flag(LocationAuthority.shared.isEnabled)))
        out.append(DiagnosticReportField(label: "Automatic endpoint probing",
                                         value: .flag(EndpointProbeStore.isEnabled)))
        out.append(DiagnosticReportField(
            label: "Looking for virtual machines on this Mac",
            value: .flag(VirtualizationSettings.detectionEnabled),
            detail: VirtualizationSettings.detectionEnabled
                ? []
                : [.words("off, so the virtual-machine section is empty by design")]))
        out.append(DiagnosticReportField(
            label: "Warning before a VPN captures a guest network",
            value: .flag(VirtualizationSettings.warningEnabled)))

        // --- What an administrator decided --------------------------------
        // Reported even when nothing is forced, because "no policy is in force"
        // is itself the answer to "is MDM doing this to me?".
        let connectionPolicies = ManagedPolicy.activeSummary
        out.append(DiagnosticReportField(
            label: "Managed connection policy",
            value: ManagedPolicy.isManaged
                ? .words(connectionPolicies.isEmpty ? "managed, nothing currently restricted"
                                                    : "in force")
                : .words("none"),
            detail: connectionPolicies.map { ReportValue.words($0) }))

        out.append(DiagnosticReportField(label: "Connection settings locked (lockConfiguration)",
                                         value: .flag(ManagedPolicy.lockConfiguration)))

        let signInPolicies = ManagedSignInSourcePolicy.activeSummary()
        out.append(DiagnosticReportField(
            label: "Managed sign-in policy",
            value: ManagedSignInSourcePolicy.isManaged()
                ? .words(signInPolicies.isEmpty ? "managed, nothing currently restricted" : "in force")
                : .words("none"),
            detail: signInPolicies.map { ReportValue.words($0) }))

        return out
    }

    // MARK: Words for states

    /// The four-state availability, in the same words the chooser uses. One
    /// vocabulary, so a report and a screenshot of the app agree.
    /// `vendor` supplies the vendor's OWN NOUN for the file-shaped states — "database",
    /// "store", "server". Without it these sentences said "database" about everything,
    /// which was true of every multi-instance vendor until one of them stopped being a
    /// file: telling somebody their password STORE's "database file is not where
    /// SimpleVPN was told to look" describes a thing that does not exist. Optional, and
    /// falling back to "vault", so a caller with no vendor in hand still gets a sentence
    /// rather than a placeholder.
    static func stateWords(_ availability: LocalVaultAvailability,
                           vendor: LocalVaultVendor? = nil) -> String {
        let noun = vendor?.instanceNoun ?? "vault"
        return switch availability {
        case .notInstalled: "not installed"
        // "installed and reachable, never proven end to end" was the old sentence, and
        // for a SERVER-shaped source it claimed something nothing had established:
        // reachability is exactly what was never checked. The ceiling says which of
        // the two it is, so a maintainer reading a report can tell "the check is owed"
        // from "the check would have been a sign-in attempt on somebody else's box".
        case .unchecked(let ceiling):
            switch ceiling {
            case .checkOwedOnUse: "installed, and the one-time check hasn\u{2019}t run yet"
            case .wouldSignInToServer:
                "set up, and deliberately never probed \u{2014} asking would be a real sign-in "
                + "attempt against the server"
            case .wouldPromptTheUser:
                "set up, and deliberately never probed \u{2014} checking further would have to "
                + "ask the user for something"
            case .wouldSpendSingleUseCode:
                "set up, and deliberately never probed \u{2014} checking further would use up a "
                + "verification code"
            }
        case .ready: "ready to use"
        case .blocked(let block):
            switch block {
            case .appNotRunning: "installed, but its app isn\u{2019}t running"
            case .needsUpdate: "installed, but too old for the part SimpleVPN talks to"
            case .integrationOff: "installed and running, but the integration switch is off"
            case .toolMissing: "its app is here, but the command-line tool or local API is not installed"
            case .notSignedIn: "its tool is here, but nobody has signed in to it"
            case .toolOutsideAllowList:
                "its tool IS installed, but not somewhere SimpleVPN will run from, and no explicit path is set"
            // Signed in, but the vault itself is locked — a distinct state, because
            // telling someone they aren't signed in when they are is how they
            // conclude SimpleVPN can't see their vault at all.
            case .vaultLocked: "signed in, but the vault is locked"
            // The kdbx file states. Each is a different fix, and each is
            // indistinguishable from a wrong password unless it is named — which
            // is the whole reason the header is read before any unlock.
            case .noVaultFile: "no \(noun) has been chosen yet"
            case .vaultFileMissing: "the \(noun) is not where SimpleVPN was told to look"
            case .vaultFileNotDownloaded:
                "the \(noun) is in iCloud or Dropbox and has not been downloaded yet"
            case .vaultFileNotReadable:
                "the \(noun) is there, but macOS will not let SimpleVPN open it"
            case .vaultFileNotAKeePassDatabase: "that file is not a KeePass database"
            case .vaultFileTooNew: "the database is a newer KeePass version than the installed tool reads"
            case .vaultPasswordRejected:
                "the \(noun) refused the password, key file or security key given"
            case .vaultNotAPasswordStore:
                "that folder is not a password store \u{2014} there is no .gpg-id file in it"
            // The one state that is a CONFIGURATION of the vendor's tool rather than a
            // gap in it: the tool would write the password to the pasteboard, so
            // SimpleVPN declines to run it. Worth spelling out in a report, because
            // from the outside it looks like a fetch that simply returns nothing.
            case .toolDivertsSecretToClipboard:
                "its tool is set up to copy the password to the clipboard, so SimpleVPN will not run it"
            // NOTHING IS BROKEN, and a report has to say that out loud: a maintainer
            // reading "not signed in" would start debugging the tool, and the tool is
            // fine.
            case .planExcludesTool:
                "everything is installed and signed in, but the account\u{2019}s plan does not "
                + "include the tool SimpleVPN reads through \u{2014} not a fault on this Mac"
            // A server, so the words are about an address rather than a file.
            case .noServerConfigured: "no server address has been set up yet"
            }
        }
    }

    static func usabilityWords(_ usability: ToolUsability) -> String {
        switch usability {
        case .runnable: "SimpleVPN will run this"
        case .outsideAllowList: "SimpleVPN won\u{2019}t look here on its own; setting it explicitly would work"
        case .unsafeDirectory: "refused: anyone using this Mac can replace files in that folder"
        case .notExecutable: "not a program SimpleVPN can run"
        }
    }
}
