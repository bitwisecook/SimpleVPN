// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  UserFacingError.swift
//  Turns whatever failed into something a person can act on: a plain title, one
//  sentence of explanation, numbered steps that name the real buttons, and the
//  raw text tucked away for support.
//
//  Foundation only — no SwiftUI — so classification is pure, testable, and the
//  sheet stays a dumb renderer.
//
//  1Password matching is by SUBSTRING on purpose. The Go SDK's failure strings
//  are prose, not API: they change between releases, several distinct failures
//  share one string, and the SDK's own advice is already stale — it tells people
//  to enable "Integrate with other apps", a toggle today's 1Password calls
//  "Integrate with 1Password SDKs" (Settings ▸ Developer ▸ Developer
//  Integrations). We match the SDK's wording and print the CURRENT wording.
//
//  Nothing here may ever put a secret on screen: `technicalDetail` is redacted
//  (known secret values, secret-shaped key/value pairs, and anything that looks
//  like a one-time code) before it is stored.
//

import Foundation

/// A failure explained the way the person in front of the Mac needs it.
nonisolated struct UserFacingError: Identifiable, Sendable, Equatable {

    /// What broke, in the vocabulary of the fix — drives the symbol and tint.
    enum Category: String, Sendable, Equatable {
        case onePassword      // the 1Password app / its integration
        case keePassXC        // the KeePassXC app / its browser integration
        case credentials      // the sign-in itself is wrong or missing
        case approval         // something is waiting for the user to say yes
        case network          // this Mac's own connectivity
        case configuration    // locked or managed settings
        case generic
    }

    /// One instruction. `text` is markdown (UI names in **bold**); `note` is an
    /// optional aside that would otherwise bloat the instruction.
    struct Step: Identifiable, Sendable, Equatable {
        var text: String
        var note: String?
        var id: String { text }

        init(_ text: String, note: String? = nil) {
            self.text = text
            self.note = note
        }
    }

    /// A button the sheet can offer. Deliberately data, not a closure: the model
    /// stays Sendable and comparable, and the view owns AppKit.
    enum Action: Sendable, Equatable {
        case openOnePassword
        case openKeePassXC
        case manageVPNs
        case networkSettings
        /// System Settings > General > Login Items & Extensions — where the
        /// network extension is approved. Four connect paths told the user those
        /// four levels of navigation in prose and gave them nothing to click.
        case loginItems
        case openURL(URL)

        var title: String {
            switch self {
            case .openOnePassword: "Open 1Password"
            case .openKeePassXC: "Open KeePassXC"
            case .manageVPNs: "Open Manage VPNs"
            case .networkSettings: "Open Network Settings"
            case .loginItems: "Open Login Items & Extensions"
            case .openURL: "Open Download Page"
            }
        }

        var symbol: String {
            switch self {
            case .openOnePassword: "key.fill"
            case .openKeePassXC: "key.horizontal.fill"
            case .manageVPNs: "slider.horizontal.3"
            case .networkSettings: "wifi"
            case .loginItems: "puzzlepiece.extension"
            case .openURL: "arrow.down.circle"
            }
        }
    }

    var title: String
    var explanation: String
    var steps: [Step]
    var action: Action?
    /// Whether offering "Try Again" makes sense (it re-runs the same connect).
    var canRetry: Bool
    var category: Category
    var symbol: String
    /// The raw underlying message. Hidden behind a disclosure; already redacted.
    var technicalDetail: String
    /// When this was raised — also what makes each failure a fresh sheet.
    var occurred: Date

    var id: String { "\(occurred.timeIntervalSince1970)|\(title)" }

    init(title: String, explanation: String, steps: [Step], action: Action? = nil,
         canRetry: Bool = false, category: Category = .generic,
         symbol: String = "exclamationmark.triangle.fill",
         technicalDetail: String = "", occurred: Date = .now) {
        self.title = title
        self.explanation = explanation
        self.steps = steps
        self.action = action
        self.canRetry = canRetry
        self.category = category
        self.symbol = symbol
        self.technicalDetail = technicalDetail
        self.occurred = occurred
    }
}

// MARK: - Classification

nonisolated extension UserFacingError {

    /// Where the "turn it on" instructions point today. Kept in one place so the
    /// day 1Password renames it again there is exactly one edit.
    static let sdkIntegrationSetting = "Integrate with 1Password SDKs"

    /// Classify a thrown error. Typed 1Password failures map by case; everything
    /// else falls through to the message text.
    static func classify(_ error: Error, secrets: [String] = [],
                         occurred: Date = .now) -> UserFacingError {
        if let native = error as? OnePasswordNativeError {
            return classify(native: native, secrets: secrets, occurred: occurred)
        }
        if let kp = error as? KeePassXCError {
            return classify(keePassXC: kp, secrets: secrets, occurred: occurred)
        }
        return classify(message: error.localizedDescription, secrets: secrets, occurred: occurred)
    }

    /// Classify a message the app has already reduced to text (every legacy
    /// `lastError = "…"` path lands here, so nothing is ever swallowed).
    static func classify(message raw: String, secrets: [String] = [],
                         occurred: Date = .now) -> UserFacingError {
        let detail = redact(raw, secrets: secrets)
        let s = raw.lowercased()

        // MDM first: "locked" also appears in 1Password's own failures, and an
        // org-locked configuration is not a 1Password problem.
        if s.contains("locked by your organization") || s.contains("locked by your organisation") {
            return managed(detail: detail, occurred: occurred)
        }
        if isOnePassword(s) {
            return onePassword(lowercased: s, detail: detail, occurred: occurred)
        }
        if isKeePassXC(s) {
            return keePassXC(lowercased: s, detail: detail, occurred: occurred)
        }
        if s.contains("offline") || s.contains("not connected to the internet") {
            return offline(detail: detail, occurred: occurred)
        }
        // The connect paths for all four packet-tunnel kinds throw this exact
        // sentence when the system extension hasn't been approved. It named the
        // System Settings pane in prose; now it opens it.
        if s.contains("network extension approved") {
            return extensionNotApproved(detail: detail, occurred: occurred)
        }
        return generic(raw: raw, detail: detail, occurred: occurred)
    }

    /// Typed helper failures. `.other` carries the SDK's raw prose, which is
    /// exactly the case the substring pass exists for.
    static func classify(native: OnePasswordNativeError, secrets: [String] = [],
                         occurred: Date = .now) -> UserFacingError {
        let detail = redact(native.errorDescription ?? "", secrets: secrets)
        switch native {
        case .appNotInstalled:   return opNotInstalled(detail: detail, occurred: occurred)
        case .appNotRunning:     return opNotRunning(detail: detail, occurred: occurred)
        case .integrationDisabled: return opIntegrationDisabled(detail: detail, occurred: occurred)
        case .userCancelled:     return opNeedsApproval(detail: detail, occurred: occurred)
        case .sessionExpired:    return opSessionExpired(detail: detail, occurred: occurred)
        case .itemNotFound:      return opItemNotFound(detail: detail, occurred: occurred)
        case .accountNotFound:   return opAccountNotFound(detail: detail, occurred: occurred)
        case .ambiguous:         return opAmbiguous(detail: detail, occurred: occurred)
        case .rateLimited:       return opBusy(detail: detail, occurred: occurred)
        case .badRequest:        return opItemNotFound(detail: detail, occurred: occurred)
        case .badResponse:       return opGeneric(detail: detail, occurred: occurred)
        // MACOS REFUSED THE SPAWN — nothing about it is 1Password's doing, so it must
        // not be routed to a 1Password-blaming sentence. Its own `errorDescription`
        // already says what happened and that trying again usually clears it.
        case .helperRefusedToStart: return opGeneric(detail: detail, occurred: occurred)
        case .other(let message):
            // It came out of the 1Password helper, so it IS a 1Password failure
            // however unfamiliar its wording — this is the path the SDK's raw
            // "desktop app connection channel is closed" prose arrives on.
            guard !message.isEmpty else { return opGeneric(detail: detail, occurred: occurred) }
            return onePassword(lowercased: message.lowercased(),
                               detail: redact(message, secrets: secrets), occurred: occurred)
        }
    }

    /// Typed KeePassXC failures — the connector maps every wire error code
    /// onto these, so unlike 1Password there is no prose to sniff: each case
    /// IS the classification.
    static func classify(keePassXC error: KeePassXCError, secrets: [String] = [],
                         occurred: Date = .now) -> UserFacingError {
        let detail = redact(error.errorDescription ?? "", secrets: secrets)
        switch error {
        case .notRunning, .handshakeFailed:
            return kpNotRunning(detail: detail, occurred: occurred)
        case .databaseLocked:
            return kpLocked(detail: detail, occurred: occurred)
        case .accessDenied:
            return kpNeedsApproval(detail: detail, occurred: occurred)
        case .associationFailed, .associationRevoked:
            return kpNeedsPairing(detail: detail, occurred: occurred)
        case .noLogins(let host):
            return kpNoLogins(host: host, detail: detail, occurred: occurred)
        case .ambiguous:
            return kpAmbiguous(detail: detail, occurred: occurred)
        case .timedOut:
            return kpTimedOut(detail: detail, occurred: occurred)
        case .protocolError, .serverError:
            return kpGeneric(detail: detail, occurred: occurred)
        }
    }

    /// Is this failure about KeePassXC at all? Only our own connector speaks
    /// its name, so the name is the whole signature.
    private static func isKeePassXC(_ s: String) -> Bool {
        s.contains("keepassxc") || s.contains("keepass")
    }

    /// Is this failure about 1Password at all? The SDK's strings don't always say
    /// "1Password", but they do always say something equally distinctive.
    private static func isOnePassword(_ s: String) -> Bool {
        s.contains("1password") || s.contains("op://") || s.contains("opnative")
            || s.contains("desktop app") || s.contains("desktop application")
            // The SDK's client-init failure names neither 1Password nor the
            // desktop app — "…processing SDK request: Error { msg: Account not
            // found …}" — and nothing else in SimpleVPN speaks that way.
            || s.contains("sdk request") || s.contains("account not found")
    }

    // MARK: 1Password substring table

    /// Does this failure text mean the SDK integration setting is switched off?
    /// Shared with OnePasswordPreflight: the setup walkthrough and this
    /// classifier must never disagree about what "integration off" looks like.
    /// Takes an ALREADY lowercased string — the matching is substring, see the
    /// file note.
    static func mentionsDisabledIntegration(_ s: String) -> Bool {
        s.contains("integrate with other apps") || s.contains("integrate with 1password sdks")
            || s.contains("connection channel is closed")
            || (s.contains("integration") && (s.contains("disabled") || s.contains("not enabled")
                || s.contains("turned off") || s.contains("not allowed")))
    }

    private static func onePassword(lowercased s: String, detail: String,
                                    occurred: Date) -> UserFacingError {
        // Order matters: the integration-disabled string ALSO mentions the
        // desktop app and a closed channel, so it has to be tested first.
        if mentionsDisabledIntegration(s) {
            return opIntegrationDisabled(detail: detail, occurred: occurred)
        }
        if s.contains("not installed") || s.contains("desktop application not found")
            || s.contains("app is not installed") {
            return opNotInstalled(detail: detail, occurred: occurred)
        }
        if s.contains("not running") || s.contains("connection refused")
            || s.contains("cannot connect") || s.contains("failed to connect")
            || s.contains("isn't running") || s.contains("locked") {
            return opNotRunning(detail: detail, occurred: occurred)
        }
        if s.contains("not authorized") || s.contains("not authorised")
            || s.contains("authorization") || s.contains("authorisation")
            || s.contains("approve") || s.contains("approval") || s.contains("denied")
            || s.contains("rejected") || s.contains("cancel") {
            return opNeedsApproval(detail: detail, occurred: occurred)
        }
        if s.contains("session") && s.contains("expired") {
            return opSessionExpired(detail: detail, occurred: occurred)
        }
        if s.contains("timed out") || s.contains("timeout") || s.contains("deadline exceeded")
            || s.contains("didn't answer") {
            return opTimedOut(detail: detail, occurred: occurred)
        }
        if s.contains("more than one") || s.contains("ambiguous") || s.contains("multiple items") {
            return opAmbiguous(detail: detail, occurred: occurred)
        }
        // Before the item matcher: "Account not found" contains "not found" but
        // means the opposite kind of fix — 1Password can't tell which ACCOUNT to
        // ask (it says this for an empty account name too), and re-picking the
        // item would send the user round in circles.
        if s.contains("account not found") || s.contains("account name")
            || (s.contains("no account") && s.contains("found")) {
            return opAccountNotFound(detail: detail, occurred: occurred)
        }
        if s.contains("not found") || s.contains("no matching") || s.contains("couldn't find")
            || s.contains("no item") || s.contains("invalid secret reference") {
            return opItemNotFound(detail: detail, occurred: occurred)
        }
        if s.contains("rate") && s.contains("limit") {
            return opBusy(detail: detail, occurred: occurred)
        }
        return opGeneric(detail: detail, occurred: occurred)
    }

    // MARK: 1Password cases

    private static func opIntegrationDisabled(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password isn\u{2019}t letting SimpleVPN connect",
            explanation: "The 1Password setting that lets other apps ask for a sign-in is switched off.",
            steps: [
                .init("Open **1Password**."),
                .init("Choose **1Password \u{25B8} Settings**, then the **Developer** tab."),
                .init("Under **Developer Integrations**, tick **\(sdkIntegrationSetting)**.",
                      note: "That\u{2019}s the one described as \u{201C}Use the desktop app to sign in to 1Password from connected integrations\u{201D}. 1Password\u{2019}s own message names an older setting that no longer exists."),
                .init("Come back here and click **Connect** again."),
            ],
            action: .openOnePassword, canRetry: true, category: .onePassword,
            symbol: "key.slash", technicalDetail: detail, occurred: occurred)
    }

    private static func opNotRunning(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password isn\u{2019}t open",
            explanation: "SimpleVPN asks the 1Password app for this VPN\u{2019}s sign-in, and it isn\u{2019}t answering.",
            steps: [
                .init("Open **1Password** and unlock it."),
                .init("Come back here and click **Connect** again."),
            ],
            action: .openOnePassword, canRetry: true, category: .onePassword,
            symbol: "moon.zzz.fill", technicalDetail: detail, occurred: occurred)
    }

    private static func opNotInstalled(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password isn\u{2019}t installed on this Mac",
            explanation: "SimpleVPN reads this VPN\u{2019}s sign-in straight from the 1Password app, so it needs the app itself.",
            steps: [
                .init("Install **1Password** (version 8 or later) from 1password.com."),
                .init("Open it and sign in to your account."),
                .init("Come back here and click **Connect** again."),
                .init("Or open **Manage VPNs** and choose a different place to keep this sign-in."),
            ],
            action: .openURL(URL(string: "https://1password.com/downloads/mac")!),
            canRetry: true, category: .onePassword,
            symbol: "arrow.down.app", technicalDetail: detail, occurred: occurred)
    }

    private static func opNeedsApproval(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password needs you to approve SimpleVPN",
            explanation: "1Password asks your permission before it hands a sign-in to another app.",
            steps: [
                .init("Switch to **1Password** \u{2014} it\u{2019}s showing a prompt asking to allow **SimpleVPN**."),
                .init("Choose **Allow**, or confirm with Touch ID."),
                .init("Click **Connect** again \u{2014} the attempt that raised the prompt stops there, so it takes a second click.",
                      note: "1Password can ask once per app and per session (**Settings \u{25B8} Developer \u{25B8} Advanced**), so seeing this the first time is normal."),
            ],
            action: .openOnePassword, canRetry: true, category: .approval,
            symbol: "hand.raised.fill", technicalDetail: detail, occurred: occurred)
    }

    private static func opSessionExpired(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "Your 1Password approval expired",
            explanation: "1Password only trusts SimpleVPN for a short while before it asks again.",
            steps: [
                .init("Click **Connect** again."),
                .init("Approve the **1Password** prompt when it appears."),
            ],
            action: .openOnePassword, canRetry: true, category: .approval,
            symbol: "clock.badge.exclamationmark", technicalDetail: detail, occurred: occurred)
    }

    private static func opItemNotFound(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "SimpleVPN couldn\u{2019}t find your VPN\u{2019}s login in 1Password",
            explanation: "The saved item isn\u{2019}t there any more, or one of its fields has a different name now.",
            steps: [
                .init("Open **Manage VPNs** and select this VPN."),
                .init("In its sign-in settings, choose the 1Password item again and check which field feeds each box."),
                .init("Click **Connect** again."),
            ],
            action: .manageVPNs, canRetry: true, category: .credentials,
            symbol: "magnifyingglass", technicalDetail: detail, occurred: occurred)
    }

    private static func opAccountNotFound(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "SimpleVPN needs your 1Password account name",
            explanation: "1Password wants to know which of your accounts to ask before it will hand over a sign-in.",
            steps: [
                .init("Open **1Password** and look at the **top left of the sidebar** \u{2014} the name there (for example, **Secure Vault**) is your account name."),
                .init("In SimpleVPN, open this VPN\u{2019}s **Credentials** settings and type it into **Account**."),
                .init("Click **Connect** again."),
            ],
            action: .manageVPNs, canRetry: true, category: .credentials,
            symbol: "person.crop.circle.badge.questionmark",
            technicalDetail: detail, occurred: occurred)
    }

    private static func opAmbiguous(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "More than one 1Password item matches",
            explanation: "1Password found several logins with that name and can\u{2019}t tell which one is this VPN\u{2019}s.",
            steps: [
                .init("Open **Manage VPNs** and select this VPN."),
                .init("Pick the exact item again, and set its vault so the name only matches once."),
                .init("Click **Connect** again."),
            ],
            action: .manageVPNs, canRetry: true, category: .credentials,
            symbol: "square.on.square", technicalDetail: detail, occurred: occurred)
    }

    private static func opTimedOut(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password didn\u{2019}t answer",
            explanation: "The request took too long \u{2014} usually a prompt waiting somewhere you couldn\u{2019}t see it.",
            steps: [
                .init("Bring **1Password** to the front and make sure it\u{2019}s unlocked."),
                .init("Click **Connect** again, and approve the prompt if one appears."),
            ],
            action: .openOnePassword, canRetry: true, category: .onePassword,
            symbol: "clock.badge.exclamationmark", technicalDetail: detail, occurred: occurred)
    }

    private static func opBusy(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password asked SimpleVPN to slow down",
            explanation: "Too many requests arrived at once, so 1Password is pausing them for a moment.",
            steps: [
                .init("Wait a few seconds."),
                .init("Click **Connect** again."),
            ],
            canRetry: true, category: .onePassword,
            symbol: "hourglass", technicalDetail: detail, occurred: occurred)
    }

    private static func opGeneric(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "1Password couldn\u{2019}t give SimpleVPN the sign-in",
            explanation: "Something went wrong between the two apps. These three things fix nearly all of it.",
            steps: [
                .init("Open **1Password** and unlock it."),
                .init("Check **1Password \u{25B8} Settings \u{25B8} Developer** and tick **\(sdkIntegrationSetting)**."),
                .init("Click **Connect** again, and approve the 1Password prompt if one appears."),
            ],
            action: .openOnePassword, canRetry: true, category: .onePassword,
            symbol: "key.fill", technicalDetail: detail, occurred: occurred)
    }

    // MARK: KeePassXC substring table

    /// Message-text fallback for KeePassXC failures that arrive as strings
    /// (a `lastError` path) — the typed classify above is the main road.
    private static func keePassXC(lowercased s: String, detail: String,
                                  occurred: Date) -> UserFacingError {
        if s.contains("locked") { return kpLocked(detail: detail, occurred: occurred) }
        if s.contains("running") || s.contains("browser integration")
            || s.contains("handshake") || s.contains("connect") {
            return kpNotRunning(detail: detail, occurred: occurred)
        }
        if s.contains("dismissed") || s.contains("denied") || s.contains("cancel") {
            return kpNeedsApproval(detail: detail, occurred: occurred)
        }
        if s.contains("pair") || s.contains("associat") {
            return kpNeedsPairing(detail: detail, occurred: occurred)
        }
        if s.contains("no entry") || s.contains("no logins") || s.contains("matches") {
            return kpNoLogins(host: "", detail: detail, occurred: occurred)
        }
        if s.contains("didn't answer") || s.contains("timed out") {
            return kpTimedOut(detail: detail, occurred: occurred)
        }
        return kpGeneric(detail: detail, occurred: occurred)
    }

    // MARK: KeePassXC cases

    private static func kpNotRunning(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "KeePassXC isn\u{2019}t answering",
            explanation: "SimpleVPN asks the KeePassXC app for this VPN\u{2019}s sign-in, and there\u{2019}s nothing to ask.",
            steps: [
                .init("Open **KeePassXC** and unlock your database."),
                .init("In **KeePassXC \u{25B8} Settings \u{25B8} Browser Integration**, make sure **Enable browser integration** is ticked.",
                      note: "That\u{2019}s the switch that opens the local connection SimpleVPN uses \u{2014} no browser is involved."),
                .init("Come back here and click **Connect** again."),
            ],
            action: .openKeePassXC, canRetry: true, category: .keePassXC,
            symbol: "moon.zzz.fill", technicalDetail: detail, occurred: occurred)
    }

    private static func kpLocked(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "Your KeePassXC database is locked",
            explanation: "KeePassXC can\u{2019}t hand over a sign-in until you\u{2019}ve unlocked it.",
            steps: [
                .init("Switch to **KeePassXC** and unlock the database \u{2014} Touch ID quick-unlock counts."),
                .init("Click **Connect** again."),
            ],
            action: .openKeePassXC, canRetry: true, category: .keePassXC,
            symbol: "lock.fill", technicalDetail: detail, occurred: occurred)
    }

    private static func kpNeedsApproval(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "KeePassXC needs you to allow SimpleVPN",
            explanation: "KeePassXC asks your permission before it hands an entry to another app.",
            steps: [
                .init("Switch to **KeePassXC** \u{2014} it\u{2019}s showing a prompt about **SimpleVPN**."),
                .init("Choose **Allow** (tick **Remember** to skip the ask next time)."),
                .init("Click **Connect** again."),
            ],
            action: .openKeePassXC, canRetry: true, category: .approval,
            symbol: "hand.raised.fill", technicalDetail: detail, occurred: occurred)
    }

    private static func kpNeedsPairing(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "SimpleVPN and KeePassXC need to pair again",
            explanation: "KeePassXC no longer recognises SimpleVPN \u{2014} the pairing was never finished, or it was removed from the database.",
            steps: [
                .init("Click **Connect** again \u{2014} KeePassXC will ask to pair."),
                .init("Give the connection a name (\u{201C}SimpleVPN\u{201D} is fine) and confirm.",
                      note: "The pairing is stored inside your database, so it follows the database wherever it goes."),
            ],
            action: .openKeePassXC, canRetry: true, category: .keePassXC,
            symbol: "link.badge.plus", technicalDetail: detail, occurred: occurred)
    }

    private static func kpNoLogins(host: String, detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "KeePassXC has no entry for this VPN",
            explanation: host.isEmpty
                ? "No entry\u{2019}s URL matches the address this VPN looks for."
                : "No entry\u{2019}s URL matches \u{201C}\(host)\u{201D}.",
            steps: [
                .init("Open **KeePassXC** and find (or create) this VPN\u{2019}s entry."),
                .init(host.isEmpty
                      ? "Put the VPN\u{2019}s address in the entry\u{2019}s **URL** field."
                      : "Put **https://\(host)** in the entry\u{2019}s **URL** field."),
                .init("Click **Connect** again."),
            ],
            action: .openKeePassXC, canRetry: true, category: .credentials,
            symbol: "magnifyingglass", technicalDetail: detail, occurred: occurred)
    }

    private static func kpAmbiguous(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "More than one KeePassXC entry matches",
            explanation: "Several entries carry this VPN\u{2019}s address, and nothing says which one is right.",
            steps: [
                .init("Open **Manage VPNs** and select this VPN."),
                .init("In its **Credentials** settings, type the entry\u{2019}s username into **Account**."),
                .init("Click **Connect** again."),
            ],
            action: .manageVPNs, canRetry: true, category: .credentials,
            symbol: "square.on.square", technicalDetail: detail, occurred: occurred)
    }

    private static func kpTimedOut(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "KeePassXC didn\u{2019}t answer",
            explanation: "The request took too long \u{2014} usually a prompt waiting somewhere you couldn\u{2019}t see it.",
            steps: [
                .init("Bring **KeePassXC** to the front and make sure the database is unlocked."),
                .init("Click **Connect** again, and answer the prompt if one appears."),
            ],
            action: .openKeePassXC, canRetry: true, category: .keePassXC,
            symbol: "clock.badge.exclamationmark", technicalDetail: detail, occurred: occurred)
    }

    private static func kpGeneric(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "KeePassXC couldn\u{2019}t give SimpleVPN the sign-in",
            explanation: "Something went wrong between the two apps. These usually fix it.",
            steps: [
                .init("Open **KeePassXC** and unlock your database."),
                .init("Check **Settings \u{25B8} Browser Integration** is enabled."),
                .init("Click **Connect** again."),
            ],
            action: .openKeePassXC, canRetry: true, category: .keePassXC,
            symbol: "key.horizontal.fill", technicalDetail: detail, occurred: occurred)
    }

    // MARK: Non-1Password cases

    private static func managed(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "This VPN\u{2019}s settings are managed for you",
            explanation: "Whoever looks after this Mac has locked these settings, so SimpleVPN can\u{2019}t change them.",
            steps: [
                .init("You can still connect and disconnect as normal."),
                .init("To have something changed, ask whoever manages this Mac."),
            ],
            category: .configuration, symbol: "lock.fill",
            technicalDetail: detail, occurred: occurred)
    }

    private static func extensionNotApproved(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "SimpleVPN\u{2019}s network extension needs approving",
            explanation: "macOS keeps the part of SimpleVPN that builds tunnels switched off until you allow it, once.",
            steps: [
                .init("Open **System Settings \u{25B8} General \u{25B8} Login Items & Extensions**."),
                .init("Under **Network Extensions**, turn SimpleVPN on."),
                .init("Come back here and click **Connect** again."),
            ],
            action: .loginItems, canRetry: true, category: .configuration,
            symbol: "puzzlepiece.extension", technicalDetail: detail, occurred: occurred)
    }

    private static func offline(detail: String, occurred: Date) -> UserFacingError {
        UserFacingError(
            title: "This Mac isn\u{2019}t online",
            explanation: "A VPN needs a working internet connection to build its tunnel on top of.",
            steps: [
                .init("Check Wi‑Fi or the network cable."),
                .init("Open a web page to confirm the connection works."),
                .init("Come back here and click **Connect** again."),
            ],
            action: .networkSettings, canRetry: true, category: .network,
            symbol: "wifi.exclamationmark", technicalDetail: detail, occurred: occurred)
    }

    /// Unrecognised. Still friendly, still actionable, and the raw text only
    /// ever appears inside the details disclosure — unless the message is
    /// already our own plain-language prose, in which case it leads.
    private static func generic(raw: String, detail: String, occurred: Date) -> UserFacingError {
        let support = Step("If it keeps happening, use **Help \u{25B8} Report an Issue** and include the details below.")
        if isPlainProse(raw) {
            let (headline, rest) = splitHeadline(raw)
            return UserFacingError(
                title: headline, explanation: rest, steps: [support],
                category: .generic, symbol: "info.circle.fill",
                technicalDetail: detail, occurred: occurred)
        }
        return UserFacingError(
            title: "Something went wrong",
            explanation: "SimpleVPN couldn\u{2019}t finish what it was doing. The exact wording is in the details below.",
            steps: [.init("Try again."), support],
            canRetry: true, category: .generic, symbol: "exclamationmark.triangle.fill",
            technicalDetail: detail, occurred: occurred)
    }

    /// Is this message already written for a person? Our own `lastError` strings
    /// are; an SDK's ("error initializing client: …") is not, and must not be
    /// promoted onto a title.
    private static func isPlainProse(_ raw: String) -> Bool {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count > 3, text.count < 400,
              let first = text.first, first.isUppercase,
              text.split(separator: " ").count >= 3 else { return false }
        let jargon = ["error", "failed", "exception", "domain=", "code=", "://", "0x",
                      "nsurl", "errno", "nil", "null", "{", "}", "<", ">"]
        let s = text.lowercased()
        return !jargon.contains { s.contains($0) }
    }

    /// First sentence as the title, the remainder as the explanation. A long
    /// opening sentence isn't a title, so it all becomes the explanation.
    private static func splitHeadline(_ raw: String) -> (String, String) {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let stop = text.firstIndex(of: "."), text.distance(from: text.startIndex, to: stop) <= 70 else {
            return text.count <= 70 ? (text, "") : ("Something went wrong", text)
        }
        let headline = String(text[text.startIndex..<stop])
        let rest = String(text[text.index(after: stop)...]).trimmingCharacters(in: .whitespaces)
        return (headline, rest)
    }
}

// MARK: - Redaction

nonisolated extension UserFacingError {

    /// Everything that reaches `technicalDetail` goes through here first. The
    /// 1Password failures don't carry secrets today — this is so they can't
    /// start to, and so a future error path can't leak a typed password by
    /// quoting the request back at us.
    ///
    /// The RULES are not here: they are `SecretScrubber`, shared with the debug
    /// bundle and the diagnostic report, so a secret shape learned in one place
    /// is known in all three. This entry point only chooses the policy —
    /// `.errorDetail`, which keeps addresses and host-key fingerprints (an error
    /// about a server is useless without them, and a fingerprint is public) and
    /// bounds the result to one readable sentence.
    static func redact(_ raw: String, secrets: [String] = []) -> String {
        SecretScrubber(policy: .errorDetail, literalSecrets: secrets).scrub(raw)
    }
}
