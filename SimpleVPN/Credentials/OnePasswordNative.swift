// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordNative.swift
//  Native 1Password: the official 1Password Go SDK (desktop-app authentication
//  — 1Password itself shows a Touch ID / authorization prompt; no `op` CLI, no
//  service-account token, and the app never sees the vault password).
//
//  The SDK lives in the bundled `opnative-helper` binary, NOT in the app: its
//  IPC path dlopens 1Password's own (AgileBits-signed) dylib, which needs the
//  library-validation relaxation — and AMFI kills any app embedding a System
//  Extension that carries that relaxation ("Hardened Runtime relaxation
//  entitlements disallowed on System Extensions"; build 87 died this way). The
//  helper is our own signed one-shot tool speaking the same JSON contract
//  (opnative.h / OPNativeHelper/main.swift) over stdin/stdout. Sessions last
//  ~10 minutes; the shim caches the SDK client and transparently
//  re-authenticates (one retry) when the session expires.
//
//  TWO THINGS THAT LOOK LIKE FAULTS AND ARE NOT. Both cost a day each; neither is
//  worth chasing again.
//
//   1. THE EXC_GUARD PAIR IS NOISE. 1Password's own IPC raises a matching EXC_GUARD
//      on both ends as each request is torn down — on runs that return correct JSON
//      and exit 0. It is their file-descriptor guard firing on a socket they close
//      themselves, it is caught, and it is present on every successful call. Do NOT
//      "fix" it: there is nothing on our side of the boundary to fix, and the last
//      person to try spent the day inside somebody else's dylib.
//
//   2. THE FIRST SPAWN AFTER AN INSTALL CAN BE REFUSED. macOS makes a one-shot
//      Gatekeeper assessment of `opnative-helper` the first time it is executed
//      after the app is installed or updated, and while that is in flight the spawn
//      is denied outright ("ASP: Security policy would not allow process"). The very
//      next spawn works. That refusal is `OnePasswordNativeError.helperRefusedToStart`
//      — its own case precisely so nothing mistakes it for an answer about 1Password
//      — and `probeAnswer()` retries once on it. See `ProbeAnswer`.
//

import Foundation
import os

/// Error kinds mirrored from the Go shim (main.go) — keep the raw values in
/// sync with its kind* constants.
enum OnePasswordNativeError: LocalizedError, Sendable, Equatable {
    case appNotInstalled
    case appNotRunning
    case integrationDisabled
    case userCancelled
    case sessionExpired
    case itemNotFound(String)
    /// 1Password wouldn't answer for the account we named (`account` is what we
    /// tried, "" when none is configured; `detail` is the SDK's own wording).
    /// Distinct from itemNotFound: the fix is naming the account, not
    /// re-picking the item.
    case accountNotFound(account: String, detail: String)
    case ambiguous(String)
    case rateLimited
    case badRequest(String)
    case badResponse
    /// THE HELPER NEVER RAN. `posix_spawn` itself was refused — not an answer from
    /// 1Password, not an answer from our own tool, no answer at all.
    ///
    /// Its own case because the first execution of `opnative-helper` after any install
    /// or update is denied by a one-shot Gatekeeper assessment ("Security policy would
    /// not allow process"), and the very next spawn works. Folded into `.other` it was
    /// indistinguishable from "1Password said no", which is how one refused spawn used
    /// to poison the vendor for a whole session.
    case helperRefusedToStart(String)
    case other(String)

    init(kind: String, message: String) {
        switch kind {
        case "appNotInstalled": self = .appNotInstalled
        case "appNotRunning": self = .appNotRunning
        case "integrationDisabled": self = .integrationDisabled
        case "userCancelled": self = .userCancelled
        case "sessionExpired": self = .sessionExpired
        case "itemNotFound": self = .itemNotFound(message)
        // The account we asked for isn't known here — the caller fills it in.
        case "accountNotFound": self = .accountNotFound(account: "", detail: message)
        case "ambiguous": self = .ambiguous(message)
        case "rateLimited": self = .rateLimited
        case "badRequest": self = .badRequest(message)
        default: self = .other(message)
        }
    }

    var errorDescription: String? {
        switch self {
        case .appNotInstalled:
            "The 1Password app isn't installed. SimpleVPN talks directly to the "
            + "1Password app (version 8 or later) — install it from 1password.com."
        case .appNotRunning:
            "1Password doesn't seem to be running or is locked. Open and unlock "
            + "1Password, then try again."
        case .integrationDisabled:
            // The SDK's own message still names "Integrate with other apps",
            // a toggle 1Password removed — say what today's Settings shows.
            "1Password refused the connection. In 1Password: Settings \u{25B8} "
            + "Developer \u{25B8} Developer Integrations \u{25B8} turn on "
            + "\u{201C}Integrate with 1Password SDKs\u{201D}, then try again."
        case .userCancelled:
            "The 1Password authorization prompt was dismissed. Press Connect "
            + "again and approve the prompt to let SimpleVPN read this item."
        case .sessionExpired:
            "The 1Password authorization expired. Try again — 1Password will "
            + "ask you to re-approve."
        case .itemNotFound(let detail):
            "1Password couldn't find that item or field (\(detail)). Open this "
            + "VPN's credential settings and pick the item again."
        case .accountNotFound(let account, let detail):
            (account.isEmpty
                ? "1Password needs to know which of your accounts to ask. "
                : "1Password doesn't have an account called \u{201C}\(account)\u{201D}. ")
            + "Open this VPN's credential settings and type the name shown at "
            + "the top of 1Password's sidebar into Account."
            + (detail.isEmpty ? "" : " (\(detail))")
        case .ambiguous(let detail):
            "More than one 1Password item matches (\(detail)). Set a vault, or "
            + "use the item's exact title or UUID."
        case .rateLimited:
            "1Password is rate-limiting requests. Wait a moment and try again."
        case .badRequest(let detail):
            "Invalid 1Password secret reference: \(detail)"
        case .badResponse:
            "1Password returned an unexpected response."
        case .helperRefusedToStart(let detail):
            // Says what happened and does NOT blame 1Password: nothing about this is
            // 1Password's doing, and sending someone to check their vault app would
            // waste their time. "Try again" is the honest advice because the retry
            // genuinely is what fixes the Gatekeeper case.
            "macOS wouldn\u{2019}t let SimpleVPN start its 1Password helper. Try again \u{2014} "
            + "the first attempt after a new version of SimpleVPN is sometimes refused, and "
            + "the next one goes through."
            + (detail.isEmpty ? "" : " (\(detail))")
        case .other(let message):
            message.isEmpty ? "1Password request failed." : message
        }
    }
}

/// Swift face of the SDK helper. All calls are safe from any actor; the
/// blocking helper runs are driven from a dedicated serial queue (never the
/// cooperative pool — an unanswered Touch ID prompt can block for minutes).
enum OnePasswordNative {
    /// The helper shipped with this build (nil = bundle is damaged/stripped).
    nonisolated static var helperURL: URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/opnative-helper")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// Whether this build carries the native integration at all.
    nonisolated static var isLinked: Bool { helperURL != nil }

    /// Serialises helper runs (1Password shows one authorization prompt at a
    /// time) and keeps the long waits off the Swift concurrency pool.
    private nonisolated static let queue = DispatchQueue(
        label: "com.bragi0.SimpleVPN.1password-native", qos: .userInitiated)

    // nonisolated: read from the helper queue and from the nonisolated probe, like
    // everything else on this type.
    private nonisolated static let log = Logger(subsystem: "com.bragi0.SimpleVPN",
                                                category: "1password-native")

    /// WHAT THE HELPER SAID ON STDERR, fit to be logged.
    ///
    /// It used to go to `/dev/null`, and that cost a day: a vendor row went sticky-bad
    /// on a Mac where the helper's own first line said exactly why, and the diagnosis
    /// had to be reconstructed from the outside. It is captured now — but this is a
    /// CREDENTIAL HELPER, so everything it prints is treated as potentially carrying a
    /// secret:
    ///
    ///   • scrubbed through `SecretScrubber` before it goes anywhere (the `.logBundle`
    ///     policy: machine output, so numbers survive, but PEM blocks, keyed values,
    ///     high-entropy runs, addresses and hostnames do not),
    ///   • bounded, so a runaway helper cannot fill the log,
    ///   • logged at `.debug` and interpolated `privacy: .private`, never `.public` —
    ///     it stays out of sysdiagnose and off anybody's screen unless a developer has
    ///     deliberately turned private data on.
    ///
    /// Never put this in an error message, a user-facing string or the diagnostic
    /// report. It is a breadcrumb for whoever is looking at a live log, and nothing
    /// else.
    private nonisolated static func loggableStderr(_ data: Data) -> String? {
        guard !data.isEmpty,
              let raw = String(data: data.prefix(8 * 1024), encoding: .utf8)
        else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return SecretScrubber(policy: .logBundle).scrub(String(trimmed.prefix(1000)))
    }

    /// One helper invocation: spawn, feed stdin, read stdout to EOF. The
    /// watchdog terminates a wedged helper; task cancellation kills it too —
    /// an unanswered authorization prompt must never wedge the connect flow.
    private nonisolated static func runHelper(
        _ mode: String, input: Data?, killAfter: TimeInterval
    ) async throws -> Data {
        guard let helperURL else {
            throw OnePasswordNativeError.other("The 1Password helper is missing from the app bundle.")
        }
        let processBox = OSAllocatedUnfairLock<Process?>(initialState: nil)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                queue.async {
                    let process = Process()
                    process.executableURL = helperURL
                    process.arguments = [mode]
                    let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
                    process.standardInput = inPipe
                    process.standardOutput = outPipe
                    // Captured rather than discarded — see `loggableStderr`.
                    process.standardError = errPipe
                    processBox.withLock { $0 = process }
                    do {
                        try process.run()
                    } catch {
                        // THE SPAWN WAS REFUSED — a distinct outcome from "the helper
                        // answered no", and the whole reason `helperRefusedToStart`
                        // exists. `probeAnswer()` retries on it; nothing treats it as a
                        // verdict about 1Password.
                        cont.resume(throwing: OnePasswordNativeError.helperRefusedToStart(
                            error.localizedDescription))
                        return
                    }
                    if let input { inPipe.fileHandleForWriting.write(input) }
                    try? inPipe.fileHandleForWriting.close()
                    DispatchQueue.global().asyncAfter(deadline: .now() + killAfter) {
                        processBox.withLock { if $0 === process, process.isRunning { process.terminate() } }
                    }
                    // Drained on ANOTHER queue, concurrently with stdout. A helper that
                    // wrote more than a pipe buffer to stderr while we blocked on stdout
                    // would deadlock both ends — which is a far worse bug than the one
                    // capturing stderr is here to help diagnose.
                    let errBox = OSAllocatedUnfairLock<Data>(initialState: Data())
                    let drained = DispatchSemaphore(value: 0)
                    DispatchQueue.global().async {
                        let bytes = errPipe.fileHandleForReading.readDataToEndOfFile()
                        errBox.withLock { $0 = bytes }
                        drained.signal()
                    }
                    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    drained.wait()
                    processBox.withLock { $0 = nil }
                    if let said = loggableStderr(errBox.withLock({ $0 })) {
                        log.debug("""
                            opnative-helper \(mode, privacy: .public) \
                            exit \(process.terminationStatus, privacy: .public) \
                            stderr: \(said, privacy: .private)
                            """)
                    }
                    cont.resume(returning: data)
                }
            }
        } onCancel: {
            processBox.withLock { $0?.terminate() }
        }
    }

    // nonisolated: the app target defaults to MainActor isolation, which would
    // otherwise make these Codable conformances main-actor-only — they're used
    // on the resolver queue.
    private nonisolated struct Request: Encodable {
        var integrationName: String
        var integrationVersion: String
        var account: String
        var secretRefs: [String]
        var timeoutSeconds: Int
    }
    private nonisolated struct Response: Decodable {
        struct Err: Decodable { var kind: String; var message: String }
        var values: [String: String]?
        var error: Err?
    }
    private nonisolated struct ProbeResponse: Decodable {
        var available: Bool
        var reason: String?
    }

    /// One field of a fetched item, in the CLI-era vocabulary the mapping UI
    /// grew up with (purpose USERNAME/PASSWORD, type OTP/CONCEALED/STRING).
    /// For OTP fields `value` is always empty and `otp` carries the CURRENT
    /// code — the shim never releases the otpauth:// enrollment seed.
    nonisolated struct OPItemField: Decodable, Sendable, Hashable {
        var id: String
        var label: String
        var purpose: String
        var type: String
        var value: String
        var otp: String?
    }

    /// A full item read: identity plus every field, for auto-detection and the
    /// field-mapping sheet.
    nonisolated struct OPItem: Decodable, Sendable {
        var title: String
        var vaultID: String
        var itemID: String
        var fields: [OPItemField]
    }

    private nonisolated struct ItemRequest: Encodable {
        var integrationName: String
        var integrationVersion: String
        var account: String
        var vault: String
        var itemRef: String
        var timeoutSeconds: Int
    }
    private nonisolated struct ItemResponse: Decodable {
        struct Err: Decodable { var kind: String; var message: String }
        var item: OPItem?
        var error: Err?
    }

    /// One vault of the account, as offered by the vault picker. Overview only
    /// — a list reply never carries an item's fields.
    nonisolated struct OPVaultOverview: Decodable, Sendable, Hashable, Identifiable {
        var id: String
        var title: String
    }

    /// One item of a vault, as offered by the item picker. `category` is
    /// 1Password's own word for the item type ("Login", "Password", …) — shown
    /// beside the title so two similarly named entries can be told apart.
    nonisolated struct OPItemOverview: Decodable, Sendable, Hashable, Identifiable {
        var id: String
        var title: String
        var category: String
    }

    /// One item plus the vault it lives in — what the item browser shows when
    /// no vault has been chosen. 1Password lists items one vault at a time; the
    /// person searching for their VPN shouldn't have to know that.
    nonisolated struct OPItemInVault: Sendable, Hashable, Identifiable {
        var itemID: String
        var title: String
        var category: String
        var vaultID: String
        var vaultTitle: String
        /// Vault-qualified: the same item id can't repeat, but a defensive
        /// compound id keeps the list stable if a reply ever duplicated one.
        var id: String { "\(vaultID)/\(itemID)" }
    }

    private nonisolated struct ListRequest: Encodable {
        var integrationName: String
        var integrationVersion: String
        var account: String
        var vault: String
        var timeoutSeconds: Int
    }

    private nonisolated struct LookupRequest: Encodable {
        var integrationName: String
        var integrationVersion: String
        var account: String
        var vault: String
        var query: String
        var limit: Int
        var timeoutSeconds: Int
    }

    /// One lookup hit: the item, its category, and — the point of the endpoint
    /// — the vault it turned out to live in. `score` is the shim's ranking on
    /// FuzzyMatch's own ladder, already sorted closest-first.
    nonisolated struct OPItemMatch: Decodable, Sendable, Hashable, Identifiable {
        var itemID: String
        var title: String
        var category: String
        var vaultID: String
        var vaultTitle: String
        var score: Int
        /// Vault-qualified, matching OPItemInVault's id rule.
        var id: String { "\(vaultID)/\(itemID)" }
    }

    private nonisolated struct LookupResponse: Decodable {
        struct Err: Decodable { var kind: String; var message: String }
        var matches: [OPItemMatch]?
        var error: Err?
    }
    private nonisolated struct ListResponse: Decodable {
        struct Err: Decodable { var kind: String; var message: String }
        var vaults: [OPVaultOverview]?
        var items: [OPItemOverview]?
        var error: Err?
    }

    /// The helper reports failures by kind; only this side knows which account
    /// was asked for, so an accountNotFound is completed here rather than
    /// surfacing a name-less complaint the user can't act on.
    private nonisolated static func nativeError(
        kind: String, message: String, account: String
    ) -> OnePasswordNativeError {
        let error = OnePasswordNativeError(kind: kind, message: message)
        // Every real call funnels through here, which makes this the one place
        // that learns the SDK integration has been turned back OFF since setup
        // was verified — so it's where the setup walkthrough is re-armed.
        OnePasswordPreflight.noteFailure(error)
        if case .accountNotFound(_, let detail) = error {
            return .accountNotFound(account: account, detail: detail)
        }
        return error
    }

    /// Resolve `op://vault/item/field` secret references via the 1Password
    /// desktop app. Returns a value for every requested reference or throws —
    /// never a partial result. `account` names the 1Password account to ask
    /// (CredentialSource.account) — sidebar name or UUID. It is not really
    /// optional: the SDK's desktop integration rejects an account it can't
    /// match, empty string included, with "Account not found".
    nonisolated static func resolve(
        refs: [String], account: String = "", timeout: TimeInterval = 180
    ) async throws -> [String: String] {
        let request = Request(
            integrationName: "SimpleVPN",
            integrationVersion: Bundle.main.object(
                forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev",
            account: account,
            secretRefs: refs,
            timeoutSeconds: Int(timeout))
        let requestData = try JSONEncoder().encode(request)

        // Helper gets the request's own timeout plus slack before the kill.
        let data = try await runHelper("resolve", input: requestData, killAfter: timeout + 15)
        guard let response = try? JSONDecoder().decode(Response.self, from: data) else {
            throw OnePasswordNativeError.badResponse
        }
        if let err = response.error {
            throw nativeError(kind: err.kind, message: err.message, account: account)
        }
        guard let values = response.values else {
            throw OnePasswordNativeError.badResponse
        }
        return values
    }

    /// Fetch one item — by title or UUID, optionally scoped to a vault (title
    /// or UUID; empty searches every vault) — with its full field list via the
    /// 1Password desktop app. This is what serves the field-mapping sheet and
    /// any resolve that lacks the explicit coordinates secret references need.
    nonisolated static func getItem(
        reference: String, vault: String = "", account: String = "",
        timeout: TimeInterval = 180
    ) async throws -> OPItem {
        let request = ItemRequest(
            integrationName: "SimpleVPN",
            integrationVersion: Bundle.main.object(
                forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev",
            account: account,
            vault: vault,
            itemRef: reference,
            timeoutSeconds: Int(timeout))
        let requestData = try JSONEncoder().encode(request)

        let data = try await runHelper("item", input: requestData, killAfter: timeout + 15)
        guard let response = try? JSONDecoder().decode(ItemResponse.self, from: data) else {
            throw OnePasswordNativeError.badResponse
        }
        if let err = response.error {
            throw nativeError(kind: err.kind, message: err.message, account: account)
        }
        guard let item = response.item else {
            throw OnePasswordNativeError.badResponse
        }
        return item
    }

    // MARK: Browsing (pickers)

    /// The account's vaults, for the vault picker. Overviews only — nothing in
    /// the reply describes an item's contents. Called ONLY from an explicit
    /// user action: the first one can raise 1Password's authorization prompt.
    nonisolated static func listVaults(
        account: String = "", timeout: TimeInterval = 180
    ) async throws -> [OPVaultOverview] {
        let data = try await runList(vault: "", account: account, timeout: timeout)
        return try vaults(fromListReply: data, account: account)
    }

    /// One vault's items, for the item picker. `vault` is required — the SDK's
    /// item list is per-vault — and may be a vault title or UUID.
    nonisolated static func listItems(
        vault: String, account: String = "", timeout: TimeInterval = 180
    ) async throws -> [OPItemOverview] {
        let v = vault.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else {
            throw OnePasswordNativeError.badRequest("no vault chosen")
        }
        let data = try await runList(vault: v, account: account, timeout: timeout)
        return try items(fromListReply: data, account: account)
    }

    /// Every item the account can show, across every vault, for the item
    /// browser when no vault has been chosen. The SDK has no "everything" list,
    /// so this fans out over the vaults — bounded, because a hundred vaults must
    /// not become a hundred simultaneous helper launches. (Helper runs are
    /// serialised on `queue` today, so the bound is about restraint rather than
    /// speed; it stops being cosmetic the moment that queue widens.)
    ///
    /// A vault that refuses is skipped rather than failing the whole list: one
    /// unreadable drawer shouldn't hide the other twenty. Failures that concern
    /// the ACCOUNT (unknown account, integration off, cancelled prompt) surface
    /// from the vault listing itself, which happens first.
    nonisolated static func listItemsAcrossVaults(
        account: String = "", maxConcurrent: Int = 4, timeout: TimeInterval = 180
    ) async throws -> [OPItemInVault] {
        // The lookup endpoint does exactly this fan-out inside ONE helper run
        // (and one authorization), so prefer it and keep the Swift-side
        // fan-out below as the fallback for an older archive that predates
        // OPNativeLookup — the helper's `default:` arm exits non-zero, which
        // arrives here as an unparseable reply rather than a crash.
        if let matches = try? await lookup(query: "", account: account, timeout: timeout) {
            return matches.map {
                OPItemInVault(itemID: $0.itemID, title: $0.title, category: $0.category,
                              vaultID: $0.vaultID, vaultTitle: $0.vaultTitle)
            }
        }
        let vaults = try await listVaults(account: account, timeout: timeout)
        guard !vaults.isEmpty else { return [] }
        let limit = max(1, min(maxConcurrent, vaults.count))
        var collected: [OPItemInVault] = []
        await withTaskGroup(of: [OPItemInVault].self) { group in
            var next = 0
            func addNext() {
                let vault = vaults[next]
                next += 1
                group.addTask {
                    guard let items = try? await listItems(
                        vault: vault.id, account: account, timeout: timeout) else { return [] }
                    return items.map {
                        OPItemInVault(itemID: $0.id, title: $0.title, category: $0.category,
                                      vaultID: vault.id, vaultTitle: vault.title)
                    }
                }
            }
            while next < limit { addNext() }
            while let batch = await group.next() {
                collected.append(contentsOf: batch)
                if next < vaults.count { addNext() }
            }
        }
        // One alphabetical list: which vault an item lives in is secondary
        // information here, so it must not scatter the names being searched.
        return collected.sorted {
            let byTitle = $0.title.localizedCaseInsensitiveCompare($1.title)
            if byTitle != .orderedSame { return byTitle == .orderedAscending }
            return $0.vaultTitle.localizedCaseInsensitiveCompare($1.vaultTitle) == .orderedAscending
        }
    }

    /// The readable name of a vault we only know by id — how a successful item
    /// read back-fills an empty Vault field. Also matches on title, because
    /// callers hold whichever of the two 1Password gave them.
    nonisolated static func vaultTitle(forID id: String,
                                       in vaults: [OPVaultOverview]) -> String? {
        let key = id.trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }
        if let match = vaults.first(where: { $0.id == key }) { return match.title }
        if let match = vaults.first(where: {
            $0.title.caseInsensitiveCompare(key) == .orderedSame
        }) { return match.title }
        return nil
    }

    /// Look an item up BY NAME and learn which vault it lives in — the one
    /// thing the SDK can't be asked directly (its item list is per-vault and
    /// unfiltered) and the last capability the retired `op` CLI had that this
    /// channel didn't. One helper run, one authorization, ranked closest-first;
    /// an empty query is a bounded browse of everything the account can show.
    ///
    /// Called ONLY from an explicit user action or in service of one: the first
    /// call can raise 1Password's authorization prompt.
    nonisolated static func lookup(
        query: String, vault: String = "", account: String = "", limit: Int = 0,
        timeout: TimeInterval = 180
    ) async throws -> [OPItemMatch] {
        let request = LookupRequest(
            integrationName: "SimpleVPN",
            integrationVersion: Bundle.main.object(
                forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev",
            account: account,
            vault: vault.trimmingCharacters(in: .whitespaces),
            query: query.trimmingCharacters(in: .whitespaces),
            limit: limit,
            timeoutSeconds: Int(timeout))
        let data = try await runHelper("lookup", input: try JSONEncoder().encode(request),
                                      killAfter: timeout + 15)
        return try matches(fromLookupReply: data, account: account)
    }

    /// The item a name resolves to when it resolves to exactly one — the shape
    /// a caller that needs coordinates (vault + item) actually wants. An
    /// ambiguous name is an error carrying the candidates, same policy as
    /// `getItem`: quietly picking one would connect a VPN with the wrong
    /// credentials.
    nonisolated static func lookupOne(
        query: String, vault: String = "", account: String = "",
        timeout: TimeInterval = 180
    ) async throws -> OPItemMatch {
        let all = try await lookup(query: query, vault: vault, account: account,
                                   timeout: timeout)
        // Only the closest tier competes: an exact title beats a substring hit
        // outright, so "VPN" matching six items isn't ambiguous when one of
        // them is called exactly that.
        guard let best = all.first else {
            throw OnePasswordNativeError.itemNotFound(
                "no item matching \u{201C}\(query.trimmingCharacters(in: .whitespaces))\u{201D}")
        }
        let tied = all.filter { $0.score == best.score }
        guard tied.count == 1 else {
            let names = tied.prefix(4).map { "\u{201C}\($0.title)\u{201D} in vault \u{201C}\($0.vaultTitle)\u{201D}" }
            throw OnePasswordNativeError.ambiguous(
                "\(tied.count) items match: \(names.joined(separator: ", "))")
        }
        return best
    }

    /// Decode half of `lookup`, split out so tests can pin the wire shape and
    /// the account-aware error mapping without spawning the helper.
    nonisolated static func matches(fromLookupReply data: Data, account: String) throws
        -> [OPItemMatch] {
        guard let response = try? JSONDecoder().decode(LookupResponse.self, from: data) else {
            throw OnePasswordNativeError.badResponse
        }
        if let err = response.error {
            throw nativeError(kind: err.kind, message: err.message, account: account)
        }
        guard let matches = response.matches else { throw OnePasswordNativeError.badResponse }
        return matches
    }

    private nonisolated static func runList(
        vault: String, account: String, timeout: TimeInterval
    ) async throws -> Data {
        let request = ListRequest(
            integrationName: "SimpleVPN",
            integrationVersion: Bundle.main.object(
                forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev",
            account: account,
            vault: vault,
            timeoutSeconds: Int(timeout))
        return try await runHelper("list", input: try JSONEncoder().encode(request),
                                   killAfter: timeout + 15)
    }

    /// Decode half of `listVaults`, split out so tests can pin the wire shape
    /// and the account-aware error mapping without spawning the helper.
    nonisolated static func vaults(fromListReply data: Data, account: String) throws
        -> [OPVaultOverview] {
        guard let response = try? JSONDecoder().decode(ListResponse.self, from: data) else {
            throw OnePasswordNativeError.badResponse
        }
        if let err = response.error {
            throw nativeError(kind: err.kind, message: err.message, account: account)
        }
        guard let vaults = response.vaults else { throw OnePasswordNativeError.badResponse }
        return vaults
    }

    /// Decode half of `listItems` — see `vaults(fromListReply:account:)`.
    nonisolated static func items(fromListReply data: Data, account: String) throws
        -> [OPItemOverview] {
        guard let response = try? JSONDecoder().decode(ListResponse.self, from: data) else {
            throw OnePasswordNativeError.badResponse
        }
        if let err = response.error {
            throw nativeError(kind: err.kind, message: err.message, account: account)
        }
        guard let items = response.items else { throw OnePasswordNativeError.badResponse }
        return items
    }

    /// WHAT THE PROMPT-FREE CHECK LEARNED — three outcomes, not two.
    ///
    /// A Bool could not tell "the helper ran and said there is no SDK here" from "the
    /// helper never ran", and the difference is the whole bug: the first execution of
    /// `opnative-helper` after any install or update is denied by a one-shot Gatekeeper
    /// assessment and the very next spawn succeeds. A `false` from that refusal was
    /// read as "old 1Password", turned into `.blocked(.needsUpdate)` by the deep scan,
    /// and — because `deepWins` lets that override a cheap `.ready` — went STICKY for
    /// the rest of the session. One coin flip per app update, poisoning a working
    /// vendor.
    nonisolated enum ProbeAnswer: Sendable, Equatable {
        /// The helper ran and found a 1Password with SDK support.
        case available
        /// The helper ran and found none. A real finding: this is an old 1Password.
        case unavailable
        /// NO ANSWER. The spawn was refused, the helper was killed, or its reply did
        /// not parse. Callers must leave whatever they already believed alone — this
        /// says nothing at all about 1Password.
        case noAnswer
    }

    /// Prompt-free availability check: is a 1Password app with SDK support
    /// installed? (Does NOT confirm it's running, unlocked, or that the
    /// "Integrate with other apps" developer setting is on.)
    ///
    /// RETRIED ONCE, and only for a refused spawn — because that refusal is
    /// one-shot by construction (the assessment is cached the moment it is made, so
    /// the second spawn of the same binary is allowed) and because a retry of a real
    /// answer would just be the same answer twice.
    nonisolated static func probeAnswer() async -> ProbeAnswer {
        let first = await probeOnce()
        guard case .refused = first else { return first.answer }
        log.debug("opnative-helper probe: spawn refused; retrying once")
        return await probeOnce().answer
    }

    /// One probe attempt, keeping "refused" separate so `probeAnswer()` can decide
    /// whether a retry is worth anything.
    private nonisolated enum ProbeAttempt: Sendable {
        case answered(Bool)
        /// The spawn itself was denied — the case that earns the retry.
        case refused
        /// Ran, but produced nothing usable (killed, empty, unparseable).
        case noReply

        var answer: ProbeAnswer {
            switch self {
            case .answered(true): .available
            case .answered(false): .unavailable
            case .refused, .noReply: .noAnswer
            }
        }
    }

    private nonisolated static func probeOnce() async -> ProbeAttempt {
        let data: Data
        do {
            data = try await runHelper("probe", input: nil, killAfter: 10)
        } catch OnePasswordNativeError.helperRefusedToStart(let detail) {
            log.debug("opnative-helper probe: \(detail, privacy: .private)")
            return .refused
        } catch {
            return .noReply
        }
        guard let probe = try? JSONDecoder().decode(ProbeResponse.self, from: data) else {
            // An unparseable reply is not a verdict either. A helper terminated by the
            // watchdog leaves an empty pipe, and reading that as "no SDK" is the same
            // mistake one layer up.
            return .noReply
        }
        return .answered(probe.available)
    }
}
