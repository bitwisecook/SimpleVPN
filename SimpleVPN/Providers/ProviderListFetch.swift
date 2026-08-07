// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListFetch.swift
//  ASKING A PROVIDER FOR ITS SERVER LIST — the only code in SimpleVPN that talks to
//  a VPN company, and the smallest it could be made.
//
//  WHAT IS NOT HERE IS THE POINT. No account, no token, no sign-in, no key
//  registration, no telemetry, nothing sent about the user, no POST, no cookies, no
//  header that identifies this Mac. One GET, to one hard-coded URL, whose ANSWER can
//  only contribute hostnames, addresses, place names and WireGuard peer keys —
//  because the parser reads nothing else and every field it reads is typed
//  (`ProviderServerList`). Cipher, port, directives and the CA fingerprint ship in
//  the binary and a fetched payload can never touch them.
//
//  WHEN IT RUNS, and the list is exhaustive (Docs/ServiceBundles.md §8): when the
//  user presses a button. Never at launch, never on a timer, never on opening a
//  profile, never on connecting, never in the background. Asking a provider for its
//  list tells that provider somebody at your address runs this app and roughly when,
//  and this repo's standing rule is that a lookup is opt-in and off by default.
//
//  THE FIVE TRANSPORT RULES, all enforced below and all pure enough to test:
//   1. HTTPS with the SYSTEM TRUST STORE. There is no delegate for authentication
//      challenges, so there is no place verification could be turned off, and there
//      must never be one.
//   2. THE HOST IS A CONSTANT. The URL comes from the shipped catalogue and the
//      response must have come from that host.
//   3. A REDIRECT OFF THAT HOST IS REFUSED rather than followed. This is the rule a
//      plain `URLSession.data(from:)` would silently break.
//   4. A SIZE CAP, so a hostile or broken endpoint cannot exhaust memory before the
//      parser ever sees it.
//   5. NEVER SILENTLY ACCEPT. Anything that fails leaves the stored list exactly as
//      it was and says so. A stale list that works beats a fresh list that might not
//      be the provider's.
//

import Foundation
import os

// MARK: - Preferences

/// The two switches of Docs/ServiceBundles.md §8, and the record of which providers
/// the user has agreed to contact.
///
/// Both keys are also in `ConfigAppSettings`, so they move with a setup — and the
/// enabling one is `importable: false` there, for the same reason `app.location` is:
/// a file that could flip an opt-in would turn "opt in" into "opt in on somebody
/// else's behalf".
nonisolated enum ProviderListSettings {

    /// Off. The whole feature.
    static let enabledKey = "providerLists.enabled"
    /// On. Wait until you are connected to that provider before asking it anything.
    static let onlyWhenConnectedKey = "providerLists.onlyWhenConnected"
    /// Which providers the user has said yes to, one at a time. Consenting to
    /// Mullvad is not consenting to Nord.
    static let consentedKey = "providerLists.consented"

    static var enabled: Bool { UserDefaults.standard.bool(forKey: enabledKey) }

    static var onlyWhenConnected: Bool {
        UserDefaults.standard.object(forKey: onlyWhenConnectedKey) == nil
            ? true
            : UserDefaults.standard.bool(forKey: onlyWhenConnectedKey)
    }

    static func hasConsented(_ id: VPNServiceProviderID) -> Bool {
        consented.contains(id.rawValue)
    }

    static var consented: Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: consentedKey) ?? [])
    }

    /// Record a yes. One provider per call — there is deliberately no "allow all".
    static func consent(to id: VPNServiceProviderID) {
        var all = consented
        all.insert(id.rawValue)
        UserDefaults.standard.set(all.sorted(), forKey: consentedKey)
    }

    /// Take it back. The caller also forgets the stored list, so withdrawing leaves
    /// nothing behind.
    static func withdrawConsent(_ id: VPNServiceProviderID) {
        var all = consented
        all.remove(id.rawValue)
        UserDefaults.standard.set(all.sorted(), forKey: consentedKey)
    }
}

// MARK: - The policy (pure)

/// May this fetch happen, and if not, what does the user get told?
///
/// PURE AND SEPARATE FROM THE TRANSPORT on purpose. Every one of these refusals is
/// a sentence somebody reads, and a decision made inside a networking closure is a
/// decision no test can reach.
nonisolated enum ProviderListFetchPolicy {

    /// Why a fetch will not happen. Each case carries the words, because "it did not
    /// work" is the answer that sends a person to the forums.
    enum Refusal: Equatable {
        /// The provider cannot be read at all (Proton VPN).
        case blocked(String)
        /// The whole feature is off, which is its default.
        case turnedOff
        /// An administrator has forbidden it.
        case managed
        /// An OpenVPN provider whose CA is not pinned yet. Fails CLOSED: fetching a
        /// certificate authority that nothing checks is the entire attack.
        case notPinned
        /// The user asked to wait until they are connected to that provider.
        case waitingForTunnel
        /// This provider has never been asked before and the user has not agreed.
        /// Not an error — it is the sheet that names the host before contacting it.
        case needsConsent

        var sentence: String {
            switch self {
            case .blocked(let why): why
            case .turnedOff:
                "Getting server lists from VPN providers is turned off. Turn it on in "
                    + "Settings \u{25B8} General \u{25B8} Privacy \u{2014} nothing is fetched until you ask for it."
            case .managed:
                "Your organization has turned off getting server lists from VPN providers."
            case .notPinned:
                "SimpleVPN does not yet ship this provider\u{2019}s certificate fingerprint, so it "
                    + "cannot check that a list really came from them. Until it does, it will not ask."
            case .waitingForTunnel:
                "SimpleVPN is set to ask this provider for its server list only while you are "
                    + "connected to it, so the request comes from the VPN rather than from your own "
                    + "address. Connect first, or change that in Settings \u{25B8} General \u{25B8} Privacy."
            case .needsConsent:
                "SimpleVPN has not contacted this provider before."
            }
        }
    }

    /// Everything the decision depends on, gathered by the caller so this stays a
    /// function of its inputs.
    struct Conditions: Equatable {
        var enabled: Bool
        var managedForbids: Bool
        var onlyWhenConnected: Bool
        var hasConsented: Bool
        /// Providers a live tunnel currently goes through — see `connected(hosts:)`.
        var connectedProviders: Set<VPNServiceProviderID>
    }

    /// The refusal, or nil to go ahead.
    ///
    /// ORDER MATTERS AND IS THE DESIGN. The provider's own impossibility comes
    /// first, because "Proton will not give us this" is true whatever the settings
    /// say and telling somebody to flip a switch that cannot help is worse than
    /// silence. Then the switches, then the pin, then the two that are about THIS
    /// moment rather than about the feature.
    static func refusal(for provider: VPNServiceProvider, _ c: Conditions) -> Refusal? {
        if let why = provider.blocked { return .blocked(why) }
        if c.managedForbids { return .managed }
        if !c.enabled { return .turnedOff }
        if !provider.canFetch { return .notPinned }
        if !c.hasConsented { return .needsConsent }
        if c.onlyWhenConnected && !c.connectedProviders.contains(provider.id) {
            return .waitingForTunnel
        }
        return nil
    }

    /// Which providers a set of live tunnel server addresses belongs to.
    ///
    /// The one place the feature can be meaningfully better than a browser: if a
    /// tunnel to that provider is already up, the request leaves through their own
    /// exit and they learn essentially nothing new — they are already carrying the
    /// traffic. Matched on the SHIPPED hostname suffix, so a hostname a payload
    /// supplied can never widen what counts as "connected to Mullvad".
    static func connected(hosts: [String]) -> Set<VPNServiceProviderID> {
        var out: Set<VPNServiceProviderID> = []
        for host in hosts.map({ $0.lowercased() }) {
            for p in VPNServiceProviderCatalog.all where host.hasSuffix(p.hostnameSuffix) {
                out.insert(p.id)
            }
        }
        return out
    }

    // MARK: Transport rules

    /// The most bytes a list may be. Comfortably above what any of the four
    /// legitimately return (Mullvad's whole payload was 300 KB and IPVanish's
    /// directory index 2 MB on 2026-08-07) and far below what would hurt.
    ///
    /// A cap rather than a stream because the parsers work on a whole document, and
    /// a cap that only applies after the download is not a cap at all — this one is
    /// checked against `Content-Length` first and enforced again on what arrived.
    static let maximumPayloadBytes = 32 * 1024 * 1024

    /// Is this a URL this provider's list may be read from?
    ///
    /// HTTPS and exactly the host the catalogue names. Nothing here is
    /// case-sensitive about the host (DNS is not) and nothing accepts a port: a
    /// provider that starts publishing on a non-standard port is a deliberate
    /// catalogue change, not something a redirect gets to decide.
    static func isAcceptable(_ url: URL, for provider: VPNServiceProvider) -> Bool {
        guard let expected = provider.listURL?.host()?.lowercased() else { return false }
        guard url.scheme?.lowercased() == "https" else { return false }
        guard let host = url.host()?.lowercased(), host == expected else { return false }
        return url.port == nil || url.port == 443
    }

    /// Why a response was not usable, in the user's words. `nil` means it was.
    static func responseProblem(_ response: URLResponse, provider: VPNServiceProvider)
        -> String? {
        guard let http = response as? HTTPURLResponse else {
            return "\(provider.displayName) answered with something that was not a web response."
        }
        guard (200...299).contains(http.statusCode) else {
            return "\(provider.displayName) answered \(http.statusCode) rather than sending its "
                + "server list. Nothing has been changed \u{2014} the list SimpleVPN already had is "
                + "still the one it is using."
        }
        guard let url = http.url, isAcceptable(url, for: provider) else {
            return "\(provider.displayName)\u{2019}s answer came from somewhere else, so SimpleVPN "
                + "refused it and kept the list it already had."
        }
        if http.expectedContentLength > Int64(maximumPayloadBytes) {
            return "\(provider.displayName) offered more than SimpleVPN will read in one go. "
                + "Nothing has been changed."
        }
        return nil
    }
}

// MARK: - The fetcher

/// One GET, with the rules above around it.
///
/// The session is built here and nowhere else, so the two things that would undo
/// the design — a delegate that answers an authentication challenge, and a redirect
/// followed off-host — cannot be introduced at a call site.
@MainActor
final class ProviderListFetcher {

    static let shared = ProviderListFetcher()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "providers")

    /// What went wrong, already in the user's words. There is no `.underlying(Error)`
    /// case: a `URLError` shown raw is how a person ends up reading "cancelled".
    struct Failure: Error, Equatable {
        let sentence: String
    }

    private let session: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        // Nothing about this Mac is remembered between fetches, and nothing about a
        // previous fetch travels with the next one.
        config.httpCookieStorage = nil
        config.httpCookieAcceptPolicy = .never
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = 30
        // Generous, because Nord's list is ~9 MB and somebody on a slow link is not
        // doing anything wrong. The user's Stop button is the real time limit.
        config.timeoutIntervalForResource = 600
        // NO SESSION-WIDE DELEGATE. Every callback that matters — the redirect
        // refusal and the progress — is per-task, so one fetch can never be handed
        // another's expected host. There is deliberately no
        // `didReceive challenge:` anywhere in this file: without one, URLSession uses
        // the system trust store and certificate verification cannot be turned off,
        // which is a policy this app does not have an option for and must not grow one.
        session = URLSession(configuration: config)
    }

    /// Fetch and parse one provider's list, reporting progress as it goes.
    ///
    /// The caller has already asked `ProviderListFetchPolicy.refusal` — this does the
    /// transport and nothing else, and in particular it NEVER WRITES ANYTHING:
    /// applying an update is a separate, confirmable step (`ProviderServerListDiff`).
    /// That is also what makes cancelling safe. Swift's cooperative cancellation
    /// tears down the byte stream and throws out of here with nothing persisted, so
    /// "stop" cannot leave a half-merged list — the apply rules are all-or-nothing
    /// and this function is the half that never applies.
    ///
    /// `progress` is called on the main actor for every chunk, which is cheap
    /// (a `URLSession` chunk is a network read, not a byte) and keeps the view free
    /// of its own timer.
    func fetch(_ provider: VPNServiceProvider, now: Date = .now,
               progress: @escaping @MainActor (ProviderFetchProgress) -> Void = { _ in })
        async throws(Failure) -> ProviderServerList {
        guard let url = provider.listURL,
              ProviderListFetchPolicy.isAcceptable(url, for: provider) else {
            throw Failure(sentence: "SimpleVPN has no address to ask \(provider.displayName) for.")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        // No User-Agent, no Accept-Language, no identifiers. The default headers
        // URLSession sends are the ones any client sends; nothing is added that
        // would tell a provider more than "somebody asked".
        request.setValue("application/json, text/html;q=0.9", forHTTPHeaderField: "Accept")
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        progress(ProviderFetchProgress(stage: .contacting))

        // DOWNLOAD RATHER THAN `data(for:)`, and this is a progress decision.
        // `data(for:)` returns only once the whole payload is in, so a 9 MB Nord list
        // is a long wait with nothing to show. A download task reports
        // `didWriteData` as it goes — real bytes against the server's own declared
        // total — which is the only honest source for a determinate bar.
        //
        // Not `bytes(for:)`: that is an `AsyncSequence` of individual UInt8s, so
        // reading nine million of them costs far more than the download.
        let observer = FetchObserver(expectedHost: url.host()?.lowercased() ?? "") { received, total in
            Task { @MainActor in
                progress(ProviderFetchProgress(stage: .downloading,
                                               received: received,
                                               expected: total > 0 ? total : nil))
            }
        }
        let fileURL: URL
        let response: URLResponse
        do {
            (fileURL, response) = try await session.download(for: request, delegate: observer)
        } catch is CancellationError {
            throw Failure(sentence: ProviderFetchOutcome.cancelled.sentence(provider: provider))
        } catch let error as URLError where error.code == .cancelled {
            throw Failure(sentence: ProviderFetchOutcome.cancelled.sentence(provider: provider))
        } catch {
            Self.log.error("\(provider.id.rawValue, privacy: .public) fetch failed")
            throw Failure(sentence: "SimpleVPN could not reach \(provider.displayName). "
                + "Nothing has been changed \u{2014} the servers you already had are untouched.")
        }
        // The temporary file is ours to remove and holds nothing secret (a published
        // server list), but leaving one behind per fetch is still litter.
        defer { try? FileManager.default.removeItem(at: fileURL) }

        if let problem = ProviderListFetchPolicy.responseProblem(response, provider: provider) {
            throw Failure(sentence: problem)
        }
        let declared = response.expectedContentLength
        let expected: Int64? = declared > 0 ? declared : nil

        progress(ProviderFetchProgress(stage: .checking, received: declared > 0 ? declared : 0,
                                       expected: expected))
        guard let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe) else {
            throw Failure(sentence: "SimpleVPN could not read what \(provider.displayName) sent. "
                + "Nothing has been changed.")
        }
        // RULE 4. Checked against what actually arrived rather than only against what
        // was declared, because a declared length is a claim.
        guard data.count <= ProviderListFetchPolicy.maximumPayloadBytes else {
            throw Failure(sentence: "\(provider.displayName) sent more than SimpleVPN will read "
                + "in one go. Nothing has been changed.")
        }
        // A Stop pressed while the body was arriving lands here. Said in the
        // feature's own words rather than as a `CancellationError`, and the sentence
        // is the promise: nothing has been changed.
        if Task.isCancelled {
            throw Failure(sentence: ProviderFetchOutcome.cancelled.sentence(provider: provider))
        }
        let list = try parse(data, provider: provider, now: now)
        // Named even though the diff itself happens in the caller: this is the stage
        // where a long pause is about to be explained by a confirmation sheet, and a
        // bar that reaches the end and sits there reads as a hang.
        progress(ProviderFetchProgress(stage: .comparing,
                                       received: Int64(data.count), expected: expected))
        return list
    }

    /// The payload → a validated list. Split out so the parse half is reachable from
    /// a test with a fixture and no network at all.
    func parse(_ data: Data, provider: VPNServiceProvider, now: Date = .now) throws(Failure)
        -> ProviderServerList {
        switch Self.parsed(data, provider: provider, now: now) {
        case .success(let list): return list
        case .failure(let why): throw Failure(sentence: Self.sentence(for: why, provider: provider))
        }
    }

    /// The parser hop, as a `Result` rather than a typed throw.
    ///
    /// One `do` per case so the caught error's type is the parser's own rather than
    /// `any Error` — which is what a single `do` around a `switch` collapses to, and
    /// it takes the two refusal cases with it.
    private static func parsed(_ data: Data, provider: VPNServiceProvider, now: Date)
        -> Result<ProviderServerList, ProviderListParser.Failure> {
        switch provider.id {
        case .mullvad:
            do { return .success(try ProviderListParser.mullvad(data, now: now)) }
            catch { return .failure(error) }
        case .nordVPN:
            do { return .success(try ProviderListParser.nordVPN(data, now: now)) }
            catch { return .failure(error) }
        case .ipVanish:
            // The one provider that publishes a directory rather than an API, so the
            // one that arrives as text. Anything that is not UTF-8 is not their index.
            guard let html = String(data: data, encoding: .utf8) else { return .failure(.malformed) }
            do { return .success(try ProviderListParser.ipVanish(html, now: now)) }
            catch { return .failure(error) }
        case .protonVPN:
            // Unreachable: `blocked` is non-nil, so the policy refuses long before
            // here. Answered rather than crashed, because a `fatalError` on a path
            // the policy already closes is a crash waiting on a future edit.
            return .failure(.malformed)
        }
    }

    /// A parser refusal in the user's words. Both cases say "nothing has been
    /// changed", because that is the promise rule 2 makes and the first thing
    /// somebody wants to know when an update does not land.
    static func sentence(for failure: ProviderListParser.Failure,
                         provider: VPNServiceProvider) -> String {
        switch failure {
        case .empty:
            "\(provider.displayName)\u{2019}s answer had no servers SimpleVPN could read. "
                + "That is how a broken endpoint and a substituted list both look, so nothing "
                + "has been changed."
        case .malformed:
            "SimpleVPN did not recognise the shape of \(provider.displayName)\u{2019}s answer, "
                + "so it kept the list it already had. This usually means they have changed how "
                + "they publish it."
        }
    }
}

// MARK: - The per-task delegate: refusing a redirect, and counting bytes

/// TWO JOBS, one object, because both are per-task facts.
///
/// RULE 3 — `URLSession` follows redirects by default and will happily follow one to
/// another host. A provider's list is fetched from a host named in a signed binary,
/// and a 302 is not permission to change that; otherwise the hard-coded host is
/// decoration. Returning nil makes the redirect itself the RESPONSE, which
/// `responseProblem` then refuses on its status code — so the user is told, rather
/// than the fetch quietly succeeding against somewhere else.
///
/// PROGRESS — `didWriteData` is the only place the real byte count is known. Both
/// numbers are passed straight through; deciding whether they amount to a drawable
/// proportion is `ProviderFetchProgress`'s, not this class's.
///
/// There is deliberately NO authentication-challenge callback. Its absence is what
/// guarantees the system trust store is used and that there is nowhere for
/// certificate verification to be turned off.
private final class FetchObserver: NSObject, URLSessionTaskDelegate,
                                   URLSessionDownloadDelegate, @unchecked Sendable {

    private let expectedHost: String
    private let onProgress: @Sendable (Int64, Int64) -> Void

    init(expectedHost: String, onProgress: @escaping @Sendable (Int64, Int64) -> Void) {
        self.expectedHost = expectedHost
        self.onProgress = onProgress
    }

    /// THE COMPLETION-HANDLER FORM, NOT THE `async` ONE, and not by preference:
    /// Swift 6.3.3 crashes in SILGen (`emitNativeToForeignThunk`) generating the
    /// Objective-C thunk for the `async` overload of this particular method. The two
    /// are equivalent to `URLSession`; only one of them compiles.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard !expectedHost.isEmpty, let url = request.url,
              url.scheme?.lowercased() == "https",
              url.host()?.lowercased() == expectedHost
        else { return completionHandler(nil) }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        onProgress(totalBytesWritten, totalBytesExpectedToWrite)
    }

    /// Required by the protocol; the `async` `download(for:delegate:)` gives us the
    /// file back directly, so there is nothing to do here.
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {}
}
