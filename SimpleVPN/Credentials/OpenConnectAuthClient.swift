// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectAuthClient.swift
//  App side of the `ocauth-helper` conversation (OpenConnectAuthWire.swift):
//  spawns one helper per sign-in attempt, feeds it the start request, and
//  bridges its events — forms are answered from stored credentials
//  (OCAuthFormAutofill), SSO URLs open through the caller's browser choice
//  (BrowserLauncher, the same mechanism Tailscale sign-in uses), and a
//  certificate that failed verification is REFUSED unless a handler explicitly
//  accepts it (cert-verification invariant: never auto-accept).
//
//  Process discipline mirrors OnePasswordNative.runHelper: a kill-watchdog
//  terminates a wedged helper, and Task cancellation kills it immediately (an
//  abandoned browser sign-in must never wedge the connect flow). The returned
//  cookie lives only in memory — never persisted, never logged.
//

import Foundation
import os

nonisolated enum OpenConnectAuthError: LocalizedError, Sendable {
    case helperMissing
    case launchFailed(String)
    case cancelled
    /// The gateway asked for fields nothing stored can answer (labels listed).
    case formUnanswered([String])
    /// The server's certificate failed verification and matched no pin.
    case certUntrusted(fingerprint: String)
    case badReply
    case gateway(kind: String, message: String)

    var errorDescription: String? {
        switch self {
        case .helperMissing:
            "The sign-in helper is missing from the app bundle — reinstall SimpleVPN."
        case .launchFailed(let why):
            "Couldn't start the sign-in helper: \(why)"
        case .cancelled:
            "The sign-in was cancelled."
        case .formUnanswered(let labels):
            "The gateway asked for \(labels.map { "\u{201C}\($0)\u{201D}" }.joined(separator: ", ")) "
            + "and there's no stored answer. Fill in the username (and save the password) "
            + "under Sign-In, or switch this VPN to password sign-in."
        case .certUntrusted(let fingerprint):
            "The server's certificate isn't trusted by macOS and doesn't match a pinned "
            + "certificate. If this gateway is yours, pin \(fingerprint) under "
            + "Security \u{25B8} Server certificate (SHA-256); otherwise do not connect."
        case .badReply:
            "The sign-in helper sent an unreadable reply."
        case .gateway(_, let message):
            message.isEmpty ? "The gateway refused the sign-in." : message
        }
    }
}

/// One conversational helper run. Handlers are how callers plug in the
/// credential machinery and browser launch; the client owns only the process
/// and the wire.
nonisolated enum OpenConnectAuthClient {

    /// What a form handler can do with a gateway form.
    nonisolated enum FormReply: Sendable {
        case answers([String: String])
        /// Give up, with the field labels that had no answer (drives the error).
        case cancel(unanswered: [String])
    }

    nonisolated struct Handlers: Sendable {
        /// Answer a sign-in form. Default policy for the connect flow: stored
        /// credentials answer silently where they match; anything else cancels.
        var answerForm: @Sendable (OCAuthFormSpec) async -> FormReply
        /// Open the SSO sign-in URL (per-VPN browser selection).
        var openURL: @Sendable (String) async -> Void
        /// Decide a certificate that FAILED verification. NEVER return true
        /// without an explicit user decision; the default refuses.
        var decideCert: @Sendable (OCAuthCert) async -> Bool = { _ in false }
        /// Progress lines (openconnect PRG_INFO) for the session log.
        var progress: @Sendable (String) -> Void = { _ in }
    }

    /// The helper shipped with this build (nil = bundle is damaged/stripped).
    static var helperURL: URL? {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/ocauth-helper")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "ocauth")

    /// Run one sign-in conversation to completion. `killAfter` is the outer
    /// watchdog — browser SSO legitimately takes minutes, so it's generous;
    /// cancellation and the handlers' own choices end things sooner.
    static func authenticate(
        start: OCAuthStart, handlers: Handlers,
        helper: URL? = nil, killAfter: TimeInterval = 600
    ) async throws -> OCAuthDone {
        guard let helperURL = helper ?? helperURL else {
            throw OpenConnectAuthError.helperMissing
        }
        let processBox = OSAllocatedUnfairLock<Process?>(initialState: nil)
        return try await withTaskCancellationHandler {
            let process = Process()
            process.executableURL = helperURL
            let inPipe = Pipe(), outPipe = Pipe()
            process.standardInput = inPipe
            process.standardOutput = outPipe
            process.standardError = FileHandle.nullDevice
            processBox.withLock { $0 = process }

            // Helper stdout → one Data per JSON line. The readability handler
            // runs serially on the pipe's own dispatch source.
            let lines = AsyncStream<Data> { continuation in
                nonisolated(unsafe) var buffer = Data()
                outPipe.fileHandleForReading.readabilityHandler = { handle in
                    let chunk = handle.availableData
                    guard !chunk.isEmpty else {
                        handle.readabilityHandler = nil
                        continuation.finish()
                        return
                    }
                    buffer.append(chunk)
                    while let nl = buffer.firstIndex(of: 0x0A) {
                        let line = buffer.subdata(in: buffer.startIndex..<nl)
                        buffer.removeSubrange(buffer.startIndex...nl)
                        if !line.isEmpty { continuation.yield(line) }
                    }
                }
            }

            do {
                try process.run()
            } catch {
                processBox.withLock { $0 = nil }
                throw OpenConnectAuthError.launchFailed(error.localizedDescription)
            }
            defer {
                processBox.withLock { $0 = nil }
                try? inPipe.fileHandleForWriting.close()
                if process.isRunning { process.terminate() }
            }
            // Watchdog: a helper wedged past any reasonable sign-in gets killed.
            DispatchQueue.global().asyncAfter(deadline: .now() + killAfter) {
                processBox.withLock { if $0 === process, process.isRunning { process.terminate() } }
            }

            func send(_ message: OCAuthClientMessage) throws {
                let data = try OCAuthJSON.encodeLine(message)
                inPipe.fileHandleForWriting.write(data)
            }
            try send(.start(start))

            var refusedCert: OCAuthCert?
            for await line in lines {
                guard let event = try? OCAuthJSON.decode(OCAuthEvent.self, from: line) else {
                    throw OpenConnectAuthError.badReply
                }
                switch event {
                case .progress(_, let message):
                    handlers.progress(message)
                case .openURL(let url):
                    log.log("SSO sign-in URL raised — opening the browser")
                    await handlers.openURL(url)
                case .form(let form):
                    switch await handlers.answerForm(form) {
                    case .answers(let answers):
                        try send(.answers(answers))
                    case .cancel(let unanswered):
                        try? send(.cancel)
                        throw unanswered.isEmpty
                            ? OpenConnectAuthError.cancelled
                            : OpenConnectAuthError.formUnanswered(unanswered)
                    }
                case .cert(let cert):
                    let accepted = await handlers.decideCert(cert)
                    if !accepted { refusedCert = cert }
                    try send(.accept(accepted))
                case .done(let done):
                    return done
                case .error(let kind, let message):
                    if let refusedCert {
                        throw OpenConnectAuthError.certUntrusted(fingerprint: refusedCert.fingerprint)
                    }
                    if kind == OCAuthErrorKind.cancelled { throw OpenConnectAuthError.cancelled }
                    throw OpenConnectAuthError.gateway(kind: kind, message: message)
                }
            }
            // EOF without done/error: killed (watchdog/cancel) or crashed.
            if Task.isCancelled { throw OpenConnectAuthError.cancelled }
            if let refusedCert {
                throw OpenConnectAuthError.certUntrusted(fingerprint: refusedCert.fingerprint)
            }
            throw OpenConnectAuthError.badReply
        } onCancel: {
            processBox.withLock { $0?.terminate() }
        }
    }
}
