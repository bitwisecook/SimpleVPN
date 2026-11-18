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
import Darwin

nonisolated enum OpenConnectAuthError: LocalizedError, Sendable {
    case helperMissing
    case launchFailed(String)
    case cancelled
    /// The gateway asked for fields nothing stored can answer (labels listed).
    case formUnanswered([String])
    /// The server's certificate failed verification and matched no pin.
    case certUntrusted(fingerprint: String)
    case badReply
    case invalidSignInURL
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
        case .invalidSignInURL:
            "The gateway supplied an invalid sign-in link. Ask your VPN administrator for an HTTP or HTTPS sign-in address."
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
        let channel: OCAuthChannel
        do { channel = try OCAuthChannel() }
        catch { throw OpenConnectAuthError.launchFailed(error.localizedDescription) }
        return try await withTaskCancellationHandler {
            if Task.isCancelled { throw OpenConnectAuthError.cancelled }
            let process = Process()
            process.executableURL = helperURL
            process.standardInput = channel.child
            process.standardOutput = channel.child
            process.standardError = FileHandle.nullDevice
            do { try process.run() }
            catch { throw OpenConnectAuthError.launchFailed(error.localizedDescription) }
            try? channel.child.close()
            channel.process.withLock { $0 = process }

            let timer = DispatchSource.makeTimerSource(queue: .global())
            timer.setEventHandler { channel.stop() }
            timer.schedule(deadline: .now() + killAfter)
            timer.resume()
            defer {
                timer.cancel()
                channel.stop()
            }
            if Task.isCancelled { throw OpenConnectAuthError.cancelled }

            func send(_ message: OCAuthClientMessage) async throws {
                do { try await channel.send(OCAuthJSON.encodeLine(message)) }
                catch {
                    if Task.isCancelled { throw OpenConnectAuthError.cancelled }
                    throw OpenConnectAuthError.badReply
                }
            }
            try await send(.start(start))

            while let line = try? await channel.nextLine() {
                if Task.isCancelled { throw OpenConnectAuthError.cancelled }
                guard let event = try? OCAuthJSON.decode(OCAuthEvent.self, from: line) else {
                    throw OpenConnectAuthError.badReply
                }
                switch event {
                case .progress(_, let message):
                    handlers.progress(message)
                case .openURL(let url):
                    guard let target = URL(string: url), SSOAuthModel.accepts(target) else {
                        throw OpenConnectAuthError.invalidSignInURL
                    }
                    log.log("SSO sign-in URL raised — opening the browser")
                    await handlers.openURL(url)
                case .form(let form):
                    switch await handlers.answerForm(form) {
                    case .answers(let answers):
                        try await send(.answers(answers))
                    case .cancel(let unanswered):
                        try? await send(.cancel)
                        throw unanswered.isEmpty
                            ? OpenConnectAuthError.cancelled
                            : OpenConnectAuthError.formUnanswered(unanswered)
                    }
                case .cert(let cert):
                    guard await handlers.decideCert(cert) else {
                        try? await send(.accept(false))
                        throw OpenConnectAuthError.certUntrusted(fingerprint: cert.fingerprint)
                    }
                    try await send(.accept(true))
                case .done(let done):
                    return done
                case .error(let kind, let message):
                    if kind == OCAuthErrorKind.cancelled { throw OpenConnectAuthError.cancelled }
                    throw OpenConnectAuthError.gateway(kind: kind, message: message)
                }
            }
            // EOF without done/error: killed (watchdog/cancel) or crashed.
            if Task.isCancelled { throw OpenConnectAuthError.cancelled }
            throw OpenConnectAuthError.badReply
        } onCancel: {
            channel.stop()
        }
    }
}


/// A private full-duplex socket lets cancellation interrupt either a blocked read
/// or a write to a helper that has stopped reading. Pulling one frame at a time
/// leaves backpressure with the kernel while a browser or form handler awaits.
private nonisolated final class OCAuthChannel: Sendable {
    let child: FileHandle
    let process = OSAllocatedUnfairLock<Process?>(initialState: nil)
    private let parent: FileHandle
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.ocauth-io", qos: .userInitiated)
    private let reader = OSAllocatedUnfairLock(initialState: OCAuthLineReader())

    init() throws {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw POSIXError(.EIO) }
        parent = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        child = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        var enabled: Int32 = 1
        guard fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else {
            throw POSIXError(.EIO)
        }
    }

    func send(_ message: Data) async throws {
        try await withCheckedThrowingContinuation { cont in
            queue.async { cont.resume(with: Result { try self.parent.write(contentsOf: message) }) }
        }
    }

    func nextLine() async throws -> Data? {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                cont.resume(with: Result { try self.reader.withLock { try $0.next(from: self.parent) } })
            }
        }
    }

    func stop() {
        _ = shutdown(parent.fileDescriptor, SHUT_RDWR)
        process.withLock { running in
            if let running, running.isRunning { kill(running.processIdentifier, SIGKILL) }
            running = nil
        }
    }
}
