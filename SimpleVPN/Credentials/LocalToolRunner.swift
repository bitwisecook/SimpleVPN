// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LocalToolRunner.swift
//  Running a vendor's own command-line tool, safely, for the CLI-backed sign-in
//  sources (Keeper Commander today; Bitwarden's `bw`, LastPass's `lpass` and
//  Dashlane's `dcli` are the same shape if they are ever added).
//
//  The rules here are security rules, not conveniences:
//
//   • THE SECRET COMES BACK ON STDOUT AND NOWHERE ELSE. `stdout` is returned to
//     the caller and never logged, never put in an error message, never
//     interpolated into a diagnostic. `stderr` is captured SEPARATELY and is the
//     only thing an error may quote — and even that is truncated and scrubbed.
//   • NOTHING SECRET GOES IN ARGV. Arguments are visible to every process on the
//     Mac (`ps`). Record names/UIDs ride argv; secrets never do, in either
//     direction.
//   • STDIN IS /dev/null BY DEFAULT. A vendor CLI that decides to prompt for a
//     master password must hit EOF and fail fast, not wedge a connect behind an
//     invisible prompt. A caller that genuinely HAS the answer may opt in with
//     `stdin:` — and stdin is then the ONLY channel a secret may travel on,
//     because argv is world-readable through `ps`. `keepassxc-cli` is the case
//     that needed it: a `.kdbx` database password has to reach the tool somehow,
//     and there is exactly one safe way. The default is unchanged, so nothing
//     that does not ask for the pipe gets one.
//   • A DEADLINE, ALWAYS, and cancellation kills the child. An unanswered vendor
//     prompt must never outlive the connect that asked for it.
//   • WE NEVER WRITE A VENDOR'S CONFIG. Keeper's own docs warn that reusing a
//     Commander config on a second device revokes both sessions; the same class
//     of footgun exists elsewhere. We read; setup stays the user's to perform,
//     and we print the commands.
//
//  Blocking work runs on a dedicated serial queue — never the cooperative pool.
//

import Foundation
import os
import Darwin

/// The outcome of one tool run. `stdout` is secret-bearing; `stderr` is not
/// (and is pre-scrubbed for anything that looks like a secret anyway).
nonisolated struct LocalToolResult: Sendable {
    var exitCode: Int32
    /// Secret-bearing. Do not log, quote or interpolate.
    var stdout: Data
    /// Safe(ish) diagnostics: truncated, and stripped of anything long enough
    /// and dense enough to be a password.
    var stderr: String
    var timedOut: Bool

    var succeeded: Bool { exitCode == 0 && !timedOut }
    /// stdout as text, trimmed. Still secret-bearing.
    var text: String {
        String(decoding: stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

nonisolated enum LocalToolError: LocalizedError, Equatable {
    case notFound(tool: String)
    case timedOut(tool: String)
    /// The tool ran and failed. `detail` is already scrubbed and truncated.
    case failed(tool: String, detail: String)

    var errorDescription: String? {
        switch self {
        case .notFound(let tool):
            "\u{201C}\(tool)\u{201D} isn\u{2019}t installed on this Mac."
        case .timedOut(let tool):
            "\(tool) didn\u{2019}t answer in time."
        case .failed(let tool, let detail):
            detail.isEmpty ? "\(tool) couldn\u{2019}t provide the sign-in."
                           : "\(tool) couldn\u{2019}t provide the sign-in: \(detail)"
        }
    }
}

nonisolated enum LocalToolRunner {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "local-tool")

    /// Blocking runs, serialised: a vendor CLI that decides to show a Touch ID
    /// or approval prompt shows one at a time, and none of that waiting belongs
    /// on the Swift concurrency pool.
    private static let queue = DispatchQueue(
        label: "com.bragi0.SimpleVPN.local-tool", qos: .userInitiated)

    // MARK: Where a tool may live — an allow-list, never $PATH

    /// `PATH` IS NOT CONSULTED, deliberately and permanently. `PATH` is
    /// attacker-influenceable: anything that can prepend a directory to it (a
    /// shell profile, a login item, a compromised dotfile repo) would otherwise
    /// choose which binary this app executes with the user's privileges, and that
    /// binary is about to be handed a request for a password. So resolution runs
    /// against a fixed list of documented install locations instead, and the user
    /// can override with an ABSOLUTE path they set themselves (see
    /// `userConfiguredPath`).
    ///
    /// The list is where the vendors' own documented installs put things:
    /// Homebrew (Apple silicon then Intel prefix), the system directories, and
    /// MacPorts. Per-user locations are included as a SEPARATE, later group
    /// because the documented install for a Python tool like Keeper Commander is
    /// `pipx`/`pip --user`, which lands in the user's own bin directory — a
    /// tighter list would simply fail to find a correctly installed tool.
    static let systemDirectories = [
        "/opt/homebrew/bin",   // Homebrew, Apple silicon
        "/usr/local/bin",      // Homebrew, Intel; most vendor .pkg installers
        "/opt/local/bin",      // MacPorts
        "/usr/bin",
        "/bin",
    ]

    static func userDirectories(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [String] {
        var dirs = [home.appendingPathComponent(".local/bin").path]   // pipx, pip --user
        // The framework-Python user bin directories, newest first. Enumerated
        // rather than globbed so the list stays an allow-list.
        for minor in (9...20).reversed() {
            dirs.append(home.appendingPathComponent("Library/Python/3.\(minor)/bin").path)
        }
        return dirs
    }

    /// Every directory a tool may be executed from, in resolution order.
    static func searchDirectories(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String] {
        var seen = Set<String>()
        return (systemDirectories + userDirectories(home: home)).filter { seen.insert($0).inserted }
    }

    /// An absolute path the user set for a tool, which always wins: someone who
    /// has installed Commander somewhere unusual must be able to say so, and a
    /// path they typed is a path they chose. Read-only key, no UI yet —
    /// `defaults write com.bragi0.SimpleVPN signin.tool.keeper.path /path/to/keeper`.
    static func userConfiguredPath(for tool: String,
                                   store: UserDefaults = .standard) -> String? {
        guard let raw = store.string(forKey: "signin.tool.\(tool).path")?
            .trimmingCharacters(in: .whitespaces), raw.hasPrefix("/") else { return nil }
        return isSafeExecutable(atPath: raw) ? raw : nil
    }

    /// Where a tool lives, or nil. Pure file checks — no spawning, so it is cheap
    /// enough for a chooser that refreshes while it is on screen.
    static func locate(
        _ tool: String,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        store: UserDefaults = .standard
    ) -> String? {
        // Reject a "tool name" that is really a path: callers name tools, and a
        // separator here would escape the allow-list entirely.
        guard !tool.isEmpty, !tool.contains("/"), tool != ".", tool != ".." else { return nil }
        if let explicit = userConfiguredPath(for: tool, store: store) { return explicit }
        for dir in searchDirectories(home: home) {
            let candidate = (dir as NSString).appendingPathComponent(tool)
            if isSafeExecutable(atPath: candidate) { return candidate }
        }
        return nil
    }

    /// A regular, executable file whose directory isn't writable by the world or
    /// by an unrelated group. The directory check is the one that matters: a
    /// group- or world-writable directory on the list means anyone could drop a
    /// binary in it and have this app run it.
    static func isSafeExecutable(atPath path: String) -> Bool {
        let fm = FileManager.default
        var st = stat()
        guard stat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
              fm.isExecutableFile(atPath: path) else { return false }
        var dir = stat()
        let parent = (path as NSString).deletingLastPathComponent
        guard stat(parent, &dir) == 0 else { return false }
        // World-writable is always wrong. Group-writable is allowed only for the
        // admin group (80), which is how Homebrew's own prefix ships.
        if (dir.st_mode & S_IWOTH) != 0 { return false }
        if (dir.st_mode & S_IWGRP) != 0 && dir.st_gid != 80 && dir.st_gid != 0 { return false }
        return true
    }

    /// The environment a vendor tool is run with: the bare minimum, built from
    /// scratch. NOTHING is inherited — no `DYLD_*`, no `PYTHONPATH`, no
    /// `PATH` the child might use to find its own helpers, no proxy variables
    /// that could redirect a vendor's traffic. `HOME` is passed because a vendor
    /// tool legitimately keeps its session there (Commander's `~/.keeper`), and
    /// without it the tool would look at the wrong account.
    static func childEnvironment(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String: String] {
        [
            "HOME": home.path,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            // Python tools write nothing useful to stdout when unbuffered output
            // is off and a wedged pipe is worse than a slow one.
            "PYTHONUNBUFFERED": "1",
        ]
    }

    /// Run `executable` with `arguments`. Never pass a secret in `arguments`.
    ///
    /// `deadline` is a hard kill: the child is terminated, then SIGKILLed if it
    /// ignores that. Cancelling the surrounding task terminates it too.
    /// `executable` must be an absolute path that came from `locate` — this
    /// refuses anything else rather than letting a relative name be resolved by
    /// the child's own search rules.
    ///
    /// `stdin` is the ONE sanctioned way to hand a tool a secret: nil (the
    /// default) keeps the historical `/dev/null`, and anything supplied is written
    /// to the child's standard input and then the pipe is CLOSED, so a tool that
    /// wants a second line hits EOF rather than waiting for ever. The bytes are
    /// never logged, never echoed and never in argv. See the file header.
    static func run(executable: String, arguments: [String],
                    deadline: TimeInterval = 12,
                    environment: [String: String]? = nil,
                    stdin: Data? = nil) async -> LocalToolResult {
        guard executable.hasPrefix("/"), isSafeExecutable(atPath: executable) else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not an approved tool location", timedOut: false)
        }
        let environment = environment ?? childEnvironment()
        let cancelled = OSAllocatedUnfairLock<Bool>(initialState: false)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (cont: CheckedContinuation<LocalToolResult, Never>) in
                queue.async {
                    guard !cancelled.withLock({ $0 }) else {
                        cont.resume(returning: LocalToolResult(exitCode: -1, stdout: Data(), stderr: "cancelled", timedOut: false))
                        return
                    }
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: executable)
                    process.arguments = arguments
                    let input = stdin == nil ? nil : Pipe()
                    let output = Pipe(), errors = Pipe()
                    process.standardInput = input ?? FileHandle.nullDevice
                    process.standardOutput = output
                    process.standardError = errors
                    process.environment = environment
                    do { try process.run() }
                    catch {
                        cont.resume(returning: LocalToolResult(exitCode: -1, stdout: Data(), stderr: "couldn’t start", timedOut: false))
                        return
                    }
                    try? output.fileHandleForWriting.close()
                    try? errors.fileHandleForWriting.close()
                    try? input?.fileHandleForReading.close()
                    let outFD = output.fileHandleForReading.fileDescriptor
                    let errFD = errors.fileHandleForReading.fileDescriptor
                    let inFD = input?.fileHandleForWriting.fileDescriptor
                    for fd in [outFD, errFD] + (inFD.map { [$0] } ?? []) {
                        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                    }
                    // Pipes can reject input after a child exits. Suppress SIGPIPE
                    // on this descriptor only, without changing the app's signals.
                    let canWriteInput = inFD.map { fcntl($0, F_SETNOSIGPIPE, 1) == 0 } ?? true
                    let started = ProcessInfo.processInfo.systemUptime
                    let limit = started + max(0.01, min(deadline, 300))
                    var terminatedAt: TimeInterval?
                    var out = Data(), err = Data(), buffer = [UInt8](repeating: 0, count: 16384)
                    var outEOF = false, errEOF = false, inputOffset = 0
                    var inputClosed = inFD == nil
                    var timedOut = false, exceeded = !canWriteInput
                    func drain(_ fd: Int32, into data: inout Data, maximum: Int, eof: inout Bool) {
                        guard !eof else { return }
                        // A flood on one pipe must not starve the other or its deadline.
                        for _ in 0..<16 {
                            let count = Darwin.read(fd, &buffer, buffer.count)
                            if count > 0 {
                                let room = maximum - data.count
                                data.append(contentsOf: buffer.prefix(min(count, max(0, room))))
                                if count > room { exceeded = true }
                            } else if count == 0 { eof = true; return }
                            else if errno != EINTR { if errno != EAGAIN && errno != EWOULDBLOCK { eof = true }; return }
                        }
                    }
                    while true {
                        drain(outFD, into: &out, maximum: 4 * 1024 * 1024, eof: &outEOF)
                        drain(errFD, into: &err, maximum: 64 * 1024, eof: &errEOF)
                        let now = ProcessInfo.processInfo.systemUptime
                        let isCancelled = cancelled.withLock { $0 }
                        if now >= limit { timedOut = true }
                        if (timedOut || isCancelled || exceeded), terminatedAt == nil {
                            terminatedAt = now
                            if process.isRunning { process.terminate() }
                        }
                        if let terminatedAt, now - terminatedAt >= 2 {
                            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                            break // descendants holding a pipe cannot keep this task alive
                        }
                        if !inputClosed, let input, let inFD {
                            if terminatedAt != nil || inputOffset == stdin!.count {
                                try? input.fileHandleForWriting.close(); inputClosed = true
                            } else {
                                let count = stdin!.withUnsafeBytes { bytes in
                                    Darwin.write(inFD, bytes.baseAddress!.advanced(by: inputOffset), min(16384, bytes.count - inputOffset))
                                }
                                if count > 0 { inputOffset += count }
                                else if count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
                                    try? input.fileHandleForWriting.close(); inputClosed = true
                                }
                            }
                        }
                        if !process.isRunning && outEOF && errEOF { break }
                        Thread.sleep(forTimeInterval: 0.005)
                    }
                    try? output.fileHandleForReading.close()
                    try? errors.fileHandleForReading.close()
                    if !inputClosed { try? input?.fileHandleForWriting.close() }
                    let wasCancelled = cancelled.withLock { $0 }
                    let exit = process.isRunning ? -1 : process.terminationStatus
                    cont.resume(returning: LocalToolResult(
                        exitCode: exceeded || wasCancelled ? -1 : exit,
                        stdout: exceeded || wasCancelled ? Data() : out,
                        stderr: exceeded ? "tool output exceeded its limit" : wasCancelled ? "cancelled" : scrub(String(decoding: err, as: UTF8.self)),
                        timedOut: timedOut))
                }
            }
        } onCancel: { cancelled.withLock { $0 = true } }
    }

    /// What a failure may say out loud: the first line of stderr, shortened, with
    /// anything that looks like a secret removed. A vendor CLI that helpfully
    /// echoes a password into its own error output must not have it end up in a
    /// diagnostic bundle.
    static func scrub(_ stderr: String, limit: Int = 200) -> String {
        let firstLine = stderr.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        let redacted = firstLine.split(separator: " ").map { word -> String in
            // Long, mixed-character, punctuation-bearing runs are what passwords
            // and tokens look like; plain words and paths are not.
            let dense = word.count >= 12
                && word.contains(where: \.isNumber)
                && word.contains(where: \.isLetter)
                && !word.contains("/")
            return dense ? "\u{2022}\u{2022}\u{2022}" : String(word)
        }.joined(separator: " ")
        return redacted.count > limit
            ? String(redacted.prefix(limit)) + "\u{2026}" : redacted
    }
}
