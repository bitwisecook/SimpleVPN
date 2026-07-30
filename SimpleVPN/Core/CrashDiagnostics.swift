// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CrashDiagnostics.swift
//  Capture crashes with enough detail to act on, and offer to report them next launch.
//
//  Two sources, because they cover different failures:
//
//   1. An uncaught NSException handler. AppKit turns an exception raised during the
//      display cycle into +[NSApplication _crashOnException:], and the resulting .ips
//      carries the backtrace but an EMPTY `asi` — so the exception name and reason, the
//      one thing that identifies the bug, is lost. We write those ourselves.
//
//   2. macOS's own .ips crash reports in ~/Library/Logs/DiagnosticReports. These cover
//      what a handler can't (SIGSEGV, SIGKILL from a watchdog, C++ aborts in the vendored
//      engines). The app isn't sandboxed, so it can read its own reports.
//
//  On the next launch, whatever turned up is offered to the user as a pre-filled GitHub
//  issue. Nothing is ever sent without them choosing to: the report is scrubbed (crash
//  reports contain the home-directory path, hence the username), shown for review, and
//  only then opened in a browser.
//

import AppKit
import Foundation
import ObjectiveC
import OSLog

/// One crash worth reporting, assembled from either source.
nonisolated struct CrashReport: Codable, Identifiable, Sendable {
    var id: String { signature }
    /// Stable-ish identity so the same crash isn't offered twice.
    var signature: String
    var when: Date
    var appVersion: String
    /// "NSInternalInconsistencyException" or "EXC_BAD_ACCESS (SIGSEGV)".
    var kind: String
    /// The reason string, when there is one — this is the bit macOS drops.
    var reason: String?
    /// Symbolised frames, already trimmed to a useful depth.
    var frames: [String]

    /// Short, GitHub-friendly summary. Deliberately compact: the full text goes on the
    /// clipboard because a URL can't carry a whole backtrace.
    var summary: String {
        var out = "**\(kind)**"
        if let reason, !reason.isEmpty { out += "\n\n> \(reason)" }
        let top = frames.prefix(12)
        if !top.isEmpty {
            out += "\n\n```\n" + top.joined(separator: "\n") + "\n```"
        }
        return out
    }

    var markdown: String {
        """
        ### Crash
        - When: \(ISO8601DateFormatter().string(from: when))
        - App version: \(appVersion)
        - Type: \(kind)
        - Reason: \(reason ?? "(none recorded)")

        ```
        \(frames.joined(separator: "\n"))
        ```
        """
    }
}

nonisolated enum CrashDiagnostics {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "crash")

    /// Where our own exception records live (Application Support, not the App Group:
    /// this is app-side only and shouldn't be visible to the extension).
    private static var recordsDirectory: URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                                  in: .userDomainMask).first else { return nil }
        let dir = base.appendingPathComponent("SimpleVPN/Crashes", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Reports already offered to the user, so we don't nag about the same crash within
    /// one build. Scoped BY APP VERSION on purpose: the same crash reappearing in a newer
    /// build means the fix didn't work, which is exactly when it must be offered again.
    /// Without this, three occurrences of one crash produced exactly one prompt.
    private static let seenKey = "crash.reportedSignatures.v2"

    private static func seenKey(for report: CrashReport) -> String {
        "\(report.appVersion)|\(report.signature)"
    }

    // MARK: Install

    /// Call once, as early as possible in app startup.
    @MainActor
    static func install() {
        // MUST come first, and NSSetUncaughtExceptionHandler is NOT enough.
        //
        // Proven the hard way: an exception raised during AppKit's display cycle goes to
        // +[NSApplication _crashOnException:], which terminates the process itself. The
        // uncaught handler below never runs — two real crashes produced an .ips with an
        // empty `asi` AND no log line from us at all. -[NSApplication reportException:]
        // is the hook AppKit *does* call on that path, so that's where we listen.
        // Throw-time interception. This is the ONLY one of the three that catches an
        // exception raised inside AppKit's display cycle — see ExceptionPreprocessor.m
        // for why the other two don't. Log-only: it also sees exceptions frameworks throw
        // and catch normally, so it must not manufacture crash reports.
        SVPNInstallExceptionPreprocessor { exception in
            let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "crash")
            log.error("""
                THROWN \(exception.name.rawValue, privacy: .public): \
                \(exception.reason ?? "(no reason)", privacy: .public)
                """)
            log.error("\(exception.callStackSymbols.prefix(30).joined(separator: "\n"), privacy: .public)")
            // Which window, and which AppKit-hosted views are in it? The layout-loop
            // exception names neither, and that's the whole question.
            if exception.name.rawValue == "NSGenericException",
               exception.reason?.contains("Update Constraints") == true {
                log.error("layout loop context: \(CrashDiagnostics.windowContext(), privacy: .public)")
            }
        }

        NSApplication.installExceptionReporter()

        // Still worth having for exceptions raised off the AppKit event path. The handler
        // is a C function pointer, so it must capture nothing — hence the static call.
        NSSetUncaughtExceptionHandler { exception in
            CrashDiagnostics.record(exception, source: "UNCAUGHT EXCEPTION")
        }
    }

    /// Describe the key window and the AppKit views hosted inside it. Runs only on the
    /// layout-loop exception, so the cost never lands on normal operation.
    nonisolated static func windowContext() -> String {
        MainActor.assumeIsolated {
            guard let window = NSApp?.keyWindow ?? NSApp?.mainWindow else { return "no key window" }
            var hosted: [String] = []
            func walk(_ view: NSView, depth: Int) {
                let name = String(describing: type(of: view))
                // Our own representables and SwiftUI's hosts for them.
                if name.contains("Catcher") || name.contains("NSTextView")
                    || name.contains("PlatformViewHost") || name.contains("ScrollView") {
                    hosted.append("\(name)@\(depth)")
                }
                for sub in view.subviews { walk(sub, depth: depth + 1) }
            }
            if let content = window.contentView { walk(content, depth: 0) }
            return "window=\(window.title.isEmpty ? String(describing: type(of: window)) : window.title) "
                 + "hosted=[\(hosted.prefix(20).joined(separator: ", "))]"
        }
    }

    /// Record an exception from whichever hook caught it. Logs at error level (persisted)
    /// and writes a report file for the next launch to offer.
    static func record(_ exception: NSException, source: String) {
        let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "crash")
        let name = exception.name.rawValue
        let reason = exception.reason ?? "(no reason given)"
        let frames = exception.callStackSymbols
        log.error("\(source, privacy: .public) \(name, privacy: .public): \(reason, privacy: .public)")
        log.error("\(frames.prefix(40).joined(separator: "\n"), privacy: .public)")
        writeExceptionRecord(name: name, reason: reason, frames: frames)
    }

    /// Best-effort synchronous write — we are on the way down, so no queues, no async.
    private static func writeExceptionRecord(name: String, reason: String, frames: [String]) {
        guard let dir = recordsDirectory else { return }
        let version = (Bundle.main.infoDictionary?["CFBundleVersion"] as? String) ?? "?"
        let report = CrashReport(
            signature: signature(kind: name, reason: reason, frames: frames),
            when: Date(), appVersion: version, kind: name, reason: reason,
            frames: Array(frames.prefix(60)))
        guard let data = try? JSONEncoder().encode(report) else { return }
        try? data.write(to: dir.appendingPathComponent("\(UUID().uuidString).json"))
    }

    /// Same crash in the same place ⇒ same signature, so a repeat isn't offered twice.
    private static func signature(kind: String, reason: String, frames: [String]) -> String {
        // Frame addresses differ run to run; the symbol names don't. Strip everything
        // but the symbol column so the signature is stable.
        let symbols = frames.prefix(6).map { line -> String in
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            return parts.count > 3 ? parts[3...].prefix(3).joined(separator: " ") : line
        }
        return "\(kind)|\(reason.prefix(80))|\(symbols.joined(separator: ">"))"
    }

    // MARK: Collect

    /// Crashes since we last looked, newest first, excluding ones already offered.
    static func pendingReports() -> [CrashReport] {
        var found = ownExceptionRecords() + systemCrashReports()
        let seen = Set(UserDefaults.standard.stringArray(forKey: seenKey) ?? [])
        found = found.filter { !seen.contains(seenKey(for: $0)) }
        return found.sorted { $0.when > $1.when }
    }

    /// Stop offering these (called once the user has reported or dismissed them).
    static func markHandled(_ reports: [CrashReport]) {
        var seen = UserDefaults.standard.stringArray(forKey: seenKey) ?? []
        seen.append(contentsOf: reports.map { seenKey(for: $0) })
        // Bounded: this list only exists to avoid nagging.
        UserDefaults.standard.set(Array(seen.suffix(50)), forKey: seenKey)
        // Our own records have served their purpose; macOS's .ips files are not ours
        // to delete.
        if let dir = recordsDirectory,
           let files = try? FileManager.default.contentsOfDirectory(at: dir,
                                                                   includingPropertiesForKeys: nil) {
            for f in files where f.pathExtension == "json" { try? FileManager.default.removeItem(at: f) }
        }
    }

    private static func ownExceptionRecords() -> [CrashReport] {
        guard let dir = recordsDirectory,
              let files = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: nil) else { return [] }
        return files.filter { $0.pathExtension == "json" }.compactMap { url in
            guard let data = try? Data(contentsOf: url) else { return nil }
            return try? JSONDecoder().decode(CrashReport.self, from: data)
        }
    }

    /// Parse macOS's own reports. Only ours, only recent — an old crash from three
    /// months ago isn't worth interrupting anyone about.
    private static func systemCrashReports(within days: Int = 7) -> [CrashReport] {
        let fm = FileManager.default
        guard let logs = fm.urls(for: .libraryDirectory, in: .userDomainMask).first else { return [] }
        let dir = logs.appendingPathComponent("Logs/DiagnosticReports", isDirectory: true)
        guard let files = try? fm.contentsOfDirectory(at: dir,
                                                     includingPropertiesForKeys: [.contentModificationDateKey])
        else { return [] }
        let cutoff = Date().addingTimeInterval(-Double(days) * 86_400)
        return files.compactMap { url -> CrashReport? in
            guard url.lastPathComponent.hasPrefix("SimpleVPN"),
                  ["ips", "crash"].contains(url.pathExtension),
                  let mod = try? url.resourceValues(forKeys: [.contentModificationDateKey])
                      .contentModificationDate, mod > cutoff,
                  let text = try? String(contentsOf: url, encoding: .utf8)
            else { return nil }
            return parseIPS(text, when: mod)
        }
    }

    /// An .ips is a one-line JSON header followed by the payload JSON.
    private static func parseIPS(_ text: String, when: Date) -> CrashReport? {
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payload = try? JSONSerialization.jsonObject(with: Data(parts[1].utf8)) as? [String: Any]
        else { return nil }

        let version = ((payload["bundleInfo"] as? [String: Any])?["CFBundleVersion"] as? String) ?? "?"
        let exception = payload["exception"] as? [String: Any]
        let type = (exception?["type"] as? String) ?? "crash"
        let signal = (exception?["signal"] as? String)
        let kind = signal.map { "\(type) (\($0))" } ?? type

        // Frames: prefer the ObjC exception backtrace when present (it names the throw
        // site), else the crashed thread.
        var frames: [String] = []
        if let asi = payload["asiBacktraces"] as? [String], let first = asi.first {
            frames = first.split(separator: "\n").map(String.init)
        } else if let threads = payload["threads"] as? [[String: Any]],
                  let crashed = threads.first(where: { $0["triggered"] as? Bool == true }),
                  let raw = crashed["frames"] as? [[String: Any]] {
            frames = raw.map { f in
                let symbol = (f["symbol"] as? String) ?? "???"
                let offset = (f["symbolLocation"] as? Int).map { " + \($0)" } ?? ""
                return "\(symbol)\(offset)"
            }
        }
        guard !frames.isEmpty else { return nil }

        // macOS drops the exception reason into `asi`, which is usually empty for the
        // AppKit display-cycle case — that's exactly why our own handler exists.
        let reason = (payload["asi"] as? [String: Any])?
            .values.compactMap { ($0 as? [String])?.joined(separator: " ") }.first

        return CrashReport(
            signature: signature(kind: kind, reason: reason ?? "", frames: frames),
            when: when, appVersion: version, kind: kind, reason: reason,
            frames: Array(frames.prefix(60)))
    }
}


// MARK: - The hook AppKit actually calls

extension NSApplication {
    /// Swap in a `reportException:` that records the exception before AppKit crashes on
    /// it. Exchanging implementations (rather than replacing) means the call below reaches
    /// the ORIGINAL, so AppKit's own behaviour is untouched — we only get to see it first.
    /// Exchanging twice would swap the original back in, so this must happen once only.
    private static nonisolated(unsafe) var reporterInstalled = false

    static func installExceptionReporter() {
        guard !reporterInstalled else { return }
        reporterInstalled = true
        guard let original = class_getInstanceMethod(
                NSApplication.self, #selector(NSApplication.reportException(_:))),
              let replacement = class_getInstanceMethod(
                NSApplication.self, #selector(NSApplication.simplevpn_reportException(_:)))
        else { return }
        method_exchangeImplementations(original, replacement)
    }

    @objc dynamic func simplevpn_reportException(_ exception: NSException) {
        CrashDiagnostics.record(exception, source: "APPKIT EXCEPTION")
        // Implementations are exchanged, so this selector now reaches the original.
        simplevpn_reportException(exception)
    }
}
