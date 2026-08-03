// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CrashDiagnosticsTests.swift
//  Proves the AppKit exception hook actually records.
//
//  This exists because the first attempt did NOT work: NSSetUncaughtExceptionHandler
//  never fires for an exception raised in AppKit's display cycle, and two real crashes
//  went unrecorded while the code looked correct. A mechanism whose whole job is to work
//  during a crash cannot be verified by reading it, so it gets a test.
//

import AppKit
import Testing
@testable import SimpleVPN

@MainActor
struct CrashDiagnosticsTests {

    @Test func appKitReportedExceptionsAreRecorded() throws {
        CrashDiagnostics.install()

        // A unique reason so this run's record can't be confused with a real crash's,
        // and can't be filtered out as already-seen.
        let marker = "test-marker-\(UUID().uuidString)"
        let exception = NSException(name: .internalInconsistencyException,
                                    reason: marker, userInfo: nil)

        // This is the exact call AppKit makes on the path that was losing crashes.
        NSApp.reportException(exception)

        let found = CrashDiagnostics.pendingReports().contains { $0.reason == marker }
        #expect(found, "reportException: must produce a crash record")

        // Leave no residue: a stray record would prompt the user to report a test.
        let ours = CrashDiagnostics.pendingReports().filter { $0.reason == marker }
        CrashDiagnostics.markHandled(ours)
    }
}
