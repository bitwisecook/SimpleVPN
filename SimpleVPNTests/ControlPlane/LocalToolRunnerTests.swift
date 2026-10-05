// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

@Suite(.serialized)
struct LocalToolProcessBoundsTests {
    @Test func drainsBothPipesWithoutDeadlock() async {
        let result = await LocalToolRunner.run(executable: "/bin/sh", arguments: ["-c",
            "i=0; while [ $i -lt 3000 ]; do printf 'abcdefghijklmnopqrstuvwxyz0123456789\\n'; printf 'a diagnostic line\\n' >&2; i=$((i+1)); done"], deadline: 5)
        #expect(result.succeeded)
        #expect(result.stdout.count == 111000)
        #expect(result.stderr == "a diagnostic line")
    }
    @Test func boundsUntrustedOutputAndRefusesTruncatedSuccess() async {
        let result = await LocalToolRunner.run(executable: "/usr/bin/yes", arguments: ["oversized tool output"], deadline: 5)
        #expect(!result.succeeded)
        #expect(result.stdout.isEmpty)
        #expect(result.stderr == "tool output exceeded its limit")
    }
    @Test func descendantsCannotHoldTheResultPastItsDeadline() async {
        let clock = ContinuousClock(), began = clock.now
        let result = await LocalToolRunner.run(executable: "/bin/sh", arguments: ["-c", "(sleep 4) & exit 0"], deadline: 0.05)
        #expect(result.timedOut)
        #expect(clock.now - began < .seconds(3.5))
    }
    @Test func cancellationKillsAChildIgnoringTermination() async throws {
        let clock = ContinuousClock(), began = clock.now
        let task = Task { await LocalToolRunner.run(executable: "/bin/sh", arguments: ["-c", "trap '' TERM; while :; do sleep 0.05; done"], deadline: 15) }
        try await Task.sleep(for: .milliseconds(100))
        task.cancel()
        let result = await task.value
        #expect(!result.succeeded)
        #expect(result.stderr == "cancelled")
        #expect(clock.now - began < .seconds(3.5))
    }
    @Test func stdinIsBoundedAndReachesTheTool() async {
        let bytes = Data(repeating: 97, count: 100000)
        let result = await LocalToolRunner.run(executable: "/bin/cat", arguments: [], deadline: 5, stdin: bytes)
        #expect(result.succeeded)
        #expect(result.stdout == bytes)
    }
}
