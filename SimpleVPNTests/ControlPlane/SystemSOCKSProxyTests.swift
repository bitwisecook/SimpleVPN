// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

nonisolated private final class MemorySOCKSStore: SystemSOCKSStore {
    var settings: [String: [String: NSObject]] = [:]
    var failBeforeCommit = false
    var failNextApply = false
    var writes = 0

    func exchange(service: String, expected: [[String: NSObject]]?,
                  replacement: [String: NSObject], beforeCommit: ([String: NSObject]) throws -> Void) throws -> SOCKSExchange {
        let current = settings[service] ?? [:]
        if let expected, !expected.contains(current) { return .externallyChanged }
        try beforeCommit(current)
        if failBeforeCommit { throw POSIXError(.EIO) }
        settings[service] = replacement
        writes += 1
        defer { failNextApply = false }
        return .committed(previous: current, applied: !failNextApply)
    }
}

nonisolated private final class MemorySOCKSJournal: SOCKSRecoveryJournal {
    var record: SOCKSRecovery?
    func load(forNewRequest: Bool) throws -> SOCKSRecovery? { record }
    func save(_ record: SOCKSRecovery) throws { self.record = record }
    func clear() throws { record = nil }
}

struct SystemSOCKSProxyTests {
    private let original: [String: NSObject] = ["SOCKSEnable": NSNumber(value: 0),
                                                 "SOCKSProxy": "work.example" as NSString,
                                                 "SOCKSPort": NSNumber(value: 9000),
                                                 "SOCKSUser": "work" as NSString]

    @Test func ownersHandOffAndRestoreOriginalAuthenticationAndDisabledState() throws {
        let store = MemorySOCKSStore(), ownership = SystemSOCKSOwnership()
        store.settings["wired"] = original
        ownership.request("first", port: 1080)
        try ownership.reconcile(primary: "wired", store: store)
        #expect(store.settings["wired"]?["SOCKSUser"] == nil)
        ownership.request("second", port: 2080)
        try ownership.reconcile(primary: "wired", store: store)
        #expect(store.settings["wired"]?["SOCKSPort"] == NSNumber(value: 2080))
        ownership.request("second", port: nil)
        try ownership.reconcile(primary: "wired", store: store)
        #expect(store.settings["wired"]?["SOCKSPort"] == NSNumber(value: 1080))

        ownership.request("third", port: 3080)
        try ownership.reconcile(primary: "wired", store: store)
        let before = store.writes
        ownership.request("first", port: nil)
        try ownership.reconcile(primary: "wired", store: store)
        #expect(store.writes == before)
        ownership.clearRequests()
        try ownership.reconcile(primary: nil, store: store)
        #expect(store.settings["wired"] == original)
    }

    @Test func networkChangesRestoreExactlyTheServicesWeChanged() throws {
        let store = MemorySOCKSStore(), ownership = SystemSOCKSOwnership()
        store.settings["wifi"] = original
        ownership.request("vpn", port: 1080)
        try ownership.reconcile(primary: "wifi", store: store)
        try ownership.reconcile(primary: "ethernet", store: store)
        #expect(store.settings["wifi"] == original)
        #expect(store.settings["ethernet"]?["SOCKSPort"] == NSNumber(value: 1080))
        // Wi-Fi is primary again when the user quits; the owned service is Ethernet.
        ownership.clearRequests()
        try ownership.reconcile(primary: "wifi", store: store)
        #expect(store.settings["ethernet"] == [:])
        #expect(store.settings["wifi"] == original)
    }

    @Test func externalEditSurvivesHandoffAndQuit() throws {
        let store = MemorySOCKSStore(), ownership = SystemSOCKSOwnership()
        ownership.request("first", port: 1080)
        try ownership.reconcile(primary: "wifi", store: store)
        ownership.request("second", port: 2080)
        try ownership.reconcile(primary: "wifi", store: store)
        store.settings["wifi"] = original
        ownership.request("second", port: nil)
        #expect(throws: (any Error).self) { try ownership.reconcile(primary: "wifi", store: store) }
        try ownership.reconcile(primary: "wifi", store: store)
        ownership.clearRequests()
        try ownership.reconcile(primary: "wifi", store: store)
        #expect(store.settings["wifi"] == original)
    }

    @Test(arguments: [false, true])
    func relaunchRecoversEitherSideOfAHandoff(interruptedBeforeCommit: Bool) throws {
        let store = MemorySOCKSStore(), journal = MemorySOCKSJournal()
        let beforeCrash = SystemSOCKSOwnership(journal: journal)
        store.settings["wired"] = original
        beforeCrash.request("first", port: 1080)
        try beforeCrash.reconcile(primary: "wired", store: store)
        beforeCrash.request("second", port: 2080)
        if interruptedBeforeCommit {
            store.failBeforeCommit = true
            #expect(throws: (any Error).self) { try beforeCrash.reconcile(primary: "wired", store: store) }
            store.failBeforeCommit = false
        } else {
            try beforeCrash.reconcile(primary: "wired", store: store)
        }
        let relaunched = SystemSOCKSOwnership(journal: journal)
        try relaunched.reconcile(primary: nil, store: store)
        #expect(store.settings["wired"] == original)
        #expect(journal.record == nil)
    }

    @Test func relaunchHonorsAnExternalProxyAndDoesNoWorkWithoutALease() throws {
        let store = MemorySOCKSStore(), journal = MemorySOCKSJournal()
        let beforeCrash = SystemSOCKSOwnership(journal: journal)
        beforeCrash.request("first", port: 1080)
        try beforeCrash.reconcile(primary: "wired", store: store)
        store.settings["wired"] = original
        let relaunched = SystemSOCKSOwnership(journal: journal)
        try relaunched.reconcile(primary: nil, store: store)
        #expect(store.settings["wired"] == original)
        #expect(journal.record == nil)
        try relaunched.reconcile(primary: nil, store: store)
        #expect(store.writes == 1)
    }

    @Test func failedActivationRetainsRestorationStateForQuitRetry() throws {
        let store = MemorySOCKSStore(), ownership = SystemSOCKSOwnership()
        store.settings["wired"] = original
        ownership.request("first", port: 1080)
        store.failNextApply = true
        #expect(throws: (any Error).self) { try ownership.reconcile(primary: "wired", store: store) }
        #expect(ownership.hasLease)
        ownership.clearRequests()
        store.failNextApply = true
        #expect(throws: (any Error).self) { try ownership.reconcile(primary: nil, store: store) }
        #expect(ownership.hasLease)
        try ownership.reconcile(primary: nil, store: store)
        #expect(!ownership.hasLease)
        #expect(store.settings["wired"] == original)
    }
}
