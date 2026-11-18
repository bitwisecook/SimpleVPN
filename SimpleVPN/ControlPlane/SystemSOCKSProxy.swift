// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation
import Security
import SystemConfiguration

/// Only the SOCKS fields belong to this operation. HTTP, PAC, exceptions and
/// other settings are always taken from the latest locked preferences.
nonisolated protocol SystemSOCKSStore {
    func exchange(service: String, expected: [[String: NSObject]]?,
                  replacement: [String: NSObject], beforeCommit: ([String: NSObject]) throws -> Void) throws -> SOCKSExchange
}

nonisolated enum SOCKSExchange {
    case externallyChanged
    case committed(previous: [String: NSObject], applied: Bool)
}

nonisolated private struct SOCKSFailure: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

/// Used exclusively on the proxy queue. Keep the authorization for the lifetime
/// of the leases so restoring a service can use the same macOS authorization.
nonisolated private final class NetworkServiceSOCKSStore: SystemSOCKSStore {
    private var authorization: AuthorizationRef?

    func releaseAuthorization() {
        if let authorization { AuthorizationFree(authorization, []) }
        authorization = nil
    }

    static func primaryService() -> String? {
        for entity in [kSCEntNetIPv4, kSCEntNetIPv6] {
            let key = SCDynamicStoreKeyCreateNetworkGlobalEntity(nil, kSCDynamicStoreDomainState, entity)
            if let global = SCDynamicStoreCopyValue(nil, key) as? [String: Any],
               let id = global[kSCDynamicStorePropNetPrimaryService as String] as? String { return id }
        }
        return nil
    }

    func exchange(service id: String, expected: [[String: NSObject]]?,
                  replacement: [String: NSObject], beforeCommit: ([String: NSObject]) throws -> Void) throws -> SOCKSExchange {
        if authorization == nil {
            guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess else {
                throw SOCKSFailure("macOS could not authorize the system SOCKS proxy change.")
            }
        }
        guard let prefs = SCPreferencesCreateWithAuthorization(nil, "SimpleVPN" as CFString, nil, authorization),
              SCPreferencesLock(prefs, true) else {
            throw SOCKSFailure("macOS did not grant access to Network settings.")
        }
        defer { SCPreferencesUnlock(prefs) }
        guard let service = SCNetworkServiceCopy(prefs, id as CFString),
              let proxies = SCNetworkServiceCopyProtocol(service, kSCEntNetProxies) else {
            if expected != nil && SCError() == kSCStatusNoKey { return .externallyChanged }
            throw SOCKSFailure("The primary network service has no enabled proxy settings.")
        }

        if expected == nil && !SCNetworkProtocolGetEnabled(proxies) {
            throw SOCKSFailure("The primary network service has proxy settings disabled.")
        }
        var settings = SCNetworkProtocolGetConfiguration(proxies) as? [String: NSObject] ?? [:]
        let current = settings.filter { $0.key.hasPrefix("SOCKS") }
        if let expected, !expected.contains(current) { return .externallyChanged }
        try beforeCommit(current)
        for key in current.keys { settings.removeValue(forKey: key) }
        settings.merge(replacement) { _, new in new }
        guard SCNetworkProtocolSetConfiguration(proxies, settings as CFDictionary),
              SCPreferencesCommitChanges(prefs) else {
            throw SOCKSFailure("macOS could not save the system SOCKS proxy settings.")
        }
        return .committed(previous: current, applied: SCPreferencesApplyChanges(prefs))
    }

    deinit { releaseAuthorization() }
}

/// A serial-queue state machine. Later requests take precedence. Compare and
/// replace under one preferences lock, including during handoff and restore.
nonisolated final class SystemSOCKSOwnership {
    private struct Lease {
        var service: String
        var original: [String: NSObject]
        var installed: [String: NSObject]
        var applied: Bool
    }
    private let journal: (any SOCKSRecoveryJournal)?
    init(journal: (any SOCKSRecoveryJournal)? = nil) { self.journal = journal }

    private var owners: [(id: String, port: Int)] = []
    private var lease: Lease?
    private var externallyManagedService: String?
    var hasRequests: Bool { !owners.isEmpty }
    var hasLease: Bool { lease != nil }
    var owner: String? { owners.last?.id }

    @discardableResult
    func request(_ id: String, port: Int?) -> Bool {
        if port == nil && !owners.contains(where: { $0.id == id }) { return false }
        owners.removeAll { $0.id == id }
        if let port {
            owners.append((id, port))
            externallyManagedService = nil
        }
        return true
    }

    func clearRequests() { owners.removeAll() }

    func reconcile(primary: String?, store: any SystemSOCKSStore) throws {
        if lease == nil { try recover(store: store) }
        if let held = lease, owners.isEmpty || primary != held.service {
            switch try store.exchange(service: held.service, expected: [held.installed], replacement: held.original, beforeCommit: { _ in }) {
            case .committed(_, false):
                lease = Lease(service: held.service, original: held.original, installed: held.original, applied: false)
                throw SOCKSFailure("The previous SOCKS settings were saved, but macOS could not activate them.")
            case .externallyChanged, .committed(_, true):
                lease = nil
                try journal?.clear()
            }
        }
        guard let owner = owners.last else { externallyManagedService = nil; return }
        guard let primary else { throw SOCKSFailure("Waiting for a primary network service.") }
        guard primary != externallyManagedService else { return }
        let local: [String: NSObject] = ["SOCKSEnable": NSNumber(value: 1), "SOCKSProxy": "127.0.0.1" as NSString,
                                         "SOCKSPort": NSNumber(value: owner.port)]
        if lease?.installed == local, lease?.applied == true { return }
        let previous = lease
        let result = try store.exchange(service: primary, expected: previous.map { [$0.installed] },
                                        replacement: local) { current in
            // Persist both sides of a handoff before changing preferences.
            // A crash on either side of commit must return to the same baseline.
            try journal?.save(SOCKSRecovery(service: primary, original: previous?.original ?? current,
                                            owned: previous.map { [$0.installed, local] } ?? [local]))
        }
        switch result {
        case .externallyChanged:
            lease = nil
            externallyManagedService = primary
            try journal?.clear()
            throw SOCKSFailure("Another app or Network settings changed the system SOCKS proxy. Turn the setting off and on to use this VPN again.")
        case .committed(let snapshot, let applied):
            let original = previous?.original ?? snapshot
            lease = Lease(service: primary, original: original, installed: local, applied: applied)
            if previous != nil && applied {
                // A completed handoff only owns its new port.
                try journal?.save(SOCKSRecovery(service: primary, original: original, owned: [local]))
            }
            if !applied { throw SOCKSFailure("The new SOCKS settings were saved, but macOS could not activate them.") }
        }
    }

    private func recover(store: any SystemSOCKSStore) throws {
        guard let journal, let record = try journal.load(forNewRequest: hasRequests) else { return }
        // The original may already be committed but still awaiting activation.
        let result = try store.exchange(service: record.service, expected: record.owned + [record.original],
                                        replacement: record.original, beforeCommit: { _ in })
        if case .committed(_, false) = result {
            throw SOCKSFailure("macOS could not activate the recovered SOCKS settings.")
        }
        try journal.clear()
    }
}

nonisolated final class SystemSOCKSProxy: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.system-socks")
    private let store = NetworkServiceSOCKSStore()
    private let journal: KeychainSOCKSJournal
    private let ownership: SystemSOCKSOwnership
    private let report: @MainActor @Sendable (String, String?) -> Void
    private let monitor = SCStoreMonitor<String?>(
        label: "com.bragi0.SimpleVPN.system-socks.primary",
        keys: ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"], patterns: [],
        snapshot: { NetworkServiceSOCKSStore.primaryService() })
    private var primary: String?

    init(report: @escaping @MainActor @Sendable (String, String?) -> Void) {
        let journal = KeychainSOCKSJournal()
        self.journal = journal
        ownership = SystemSOCKSOwnership(journal: journal)
        self.report = report
    }

    func request(_ id: String, port: Int?) {
        queue.async { [self] in
            guard ownership.request(id, port: port) else { return }
            do {
                if ownership.hasRequests {
                    try monitor.start { [weak self] value in
                        guard let self else { return }
                        self.queue.async {
                            guard self.ownership.hasRequests, self.primary != value else { return }
                            self.primary = value
                            self.update(for: self.ownership.owner)
                        }
                    }
                    primary = NetworkServiceSOCKSStore.primaryService()
                } else { monitor.stop() }
                update(for: ownership.owner ?? id)
            } catch { publish(error.localizedDescription, for: id) }
        }
    }

    /// Queue behind every pending change, including an authorization dialog or
    /// a disconnect enqueued immediately before the user chose Quit.
    func restore(afterCrash: Bool) async -> String? {
        await withCheckedContinuation { continuation in
            queue.async { [self] in
                let busyAtLaunch = afterCrash && ownership.hasRequests
                let cleanAtQuit = !afterCrash && !ownership.hasRequests && !ownership.hasLease && !journal.isOpen
                if busyAtLaunch || cleanAtQuit {
                    continuation.resume(returning: nil)
                    return
                }
                monitor.stop()
                ownership.clearRequests()
                do {
                    try ownership.reconcile(primary: nil, store: store)
                    store.releaseAuthorization()
                    journal.close()
                    continuation.resume(returning: nil)
                } catch { continuation.resume(returning: error.localizedDescription) }
            }
        }
    }

    private func update(for id: String?) {
        do {
            try ownership.reconcile(primary: primary, store: store)
            publish(nil, for: id)
        } catch { publish(error.localizedDescription, for: id) }
        if !ownership.hasRequests && !ownership.hasLease {
            store.releaseAuthorization()
            journal.close()
        }
    }

    private func publish(_ error: String?, for id: String?) {
        guard let id else { return }
        DispatchQueue.main.async { [report] in report(id, error) }
    }
}

nonisolated struct SOCKSRecovery {
    let service: String
    let original: [String: NSObject]
    let owned: [[String: NSObject]]
}

nonisolated protocol SOCKSRecoveryJournal {
    func load(forNewRequest: Bool) throws -> SOCKSRecovery?
    func save(_ record: SOCKSRecovery) throws
    func clear() throws
}

/// The file's length is the only public marker. A nonempty file means that
/// Keychain may contain a write-ahead record. The advisory lock distinguishes
/// a crashed process from another live installation using the proxy.
nonisolated private final class KeychainSOCKSJournal: SOCKSRecoveryJournal {
    private var fd: Int32 = -1
    private var active = false
    var isOpen: Bool { fd >= 0 }
    private let file = URL.applicationSupportDirectory.appending(path: "SimpleVPN/system-socks.lock")

    func load(forNewRequest: Bool) throws -> SOCKSRecovery? {
        if fd < 0 {
            let path = file.path
            if forNewRequest {
                try FileManager.default.createDirectory(at: file.deletingLastPathComponent(),
                                                        withIntermediateDirectories: true)
            } else {
                var marker = stat()
                if lstat(path, &marker) != 0 {
                    if errno == ENOENT { return nil }
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                if marker.st_size == 0 { return nil }
            }
            let flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_EXLOCK
            fd = open(path, forNewRequest ? flags | O_CREAT : flags, 0o600)
            guard fd >= 0 else {
                if errno == EWOULDBLOCK {
                    if !forNewRequest { return nil }
                    throw SOCKSFailure("Another running copy of SimpleVPN is managing the system SOCKS proxy.")
                }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid() else {
                close()
                throw SOCKSFailure("Could not open the system SOCKS recovery file.")
            }
            active = info.st_size > 0
        }
        guard active else { return nil }
        guard let data = try KeychainCredentialStore.loadSOCKSRecovery() else {
            // The process stopped between marking the file and saving the
            // first record, or between deleting the last record and clearing it.
            try mark(false)
            return nil
        }
        guard let values = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let service = values["service"] as? String, let original = values["original"] as? [String: NSObject],
              let owned = values["owned"] as? [[String: NSObject]] else {
            throw SOCKSFailure("The saved system SOCKS recovery record could not be read.")
        }
        return SOCKSRecovery(service: service, original: original, owned: owned)
    }

    func save(_ record: SOCKSRecovery) throws {
        let data = try PropertyListSerialization.data(fromPropertyList:
            ["service": record.service, "original": record.original, "owned": record.owned],
                                                      format: .binary, options: 0)
        if !active { try mark(true) }
        try KeychainCredentialStore.saveSOCKSRecovery(data)
    }

    func clear() throws {
        guard active else { return }
        try KeychainCredentialStore.removeSOCKSRecovery()
        try mark(false)
    }

    private func mark(_ present: Bool) throws {
        guard fd >= 0, ftruncate(fd, present ? 1 : 0) == 0, fsync(fd) == 0 else {
            throw SOCKSFailure("Could not save the recovery marker for the system SOCKS proxy.")
        }
        active = present
    }

    func close() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
        active = false
    }
    deinit { close() }
}
