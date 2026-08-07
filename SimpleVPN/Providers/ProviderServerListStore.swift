// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderServerListStore.swift
//  KEEPING A FETCHED LIST BETWEEN LAUNCHES, and re-checking it on the way back in.
//
//  WHERE IT DOES NOT GO, and this is the decision that shaped the file.
//  Docs/ServiceBundles.md §5: `providerConfiguration` holds only what the user
//  AUTHORED, and three thousand provider hostnames are not that. They are not the
//  user's data at all — they are a cache of somebody else's published facts, which
//  is why this is Application Support and why an export does not carry it (it is
//  reconstructible, and shipping a provider's server list inside our export file
//  would reintroduce the redistribution problem of §6).
//
//  WHY A SEPARATE CODABLE SHAPE INSTEAD OF `Codable` ON THE MODEL. `ProviderHostname`
//  and `ProviderPeerKey` are TYPES rather than validated strings precisely so that
//  "did anyone check this?" is answered by the compiler. A synthesised `Decodable`
//  conformance would hand both a second initialiser that skips every check — and
//  the file on disk is as untrusted as the network, because anything that can write
//  a file in Application Support can write that one. So the stored shape is plain
//  strings, and reading it goes through the SAME validators the fetch does: the
//  suffix check, the 32-byte key decode, the address re-serialisation. A tampered
//  cache can therefore do no more than an outright hostile payload could, which is
//  to lose rows.
//
//  A ROW THAT FAILS RE-VALIDATION IS DROPPED AND COUNTED, never repaired — and if
//  that empties the list, the answer is "there is no stored list", which the
//  integrity rules already handle (a first fetch has nothing to be substituted for)
//  rather than a half-list that looks deliberate.
//

import Foundation
import os

// MARK: - The stored shape

/// The on-disk form of one provider's list: plain strings, no validated types.
///
/// Deliberately dull. Every field here is re-checked by `ProviderServerList` on the
/// way back into memory, so nothing in this struct is trusted by anything.
nonisolated struct StoredProviderServerList: Codable, Sendable, Equatable {

    nonisolated struct Row: Codable, Sendable, Equatable {
        var hostname: String
        var ipv4: String?
        var ipv6: String?
        var countryCode: String?
        var cityCode: String?
        var cityName: String?
        var peerKey: String?
        var active: Bool
    }

    var providerID: String
    var servers: [Row]
    var dropped: Int
    var fetchedAt: Date
}

nonisolated extension ProviderServerList {

    /// The list as it goes to disk.
    var stored: StoredProviderServerList {
        StoredProviderServerList(
            providerID: providerID.rawValue,
            servers: servers.map {
                .init(hostname: $0.hostname.value, ipv4: $0.ipv4, ipv6: $0.ipv6,
                      countryCode: $0.countryCode, cityCode: $0.cityCode,
                      cityName: $0.cityName, peerKey: $0.peerKey?.base64, active: $0.active)
            },
            dropped: dropped, fetchedAt: fetchedAt)
    }

    /// The list as it comes BACK, every field re-validated.
    ///
    /// `nil` when the file names a provider this build does not know, or when
    /// nothing in it survives — both of which mean "there is no stored list", which
    /// is a state the rest of the feature already knows how to be in.
    static func from(_ stored: StoredProviderServerList) -> ProviderServerList? {
        guard let id = VPNServiceProviderID(rawValue: stored.providerID) else { return nil }
        let suffix = VPNServiceProviderCatalog.provider(id).hostnameSuffix
        var servers: [ProviderServer] = []
        var dropped = 0
        for row in stored.servers {
            guard let host = ProviderHostname(row.hostname, allowedSuffix: suffix) else {
                dropped += 1
                continue
            }
            // A key that no longer decodes to 32 bytes becomes NO key rather than a
            // bad one. For a provider whose relays carry keys that makes the row
            // unselectable and says why (`WireGuardEndpointSelection`), which is the
            // loud failure; keeping a malformed key would be the quiet one.
            let key = row.peerKey.flatMap(ProviderPeerKey.init)
            if row.peerKey != nil && key == nil { dropped += 1; continue }
            servers.append(ProviderServer(
                hostname: host,
                ipv4: ProviderServer.normalisedIPv4(row.ipv4),
                ipv6: ProviderServer.normalisedIPv6(row.ipv6),
                countryCode: ProviderServer.normalisedCountry(row.countryCode),
                cityCode: row.cityCode,
                cityName: row.cityName,
                peerKey: key,
                active: row.active))
        }
        guard !servers.isEmpty else { return nil }
        return ProviderServerList(providerID: id, servers: servers,
                                  dropped: stored.dropped + dropped, fetchedAt: stored.fetchedAt)
    }
}

// MARK: - The store

/// One file per provider under Application Support.
///
/// Not `@Observable` and not a singleton with state: reads are cheap, writes are
/// rare (a fetch is a button), and a cache that nothing observes cannot become a
/// second source of truth for what the Servers table shows — the endpoint list is
/// that, and this only ever feeds it.
@MainActor
final class ProviderServerListStore {

    static let shared = ProviderServerListStore()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "providers")

    /// Overridable so tests get their own directory rather than the user's.
    let directory: URL

    init(directory: URL? = nil) {
        self.directory = directory ?? Self.defaultDirectory()
    }

    private static func defaultDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return base.appendingPathComponent("SimpleVPN/ProviderLists", isDirectory: true)
    }

    private func url(_ id: VPNServiceProviderID) -> URL {
        // The raw value is a fixed enum case, never anything from a payload, so
        // there is no path component a fetch could influence.
        directory.appendingPathComponent("\(id.rawValue).json")
    }

    /// The last good list for a provider, re-validated, or nil.
    func list(_ id: VPNServiceProviderID) -> ProviderServerList? {
        guard let data = try? Data(contentsOf: url(id)),
              let stored = try? JSONDecoder().decode(StoredProviderServerList.self, from: data)
        else { return nil }
        // A file naming a DIFFERENT provider than its own name is not a mix-up to
        // paper over: it would put one company's relays under another's row.
        guard stored.providerID == id.rawValue else {
            Self.log.error("stored list for \(id.rawValue, privacy: .public) names \(stored.providerID, privacy: .public)")
            return nil
        }
        return ProviderServerList.from(stored)
    }

    /// Replace the stored list. Called only after the diff rules have said this
    /// update may be applied — this function makes no judgement of its own, which is
    /// why it cannot accidentally become a second way to accept a substitution.
    func save(_ list: ProviderServerList) {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            try encoder.encode(list.stored).write(to: url(list.providerID), options: .atomic)
        } catch {
            // A cache that cannot be written is a slower feature, never a broken one:
            // the fetch still produced a list and the caller still has it.
            Self.log.error("could not store \(list.providerID.rawValue, privacy: .public) list: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Forget one provider's list. The counterpart to consenting: withdrawing
    /// consent must be able to leave nothing behind.
    func forget(_ id: VPNServiceProviderID) {
        try? FileManager.default.removeItem(at: url(id))
    }
}
