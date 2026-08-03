// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ChromiumWebCustomData.swift
//  Reads the `org.chromium.web-custom-data` drag flavour — how 1Password 8
//  (an Electron app, so a Chromium one) really names the item you dragged.
//
//  Dragging an item ROW out of 1Password puts four flavours on the pasteboard:
//  the plain text is ONLY the item's title, two chromium flavours are drag
//  bookkeeping, and this one carries the actual coordinates:
//
//      [{"type":"item",
//        "itemUuidComponents":{"accountUuid":"…","vaultUuid":"…","itemUuid":"…"},
//        …}]
//
//  That is the whole setup in one gesture — account, vault and item — which no
//  other flavour offers (a field drag gives `op://` with the vault but never the
//  account; only "Copy Private Link" names the account).
//
//  The container is a Chromium `base::Pickle`: little-endian throughout, a
//  uint32 payload size, a uint32 entry count, then per entry two strings, each a
//  uint32 count of UTF-16 code units followed by UTF-16LE bytes padded up to a
//  4-byte boundary. Nothing here trusts any of those numbers: this parser is fed
//  whatever a foreign app decided to put on a pasteboard, so every read is
//  bounds-checked, lengths are capped, and anything unexpected yields no entries
//  rather than a crash or a huge allocation.
//

import Foundation

nonisolated enum ChromiumWebCustomData {
    /// The pasteboard/item-provider type identifier, as a plain string: it is
    /// not a registered UTType on a Mac without Chromium, so it can only ever be
    /// asked for by identifier (NSItemProvider is happy with that).
    static let typeIdentifier = "org.chromium.web-custom-data"

    /// Caps so a malformed or hostile blob can't make us allocate on its say-so.
    private static let maxEntries = 64
    private static let maxStringUnits = 1 << 18

    /// The (type, value) pairs a web-custom-data blob carries, or none when it
    /// isn't one. Layout variants (with/without the pickle header, padded or
    /// not) are tried in turn, most-likely first — the format is another app's
    /// private detail and we'd rather survive a variant than reject a good drag.
    static func entries(from data: Data) -> [(type: String, value: String)] {
        for skipHeader in [true, false] {
            for padded in [true, false] {
                if let out = decode(data, skipHeader: skipHeader, padded: padded), !out.isEmpty {
                    return out
                }
            }
        }
        return []
    }

    /// One decode attempt. Returns nil the moment anything doesn't add up —
    /// partial results would let a coincidence pass for a payload.
    private static func decode(_ data: Data, skipHeader: Bool, padded: Bool)
        -> [(type: String, value: String)]? {
        var cursor = data.startIndex

        func remaining() -> Int { data.distance(from: cursor, to: data.endIndex) }

        func readU32() -> UInt32? {
            guard remaining() >= 4 else { return nil }
            var value: UInt32 = 0
            for offset in 0..<4 {
                value |= UInt32(data[data.index(cursor, offsetBy: offset)]) << (8 * UInt32(offset))
            }
            cursor = data.index(cursor, offsetBy: 4)
            return value
        }

        func readString() -> String? {
            guard let units = readU32(), units <= UInt32(maxStringUnits) else { return nil }
            let byteCount = Int(units) * 2
            guard remaining() >= byteCount else { return nil }
            var codeUnits = [UInt16]()
            codeUnits.reserveCapacity(Int(units))
            var index = cursor
            for _ in 0..<Int(units) {
                let low = UInt16(data[index])
                let high = UInt16(data[data.index(after: index)])
                codeUnits.append(low | (high << 8))
                index = data.index(index, offsetBy: 2)
            }
            cursor = index
            if padded {
                // Alignment is measured from the start of the blob; the header is
                // itself 4 bytes, so absolute and payload-relative agree.
                let consumed = data.distance(from: data.startIndex, to: cursor)
                let slack = (4 - consumed % 4) % 4
                guard remaining() >= slack else { return nil }
                cursor = data.index(cursor, offsetBy: slack)
            }
            return String(decoding: codeUnits, as: UTF16.self)
        }

        if skipHeader, readU32() == nil { return nil }
        guard let count = readU32(), count > 0, count <= UInt32(maxEntries) else { return nil }
        var out: [(type: String, value: String)] = []
        out.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let type = readString(), let value = readString() else { return nil }
            out.append((type, value))
        }
        return out
    }
}

/// The 1Password half of the payload: which item was dragged, in the only
/// vocabulary that needs no typing afterwards — account, vault and item UUIDs,
/// all three of which the desktop-app SDK accepts directly.
nonisolated enum OnePasswordDragPayload {
    /// The custom-data entry 1Password writes its own JSON under.
    static let entryType = "application/1password"

    struct Coordinates: Sendable, Equatable {
        var itemUUID = ""
        var vaultUUID = ""
        var accountUUID = ""
    }

    /// The coordinates carried by a decoded web-custom-data blob — one per
    /// dragged item, in the order they were selected. Empty when the drag wasn't
    /// a 1Password item drag at all.
    static func coordinates(in entries: [(type: String, value: String)]) -> [Coordinates] {
        guard let json = entries.first(where: { $0.type == entryType })?.value else { return [] }
        return parse(json: json)
    }

    /// A drag can name several things (and 1Password labels each), so only
    /// entries that say they are ITEMS count — a dragged field or folder has no
    /// item UUID to offer and must fall through to the other flavours. A
    /// multi-selection drags as several entries, and picking one of them is the
    /// user's call, so all of them are returned in selection order.
    static func parse(json: String) -> [Coordinates] {
        struct Components: Decodable {
            var accountUuid: String?
            var vaultUuid: String?
            var itemUuid: String?
        }
        struct Entry: Decodable {
            var type: String?
            var itemUuidComponents: Components?
        }
        guard let data = json.data(using: .utf8),
              let entries = try? JSONDecoder().decode([Entry].self, from: data)
        else { return [] }
        return entries.compactMap { entry in
            guard entry.type == "item",
                  let components = entry.itemUuidComponents,
                  let itemUUID = components.itemUuid, !itemUUID.isEmpty
            else { return nil }
            return Coordinates(itemUUID: itemUUID,
                               vaultUUID: components.vaultUuid ?? "",
                               accountUUID: components.accountUuid ?? "")
        }
    }

    /// Titles to show for `count` dragged items, taken from the plain-text
    /// flavour. A single drag carries the bare title; a multi-selection carries
    /// one title per line in the same order. When the two don't line up (any
    /// other shape, an item whose own title contains a newline, a future
    /// change) the titles are dropped entirely rather than misattributed — a
    /// chooser labelling the wrong item is worse than one labelling none.
    static func titles(fromPlainText text: String?, count: Int) -> [String] {
        guard count > 0, let text else { return [] }
        let lines = text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return lines.count == count ? lines : []
    }
}
