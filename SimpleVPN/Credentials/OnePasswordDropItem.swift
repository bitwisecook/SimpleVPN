// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordDropItem.swift
//  What a drag out of the 1Password app actually carries — and why the drop
//  wells read four flavours instead of one.
//
//  Live testing settled this. Dragging an item ROW offers:
//    • public.utf8-plain-text          — ONLY the item's title, nothing else;
//    • org.chromium.web-custom-data    — 1Password's own JSON: account, vault
//                                        AND item UUIDs (1Password 8 is an
//                                        Electron app, so its drags carry
//                                        Chromium's custom-data flavour);
//    • two chromium drag-bookkeeping flavours with nothing in them for us.
//  Dragging a FIELD instead gives an `op://vault/item/field` reference (vault,
//  never an account), and only "Copy Private Link" produces a link naming the
//  account. So the plain text alone can never finish the setup, and the custom
//  data always can — which is the whole reason this file reads it.
//
//  Priority is therefore: 1Password's payload, then a link that names an
//  account, then op://, then the bare title. Everything below the first is a
//  fallback that still has to work: a link pasted as text, an older 1Password,
//  another password manager's drag.
//

import Foundation
import UniformTypeIdentifiers
import AppKit
import os

/// One item a drop resolved to. `reference` is what 1Password will be ASKED for
/// (a UUID whenever the drag carried one — exact, and immune to renaming),
/// `title` is what the person should SEE.
nonisolated struct OnePasswordDrop: Sendable, Equatable, Identifiable, Hashable {
    var reference: String
    var vault: String = ""
    var account: String = ""
    var title: String = ""
    var vaultTitle: String = ""
    var accountTitle: String = ""
    var id: String { "\(vault)/\(reference)" }

    /// What to show in a list: the real title when the drag gave one, otherwise
    /// a plain position ("Item 2") — never a raw UUID, which tells nobody
    /// anything.
    func displayName(position: Int) -> String {
        title.isEmpty ? "Item \(position)" : title
    }

    /// Same item? Coordinates only — account, vault and item. Two readings of
    /// one drag can differ in TITLE (the copy that carried no plain text has
    /// none), and treating those as two items is what sent a single-item drop to
    /// the "which one?" chooser in build 100.
    func isSameItem(as other: OnePasswordDrop) -> Bool {
        reference == other.reference && vault == other.vault && account == other.account
    }

    /// Take whatever the other reading of this same item knows and we don't.
    mutating func fillGaps(from other: OnePasswordDrop) {
        if title.isEmpty { title = other.title }
        if vault.isEmpty { vault = other.vault }
        if account.isEmpty { account = other.account }
        if vaultTitle.isEmpty { vaultTitle = other.vaultTitle }
        if accountTitle.isEmpty { accountTitle = other.accountTitle }
    }

    /// Does this reference look like one of 1Password's own ids (26 letters and
    /// digits, no spaces) rather than something a person typed? Only used to
    /// decide whether a string is fit to SHOW — never to decide what to ask for.
    static func looksLikeItemID(_ reference: String) -> Bool {
        let s = reference.trimmingCharacters(in: .whitespaces)
        return s.count == 26 && s.allSatisfy { $0.isLetter || $0.isNumber } && s.contains { $0.isNumber }
    }
}

nonisolated struct OnePasswordDropItem: Sendable, Equatable {
    /// Which flavour a payload came from. Recorded so a log capture can show
    /// what 1Password really offers on drag, which is the only way to tell a
    /// "1Password didn't provide it" bug from a "we didn't ask for it" one.
    enum Flavor: String, Sendable, Equatable { case url, text }

    var raw: String
    var flavor: Flavor

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "1password")

    /// Public flavours used to register the SwiftUI destination. A 1Password
    /// row drag always includes UTF-8 text alongside Chromium's private payload;
    /// once SwiftUI admits the drag, `read(from:)` asks the provider for that
    /// private representation by its exact identifier.
    static var acceptedContentTypes: [UTType] {
        [.utf8PlainText, .plainText, .text, .url]
    }

    // MARK: Reading a real drag

    static func logTargeting(_ targeted: Bool) {
        log.log("1Password SwiftUI drop target entered=\(targeted, privacy: .public)")
    }

    static func logTypedDrop(stringCount: Int, snapshot: Reading) {
        log.log("1Password SwiftUI typed drop strings=\(stringCount, privacy: .public) snapshotPayload=\(snapshot.fromPayload, privacy: .public)")
    }

    static func logDropSession(phase: String, items: Int) {
        log.log("1Password SwiftUI drop session phase=\(phase, privacy: .public) items=\(items, privacy: .public)")
    }

    /// Whether this drag is worth accepting, decided from the flavour list
    /// alone — `onDrop` must answer before anything can be loaded. A dragged
    /// FILE is refused: it is not a 1Password item, and accepting it would put
    /// "file:///Users/…" in the item field and look like the drop worked.
    static func canAccept(_ providers: [NSItemProvider]) -> Bool {
        providers.contains { provider in
            if provider.registeredTypeIdentifiers.contains(ChromiumWebCustomData.typeIdentifier) {
                return true
            }
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) { return false }
            return provider.hasItemConformingToTypeIdentifier(UTType.utf8PlainText.identifier)
                || provider.hasItemConformingToTypeIdentifier(UTType.url.identifier)
        }
    }

    /// Pasteboard-side acceptance used by the SwiftUI adapter's decoding tests.
    /// A real 1Password drag is an Electron drag, so its useful coordinates
    /// live in Chromium's private representation.
    @MainActor
    static func canAccept(_ pasteboard: NSPasteboard) -> Bool {
        let types = Set(pasteboard.types ?? [])
        if types.contains(NSPasteboard.PasteboardType(ChromiumWebCustomData.typeIdentifier)) {
            return true
        }
        // Never turn a configuration-file drop into a password-manager item.
        if types.contains(NSPasteboard.PasteboardType(UTType.fileURL.identifier)) {
            return false
        }
        return types.contains(.string)
            || types.contains(.URL)
            || types.contains(NSPasteboard.PasteboardType(UTType.utf8PlainText.identifier))
    }

    /// What ONE delivery of a drag added up to. A value rather than a plain
    /// array because macOS delivers the same gesture more than once (build 100
    /// logged every drop twice, the second time with an extra provider), and the
    /// deliveries have to be merged before anything is applied.
    nonisolated struct Reading: Sendable, Equatable {
        var drops: [OnePasswordDrop] = []
        /// Read from 1Password's own payload — the only flavour that names the
        /// account, and the one that wins over any text reading of the same drag.
        var fromPayload = false
        var providers = 0
        var sawWebCustomData = false
        var sawString = false
        var sawURL = false
        /// The payload was missing from the item providers and came off the drag
        /// pasteboard instead — see `dragPasteboardPayload`.
        var fromDragPasteboard = false

        var isEmpty: Bool { drops.isEmpty }

        /// Fold another delivery of the same drag into this one. The payload
        /// flavour wins outright, exactly as it does within a single delivery;
        /// otherwise the items are pooled and deduplicated by coordinates.
        func merging(_ other: Reading) -> Reading {
            var out: Reading
            if fromPayload == other.fromPayload {
                out = self
                out.drops = OnePasswordDropItem.deduped(drops + other.drops)
            } else {
                // Keep the payload reading's items, and nothing of the text
                // reading's — they describe the same item under another name.
                out = fromPayload ? self : other
            }
            out.fromPayload = fromPayload || other.fromPayload
            out.providers = providers + other.providers
            out.sawWebCustomData = sawWebCustomData || other.sawWebCustomData
            out.sawString = sawString || other.sawString
            out.sawURL = sawURL || other.sawURL
            out.fromDragPasteboard = fromDragPasteboard || other.fromDragPasteboard
            return out
        }

        /// Default level, NOT debug: debug messages aren't persisted, so a
        /// diagnostics capture taken after a failed drag showed nothing at all —
        /// which is exactly how the item-title-only drag went unnoticed. Booleans
        /// and counts only; never a value, a title or a UUID. Logged ONCE per
        /// drop, after the deliveries have been merged.
        func log() {
            OnePasswordDropItem.log.log("""
                1Password drop: payloads=\(providers, privacy: .public) \
                hadWebCustomData=\(sawWebCustomData, privacy: .public) \
                fromDragPasteboard=\(fromDragPasteboard, privacy: .public) \
                hadString=\(sawString, privacy: .public) \
                hadURL=\(sawURL, privacy: .public) \
                items=\(drops.count, privacy: .public) \
                hadVault=\(drops.contains { !$0.vault.isEmpty }, privacy: .public) \
                hadAccount=\(drops.contains { !$0.account.isEmpty }, privacy: .public)
                """)
        }
    }

    /// One entry per set of coordinates, first appearance wins its position and
    /// later readings only fill in what it was missing. Identical coordinates
    /// are ONE item however many times they were delivered.
    static func deduped(_ drops: [OnePasswordDrop]) -> [OnePasswordDrop] {
        var out: [OnePasswordDrop] = []
        for drop in drops {
            if let index = out.firstIndex(where: { $0.isSameItem(as: drop) }) {
                out[index].fillGaps(from: drop)
            } else {
                out.append(drop)
            }
        }
        return out
    }

    /// Everything a drop resolved to, best flavour first. Runs on the main actor
    /// because that's where the drop handler lives — the loads themselves are
    /// asynchronous and the parsing is pure.
    @MainActor
    static func load(from providers: [NSItemProvider]) async -> [OnePasswordDrop] {
        await read(from: providers).drops
    }

    /// As `load`, but keeping what the delivery looked like so several
    /// deliveries of one gesture can be merged (and logged once).
    @MainActor
    static func read(from providers: [NSItemProvider]) async -> Reading {
        // Read each dragging item on its own terms. A multi-selection usually
        // arrives as ONE provider carrying every item in its payload, but AppKit
        // is free to hand over one provider per item — and quietly keeping only
        // the first would silently pick a VPN's sign-in for the user.
        var reading = Reading(providers: providers.count)
        var fromPayload: [OnePasswordDrop] = []
        var fallback: [OnePasswordDrop] = []
        var firstText: String?
        var firstURL: String?
        for provider in providers {
            var custom: Data?
            var plainText: String?
            var urlText: String?
            if provider.registeredTypeIdentifiers.contains(ChromiumWebCustomData.typeIdentifier) {
                custom = await data(from: provider, identifier: ChromiumWebCustomData.typeIdentifier)
            }
            if provider.hasItemConformingToTypeIdentifier(UTType.utf8PlainText.identifier),
               let raw = await data(from: provider, identifier: UTType.utf8PlainText.identifier) {
                plainText = String(decoding: raw, as: UTF8.self)
            }
            if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier),
               let raw = await data(from: provider, identifier: UTType.url.identifier) {
                // A URL flavour arrives either as bytes of the string or as an
                // encoded NSURL; the string form is what parsing wants.
                urlText = String(decoding: raw, as: UTF8.self)
                    .trimmingCharacters(in: .controlCharacters)
            }
            reading.sawWebCustomData = reading.sawWebCustomData || custom != nil
            reading.sawString = reading.sawString || plainText != nil
            reading.sawURL = reading.sawURL || urlText != nil
            if firstText == nil { firstText = plainText }
            if firstURL == nil { firstURL = urlText }
            let parsed = classify(webCustomData: custom, plainText: plainText, urlText: urlText)
            if parsed.fromPayload { fromPayload += parsed.drops } else { fallback += parsed.drops }
        }
        // NSItemProvider doesn't always deliver 1Password's payload: the same
        // drag gesture that carried it minutes earlier arrived with only the
        // title (build 100, hadWebCustomData=false). The drag pasteboard still
        // holds the blob for the gesture in progress, so ask it directly rather
        // than fall back to a title-only setup that can't name the account.
        if fromPayload.isEmpty, !providers.isEmpty, let data = dragPasteboardPayload() {
            let parsed = classify(webCustomData: data, plainText: firstText, urlText: firstURL)
            if parsed.fromPayload {
                fromPayload = parsed.drops
                reading.sawWebCustomData = true
                reading.fromDragPasteboard = true
            }
        }
        // The payload flavour wins across the whole drop, not just within one
        // provider: mixing it with a text-only reading of the same drag would
        // offer the same item twice under two different names.
        reading.fromPayload = !fromPayload.isEmpty
        reading.drops = deduped(fromPayload.isEmpty ? fallback : fromPayload)
        return reading
    }

    /// Read one native AppKit dragging pasteboard synchronously.  Dragging data
    /// is valid only for the current gesture, which makes this the reliable
    /// place to fetch 1Password's Chromium payload.  It intentionally mirrors
    /// the final classification in the provider path above, so both routes use
    /// exactly the same account/vault/item parser.
    @MainActor
    static func read(from pasteboard: NSPasteboard) -> Reading {
        let custom = pasteboard.data(
            forType: NSPasteboard.PasteboardType(ChromiumWebCustomData.typeIdentifier))
        let plainText = pasteboard.string(forType: .string)
            ?? pasteboard.string(forType: NSPasteboard.PasteboardType(UTType.utf8PlainText.identifier))
        let urlText = pasteboard.string(forType: .URL)
        let parsed = classify(webCustomData: custom, plainText: plainText, urlText: urlText)
        return Reading(drops: deduped(parsed.drops),
                       fromPayload: parsed.fromPayload,
                       providers: 1,
                       sawWebCustomData: custom != nil,
                       sawString: plainText != nil,
                       sawURL: urlText != nil,
                       fromDragPasteboard: custom != nil)
    }

    /// Turn SwiftUI's typed String transfer into the same domain reading as the
    /// richer Chromium snapshot. This is also the fallback for older 1Password
    /// builds that expose only a title or an `op://` reference.
    static func read(plainTexts: [String]) -> Reading {
        let drops = plainTexts.flatMap {
            classify(webCustomData: nil, plainText: $0, urlText: $0).drops
        }
        return Reading(drops: deduped(drops),
                       providers: plainTexts.count,
                       sawString: !plainTexts.isEmpty,
                       sawURL: plainTexts.contains { $0.hasPrefix("op://") })
    }

    /// 1Password's payload for the drag in progress, straight off the drag
    /// pasteboard. Read-only, and only ever consulted while a drop is being
    /// handled — the pasteboard belongs to the gesture the user just made.
    @MainActor
    static func dragPasteboardPayload() -> Data? {
        NSPasteboard(name: .drag)
            .data(forType: NSPasteboard.PasteboardType(ChromiumWebCustomData.typeIdentifier))
    }

    /// SwiftUI-facing snapshot of the gesture that triggered a typed drop
    /// closure. The view never needs to know that 1Password's extra coordinates
    /// come from an AppKit pasteboard rather than an `NSItemProvider`.
    @MainActor
    static func activeDragSnapshot() -> Reading {
        read(from: NSPasteboard(name: .drag))
    }

    /// NSItemProvider's completion-handler load, by raw identifier so the
    /// unregistered Chromium type can be asked for at all.
    private static func data(from provider: NSItemProvider, identifier: String) async -> Data? {
        await withCheckedContinuation { continuation in
            provider.loadDataRepresentation(forTypeIdentifier: identifier) { data, _ in
                continuation.resume(returning: data)
            }
        }
    }

    // MARK: Parsing (pure)

    /// The items a set of flavours resolves to, in priority order. A 1Password
    /// payload wins outright — it is the only flavour that names the account,
    /// and a multi-selection drag carries one entry per dragged item (which the
    /// caller offers as a choice; a VPN uses exactly one).
    static func drops(webCustomData: Data?, plainText: String?, urlText: String?)
        -> [OnePasswordDrop] {
        classify(webCustomData: webCustomData, plainText: plainText, urlText: urlText).drops
    }

    /// As `drops`, but also says whether the answer came from 1Password's own
    /// payload — which decides what a multi-provider drop is allowed to mix.
    static func classify(webCustomData: Data?, plainText: String?, urlText: String?)
        -> (drops: [OnePasswordDrop], fromPayload: Bool) {
        if let webCustomData {
            let coordinates = OnePasswordDragPayload.coordinates(
                in: ChromiumWebCustomData.entries(from: webCustomData))
            if !coordinates.isEmpty {
                let titles = OnePasswordDragPayload.titles(
                    fromPlainText: plainText, count: coordinates.count)
                return (coordinates.enumerated().map { index, c in
                    OnePasswordDrop(reference: c.itemUUID, vault: c.vaultUUID,
                                    account: c.accountUUID,
                                    title: index < titles.count ? titles[index] : "")
                }, true)
            }
        }
        var flavours: [OnePasswordDropItem] = []
        if let urlText, !urlText.isEmpty { flavours.append(.init(raw: urlText, flavor: .url)) }
        if let plainText, !plainText.isEmpty { flavours.append(.init(raw: plainText, flavor: .text)) }
        return (parse(flavours).map { [$0] } ?? [], false)
    }

    /// The item a set of text/URL flavours names, preferring the one that can
    /// carry an account. Returns nil when nothing looks like a 1Password item —
    /// the drop well then refuses it, leaving the previous choice alone.
    ///
    /// File URLs are rejected outright: a dragged file is not a 1Password item.
    static func parse(_ items: [OnePasswordDropItem]) -> OnePasswordDrop? {
        let usable = items.filter { item in
            guard item.flavor == .url else { return true }
            return URL(string: item.raw)?.isFileURL != true
        }
        let parsed = usable.compactMap { item -> (item: OnePasswordDropItem,
                                                  parsed: (reference: String, vault: String, account: String))? in
            guard let p = parseRaw(item.raw) else { return nil }
            return (item, p)
        }
        // A link that names the account outranks everything: it's the only
        // text flavour that makes the drop a one-gesture setup.
        let chosen = parsed.first { !$0.parsed.account.isEmpty }
            ?? parsed.first { $0.item.flavor == .url }
            ?? parsed.first
        guard let chosen else { return nil }
        return OnePasswordDrop(
            reference: chosen.parsed.reference,
            vault: chosen.parsed.vault,
            account: chosen.parsed.account,
            // Only the text flavour's reference is something to show a person;
            // a link's is a UUID, which the first successful lookup replaces.
            title: chosen.item.flavor == .text ? chosen.parsed.reference : "")
    }

    /// Pure string parsing at the credential boundary. Keeping this out of an
    /// editor view lets every SwiftUI surface (including the isolated probe)
    /// consume exactly the same 1Password drag representations.
    static func parseRaw(_ raw: String)
        -> (reference: String, vault: String, account: String)? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.hasPrefix("op://") {
            // op://<vault>/<item>[/<section>/<field>] — keep vault + item. A
            // secret reference never names the account.
            let parts = s.dropFirst("op://".count).split(separator: "/").map(String.init)
            if parts.count >= 2 { return (parts[1], parts[0], "") }
            if parts.count == 1 { return (parts[0], "", "") }
            return nil
        }
        // Deep links carry account + vault + item coordinates. They stay
        // internal: the UI resolves them to titles before showing anything.
        if s.hasPrefix("onepassword://")
            || (s.hasPrefix("https://") && s.contains("1password.com/open")),
           let comps = URLComponents(string: s) {
            let q = comps.queryItems ?? []
            func param(_ names: Set<String>) -> String {
                q.first { names.contains($0.name) }?.value ?? ""
            }
            let item = param(["i", "item"])
            guard !item.isEmpty else { return nil }
            return (item, param(["v", "vault"]), param(["a", "account"]))
        }
        // Plain text: an item title. First line only.
        let firstLine = s.split(whereSeparator: \.isNewline).first.map(String.init) ?? s
        return (firstLine, "", "")
    }
}

/// Collects the deliveries of ONE drag into one answer.
///
/// macOS handed build 100 every 1Password drop twice — first one provider, then
/// two — and the second delivery's title-less copy of the same item turned a
/// one-item drop into the "which item?" chooser, which read to the user as
/// "nothing happened". So: no drop is applied the instant it arrives. Each
/// delivery is merged into the pending reading, and only the last one within the
/// coalescing window applies it (once) and logs it (once).
@MainActor final class OnePasswordDropCollector {
    private let coalesce: Duration
    private var pending = OnePasswordDropItem.Reading()
    private var generation = 0

    /// The window is short enough to be invisible and long enough to catch a
    /// redelivery of the same gesture, which arrives immediately.
    init(coalesce: Duration = .milliseconds(150)) {
        self.coalesce = coalesce
    }

    /// The items this drag resolved to, or nil when another delivery of the same
    /// drag superseded this one (that one applies the merged result) or when
    /// nothing usable arrived.
    func collect(_ providers: [NSItemProvider],
                 dragSnapshot: OnePasswordDropItem.Reading = .init()) async -> [OnePasswordDrop]? {
        // The SwiftUI closure captured `dragSnapshot` synchronously while the
        // drag pasteboard was alive, before this method began loading providers;
        // keep that value beside whichever asynchronous flavours arrive.
        let delivery = await OnePasswordDropItem.read(from: providers)
        // Read `pending` only after the suspension above. Main-actor methods are
        // re-entrant: another delivery can finish while this one is loading its
        // providers, and capturing the old value before `await` would overwrite
        // that delivery (usually losing the title-only flavour).
        pending = pending.merging(dragSnapshot).merging(delivery)
        generation += 1
        let mine = generation
        try? await Task.sleep(for: coalesce)
        guard mine == generation else { return nil }
        let batch = pending
        pending = OnePasswordDropItem.Reading()
        batch.log()
        return batch.isEmpty ? nil : batch.drops
    }
}
