// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordBrowseTests.swift
//  The logic behind the 1Password pickers, all of which came out of live
//  testing going wrong:
//    • the search that makes a browse list usable (people type "grlab" for
//      "GR Lab VPN", and the closest match has to be the row Return picks);
//    • the remembered account name, whose absence made every new VPN fail with
//      "Account not found" until it was typed again by hand — so the precedence
//      (this VPN's own name, then the remembered one, then nothing) is pinned;
//    • back-filling the vault from a successful read, which only knows the
//      vault's id and has to turn it into the name shown in 1Password;
//    • what a drag REALLY carries. An item-row drag hands over only the title
//      as text — the coordinates ride in Chromium's web-custom-data flavour,
//      because 1Password 8 is an Electron app. That binary blob comes from
//      another program and is parsed defensively: truncated, padded oddly or
//      simply foreign, it must yield nothing rather than crash.
//

import Foundation
import Testing
@testable import SimpleVPN

struct OnePasswordBrowseTests {

    // MARK: - Search

    @Test func exactAndPrefixOutrankContains() throws {
        #expect(FuzzyMatch.score("vpn", "vpn") == 0)
        #expect(try #require(FuzzyMatch.score("gr", "GR Lab VPN"))
                < #require(FuzzyMatch.score("lab", "GR Lab VPN")))
    }

    @Test func matchingIgnoresCaseAndAccents() {
        #expect(FuzzyMatch.matches("gr lab", in: "GR Lab VPN"))
        #expect(FuzzyMatch.matches("RESUME", in: "R\u{00E9}sum\u{00E9} server"))
        #expect(FuzzyMatch.matches("  vpn  ", in: "GR Lab VPN"))
    }

    /// Letters have to appear IN ORDER — otherwise "npv" would find every VPN
    /// in the account and the list would stop meaning anything.
    @Test func lettersMustAppearInOrder() {
        #expect(FuzzyMatch.matches("grvpn", in: "GR Lab VPN"))
        #expect(!FuzzyMatch.matches("npvrg", in: "GR Lab VPN"))
    }

    @Test func nothingMatchesWhatIsntThere() {
        #expect(FuzzyMatch.score("router", "GR Lab VPN") == nil)
        #expect(!FuzzyMatch.matches("zzz", in: "GR Lab VPN"))
    }

    /// An empty search shows everything, in the order it was given.
    @Test func emptyQueryKeepsEveryRowAndItsOrder() {
        let rows = ["b", "a", "c"]
        #expect(FuzzyMatch.rank(rows, query: "  ") { [$0] } == rows)
    }

    @Test func rankPutsTheClosestMatchFirst() {
        let rows = ["Work VPN backup", "VPN", "VPN — office", "Router"]
        let ranked = FuzzyMatch.rank(rows, query: "vpn") { [$0] }
        #expect(ranked.first == "VPN")
        #expect(ranked.count == 3)                 // Router doesn't match at all
        #expect(!ranked.contains("Router"))
    }

    /// A hit on the row's NAME always beats a hit on its secondary line, so
    /// searching for a vault's name can't bury the item actually called that.
    @Test func titleMatchesOutrankSubtitleMatches() {
        struct Row { var title: String; var vault: String }
        let rows = [Row(title: "Router", vault: "Work"), Row(title: "Work VPN", vault: "Private")]
        let ranked = FuzzyMatch.rank(rows, query: "work") { [$0.title, $0.vault] }
        #expect(ranked.first?.title == "Work VPN")
        #expect(ranked.count == 2)
    }

    // MARK: - Remembered account

    private func scratchDefaults(_ name: String = #function) -> UserDefaults {
        let suite = "OnePasswordBrowseTests.\(name)"
        UserDefaults.standard.removePersistentDomain(forName: suite)
        return UserDefaults(suiteName: suite)!
    }

    /// The precedence, in one place: what this VPN says wins; a blank falls back
    /// to the remembered name; with neither there is nothing to send.
    @Test func profileAccountBeatsTheRememberedDefault() {
        #expect(OnePasswordAccountMemory.effective(profile: "Work", remembered: "Personal") == "Work")
        #expect(OnePasswordAccountMemory.effective(profile: "   ", remembered: "Personal") == "Personal")
        #expect(OnePasswordAccountMemory.effective(profile: "", remembered: "") == "")
        #expect(OnePasswordAccountMemory.effective(profile: " Work ", remembered: "") == "Work")
    }

    @Test func aNameThatWorkedIsRemembered() {
        let store = scratchDefaults()
        #expect(OnePasswordAccountMemory.remembered(in: store) == "")
        OnePasswordAccountMemory.remember(" Personal ", in: store)
        #expect(OnePasswordAccountMemory.remembered(in: store) == "Personal")
        #expect(OnePasswordAccountMemory.effectiveAccount(profile: "", in: store) == "Personal")
        // A later success with a different name replaces it — the last account
        // known to work is the best guess for the next VPN.
        OnePasswordAccountMemory.remember("Work", in: store)
        #expect(OnePasswordAccountMemory.remembered(in: store) == "Work")
    }

    /// Nothing to learn from a blank, or from the name already stored.
    @Test func blankAndUnchangedNamesAreNotWorthStoring() {
        #expect(!OnePasswordAccountMemory.shouldRemember("   ", current: "Work"))
        #expect(!OnePasswordAccountMemory.shouldRemember("Work", current: "Work"))
        #expect(OnePasswordAccountMemory.shouldRemember("Work", current: ""))

        let store = scratchDefaults()
        OnePasswordAccountMemory.remember("Work", in: store)
        OnePasswordAccountMemory.remember("  ", in: store)
        #expect(OnePasswordAccountMemory.remembered(in: store) == "Work")
    }

    /// After "1Password doesn't know that account", the remembered name is worth
    /// one silent retry — unless it's the very name that just failed, or there
    /// is no remembered name at all. Then the user has to be asked.
    @Test func retryOnlyHappensWhenThereIsSomethingNewToTry() {
        #expect(OnePasswordAccountMemory.retry(after: "", remembered: "Personal") == "Personal")
        #expect(OnePasswordAccountMemory.retry(after: "Typo", remembered: "Personal") == "Personal")
        #expect(OnePasswordAccountMemory.retry(after: "personal", remembered: "Personal") == nil)
        #expect(OnePasswordAccountMemory.retry(after: "Personal ", remembered: "Personal") == nil)
        #expect(OnePasswordAccountMemory.retry(after: "Anything", remembered: "  ") == nil)
    }

    // MARK: - Back-filling the vault after a successful read

    @Test func vaultIDBecomesTheNameShownInOnePassword() {
        let vaults = [
            OnePasswordNative.OPVaultOverview(id: "k3owyg7dnj4yhnvhmh2gkjq4ie", title: "Private"),
            OnePasswordNative.OPVaultOverview(id: "v2", title: "Shared"),
        ]
        #expect(OnePasswordNative.vaultTitle(forID: "k3owyg7dnj4yhnvhmh2gkjq4ie", in: vaults) == "Private")
        // Callers hold whichever of id/title 1Password gave them.
        #expect(OnePasswordNative.vaultTitle(forID: "shared", in: vaults) == "Shared")
        #expect(OnePasswordNative.vaultTitle(forID: "unknown", in: vaults) == nil)
        #expect(OnePasswordNative.vaultTitle(forID: "  ", in: vaults) == nil)
        #expect(OnePasswordNative.vaultTitle(forID: "v2", in: []) == nil)
    }

    // MARK: - Chromium web-custom-data

    /// Rebuilds the exact container 1Password drags: little-endian uint32
    /// payload size, uint32 entry count, then per entry two strings, each a
    /// uint32 count of UTF-16 code units, the UTF-16LE bytes, and padding up to
    /// a 4-byte boundary.
    private func webCustomData(_ pairs: [(String, String)], padded: Bool = true) -> Data {
        func append(_ value: UInt32, to data: inout Data) {
            withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
        }
        var payload = Data()
        append(UInt32(pairs.count), to: &payload)
        for pair in pairs {
            for string in [pair.0, pair.1] {
                let units = Array(string.utf16)
                append(UInt32(units.count), to: &payload)
                for unit in units {
                    withUnsafeBytes(of: unit.littleEndian) { payload.append(contentsOf: $0) }
                }
                // The payload starts 4 bytes in, so its own length is congruent
                // to the absolute offset modulo 4.
                if padded { while payload.count % 4 != 0 { payload.append(0) } }
            }
        }
        var out = Data()
        append(UInt32(payload.count), to: &out)
        out.append(payload)
        return out
    }

    private func dragJSON(_ items: [(account: String, vault: String, item: String)]) -> String {
        let entries = items.map {
            """
            {"type":"item","itemUuidComponents":{"accountUuid":"\($0.account)",\
            "vaultUuid":"\($0.vault)","itemUuid":"\($0.item)"},"canMove":true,"canEdit":true}
            """
        }
        return "[\(entries.joined(separator: ","))]"
    }

    /// The real thing, byte for byte: one entry, 21 UTF-16 units of type name,
    /// 194 of JSON — which is where the observed 448-byte blob comes from.
    @Test func oneDraggedItemDecodesToItsCoordinates() throws {
        let json = dragJSON([("4V26ZNTCZZDNBEE3IYEEG6Y5AA",
                              "k3owyg7dnj4yhnvhmh2gkjq4ie",
                              "esfn3iokhykkgoab4xk2pqtopq")])
        let blob = webCustomData([("application/1password", json)])
        let entries = ChromiumWebCustomData.entries(from: blob)
        #expect(entries.count == 1)
        #expect(entries.first?.type == "application/1password")

        let coordinates = OnePasswordDragPayload.coordinates(in: entries)
        #expect(coordinates.count == 1)
        #expect(coordinates.first?.itemUUID == "esfn3iokhykkgoab4xk2pqtopq")
        #expect(coordinates.first?.vaultUUID == "k3owyg7dnj4yhnvhmh2gkjq4ie")
        #expect(coordinates.first?.accountUUID == "4V26ZNTCZZDNBEE3IYEEG6Y5AA")
    }

    /// A multi-selection drag carries one entry per item, in selection order,
    /// each with its own home vault.
    @Test func fourDraggedItemsKeepTheirOrderAndTheirVaults() {
        let json = dragJSON([
            ("acct", "vaultone", "itemone"),
            ("acct", "vaulttwo", "itemtwo"),
            ("acct", "vaultone", "itemthree"),
            ("acct", "vaultthree", "itemfour"),
        ])
        let coordinates = OnePasswordDragPayload.parse(json: json)
        #expect(coordinates.map(\.itemUUID) == ["itemone", "itemtwo", "itemthree", "itemfour"])
        #expect(coordinates.map(\.vaultUUID) == ["vaultone", "vaulttwo", "vaultone", "vaultthree"])
        #expect(Set(coordinates.map(\.accountUUID)) == ["acct"])
    }

    /// Other apps put their own things on the pasteboard under this flavour, and
    /// a drag that isn't an ITEM (a field, a folder) has no coordinates to give.
    @Test func nonItemPayloadsAreIgnored() {
        #expect(OnePasswordDragPayload.parse(json: "[]").isEmpty)
        #expect(OnePasswordDragPayload.parse(json: "not json").isEmpty)
        #expect(OnePasswordDragPayload.parse(json:
            #"[{"type":"field","itemUuidComponents":{"itemUuid":"x"}}]"#).isEmpty)
        #expect(OnePasswordDragPayload.parse(json:
            #"[{"type":"item","itemUuidComponents":{"itemUuid":""}}]"#).isEmpty)
        // An unrelated custom-data entry isn't ours.
        let foreign = webCustomData([("text/html", "<b>hi</b>")])
        #expect(OnePasswordDragPayload.coordinates(
            in: ChromiumWebCustomData.entries(from: foreign)).isEmpty)
    }

    /// A vault UUID may be absent (a shared link, a future change) without
    /// sinking the item UUID, which is the part that matters.
    @Test func missingVaultDoesNotSinkTheItem() {
        let coordinates = OnePasswordDragPayload.parse(json:
            #"[{"type":"item","itemUuidComponents":{"itemUuid":"itemone"}}]"#)
        #expect(coordinates.count == 1)
        #expect(coordinates.first?.vaultUUID.isEmpty == true)
        #expect(coordinates.first?.accountUUID.isEmpty == true)
    }

    /// Whatever a foreign app put there, this parser is fed it — so nothing may
    /// crash, over-allocate, or invent entries.
    @Test func malformedBlobsYieldNothing() {
        #expect(ChromiumWebCustomData.entries(from: Data()).isEmpty)
        #expect(ChromiumWebCustomData.entries(from: Data([1, 2, 3])).isEmpty)
        let good = webCustomData([("application/1password", dragJSON([("a", "v", "i")]))])
        #expect(ChromiumWebCustomData.entries(from: good.prefix(good.count / 2)).isEmpty)
        #expect(ChromiumWebCustomData.entries(from: good.prefix(12)).isEmpty)
        // A huge declared string length must be refused, not allocated.
        var absurd = Data([0, 0, 0, 0, 1, 0, 0, 0])
        absurd.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])
        #expect(ChromiumWebCustomData.entries(from: absurd).isEmpty)
        #expect(ChromiumWebCustomData.entries(from: Data(repeating: 0x41, count: 64)).isEmpty)
    }

    /// The padding is another program's private detail, so an unpadded variant
    /// still has to be readable.
    @Test func unpaddedVariantStillDecodes() {
        // "abc" is 3 units = 6 bytes, so padding does change the layout here.
        let blob = webCustomData([("abc", "de")], padded: false)
        let entries = ChromiumWebCustomData.entries(from: blob)
        #expect(entries.count == 1)
        #expect(entries.first?.type == "abc")
        #expect(entries.first?.value == "de")
    }

    // MARK: - Titles from the plain-text flavour

    @Test func titlesLineUpWithTheDraggedItems() {
        #expect(OnePasswordDragPayload.titles(fromPlainText: "Grlab", count: 1) == ["Grlab"])
        #expect(OnePasswordDragPayload.titles(fromPlainText: "One\nTwo\nThree", count: 3)
                == ["One", "Two", "Three"])
    }

    /// When the count doesn't line up, the titles are dropped entirely: a
    /// chooser labelling the wrong item is worse than one labelling none.
    @Test func mismatchedTitleCountIsDiscarded() {
        #expect(OnePasswordDragPayload.titles(fromPlainText: "One\nTwo", count: 4).isEmpty)
        #expect(OnePasswordDragPayload.titles(fromPlainText: nil, count: 1).isEmpty)
        #expect(OnePasswordDragPayload.titles(fromPlainText: "One", count: 0).isEmpty)
    }

    // MARK: - Which flavour wins

    /// The 1Password payload is the only flavour naming the account, so it beats
    /// everything — including a link that names one, and the op:// text.
    @Test func onePasswordPayloadOutranksTheOtherFlavours() throws {
        let blob = webCustomData([("application/1password",
                                   dragJSON([("ACCT", "VAULT", "ITEM")]))])
        let drops = OnePasswordDropItem.drops(
            webCustomData: blob,
            plainText: "op://Private/GR Lab VPN/password",
            urlText: "onepassword://open/i?a=OTHER&v=OTHERVAULT&i=OTHERITEM")
        let drop = try #require(drops.first)
        #expect(drops.count == 1)
        #expect(drop.reference == "ITEM")
        #expect(drop.vault == "VAULT")
        #expect(drop.account == "ACCT")
    }

    /// Without the payload the old order still holds: a link that names an
    /// account, then op://, then the bare title.
    @Test func linkThenReferenceThenTitle() throws {
        let link = try #require(OnePasswordDropItem.drops(
            webCustomData: nil,
            plainText: "op://Private/GR Lab VPN/password",
            urlText: "https://start.1password.com/open/i?a=ACCT&v=VAULT&i=ITEM").first)
        #expect(link.account == "ACCT")

        let reference = try #require(OnePasswordDropItem.drops(
            webCustomData: nil, plainText: "op://Private/GR Lab VPN/password", urlText: nil).first)
        #expect(reference.reference == "GR Lab VPN")
        #expect(reference.vault == "Private")

        let title = try #require(OnePasswordDropItem.drops(
            webCustomData: nil, plainText: "Grlab", urlText: nil).first)
        #expect(title.reference == "Grlab")
        #expect(title.title == "Grlab")     // a bare title IS something to show
    }

    /// An unreadable payload must fall through to the flavours that still work,
    /// not swallow the drop.
    @Test func unreadablePayloadFallsBackToText() throws {
        let drop = try #require(OnePasswordDropItem.drops(
            webCustomData: Data([9, 9, 9]), plainText: "Grlab", urlText: nil).first)
        #expect(drop.reference == "Grlab")
        #expect(OnePasswordDropItem.drops(webCustomData: nil, plainText: nil, urlText: nil).isEmpty)
    }

    /// A multi-item drop is offered as a choice, with the titles attached in
    /// order — and with a plain position when they can't be trusted.
    @Test func multipleDroppedItemsBecomeAChoice() {
        let json = dragJSON([("acct", "v1", "itemone"), ("acct", "v2", "itemtwo")])
        let blob = webCustomData([("application/1password", json)])

        let named = OnePasswordDropItem.drops(
            webCustomData: blob, plainText: "GR Lab VPN\nRouter", urlText: nil)
        #expect(named.count == 2)
        #expect(named.map(\.title) == ["GR Lab VPN", "Router"])
        #expect(named[1].displayName(position: 2) == "Router")

        let unnamed = OnePasswordDropItem.drops(
            webCustomData: blob, plainText: "only one line", urlText: nil)
        #expect(unnamed.map(\.title) == ["", ""])
        #expect(unnamed[1].displayName(position: 2) == "Item 2")
    }

    // MARK: - The real drop path

    private func provider(_ payloads: [(identifier: String, data: Data)]) -> NSItemProvider {
        let provider = NSItemProvider()
        for payload in payloads {
            provider.registerDataRepresentation(
                forTypeIdentifier: payload.identifier, visibility: .all
            ) { completion in
                completion(payload.data, nil)
                return nil
            }
        }
        return provider
    }

    /// End to end over what AppKit actually hands a drop well: the title-only
    /// text flavour beside the payload that names everything.
    @Test func aDroppedItemProviderYieldsFullCoordinates() async throws {
        let blob = webCustomData([("application/1password",
                                   dragJSON([("ACCT", "VAULT", "ITEM")]))])
        let drops = await OnePasswordDropItem.load(from: [provider([
            (ChromiumWebCustomData.typeIdentifier, blob),
            ("public.utf8-plain-text", Data("Grlab".utf8)),
        ])])
        let drop = try #require(drops.first)
        #expect(drops.count == 1)
        #expect(drop.reference == "ITEM")
        #expect(drop.vault == "VAULT")
        #expect(drop.account == "ACCT")
        #expect(drop.title == "Grlab")
    }

    /// If a multi-selection ever arrives as one provider per item, all of them
    /// have to survive — silently keeping the first would choose a VPN's
    /// sign-in on the user's behalf.
    @Test func oneProviderPerDraggedItemKeepsThemAll() async {
        func one(_ item: String, title: String) -> NSItemProvider {
            provider([
                (ChromiumWebCustomData.typeIdentifier,
                 webCustomData([("application/1password", dragJSON([("ACCT", "VAULT", item)]))])),
                ("public.utf8-plain-text", Data(title.utf8)),
            ])
        }
        let drops = await OnePasswordDropItem.load(
            from: [one("itemone", title: "GR Lab VPN"), one("itemtwo", title: "Router")])
        #expect(drops.map(\.reference) == ["itemone", "itemtwo"])
        #expect(drops.map(\.title) == ["GR Lab VPN", "Router"])
    }

    /// A dragged FILE is not a 1Password item: accepting it would put
    /// "file:///Users/…" in the item field and look like the drop worked.
    @Test func filesAreRefusedButTextIsAccepted() {
        let file = provider([("public.file-url", Data("file:///Users/jim/secrets.txt".utf8))])
        #expect(!OnePasswordDropItem.canAccept([file]))
        #expect(!OnePasswordDropItem.canAccept([]))
        let text = provider([("public.utf8-plain-text", Data("Grlab".utf8))])
        #expect(OnePasswordDropItem.canAccept([text]))
    }

    /// UUIDs are exact but unreadable, so the UI needs to know when it is
    /// holding one rather than something a person would recognise.
    @Test func onePasswordIDsAreRecognisedAsUnreadable() {
        #expect(OnePasswordDrop.looksLikeItemID("esfn3iokhykkgoab4xk2pqtopq"))
        #expect(OnePasswordDrop.looksLikeItemID("4V26ZNTCZZDNBEE3IYEEG6Y5AA"))
        #expect(!OnePasswordDrop.looksLikeItemID("GR Lab VPN"))
        #expect(!OnePasswordDrop.looksLikeItemID(""))
    }

    // MARK: - One drag, delivered more than once

    /// The build-100 bug, in one line: macOS delivered each drop twice and the
    /// second copy of the same item had no title, so two "different" items went
    /// to the chooser and the drop looked like it had done nothing.
    @Test func theSameItemDeliveredTwiceIsOneItem() throws {
        let titled = OnePasswordDrop(reference: "ITEM", vault: "VAULT", account: "ACCT",
                                     title: "GR Lab VPN")
        let bare = OnePasswordDrop(reference: "ITEM", vault: "VAULT", account: "ACCT")
        let merged = OnePasswordDropItem.deduped([bare, titled])
        #expect(merged.count == 1)
        // …and the title survives whichever copy carried it.
        #expect(try #require(merged.first).title == "GR Lab VPN")
    }

    /// Genuinely different items still both survive — the chooser exists for
    /// exactly this, and collapsing it would pick a VPN's sign-in for the user.
    @Test func distinctItemsAreNotCollapsed() {
        let merged = OnePasswordDropItem.deduped([
            OnePasswordDrop(reference: "one", vault: "VAULT", account: "ACCT", title: "GR Lab VPN"),
            OnePasswordDrop(reference: "two", vault: "VAULT", account: "ACCT", title: "Router"),
        ])
        #expect(merged.map(\.reference) == ["one", "two"])
    }

    /// Across deliveries, the payload reading still beats a text-only one: the
    /// same drag read two ways is one item, described best by the flavour that
    /// names the account.
    @Test func mergingDeliveriesKeepsThePayloadReading() throws {
        let payload = OnePasswordDropItem.Reading(
            drops: [OnePasswordDrop(reference: "ITEM", vault: "VAULT", account: "ACCT")],
            fromPayload: true, providers: 1, sawWebCustomData: true)
        let textOnly = OnePasswordDropItem.Reading(
            drops: [OnePasswordDrop(reference: "GR Lab VPN", title: "GR Lab VPN")],
            fromPayload: false, providers: 1, sawString: true)

        for merged in [payload.merging(textOnly), textOnly.merging(payload)] {
            #expect(merged.drops.count == 1)
            #expect(try #require(merged.drops.first).account == "ACCT")
            #expect(merged.fromPayload)
            // The log line still describes the whole drop, not half of it.
            #expect(merged.providers == 2)
            #expect(merged.sawWebCustomData)
            #expect(merged.sawString)
        }
    }

    /// End to end: two deliveries of one drag, arriving together the way they
    /// really do, produce ONE apply carrying ONE item.
    @MainActor @Test func twoDeliveriesOfOneDragApplyOnce() async throws {
        let blob = webCustomData([("application/1password",
                                   dragJSON([("ACCT", "VAULT", "ITEM")]))])
        func delivery(withTitle: Bool) -> [NSItemProvider] {
            var payloads: [(identifier: String, data: Data)] = [
                (ChromiumWebCustomData.typeIdentifier, blob),
            ]
            if withTitle { payloads.append(("public.utf8-plain-text", Data("Grlab".utf8))) }
            return [provider(payloads)]
        }
        let collector = OnePasswordDropCollector(coalesce: .milliseconds(60))
        let withTitle = delivery(withTitle: true)
        let withoutTitle = delivery(withTitle: false)
        // Both deliveries in flight at once — the shape the real bug had.
        let first = Task { @MainActor in await collector.collect(withTitle) }
        let second = Task { @MainActor in await collector.collect(withoutTitle) }
        let applied = await [first.value, second.value].compactMap { $0 }

        #expect(applied.count == 1, "one drag must apply once")
        let items = try #require(applied.first)
        #expect(items.count == 1, "one item must not become a chooser")
        #expect(items[0].reference == "ITEM")
        #expect(items[0].account == "ACCT")
        #expect(items[0].title == "Grlab")
    }

    // MARK: - Seeding the account from a drag

    /// A dragged item names its account, which is the only account a first-time
    /// user can have without typing one — so it fills the blank that otherwise
    /// makes Browse fail before it can succeed.
    @Test func aDraggedItemAnswersWhichAccount() {
        let store = scratchDefaults()
        #expect(OnePasswordAccountMemory.seed("4V26ZNTCZZDNBEE3IYEEG6Y5AA", in: store))
        #expect(OnePasswordAccountMemory.remembered(in: store) == "4V26ZNTCZZDNBEE3IYEEG6Y5AA")
        // A name that has actually worked is more use than a UUID: never replaced.
        OnePasswordAccountMemory.remember("Secure Vault", in: store)
        #expect(!OnePasswordAccountMemory.seed("SOMEOTHERACCOUNTUUID000000", in: store))
        #expect(OnePasswordAccountMemory.remembered(in: store) == "Secure Vault")
        // Nothing to learn from an empty one.
        #expect(!OnePasswordAccountMemory.seed("  ", in: scratchDefaults("empty")))
    }
}
