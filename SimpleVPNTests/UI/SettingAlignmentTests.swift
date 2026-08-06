// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingAlignmentTests.swift
//  "All setting values should be right-aligned" — pinned, because it was reported
//  TWICE. The second report was "again with values not right aligned", after a fix
//  that had landed in one of the five near-identical per-editor row helpers and not
//  in the other four.
//
//  These walk the SOURCE, like `SettingRenderingTests`: what they check is a property
//  of how a row is CONSTRUCTED, and a `View`'s body cannot be enumerated without
//  building and driving the whole hierarchy. Both offences they catch are invisible
//  in a screenshot of the tab you happen to be looking at and obvious in the one you
//  are not.
//

import Testing
import Foundation

@MainActor
struct SettingAlignmentTests {

    /// The repo root, from this file's own compile-time path.
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // UI/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// The seven VPN editors plus the two forms they compose. The scope is
    /// deliberately "config surfaces", not all of UI/: a `Picker` in the network
    /// tools or the menu bar is not a setting row and has no value column to sit in.
    private static func editorSources() throws -> [String: String] {
        let root = repoRoot.appendingPathComponent("SimpleVPN/UI/Editors")
        let e = try #require(FileManager.default.enumerator(at: root,
                                                           includingPropertiesForKeys: nil))
        var out: [String: String] = [:]
        for case let url as URL in e where url.pathExtension == "swift" {
            out[url.lastPathComponent] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        }
        #expect(!out.isEmpty, "no editor sources found under \(root.path)")
        return out
    }

    /// EVERY PICKER IN A SETTING ROW GOES THROUGH `SettingPicker`.
    ///
    /// THE BUG THIS CATCHES: a bare `Picker` sizes to label-plus-popup and is not
    /// greedy, so the shared row's frame pinned that whole pair to the LEADING edge —
    /// about thirty rows whose value sat on the left while every text row's sat on the
    /// right. `SettingPicker` wraps it in `LabeledContent` with `.labelsHidden()`,
    /// which is what moves the popup into the value column.
    ///
    /// A row picker is identified by its LABEL: if the label renders
    /// `EngineSettingLabel` or `SettingLabel` it is a setting's value control, and it
    /// must be a `SettingPicker`. Anything else (a rule's verb in a Custom Routing
    /// table row, a composition member's role) is not a setting row and is left alone.
    @Test func everySettingRowsPickerIsRightAligned() throws {
        var offenders: [String] = []
        for (name, text) in try Self.editorSources() {
            for range in text.ranges(of: "Picker(") {
                // `SettingPicker(` also ends in "Picker(" — skip the compliant ones.
                let precededBySetting = text[..<range.lowerBound].hasSuffix("Setting")
                if precededBySetting { continue }
                let tail = text[range.lowerBound...]
                // The label closure is within a few lines of the call for every row in
                // this codebase; a window is enough and cannot be fooled by a later,
                // unrelated row's label.
                let window = String(tail.prefix(1200))
                let end = window.range(of: "\n            }")?.lowerBound ?? window.endIndex
                let expr = String(window[..<end])
                if expr.contains("EngineSettingLabel(") || expr.contains("SettingLabel(") {
                    let line = (text[..<range.lowerBound].components(separatedBy: "\n").count)
                    offenders.append("\(name):\(line)")
                }
            }
        }
        #expect(offenders.isEmpty, """
            these setting rows use a bare Picker, so their value is pinned to the \
            LEADING edge while every text row's value is trailing — use SettingPicker: \
            \(offenders.sorted().joined(separator: ", "))
            """)
    }

    /// NO EXAMPLE IS PASSED AS A FIELD TITLE INSIDE `LabeledContent`.
    ///
    /// THE BUG THIS CATCHES: a `TextField`'s first argument is its TITLE, and inside
    /// `LabeledContent` SwiftUI DRAWS that title next to the value — so an example
    /// rendered as though it were the value ("Name on the Network  Jim-s-MacBook-Pro
    /// Jim-s-MacBook-Pro"), and VoiceOver announced the example as the field's NAME.
    /// Twenty-six sites were fixed for exactly this once already; the shared
    /// `SettingValueField` now makes it structurally impossible, and this stops the
    /// next hand-rolled row from reintroducing it.
    ///
    /// The check is per-LINE and looks only at fields inside a `LabeledContent`
    /// content closure, which is where the double-render happens. A bare
    /// `TextField("Name", text:)` as a direct Form row is correct usage — the title IS
    /// the label there — and is not flagged.
    /// Fields whose title is still an example, listed rather than fixed.
    ///
    /// THE LIST IS THE POINT — the same device as
    /// `SettingRenderingTests.unrenderedByDesign`: being on it is a deliberate act
    /// visible in a diff, not a silent exemption. Both entries are PKCS#11 rows in
    /// `SubprocessTunnelView` (the module path and the certificate URI), which another
    /// change in flight is DELETING outright. Fixing a title in code that is about to
    /// be removed would have collided with that change for no benefit; when smartcard
    /// support goes, these two lines go with it and this list is empty again.
    static let titledFieldsAwaitingDeletion: Set<String> = [
        "SubprocessTunnelView.swift:1015",
        "SubprocessTunnelView.swift:1132",
    ]

    @Test func noFieldInsideLabeledContentPassesATitle() throws {
        var offenders: [String] = []
        for (name, text) in try Self.editorSources() {
            let lines = text.components(separatedBy: "\n")
            var labeledContentDepth = 0
            for (i, line) in lines.enumerated() {
                if line.contains("LabeledContent {") { labeledContentDepth = 1 }
                // The content closure is short in every case here; three lines past
                // the opening covers it and `} label: {` closes it explicitly.
                if labeledContentDepth > 0, line.contains("} label: {") { labeledContentDepth = 0 }
                guard labeledContentDepth > 0 else { continue }
                for kind in ["TextField(\"", "SecureField(\""] where line.contains(kind) {
                    guard let start = line.range(of: kind) else { continue }
                    let rest = line[start.upperBound...]
                    guard let quote = rest.firstIndex(of: "\"") else { continue }
                    let title = String(rest[..<quote])
                    guard !title.isEmpty else { continue }
                    let site = "\(name):\(i + 1)"
                    if Self.titledFieldsAwaitingDeletion.contains(site) { continue }
                    offenders.append("\(site): \(kind)\(title)\"")
                }
            }
        }
        #expect(offenders.isEmpty, """
            a field inside LabeledContent passes a non-empty title, which SwiftUI draws \
            beside the value AND makes the field's VoiceOver name — move it to prompt:: \
            \(offenders.sorted().joined(separator: " | "))
            """)
    }

    /// THERE IS ONE ROW LAYOUT, not five.
    ///
    /// `EngineSettingRow` and the OpenVPN form's `SettingRow` are the two row types
    /// that can never merge (they differ in where "changed" and availability come
    /// from) — but the LAYOUT must not be written out in either of them, because
    /// having it twice is how the two drifted. Both delegate to `SettingRowLayout`,
    /// and that is the only place the summary, the "?", the padding and the reveal
    /// identity are assembled.
    @Test func bothRowTypesDelegateToTheOneLayout() throws {
        let engine = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/ControlPlane/EngineSettings.swift"), encoding: .utf8)
        let openVPN = try String(contentsOf: Self.repoRoot
            .appendingPathComponent("SimpleVPN/UI/Editors/OpenVPNOptionsForm.swift"), encoding: .utf8)
        for (name, text) in [("EngineSettingRow", engine), ("SettingRow", openVPN)] {
            #expect(text.contains("SettingRowLayout("),
                    "\(name) no longer delegates to the shared row layout")
            // The tells of a re-inlined layout: its own ManualLink, its own summary
            // Text, its own reveal identity.
            #expect(!text.contains("ManualLink(setting:"),
                    "\(name) renders its own \"?\" instead of letting SettingRowLayout do it")
            #expect(!text.contains(".settingReveal("),
                    "\(name) declares its own reveal identity instead of using SettingRowLayout's")
        }
    }

    /// THE FIVE PER-EDITOR TEXT-ROW HELPERS ARE ONE. Each editor may keep a private
    /// forwarder for readability, but none may build the row itself again — that is
    /// what let "values aren't right-aligned" be true in four editors and false in the
    /// fifth at the same time.
    @Test func everyEditorsTextRowForwardsToTheSharedField() throws {
        var offenders: [String] = []
        for (name, text) in try Self.editorSources() {
            let lines = text.components(separatedBy: "\n")
            for (i, line) in lines.enumerated() {
                // A private helper whose name says "field" and whose body is not the
                // shared one.
                guard line.contains("private func"),
                      line.contains("_ spec: EngineSettingSpec"),
                      line.lowercased().contains("field") else { continue }
                let body = lines[i..<min(i + 12, lines.count)].joined(separator: "\n")
                if !body.contains("SettingValueField(") {
                    offenders.append("\(name):\(i + 1)")
                }
            }
        }
        #expect(offenders.isEmpty, """
            these editors build their own text row instead of forwarding to \
            SettingValueField, which is how right-alignment drifted between editors: \
            \(offenders.sorted().joined(separator: ", "))
            """)
    }
}
