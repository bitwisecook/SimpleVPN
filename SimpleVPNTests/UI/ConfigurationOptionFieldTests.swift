// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct ConfigurationOptionFieldTests {
    @Test func nativeEditingPreservesCompositionAndCommitsOnBlurAndReturn() throws {
        var source = "Ciphers fixture"
        var submits = 0
        var commits = 0
        let root = ConfigurationOptionField(
            text: Binding(get: { source }, set: { source = $0 }), format: .ssh,
            prompt: "SSH directive", accessibilityLabel: "Options", onSubmit: { submits += 1 })
            .environment(\.settingCommit, SettingCommit(action: { commits += 1 }))
        let host = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: .init(x: 0, y: 0, width: 360, height: 60),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        let field = try #require(findField(in: host))
        #expect(field.isEditable && field.usesSingleLineMode && field.accessibilityLabel() == "Options")
        #expect(window.makeFirstResponder(field))
        let editor = try #require(field.currentEditor() as? NSTextView)

        editor.isAutomaticQuoteSubstitutionEnabled = true
        editor.isAutomaticDashSubstitutionEnabled = true
        editor.selectAll(nil)
        editor.insertText("Host fixture", replacementRange: editor.selectedRange())
        #expect(source == "Host fixture")
        #expect(!editor.isAutomaticQuoteSubstitutionEnabled && !editor.isAutomaticDashSubstitutionEnabled)
        let ink = editor.layoutManager?.temporaryAttribute(.foregroundColor, atCharacterIndex: 0, effectiveRange: nil) as? NSColor
        #expect(ink == ConfigSyntax.Kind.keyword.sourceColor)
        #expect(editor.selectedRange() == NSRange(location: 12, length: 0))

        editor.setMarkedText("假", selectedRange: .init(location: 1, length: 0),
                             replacementRange: .init(location: 5, length: 7))
        #expect(editor.hasMarkedText() && source == "Host fixture")
        editor.insertText("test", replacementRange: editor.markedRange())
        #expect(!editor.hasMarkedText() && source == "Host test")
        editor.doCommand(by: #selector(NSResponder.insertNewline(_:)))
        #expect(submits == 1 && commits == 1)
        if let continuing = field.currentEditor() as? NSTextView {
            let ink = continuing.layoutManager?.temporaryAttribute(.foregroundColor, atCharacterIndex: 0, effectiveRange: nil) as? NSColor
            #expect(ink == ConfigSyntax.Kind.keyword.sourceColor)
            #expect(!continuing.isAutomaticQuoteSubstitutionEnabled && !continuing.isAutomaticDashSubstitutionEnabled)
        } else {
            #expect(window.makeFirstResponder(field))
        }

        let next = try #require(field.currentEditor() as? NSTextView)
        next.selectAll(nil)
        next.insertText("Host original", replacementRange: next.selectedRange())
        source = "Host next-row"
        #expect(window.makeFirstResponder(nil))
        #expect(submits == 1)
        #expect(commits == 2)
        #expect(source == "Host next-row")
        #expect(next.isAutomaticQuoteSubstitutionEnabled && next.isAutomaticDashSubstitutionEnabled)
        let shown = field.attributedStringValue.attribute(.foregroundColor, at: 0, effectiveRange: nil) as? NSColor
        #expect(shown == ConfigSyntax.Kind.keyword.sourceColor)
    }

    private func findField(in view: NSView) -> NSTextField? {
        if let field = view as? NSTextField { return field }
        return view.subviews.compactMap { findField(in: $0) }.first
    }
}
