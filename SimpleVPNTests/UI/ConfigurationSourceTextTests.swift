// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct ConfigurationSourceTextTests {
    private func textView(in view: NSView) -> NSTextView? {
        if let editor = view as? NSTextView { return editor }
        for child in view.subviews {
            if let editor = textView(in: child) { return editor }
        }
        return nil
    }

    private func foreground(in view: NSTextView, at index: Int) -> NSColor? {
        let temporary = view.layoutManager?.temporaryAttribute(.foregroundColor, atCharacterIndex: index,
                                                              effectiveRange: nil)
        return (temporary ?? view.textStorage?.attribute(.foregroundColor, at: index, effectiveRange: nil)) as? NSColor
    }

    @Test func colouringPreservesSourceSelectionAndUndo() async throws {
        let source = "# Cafe\u{301} 🔐\r\nremote vpn.example.test 1194\r\n"
        var draft = source
        let control = ConfigurationSourceText(text: Binding(get: { draft }, set: { draft = $0 }),
                                              format: .openVPN, accessibilityLabel: "OpenVPN configuration")
        let host = NSHostingView(rootView: control)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 200),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        let editor = try #require(textView(in: host))
        #expect(window.makeFirstResponder(editor))
        let match = (source as NSString).range(of: "1194")
        editor.setSelectedRange(match)

        // Syntax is scheduled off the editing path. Wait for two distinct token
        // colours so this checks actual rendering as well as the lexical output.
        let deadline = ContinuousClock.now + .seconds(5)
        while foreground(in: editor, at: 0) == foreground(in: editor, at: match.location),
              ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(foreground(in: editor, at: 0) != foreground(in: editor, at: match.location))
        #expect(editor.string.utf8.elementsEqual(source.utf8))
        #expect(editor.selectedRange() == match)
        #expect(editor.accessibilityLabel() == "OpenVPN configuration")

        let undo = try #require(editor.undoManager)
        undo.beginUndoGrouping()
        editor.insertText("443", replacementRange: match)
        editor.breakUndoCoalescing()
        undo.endUndoGrouping()
        #expect(draft.utf8.elementsEqual(source.replacingOccurrences(of: "1194", with: "443").utf8))
        undo.undo()
        #expect(draft.utf8.elementsEqual(source.utf8))
        #expect(editor.string.utf8.elementsEqual(source.utf8))
    }

    @Test func lockedConfigurationRemainsSelectable() throws {
        let control = ConfigurationSourceText(text: .constant("client\n"), format: .openVPN,
                                              accessibilityLabel: "OpenVPN configuration")
        let host = NSHostingView(rootView: control.disabled(true))
        host.frame = NSRect(x: 0, y: 0, width: 320, height: 160)
        host.layoutSubtreeIfNeeded()
        let editor = try #require(textView(in: host))
        #expect(!editor.isEditable)
        #expect(editor.isSelectable)
        #expect(editor.string == "client\n")
    }
}
