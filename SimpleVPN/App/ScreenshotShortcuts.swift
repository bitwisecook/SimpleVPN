// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ScreenshotShortcuts.swift
//  Tells the user THEIR screenshot keys, not Apple's defaults — people remap these,
//  and "press ⇧⌘4" is useless (or wrong) if they haven't. macOS keeps them in the
//  com.apple.symbolichotkeys domain, keyed by a stable action id, with the binding
//  as [character, virtual key code, modifier mask].
//
//  Falls back to the Apple defaults (clearly labelled as such) if the domain can't
//  be read or the entry is missing, and reports when a shortcut is switched OFF —
//  in which case telling someone to press it would just be wrong.
//

import Foundation
import AppKit

nonisolated enum ScreenshotShortcuts {

    struct Shortcut {
        /// e.g. "⇧⌘4" — already in the conventional ⌃⌥⇧⌘ order.
        var display: String
        var enabled: Bool
        /// True when we couldn't read the real binding and are quoting Apple's default.
        var isFallback: Bool

        /// Instruction-ready: "⇧⌘4", or an honest note when it's off/unknown.
        var phrase: String {
            if !enabled { return "\(display) (currently turned off in System Settings)" }
            return isFallback ? "\(display) (macOS default)" : display
        }
    }

    /// "Copy/Save picture of selected area" — the everyday screenshot.
    static var selectedArea: Shortcut { read(id: 30, fallback: "⇧⌘4") }
    /// "Screenshot and recording options" — the panel that also records video.
    static var screenshotPanel: Shortcut { read(id: 184, fallback: "⇧⌘5") }

    /// Apple's Screenshot app (the ⇧⌘5 panel). Launching it means the recording
    /// permission belongs to Apple's app — SimpleVPN never asks for, or holds,
    /// Screen Recording access just to help someone file a bug.
    static let screenshotAppBundleID = "com.apple.screenshot.launcher"

    static var screenshotAppAvailable: Bool {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: screenshotAppBundleID) != nil
    }

    @MainActor
    static func openScreenshotApp() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: screenshotAppBundleID) else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }

    // MARK: Reading the user's bindings

    private static func read(id: Int, fallback: String) -> Shortcut {
        guard let defaults = UserDefaults(suiteName: "com.apple.symbolichotkeys"),
              let all = defaults.dictionary(forKey: "AppleSymbolicHotKeys"),
              let entry = all["\(id)"] as? [String: Any] else {
            return Shortcut(display: fallback, enabled: true, isFallback: true)
        }
        let enabled = (entry["enabled"] as? Bool) ?? true
        guard let value = entry["value"] as? [String: Any],
              let params = value["parameters"] as? [Any], params.count >= 3,
              let character = (params[0] as? NSNumber)?.intValue,
              let modifiers = (params[2] as? NSNumber)?.intValue,
              let display = format(character: character, modifiers: modifiers) else {
            return Shortcut(display: fallback, enabled: enabled, isFallback: true)
        }
        return Shortcut(display: display, enabled: enabled, isFallback: false)
    }

    /// NSEvent modifier bits, rendered in the order the HIG uses: ⌃⌥⇧⌘.
    private static func format(character: Int, modifiers: Int) -> String? {
        var out = ""
        if modifiers & (1 << 18) != 0 { out += "⌃" }
        if modifiers & (1 << 19) != 0 { out += "⌥" }
        if modifiers & (1 << 17) != 0 { out += "⇧" }
        if modifiers & (1 << 20) != 0 { out += "⌘" }
        // 65535 means "no character" (a function/special key) — we can't name those
        // reliably, so let the caller fall back rather than print something wrong.
        guard character != 65535, (32..<127).contains(character),
              let scalar = UnicodeScalar(UInt32(character)) else { return nil }
        out += String(Character(scalar)).uppercased()
        return out.isEmpty ? nil : out
    }
}
