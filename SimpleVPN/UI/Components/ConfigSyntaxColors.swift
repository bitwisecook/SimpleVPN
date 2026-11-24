// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

@MainActor
enum ConfigSyntaxColors {
    static let keyword = readable(.systemPurple)
    static let section = readable(.systemIndigo)
    static let string = readable(.systemTeal)
    static let number = readable(.systemBlue)
    static let error = readable(.systemRed)
    static let secondary = readable(.secondaryLabelColor)

    // The system accent hues alone are too faint for code-sized text on a
    // light background. Re-resolve the base hue when the appearance changes.
    private static func readable(_ color: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            let match = appearance.bestMatch(from: [.accessibilityHighContrastDarkAqua,
                                                    .accessibilityHighContrastAqua, .darkAqua, .aqua])
            let dark = match == .darkAqua || match == .accessibilityHighContrastDarkAqua
            let increasedContrast = match == .accessibilityHighContrastAqua || match == .accessibilityHighContrastDarkAqua
            let fraction = increasedContrast ? 0.55 : (dark ? 0.25 : 0.46)
            let ink: NSColor = dark ? .white : .black
            return color.blended(withFraction: fraction, of: ink) ?? ink
        }
    }
}
