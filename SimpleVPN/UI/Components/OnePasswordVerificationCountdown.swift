// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// A non-secret visual countdown for a 1Password-generated verification code.
// 1Password SDK gives us only the current code, not its expiry metadata; its
// TOTP codes use the standard 30-second boundary, so this uses the same clock
// boundary without retaining or refreshing the code itself.

import SwiftUI

/// Pure timing math for the non-secret 1Password TOTP indicator. Keeping this
/// independent of the view makes the ring's position a function of wall-clock
/// time, rather than of how often SwiftUI happens to redraw it.
enum OnePasswordTOTPClock {
    static let period: TimeInterval = 30

    /// The fraction of the current code's life still available. This keeps the
    /// progress arc fluid between integer labels and resets exactly at each
    /// Unix-time TOTP boundary.
    static func remainingFraction(at date: Date) -> Double {
        let elapsed = date.timeIntervalSince1970
            .truncatingRemainder(dividingBy: period)
        let withinPeriod = elapsed >= 0 ? elapsed : elapsed + period
        return max(0, min(1, 1 - withinPeriod / period))
    }

    /// The readable whole-second value uses ceiling so a newly issued code
    /// begins at 30 and does not claim it has one second left prematurely.
    static func displaySecondsRemaining(at date: Date) -> Int {
        max(1, Int(ceil(remainingFraction(at: date) * period)))
    }
}

struct OnePasswordVerificationCountdown: View {
    @Environment(\.liveVisualPolicy) private var liveVisuals

    var body: some View {
        TimelineView(.animation(minimumInterval: liveVisuals.frameInterval(normalFramesPerSecond: 60))) { context in
            let remaining = OnePasswordTOTPClock.displaySecondsRemaining(at: context.date)
            let fraction = OnePasswordTOTPClock.remainingFraction(at: context.date)
            ZStack {
                Circle().stroke(.quaternary, lineWidth: 3)
                Circle()
                    .trim(from: 0, to: fraction)
                    .stroke(.tint, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text("\(remaining)")
                    .font(.caption2.monospacedDigit().weight(.semibold))
            }
            .frame(width: 28, height: 28)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Verification code changes in \(remaining) seconds")
        }
        .help(liveVisuals.isLowPowerModeEnabled
              ? "The verification-code ring updates at 20 frames per second in Low Power Mode."
              : "The verification-code ring updates at 60 frames per second.")
    }
}
