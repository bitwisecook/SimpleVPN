// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// One power policy for decorative/live visual work. It is deliberately separate
// from the connection control plane: Low Power Mode must reduce drawing and
// sampling, never delay connecting, disconnecting, or receiving tunnel state.

import Foundation
import Observation
import SwiftUI

/// Pure cadence decisions, shared by Canvas, TimelineView, and Metal surfaces.
/// A source must opt in to this policy rather than choosing its own interpretation
/// of Low Power Mode, so the app has one predictable power story.
nonisolated enum LiveVisualCadence {
    static let lowPowerFramesPerSecond = 20
    static let globeLowPowerFramesPerSecond = 15

    static func framesPerSecond(normal: Int, lowPower: Bool) -> Int {
        lowPower ? min(normal, lowPowerFramesPerSecond) : normal
    }

    static func frameInterval(normal: Int, lowPower: Bool) -> TimeInterval {
        1 / Double(framesPerSecond(normal: normal, lowPower: lowPower))
    }

    static func globeFramesPerSecond(lowPower: Bool) -> Int {
        lowPower ? globeLowPowerFramesPerSecond : 30
    }
}

/// The app-wide, observable answer to “may a decorative/live graphic animate?”
/// `NSProcessInfoPowerStateDidChangeNotification` fires when the user changes
/// Low Power Mode, so open windows adapt immediately without a relaunch.
@Observable
final class LiveVisualPolicy {
    static let shared = LiveVisualPolicy()

    private(set) var isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled
    @ObservationIgnored private var powerObserver: NSObjectProtocol?

    private init() {
        powerObserver = NotificationCenter.default.addObserver(
            forName: Notification.Name("NSProcessInfoPowerStateDidChangeNotification"),
            object: ProcessInfo.processInfo,
            queue: .main
        ) { [weak self] _ in
            // The observer closure is Sendable in Swift 6 even though we ask
            // NotificationCenter to deliver it on the main queue. Hop explicitly
            // before changing the observable, main-actor-owned policy.
            Task { @MainActor [weak self] in
                self?.isLowPowerModeEnabled = ProcessInfo.processInfo.isLowPowerModeEnabled
            }
        }
    }

    /// High-frequency decoration is paused under either user motion preference.
    func permitsContinuousAnimation(reduceMotion: Bool) -> Bool {
        !reduceMotion && !isLowPowerModeEnabled
    }

    func frameInterval(normalFramesPerSecond: Int) -> TimeInterval {
        LiveVisualCadence.frameInterval(normal: normalFramesPerSecond,
                                        lowPower: isLowPowerModeEnabled)
    }

    var globeFramesPerSecond: Int {
        LiveVisualCadence.globeFramesPerSecond(lowPower: isLowPowerModeEnabled)
    }
}

private struct LiveVisualPolicyKey: EnvironmentKey {
    static let defaultValue = LiveVisualPolicy.shared
}

extension EnvironmentValues {
    var liveVisualPolicy: LiveVisualPolicy {
        get { self[LiveVisualPolicyKey.self] }
        set { self[LiveVisualPolicyKey.self] = newValue }
    }
}
