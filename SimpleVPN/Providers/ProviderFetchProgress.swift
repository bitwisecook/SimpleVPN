// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderFetchProgress.swift
//  WHAT A FETCH IS DOING, IN WORDS A PERSON CAN CHECK AGAINST WHAT THEY SEE.
//
//  FOUR STAGES, AND THEY ARE THE FOUR A USER CAN ACTUALLY DISTINGUISH: contacting
//  the host, downloading, checking what arrived, comparing it with what they have.
//  The last one earns its place rather than being tidiness — a large diff STOPS for
//  confirmation, so somebody watching a bar sit at 100% while the comparison runs
//  would reasonably conclude it had hung. Naming the stage is the whole fix.
//
//  DETERMINATE ONLY WHERE IT CAN BE. A proportion is shown when the server sent a
//  `Content-Length` and never otherwise: a percentage computed against a guess is a
//  lie that looks like data, and the moment it jumps from 140% to done the user has
//  learnt not to believe the next one. Nord's list is about 9 MB and IPVanish's
//  about 2 MB (both measured), so this is a bar people will genuinely watch.
//
//  UNDER ABOUT A SECOND, NOTHING IS SHOWN. Mullvad's 300 KB usually lands faster
//  than that, and an indicator that flashes on and off is worse than no indicator —
//  it reads as a glitch rather than as work. `showsIndicator(after:)` is where that
//  lives, so the rule is one function rather than a timing decision per view.
//
//  THE CRASH THIS FILE IS SHAPED AROUND. `ProgressView` is platform-backed, and a
//  platform-backed view inside a transform-animated container caused a real
//  layout-loop crash in this app (AGENTS.md; MEMORY). So the model carries a stable
//  `Layout` height: the row reserves its space whether or not the indicator is
//  showing, so appearing and disappearing changes NOTHING about the container's
//  geometry and there is no size animation for the indicator to be inside of.
//
//  PURE AND SENDABLE. Nothing here touches the network or a view; the fetcher emits
//  these and a view renders them, which is what lets the wording be tested.
//

import Foundation

/// One report from a fetch in flight.
nonisolated struct ProviderFetchProgress: Sendable, Equatable {

    /// What the fetch is doing now.
    enum Stage: Sendable, Equatable, CaseIterable {
        /// The request is out; nothing has come back.
        case contacting
        /// Bytes are arriving.
        case downloading
        /// The payload is being parsed and every field validated.
        case checking
        /// The new list is being compared with the stored one — the stage that can
        /// end in a confirmation rather than in a result.
        case comparing
    }

    var stage: Stage
    /// Bytes received so far. Zero until something arrives.
    var received: Int64 = 0
    /// What the server SAID it would send, or nil when it said nothing.
    ///
    /// Deliberately not defaulted to the catalogue's measured size: this field means
    /// "the server told us", and `fraction` refuses to draw a proportion without it.
    var expected: Int64?

    /// The proportion done, or nil when it is not knowable.
    ///
    /// Only ever non-nil during `.downloading` and only with a real `Content-Length`.
    /// Clamped, because a server that under-declares its length must not produce a
    /// bar that runs off the end.
    var fraction: Double? {
        guard stage == .downloading, let expected, expected > 0 else { return nil }
        return min(1, max(0, Double(received) / Double(expected)))
    }

    var isDeterminate: Bool { fraction != nil }

    /// The line beside the indicator. Names the HOST during the stage where the host
    /// is what matters, because "contacting api.mullvad.net" is a sentence somebody
    /// can act on and "connecting…" is not.
    func sentence(provider: VPNServiceProvider) -> String {
        let host = provider.listURL?.host() ?? provider.displayName
        switch stage {
        case .contacting:
            return "Contacting \(host)\u{2026}"
        case .downloading:
            guard let expected, expected > 0 else {
                return received > 0
                    ? "Downloading \(provider.displayName)\u{2019}s server list \u{2014} \(Self.bytes(received)) so far\u{2026}"
                    : "Downloading \(provider.displayName)\u{2019}s server list\u{2026}"
            }
            return "Downloading \(provider.displayName)\u{2019}s server list \u{2014} "
                + "\(Self.bytes(received)) of \(Self.bytes(expected))\u{2026}"
        case .checking:
            return "Checking what \(provider.displayName) sent\u{2026}"
        case .comparing:
            return "Comparing it with the servers you already have\u{2026}"
        }
    }

    /// The same thing for VoiceOver, which needs the STAGE in words rather than a
    /// moving bar — and a spoken percentage only where there is a real one.
    ///
    /// `Docs/Accessibility.md`: a progress indicator whose only content is motion
    /// tells a listener nothing at all.
    func spoken(provider: VPNServiceProvider) -> String {
        guard let fraction else { return sentence(provider: provider) }
        return sentence(provider: provider) + " \(Int(fraction * 100)) percent."
    }

    /// How long a fetch must have been running before anything is drawn.
    ///
    /// A second, because that is roughly where a person stops assuming a click
    /// worked and starts wondering. Mullvad's list normally beats it.
    static let indicatorDelay: Duration = .seconds(1)

    /// Bytes as a person reads them. `ByteCountFormatStyle` so the units, the
    /// separators and the rounding are the system's rather than ours.
    static func bytes(_ n: Int64) -> String {
        n.formatted(.byteCount(style: .file))
    }
}

// MARK: - What a finished fetch says

/// The end of a fetch, in the words the UI shows and VoiceOver announces.
///
/// A separate type from the progress because completion is ANNOUNCED — a
/// user-initiated action ends with an immediate `AccessibilityAnnouncer.sayNow`
/// rather than through the debounced event path, and an announcement needs one
/// finished sentence rather than a stage.
nonisolated enum ProviderFetchOutcome: Sendable, Equatable {

    /// Nothing needed confirming; here is the list.
    case ready(added: Int, unchanged: Int, total: Int)
    /// Something moved, or too much vanished. Nothing has been applied.
    case needsConfirmation(moved: Int, retired: Int)
    /// The user stopped it. Nothing has been changed — said explicitly, because
    /// "did my cancel leave it half-done?" is the question a cancel must answer.
    case cancelled
    /// It did not work, and this is the sentence (which already names the fix).
    case failed(String)

    func sentence(provider: VPNServiceProvider) -> String {
        switch self {
        case .ready(let added, _, let total):
            if added == 0 {
                return "\(provider.displayName)\u{2019}s list has not changed \u{2014} still "
                    + "\(total) server\(total == 1 ? "" : "s")."
            }
            return "\(provider.displayName) published \(total) server\(total == 1 ? "" : "s"), "
                + "\(added) of them new since last time."
        case .needsConfirmation(let moved, let retired):
            var parts: [String] = []
            if moved > 0 {
                parts.append("\(moved) server\(moved == 1 ? " has" : "s have") changed address or key")
            }
            if retired > 0 {
                parts.append("\(retired) \(retired == 1 ? "is" : "are") no longer listed")
            }
            return "\(provider.displayName)\u{2019}s list needs your say-so before any of it is "
                + "used: " + parts.joined(separator: ", ") + ". Nothing has been changed yet."
        case .cancelled:
            return "Stopped. Nothing has been changed \u{2014} the servers you already had are "
                + "exactly as they were."
        case .failed(let why):
            return why
        }
    }
}
