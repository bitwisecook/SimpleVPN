// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AccessibilityAnnouncer.swift
//  State changes are ANNOUNCED, not discovered: a blind user must hear a
//  connect succeed (or fail, or stop to wait on a code) without touching
//  anything. This subscribes to the control plane's one event stream — the
//  SAME `statusChanged`/`gatewayChanged` broadcasts the CLI's `watch` and App Intents consume,
//  via ControlPlaneDispatcher.subscribe() — so it can never disagree with what
//  the app itself believes, and no status derivation is duplicated here.
//
//  Announcements are plain sentences in the UI's own words ("Tig Lab
//  connected", "Tig Lab needs a verification code") and are debounced per
//  profile: reconnect churn coalesces into at most one announcement per quiet
//  window, always speaking the LATEST state — a stale "disconnected" after the
//  tunnel already came back would be worse than silence.
//
//  API choice (macOS 26): AccessibilityNotification.Announcement(_:).post()
//  from the Accessibility framework — the supported process-wide announcement
//  since macOS 14. It reaches VoiceOver without needing an NSAccessibility
//  element to hang the post on (this object has no view), which is exactly the
//  situation NSAccessibility.post(element:notification:) makes awkward.
//

import Foundation
import Accessibility

@MainActor
final class AccessibilityAnnouncer {
    /// Reconnect-churn quiet window: at most one announcement per profile per
    /// this many seconds; later transitions within it coalesce to the newest.
    static let quietWindow: TimeInterval = 3

    /// Debounce key for gateway-change announcements. Starts with a control
    /// character so it can never collide with a real profile id.
    private static let gatewayKey = "\u{1}gateway"

    /// The one path for USER-INITIATED speech (a reveal the user just clicked,
    /// like the route graph's overlap arrow). Immediate on purpose: the click
    /// itself is the debounce — one click, one sentence — and running it
    /// through the per-profile churn window would only delay the answer to a
    /// question the user just asked. Views never post announcements directly;
    /// they call this, so the app's whole speaking voice stays in one file.
    static func sayNow(_ sentence: String) {
        AccessibilityNotification.Announcement(sentence).post()
    }

    private weak var vpn: VPNController?
    private var listenTask: Task<Void, Never>?

    /// Last wire status seen per profile. The FIRST observation only records —
    /// launch resyncs report every profile's standing state, and announcing a
    /// wall of "disconnected" at startup would teach people to tune it out.
    private var lastStatus: [String: String] = [:]
    private var lastSpokenAt: [String: Date] = [:]
    /// One deferred sentence per profile (the coalescing half of the debounce).
    private var pending: [String: (sentence: String, task: Task<Void, Never>)] = [:]

    init(dispatcher: ControlPlaneDispatcher, vpn: VPNController) {
        self.vpn = vpn
        listenTask = Task { [weak self] in
            for await event in dispatcher.subscribe() {
                self?.handle(event)
            }
        }
    }

    deinit {
        listenTask?.cancel()
    }

    // MARK: Event → sentence

    private func handle(_ event: ControlEvent) {
        switch event {
        case .statusChanged(let id, let status):
            let previous = lastStatus[id]
            lastStatus[id] = status
            guard let previous, previous != status else { return }
            guard let sentence = sentence(profile: id, from: previous, to: status) else { return }
            announce(sentence, for: id)
        case .gatewayChanged(let owner):
            // The dispatcher only broadcasts a REAL change (RC5 diffs before it
            // publishes), so every one of these is worth a sentence. Same words
            // as the gateway bar's own value, debounced under one key so a
            // reconciliation wobble collapses to the state it settled on.
            let sentence: String = if let owner,
                let name = vpn?.profiles.first(where: { $0.id == owner })?.name {
                "Default gateway is now \(name)"
            } else {
                "Default gateway is now direct — traffic goes out your normal connection"
            }
            announce(sentence, for: Self.gatewayKey)
        default:
            return
        }
    }

    /// The transition in words, or nil for the transient states (connecting /
    /// disconnecting always resolve into an end state that IS announced —
    /// speaking both halves would double every connect).
    private func sentence(profile id: String, from old: String, to new: String) -> String? {
        let name = vpn?.profiles.first { $0.id == id }?.name ?? "VPN"
        switch new {
        case ControlStatusWord.connected:
            return "\(name) connected"
        case ControlStatusWord.reasserting:
            return "\(name) reconnecting"
        case ControlStatusWord.disconnected, ControlStatusWord.invalid:
            // A connect that landed back at disconnected stopped FOR a reason —
            // say the reason where the app knows it. The readiness read here is
            // the same shared decision the Connect button and sidebar play read.
            if old == ControlStatusWord.connecting {
                switch vpn?.connectReadiness(for: id) {
                case .needsCode: return "\(name) needs a verification code"
                case .needsSignIn: return "\(name) needs your sign-in"
                default: break
                }
                if vpn?.incidents[id] != nil { return "\(name) couldn't connect" }
            }
            return "\(name) disconnected"
        default:
            return nil
        }
    }

    // MARK: Debounce (per profile, newest wins)

    private func announce(_ sentence: String, for id: String) {
        // A newer transition supersedes anything still waiting for this profile.
        pending.removeValue(forKey: id)?.task.cancel()

        let elapsed = Date().timeIntervalSince(lastSpokenAt[id] ?? .distantPast)
        if elapsed >= Self.quietWindow {
            speak(sentence, for: id)
            return
        }
        // Inside the quiet window: hold the sentence until the window closes.
        // If more transitions arrive meanwhile, each replaces this one — the
        // flush always speaks the final state of the churn, exactly once.
        let wait = Self.quietWindow - elapsed
        let task = Task { [weak self] in
            try? await Task.sleep(for: .seconds(wait))
            guard !Task.isCancelled else { return }
            self?.flush(id: id)
        }
        pending[id] = (sentence, task)
    }

    private func flush(id: String) {
        guard let held = pending.removeValue(forKey: id) else { return }
        speak(held.sentence, for: id)
    }

    private func speak(_ sentence: String, for id: String) {
        lastSpokenAt[id] = Date()
        AccessibilityNotification.Announcement(sentence).post()
    }
}
