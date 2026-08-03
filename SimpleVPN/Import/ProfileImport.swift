// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProfileImport.swift
//  The single import pipeline every entry point funnels into: the file-open
//  panels, drag-and-drop onto any window, Finder double-click/Dock drops, and
//  the File ▸ Import menu. Validates with the real engine parser, detects
//  duplicates by content hash, and auto-suffixes name collisions.
//

import Foundation

enum ImportOutcome: Equatable, Sendable {
    case imported(profileID: String, name: String)
    case duplicate(existingID: String, existingName: String)
    case invalid(reason: String)
}

extension VPNController {

    /// Import an .ovpn (or WireGuard / Cisco config — see below) from disk.
    /// Never throws — every failure mode is an outcome the UI presents.
    func importProfile(from url: URL) async -> ImportOutcome {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return .invalid(reason: "Could not read \(url.lastPathComponent).")
        }
        // Sniff the real kind from the full filename (extension included) —
        // ConfigDetector's own doc: content wins, the extension is only a weak
        // hint — but name the profile from the extension-less form, same as
        // ManageVPNsView's own importer.
        let suggestedName = url.deletingPathExtension().lastPathComponent
        if let outcome = await routeNonOpenVPN(text: text, filename: url.lastPathComponent, suggestedName: suggestedName) {
            return outcome
        }
        return await importProfile(text: text, suggestedName: suggestedName)
    }

    /// Import from raw profile text (also used by tests and future paste-import).
    func importProfile(text: String, suggestedName: String) async -> ImportOutcome {
        // Same sniff for the text-only entry point (paste, discovery stubs):
        // a WireGuard/Cisco config pasted or dropped here must reach its own
        // store instead of always failing the OpenVPN evaluator below.
        if let outcome = await routeNonOpenVPN(text: text, filename: suggestedName, suggestedName: suggestedName) {
            return outcome
        }
        // Validate with the engine's own parser before anything else.
        let eval = ProfileEvaluation(bridging: OVPNProfileEvaluator.evaluate(text), ovpnText: text)
        if eval.error {
            return .invalid(reason: eval.message.isEmpty
                            ? "This doesn't look like an OpenVPN configuration."
                            : eval.message)
        }

        // Same content as an existing VPN? Tell the user which one, import nothing.
        let hash = ProfileEvaluation.contentHash(of: text)
        for p in profiles {
            if let existing = ovpnText(id: p.id), !existing.isEmpty,
               ProfileEvaluation.contentHash(of: existing) == hash {
                return .duplicate(existingID: p.id, existingName: p.name)
            }
        }

        // Different content but a clashing name gets a numbered suffix.
        let name = uniqueName(from: friendlyImportName(eval: eval, fallback: suggestedName))
        let server = eval.remoteHostOrNil ?? name
        do {
            let id = try await importProfile(name: name, ovpn: text, server: server)
            // A `static-challenge` directive means the server will demand a
            // one-time code — default the OTP requirement on so the field shows
            // and quick-connect never sends password-only. (Already-imported
            // profiles are covered by effectiveAuthConfig, which re-reads the
            // evaluation on every connect.)
            if !eval.staticChallenge.isEmpty {
                var auth = authConfig(for: id)
                auth.requiresOTP = true
                try? await setAuthConfig(auth, for: id)
            }
            return .imported(profileID: id, name: name)
        } catch {
            return .invalid(reason: error.localizedDescription)
        }
    }

    private func friendlyImportName(eval: ProfileEvaluation, fallback: String) -> String {
        if !eval.friendlyName.isEmpty { return eval.friendlyName }
        if !eval.profileName.isEmpty { return eval.profileName }
        let trimmed = fallback.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "Imported VPN" : trimmed
    }

    /// WireGuard / Cisco configs are sniffed by content (`ConfigDetector`), the
    /// same way `ManageVPNsView.importFile` already routes its own drops, and
    /// handed to whichever store owns that engine — wired once at launch (see
    /// `SimpleVPNApp`) via `otherEngineImportHandler` so this shared pipeline
    /// (main-window drop/Import, Finder open) reaches the same stores instead
    /// of only ever validating against the OpenVPN parser. Returns nil for
    /// `.openVPN`, or when the handler isn't wired yet, so the caller falls
    /// through to the OpenVPN evaluator exactly as before.
    private func routeNonOpenVPN(text: String, filename: String, suggestedName: String) async -> ImportOutcome? {
        let kind = ConfigDetector.detect(text: text, filename: filename)
        guard kind != .openVPN, let handler = otherEngineImportHandler else { return nil }
        return await handler(kind, text, suggestedName)
    }

    private func uniqueName(from base: String) -> String {
        let existing = Set(profiles.map { $0.name.lowercased() })
        if !existing.contains(base.lowercased()) { return base }
        for n in 2...999 {
            let candidate = "\(base) \(n)"
            if !existing.contains(candidate.lowercased()) { return candidate }
        }
        return "\(base) \(UUID().uuidString.prefix(4))"
    }
}
