// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Reusable Teleport identity. Only Keychain and private, in-memory start options
/// may contain this value. WireGuard keys are generated afresh by the engine.
nonisolated struct TeleportSession: Codable, Sendable, Equatable, CustomStringConvertible {
    var token: String
    var secret: String
    enum CodingKeys: String, CodingKey {
        case token = "session_token", secret = "session_secret"
    }
    var isValid: Bool {
        !token.isEmpty && !secret.isEmpty && token.utf8.count <= 4096 && secret.utf8.count <= 4096
    }
    var description: String { "Teleport session (redacted)" }

    static func inviteProblem(_ raw: String) -> String? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let value: String
        if text.contains("://") {
            guard let url = URLComponents(string: text), url.scheme == "https",
                  url.host?.lowercased() == "teleport.ui.link", url.port == nil,
                  url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
                  url.path.split(separator: "/").count == 1 else {
                return "Enter a https://teleport.ui.link/<UUID> invite or its UUID."
            }
            value = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        } else { value = text }
        guard value.count == 36, UUID(uuidString: value) != nil else {
            return "Enter the complete invite UUID or Teleport link."
        }
        return nil
    }
}
