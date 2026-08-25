// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import Foundation
import UniformTypeIdentifiers

/// Identifies the password manager that originated a credential drag before the
/// connection's currently selected source is considered. A selection is a
/// manual fallback, not a filter on what the person is allowed to drop.
nonisolated enum CredentialItemDropSource: Sendable, Equatable {
    case onePassword
    case applePasswords(ApplePasswordsDropHint)
}

/// The non-secret hint Apple Passwords puts on the drag pasteboard. Apple does
/// not expose a public API that resolves this opaque value back to a password;
/// it is useful only to recognise the source and explain the authorized picker
/// that follows.
nonisolated struct ApplePasswordsDropHint: Sendable, Equatable {
    var title: String
    var username: String
    var protectionSpaces: [String]

    static func parse(_ data: Data) -> ApplePasswordsDropHint? {
        guard data.count <= 1 << 20,
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any],
              let raw = dictionary["id"] as? String,
              raw.contains("protectionSpaces=["),
              raw.contains("customTitle=") || raw.contains("passkey_rpid=") else {
            return nil
        }

        func value(after key: String, before suffix: String = ";") -> String {
            guard let start = raw.range(of: key)?.upperBound else { return "" }
            let rest = raw[start...]
            let end = rest.range(of: suffix)?.lowerBound ?? rest.endIndex
            return String(rest[..<end]).trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let spaces = value(after: "protectionSpaces=[", before: "]")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return ApplePasswordsDropHint(title: value(after: "customTitle="),
                                      username: value(after: "user="),
                                      protectionSpaces: spaces)
    }
}

/// The SwiftUI-shaped drag boundary shared by all credential sources.
@MainActor
enum CredentialItemDrop {
    /// Public types only: SwiftUI must negotiate one of these before either
    /// provider's private/opaque payload can be inspected.
    static let acceptedContentTypes: [UTType] = [
        .utf8PlainText, .plainText, .text, .url, .data
    ]

    static func canAccept(_ providers: [NSItemProvider]) -> Bool {
        providers.contains { provider in
            if provider.registeredTypeIdentifiers.contains(ChromiumWebCustomData.typeIdentifier) {
                return true
            }
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                return false
            }
            return provider.hasItemConformingToTypeIdentifier(UTType.data.identifier)
                || OnePasswordDropItem.canAccept([provider])
        }
    }

    /// Source identity wins over the selected button. The private Chromium type
    /// is conclusive for 1Password; Apple's JSON shape is checked before text
    /// fallbacks so its opaque id can never be mistaken for a 1Password title.
    static func source(from providers: [NSItemProvider]) async -> CredentialItemDropSource? {
        if providers.contains(where: {
            $0.registeredTypeIdentifiers.contains(ChromiumWebCustomData.typeIdentifier)
        }) {
            return .onePassword
        }
        if let hint = applePasswordsHintOnDragPasteboard() {
            return .applePasswords(hint)
        }
        for provider in providers where
            provider.hasItemConformingToTypeIdentifier(UTType.data.identifier) {
            if let data = await data(from: provider, identifier: UTType.data.identifier),
               let hint = ApplePasswordsDropHint.parse(data) {
                return .applePasswords(hint)
            }
        }
        if OnePasswordDropItem.canAccept(providers) {
            return .onePassword
        }
        return nil
    }

    private static func applePasswordsHintOnDragPasteboard() -> ApplePasswordsDropHint? {
        let pasteboard = NSPasteboard(name: .drag)
        guard let data = pasteboard.data(forType: .init(UTType.data.identifier)) else {
            return nil
        }
        return ApplePasswordsDropHint.parse(data)
    }

    private static func data(from provider: NSItemProvider, identifier: String) async -> Data? {
        await withCheckedContinuation { continuation in
            provider.loadDataRepresentation(forTypeIdentifier: identifier) { data, _ in
                continuation.resume(returning: data)
            }
        }
    }
}
