// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import AuthenticationServices
import SwiftUI

/// The one value the system returns after the person chooses and authorizes a
/// saved password. It is intentionally not identifiable or persistable: callers
/// put it straight into the existing in-memory sign-in fields for this attempt.
struct ApplePasswordSelection: Sendable {
    let username: String
    let password: String
}

/// SwiftUI-shaped access to macOS's own password authorization UI.
///
/// AuthenticationServices owns the catalogue, search UI and authentication.
/// SimpleVPN receives only the one credential the person chose; there is no
/// public API that hands an ordinary app the Apple Passwords catalogue to index.
@MainActor
enum ApplePasswordsPicker {
    static func choose() async throws -> ApplePasswordSelection {
        try await withCheckedThrowingContinuation { continuation in
            let session = ApplePasswordPickerSession(
                anchor: NSApp.keyWindow ?? NSApp.mainWindow,
                continuation: continuation)
            session.begin()
        }
    }
}

@MainActor
private final class ApplePasswordPickerSession: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding {

    private let anchor: NSWindow?
    private var continuation: CheckedContinuation<ApplePasswordSelection, any Error>?
    private var controller: ASAuthorizationController?
    /// `ASAuthorizationController` retains itself while a request is running,
    /// but its delegate is weak. This small cycle keeps the delegate alive and
    /// is broken in both completion paths.
    private var keepAlive: ApplePasswordPickerSession?

    init(anchor: NSWindow?,
         continuation: CheckedContinuation<ApplePasswordSelection, any Error>) {
        self.anchor = anchor
        self.continuation = continuation
    }

    func begin() {
        keepAlive = self
        let request = ASAuthorizationPasswordProvider().createRequest()
        let controller = ASAuthorizationController(authorizationRequests: [request])
        self.controller = controller
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor ?? NSApp.keyWindow ?? NSApp.mainWindow ?? NSWindow()
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential as? ASPasswordCredential else {
            finish(.failure(ApplePasswordsPickerError.unexpectedCredential))
            return
        }
        finish(.success(ApplePasswordSelection(username: credential.user,
                                               password: credential.password)))
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: any Error) {
        if let authorizationError = error as? ASAuthorizationError,
           authorizationError.code == .canceled {
            finish(.failure(CancellationError()))
        } else {
            finish(.failure(error))
        }
    }

    private func finish(_ result: Result<ApplePasswordSelection, any Error>) {
        let continuation = self.continuation
        self.continuation = nil
        controller = nil
        keepAlive = nil
        continuation?.resume(with: result)
    }
}

private enum ApplePasswordsPickerError: LocalizedError {
    case unexpectedCredential

    var errorDescription: String? {
        "macOS returned something other than a username and password."
    }
}

/// Reusable SwiftUI control for every sign-in surface. The AppKit presentation
/// detail stays behind `ApplePasswordsPicker`; callers get one ordinary action
/// that fills their existing bindings.
struct ApplePasswordsPickerButton: View {
    let onPick: (ApplePasswordSelection) -> Void

    @State private var choosing = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                choose()
            } label: {
                Label(choosing ? "Opening Apple Passwords…" : "Choose from Apple Passwords…",
                      systemImage: "person.badge.key.fill")
            }
            .disabled(choosing)

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func choose() {
        choosing = true
        errorMessage = nil
        Task {
            defer { choosing = false }
            do {
                onPick(try await ApplePasswordsPicker.choose())
            } catch is CancellationError {
                // Closing a picker is a choice, not a connection error.
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
