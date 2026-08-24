// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import SwiftUI
import UniformTypeIdentifiers

@main
struct OnePasswordProbeApp: App {
    var body: some Scene {
        WindowGroup("Credential Drop Probe") {
            OnePasswordProbeView()
        }
        .defaultSize(width: 720, height: 820)
    }
}

private struct OnePasswordProbeView: View {
    @State private var isDropTargeted = false
    @State private var dropStatus = "Drag the whole 1Password item row here."
    @State private var dropCollector = OnePasswordDropCollector()
    @State private var droppedOnePasswordItem: OnePasswordDrop?
    @State private var isFetchingOnePasswordItem = false
    @State private var onePasswordFetchStatus = "Drop an item before fetching it."
    @State private var isTransferTargeted = false
    @State private var transferStatus = "Drag an Apple Passwords row here. Only password values are masked."
    @State private var applePickerStatus = "The system picker has not returned a selection yet."
    @State private var droppedAppleIdentifier: String?
    @State private var isFetchingApplePassword = false
    @State private var nativeDropUsername = ""
    @State private var nativeDropPassword = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
            Text("Credential Drop Probe")
                .font(.largeTitle.bold())

            Text("Drop first, then fetch. The drop records only item coordinates; Fetch uses SimpleVPN’s production client and signed helper to authorize and read that exact item.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            GroupBox("1. 1Password drag, then fetch") {
                VStack(spacing: 10) {
                    Image(systemName: isDropTargeted ? "arrow.down.circle.fill" : "arrow.down.circle")
                        .font(.system(size: 34))
                    Text(isDropTargeted ? "Release to use this item" : dropStatus)
                        .font(.headline)
                }
                .frame(maxWidth: .infinity, minHeight: 120)
                .contentShape(Rectangle())
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(isDropTargeted
                              ? Color.accentColor.opacity(0.16)
                              : Color.secondary.opacity(0.08))
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isDropTargeted ? Color.accentColor : Color.secondary,
                            style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                }
                .onDrop(of: OnePasswordDropItem.acceptedContentTypes,
                        isTargeted: $isDropTargeted,
                        perform: acceptDrop)
                .onChange(of: isDropTargeted) { _, targeted in
                    OnePasswordDropItem.logTargeting(targeted)
                }
                .padding(8)

                VStack(alignment: .leading, spacing: 8) {
                    Button(isFetchingOnePasswordItem
                           ? "Fetching from 1Password…"
                           : "Fetch dropped 1Password item") {
                        fetchDroppedOnePasswordItem()
                    }
                    .disabled(droppedOnePasswordItem == nil || isFetchingOnePasswordItem)
                    Text(onePasswordFetchStatus)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 8)
                .padding(.bottom, 8)
            }

            GroupBox("2. Apple Passwords drag and fetch") {
                VStack(alignment: .leading, spacing: 12) {
                    VStack(spacing: 10) {
                        Image(systemName: isTransferTargeted
                              ? "arrow.down.circle.fill" : "arrow.down.circle")
                            .font(.system(size: 34))
                        Text(isTransferTargeted
                             ? "Release to inspect its payload"
                             : transferStatus)
                            .font(.headline)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, minHeight: 110)
                    .contentShape(Rectangle())
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(isTransferTargeted
                                  ? Color.accentColor.opacity(0.16)
                                  : Color.secondary.opacity(0.08))
                    )
                    .overlay {
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(
                                isTransferTargeted ? Color.accentColor : Color.secondary,
                                style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    }
                    // Deliberately broad and diagnostic-only. Non-password
                    // values are visible in this throwaway probe; password keys
                    // retain their character count but not their middle.
                    .onDrop(of: [.item, .data, .text, .url],
                            isTargeted: $isTransferTargeted,
                            perform: inspectTransferTypes)
                    if droppedAppleIdentifier != nil {
                        Button(isFetchingApplePassword
                               ? "Waiting for Apple Passwords…"
                               : "Fetch dropped Apple Passwords item…") {
                            fetchApplePassword()
                        }
                        .disabled(isFetchingApplePassword)
                        Text(applePickerStatus)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Text("Apple’s public authorization request has nowhere to pass the dropped id. Fetch therefore opens Apple Passwords’ chooser; selecting the same row proves what the authorized request returns.")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Divider()
                    Text("Native field drop test")
                        .font(.headline)
                    Text("Drag the Apple Passwords row directly onto either field. These fields have no custom drop handler, so any fill comes from macOS itself.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        TextField("Username", text: $nativeDropUsername)
                            .textContentType(.username)
                        SecureField("Password", text: $nativeDropPassword)
                            .textContentType(.password)
                    }
                    .textFieldStyle(.roundedBorder)
                    Text("Username: \(nativeDropUsername.isEmpty ? "(empty)" : nativeDropUsername)"
                         + " · Password: \(Self.maskedPassword(nativeDropPassword))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(8)
            }
            }
            .padding(24)
        }
        .frame(minWidth: 640, minHeight: 720)
    }

    private func acceptDrop(_ providers: [NSItemProvider]) -> Bool {
        guard OnePasswordDropItem.canAccept(providers) else { return false }
        let snapshot = OnePasswordDropItem.activeDragSnapshot()
        Task {
            guard let drops = await dropCollector.collect(providers, dragSnapshot: snapshot),
                  let dropped = drops.first else {
                dropStatus = "SwiftUI accepted the drop, but it contained no usable 1Password item."
                return
            }
            let completeCoordinates = !dropped.reference.isEmpty
                && !dropped.vault.isEmpty && !dropped.account.isEmpty
            droppedOnePasswordItem = completeCoordinates ? dropped : nil
            onePasswordFetchStatus = completeCoordinates
                ? "Ready to fetch this exact item."
                : "The drop did not carry enough coordinates to fetch."
            dropStatus = completeCoordinates
                ? "Received account, vault and item coordinates without opening 1Password."
                : "Drop arrived, but it did not include complete account, vault and item coordinates."
        }
        return true
    }

    private func inspectTransferTypes(_ providers: [NSItemProvider]) -> Bool {
        let types = Set(providers.flatMap(\.registeredTypeIdentifiers)).sorted()
        let typeSummary = types.isEmpty
            ? "The drop arrived, but advertised no pasteboard types."
            : "Advertised types: \(types.joined(separator: ", "))"
        transferStatus = typeSummary + " Loading payload…"

        let dataProviders = providers.filter {
            $0.hasItemConformingToTypeIdentifier(UTType.data.identifier)
        }
        guard !dataProviders.isEmpty else {
            transferStatus = typeSummary + ". No public.data representation was available."
            return true
        }

        Task {
            var structures = [String]()
            for provider in dataProviders {
                guard let data = await transferData(from: provider) else {
                    structures.append("representation could not be loaded")
                    continue
                }
                if let identifier = Self.appleIdentifier(in: data) {
                    droppedAppleIdentifier = identifier
                }
                structures.append(Self.inspectablePayload(of: data))
            }
            transferStatus = typeSummary + ". " + structures.joined(separator: "; ")
        }
        return true
    }

    private func fetchDroppedOnePasswordItem() {
        guard let droppedOnePasswordItem else { return }
        isFetchingOnePasswordItem = true
        onePasswordFetchStatus = "Waiting for 1Password authorization…"
        Task {
            defer { isFetchingOnePasswordItem = false }
            do {
                let item = try await OnePasswordNative.getItem(
                    reference: droppedOnePasswordItem.reference,
                    vault: droppedOnePasswordItem.vault,
                    account: droppedOnePasswordItem.account)
                onePasswordFetchStatus = Self.render(item)
            } catch {
                onePasswordFetchStatus = "Fetch failed: \(error.localizedDescription)"
            }
        }
    }

    private func fetchApplePassword() {
        isFetchingApplePassword = true
        applePickerStatus = droppedAppleIdentifier == nil
            ? "Waiting for Apple Passwords authorization…"
            : "The dropped id cannot be supplied to Apple’s request; choose that row in the system sheet…"
        Task {
            defer { isFetchingApplePassword = false }
            do {
                let selection = try await ApplePasswordsPicker.choose()
                applePickerStatus = "Username: \(selection.username.isEmpty ? "(empty)" : selection.username)"
                    + " · Password: \(Self.maskedPassword(selection.password))"
            } catch is CancellationError {
                applePickerStatus = "Apple Passwords was cancelled."
            } catch {
                applePickerStatus = "Fetch failed: \(error.localizedDescription)"
            }
        }
    }

    /// Completion-handler bridge kept inside the probe. No bytes leave this
    /// process and no payload is written to disk or the log.
    private func transferData(from provider: NSItemProvider) async -> Data? {
        await withCheckedContinuation { continuation in
            provider.loadDataRepresentation(
                forTypeIdentifier: UTType.data.identifier
            ) { data, _ in
                continuation.resume(returning: data)
            }
        }
    }

    /// This is deliberately probe-only. It exposes non-password values so we can
    /// learn the real transfer contract, recursively replacing password values
    /// with a same-length first/dots/last rendering.
    private static func inspectablePayload(of data: Data) -> String {
        let byteCount = data.count
        if let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil) {
            return "\(byteCount) bytes; property list: \(render(maskPasswords(in: plist)))"
        }
        if let json = try? JSONSerialization.jsonObject(with: data) {
            return "\(byteCount) bytes; JSON: \(render(maskPasswords(in: json)))"
        }
        return "\(byteCount) bytes; opaque data"
    }

    private static func appleIdentifier(in data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data),
              let dictionary = json as? [String: Any] else { return nil }
        return dictionary["id"] as? String
    }

    private static func render(_ item: OnePasswordNative.OPItem) -> String {
        let fields = item.fields.map { field in
            let identifiesPassword = field.purpose.caseInsensitiveCompare("PASSWORD") == .orderedSame
                || field.type.caseInsensitiveCompare("CONCEALED") == .orderedSame
                || field.label.localizedCaseInsensitiveContains("password")
            let value = identifiesPassword ? maskedPassword(field.value) : field.value
            let code = field.otp.map { "; otp=\($0)" } ?? ""
            return "\(field.label) [\(field.type), \(field.purpose)]: \(value)\(code)"
        }
        return ([
            "title=\(item.title)",
            "vault=\(item.vaultID)",
            "item=\(item.itemID)",
        ] + fields).joined(separator: "\n")
    }

    private static func maskPasswords(in value: Any) -> Any {
        if let dictionary = value as? [String: Any] {
            return dictionary.mapValues { value in
                value
            }.reduce(into: [String: Any]()) { result, pair in
                let key = pair.key
                if key.localizedCaseInsensitiveContains("password"),
                   let password = pair.value as? String {
                    result[key] = maskedPassword(password)
                } else {
                    result[key] = maskPasswords(in: pair.value)
                }
            }
        }
        if let array = value as? [Any] {
            return array.map(maskPasswords)
        }
        return value
    }

    private static func render(_ value: Any) -> String {
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value,
                                                  options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        return String(describing: value)
    }

    private static func maskedPassword(_ password: String) -> String {
        let characters = Array(password)
        guard characters.count > 2 else { return password }
        return String(characters[0])
            + String(repeating: ".", count: characters.count - 2)
            + String(characters[characters.count - 1])
    }
}
