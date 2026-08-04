// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordFieldMapSheet.swift
//  After a 1Password item is dropped (or its reference typed), this sheet lets
//  the user say which of the item's fields feeds which auth role — username,
//  password, one-time code. Each role is a picker over the item's fields (plus
//  "None"); the choices are seeded from 1Password's own field purposes so the
//  common case needs no editing. The mapping is stored on the CredentialSource
//  (by field id) and honoured by OnePasswordProvider at connect time.
//

import SwiftUI

struct OnePasswordFieldMapSheet: View {
    let itemTitle: String
    let fields: [OnePasswordProvider.OPField]
    /// The auth roles this VPN actually uses — computed from its configuration,
    /// so the sheet only offers slots that mean something for this connection.
    let roles: [CredentialRole]
    @Binding var mapping: [String: String]
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label(itemTitle.isEmpty ? "1Password item" : itemTitle, systemImage: "key.fill")
                        .font(.headline)
                    Text("Choose which field 1Password should hand SimpleVPN for each role this VPN uses. Leave a role as “None” if the item doesn't carry it.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if roles.isEmpty {
                    Section {
                        Label("This VPN signs in automatically — there's nothing to map.",
                              systemImage: "person.fill.checkmark")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Section("Field Mapping") {
                        ForEach(roles) { role in
                            Picker(selection: binding(for: role.id)) {
                                Text("None").tag("")
                                ForEach(fields) { f in
                                    Text(fieldLabel(f)).tag(f.id)
                                }
                            } label: {
                                Label {
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(role.title)
                                        Text(role.hint).font(.caption).foregroundStyle(.secondary)
                                    }
                                } icon: { Image(systemName: role.systemImage) }
                            }
                        }
                    }
                }
                if fields.isEmpty {
                    Text("This item has no readable fields. Check the reference points at the right item.")
                        .font(.callout).foregroundStyle(.orange)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Map 1Password Fields")
            .frame(minWidth: 460, minHeight: 420)
            .toolbar {
                // "Done" is dismissive — ESC must close the sheet too.
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
                }
            }
        }
    }

    /// Show the OTP field type so a user recognises which field carries the code.
    private func fieldLabel(_ f: OnePasswordProvider.OPField) -> String {
        f.isOTP ? "\(f.label) (verification code)" : f.label
    }

    private func binding(for role: String) -> Binding<String> {
        Binding(get: { mapping[role] ?? "" },
                set: { newValue in
                    if newValue.isEmpty { mapping.removeValue(forKey: role) }
                    else { mapping[role] = newValue }
                })
    }
}
