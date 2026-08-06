// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExportImportSettings.swift
//  ONE place to move a whole setup: Settings ▸ General ▸ Export & Import.
//
//  WHY HERE and not in the VPN menu. That menu's "Import Configuration…" opens ONE
//  VPN's file (.ovpn, wg-quick, .mobileconfig) — a per-VPN document action. This is
//  the whole Mac: every VPN and every app setting at once, which is a settings
//  operation rather than a document one. Sharing the menu would give one word two
//  meanings, and the difference between them ("did that just replace all my
//  VPNs?") is exactly the kind nobody should have to guess at.
//
//  THE IMPORT IS ALWAYS CONFIRMED WITH A DIFF, never a bare "are you sure": every
//  setting that would change with its before and after, every VPN that would be
//  added along with the values deciding where its traffic goes and who it trusts,
//  and everything the file was refused for. A server address and a pinned
//  certificate are not details.
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// A file that has been read and understood, waiting for a yes — and afterwards,
/// what happened.
struct PendingConfigImport: Identifiable {
    let id = UUID()
    let fileName: String
    var plan: ConfigImportPlan
    var result: ConfigTransfer.ApplyResult?
    var applying = false
}

struct ExportImportSettings: View {

    var vpn: VPNController
    var tunnels: SubprocessTunnelStore
    var nativeVPN: NativeVPNManager
    var labels: LabelStore

    @State private var pending: PendingConfigImport?
    @State private var problem: String?

    private var locked: String? { ConfigTransfer.policyRefusal }

    var body: some View {
        Section("Export & Import") {
            VStack(alignment: .leading, spacing: 6) {
                Button("Export All Settings\u{2026}") { export() }
                    .disabled(locked != nil)
                    .help(locked ?? "Write every VPN and every SimpleVPN setting to one file")
                    .accessibilityValue(locked.map { "unavailable \u{2014} \($0)" } ?? "")
                Text("Writes every VPN and every SimpleVPN setting to a single file you can read \u{2014} "
                     + "JSON or YAML, whichever you name it. No passwords, keys or other secrets are "
                     + "ever written to it, and there is no option to include them: a file like that "
                     + "can\u{2019}t be recalled once it exists. It says what it left out and how to put "
                     + "it back.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .contain)

            VStack(alignment: .leading, spacing: 6) {
                Button("Import Settings\u{2026}") { openFile() }
                    .disabled(locked != nil)
                    .help(locked ?? "Read a settings file and choose whether to apply it")
                    .accessibilityValue(locked.map { "unavailable \u{2014} \($0)" } ?? "")
                Text("Reads one of those files back. SimpleVPN shows you exactly what would change "
                     + "and asks first. VPNs are added alongside the ones you already have \u{2014} nothing "
                     + "is replaced \u{2014} and your current settings are written to a file you can go "
                     + "back to before anything changes.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .contain)

            if let locked {
                Label(locked, systemImage: "lock.fill")
                    .font(.callout).foregroundStyle(.secondary)
            }

            // How proven this is, DERIVED from the maturity registry — never a
            // sentence written here. Half of this feature is provable by test (the
            // file, the scrubbing, the refusals) and half is not (applying a file
            // from another Mac, on one Mac), and saying so is the house rule.
            if let notice = MaturityNotice.forFeature(.configurationTransfer) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("\(notice.badgeText) \u{2014} \(notice.title)", systemImage: notice.symbolName)
                        .font(.callout)
                    Text(notice.detail)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // One sentence, not two fragments and an icon.
                .accessibilityElement(children: .combine)
                .accessibilityLabel(notice.spokenSummary)
            }
        }
        .sheet(item: $pending) { _ in
            ImportConfirmationSheet(pending: $pending, onApply: apply)
        }
        .alert("SimpleVPN couldn\u{2019}t use that file",
               isPresented: Binding(get: { problem != nil }, set: { if !$0 { problem = nil } })) {
            Button("OK") { problem = nil }
        } message: {
            Text(problem ?? "")
        }
    }

    // MARK: Export

    private func export() {
        guard locked == nil else { return }
        let panel = NSSavePanel()
        panel.title = "Export SimpleVPN Settings"
        panel.message = "No passwords, keys or other secrets are written to this file."
        panel.nameFieldStringValue = ConfigTransfer.suggestedFileName(format: .yaml)
        // Two types, so the panel's own pop-up chooses the encoding and the file's
        // name stays an honest record of what is in it.
        panel.allowedContentTypes = [.yaml, .json]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let format = ConfigFileFormat.forFileName(url.lastPathComponent)
        let text = ConfigTransfer.exportText(vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN,
                                             labels: labels, format: format)
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            problem = "The file couldn\u{2019}t be written: \(error.localizedDescription)"
        }
    }

    // MARK: Import

    private func openFile() {
        guard locked == nil else { return }
        let panel = NSOpenPanel()
        panel.title = "Import SimpleVPN Settings"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.yaml, .json, .text]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            let current = ConfigTransfer.snapshot(vpn: vpn, tunnels: tunnels,
                                                  nativeVPN: nativeVPN, labels: labels)
            pending = PendingConfigImport(fileName: url.lastPathComponent,
                                          plan: ConfigImport.plan(text: text, current: current))
        } catch {
            problem = "The file couldn\u{2019}t be read: \(error.localizedDescription)"
        }
    }

    private func apply() {
        guard var current = pending else { return }
        current.applying = true
        pending = current
        Task {
            let result = await ConfigTransfer.apply(current.plan, vpn: vpn, tunnels: tunnels,
                                                    nativeVPN: nativeVPN, labels: labels)
            var done = current
            done.applying = false
            done.result = result
            pending = done
        }
    }
}

// MARK: - The confirmation

/// The diff, in the order somebody would want to check it: what the file was
/// refused for, which VPNs would arrive and what they trust, which settings would
/// change, and what the file admits it does not carry.
private struct ImportConfirmationSheet: View {

    @Binding var pending: PendingConfigImport?
    let onApply: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let pending {
                header(pending)
                Divider()
                if let result = pending.result {
                    resultBody(result)
                } else {
                    ScrollView { diffBody(pending.plan) }
                        .frame(maxHeight: .infinity)
                    Divider()
                    buttons(pending)
                }
            }
        }
        .padding(20)
        .frame(width: 640, height: 540)
    }

    private func header(_ pending: PendingConfigImport) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(pending.result == nil
                 ? "Import settings from \u{201C}\(pending.fileName)\u{201D}?"
                 : "Imported from \u{201C}\(pending.fileName)\u{201D}")
                .font(.headline)
            if !pending.plan.writtenBy.isEmpty || !pending.plan.exported.isEmpty {
                Text(origin(pending.plan)).font(.callout).foregroundStyle(.secondary)
            }
            if pending.result == nil {
                Text(pending.plan.summary).font(.callout)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func origin(_ plan: ConfigImportPlan) -> String {
        var parts: [String] = []
        if !plan.writtenBy.isEmpty { parts.append("Written by \(plan.writtenBy)") }
        if !plan.exported.isEmpty { parts.append("exported \(plan.exported)") }
        return parts.joined(separator: ", ") + "."
    }

    @ViewBuilder
    private func diffBody(_ plan: ConfigImportPlan) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            if !plan.fatal.isEmpty {
                group("This file can\u{2019}t be used", symbol: "exclamationmark.triangle.fill") {
                    ForEach(plan.fatal, id: \.self) { Text($0).font(.callout) }
                }
            }
            if !plan.refusals.isEmpty {
                group("Left out, and why", symbol: "hand.raised.fill") {
                    ForEach(plan.refusals) { refusal in
                        Text("\u{201C}\(refusal.subject)\u{201D} \u{2014} \(refusal.reason)")
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if !plan.vpns.isEmpty {
                group("VPNs to add", symbol: "plus.circle") {
                    ForEach(plan.vpns) { planned in
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(planned.addedName) \u{2014} \(planned.vpn.kind.displayName)")
                                .font(.callout).fontWeight(.medium)
                            ForEach(planned.securityNotes, id: \.self) { note in
                                Text(note).font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            ForEach(planned.omitted, id: \.self) { note in
                                Label(note, systemImage: "key.slash")
                                    .font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(.bottom, 4)
                        // One VPN reads as one sentence rather than a dozen fragments.
                        .accessibilityElement(children: .combine)
                    }
                }
            }
            if !plan.settingChanges.isEmpty {
                group("Settings to change", symbol: "slider.horizontal.3") {
                    ForEach(plan.settingChanges) { change in
                        Text("\(change.name): \(change.from) \u{2192} \(change.to)")
                            .font(.callout)
                            .accessibilityLabel("\(change.name), now \(change.from), would become \(change.to)")
                    }
                }
            }
            if !plan.newLabels.isEmpty || !plan.keptLabels.isEmpty {
                group("Labels", symbol: "tag") {
                    if !plan.newLabels.isEmpty {
                        Text("Adding: \(plan.newLabels.map(\.name).joined(separator: ", "))").font(.callout)
                    }
                    if !plan.keptLabels.isEmpty {
                        Text("Keeping yours: \(plan.keptLabels.joined(separator: ", "))")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            if !plan.unknownKeys.isEmpty {
                group("Ignored", symbol: "questionmark.circle") {
                    Text("\(plan.unknownKeys.count) setting\(plan.unknownKeys.count == 1 ? "" : "s") in this "
                         + "file \(plan.unknownKeys.count == 1 ? "is" : "are") unknown to this version of "
                         + "SimpleVPN and \(plan.unknownKeys.count == 1 ? "was" : "were") skipped: "
                         + plan.unknownKeys.sorted().joined(separator: ", "))
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("A newer SimpleVPN wrote this file. Nothing is wrong with it \u{2014} this version "
                         + "just has no such setting to put them in.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func resultBody(_ result: ConfigTransfer.ApplyResult) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Label(result.summary, systemImage: result.failures.isEmpty
                      ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.callout)
                if !result.vpnsAdded.isEmpty {
                    Text("Added: \(result.vpnsAdded.joined(separator: ", "))")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(result.failures, id: \.self) { failure in
                    Text(failure).font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let recovery = result.recovery {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Your settings from before this import were saved first, so you can put "
                             + "anything back by hand.")
                            .font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Show the Saved Copy") {
                            NSWorkspace.shared.activateFileViewerSelecting([recovery])
                        }
                    }
                    .accessibilityElement(children: .contain)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        HStack {
            Spacer()
            Button("Done") { pending = nil }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.glassProminent)
        }
    }

    @ViewBuilder
    private func buttons(_ pending: PendingConfigImport) -> some View {
        HStack {
            if pending.applying {
                Text("Importing\u{2026}").font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Cancel") { self.pending = nil }
                .keyboardShortcut(.cancelAction)
            Button("Import") { onApply() }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!pending.plan.isApplicable || pending.applying)
                // A disabled primary action must say why.
                .help(pending.plan.isApplicable
                      ? "Apply everything listed above"
                      : (pending.plan.fatal.first ?? "Nothing in this file would change anything"))
                .accessibilityValue(pending.plan.isApplicable ? ""
                      : "unavailable \u{2014} \(pending.plan.fatal.first ?? "nothing in this file would change anything")")
        }
    }

    @ViewBuilder
    private func group(_ title: String, symbol: String,
                       @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Label(title, systemImage: symbol)
                .font(.subheadline).fontWeight(.semibold)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
