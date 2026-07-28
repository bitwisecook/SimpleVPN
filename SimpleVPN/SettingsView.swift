// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsView.swift
//  The standard Settings window (⌘, / SimpleVPN ▸ Settings): global configuration —
//  system-extension management and the label catalog.
//

import SwiftUI

struct SettingsView: View {
    @Bindable var ext: ExtensionController
    @Bindable var labels: LabelStore

    var body: some View {
        TabView {
            ExtensionsSettings(ext: ext)
                .tabItem { Label("Extensions", systemImage: "puzzlepiece.extension") }
            LabelsSettings(labels: labels)
                .tabItem { Label("Labels", systemImage: "tag") }
        }
        .frame(width: 480, height: 400)
    }
}

private struct ExtensionsSettings: View {
    @Bindable var ext: ExtensionController
    var body: some View {
        Form {
            Section("System Extension") {
                LabeledContent("Status", value: ext.status)
                LabeledContent("Bundled version", value: ext.bundledVersion)
                Button("Re-activate Extension") { Task { await ext.activate() } }
            }
            Section("About") {
                LabeledContent("Application", value: UI.appVersion)
            }
        }
        .formStyle(.grouped)
    }
}

private struct LabelsSettings: View {
    @Bindable var labels: LabelStore
    @Environment(\.self) private var environment
    @State private var newName = ""
    @State private var newColor = Color(.sRGB, red: 0.78, green: 0.86, blue: 0.96)

    var body: some View {
        VStack(spacing: 0) {
            List {
                ForEach(labels.labels) { l in
                    HStack {
                        ColorPicker("", selection: colorBinding(l)).labelsHidden()
                        TextField("Name", text: nameBinding(l))
                        Spacer()
                        Button(role: .destructive) { labels.remove(l.id) } label: { Image(systemName: "trash") }
                            .buttonStyle(.borderless)
                    }
                }
            }
            Divider()
            HStack {
                ColorPicker("", selection: $newColor).labelsHidden()
                TextField("New label", text: $newName)
                Button("Add") {
                    labels.addLabel(name: newName, resolved: newColor.resolve(in: environment)); newName = ""
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding()
        }
    }

    private func nameBinding(_ l: LabelDef) -> Binding<String> {
        Binding(get: { l.name }, set: { var m = l; m.name = $0; labels.update(m) })
    }
    private func colorBinding(_ l: LabelDef) -> Binding<Color> {
        Binding(get: { l.color }, set: { var m = l; m.set($0.resolve(in: environment)); labels.update(m) })
    }
}
