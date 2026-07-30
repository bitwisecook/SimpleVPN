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
                .tabItem { Label("General", systemImage: "gearshape") }
            LabelsSettings(labels: labels)
                .tabItem { Label("Labels", systemImage: "tag") }
        }
        .frame(width: 560, height: 480)
    }
}

private struct ExtensionsSettings: View {
    @Bindable var ext: ExtensionController
    @AppStorage(menuBarGraphDefaultsKey) private var menuBarGraph = true
    @AppStorage(publicIPLookupDefaultsKey) private var publicIPLookup = true
    @AppStorage(publicIPProviderDefaultsKey) private var ipProviderID = "ipify"
    @AppStorage(publicIPCustomV4DefaultsKey) private var ipCustomV4 = ""
    @AppStorage(publicIPCustomV6DefaultsKey) private var ipCustomV6 = ""
    // Default false — the permission is only ever requested by flipping this on.
    @AppStorage(LocationAuthority.enabledKey) private var locationEnabled = false
    @State private var location = LocationAuthority.shared
    @Environment(PublicIPMonitor.self) private var publicIP: PublicIPMonitor?
    @State private var appBrowser = BrowserDefaults.appDefault

    var body: some View {
        Form {
            Section("Menu Bar") {
                Toggle("Show traffic graph next to the icon", isOn: $menuBarGraph)
                Text("Widens the menu-bar icon with a small live up/down graph while a VPN is connected.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("Sign-in Browser") {
                BrowserPicker(selection: $appBrowser)
                    .onChange(of: appBrowser) { BrowserDefaults.appDefault = appBrowser }
                Text("The browser (and profile) SimpleVPN uses for SAML/SSO sign-in when a VPN needs one. Each VPN can override this; the default is your system default browser.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("Privacy") {
                Toggle("Look up my public address", isOn: $publicIPLookup)
                    .onChange(of: publicIPLookup) {
                        if publicIPLookup { Task { await publicIP?.refresh() } }
                        else { publicIP?.clear() }
                    }
                Text("Shows \u{201C}your connection appears from…\u{201D} and the map's you-are-here pin by asking an internet service what address it sees. Off means no such requests are ever made.")
                    .font(.callout).foregroundStyle(.secondary)

                if publicIPLookup {
                    Picker("Lookup service", selection: $ipProviderID) {
                        ForEach(IPLookupProvider.selectable) { Text($0.name).tag($0.id) }
                    }
                    .onChange(of: ipProviderID) { Task { await publicIP?.refresh() } }
                    if ipProviderID == IPLookupProvider.customID {
                        TextField("IPv4 URL (plain-text body)", text: $ipCustomV4,
                                  prompt: Text("https://api4.ipify.org"))
                            .autocorrectionDisabled()
                        TextField("IPv6 URL (optional)", text: $ipCustomV6,
                                  prompt: Text("https://api6.ipify.org"))
                            .autocorrectionDisabled()
                            .onSubmit { Task { await publicIP?.refresh() } }
                        Text("Each URL must return just the address as plain text.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }

                Divider()

                // A switch is only honest once macOS has actually granted the
                // permission. Before that it's a request, so it's a button — a toggle
                // that flips on and silently does nothing (or worse, sticks on after a
                // denial macOS will never re-prompt for) is a lie about app state.
                switch location.status {
                case .authorized:
                    Toggle("Use this Mac's location", isOn: $locationEnabled)
                        .onChange(of: locationEnabled) { location.setEnabled(locationEnabled) }
                    Label(location.ssid.map { "Allowed \u{2014} on \u{201C}\($0)\u{201D}" } ?? "Allowed",
                          systemImage: "checkmark.circle.fill")
                        .font(.callout).foregroundStyle(.green)

                case .waiting:
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Waiting for your answer to the macOS prompt\u{2026}")
                            .font(.callout).foregroundStyle(.secondary)
                    }

                case .denied:
                    // macOS records the first refusal permanently; nothing in-app can
                    // re-ask, so the only honest offer is a route to System Settings.
                    VStack(alignment: .leading, spacing: 6) {
                        Label("macOS is blocking location for SimpleVPN",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.callout).foregroundStyle(.orange)
                        Button("Open System Settings\u{2026}") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                    }

                case .unavailable:
                    Label("Location Services is turned off for this Mac",
                          systemImage: "location.slash")
                        .font(.callout).foregroundStyle(.orange)

                case .off, .needsRequest:
                    Button {
                        location.requestAccess()
                    } label: {
                        Label("Ask for Location Permission", systemImage: "location")
                    }
                }

                Text("Places you accurately on the maps, and lets SimpleVPN read the Wi-Fi network's name \u{2014} macOS withholds the network name from apps without this. This data never leaves this device. Off means macOS is never asked for your location.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if ManagedPolicy.isManaged {
                Section("Managed by Your Organization") {
                    ForEach(ManagedPolicy.activeSummary, id: \.self) { line in
                        Label(line, systemImage: "lock.fill").font(.callout)
                    }
                    Text("These settings are enforced by your organization's device management and can't be changed here.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            Section("System Extension") {
                LabeledContent("Status", value: ext.status)
                LabeledContent("Bundled version", value: ext.bundledVersion)
                Button("Re-activate Extension") { Task { await ext.activate() } }
            }
            Section("About") {
                LabeledContent("Application", value: UI.appVersion)
                // License terms: DB-IP Country Lite is CC BY 4.0; Natural Earth is
                // public domain (credited as a courtesy).
                Text("VPN engine: OpenVPN 3 · [IP Geolocation by DB-IP](https://db-ip.com) · Map data: Natural Earth")
                    .font(.callout)
                    .foregroundStyle(.secondary)
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
                    HStack(spacing: 10) {
                        ColorPicker("", selection: colorBinding(l)).labelsHidden()
                        TextField("Name", text: nameBinding(l))
                        Spacer()
                        Button(role: .destructive) { labels.remove(l.id) } label: { Image(systemName: "trash") }
                            .buttonStyle(.borderless)
                    }
                    .padding(.vertical, 5)
                }
            }
            .scrollContentBackground(.hidden)
            .padding(.top, 6)
            Divider()
            HStack(spacing: 10) {
                ColorPicker("", selection: $newColor).labelsHidden()
                TextField("New label", text: $newName)
                Button("Add") {
                    labels.addLabel(name: newName, resolved: newColor.resolve(in: environment)); newName = ""
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(16)
        }
    }

    private func nameBinding(_ l: LabelDef) -> Binding<String> {
        Binding(get: { l.name }, set: { var m = l; m.name = $0; labels.update(m) })
    }
    private func colorBinding(_ l: LabelDef) -> Binding<Color> {
        Binding(get: { l.color }, set: { var m = l; m.set($0.resolve(in: environment)); labels.update(m) })
    }
}
