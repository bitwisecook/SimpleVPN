// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsView.swift
//  The standard Settings window (⌘, / SimpleVPN ▸ Settings): global configuration —
//  system-extension management and the label catalog.
//

import SwiftUI
import AppKit
import Sparkle

struct SettingsView: View {
    @Bindable var ext: ExtensionController
    @Bindable var labels: LabelStore
    /// Sparkle's updater (from the app-level controller); nil in previews.
    var updater: SPUUpdater?

    var body: some View {
        TabView {
            ExtensionsSettings(ext: ext, updater: updater)
                .tabItem { Label("General", systemImage: "gearshape") }
            LabelsSettings(labels: labels)
                .tabItem { Label("Labels", systemImage: "tag") }
        }
        .frame(width: 560, height: 480)
    }
}

private struct ExtensionsSettings: View {
    @Bindable var ext: ExtensionController
    var updater: SPUUpdater?
    /// Mirrors Sparkle's own persisted setting (it stores this in defaults);
    /// seeded in onAppear, written back on toggle.
    @State private var autoCheckUpdates = false
    @AppStorage(menuBarGraphDefaultsKey) private var menuBarGraph = false
    @AppStorage(inspectorDefaultsKey) private var inspectorOpenByDefault = false
    @AppStorage(dockIconDefaultsKey) private var dockIcon = true
    @AppStorage(menuBarIconDefaultsKey) private var menuBarIcon = true
    @AppStorage(publicIPLookupDefaultsKey) private var publicIPLookup = true
    // On by default: unlike a location or public-address lookup, this only ever
    // contacts servers the user has already configured a VPN for.
    @AppStorage(endpointProbeDefaultsKey) private var endpointProbing = true
    @AppStorage(publicIPProviderDefaultsKey) private var ipProviderID = "ipify"
    @AppStorage(publicIPCustomV4DefaultsKey) private var ipCustomV4 = ""
    @AppStorage(publicIPCustomV6DefaultsKey) private var ipCustomV6 = ""
    // Default false — the permission is only ever requested by flipping this on.
    @AppStorage(LocationAuthority.enabledKey) private var locationEnabled = false
    @State private var location = LocationAuthority.shared
    @Environment(PublicIPMonitor.self) private var publicIP: PublicIPMonitor?
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?
    @State private var appBrowser = BrowserDefaults.appDefault

    /// Both icons off is allowed but worth a plain warning: the app becomes
    /// hard to find again (nothing in the Dock, nothing in the menu bar). The
    /// recommended way out is offered right in the dialog; opening SimpleVPN
    /// again from Applications also brings the window back (single instance).
    private func warnIfBothIconsOff() {
        guard !dockIcon && !menuBarIcon else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "SimpleVPN now has no icon anywhere"
        alert.informativeText = "With no Dock icon and no menu-bar icon, it can be hard to find SimpleVPN again — especially if its window gets closed or minimised. If that happens, open SimpleVPN from the Applications folder and the window comes back. We recommend keeping at least one icon on."
        alert.addButton(withTitle: "Show the Menu-Bar Icon")
        alert.addButton(withTitle: "Keep Both Off")
        if alert.runModal() == .alertFirstButtonReturn {
            menuBarIcon = true
        }
    }

    var body: some View {
        Form {
            // Sections group by user goal (AGENTS.md "Config surfaces"):
            // General → Menu Bar & Icons → Updates → Privacy → Advanced.
            Section("General") {
                Toggle("Open the live-details pane by default", isOn: $inspectorOpenByDefault)
                Text("The right-hand pane with the traffic graph, map and connection details. It can always be opened from the toolbar; this only sets how the window starts.")
                    .font(.callout).foregroundStyle(.secondary)
                BrowserPicker(selection: $appBrowser)
                    .onChange(of: appBrowser) { BrowserDefaults.appDefault = appBrowser }
                Text("The browser (and profile) SimpleVPN uses for SAML/SSO sign-in when a VPN needs one. Each VPN can override this; the default is your system default browser.")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("Check how quick each server is", isOn: $endpointProbing)
                    .onChange(of: endpointProbing) { if !endpointProbing { probes?.clear() } }
                Text("When a VPN offers several servers, SimpleVPN measures them as you open its server list and puts the quickest first. Off means no checks are made at all — the list is ordered by which servers are nearest to you instead.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section("Menu Bar & Icons") {
                Toggle("Show the Dock icon", isOn: $dockIcon)
                    .onChange(of: dockIcon) {
                        NSApp.setActivationPolicy(dockIcon ? .regular : .accessory)
                        if !dockIcon { NSApp.activate() }   // keep this window frontmost across the switch
                        warnIfBothIconsOff()
                    }
                Text("Without a Dock icon SimpleVPN lives in the menu bar only — the menus at the top of the screen are hidden too.")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("Show the menu-bar icon", isOn: $menuBarIcon)
                    .onChange(of: menuBarIcon) { warnIfBothIconsOff() }
                Text("Takes effect the next time SimpleVPN opens. With no menu-bar icon, closing the SimpleVPN window quits the app — and quitting always disconnects.")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("Show traffic graph next to the icon", isOn: $menuBarGraph)
                Text("Widens the menu-bar icon with a small live up/down graph while a VPN is connected.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("Updates") {
                Toggle("Check for updates automatically", isOn: $autoCheckUpdates)
                    .onChange(of: autoCheckUpdates) { updater?.automaticallyChecksForUpdates = autoCheckUpdates }
                    .onAppear { autoCheckUpdates = updater?.automaticallyChecksForUpdates ?? false }
                    .disabled(updater == nil)
                Text("Asks GitHub about once a day whether a newer SimpleVPN exists. Off means SimpleVPN never checks on its own — you can always check from the SimpleVPN menu.")
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
                        ProgressView().controlSize(.small).accessibilityHidden(true)
                        Text("Waiting for your answer to the macOS prompt\u{2026}")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)

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
            Section("Advanced") {
                LabeledContent("Extension status", value: ext.status)
                LabeledContent("Bundled extension version", value: ext.bundledVersion)
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
                        // Every row has the same three controls — each must say
                        // WHICH label it edits, or the list is ten anonymous
                        // colour wells and ten fields all called "Name".
                        ColorPicker("", selection: colorBinding(l)).labelsHidden()
                            .accessibilityLabel("Colour for the \(l.name) label")
                        TextField("Name", text: nameBinding(l))
                            .accessibilityLabel("Name of the \(l.name) label")
                        Spacer()
                        Button(role: .destructive) { labels.remove(l.id) } label: {
                            Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                        }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Delete the \(l.name) label")
                    }
                    .padding(.vertical, 5)
                }
            }
            .scrollContentBackground(.hidden)
            .padding(.top, 6)
            Divider()
            HStack(spacing: 10) {
                ColorPicker("", selection: $newColor).labelsHidden()
                    .accessibilityLabel("Colour for the new label")
                TextField("New label", text: $newName)
                Button("Add") {
                    labels.addLabel(name: newName, resolved: newColor.resolve(in: environment)); newName = ""
                }
                .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
                // A dead button must say why.
                .help(newName.trimmingCharacters(in: .whitespaces).isEmpty
                      ? "Type a name for the new label first" : "Add the label")
                .accessibilityValue(newName.trimmingCharacters(in: .whitespaces).isEmpty
                      ? "unavailable — type a name first" : "")
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
