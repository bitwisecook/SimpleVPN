// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PublicIPMonitor.swift
//  "Where does the internet see me?" for the endpoint map: fetches the public
//  IPv4/IPv6 addresses, geolocates them via the bundled GeoIP DB, and refreshes
//  on a timer. Callers also poke refresh() on tunnel status changes so the pin
//  jumps the moment traffic starts flowing through the VPN. Never touches the
//  network at init — only when started or refreshed.
//

import Foundation

/// Settings key: allow the app to ask an internet service for the public
/// address ("Where do I appear from?"). Default on; when off the monitor makes
/// no network calls at all and publishes nothing.
let publicIPLookupDefaultsKey = "privacy.publicIPLookup"

@Observable
final class PublicIPMonitor {

    private(set) var publicIPv4: String?
    private(set) var publicIPv6: String?
    private(set) var countryCode: String?
    private(set) var countryName: String?
    private(set) var lat: Double?
    private(set) var lon: Double?
    private(set) var lastUpdated: Date?
    private(set) var isRefreshing = false

    // Where the Mac appears from *without* any VPN — snapshotted whenever a lookup
    // runs while no tunnel is active, so the map can show home (pre-VPN) distinctly
    // from the egress (while connected, `lat`/`lon`/`countryName` are the egress).
    private(set) var homeCountryCode: String?
    private(set) var homeCountryName: String?
    private(set) var homeLat: Double?
    private(set) var homeLon: Double?

    /// The app tells the monitor whether any VPN is currently carrying traffic, so
    /// it knows when a fresh lookup represents home vs egress. Default: not active.
    static var isVPNActive: @Sendable () -> Bool = { false }

    @ObservationIgnored private var monitorTask: Task<Void, Never>?

    // Free, keyless, plain-text "what's my IP" services. Where a service offers
    // family-specific hosts, each family is probed independently (a v4-only or
    // v6-only network still half-works). nonisolated: fetchIP runs off-main.
    nonisolated private static let timeout: TimeInterval = 10

    /// The lookup service to use — presets plus a user-supplied custom URL.
    /// Persisted by id in Settings ▸ Privacy.
    static var provider: IPLookupProvider { IPLookupProvider.current }

    /// Whether the user allows public-address lookups (Settings ▸ Privacy).
    static var lookupEnabled: Bool {
        UserDefaults.standard.object(forKey: publicIPLookupDefaultsKey) == nil
            || UserDefaults.standard.bool(forKey: publicIPLookupDefaultsKey)
    }

    /// Drop everything we learned (called when the user turns the lookup off).
    func clear() {
        publicIPv4 = nil; publicIPv6 = nil
        countryCode = nil; countryName = nil
        lat = nil; lon = nil
        homeCountryCode = nil; homeCountryName = nil; homeLat = nil; homeLon = nil
        lastUpdated = nil
    }

    /// Fetch both addresses (each independently best-effort) and geolocate.
    func refresh() async {
        guard Self.lookupEnabled else { clear(); return }
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        let provider = Self.provider
        async let v4 = Self.fetchIP(from: provider.v4URL)
        async let v6 = Self.fetchIP(from: provider.v6URL)
        // A single-endpoint service (no family-specific host) returns whichever
        // family the connection used; classify the result by its shape.
        let a = await v4, b = await v6
        if provider.v6URL == nil, let a, a.contains(":") {
            publicIPv4 = nil; publicIPv6 = a
        } else {
            publicIPv4 = a; publicIPv6 = b
        }

        if let probe = publicIPv4 ?? publicIPv6 {
            lastUpdated = Date()
            countryCode = GeoIP.shared?.countryCode(for: probe)
        } else {
            countryCode = nil
        }
        countryName = countryCode.flatMap { CountryCentroids.name(for: $0) }
        let centroid = countryCode.flatMap { CountryCentroids.coordinate(for: $0) }
        lat = centroid?.lat
        lon = centroid?.lon

        // With no VPN carrying traffic, "where we appear from" IS home. Snapshot it
        // so that once a VPN is up, the map still knows the pre-VPN origin.
        if !Self.isVPNActive() {
            homeCountryCode = countryCode; homeCountryName = countryName
            homeLat = lat; homeLon = lon
        }
    }

    /// Refresh now, then every `interval`. Safe to call repeatedly — the previous
    /// loop is cancelled first. The loop holds self weakly, so it dies with the
    /// monitor (at most one interval later).
    func startMonitoring(interval: TimeInterval = 300) {
        stopMonitoring()
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                guard self != nil else { return }
                try? await Task.sleep(for: .seconds(interval))
            }
        }
    }

    func stopMonitoring() {
        monitorTask?.cancel()
        monitorTask = nil
    }

    /// Plain-text body → trimmed address string; nil on any failure (or no URL).
    nonisolated private static func fetchIP(from url: URL?) async -> String? {
        guard let url else { return nil }
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let body = String(data: data, encoding: .utf8) else { return nil }
        let ip = body.trimmingCharacters(in: .whitespacesAndNewlines)
        return ip.isEmpty ? nil : ip
    }
}
