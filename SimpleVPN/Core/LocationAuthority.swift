// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LocationAuthority.swift
//  Opt-in, off-by-default access to this Mac's location.
//
//  Two things in the app get better with it, and only with it:
//    • the map's you-are-here pin becomes the real device position instead of a guess
//      geolocated from the public IP address;
//    • the Wi-Fi network NAME becomes readable — since macOS 14, CoreWLAN returns nil
//      for the SSID unless the process holds location authorization. That's why
//      NetworkMemory otherwise has to describe a network as "the network on en0
//      (gateway …)" rather than "Office Wi-Fi".
//
//  The permission is requested ONLY when the user turns the setting on. Nothing here
//  touches CoreLocation until then — not even instantiating a manager — so a user who
//  leaves it off never sees a prompt and the app never asks the system for a position.
//  Nothing collected here is persisted or transmitted: it feeds the live UI, plus the
//  network label in NetworkMemory, and dies with the process.
//

import CoreLocation
import CoreWLAN
import Foundation

@MainActor
@Observable
final class LocationAuthority: NSObject, CLLocationManagerDelegate {
    static let shared = LocationAuthority()

    /// Where the user's choice lives. Absent ⇒ off; we never default this to true.
    static let enabledKey = "location.enabled"

    enum Status: Equatable {
        case off                 // the setting is off — no manager exists
        case needsRequest        // opted in previously, but macOS has never been asked
        case waiting             // asked the system, no answer yet
        case authorized
        case denied              // user or MDM said no; only System Settings can undo it
        case unavailable         // services switched off machine-wide
    }

    private(set) var status: Status = .off
    /// Live device position, nil unless authorized and a fix has arrived.
    private(set) var coordinate: CLLocationCoordinate2D?
    /// Current Wi-Fi network name — readable only while authorized (see the note above).
    private(set) var ssid: String?

    /// Deliberately optional and lazily made: constructing a CLLocationManager is
    /// harmless, but keeping the whole object graph absent while off makes it obvious by
    /// inspection that nothing is watching the user's location.
    private var manager: CLLocationManager?

    var isEnabled: Bool { UserDefaults.standard.bool(forKey: Self.enabledKey) }

    /// Did WE raise the prompt this session? Assigning the delegate immediately fires an
    /// authorization callback, and without this that callback would report "waiting for
    /// your answer" when no panel was ever shown.
    private var hasRequested = false

    private override init() {
        super.init()
        // Restore a previously granted opt-in: if authorization was already given this
        // resumes silently, and if it was revoked in System Settings the delegate reports
        // .denied. Deliberately `requesting: false`. A stored opt-in whose permission was never
        // actually granted must NOT re-raise the prompt at launch — from the user's side
        // that's indistinguishable from the app asking unbidden, which is the one thing
        // this whole design promises not to do. Settings shows an explicit ask instead.
        if isEnabled { start(requesting: false) }
    }

    /// Turning the setting on is the *only* thing that asks the system for permission.
    func setEnabled(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: Self.enabledKey)
        if on { start(requesting: true) } else { stop() }
    }

    /// Ask now, from an explicit user action (the "Allow Location Access" button).
    func requestAccess() {
        UserDefaults.standard.set(true, forKey: Self.enabledKey)
        start(requesting: true)
    }

    private func start(requesting: Bool) {
        let m = manager ?? CLLocationManager()
        manager = m
        m.delegate = self
        // Coarse is all the map needs, and it's the cheaper, less invasive fix.
        m.desiredAccuracy = kCLLocationAccuracyKilometer
        if requesting {
            hasRequested = true
            status = .waiting
            m.requestWhenInUseAuthorization()
            // On macOS the panel is raised by an actual location REQUEST, not by
            // requestWhenInUseAuthorization() alone — asking without starting leaves the
            // app waiting on an answer to a question nobody was shown.
            m.startUpdatingLocation()
        }
        applyAuthorization(m.authorizationStatus, requesting: requesting)
    }

    private func stop() {
        manager?.stopUpdatingLocation()
        manager?.delegate = nil
        manager = nil
        status = .off
        coordinate = nil
        ssid = nil
    }

    private func applyAuthorization(_ auth: CLAuthorizationStatus, requesting: Bool = true) {
        switch auth {
        case .notDetermined:
            // Not yet asked (or asked and not answered). `.needsRequest` is what makes
            // Settings show a button rather than a switch that appears on but does
            // nothing.
            status = requesting ? .waiting : .needsRequest
        case .authorized, .authorizedAlways:
            status = .authorized
            manager?.startUpdatingLocation()
            refreshSSID()
        case .denied:
            // Said no ⇒ the setting goes back off. Leaving it on would be a switch that
            // claims a capability the app does not have, and macOS will never re-prompt
            // for it — only System Settings can undo a denial.
            status = CLLocationManager.locationServicesEnabled() ? .denied : .unavailable
            forgetDenied()
        case .restricted:
            status = .denied
            forgetDenied()
        @unknown default:
            status = .waiting
        }
    }

    /// Drop the opt-in and stop watching, without wiping the `.denied` status the UI
    /// needs in order to explain itself.
    private func forgetDenied() {
        UserDefaults.standard.set(false, forKey: Self.enabledKey)
        manager?.stopUpdatingLocation()
        coordinate = nil
        ssid = nil
    }

    /// The SSID, or nil when it isn't knowable. Called on fixes and on network changes.
    func refreshSSID() {
        guard status == .authorized else { ssid = nil; return }
        let name = CWWiFiClient.shared().interface()?.ssid()
        ssid = (name?.isEmpty == false) ? name : nil
    }

    // MARK: CLLocationManagerDelegate

    // CoreLocation calls these back on the queue the manager was created on — the main
    // queue here — but the delegate protocol isn't isolated, so hop explicitly rather
    // than assume.
    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let auth = manager.authorizationStatus
        Task { @MainActor in
            self.applyAuthorization(auth, requesting: self.hasRequested)
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didUpdateLocations locations: [CLLocation]) {
        guard let last = locations.last else { return }
        let coord = last.coordinate
        Task { @MainActor in
            self.coordinate = coord
            self.refreshSSID()
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didFailWithError error: Error) {
        // A denial arrives as an error too; authorization changes are handled above, so
        // there's nothing to do but leave the last known position alone.
    }
}
