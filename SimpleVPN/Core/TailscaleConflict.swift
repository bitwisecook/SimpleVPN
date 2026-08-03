// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleConflict.swift
//  Detects whether an OFFICIAL Tailscale client is already running, so our own
//  Tailscale-kind profile can warn before starting a second one.
//
//  WHY this matters: two Tailscale/gVisor datapaths on one Mac fight over the same
//  wireguard/magicsock role and the same tun-injection path. In the field this has
//  crashed the KERNEL (in_finalize_cksum / ip_output — a packet went out with bad
//  checksum-offload metadata). So a second client is not merely redundant; it's a
//  stability hazard we must actively steer the user away from.
//
//  DETECTION is by bundle-id PREFIX, not an exact list: Tailscale ships as several
//  distributions (App Store `io.tailscale.ipn.macos`, standalone `io.tailscale.ipn.
//  macsys`, and their helper/extension bundles), and matching the shared `io.tailscale`
//  prefix catches all of them — including future ones — without us maintaining a list.
//  We do NOT match our own bundle id (`com.bragi0.SimpleVPN`); that's us, not a conflict.
//
//  It reads NSWorkspace.runningApplications (GUI/agent apps). The pure open-source
//  `tailscaled` daemon with no app wrapper won't appear there; catching that would need
//  process enumeration we can't do from the sandbox, and it's the rare case. Callers
//  should POLL this (see ConnectionView) — NSWorkspace's launch/quit notifications are
//  unreliable for menu-bar/LSUIElement apps like Tailscale, so a notification-only
//  approach goes stale.
//

import AppKit

enum TailscaleConflict {
    /// Bundle-id prefix shared by every official Tailscale distribution and its helpers.
    private static let bundlePrefix = "io.tailscale"

    /// True when at least one official Tailscale client is running right now.
    @MainActor static var isOfficialClientRunning: Bool {
        NSWorkspace.shared.runningApplications.contains { app in
            app.bundleIdentifier?.hasPrefix(bundlePrefix) == true
        }
    }
}
