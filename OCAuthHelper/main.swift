// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ocauth-helper — OpenConnect sign-in as its own process.
//
//  SSO needs a user-context browser and libopenconnect's blocking
//  openconnect_obtain_cookie(); neither belongs in the root system extension or
//  on the app's main process (a wedged gateway must be killable without
//  touching the app). So sign-in runs here: the app spawns one helper per
//  attempt (the opnative-helper spawn/watchdog/cancel pattern), converses over
//  stdin/stdout (protocol in OpenConnectAuthWire.swift, driver in
//  OCAuthSession.swift), and receives the session cookie to hand to the
//  connect path. The helper exits after done/error/cancel — the cookie never
//  outlives the conversation on this side.
//
//  Codesigning: libopenconnect (+OpenSSL, lz4) is STATICALLY linked and dlopens
//  nothing, so unlike opnative-helper this binary carries NO hardened-runtime
//  relaxation entitlements — none may ever be added.
//

import Foundation

// The app vanishing mid-conversation must surface as EOF/short-write handling,
// not a SIGPIPE kill — the session treats EOF as cancel and exits cleanly.
signal(SIGPIPE, SIG_IGN)

OCAuthSession().run()
