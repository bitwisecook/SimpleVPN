// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  PacketTunnel-Bridging-Header.h
//  Exposes the Objective-C++ OpenVPN 3 bridge to the Swift provider, plus the
//  Tailscale/Headscale Go engine's stable C interface.
//

#import "OpenVPN3Bridge.h"
#import "OpenConnectBridge.h"
#import "tsengine.h"
// The proxy-tunnel engine's exports live in the SAME Go c-archive as tsengine
// (two Go c-archives cannot co-link); this is just its stable C header.
#import "pxengine.h"
// The plain-WireGuard engine's exports live in that same archive too (its
// module already pins wireguard-go); this is its stable C header.
#import "wgengine.h"
