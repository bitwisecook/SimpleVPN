// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// carchive/main.go — the thin c-archive entry point for the proxy-tunnel
// engine. It exists ONLY so the engine can be built as a standalone static
// archive (libpxengine.a) for isolated verification: a -buildmode=c-archive
// build needs a `main` package, and the //export functions themselves live in
// the importable `pxengine` package (engine.go et al.).
//
// WHY A BLANK IMPORT: the exported cgo symbols land in the archive as long as
// the package is linked in. In the SHIPPING build the same pxengine package is
// blank-imported by the Tailscale engine's shim (Vendor/tailscale-engine/src)
// instead, so BOTH engines' exports end up in the ONE Go c-archive that
// PacketTunnel links — two separate Go c-archives cannot be linked into one
// binary (duplicate runtime symbols like _crosscall2). See
// Tools/build-proxy-engine.sh and AGENTS.md.
package main

import _ "pxengine"

func main() {}
