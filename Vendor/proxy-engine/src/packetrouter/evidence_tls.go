// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import "pxengine/internal/clienthello"

const maxHelloBytes = clienthello.MaxBytes

func eventTLSHello(payload []byte) (string, bool) {
	name, status := clienthello.ServerName(payload)
	return name, status == clienthello.Visible
}
