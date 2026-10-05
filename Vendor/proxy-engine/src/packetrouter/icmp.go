// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import "encoding/binary"

// Packet-too-big feedback comes from the capture endpoint. It carries the
// original virtual source and flow tuple, so the host can update its PMTU cache.
func mtuError(p packet, mtu int) []byte {
	headerLength, quoted := 20, min(len(p.raw), p.ipHeader+8)
	if p.src.Is6() {
		headerLength, quoted = 40, min(len(p.raw), 1232)
	}
	raw := make([]byte, headerLength+8+quoted)
	if p.src.Is4() {
		raw[0], raw[8], raw[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		copy(raw[12:], p.src.AsSlice())
		copy(raw[16:], p.src.AsSlice())
		raw[20], raw[21] = 3, 4
		binary.BigEndian.PutUint16(raw[26:], uint16(mtu))
		binary.BigEndian.PutUint16(raw[10:], ^sum(raw[:20]))
	} else {
		raw[0], raw[6], raw[7], raw[40] = 0x60, 58, 64, 2
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		copy(raw[8:], p.src.AsSlice())
		copy(raw[24:], p.src.AsSlice())
		binary.BigEndian.PutUint32(raw[44:], uint32(mtu))
	}
	copy(raw[headerLength+8:], p.raw[:quoted])
	out := packet{raw: raw, src: p.src, dst: p.src, protocol: raw[9], transport: headerLength, checksumOffset: headerLength + 2}
	if p.src.Is6() {
		out.protocol = 58
	}
	out.fixTransportChecksum()
	return raw
}
