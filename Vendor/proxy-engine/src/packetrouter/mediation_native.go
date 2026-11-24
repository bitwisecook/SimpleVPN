// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build routing_rust && cgo

package packetrouter

/*
#cgo CFLAGS: -I${SRCDIR}/../../../routing-core/include
#cgo noescape rc_traffic_record
#cgo nocallback rc_traffic_record
#cgo noescape rc_udp_seen
#cgo nocallback rc_udp_seen
#cgo noescape rc_udp_accept
#cgo nocallback rc_udp_accept
#cgo nocallback rc_udp_history_new
#cgo nocallback rc_udp_history_free
#include "routing_mediation.h"
*/
import "C"
import "unsafe"

type trafficRow C.RCTrafficCounters

func (r *trafficRow) record(stage C.uint32_t, n, b, h, e uint64) {
	C.rc_traffic_record((*C.RCTrafficCounters)(r), stage, C.uint64_t(n), C.uint64_t(b), C.uint64_t(h), C.uint64_t(e))
}
func (r *trafficRow) received(size int)   { r.record(C.RC_RECEIVE, 1, uint64(size), 0, 0) }
func (r *trafficRow) forward(n, b uint64) { r.record(C.RC_FORWARD, n, b, 0, 0) }
func (r *trafficRow) finish(size int, pass bool) {
	if pass {
		r.forward(1, uint64(size))
	} else {
		r.record(C.RC_DROP_PACKET, 1, uint64(size), 0, 0)
	}
}
func (r *trafficRow) passthrough(n, b uint64) { r.record(C.RC_PASSTHROUGH, n, b, 0, 0) }
func (r *trafficRow) evaluated(hits uint64, edited bool) {
	var e uint64
	if edited {
		e = 1
	}
	r.record(C.RC_EVALUATE, 1, 0, hits, e)
}
func (r *trafficRow) snapshot() DirectionCounters {
	return DirectionCounters{
		uint64(r.received_packets), uint64(r.received_bytes), uint64(r.forwarded_packets), uint64(r.forwarded_bytes),
		uint64(r.dropped_packets), uint64(r.dropped_bytes), uint64(r.evaluated_packets), uint64(r.edited_packets), uint64(r.rule_hits),
	}
}

type udpHistory struct{ handle *C.RCUdpHistory }

func nativeUDPTuple(k tuple) C.RCUdpTuple {
	f := C.uint8_t(6)
	if k.src.Is4() {
		f = 4
	}
	t := C.RCUdpTuple{family: f, src_port: C.uint16_t(k.srcPort), dst_port: C.uint16_t(k.dstPort)}
	*(*[16]byte)(unsafe.Pointer(&t.src[0])) = k.src.As16()
	*(*[16]byte)(unsafe.Pointer(&t.dst[0])) = k.dst.As16()
	return t
}
func (u *udpHistory) seen(k tuple, ms uint64) int32 {
	if u.handle == nil {
		u.handle = C.rc_udp_history_new()
	}
	key := nativeUDPTuple(k)
	return int32(C.rc_udp_seen(u.handle, &key, C.uint64_t(ms)))
}
func (u *udpHistory) accept(k tuple, ms uint64) {
	key := nativeUDPTuple(k)
	C.rc_udp_accept(u.handle, &key, C.uint64_t(ms))
}
func (u *udpHistory) close() { C.rc_udp_history_free(u.handle); u.handle = nil }
