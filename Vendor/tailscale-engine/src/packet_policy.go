// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"pxengine/instance"
	"pxengine/packetrouter"
	"unicode/utf8"
	"unsafe"
)

var rawPolicies instance.Registry[*packetrouter.RawPacketPolicy]

func boundedPolicyString(s *C.char, max int) (string, bool) {
	if s == nil {
		return "", true
	}
	n := C.strnlen(s, C.size_t(max+1))
	if n > C.size_t(max) {
		return "", false
	}
	v := C.GoStringN(s, C.int(n))
	return v, utf8.ValidString(v)
}

//export PPCreate
func PPCreate(adapter, source *C.char, diagnostic **C.char) C.uint64_t {
	return PPCreateWithContext(adapter, nil, nil, source, diagnostic)
}

//export PPCreateWithContext
func PPCreateWithContext(adapter, profile, kind, source *C.char, diagnostic **C.char) C.uint64_t {
	if diagnostic != nil {
		*diagnostic = nil
	}
	id, ok1 := boundedPolicyString(adapter, 80)
	name, ok2 := boundedPolicyString(profile, 256)
	vpn, ok3 := boundedPolicyString(kind, 256)
	program, ok4 := boundedPolicyString(source, 32768)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		if diagnostic != nil {
			*diagnostic = C.CString("Invalid or oversized UTF-8 packet policy configuration")
		}
		return 0
	}
	policy, err := packetrouter.NewRawPacketPolicy(id, name, vpn, program)
	if err != nil {
		if diagnostic != nil {
			*diagnostic = C.CString(err.Error())
		}
		return 0
	}
	return C.uint64_t(rawPolicies.Add(policy))
}

//export PPDirectionNeedsPackets
func PPDirectionNeedsPackets(handle C.uint64_t, d C.int) C.int {
	p, ok := rawPolicies.Get(uint64(handle))
	if !ok || d < 0 || d > 1 {
		return -1
	}
	return C.int(p.NeedsPackets(packetrouter.Direction(d)))
}

//export PPObserve
func PPObserve(handle C.uint64_t, d C.int, n, bytes C.uint64_t) {
	if p, ok := rawPolicies.Get(uint64(handle)); ok && d >= 0 && d <= 1 {
		p.Observe(packetrouter.Direction(d), uint64(n), uint64(bytes))
	}
}

//export PPApply
func PPApply(handle C.uint64_t, d C.int, bytes unsafe.Pointer, length C.int) C.int {
	p, ok := rawPolicies.Get(uint64(handle))
	if !ok || d < 0 || d > 1 {
		return 0
	}
	if bytes == nil || length <= 0 || length > 65575 {
		p.RejectInput(packetrouter.Direction(d), int(length))
		return 0
	}
	if p.Apply(packetrouter.Direction(d), unsafe.Slice((*byte)(bytes), int(length))) {
		return 1
	}
	return 0
}

//export PPStatus
func PPStatus(handle C.uint64_t) *C.char {
	if p, ok := rawPolicies.Get(uint64(handle)); ok {
		return cJSON(p.Status())
	}
	return nil
}

//export PPDestroy
func PPDestroy(handle C.uint64_t) {
	if p, ok := rawPolicies.Remove(uint64(handle)); ok {
		p.Close()
	}
}

//export PPFree
func PPFree(text *C.char) { C.free(unsafe.Pointer(text)) }

//export VRPacketStats
func VRPacketStats(handle C.uint64_t) *C.char {
	if st, ok := virtualInstances.Get(uint64(handle)); ok {
		return cJSON(st.router.PacketPolicyStatus())
	}
	return nil
}
