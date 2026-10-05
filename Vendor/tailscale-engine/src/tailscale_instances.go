// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*TSInstancePacketCallback)(uint64_t context, const unsigned char *bytes, int len);
typedef void (*TSInstanceStringCallback)(uint64_t context, const char *text);
static void tsInstancePacket(TSInstancePacketCallback f, uint64_t c, const unsigned char *p, int n) { if (f) f(c,p,n); }
static void tsInstanceString(TSInstanceStringCallback f, uint64_t c, const char *s) { if (f) f(c,s); }
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"pxengine/instance"
)

type tsInstance struct {
	state     *engineState
	directory string
}

var tsInstances instance.Registry[tsInstance]
var tsDirectories = struct {
	sync.Mutex
	active map[string]bool
}{active: make(map[string]bool)}

func releaseTSDirectory(directory string) {
	tsDirectories.Lock()
	delete(tsDirectories.active, directory)
	tsDirectories.Unlock()
}

//export TSCreateInstance
func TSCreateInstance(cfgJSON *C.char, context C.uint64_t, packet C.TSInstancePacketCallback,
	state C.TSInstanceStringCallback, browse C.TSInstanceStringCallback,
	netmap C.TSInstanceStringCallback, diagnostic C.TSInstanceStringCallback) *C.char {
	if cfgJSON == nil {
		return fail("badRequest", "missing configuration")
	}
	var cfg startConfig
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return fail("badRequest", "invalid configuration")
	}
	control, err := validateControlURL(cfg.ControlURL)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	routes, err := parseRoutes(cfg.AdvertiseRoutes)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return fail("badRequest", "no state directory given")
	}
	directory, err := filepath.Abs(cfg.StateDir)
	if err != nil {
		return fail("badRequest", "invalid state directory")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fail("stateDir", "cannot open node state directory")
	}
	// Resolve aliases before reserving: two nodes cannot safely share identity.
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return fail("stateDir", "cannot resolve node state directory")
	}
	tsDirectories.Lock()
	if tsDirectories.active[directory] {
		tsDirectories.Unlock()
		return fail("alreadyRunning", "this Tailscale node is already running")
	}
	tsDirectories.active[directory] = true
	tsDirectories.Unlock()
	cfg.StateDir = directory
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	emit := func(callback C.TSInstanceStringCallback, text string) {
		s := C.CString(text)
		defer C.free(unsafe.Pointer(s))
		C.tsInstanceString(callback, context, s)
	}
	jsonEmit := func(callback C.TSInstanceStringCallback, value any) {
		b, _ := json.Marshal(value)
		emit(callback, string(b))
	}
	st, err := buildEngineWithCallbacks(cfg, control, routes, mtu, tsCallbacks{
		packet: func(p []byte) {
			if len(p) > 0 {
				C.tsInstancePacket(packet, context, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
			}
		},
		state:  func(s statePayload) { jsonEmit(state, s) },
		browse: func(s string) { emit(browse, s) },
		netmap: func(c *tunnelConfig) { jsonEmit(netmap, c) },
		logf:   func(format string, args ...any) { emit(diagnostic, fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		releaseTSDirectory(directory)
		return fail(kindOf(err), "%v", err)
	}
	handle := tsInstances.Add(tsInstance{st, directory})
	if st.identity != nil {
		st.identity.arm()
	}
	return cJSON(struct {
		OK     bool   `json:"ok"`
		Handle uint64 `json:"handle"`
	}{true, handle})
}

//export TSPacketInInstance
func TSPacketInInstance(handle C.uint64_t, bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	owned, ok := tsInstances.Get(uint64(handle))
	if ok && owned.state.tundev.push(C.GoBytes(bytes, length)) {
		return 1
	}
	return 0
}

//export TSStatusInstance
func TSStatusInstance(handle C.uint64_t) *C.char {
	owned, _ := tsInstances.Get(uint64(handle))
	return tsStatusState(owned.state)
}

//export TSUpdatePrefsInstance
func TSUpdatePrefsInstance(handle C.uint64_t, patchJSON *C.char) *C.char {
	owned, _ := tsInstances.Get(uint64(handle))
	return tsUpdateStatePrefs(owned.state, patchJSON)
}

//export TSStopInstance
func TSStopInstance(handle C.uint64_t) *C.char {
	if owned, ok := tsInstances.Remove(uint64(handle)); ok {
		stopTSState(owned.state)
		releaseTSDirectory(owned.directory)
	}
	return cJSON(okResponse{OK: true})
}

// TSNodeState is a private credential-broker message, never telemetry or logs.
//
//export TSNodeState
func TSNodeState(handle C.uint64_t) *C.char {
	owned, ok := tsInstances.Get(uint64(handle))
	if !ok || owned.state.identity == nil {
		return fail("unavailable", "node identity unavailable")
	}
	snapshot, err := owned.state.identity.snapshot()
	if err != nil {
		return fail("unavailable", "node identity unavailable")
	}
	return cJSON(snapshot)
}

//export TSAckNodeState
func TSAckNodeState(handle C.uint64_t, revision C.uint64_t) *C.char {
	owned, ok := tsInstances.Get(uint64(handle))
	if !ok || owned.state.identity == nil {
		return fail("unavailable", "node identity unavailable")
	}
	if err := owned.state.identity.ack(uint64(revision)); err != nil {
		return fail("state", "%v", err)
	}
	return cJSON(okResponse{OK: true})
}
