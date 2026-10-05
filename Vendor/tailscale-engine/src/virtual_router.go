// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*VRPacketCallback)(uint64_t context, const unsigned char *bytes, int length);
static void vrPacket(VRPacketCallback f, uint64_t c, const unsigned char *p, int n) { if (f) f(c,p,n); }
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"pxengine/instance"
	"pxengine/packetrouter"
)

type vrMember struct {
	ID        string        `json:"id"`
	Addresses []string      `json:"addresses"`
	WireGuard wgStartConfig `json:"wireGuard"`
}
type vrRule struct {
	Prefix string `json:"prefix"`
	Port   string `json:"port"`
}
type vrPolicy struct {
	Version  int      `json:"version"`
	Revision uint64   `json:"revision"`
	Rules    []vrRule `json:"rules"`
	Default  string   `json:"defaultOwner"`
}
type vrConfig struct {
	Version  int        `json:"version"`
	Underlay uint32     `json:"underlayInterfaceIndex"`
	Capture  []string   `json:"captureAddresses"`
	Members  []vrMember `json:"members"`
	Policy   vrPolicy   `json:"policy"`
}
type vrState struct {
	mu         sync.Mutex
	router     *packetrouter.Router
	engines    map[string]uint64
	closed     bool
	mtu        int
	transports []*physicalBind
}

var virtualInstances instance.Registry[*vrState]

func (p vrPolicy) compile() (packetrouter.Policy, error) {
	if p.Version != 1 {
		return packetrouter.Policy{}, errors.New("unsupported routing policy version")
	}
	policy := packetrouter.Policy{Revision: p.Revision, Default: p.Default}
	for _, rule := range p.Rules {
		prefix, err := netip.ParsePrefix(rule.Prefix)
		if err != nil {
			return policy, errors.New("invalid routing prefix")
		}
		policy.Rules = append(policy.Rules, packetrouter.Rule{Prefix: prefix, Port: rule.Port})
	}
	return policy, nil
}

// The same production constructor is exercised by encrypted loopback tests.
// Engines only see raw packet ports; this session is the sole capture consumer.
func createVRState(cfg vrConfig, output func([]byte), bind func(string) conn.Bind) (*vrState, error) {
	if cfg.Version != 1 || len(cfg.Members) < 2 || len(cfg.Members) > 16 || len(cfg.Capture) > 2 {
		return nil, errors.New("unsupported virtual routing configuration")
	}
	policy, err := cfg.Policy.compile()
	if err != nil {
		return nil, err
	}
	var capture []netip.Addr
	for _, value := range cfg.Capture {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("invalid capture address")
		}
		capture = append(capture, address)
	}
	st := &vrState{engines: make(map[string]uint64), mtu: 1280}
	var target atomic.Pointer[packetrouter.Router]
	var ports []packetrouter.Port
	for _, member := range cfg.Members {
		if member.ID == "" || st.engines[member.ID] != 0 {
			st.stop()
			return nil, errors.New("duplicate or empty VPN port")
		}
		var addresses []netip.Addr
		for _, value := range member.Addresses {
			if prefix, err := netip.ParsePrefix(value); err == nil {
				addresses = append(addresses, prefix.Addr())
			} else if address, err := netip.ParseAddr(value); err == nil {
				addresses = append(addresses, address)
			} else {
				st.stop()
				return nil, errors.New("invalid assigned VPN address")
			}
		}
		var allowed []netip.Prefix
		for _, value := range member.WireGuard.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				st.stop()
				return nil, errors.New("invalid authorized VPN prefix")
			}
			allowed = append(allowed, prefix)
		}
		id := member.ID
		var generation atomic.Uint64
		engine, problem := createWGState(member.WireGuard, bind(id), func(p []byte) {
			if router := target.Load(); router != nil {
				router.Return(id, generation.Load(), p)
			}
		}, func(string, ...any) {})
		if problem != nil {
			st.stop()
			return nil, fmt.Errorf("VPN %s: %s", id, problem.Message)
		}
		handle := wgInstances.Add(engine)
		generation.Store(handle)
		st.engines[id] = handle
		mtu := member.WireGuard.MTU
		if mtu <= 0 {
			mtu = wgDefaultMTU
		}
		st.mtu = min(st.mtu, mtu)
		ports = append(ports, packetrouter.Port{ID: id, Generation: handle, Addresses: addresses, Allowed: allowed, MTU: mtu,
			Send: func(p []byte) bool { return engine.tundev.push(bytes.Clone(p)) }})
	}
	router, err := packetrouter.New(capture, ports, policy, output)
	if err != nil {
		st.stop()
		return nil, err
	}
	st.router = router
	target.Store(router)
	return st, nil
}

func (st *vrState) stop() {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	st.closed = true
	if st.router != nil {
		st.router.Close()
	}
	engines := st.engines
	st.engines = make(map[string]uint64)
	st.mu.Unlock()
	for _, handle := range engines {
		if engine, ok := wgInstances.Remove(handle); ok {
			engine.dev.Close()
			engine.tundev.Close()
		}
	}
}

//export VRCreateInstance
func VRCreateInstance(configuration *C.char, context C.uint64_t, packetOut C.VRPacketCallback) *C.char {
	if configuration == nil {
		return fail("badRequest", "missing routing configuration")
	}
	var cfg vrConfig
	if err := json.Unmarshal([]byte(C.GoString(configuration)), &cfg); err != nil {
		return fail("badRequest", "invalid routing configuration")
	}
	if cfg.Underlay == 0 {
		return fail("badRequest", "physical network unavailable")
	}
	var transports []*physicalBind
	st, err := createVRState(cfg, func(p []byte) {
		if len(p) > 0 {
			C.vrPacket(packetOut, context, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
		}
	}, func(string) conn.Bind {
		b := newPhysicalBind(cfg.Underlay)
		transports = append(transports, b)
		return b
	})
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	st.transports = transports
	handle := virtualInstances.Add(st)
	return cJSON(struct {
		OK     bool   `json:"ok"`
		Handle uint64 `json:"handle"`
	}{true, handle})
}

//export VRPacketIn
func VRPacketIn(handle C.uint64_t, bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st, ok := virtualInstances.Get(uint64(handle))
	if ok && st.router.Forward(C.GoBytes(bytes, length)) {
		return 1
	}
	return 0
}

//export VRApplyPolicy
func VRApplyPolicy(handle C.uint64_t, policy *C.char) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || policy == nil {
		return fail("badRequest", "routing session unavailable")
	}
	var request vrPolicy
	if err := json.Unmarshal([]byte(C.GoString(policy)), &request); err != nil {
		return fail("badRequest", "invalid routing policy")
	}
	compiled, err := request.compile()
	if err == nil {
		err = st.router.Apply(compiled)
	}
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	return cJSON(okResponse{OK: true})
}

//export VRCheckPolicy
func VRCheckPolicy(handle C.uint64_t, policy *C.char) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || policy == nil {
		return fail("badRequest", "routing session unavailable")
	}
	var request vrPolicy
	if err := json.Unmarshal([]byte(C.GoString(policy)), &request); err != nil {
		return fail("badRequest", "invalid routing policy")
	}
	compiled, err := request.compile()
	if err == nil {
		err = st.router.Check(compiled)
	}
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	return cJSON(okResponse{OK: true})
}

//export VRStatus
func VRStatus(handle C.uint64_t) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok {
		return cJSON(map[string]string{"state": "stopped"})
	}
	st.mu.Lock()
	engines := make(map[string]uint64)
	for id, handle := range st.engines {
		engines[id] = handle
	}
	closed := st.closed
	st.mu.Unlock()
	ports := make(map[string]wgStatusPayload)
	for id, handle := range engines {
		if engine, ok := wgInstances.Get(handle); ok {
			ports[id] = statusWGState(engine)
		}
	}
	state := "running"
	if closed {
		state = "stopped"
	}
	return cJSON(struct {
		State   string                     `json:"state"`
		MTU     int                        `json:"mtu"`
		Routing packetrouter.Status        `json:"routing"`
		Ports   map[string]wgStatusPayload `json:"ports"`
	}{state, st.mtu, st.router.Status(), ports})
}

//export VRStopPort
func VRStopPort(handle C.uint64_t, id *C.char) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || id == nil {
		return fail("badRequest", "routing session unavailable")
	}
	name := C.GoString(id)
	st.mu.Lock()
	port := st.engines[name]
	delete(st.engines, name)
	st.router.RemovePort(name)
	st.mu.Unlock()
	if engine, ok := wgInstances.Remove(port); ok {
		engine.dev.Close()
		engine.tundev.Close()
	}
	return cJSON(okResponse{OK: true})
}

//export VRStopInstance
func VRStopInstance(handle C.uint64_t) *C.char {
	if st, ok := virtualInstances.Remove(uint64(handle)); ok {
		st.stop()
	}
	return cJSON(okResponse{OK: true})
}

//export VRFree
func VRFree(text *C.char) {
	if text != nil {
		C.free(unsafe.Pointer(text))
	}
}

//export VRSetUnderlayInterface
func VRSetUnderlayInterface(handle C.uint64_t, index C.uint32_t) C.int {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok {
		return -1
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return -1
	}
	for _, b := range st.transports {
		if err := b.SetInterface(uint32(index)); err != nil {
			for _, other := range st.transports {
				_ = other.SetInterface(0)
			}
			return -1
		}
	}
	return 0
}
