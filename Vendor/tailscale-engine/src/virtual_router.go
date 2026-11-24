// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef void (*VRPacketCallback)(uint64_t context, const unsigned char *bytes, int length);
typedef int (*VRPortSendCallback)(uint64_t, uint32_t, uint64_t, const unsigned char *, int);
static int vrSend(VRPortSendCallback f,uint64_t c,uint32_t slot,uint64_t gen,const unsigned char *p,int n) { return f(c,slot,gen,p,n); }
static void vrPacket(VRPacketCallback f, uint64_t c, const unsigned char *p, int n) { if (f) f(c,p,n); }
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"pxengine"
	"pxengine/instance"
	"pxengine/packetrouter"
	"pxengine/routelang"
	"pxengine/routelang/catalog"
)

type vrMember struct {
	EventSource string                      `json:"eventSource,omitempty"`
	Adapter     string                      `json:"adapter,omitempty"`
	VPNKind     string                      `json:"vpnKind,omitempty"`
	External    *vrDriverConfig             `json:"external,omitempty"`
	MTU         int                         `json:"mtu,omitempty"`
	ID          string                      `json:"id"`
	Addresses   []string                    `json:"addresses"`
	WireGuard   wgStartConfig               `json:"wireGuard"`
	Proxy       *pxengine.RoutingPortConfig `json:"proxy,omitempty"`
	Allowed     []string                    `json:"allowed,omitempty"`
	ExitNodeID  string                      `json:"exitNodeID,omitempty"`
}
type vrRule struct {
	Prefix string `json:"prefix"`
	Port   string `json:"port"`
}
type vrPolicy struct {
	Version     int                       `json:"version"`
	Revision    uint64                    `json:"revision"`
	Rules       []vrRule                  `json:"rules"`
	EventSource string                    `json:"eventSource,omitempty"`
	SourceRules []packetrouter.SourceRule `json:"sourceRules"`
	Default     string                    `json:"defaultOwner"`
}
type vrConfig struct {
	Version  int        `json:"version"`
	Underlay uint32     `json:"underlayInterfaceIndex"`
	Capture  []string   `json:"captureAddresses"`
	Members  []vrMember `json:"members"`
	Policy   vrPolicy   `json:"policy"`
}
type vrState struct {
	mu           sync.Mutex
	router       *packetrouter.Router
	engines      map[string]uint64
	proxies      map[string]*pxengine.RoutingPort
	retired      map[string]wgStatusPayload
	external     []*vrDriverPort
	memberPolicy []*packetrouter.RawPacketPolicy
	underlay     uint32
	closed       bool
	mtu          int
	transports   []*physicalBind
}

var virtualInstances instance.Registry[*vrState]

func (p vrPolicy) compile() (packetrouter.Policy, error) {
	if (p.EventSource == "" && p.Version != 1) || (p.EventSource != "" && p.Version != 2) {
		return packetrouter.Policy{}, errors.New("unsupported routing policy version")
	}
	policy := packetrouter.Policy{Revision: p.Revision, EventSource: p.EventSource, Default: p.Default, SourceRules: p.SourceRules}
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
	return createVRWithDrivers(cfg, output, bind, nil)
}
func createVRWithDrivers(cfg vrConfig, output func([]byte), bind func(string) conn.Bind, driverSend vrDriverSend) (*vrState, error) {
	if (cfg.Version < 1 || cfg.Version > 3) || len(cfg.Members) == 0 || len(cfg.Members) == 1 && cfg.Policy.SourceRules == nil && cfg.Version < 3 || len(cfg.Members) > 16 || len(cfg.Capture) > 2 {
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
	st := &vrState{engines: make(map[string]uint64), proxies: make(map[string]*pxengine.RoutingPort),
		retired: make(map[string]wgStatusPayload), underlay: cfg.Underlay, mtu: 1280}
	var target atomic.Pointer[packetrouter.Router]
	var ports []packetrouter.Port
	seen := make(map[string]bool, len(cfg.Members))
	st.external = make([]*vrDriverPort, len(cfg.Members))
	st.memberPolicy = make([]*packetrouter.RawPacketPolicy, len(cfg.Members))
	for slot, member := range cfg.Members {
		if member.ID == "" || len(member.ID) > 256 || seen[member.ID] {
			st.stop()
			return nil, errors.New("duplicate or empty VPN port")
		}
		id := member.ID
		seen[id] = true
		var generation atomic.Uint64
		returned := func(p []byte) {
			if router := target.Load(); router != nil {
				router.Return(id, generation.Load(), p)
			}
		}
		adapter := "wireguard"
		var send func([]byte) bool
		var prefixes []string
		var mtu int
		if member.External != nil {
			if cfg.Version != 3 || driverSend == nil || cfg.Underlay == 0 {
				st.stop()
				return nil, errors.New("provider port requires the scoped driver attachment")
			}
			port, epoch, err := newVRDriverPort(slot, member, driverSend)
			if err != nil {
				st.stop()
				return nil, err
			}
			st.external[slot] = port
			adapter = port.adapter
			generation.Store(epoch)
			prefixes, mtu = member.Allowed, member.MTU
			send = func(raw []byte) bool { return port.send(epoch, raw) }
		} else if member.Proxy != nil {
			if cfg.Version < 2 || cfg.Underlay == 0 || member.WireGuard.PrivateKey != "" || len(member.Allowed) == 0 {
				st.stop()
				return nil, errors.New("invalid mixed proxy port")
			}
			dialer, err := physicalProxyDialer(cfg.Underlay)
			if err != nil {
				st.stop()
				return nil, err
			}
			proxy, err := pxengine.NewRoutingPort(*member.Proxy, dialer, returned)
			if err != nil {
				st.stop()
				return nil, err
			}
			generation.Store(1) // Ports are never reopened within this router.
			st.proxies[id] = proxy
			adapter = proxy.Adapter
			prefixes, mtu, send = member.Allowed, member.Proxy.MTU, proxy.Send
		} else {
			engine, problem := createWGState(member.WireGuard, bind(id), returned, func(string, ...any) {})
			if problem != nil {
				st.stop()
				return nil, fmt.Errorf("VPN %s: %s", id, problem.Message)
			}
			handle := wgInstances.Add(engine)
			generation.Store(handle)
			st.engines[id] = handle
			if engine.teleport != nil {
				member.Addresses = engine.teleport.Addresses
				adapter = "wireguard-teleport"
			}
			prefixes, mtu, send = engine.allowedIPs, member.WireGuard.MTU, engine.tundev.push
			if mtu <= 0 {
				mtu = wgDefaultMTU
			}
		}
		addresses, allowed, err := negotiatedRoutes(member.Addresses, prefixes)
		if err != nil {
			st.stop()
			return nil, err
		}
		row, known := catalog.AdapterByID(adapter)
		if member.ExitNodeID != "" && (adapter != "tailscale-node" || member.External == nil || !routelang.ValidExitNodeID(member.ExitNodeID)) {
			st.stop()
			return nil, errors.New("invalid exit node on the selected driver")
		}
		kind := member.VPNKind
		if member.EventSource != "" || member.Adapter != "" || kind != "" {
			if cfg.Version != 3 || adapter != member.Adapter || !known || !slices.Contains(row.VPNKinds, kind) {
				st.stop()
				return nil, errors.New("member traffic policy does not match the selected driver")
			}
		} else if known && len(row.VPNKinds) == 1 {
			kind = row.VPNKinds[0]
		}
		// The empty-program path records a pass-through without parsing the
		// packet, allocating a connection record, or starting a sampling task.
		profilePolicy, err := packetrouter.NewRawPacketPolicy(adapter, id, kind, member.EventSource)
		if err != nil {
			st.stop()
			return nil, err
		}
		st.memberPolicy[slot] = profilePolicy
		st.mtu = min(st.mtu, mtu)
		ports = append(ports, packetrouter.Port{Kind: kind, Policy: profilePolicy, ID: id, Generation: generation.Load(), Addresses: addresses, Allowed: allowed, MTU: mtu, ExitNodeID: member.ExitNodeID,
			Send: send})
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
	for _, port := range st.external {
		if port != nil {
			port.revoke(0)
		}
	}
	if st.router != nil {
		st.router.Close()
	}
	for _, p := range st.memberPolicy {
		if p != nil {
			p.Close()
		}
	}
	engines, proxies := st.engines, st.proxies
	st.proxies = nil
	st.engines = make(map[string]uint64)
	st.mu.Unlock()
	for _, proxy := range proxies {
		proxy.Close()
	}
	for _, handle := range engines {
		if engine, ok := wgInstances.Remove(handle); ok {
			engine.close()
		}
	}
}

//export VRCreateInstance
func VRCreateInstance(configuration *C.char, context C.uint64_t, packetOut C.VRPacketCallback) *C.char {
	return createVR(configuration, context, packetOut, nil)
}

//export VRCreateInstanceWithPorts
func VRCreateInstanceWithPorts(configuration *C.char, context C.uint64_t, packetOut C.VRPacketCallback, portSend C.VRPortSendCallback) *C.char {
	return createVR(configuration, context, packetOut, portSend)
}

func createVR(configuration *C.char, context C.uint64_t, packetOut C.VRPacketCallback, portSend C.VRPortSendCallback) *C.char {
	if configuration == nil || packetOut == nil || C.strnlen(configuration, 4194305) > 4194304 {
		return fail("badRequest", "missing or oversized routing configuration")
	}
	var cfg vrConfig
	if err := json.Unmarshal([]byte(C.GoString(configuration)), &cfg); err != nil {
		return fail("badRequest", "invalid routing configuration")
	}
	if cfg.Underlay == 0 {
		return fail("badRequest", "physical network unavailable")
	}
	var transports []*physicalBind
	var driver vrDriverSend
	if portSend != nil {
		driver = func(slot uint32, epoch uint64, raw []byte) bool {
			return C.vrSend(portSend, context, C.uint32_t(slot), C.uint64_t(epoch), (*C.uchar)(unsafe.Pointer(&raw[0])), C.int(len(raw))) != 0
		}
	}
	st, err := createVRWithDrivers(cfg, func(p []byte) {
		if len(p) > 0 {
			C.vrPacket(packetOut, context, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
		}
	}, func(string) conn.Bind {
		b := newPhysicalBind(cfg.Underlay)
		transports = append(transports, b)
		return b
	}, driver)
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

//export VRPortReturn
func VRPortReturn(handle C.uint64_t, slot C.uint32_t, generation C.uint64_t, raw unsafe.Pointer, length C.int) C.int {
	if raw == nil || length < 1 || length > maxPacketSize {
		return 0
	}
	st, ok := virtualInstances.Get(uint64(handle))
	if ok && st.returnDriver(uint32(slot), uint64(generation), unsafe.Slice((*byte)(raw), int(length))) {
		return 1
	}
	return 0
}

//export VRRevokePort
func VRRevokePort(handle C.uint64_t, slot C.uint32_t, generation C.uint64_t) C.int {
	st, ok := virtualInstances.Get(uint64(handle))
	if ok && st.revokeDriver(uint32(slot), uint64(generation)) {
		return 1
	}
	return 0
}

//export VRReplacePort
func VRReplacePort(handle C.uint64_t, slot C.uint32_t, old C.uint64_t, member *C.char) C.int {
	if member == nil || C.strnlen(member, 262145) > 262144 {
		return 0
	}
	st, ok := virtualInstances.Get(uint64(handle))
	var next vrMember
	if ok && json.Unmarshal([]byte(C.GoString(member)), &next) == nil && st.replaceDriver(uint32(slot), uint64(old), next) {
		return 1
	}
	return 0
}

//export VRPacketIn
func VRPacketIn(handle C.uint64_t, bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st, ok := virtualInstances.Get(uint64(handle))
	// Forward takes its own copy before translation, fragment storage, or queueing.
	if ok && st.router.Forward(unsafe.Slice((*byte)(bytes), int(length))) {
		return 1
	}
	return 0
}

//export VRPacketInWithSource
func VRPacketInWithSource(handle C.uint64_t, bytes unsafe.Pointer, length C.int, source *C.char, owner C.uint64_t) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok {
		return 0
	}
	alias := ""
	if source != nil {
		n := C.strnlen(source, 257)
		if n <= 256 {
			alias = C.GoStringN(source, C.int(n))
		}
	}
	if st.router.ForwardWithSource(unsafe.Slice((*byte)(bytes), int(length)), alias, uint64(owner)) {
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

//export VRValidateEvents
func VRValidateEvents(source *C.char) *C.char {
	if source == nil || C.strnlen(source, 262145) > 262144 {
		return fail("badRequest", "invalid event source")
	}
	program, err := packetrouter.CompileEvents(C.GoString(source))
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	program.Close()
	return cJSON(okResponse{OK: true})
}

//export VRInspect
func VRInspect(handle C.uint64_t, request *C.char) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || request == nil || C.strnlen(request, 4097) > 4096 {
		return fail("badRequest", "invalid inspection request")
	}
	var req packetrouter.InspectRequest
	if err := json.Unmarshal([]byte(C.GoString(request)), &req); err != nil {
		return fail("badRequest", "invalid inspection request")
	}
	page, err := st.router.Inspect(req)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	return cJSON(page)
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
	ports := make(map[string]wgStatusPayload)
	for id, status := range st.retired {
		ports[id] = status
	}
	for _, port := range st.external {
		if port != nil {
			ports[port.id] = port.status()
		}
	}
	for id, proxy := range st.proxies {
		rx, tx, drops := proxy.Traffic()
		ports[id] = wgStatusPayload{State: "running", Endpoint: proxy.Endpoint.String(), RxBytes: rx, TxBytes: tx, PacketsDropped: drops}
	}
	st.mu.Unlock()
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

//export VRPortPacketStats
func VRPortPacketStats(handle C.uint64_t, slot C.uint32_t) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || uint64(slot) >= uint64(len(st.memberPolicy)) || st.memberPolicy[slot] == nil {
		return nil
	}
	return cJSON(st.memberPolicy[slot].Status())
}

//export VRStopPort
func VRStopPort(handle C.uint64_t, id *C.char) *C.char {
	st, ok := virtualInstances.Get(uint64(handle))
	if !ok || id == nil {
		return fail("badRequest", "routing session unavailable")
	}
	name := C.GoString(id)
	if !st.stopPort(name) {
		return fail("badRequest", "VPN port unavailable")
	}
	return cJSON(okResponse{OK: true})
}

func (st *vrState) stopPort(name string) bool {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return false
	}
	if _, stopped := st.retired[name]; stopped {
		st.mu.Unlock()
		return true
	}
	handle := st.engines[name]
	proxy := st.proxies[name]
	known := handle != 0 || proxy != nil
	for _, ext := range st.external {
		if ext != nil && ext.id == name {
			ext.revoke(0)
			known = true
			break
		}
	}
	if !known {
		st.mu.Unlock()
		return false
	}
	if engine, ok := wgInstances.Get(handle); ok {
		status := statusWGState(engine)
		status.State = "stopped"
		st.retired[name] = status
	} else if proxy != nil {
		rx, tx, drops := proxy.Traffic()
		st.retired[name] = wgStatusPayload{State: "stopped", Endpoint: proxy.Endpoint.String(), RxBytes: rx, TxBytes: tx, PacketsDropped: drops}
	}
	delete(st.proxies, name)
	delete(st.engines, name)
	st.router.RemovePort(name)
	st.mu.Unlock()
	if proxy != nil {
		proxy.Close()
	}
	if engine, ok := wgInstances.Remove(handle); ok {
		engine.close()
	}
	return true
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
	if st.closed || ((len(st.proxies) != 0 || st.hasExternal()) && uint32(index) != st.underlay) {
		// Existing proxy TCP/UDP sessions cannot roam. Reconnect the composition
		// to establish fresh carrier sockets bound to the new physical interface.
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
