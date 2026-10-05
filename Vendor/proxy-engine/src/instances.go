// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package pxengine

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*PXInstancePacketCallback)(uint64_t context, const unsigned char *bytes, int len);
typedef void (*PXInstanceStringCallback)(uint64_t context, const char *text);
typedef int (*PXInstanceFlowDialCallback)(uint64_t context, const char *host, int port);
static void pxInstancePacket(PXInstancePacketCallback f, uint64_t c, const unsigned char *p, int n) { if (f) f(c,p,n); }
static void pxInstanceString(PXInstanceStringCallback f, uint64_t c, const char *s) { if (f) f(c,s); }
static int pxInstanceDial(PXInstanceFlowDialCallback f, uint64_t c, const char *s, int p) { return f ? f(c,s,p) : -2; }
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"unsafe"

	"pxengine/instance"
)

var pxInstances instance.Registry[*engineState]

type scopedFlowDialer struct{ dialFD func(string, int) int }

func (d scopedFlowDialer) dial(ctx context.Context, _ *net.Dialer, host string, port int) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd := d.dialFD(host, port)
	if fd < 0 {
		return nil, refusalError(fd)
	}
	file := os.NewFile(uintptr(fd), "sshflow")
	defer file.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return net.FileConn(file)
}

//export PXCreateInstance
func PXCreateInstance(cfgJSON *C.char, context C.uint64_t, packet C.PXInstancePacketCallback,
	state C.PXInstanceStringCallback, diagnostic C.PXInstanceStringCallback, dial C.PXInstanceFlowDialCallback) *C.char {
	if cfgJSON == nil {
		return fail("badRequest", "missing configuration")
	}
	var cfg startConfig
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return fail("badRequest", "invalid configuration")
	}
	up, err := parseUpstream(cfg.Upstream, cfg.Username, cfg.Password)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	if up.kind == proxySSHExtension && dial == nil {
		return fail("badRequest", "this tunnel's SSH session was not registered with the engine")
	}
	if cfg.DNSSentinel != "" && cfg.DNSUpstream == "" {
		return fail("badRequest", "a DNS sentinel needs a resolver")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	emitString := func(cb C.PXInstanceStringCallback, text string) {
		s := C.CString(text)
		defer C.free(unsafe.Pointer(s))
		C.pxInstanceString(cb, context, s)
	}
	st, err := buildEngineWithOptions(engineOptions{
		up: up, mtu: mtu, dnsSentinel: cfg.DNSSentinel, dnsUpstream: cfg.DNSUpstream,
		packetOutput: func(p []byte) {
			if len(p) > 0 {
				C.pxInstancePacket(packet, context, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
			}
		},
		diagnostic: func(format string, args ...any) { emitString(diagnostic, fmt.Sprintf(format, args...)) },
		stateOutput: func(stateName, message string) {
			text, _ := json.Marshal(map[string]string{"state": stateName, "message": message})
			emitString(state, string(text))
		},
		flowDial: scopedFlowDialer{dialFD: func(host string, port int) int {
			s := C.CString(host)
			defer C.free(unsafe.Pointer(s))
			return int(C.pxInstanceDial(dial, context, s, C.int(port)))
		}},
	})
	if err != nil {
		return fail("engine", "%v", err)
	}
	// In-process proxy sessions retain their ordinary SOCKS/CONNECT dialer.
	// It must be selected before forwarders/pump start, not patched afterward.
	handle := pxInstances.Add(st)
	st.stateOutput("running", "")
	return cJSON(struct {
		OK     bool   `json:"ok"`
		Handle uint64 `json:"handle"`
	}{true, handle})
}

//export PXPacketInInstance
func PXPacketInInstance(handle C.uint64_t, bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st, ok := pxInstances.Get(uint64(handle))
	if !ok {
		return 0
	}
	raw := C.GoBytes(bytes, length)
	proto, valid := ipProtocolOf(raw)
	if !valid {
		st.packetsInDrop.Add(1)
		return 0
	}
	pkt := newInboundPacket(raw)
	defer pkt.DecRef()
	st.ep.InjectInbound(proto, pkt)
	return 1
}

//export PXStatusInstance
func PXStatusInstance(handle C.uint64_t) *C.char {
	st, _ := pxInstances.Get(uint64(handle))
	return cJSON(statusEngine(st))
}

//export PXStopInstance
func PXStopInstance(handle C.uint64_t) *C.char {
	if st, ok := pxInstances.Remove(uint64(handle)); ok {
		stopEngine(st)
	}
	return cJSON(okResponse{OK: true})
}
