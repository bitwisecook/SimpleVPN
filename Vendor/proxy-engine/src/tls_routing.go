// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package pxengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"pxengine/internal/clienthello"
)

// Older engines reject this scheme before creating a tunnel. A missing table
// must never silently turn a guarded port back into an unrestricted proxy.
const tlsRoutingPrefix = "tls-route-v1+"
const authenticationPrefix = "auth-required-v1+"

type tlsBackends map[string]netip.AddrPort
type tlsRouteTable map[int]tlsBackends

func (cfg startConfig) proxy() (*upstream, error) {
	raw, authMarked := strings.CutPrefix(cfg.Upstream, authenticationPrefix)
	if authMarked && (cfg.RequiresAuth == nil || !*cfg.RequiresAuth) {
		return nil, errors.New("missing required proxy authentication mode")
	}
	if cfg.RequiresAuth != nil {
		if *cfg.RequiresAuth && (cfg.Username == "" || cfg.Password == "") {
			return nil, errors.New("proxy authentication requires both username and password")
		}
		if !*cfg.RequiresAuth && (cfg.Username != "" || cfg.Password != "") {
			return nil, errors.New("credentials supplied for an unauthenticated proxy")
		}
	}
	raw, marked := strings.CutPrefix(raw, tlsRoutingPrefix)
	if marked != (cfg.TLSRoutes != "") {
		return nil, errors.New("incomplete TLS route configuration")
	}
	up, err := parseUpstream(raw, cfg.Username, cfg.Password)
	if err != nil {
		return nil, err
	}
	if cfg.RequiresAuth != nil && up.kind != proxySSHExtension && (up.username != cfg.Username || up.password != cfg.Password) {
		return nil, errors.New("proxy credentials must be supplied separately from the upstream URL")
	}
	return up, nil
}

func compileTLSRoutes(text string) (tlsRouteTable, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > 32768 {
		return nil, errors.New("TLS routes exceed 32 KiB")
	}
	routes := make(tlsRouteTable)
	total := 0
	for line, raw := range strings.Split(text, "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("TLS route %d needs a port, server name and backend address:port", line+1)
		}
		port, err := strconv.ParseUint(fields[0], 10, 16)
		name, ok := clienthello.Hostname(fields[1])
		backend, backendErr := netip.ParseAddrPort(fields[2])
		if err != nil || port == 0 || !ok || strings.HasSuffix(fields[1], ".") || backendErr != nil || backend.Port() == 0 ||
			backend.Addr().Zone() != "" || backend.Addr().Is4In6() || backend.Addr().IsUnspecified() || backend.Addr().IsMulticast() {
			return nil, fmt.Errorf("invalid TLS route on line %d", line+1)
		}
		entry := routes[int(port)]
		if entry == nil {
			entry = make(tlsBackends)
			routes[int(port)] = entry
		}
		if _, found := entry[name]; found {
			return nil, fmt.Errorf("duplicate TLS route on line %d", line+1)
		}
		entry[name] = backend
		total++
		if total > 128 {
			return nil, errors.New("at most 128 TLS routes are supported")
		}
	}
	if total == 0 {
		return nil, errors.New("TLS routing needs at least one rule")
	}
	return routes, nil
}

var errTLSRoute = errors.New("TLS connection did not match an allowed backend")

// Read only complete handshake records. Bytes after the ClientHello's record
// stay on the stream and are handled by the ordinary relay.
func readTLSRoute(guest net.Conn, routes tlsBackends, timeout time.Duration) (netip.AddrPort, []byte, error) {
	var zero netip.AddrPort
	if err := guest.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return zero, nil, err
	}
	defer guest.SetReadDeadline(time.Time{})
	var records []byte
	for i := 0; i < 8; i++ {
		var header [5]byte
		if _, err := io.ReadFull(guest, header[:]); err != nil {
			return zero, nil, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || header[2] < 1 || header[2] > 3 || size == 0 || len(records)+size+5 > clienthello.MaxBytes+40 {
			return zero, nil, errTLSRoute
		}
		if records == nil {
			records = make([]byte, 0, clienthello.MaxBytes+40)
		}
		records = append(records, header[:]...)
		start := len(records)
		records = records[:start+size]
		if _, err := io.ReadFull(guest, records[start:]); err != nil {
			return zero, nil, err
		}
		name, status := clienthello.ServerName(records)
		switch status {
		case clienthello.Incomplete:
			continue
		case clienthello.Absent:
			return zero, nil, errors.New("TLS ClientHello has no server name")
		case clienthello.Encrypted:
			return zero, nil, errors.New("TLS server name is encrypted or unavailable")
		case clienthello.Visible:
		default:
			return zero, nil, errors.New("invalid TLS ClientHello")
		}
		if backend, ok := routes[name]; ok {
			return backend, records, nil
		}
		return zero, nil, errTLSRoute
	}
	return zero, nil, errTLSRoute
}

func (st *engineState) handleGuardedTCP(req *tcp.ForwarderRequest, routes tlsBackends) {
	select {
	case st.helloSlots <- struct{}{}:
	default:
		st.failedFlows.Add(1)
		req.Complete(true)
		return
	}
	defer func() { <-st.helloSlots }()
	st.relayMu.Lock()
	if st.ctx.Err() != nil {
		st.relayMu.Unlock()
		req.Complete(true)
		return
	}
	st.relayWG.Add(1)
	st.relayMu.Unlock()
	defer st.relayWG.Done()

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		st.failedFlows.Add(1)
		return
	}
	req.Complete(false)
	guest := gonet.NewTCPConn(&wq, ep)
	stop := context.AfterFunc(st.ctx, func() { guest.Close() })
	defer stop()
	if err := st.dialGuarded(guest, routes, 3*time.Second); err != nil {
		st.failedFlows.Add(1)
		ep.Abort() // The handshake completed locally. Reset refused flows.
		guest.Close()
	}
}

func (st *engineState) dialGuarded(guest net.Conn, routes tlsBackends, timeout time.Duration) error {
	backend, hello, err := readTLSRoute(guest, routes, timeout)
	if err != nil {
		return err
	}
	defer clear(hello)
	ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	proxy, err := st.flowDial.dial(ctx, st.dialer, backend.Addr().String(), int(backend.Port()))
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { proxy.Close() })
	_ = proxy.SetWriteDeadline(time.Now().Add(dialTimeout))
	size, err := proxy.Write(hello)
	st.bytesUp.Add(int64(size))
	if err != nil || size != len(hello) || !stop() {
		stop()
		proxy.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	_ = proxy.SetWriteDeadline(time.Time{})
	st.startRelay(guest, proxy)
	return nil
}
