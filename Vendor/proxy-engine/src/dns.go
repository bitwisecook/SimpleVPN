// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// dns.go — the one UDP flow a CONNECT (TCP-only) proxy can still carry.
//
// A SOCKS5 proxy that grants UDP ASSOCIATE forwards UDP directly (see udp.go).
// An http/https CONNECT proxy cannot carry UDP at all — so all UDP is dropped
// EXCEPT DNS (destination port 53), which we rescue by tunnelling it as
// DNS-over-TCP (RFC 7766: a 2-byte big-endian length prefix in front of the
// message) to the SAME resolver the guest addressed. The guest sent a UDP query
// to, say, 8.8.8.8:53; we CONNECT to 8.8.8.8:53 through the proxy, frame the
// query with its length prefix, read the framed answer back, and hand the bare
// message to the guest as the UDP reply. The guest is none the wiser.
//
// This keeps name resolution working behind a TCP-only proxy without leaking
// the query onto the physical network — which is the whole point of the tunnel.

package pxengine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// maxDNSMessage caps a DNS message we will relay. 4096 covers EDNS0; anything
// larger is refused rather than trusted.
const maxDNSMessage = 4096

// dnsOverTCP sends one DNS query to resolverHost:resolverPort through the proxy
// as DNS-over-TCP and returns the response message (without the length prefix).
// It is a single request/response exchange — the guest's UDP socket semantics.
func dnsOverTCP(ctx context.Context, up flowDialer, base *net.Dialer, resolverHost string, resolverPort int, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > maxDNSMessage {
		return nil, fmt.Errorf("dns: query length %d out of range", len(query))
	}
	conn, err := up.dial(ctx, base, resolverHost, resolverPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// Framed write: 2-byte length + message.
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("dns: write query: %w", err)
	}

	// Framed read: 2-byte length then that many bytes.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("dns: read length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > maxDNSMessage {
		return nil, fmt.Errorf("dns: response length %d out of range", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("dns: read response: %w", err)
	}
	return resp, nil
}

// resolverAddress renders a resolver host:port for logging/errors.
func resolverAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// resolveDNSTarget applies the far-side-resolver substitution: a query addressed
// to the configured SENTINEL address is re-aimed at the resolver the sentinel
// stands for, which is then dialled through the upstream — i.e. resolved AT THE
// SERVER. Everything else is passed through untouched.
//
// Why a sentinel at all: a tunnel must advertise a resolver ADDRESS on the utun
// (there is no "ask the other end" in NEDNSSettings), and over SSH the resolver
// you actually want is usually one only the server can see — `127.0.0.1:53` on
// the server, or an internal resolver on an RFC 1918 address the client has no
// route to. So the app advertises an address it owns inside the tunnel's own
// benchmarking range, and this function turns queries to it into a direct-tcpip
// forward to the real thing.
//
// A sentinel whose upstream is unparseable is IGNORED rather than failed: the
// query still goes to the address the guest asked for, which is the pre-sentinel
// behaviour, and PXStart already refuses an empty upstream. Silently sending
// every lookup somewhere unintended would be worse than doing nothing.
func (st *engineState) resolveDNSTarget(host string, port int) (string, int) {
	if st.dnsSentinel == "" || host != st.dnsSentinel {
		return host, port
	}
	upHost, upPort, err := net.SplitHostPort(st.dnsUpstream)
	if err != nil {
		// No port given: the whole string is the host, keep the guest's port.
		if st.dnsUpstream == "" {
			return host, port
		}
		return st.dnsUpstream, port
	}
	n, err := strconv.Atoi(upPort)
	if err != nil || n <= 0 || n > 65535 {
		return upHost, port
	}
	return upHost, n
}
