// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// proxy.go — the upstream dialers for the proxy-tunnel engine. Every TCP flow
// gVisor's forwarder hands us is dialled through ONE of these, chosen by the
// scheme of the configured upstream URL:
//
//   socks5://   RFC 1928 CONNECT, optional RFC 1929 username/password auth.
//   http://     HTTP CONNECT (plaintext hop to the proxy), optional
//               Proxy-Authorization: Basic.
//   https://    HTTP CONNECT over TLS to the proxy itself. The TLS is verified
//               against the SYSTEM roots (crypto/x509 on darwin uses Security's
//               verifier — SecTrustEvaluate — so this honours the login
//               keychain and MDM-pushed anchors). See dialTLS.
//
// No third-party proxy library: the two handshakes are small, and hand-rolling
// them keeps the dependency surface to gVisor + the standard library (which is
// what lets this fold into the tailscale archive without dragging x/net/proxy
// and its transitive graph in).

package pxengine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// dialTimeout bounds a single upstream dial (TCP connect + proxy handshake). A
// flow that cannot reach its proxy must fail fast so the guest's SYN times out
// like a normal unreachable host rather than hanging a socket forever.
const dialTimeout = 30 * time.Second

// proxyKind is the upstream family, decided once at start from the URL scheme.
type proxyKind int

const (
	proxySOCKS5 proxyKind = iota
	proxyHTTPConnect
	proxyHTTPSConnect
)

func (k proxyKind) tcpOnly() bool { return k != proxySOCKS5 }

// upstream is the parsed, credentialled description of the proxy every flow is
// dialled through. Credentials live only here in memory; they are never logged
// and never echoed in status.
type upstream struct {
	kind proxyKind
	// host:port of the proxy itself.
	address string
	// serverName for the https:// TLS handshake (the proxy's own hostname).
	serverName string
	username   string
	password   string
}

// parseUpstream turns the configured URL + separately-supplied credentials into
// an upstream. Credentials in the URL userinfo are accepted too (the app keeps
// them out of the saved URL, but a hand-entered one might carry them), with the
// explicit username/password winning.
func parseUpstream(raw, username, password string) (*upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("no upstream proxy URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream URL is not valid: %w", err)
	}
	var kind proxyKind
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		kind = proxySOCKS5
	case "http":
		kind = proxyHTTPConnect
	case "https":
		kind = proxyHTTPSConnect
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5://, http:// or https://)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("upstream URL has no host")
	}
	port := u.Port()
	if port == "" {
		// Sensible per-scheme defaults; SOCKS has no IANA default so 1080 is the
		// universal convention.
		switch kind {
		case proxySOCKS5:
			port = "1080"
		case proxyHTTPConnect:
			port = "8080"
		case proxyHTTPSConnect:
			port = "443"
		}
	}
	up := &upstream{
		kind:       kind,
		address:    net.JoinHostPort(host, port),
		serverName: host,
		username:   username,
		password:   password,
	}
	// URL userinfo is a fallback only — the app supplies credentials out of band.
	if up.username == "" {
		if ui := u.User; ui != nil {
			up.username = ui.Username()
			if p, ok := ui.Password(); ok && up.password == "" {
				up.password = p
			}
		}
	}
	return up, nil
}

// dialProxyConn opens the raw TCP (or TLS) connection to the proxy itself,
// before any CONNECT/SOCKS handshake. base is the real OS dialer: this traffic
// must leave via the physical interface, NOT back into our own utun (which
// would be a routing loop).
//
// Two things keep it out of the utun, and NEITHER is anything this file does:
//   - NetworkExtension excludes the provider process's own sockets from the
//     tunnel it operates, so these dials leave via the physical interface even
//     when the utun owns 0.0.0.0/0. That is the mechanism the tunnel actually
//     relies on today.
//   - Belt and braces: the extension resolves this proxy's host at connect and
//     adds each literal address as a /32 (/128) excluded route
//     (Shared/ProxyTunnelNetworkSettings.swift `proxyExclusions`), so the host
//     routing table itself never points the proxy's address at the utun.
//
// There is no interface binding (IP_BOUND_IF) on this dialer — if that ever
// becomes necessary, it belongs here, on base.
func (up *upstream) dialProxyConn(ctx context.Context, base *net.Dialer) (net.Conn, error) {
	conn, err := base.DialContext(ctx, "tcp", up.address)
	if err != nil {
		return nil, fmt.Errorf("cannot reach proxy %s: %w", up.address, err)
	}
	if up.kind != proxyHTTPSConnect {
		return conn, nil
	}
	// https:// proxy: wrap in TLS verified against the system roots. A nil
	// RootCAs makes crypto/tls fall back to the platform verifier, which on
	// darwin is Security.framework — so enterprise/MDM anchors are honoured.
	tc := tls.Client(conn, &tls.Config{ServerName: up.serverName})
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy TLS handshake failed: %w", err)
	}
	return tc, nil
}

// dialThrough dials targetHost:targetPort THROUGH the proxy, returning a
// connection whose payload is the tunnelled TCP stream. base is the OS dialer
// used to reach the proxy.
func (up *upstream) dialThrough(ctx context.Context, base *net.Dialer, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := up.dialProxyConn(ctx, base)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	switch up.kind {
	case proxySOCKS5:
		err = socks5Connect(conn, targetHost, targetPort, up.username, up.password)
	default:
		err = httpConnect(conn, up.serverName, targetHost, targetPort, up.username, up.password)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Clear the handshake deadline: the flow itself is governed by the guest's
	// own timeouts and our idle copy, not this one-shot dial budget.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ---- SOCKS5 (RFC 1928 / RFC 1929) ------------------------------------------

const (
	socksVersion5 = 0x05
	socksNoAuth   = 0x00
	socksUserPass = 0x02
	socksNoAccept = 0xFF

	socksCmdConnect  = 0x01
	socksCmdUDPAssoc = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04
)

// socks5Negotiate performs the method-selection and (if offered/required) the
// username/password sub-negotiation, leaving conn positioned for a request.
func socks5Negotiate(conn net.Conn, username, password string) error {
	methods := []byte{socksNoAuth}
	if username != "" {
		methods = []byte{socksUserPass, socksNoAuth}
	}
	greeting := append([]byte{socksVersion5, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks: write greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks: read method: %w", err)
	}
	if reply[0] != socksVersion5 {
		return fmt.Errorf("socks: bad version 0x%02x", reply[0])
	}
	switch reply[1] {
	case socksNoAuth:
		return nil
	case socksUserPass:
		return socks5UserPassAuth(conn, username, password)
	case socksNoAccept:
		return errors.New("socks: proxy rejected all offered auth methods")
	default:
		return fmt.Errorf("socks: proxy chose unsupported method 0x%02x", reply[1])
	}
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("socks: username or password exceeds 255 bytes")
	}
	// RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, 0x01, byte(len(username)))
	buf = append(buf, username...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks: write auth: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks: read auth reply: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("socks: username/password rejected")
	}
	return nil
}

// socks5Connect issues a CONNECT for targetHost:targetPort after negotiating.
func socks5Connect(conn net.Conn, targetHost string, targetPort int, username, password string) error {
	if err := socks5Negotiate(conn, username, password); err != nil {
		return err
	}
	req, err := socksRequest(socksCmdConnect, targetHost, targetPort)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks: write connect: %w", err)
	}
	_, _, err = readSocksReply(conn)
	return err
}

// socksRequest builds a SOCKS5 request (CONNECT or UDP ASSOCIATE). A literal IP
// target uses the IPv4/IPv6 address types; otherwise the domain type lets the
// proxy resolve (socks5h semantics, which is what a real tunnel wants — DNS
// must not leak from the guest).
func socksRequest(cmd byte, host string, port int) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("socks: port %d out of range", port)
	}
	buf := []byte{socksVersion5, cmd, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, socksAtypIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, socksAtypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("socks: hostname exceeds 255 bytes")
		}
		buf = append(buf, socksAtypDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port&0xFF))
	return buf, nil
}

// socksReplyMessage maps the RFC 1928 reply codes to prose.
var socksReplyMessage = map[byte]string{
	0x00: "succeeded",
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

// readSocksReply reads a reply and returns the bound address it carries (needed
// for UDP ASSOCIATE — the relay endpoint). A non-zero status is an error.
func readSocksReply(conn net.Conn) (net.IP, int, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, 0, fmt.Errorf("socks: read reply: %w", err)
	}
	if head[0] != socksVersion5 {
		return nil, 0, fmt.Errorf("socks: bad reply version 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		msg := socksReplyMessage[head[1]]
		if msg == "" {
			msg = fmt.Sprintf("code 0x%02x", head[1])
		}
		return nil, 0, fmt.Errorf("socks: %s", msg)
	}
	var addr net.IP
	switch head[3] {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
		addr = net.IP(b)
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
		addr = net.IP(b)
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
		// A domain bound-address is unusual; leave addr nil, the caller only
		// needs the port for the relay in that case.
	default:
		return nil, 0, fmt.Errorf("socks: reply has unknown address type 0x%02x", head[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return nil, 0, err
	}
	return addr, int(pb[0])<<8 | int(pb[1]), nil
}

// ---- HTTP CONNECT ----------------------------------------------------------

// httpConnect issues a CONNECT request and consumes the response headers. On
// success the connection carries the tunnelled stream. proxyHost is only used
// for the Host header cosmetics; the target is what we tunnel to.
func httpConnect(conn net.Conn, proxyHost, targetHost string, targetPort int, username, password string) error {
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&b, "Host: %s\r\n", target)
	b.WriteString("Proxy-Connection: Keep-Alive\r\n")
	if username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("http connect: write: %w", err)
	}
	// Parse just the status line + headers with the standard reader; the body
	// (if any error body) is left on the wire but we fail before using conn.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("http connect: read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http connect: proxy returned %s", resp.Status)
	}
	// bufio may have read past the header into buffered data; for a CONNECT
	// tunnel the proxy sends nothing until we do, so an empty buffer is the
	// normal case. Guard it anyway — a proxy that pipelined data would need a
	// wrapped reader, which we do not support (documented limitation).
	if br.Buffered() > 0 {
		return errors.New("http connect: proxy sent unexpected data before the tunnel opened")
	}
	return nil
}
