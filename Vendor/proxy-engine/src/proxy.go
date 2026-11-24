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
// SOCKS wire encoding uses SagerNet sing. HTTP and TLS use the Go standard library.

package pxengine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
	// proxySSHExtension is not a proxy this file dials at all: the transport is
	// an SSH session owned by the Swift extension, and each flow is opened by a
	// callback into it (flowdial.go). It appears here only so ONE parser
	// validates every upstream URL the engine accepts, and so schemeName() has
	// an honest answer for PXStatus.
	proxySSHExtension
)

func (k proxyKind) tcpOnly() bool { return k != proxySOCKS5 }

// dialledInProcess is false for the upstream families this file does NOT dial.
// Everything keyed off it (the concrete st.up, the SOCKS UDP-ASSOCIATE path)
// must tolerate its absence.
func (k proxyKind) dialledInProcess() bool { return k != proxySSHExtension }

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
		// url.Error includes the entire input, which can contain credentials.
		return nil, errors.New("upstream proxy URL is invalid")
	}
	var kind proxyKind
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		kind = proxySOCKS5
	case "http":
		kind = proxyHTTPConnect
	case "https":
		kind = proxyHTTPSConnect
	case "ssh":
		// SimpleVPN's SSH Network Tunnel: the session is Swift's, so nothing in
		// this file will dial it. Userinfo IS accepted here (unlike the proxy
		// schemes, which refuse it) because an SSH URL's userinfo is the LOGIN
		// NAME, not a secret — `ssh://alice@gateway.example` is how everyone
		// writes it, and refusing it would be refusing the ordinary spelling.
		// A password in the userinfo would still be a secret, so parseUpstream
		// takes only the username half below and drops any password component.
		kind = proxySSHExtension
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5://, http://, https:// or ssh://)", u.Scheme)
	}
	if (u.EscapedPath() != "" && u.EscapedPath() != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("use a proxy endpoint without a path, query or fragment")
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("upstream URL has no host")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, errors.New("proxy port must be between 1 and 65535")
		}
	}
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
		case proxySSHExtension:
			port = "22"
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
			// An ssh:// URL never yields a password: SSH secrets arrive through
			// startTunnel options, and honouring one here would mean a password
			// could reach the engine from the SAVED upstream string.
			if p, ok := ui.Password(); ok && up.password == "" && kind != proxySSHExtension {
				up.password = p
			}
		}
	}
	if kind != proxySSHExtension {
		if (up.username == "") != (up.password == "") {
			return nil, errors.New("proxy authentication requires both username and password")
		}
		if kind == proxySOCKS5 {
			if len(up.username) > 255 || len(up.password) > 255 {
				return nil, errors.New("SOCKS5 credentials exceed 255 bytes")
			}
		} else {
			control := func(c rune) bool { return c < 32 || c == 127 }
			if strings.Contains(up.username, ":") || strings.IndexFunc(up.username, control) >= 0 || strings.IndexFunc(up.password, control) >= 0 {
				return nil, errors.New("invalid HTTP Basic credential format")
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
	raw := conn
	stopCancel := context.AfterFunc(ctx, func() { raw.Close() })
	switch up.kind {
	case proxySOCKS5:
		_, err = up.socksHandshake(conn, socks5.CommandConnect, targetHost, targetPort)
	default:
		conn, err = httpConnect(conn, targetHost, targetPort, up.username, up.password)
	}
	if !stopCancel() {
		raw.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	// Clear the handshake deadline: the flow itself is governed by the guest's
	// own timeouts and our idle copy, not this one-shot dial budget.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ---- SOCKS5 (RFC 1928 / RFC 1929) ------------------------------------------

// Use the upstream codecs for both CONNECT and UDP ASSOCIATE. Bind the server's
// selection to the profile's authentication method before sending any secret.
func (up *upstream) socksHandshake(conn net.Conn, command byte, host string, port int) (metadata.Socksaddr, error) {
	var empty metadata.Socksaddr
	if host == "" || len(host) > 255 || port < 0 || port > 65535 {
		return empty, errors.New("invalid SOCKS target")
	}
	method := socks5.AuthTypeNotRequired
	if up.username != "" {
		if len(up.username) > 255 || len(up.password) > 255 {
			return empty, errors.New("SOCKS credentials exceed 255 bytes")
		}
		method = socks5.AuthTypeUsernamePassword
	}
	if err := socks5.WriteAuthRequest(conn, socks5.AuthRequest{Methods: []byte{method}}); err != nil {
		return empty, err
	}
	reader := varbin.StubReader(conn)
	auth, err := socks5.ReadAuthResponse(reader)
	if err != nil {
		return empty, err
	}
	if auth.Method != method {
		return empty, errors.New("SOCKS proxy did not accept the configured authentication method")
	}
	if method == socks5.AuthTypeUsernamePassword {
		err = socks5.WriteUsernamePasswordAuthRequest(conn, socks5.UsernamePasswordAuthRequest{Username: up.username, Password: up.password})
		if err != nil {
			return empty, err
		}
		reply, err := socks5.ReadUsernamePasswordAuthResponse(reader)
		if err != nil {
			return empty, err
		}
		if reply.Status != socks5.UsernamePasswordStatusSuccess {
			return empty, errors.New("SOCKS username/password rejected")
		}
	}
	destination := metadata.ParseSocksaddrHostPort(host, uint16(port))
	if err := socks5.WriteRequest(conn, socks5.Request{Command: command, Destination: destination}); err != nil {
		return empty, err
	}
	// sing deliberately ignores RSV. Reject extensions to the advertised
	// protocol before consuming the returned relay address.
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return empty, err
	}
	if header[2] != 0 {
		return empty, errors.New("invalid SOCKS reserved byte")
	}
	reply, err := socks5.ReadResponse(varbin.StubReader(io.MultiReader(bytes.NewReader(header[:]), conn)))
	if err != nil {
		return empty, err
	}
	if reply.ReplyCode == socks5.ReplyCodeUnsupported {
		return empty, errors.New("SOCKS command not supported")
	}
	if reply.ReplyCode != socks5.ReplyCodeSuccess {
		return empty, fmt.Errorf("SOCKS request rejected (code %d)", reply.ReplyCode)
	}
	return reply.Bind, nil
}

// ---- HTTP CONNECT ----------------------------------------------------------

const maxConnectHeaders = 64 * 1024

// Server-first protocols can send their greeting in the same read as the
// CONNECT response. Preserve those bytes and the stream's TCP half-close.
type prefixedConn struct {
	net.Conn
	readMu sync.Mutex
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	if len(c.prefix) != 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		c.readMu.Unlock()
		return n, nil
	}
	c.readMu.Unlock()
	return c.Conn.Read(p)
}

func (c *prefixedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

func httpConnect(conn net.Conn, targetHost string, targetPort int, username, password string) (net.Conn, error) {
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	if targetPort < 1 || targetPort > 65535 || (!metadata.ParseAddr(targetHost).IsValid() && !metadata.IsDomainName(targetHost)) {
		return nil, errors.New("invalid HTTP CONNECT destination")
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("http connect: write: %w", err)
	}
	// ReadResponse on its own permits unbounded header lines. Bound only the
	// handshake and pass any buffered bytes on to the tunnel on success.
	limit := &io.LimitedReader{R: conn, N: maxConnectHeaders}
	br := bufio.NewReader(limit)
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			if limit.N == 0 {
				return nil, errors.New("http connect: response headers too large")
			}
			// A protocol error can include a proxy-generated header or status line.
			return nil, errors.New("http connect: incomplete or invalid proxy response")
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			continue
		}
		// Draining an error body would wait on a tunnel we have already refused.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("http connect: proxy returned %d", resp.StatusCode)
		}
		break
	}
	if br.Buffered() != 0 {
		prefix, _ := br.Peek(br.Buffered())
		return &prefixedConn{Conn: conn, prefix: prefix}, nil
	}
	return conn, nil
}
