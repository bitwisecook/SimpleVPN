// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"unicode"

	"pxengine/routelang"
)

// Inputs are supplied by the fixture only. No process table, environment,
// socket, resolver or OS credential store is consulted.
func validateSocketFixture(fields map[string]routelang.Value) error {
	if v, ok := fields["socket.transport"]; ok && v.AsString() != "tcp" && v.AsString() != "udp" {
		return errors.New("socket.transport must be tcp or udp")
	}
	family, hasFamily := fields["socket.family"]
	if hasFamily && family.AsString() != "ipv4" && family.AsString() != "ipv6" {
		return errors.New("socket.family must be ipv4 or ipv6")
	}
	// Infer a constraint across supplied addresses without filling in any absent
	// evidence. Handlers that require an omitted family must still fail on read.
	for _, field := range []string{"socket.local_address", "socket.remote_address"} {
		if address, ok := fields[field]; ok {
			addressFamily := "ipv4"
			if address.AsAddr().Is6() {
				addressFamily = "ipv6"
			}
			if hasFamily && family.AsString() != addressFamily {
				return fmt.Errorf("%s disagrees with the socket address family", field)
			}
			family, hasFamily = routelang.String(addressFamily), true
		}
	}
	if port, ok := fields["socket.local_port"]; ok && (port.AsInt() < 0 || port.AsInt() > 65535) {
		return errors.New("socket.local_port must be 0–65535")
	}
	if port, ok := fields["socket.remote_port"]; ok && (port.AsInt() < 1 || port.AsInt() > 65535) {
		return errors.New("socket.remote_port must be 1–65535")
	}
	return validateProcessContext(fields)
}

func validateProcessContext(fields map[string]routelang.Value) error {
	if value, ok := fields["process.executable_name"]; ok {
		name := value.AsString()
		if name == "" || len(name) > 255 || name == "." || name == ".." || strings.Contains(name, "/") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return errors.New("process.executable_name must be an executable filename")
		}
	}
	if value, ok := fields["process.executable_path"]; ok && !validProcessPath(value.AsString()) {
		return errors.New("process.executable_path requires an absolute executable path")
	}
	if ancestors, ok := fields["process.ancestor_paths"]; ok {
		paths := ancestors.AsArray()
		if len(paths) > 8 {
			return errors.New("process.ancestor_paths supports up to eight paths")
		}
		for _, ancestor := range paths {
			if !validProcessPath(ancestor.AsString()) {
				return errors.New("process.ancestor_paths requires absolute executable paths")
			}
		}
	}
	variable, hasVariable := fields["process.proxy_variable"]
	if hasVariable && variable.AsString() != "HTTP_PROXY" && variable.AsString() != "http_proxy" {
		return errors.New("process.proxy_variable must be HTTP_PROXY or http_proxy")
	}
	expected, hasEndpoint := fields["process.expected_proxy_endpoint"]
	if hasEndpoint {
		canonical, ok := fixtureProxyEndpoint(expected.AsString())
		if !ok {
			return errors.New("process.expected_proxy_endpoint requires a credential-free HTTP proxy host and port")
		}
		fields["process.expected_proxy_endpoint"] = routelang.String(canonical)
	}
	if _, hasVerdict := fields["process.proxy_endpoint_matched"]; hasVerdict && (!hasVariable || !hasEndpoint) {
		return errors.New("a proxy comparison verdict requires its named variable and configured expected endpoint")
	}
	return nil
}

func validMemberID(id string) bool {
	if id == "" || len(id) > 80 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validProcessPath(s string) bool {
	return len(s) > 1 && len(s) < 1024 && strings.HasPrefix(s, "/") && path.Clean(s) == s &&
		strings.IndexFunc(s, unicode.IsControl) < 0
}

func fixtureProxyEndpoint(s string) (string, bool) {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, "@#?%\\") {
		return "", false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return "", false
		}
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if strings.Contains(s, "/") {
		return "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || port == "" {
		return "", false
	}
	for _, c := range []byte(port) {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || strings.HasPrefix(s, "[") != addr.Is6() {
			return "", false
		}
		host = addr.String()
	} else {
		if strings.HasPrefix(s, "[") || strings.IndexFunc(host, func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 {
			return "", false
		}
		dns, err := routelang.DNS(host)
		if err != nil {
			return "", false
		}
		host = dns.AsString()
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10)), true
}
