package teleport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/pion/stun"
)

func parseXorMapped(data []byte) (string, bool) {
	var msg stun.Message
	msg.Raw = append(msg.Raw[:0], data...)
	if err := msg.Decode(); err != nil {
		return "", false
	}
	var addr stun.XORMappedAddress
	if err := addr.GetFrom(&msg); err != nil {
		return "", false
	}
	return net.JoinHostPort(addr.IP.String(), fmt.Sprint(addr.Port)), true
}

// stunServerFromIce returns the host and effective port of the first STUN URL
// in a fetched GET_ICE_CONFIGURATION server list.
func stunServerFromIce(ice []iceServer) (string, bool) {
	for _, s := range ice {
		for _, rawURL := range s.URLs {
			u, ok := parseConsoleICEURL(rawURL)
			if !ok || u.Scheme != "stun" || u.Hostname() == "" {
				continue
			}
			port := u.Port()
			if port == "" {
				port = "3478"
			}
			return net.JoinHostPort(u.Hostname(), port), true
		}
	}
	return "", false
}

// turnServerFromIce mirrors the console parser's important constraints. The
// recovered teleportd accepts the turn scheme only with transport=udp; turns
// and TCP/TLS relay URLs do not create its TURN worker.
func turnServerFromIce(ice []iceServer) (string, bool) {
	for _, s := range ice {
		for _, rawURL := range s.URLs {
			u, ok := parseConsoleICEURL(rawURL)
			if !ok || u.Scheme != "turn" || u.Hostname() == "" || u.Query().Get("transport") != "udp" {
				continue
			}
			port := u.Port()
			if port == "" {
				port = "3478"
			}
			return net.JoinHostPort(u.Hostname(), port), true
		}
	}
	return "", false
}

func parseConsoleICEURL(rawURL string) (*url.URL, bool) {
	// teleportd turns the first colon into :// before using net/url.Parse.
	normalized := strings.Replace(rawURL, ":", "://", 1)
	u, err := url.Parse(normalized)
	return u, err == nil
}

func stunNetwork(family networkFamily) (string, error) {
	switch family {
	case familyIPv4:
		return "udp4", nil
	case familyIPv6:
		return "udp6", nil
	default:
		return "", errors.New("a reflexive candidate requires an address family")
	}
}

func reflexiveCandidateFromConn(conn *net.UDPConn, ice []iceServer, family networkFamily) (candidate, error) {
	return reflexiveCandidateFromConnWithTimeout(conn, ice, family, 5*time.Second)
}

func reflexiveCandidateFromConnWithTimeout(conn *net.UDPConn, ice []iceServer, family networkFamily, timeout time.Duration) (candidate, error) {
	network, err := stunNetwork(family)
	if err != nil {
		return candidate{}, err
	}
	if conn == nil {
		return candidate{}, fmt.Errorf("no %s socket for reflexive candidate", network)
	}
	stunServer, ok := stunServerFromIce(ice)
	if !ok {
		return candidate{}, errors.New("ICE_CONFIGURATION supplied no console-compatible STUN endpoint")
	}
	addr, err := net.ResolveUDPAddr(network, stunServer)
	if err != nil {
		var dnsErr *net.DNSError
		if family == familyIPv6 && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return candidate{}, fmt.Errorf("STUN host %s has no AAAA record: %w", stunServer, err)
		}
		return candidate{}, err
	}
	req, _ := stunBindingProbe("")
	// This socket is later handed to WireGuard. Restrict only the STUN read:
	// SetDeadline would leave a write deadline behind and make all later
	// WireGuard sends fail once the discovery timeout expires. Clear even the
	// read-only deadline before handing the socket to nomination; otherwise a
	// listener already blocked in ReadFromUDP exits when this stale deadline
	// fires.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return candidate{}, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	if _, err := conn.WriteToUDP(req, addr); err != nil {
		return candidate{}, err
	}
	appLog.Debug("sent STUN discovery request", "network", network, "server", addr.String())
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return candidate{}, err
		}
		if from.String() != addr.String() {
			// Stray packet from something other than the STUN server; keep
			// reading until the deadline instead of failing the whole probe.
			continue
		}
		mapped, ok := parseXorMapped(buf[:n])
		if !ok {
			appLog.Debug("STUN response from server had no XOR-MAPPED-ADDRESS", "network", network, "server", addr.String())
			continue
		}
		appLog.Debug("received STUN discovery response", "network", network, "mapped_address", mapped)
		return candidate{Type: "reflex", Addr: mapped}, nil
	}
}

func parseStunMessage(data []byte) (*stun.Message, bool) {
	var msg stun.Message
	msg.Raw = append(msg.Raw[:0], data...)
	if err := msg.Decode(); err != nil {
		return nil, false
	}
	return &msg, true
}

func validStunIntegrity(msg *stun.Message, secret string) bool {
	return secret != "" && stun.NewShortTermIntegrity(secret).Check(msg) == nil
}

// stunBindingSuccess builds the Binding Success reply. secret is the session
// secret as sent to the peer, passed straight to Pion's MessageIntegrity; it
// is not a SHA-256 digest encoded as base64. An empty secret omits
// MESSAGE-INTEGRITY (unauthenticated discovery probes).
func stunBindingSuccess(req *stun.Message, secret string) []byte {
	var setters []stun.Setter
	setters = append(setters, stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess)
	if secret != "" {
		setters = append(setters, stun.NewShortTermIntegrity(secret))
	}
	msg := stun.MustBuild(setters...)
	return msg.Raw
}

// respondToStunBindingRequestAddrPort validates an inbound STUN Binding Request's
// MESSAGE-INTEGRITY, replies with Binding Success over conn, and feeds any
// nomination DATA payload to tracker. Zero allocations for address representation.
func respondToStunBindingRequestAddrPort(conn *net.UDPConn, msg *stun.Message, addrPort netip.AddrPort, secret string, tracker *nominationTracker) (response []byte, accepted bool) {
	if !validStunIntegrity(msg, secret) {
		appLog.Debug("discarded STUN request with invalid integrity", "remote", addrPort.String())
		return nil, false
	}
	if resp := stunBindingSuccess(msg, secret); resp != nil {
		if conn != nil {
			_, _ = conn.WriteToUDPAddrPort(resp, addrPort)
		}
		appLog.Debug("sent STUN success response", "remote", addrPort.String())
		response = resp
	}
	if tracker != nil {
		if waitMs, ok := stunNominationWait(msg); ok {
			appLog.Debug("nomination sequence progress", "remote", addrPort.String(), "wait_ms", waitMs)
			if tracker.observe(addrPort.String(), waitMs) {
				appLog.Info("nomination selected endpoint", "endpoint", addrPort.String())
			}
		}
	}
	return response, true
}

func respondToStunBindingRequest(conn *net.UDPConn, msg *stun.Message, addr *net.UDPAddr, secret string, tracker *nominationTracker) (response []byte, accepted bool) {
	if addr == nil {
		return nil, false
	}
	return respondToStunBindingRequestAddrPort(conn, msg, addr.AddrPort(), secret, tracker)
}

func isSTUN(data []byte) bool {
	return len(data) >= 20 &&
		(data[0] == 0x00 || data[0] == 0x01) &&
		binary.BigEndian.Uint32(data[4:8]) == 0x2112A442
}
