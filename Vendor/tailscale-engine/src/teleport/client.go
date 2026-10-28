// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package teleport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/crypto/curve25519"
)

// Session is the reusable identity, stored only in the app's user Keychain.
// Ephemeral WireGuard keys and ICE credentials are regenerated on every connect.
type Session struct {
	Token  string `json:"session_token"`
	Secret string `json:"session_secret"`
}

func (s Session) Valid() bool {
	return s.Token != "" && s.Secret != "" && len(s.Token) <= 4096 && len(s.Secret) <= 4096
}

// Pair redeems an invite once. It never creates a session file or logs secrets.
func Pair(ctx context.Context, invite, name string) (Session, error) {
	return pair(ctx, invite, name, apiRequestFunc(ctx), 2*time.Second)
}

func pair(ctx context.Context, invite, name string, request func(string, string, string, interface{}) (*apiResponse, error), interval time.Duration) (Session, error) {
	invite, err := normalizeInviteSecret(invite)
	if err != nil {
		return Session{}, errors.New("Enter a Teleport invite UUID or https://teleport.ui.link/<UUID> link.")
	}
	if strings.TrimSpace(name) == "" || len(name) > 128 {
		return Session{}, errors.New("Enter a device name of at most 128 bytes.")
	}
	token, err := secretToToken(invite)
	if err != nil {
		return Session{}, errors.New("Teleport could not derive the invite token.")
	}
	access, err := request("POST", "/", "", apiEnvelope{Token: token, Payload: map[string]interface{}{"request_type": "REQUEST_ACCESS", "secret": invite, "client_id": randomUUID(), "client_name": name}})
	if err != nil {
		return Session{}, err
	}
	if access.TeleportRequestID == "" {
		return Session{}, errors.New("Teleport did not accept the invite.")
	}
	poll, err := pollForResponseWithContext(ctx, request, token, access.TeleportRequestID, "ACCESS_GRANTED", interval, 60)
	if err != nil {
		return Session{}, err
	}
	if poll == nil {
		return Session{}, errors.New("Teleport did not grant access. Create a fresh invite and try again.")
	}
	session := Session{Token: poll.Token, Secret: poll.Secret}
	if !session.Valid() {
		return Session{}, errors.New("Teleport returned an incomplete session.")
	}
	// Cleanup is best effort; returning the only reusable identity takes priority.
	_, _ = request("DELETE", "/"+access.TeleportRequestID, token, nil)
	return session, nil
}

// Connection supplies transport and fresh configuration to the ONE shared
// WireGuard implementation. It owns no WireGuard device and no IP netstack.
type Connection struct {
	PrivateKey, PublicKey, Endpoint string
	Addresses, DNS                  []string
	Port                            int
	Bind                            conn.Bind
	sockets                         *udpSockets
	owner                           conn.Bind
}

func (c *Connection) Close() {
	if c.Bind != nil {
		_ = c.Bind.Close()
	}
	// Clear the physical transport's references as well: a stopped virtual
	// member must not break the remaining ports' next interface-scope update.
	if c.owner != nil {
		_ = c.owner.Close()
	}
	c.sockets.Close()
}

// Prepare keeps the very same UDP sockets throughout discovery, nomination and
// WireGuard. sender optionally scopes sends to the virtual router's underlay.
func Prepare(ctx context.Context, session Session, name string, v4, v6 *net.UDPConn, sender conn.Bind) (*Connection, error) {
	return prepare(ctx, session, name, v4, v6, sender, apiRequestFunc(ctx))
}

func prepare(ctx context.Context, session Session, name string, v4, v6 *net.UDPConn, sender conn.Bind, request requestFunc) (*Connection, error) {
	sockets := &udpSockets{V4: v4, V6: v6}
	success := false
	defer func() {
		if !success {
			if sender != nil {
				_ = sender.Close()
			}
			sockets.Close()
		}
	}()
	if !session.Valid() {
		return nil, errors.New("Pair this Teleport VPN with a fresh invite first.")
	}
	if v4 == nil && v6 == nil {
		return nil, errors.New("Teleport requires a UDP socket.")
	}
	port := 0
	if v4 != nil {
		port = v4.LocalAddr().(*net.UDPAddr).Port
	} else {
		port = v6.LocalAddr().(*net.UDPAddr).Port
	}
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return nil, err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	ice, err := fetchICEConfiguration(ctx, session.Token, session.Secret, request)
	if err != nil {
		return nil, err
	}
	family := familyDual
	if v6 == nil {
		family = familyIPv4
	} else if v4 == nil {
		family = familyIPv6
	}
	local := gatherLocalCandidates(sockets, port, family, ice)
	if len(local) == 0 {
		return nil, errors.New("Teleport found no usable network candidates.")
	}
	secret := randomB64(32)
	tracker := newNominationTracker()
	early := newEarlyNominationListener(sockets, secret, tracker)
	early.Start()
	defer early.Stop()
	response, err := connectAndAwaitResponse(ctx, sessionResult{Token: session.Token, Secret: session.Secret}, name, base64.StdEncoding.EncodeToString(public), secret, local, ice, request)
	if err != nil {
		return nil, err
	}
	endpoint, _, _, _, err := negotiateEndpoint(ctx, "", false, sockets, port, response, secret, tracker, early, local)
	if err != nil {
		return nil, err
	}
	if _, err = netip.ParseAddrPort(endpoint); err != nil {
		return nil, errors.New("Teleport returned an invalid endpoint.")
	}
	if key, err := base64.StdEncoding.DecodeString(response.ServerInfo.WGPubKey); err != nil || len(key) != 32 {
		return nil, errors.New("Teleport returned an invalid peer key.")
	}
	var addresses []string
	for _, raw := range []string{response.ClientIP, response.ServerInfo.TunnelAddr} {
		if raw == "" {
			continue
		}
		address, err := netip.ParseAddr(raw)
		if err != nil || address.IsUnspecified() || address.IsMulticast() {
			return nil, errors.New("Teleport returned an invalid tunnel address.")
		}
		addresses = append(addresses, fmt.Sprintf("%s/%d", address, address.BitLen()))
	}
	if len(addresses) == 0 {
		return nil, errors.New("Teleport did not assign a tunnel address.")
	}
	var dns []string
	for _, raw := range response.DNSAddrs {
		if address, err := netip.ParseAddr(raw); err == nil && !address.IsUnspecified() && !address.IsMulticast() {
			dns = append(dns, address.String())
		} else {
			return nil, errors.New("Teleport returned an invalid DNS server.")
		}
	}
	if len(dns) == 0 {
		dns = []string{"192.168.88.1"}
	} // upstream console fallback
	success = true
	return &Connection{PrivateKey: base64.StdEncoding.EncodeToString(private), PublicKey: response.ServerInfo.WGPubKey, Endpoint: endpoint, Addresses: addresses, DNS: dns, Port: port,
		Bind: &stunBind{sender: sender, conn4: v4, conn6: v6, stunSecret: secret, nomination: tracker}, sockets: sockets, owner: sender}, nil
}
