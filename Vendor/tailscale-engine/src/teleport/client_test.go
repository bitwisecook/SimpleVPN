package teleport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/pion/stun"
	"github.com/tailscale/wireguard-go/conn"
	"net"
	"testing"
	"time"
)

type trackedTransport struct {
	conn.Bind
	closed bool
}

func (t *trackedTransport) Close() error { t.closed = true; return nil }

func TestConnectionReleasesItsPhysicalTransport(t *testing.T) {
	owner := &trackedTransport{}
	connection := &Connection{sockets: &udpSockets{V4: loopbackUDP(t)}, owner: owner}
	connection.Close()
	if !owner.closed {
		t.Fatal("stopped Teleport port retained its physical transport sockets")
	}
}

func TestPairRedeemsInviteAndReturnsReusableSession(t *testing.T) {
	var calls []string
	request := func(method, path, token string, body interface{}) (*apiResponse, error) {
		calls = append(calls, method+" "+path)
		switch method {
		case "POST":
			envelope := body.(apiEnvelope)
			payload := envelope.Payload.(map[string]interface{})
			if payload["request_type"] != "REQUEST_ACCESS" || payload["secret"] != "b9e5a976-3ca6-45fb-85ba-bd30ce1d5527" || envelope.Token == "" || token != "" {
				t.Fatal("invalid invite exchange")
			}
			return &apiResponse{TeleportRequestID: "request"}, nil
		case "GET":
			return &apiResponse{ResponseType: "ACCESS_GRANTED", Token: "reusable-token", Secret: "reusable-secret"}, nil
		default:
			return nil, errors.New("cleanup unavailable")
		}
	}
	session, err := pair(context.Background(), "https://teleport.ui.link/B9E5A976-3CA6-45FB-85BA-BD30CE1D5527", "SimpleVPN", request, time.Nanosecond)
	if err != nil || session.Token != "reusable-token" || session.Secret != "reusable-secret" {
		t.Fatalf("pair failed: %v", err)
	}
	if len(calls) != 3 || calls[2] != "DELETE /request" {
		t.Fatal("request cleanup missing")
	}
}

func TestReconnectUsesSavedSessionAndNegotiatesFreshWireGuardConfiguration(t *testing.T) {
	session := Session{Token: "saved-token", Secret: "saved-secret"}
	var previousKey string
	for attempt := 0; attempt < 2; attempt++ {
		local, peer := loopbackUDP(t), loopbackUDP(t)
		var stunSecret, advertisedPublic string
		request := func(method, path, token string, body interface{}) (*apiResponse, error) {
			if method == "DELETE" {
				return &apiResponse{}, nil
			}
			if method == "POST" {
				envelope := body.(apiEnvelope)
				payload := envelope.Payload.(map[string]interface{})
				if envelope.Token != session.Token || payload["secret"] != session.Secret {
					t.Fatal("saved session was not reused")
				}
				switch payload["request_type"] {
				case "GET_ICE_CONFIGURATION":
					return &apiResponse{TeleportRequestID: "ice"}, nil
				case "CONNECT":
					info := payload["client_info"].(map[string]interface{})
					stunSecret = info["stun_session_secret"].(string)
					advertisedPublic = info["wg_pub_key"].(string)
					return &apiResponse{TeleportRequestID: "connect"}, nil
				default:
					t.Fatal("reconnect tried to redeem an invite")
				}
			}
			if token != session.Token {
				t.Fatal("poll did not authenticate with the saved session")
			}
			switch path {
			case "/ice":
				return &apiResponse{ResponseType: "ICE_CONFIGURATION", IceConfiguration: []iceServer{{}}}, nil
			case "/connect":
				for _, wait := range nominationWaitSequence {
					msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.RawAttribute{Type: stun.AttrData, Value: []byte(fmt.Sprintf(`{"wait":%d}`, wait))}, stun.NewShortTermIntegrity(stunSecret))
					if _, err := peer.WriteToUDP(msg.Raw, local.LocalAddr().(*net.UDPAddr)); err != nil {
						return nil, err
					}
				}
				return &apiResponse{ResponseType: "CONNECT_RESPONSE", ClientIP: "192.168.88.5", DNSAddrs: []string{"192.168.88.1"}, ServerInfo: serverInfo{
					TunnelAddr: "fd00::5", WGPubKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
					PeerDesc: peerDesc{Candidates: []candidate{{Type: "iface", Addr: peer.LocalAddr().String()}}}}}, nil
			}
			return nil, errors.New("unexpected API request")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		connection, err := prepare(ctx, session, "SimpleVPN", local, nil, nil, request)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if connection.Endpoint != peer.LocalAddr().String() || len(connection.Addresses) != 2 || connection.DNS[0] != "192.168.88.1" || advertisedPublic == "" {
			t.Fatal("negotiated WireGuard configuration was lost")
		}
		if connection.PrivateKey == previousKey {
			t.Fatal("reconnect reused an ephemeral WireGuard private key")
		}
		previousKey = connection.PrivateKey
		functions, port, err := connection.Bind.Open(uint16(connection.Port))
		if err != nil || len(functions) != 1 || int(port) != local.LocalAddr().(*net.UDPAddr).Port {
			t.Fatal("nomination socket was not handed to WireGuard")
		}
		_ = connection.Bind.Close()
		connection.Close()
	}
}

func TestNominatedSocketHandoffFiltersSTUNAndKeepsTheTuple(t *testing.T) {
	local, peer := loopbackUDP(t), loopbackUDP(t)
	bind := &stunBind{conn4: local, stunSecret: "secret", nomination: newNominationTracker()}
	t.Cleanup(func() { _ = bind.Close() })
	port := uint16(local.LocalAddr().(*net.UDPAddr).Port)
	functions, actual, err := bind.Open(port)
	if err != nil || actual != port || len(functions) != 1 {
		t.Fatal("nominated socket was not retained")
	}
	packet := []byte{4, 0, 0, 0, 1, 2, 3, 4}
	received := make(chan error, 1)
	go func() {
		slab := make([]byte, 65535)
		packets := make([]conn.ReceivedPacket, 1)
		n, err := functions[0](slab, packets)
		if err == nil && (n != 1 || !bytes.Equal(packets[0].Bytes(slab), packet) || packets[0].Endpoint.DstToString() != peer.LocalAddr().String()) {
			err = errors.New("WireGuard datagram was changed")
		}
		received <- err
	}()
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewShortTermIntegrity("secret"))
	if _, err = peer.WriteToUDP(request.Raw, local.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	raw, source, err := readUDP(peer, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := parseStunMessage(raw)
	if !ok || response.Type != stun.BindingSuccess || !validStunIntegrity(response, "secret") || source.String() != local.LocalAddr().String() {
		t.Fatal("STUN response changed its tuple or authentication")
	}
	_, _ = peer.WriteToUDP(packet, local.LocalAddr().(*net.UDPAddr))
	if err = waitChan(t, received, time.Second); err != nil {
		t.Fatal(err)
	}
	endpoint, err := bind.ParseEndpoint(peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = bind.Send([][]byte{append([]byte{99, 99}, packet...)}, endpoint, 2); err != nil {
		t.Fatal(err)
	}
	raw, source, err = readUDP(peer, time.Second)
	if err != nil || !bytes.Equal(raw, packet) || source.String() != local.LocalAddr().String() {
		t.Fatal("outbound WireGuard packet changed its payload or nominated UDP tuple")
	}
	go func() {
		slab := make([]byte, 65535)
		packets := make([]conn.ReceivedPacket, 1)
		_, err := functions[0](slab, packets)
		received <- err
	}()
	_ = bind.Close()
	if err = waitChan(t, received, time.Second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close did not unblock the shared WireGuard reader: %v", err)
	}
}

func TestPairRejectsIncompleteIdentityAndUntrustedInvites(t *testing.T) {
	request := func(method, path, token string, body interface{}) (*apiResponse, error) {
		if method == "POST" {
			return &apiResponse{TeleportRequestID: "request"}, nil
		}
		return &apiResponse{ResponseType: "ACCESS_GRANTED", Token: "missing-secret"}, nil
	}
	if _, err := pair(context.Background(), "b9e5a976-3ca6-45fb-85ba-bd30ce1d5527", "SimpleVPN", request, time.Nanosecond); err == nil {
		t.Fatal("accepted incomplete identity")
	}
	for _, invite := range []string{"http://teleport.ui.link/b9e5a976-3ca6-45fb-85ba-bd30ce1d5527", "https://evil.invalid/b9e5a976-3ca6-45fb-85ba-bd30ce1d5527"} {
		if _, err := pair(context.Background(), invite, "SimpleVPN", request, time.Nanosecond); err == nil {
			t.Fatal("accepted untrusted invite")
		}
	}
}
