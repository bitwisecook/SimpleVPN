package teleport

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/stun"
)

func TestSTUNNetworkFollowsFamily(t *testing.T) {
	for _, tt := range []struct {
		family networkFamily
		want   string
	}{
		{familyIPv4, "udp4"},
		{familyIPv6, "udp6"},
	} {
		got, err := stunNetwork(tt.family)
		if err != nil || got != tt.want {
			t.Fatalf("stunNetwork(%v) = (%q, %v), want (%q, nil)", tt.family, got, err, tt.want)
		}
	}
	if _, err := stunNetwork(familyDual); err == nil {
		t.Fatal("stunNetwork(familyDual) unexpectedly succeeded")
	}
}

func TestConsoleCompatibleICEServerParsing(t *testing.T) {
	ice := []iceServer{{
		URLs: []string{
			"stun:stun.example:19302",
			"turn:turn.example:3478?transport=udp",
		},
	}}
	if got, ok := stunServerFromIce(ice); !ok || got != "stun.example:19302" {
		t.Fatalf("stunServerFromIce = (%q, %v), want (%q, true)", got, ok, "stun.example:19302")
	}
	if got, ok := turnServerFromIce(ice); !ok || got != "turn.example:3478" {
		t.Fatalf("turnServerFromIce = (%q, %v), want (%q, true)", got, ok, "turn.example:3478")
	}
}

func TestTurnServerRequiresConsoleSupportedUDPURL(t *testing.T) {
	for _, rawURL := range []string{
		"turn:turn.example:3478",
		"turn:turn.example:3478?transport=tcp",
		"turns:turn.example:5349?transport=udp",
	} {
		if got, ok := turnServerFromIce([]iceServer{{URLs: []string{rawURL}}}); ok {
			t.Fatalf("turnServerFromIce(%q) = (%q, true), want unsupported", rawURL, got)
		}
	}
}

func TestValidateTurnPrerequisitesPreservesReflexCandidate(t *testing.T) {
	ice := []iceServer{{URLs: []string{
		"stun:stun.example:3478",
		"turn:turn.example:3478?transport=udp",
	}}}
	if err := validateTurnPrerequisites(ice, []candidate{{Type: "reflex", Addr: "203.0.113.10:5000"}}); err != nil {
		t.Fatalf("valid TURN prerequisites rejected: %v", err)
	}
	if err := validateTurnPrerequisites(ice, []candidate{{Type: "iface", Addr: "192.168.1.10:5000"}}); err == nil {
		t.Fatal("TURN prerequisites accepted without a reflex candidate")
	}
}

func TestReflexiveDiscoveryClearsReadDeadline(t *testing.T) {
	server := loopbackUDP(t)
	client := loopbackUDP(t)

	serverErr := make(chan error, 1)
	go func() {
		buf, peer, err := readUDP(server, 5*time.Second)
		if err != nil {
			serverErr <- err
			return
		}
		request, ok := parseStunMessage(buf)
		if !ok {
			serverErr <- errors.New("test server received invalid STUN request")
			return
		}
		response := stun.MustBuild(
			stun.NewTransactionIDSetter(request.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.IPv4(203, 0, 113, 10), Port: 45678},
		)
		_, err = server.WriteToUDP(response.Raw, peer)
		serverErr <- err
	}()

	ice := []iceServer{{URLs: []string{"stun:" + server.LocalAddr().String()}}}
	if _, err := reflexiveCandidateFromConnWithTimeout(client, ice, familyIPv4, 200*time.Millisecond); err != nil {
		t.Fatalf("reflexive discovery failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("STUN server failed: %v", err)
	}

	// Wait past the discovery timeout (200ms) so a leftover read deadline
	// would fire, then prove the same socket can still receive nomination
	// traffic. Before the fix ReadFromUDP returned an immediate timeout here.
	time.Sleep(350 * time.Millisecond)
	if _, err := server.WriteToUDP([]byte("nomination"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		_, _, err := client.ReadFromUDP(buf)
		readResult <- err
	}()
	if err := waitChan(t, readResult, time.Second); err != nil {
		t.Fatalf("socket retained discovery read deadline: %v", err)
	}
}
