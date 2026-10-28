package teleport

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/stun"
)

// loopbackUDP listens on an IPv4 loopback UDP socket and closes it via
// t.Cleanup.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// closedLoopbackAddr returns the address of a loopback UDP socket that has
// already been closed, so probes to it are never answered.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	conn := loopbackUDP(t)
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

// testLogger returns an appLogger writing into a fresh buffer plus that
// buffer, so tests can assert on the emitted log lines.
func testLogger(t *testing.T, debug bool) (*appLogger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return newAppLogger(&buf, debug), &buf
}

// readUDP reads a single datagram from conn, waiting at most timeout.
func readUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:n], addr, nil
}

// parseAuthenticatedBindingRequest parses raw and requires a Binding Request
// whose MESSAGE-INTEGRITY validates against secret.
func parseAuthenticatedBindingRequest(raw []byte, secret string) (*stun.Message, error) {
	msg, ok := parseStunMessage(raw)
	if !ok {
		return nil, errors.New("invalid STUN message")
	}
	if msg.Type != stun.BindingRequest {
		return nil, fmt.Errorf("STUN message type = %s, want Binding Request", msg.Type)
	}
	if !validStunIntegrity(msg, secret) {
		return nil, errors.New("MESSAGE-INTEGRITY did not validate")
	}
	return msg, nil
}

// requireAuthenticatedBindingRequest is parseAuthenticatedBindingRequest for
// the test goroutine: it fails the test instead of returning an error.
func requireAuthenticatedBindingRequest(t *testing.T, raw []byte, secret string) *stun.Message {
	t.Helper()
	msg, err := parseAuthenticatedBindingRequest(raw, secret)
	if err != nil {
		t.Fatalf("want authenticated Binding Request: %v", err)
	}
	return msg
}

// replyStunBinding reads one datagram on conn within timeout, requires an
// authenticated Binding Request, and replies with Binding Success to its
// sender.
func replyStunBinding(conn *net.UDPConn, secret string, timeout time.Duration) error {
	raw, remote, err := readUDP(conn, timeout)
	if err != nil {
		return err
	}
	msg, err := parseAuthenticatedBindingRequest(raw, secret)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(stunBindingSuccess(msg, secret), remote)
	return err
}

// waitChan returns the next value sent on ch, failing the test if none
// arrives within timeout.
func waitChan[T any](t *testing.T, ch <-chan T, timeout time.Duration) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting on channel", timeout)
		var zero T
		return zero
	}
}
