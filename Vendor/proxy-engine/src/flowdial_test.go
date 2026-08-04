// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// flowdial_test.go — the extension-dialled upstream (SimpleVPN's SSH Network
// Tunnel). There is no SSH server here and none is needed: what has to be proven
// is the HANDOFF — that a descriptor handed across the C boundary becomes a
// working net.Conn, that the original descriptor is released rather than leaked,
// and that every refusal code maps to a distinct, honest error.

package pxengine

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// socketpairFDs makes a connected pair of stream sockets, mimicking exactly what
// the Swift engine does per flow: it keeps one end (pumped against an SSH
// channel) and hands the other's raw fd to Go.
func socketpairFDs(t *testing.T) (ours, theirs int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return fds[0], fds[1]
}

// adoptFD is exactly the adoption half of extensionDialer.dial, factored out so
// it can be exercised without a C function pointer. If this and dial() ever
// diverge the divergence is the bug — dial()'s body is four lines longer than
// this and does nothing else.
func adoptFD(fd int, name string) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), name)
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return conn, nil
	}
	return conn, nil
}

func TestExtensionDialerAdoptsSocketpair(t *testing.T) {
	ours, theirs := socketpairFDs(t)
	// Our side stays a plain fd, like Swift's half.
	defer syscall.Close(ours)

	conn, err := adoptFD(theirs, "sshflow:test")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	defer conn.Close()

	// Bytes must flow both ways: this is the whole point of the fd handoff — Go
	// gets a REAL socket, so pipe()/copyCounted()/CloseWrite() need no special
	// case for this upstream.
	if _, err := syscall.Write(ours, []byte("from-ssh")); err != nil {
		t.Fatalf("write on the Swift side: %v", err)
	}
	buf := make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "from-ssh" {
		t.Fatalf("read through the adopted conn: n=%d err=%v got=%q", n, err, buf[:n])
	}

	if _, err := conn.Write([]byte("to-ssh")); err != nil {
		t.Fatalf("write through the adopted conn: %v", err)
	}
	nb, err := syscall.Read(ours, buf)
	if err != nil || string(buf[:nb]) != "to-ssh" {
		t.Fatalf("read on the Swift side: n=%d err=%v got=%q", nb, err, buf[:nb])
	}

	// Half-close must reach the peer as EOF — pipe() relies on it to drain the
	// other direction rather than tearing the flow down.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("the adopted conn must support CloseWrite (it is a real socket)")
	}
	if nb, err := syscall.Read(ours, buf); err != nil || nb != 0 {
		t.Fatalf("expected EOF on the Swift side after CloseWrite: n=%d err=%v", nb, err)
	}
}

// TestExtensionDialerReleasesTheHandedOverDescriptor is the fd-leak check. The
// adoption DUPS, so the descriptor Swift handed over must be closed immediately;
// otherwise every flow costs the extension one permanent descriptor and a
// long-lived tunnel eventually cannot open any.
func TestExtensionDialerReleasesTheHandedOverDescriptor(t *testing.T) {
	ours, theirs := socketpairFDs(t)
	defer syscall.Close(ours)

	conn, err := adoptFD(theirs, "sshflow:leak")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	defer conn.Close()

	// The ORIGINAL descriptor number must no longer be a live socket. fstat on a
	// closed fd is EBADF; on a still-open one it succeeds. (Nothing in this test
	// opens a file in between, so the number cannot have been recycled.)
	var st syscall.Stat_t
	if err := syscall.Fstat(theirs, &st); err == nil {
		t.Fatalf("fd %d is still open — the handed-over descriptor leaked", theirs)
	} else if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF for the released fd, got %v", err)
	}
}

func TestFlowDialRefusalCodes(t *testing.T) {
	cases := []struct {
		code     int
		contains string
	}{
		{flowRefuseGeneric, "could not open"},
		{flowRefuseNoUpstream, "no SSH session is configured"},
		{flowRefuseSessionDown, "reconnecting"},
		{flowRefuseServer, "refused to open the forward"},
		{flowRefuseTimeout, "did not open the forward in time"},
		{-99, "code -99"}, // an unknown negative is reported honestly, not guessed at
	}
	seen := map[string]bool{}
	for _, c := range cases {
		err := refusalError(c.code)
		if err == nil {
			t.Fatalf("code %d produced no error", c.code)
		}
		if !strings.Contains(err.Error(), c.contains) {
			t.Errorf("code %d: %q does not mention %q", c.code, err, c.contains)
		}
		if seen[err.Error()] {
			t.Errorf("code %d shares its message with another code — a refusal must name its own cause", c.code)
		}
		seen[err.Error()] = true
	}
	// The sentinels are comparable, which is what lets a caller distinguish
	// "reconnecting" (retryable) from "the server said no" (not).
	if !errors.Is(refusalError(flowRefuseSessionDown), errSessionDown) {
		t.Error("session-down must be the comparable sentinel")
	}
}

// TestExtensionDialerRefusesWithoutACallback: no registered dialler must be an
// immediate -2 refusal, never a hang. (The registry is process-global, so this
// test never registers one — PXStart's own guard is what users see.)
func TestExtensionDialerRefusesWithoutACallback(t *testing.T) {
	if hasFlowDialCallback() {
		t.Skip("a flow-dial callback is registered in this process")
	}
	_, err := extensionDialer{}.dial(context.Background(), nil, "example.com", 443)
	if !errors.Is(err, errNoUpstream) {
		t.Fatalf("expected the no-upstream refusal, got %v", err)
	}
}

// TestExtensionDialerHonoursACancelledContext: handleTCP dials under a bounded
// context, and a tunnel that is being torn down must not call into Swift at all.
func TestExtensionDialerHonoursACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (extensionDialer{}).dial(ctx, nil, "example.com", 443); err == nil {
		t.Fatal("a cancelled context must refuse before crossing the C boundary")
	}
}

func TestParseUpstreamSSH(t *testing.T) {
	// The ssh:// scheme: userinfo IS accepted (a login name, not a secret) and
	// the default port is 22.
	up, err := parseUpstream("ssh://alice@gateway.example", "", "")
	if err != nil {
		t.Fatalf("ssh:// must parse: %v", err)
	}
	if up.kind != proxySSHExtension {
		t.Fatalf("kind = %d, want proxySSHExtension", up.kind)
	}
	if up.address != "gateway.example:22" {
		t.Fatalf("address = %q, want gateway.example:22", up.address)
	}
	if up.username != "alice" {
		t.Fatalf("username = %q, want alice", up.username)
	}
	if up.kind.dialledInProcess() {
		t.Error("an ssh:// upstream must NOT be dialled in-process")
	}
	if schemeName(up.kind) != "ssh" {
		t.Errorf("schemeName = %q, want ssh", schemeName(up.kind))
	}

	// An explicit port wins.
	up, err = parseUpstream("ssh://gateway.example:2222", "", "")
	if err != nil || up.address != "gateway.example:2222" {
		t.Fatalf("explicit port: %v / %q", err, up.address)
	}

	// A PASSWORD in an ssh:// userinfo must never reach the engine: SSH secrets
	// travel in startTunnel options, and honouring one here would mean a saved
	// upstream string could carry a credential.
	up, err = parseUpstream("ssh://alice:hunter2@gateway.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if up.password != "" {
		t.Fatalf("ssh:// userinfo password leaked into the engine: %q", up.password)
	}
	// …but a proxy scheme still honours it (unchanged behaviour).
	up, _ = parseUpstream("socks5://bob:s3cret@proxy.example", "", "")
	if up.password != "s3cret" {
		t.Fatalf("socks5 userinfo password should still be honoured, got %q", up.password)
	}
}

func TestBuildEngineWiresTheExtensionDialer(t *testing.T) {
	up, err := parseUpstream("ssh://alice@gateway.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := buildEngine(up, 1500)
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	defer func() { st.cancel(); st.ep.Close(); st.stack.Close(); st.stack.Wait() }()

	// st.up MUST be nil: there is no proxy in this process, and the SOCKS UDP
	// path keys off exactly this.
	if st.up != nil {
		t.Error("st.up must be nil for an extension-dialled upstream")
	}
	if _, ok := st.flowDial.(extensionDialer); !ok {
		t.Errorf("flowDial = %T, want extensionDialer", st.flowDial)
	}
	if st.scheme != "ssh" {
		t.Errorf("scheme = %q, want ssh", st.scheme)
	}

	// And the proxy case still wires itself.
	pup, _ := parseUpstream("socks5://proxy.example:1080", "", "")
	pst, err := buildEngine(pup, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { pst.cancel(); pst.ep.Close(); pst.stack.Close(); pst.stack.Wait() }()
	if pst.up == nil {
		t.Error("a proxy upstream must keep its concrete st.up")
	}
	if _, ok := pst.flowDial.(*upstream); !ok {
		t.Errorf("flowDial = %T, want *upstream", pst.flowDial)
	}
}
