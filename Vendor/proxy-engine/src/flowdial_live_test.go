// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//go:build pxcgotest

// flowdial_live_test.go — the flow-dial handoff through the REAL C boundary.
//
// flowdial_test.go proves the adoption logic with `adoptFD`, a hand-copied twin of
// the four lines inside extensionDialer.dial. That leaves the boundary itself
// unproven: whether a genuine PXFlowDialCallback registered with
// PXSetFlowDialCallback is actually reached, whether the host and port survive the
// crossing, whether the descriptor it returns becomes a working net.Conn, and whether
// the original is released. Those are the things the SSH Network Tunnel depends on.
//
// The C callback lives in flowdial_cgotest.go (cgo is not allowed in _test.go files);
// both are behind the `pxcgotest` tag, which Tools/build-proxy-engine.sh runs.
//
// No SSH server is involved and none is needed: the callback hands back one end of a
// socketpair, exactly as SSHNetworkTunnelEngine.dialFlow does.

package pxengine

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestExtensionDialerCrossesTheRealCBoundary(t *testing.T) {
	t.Cleanup(testFlowDialInstall(0))

	if !hasFlowDialCallback() {
		t.Fatal("the registry did not see the registered callback")
	}

	conn, err := extensionDialer{}.dial(context.Background(), nil, "echo.internal", 7)
	if err != nil {
		t.Fatalf("dial through the C boundary: %v", err)
	}
	defer conn.Close()

	// The arguments survived the crossing. A dial that reached Swift with the wrong
	// host would open a channel to the wrong place — silently.
	if got := testFlowDialHost(); got != "echo.internal" {
		t.Errorf("callback saw host %q, want echo.internal", got)
	}
	if got := testFlowDialPort(); got != 7 {
		t.Errorf("callback saw port %d, want 7", got)
	}
	if got := testFlowDialCalls(); got != 1 {
		t.Errorf("callback ran %d times, want 1", got)
	}

	// THE HANDED-OVER DESCRIPTOR IS RELEASED. net.FileConn dups, so the original must
	// be closed at once; otherwise every flow costs the extension one permanent
	// descriptor and a long-lived tunnel eventually cannot open any.
	theirs := testFlowDialTheirsFD()
	var st syscall.Stat_t
	if err := syscall.Fstat(theirs, &st); err == nil {
		t.Errorf("fd %d is still open — the handed-over descriptor leaked", theirs)
	} else if !errors.Is(err, syscall.EBADF) {
		t.Errorf("expected EBADF for the released fd, got %v", err)
	}

	// Bytes flow both ways over the adopted conn — the whole point of handing back a
	// descriptor rather than inventing a callback byte pump.
	ours := testFlowDialOursFD()
	if _, err := syscall.Write(ours, []byte("from-ssh")); err != nil {
		t.Fatalf("write on the session side: %v", err)
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
		t.Fatalf("read on the session side: n=%d err=%v got=%q", nb, err, buf[:nb])
	}

	// Half-close must reach the session side as EOF: pipe() uses it to drain the other
	// direction instead of tearing the flow down, which is what lets a request/response
	// protocol get its answer at all.
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the adopted conn must support CloseWrite (it is a real socket)")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if nb, err := syscall.Read(ours, buf); err != nil || nb != 0 {
		t.Fatalf("expected EOF on the session side after CloseWrite: n=%d err=%v", nb, err)
	}
}

// TestExtensionDialerRefusalCrossesTheRealCBoundary: a negative return from the real
// callback must arrive as the matching comparable error, not as a generic failure —
// that is what lets handleTCP tell "reconnecting" from "the server said no".
func TestExtensionDialerRefusalCrossesTheRealCBoundary(t *testing.T) {
	t.Cleanup(testFlowDialInstall(flowRefuseSessionDown))

	conn, err := extensionDialer{}.dial(context.Background(), nil, "blocked.internal", 443)
	if conn != nil {
		conn.Close()
		t.Fatal("a refused dial must not produce a conn")
	}
	if !errors.Is(err, errSessionDown) {
		t.Fatalf("got %v, want the session-down sentinel", err)
	}
	if got := testFlowDialCalls(); got != 1 {
		t.Errorf("callback ran %d times, want 1", got)
	}
}

// TestExtensionDialerAdoptsManyFlowsWithoutLeaking dials repeatedly and closes each
// conn, then checks that descriptor numbers are not climbing — the signature of one
// leaked fd per flow, which only shows up after a tunnel has been up for a while.
func TestExtensionDialerAdoptsManyFlowsWithoutLeaking(t *testing.T) {
	t.Cleanup(testFlowDialInstall(0))

	dialOnce := func() int {
		conn, err := extensionDialer{}.dial(context.Background(), nil, "many.internal", 80)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		handedOver := testFlowDialTheirsFD()
		if err := conn.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		syscall.Close(testFlowDialOursFD())
		return handedOver
	}

	first := dialOnce()
	last := first
	for i := 0; i < 200; i++ {
		last = dialOnce()
	}
	// Descriptor numbers are reused when nothing leaks. A per-flow leak would push
	// `last` up by roughly the iteration count.
	if last > first+32 {
		t.Fatalf("descriptor numbers climbed from %d to %d over 200 flows — fds are leaking",
			first, last)
	}
}
