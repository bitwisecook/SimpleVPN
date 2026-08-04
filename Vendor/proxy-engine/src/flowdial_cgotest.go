// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//go:build pxcgotest

// flowdial_cgotest.go — a REAL PXFlowDialCallback for flowdial_live_test.go.
//
// WHY IT IS NOT IN THE TEST FILE: the go command refuses cgo in `_test.go` files
// ("use of cgo in test … not supported"), and a C function pointer is exactly what
// the flow-dial boundary needs to be exercised with. So the C half lives here,
// behind the `pxcgotest` build tag — which keeps it out of the shipped c-archive
// entirely while Tools/build-proxy-engine.sh runs one extra `go test -tags pxcgotest`
// pass to make sure it is not quietly rotting.
//
// The callback does what SSHNetworkTunnelEngine.dialFlow does: make a socketpair,
// keep one end, hand the other's raw descriptor back across the boundary.

package pxengine

/*
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int (*pxTestFn)(const char *host, int port);

static int pxTestOurs = -1;      // the end an SSH session would pump
static int pxTestTheirs = -1;    // the end handed across the boundary
static int pxTestCalls = 0;
static char pxTestHost[256];
static int pxTestPort = 0;
static int pxTestRefuse = 0;     // when non-zero, refuse with this code instead

static int pxTestDial(const char *host, int port) {
	pxTestCalls++;
	pxTestHost[0] = '\0';
	if (host != NULL) {
		snprintf(pxTestHost, sizeof pxTestHost, "%s", host);
	}
	pxTestPort = port;
	if (pxTestRefuse != 0) {
		return pxTestRefuse;
	}
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		return -1;
	}
	pxTestOurs = fds[0];
	pxTestTheirs = fds[1];
	return fds[1];
}

// Registration happens in C, through the ordinary exported entry point. It has to:
// each Go file's `import "C"` has its OWN C scope, so PXFlowDialCallback — declared
// in flowdial.go's preamble — is not a name this file can use from Go. Declaring the
// exported function with an identically-shaped typedef is exact in C, and it means
// the test drives the same registry every real caller does.
extern void PXSetFlowDialCallback(pxTestFn dial);

static void pxTestInstall(void) { PXSetFlowDialCallback(pxTestDial); }
static void pxTestUninstall(void) { PXSetFlowDialCallback(NULL); }

static void pxTestReset(int refuse) {
	if (pxTestOurs >= 0) { close(pxTestOurs); pxTestOurs = -1; }
	pxTestTheirs = -1;
	pxTestCalls = 0;
	pxTestPort = 0;
	pxTestHost[0] = '\0';
	pxTestRefuse = refuse;
}

static int pxTestOursFD(void) { return pxTestOurs; }
static int pxTestTheirsFD(void) { return pxTestTheirs; }
static int pxTestCallCount(void) { return pxTestCalls; }
static int pxTestPortSeen(void) { return pxTestPort; }
static const char *pxTestHostSeen(void) { return pxTestHost; }
*/
import "C"

// testFlowDialInstall registers the C callback above through PXSetFlowDialCallback
// and returns the teardown the test defers — which unregisters again, so the
// "no callback registered" test elsewhere in this package keeps its meaning.
// `refuse`, when non-zero, is the refusal code the callback returns instead of a
// descriptor.
func testFlowDialInstall(refuse int) (restore func()) {
	C.pxTestReset(C.int(refuse))
	C.pxTestInstall()
	return func() {
		C.pxTestUninstall()
		C.pxTestReset(0)
	}
}

// What the callback was asked for, and the descriptors it produced.
func testFlowDialHost() string  { return C.GoString(C.pxTestHostSeen()) }
func testFlowDialPort() int     { return int(C.pxTestPortSeen()) }
func testFlowDialCalls() int    { return int(C.pxTestCallCount()) }
func testFlowDialOursFD() int   { return int(C.pxTestOursFD()) }
func testFlowDialTheirsFD() int { return int(C.pxTestTheirsFD()) }
