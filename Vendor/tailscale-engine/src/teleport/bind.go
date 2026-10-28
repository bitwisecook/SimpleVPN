package teleport

import (
	"fmt"
	"github.com/pion/stun"
	"github.com/tailscale/wireguard-go/conn"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// udpSockets are opened for candidate discovery and nomination, then handed
// to wireguard-go through stunBind so STUN and WireGuard retain the same NAT
// mappings and UDP tuples.
type udpSockets struct {
	V4 *net.UDPConn
	V6 *net.UDPConn
}

func (s *udpSockets) Close() {
	if s == nil {
		return
	}
	if s.V4 != nil {
		_ = s.V4.Close()
	}
	if s.V6 != nil {
		_ = s.V6.Close()
	}
}

// stunBind wraps an existing STUN UDP socket as a conn.Bind for wireguard-go.
// It handles STUN Binding Requests inline and passes only WireGuard packets to
// wireguard-go.
type stunBind struct {
	sender     conn.Bind
	conn4      *net.UDPConn
	conn6      *net.UDPConn
	stunSecret string
	mu         sync.Mutex
	done       chan struct{}

	stunCount  atomic.Uint64
	recvCount  atomic.Uint64
	nomination *nominationTracker
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Fresh lifecycle for this Open; also clear any read deadline a prior
	// Close set so the receive loops can read again after a rebind.
	b.mu.Lock()
	b.done = make(chan struct{})
	done := b.done
	b.mu.Unlock()
	var fns []conn.ReceiveFunc
	if b.conn4 != nil {
		_ = b.conn4.SetReadDeadline(time.Time{})
		fns = append(fns, b.makeRecvFunc(b.conn4, done))
	}
	if b.conn6 != nil {
		_ = b.conn6.SetReadDeadline(time.Time{})
		fns = append(fns, b.makeRecvFunc(b.conn6, done))
	}
	appLog.Debug("WireGuard UDP bind opened", "port", port, "receive_loops", len(fns))
	return fns, port, nil
}

func (b *stunBind) handleSTUN(c *net.UDPConn, data []byte, addrPort netip.AddrPort) {
	msg, ok := parseStunMessage(data)
	if !ok {
		return
	}
	if appLog.IsDebug() {
		n := b.stunCount.Add(1)
		appLog.Debug("received STUN packet", "type", msg.Type.String(), "remote", addrPort.String(), "count", n)
	}
	if msg.Type == stun.BindingRequest {
		respondToStunBindingRequestAddrPort(c, msg, addrPort, b.stunSecret, b.nomination)
	}
}

func (b *stunBind) makeRecvFunc(c *net.UDPConn, done chan struct{}) conn.ReceiveFunc {
	var last *conn.StdNetEndpoint
	return func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		for {
			n, addrPort, err := c.ReadFromUDPAddrPort(slab)
			if err != nil {
				// If Close() woke us (deadline/socket close), report ErrClosed so
				// wireguard-go's receive routine exits and closeBindLocked's
				// stopping.Wait() can return instead of deadlocking.
				select {
				case <-done:
					return 0, net.ErrClosed
				default:
				}
				return 0, err
			}
			if isSTUN(slab[:n]) {
				b.handleSTUN(c, slab[:n], addrPort)
				continue
			}
			if appLog.IsDebug() {
				rn := b.recvCount.Add(1)
				appLog.Debug("passing UDP packet to WireGuard", "bytes", n, "remote", addrPort.String(), "count", rn)
			}
			packets[0].Offset = 0
			packets[0].Size = n
			if last != nil && last.AddrPort == addrPort {
				packets[0].Endpoint = last
			} else {
				last = &conn.StdNetEndpoint{AddrPort: addrPort}
				packets[0].Endpoint = last
			}
			return 1, nil
		}
	}
}

func (b *stunBind) Close() error {
	// We do not own the sockets' lifetime (main manages them), but we must
	// unblock any receive goroutine parked in ReadFromUDPAddrPort; otherwise
	// closeBindLocked -> stopping.Wait() can deadlock during BindUpdate/Down/Close.
	b.mu.Lock()
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
	b.mu.Unlock()
	now := time.Now()
	if b.conn4 != nil {
		_ = b.conn4.SetReadDeadline(now)
	}
	if b.conn6 != nil {
		_ = b.conn6.SetReadDeadline(now)
	}
	appLog.Debug("WireGuard UDP bind closed")
	return nil
}

func (b *stunBind) SetMark(uint32) error { return nil }

func (b *stunBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	if b.sender != nil {
		return b.sender.Send(bufs, ep, offset)
	}
	se, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	var udpConn *net.UDPConn
	network := "udp4"
	if se.AddrPort.Addr().Is4() && b.conn4 != nil {
		udpConn = b.conn4
	} else if !se.AddrPort.Addr().Is4() && b.conn6 != nil {
		udpConn, network = b.conn6, "udp6"
	} else {
		return fmt.Errorf("no bound socket for endpoint %s address family", se.AddrPort.String())
	}
	for _, buf := range bufs {
		if _, err := udpConn.WriteToUDPAddrPort(buf[offset:], se.AddrPort); err != nil {
			return err
		}
		if appLog.IsDebug() {
			appLog.Debug("sent WireGuard UDP packet", "bytes", len(buf), "remote", se.AddrPort.String(), "network", network)
		}
	}
	return nil
}

func (b *stunBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return (&conn.StdNetBind{}).ParseEndpoint(s)
}

func (b *stunBind) BatchSize() int {
	// stunBind currently performs single-packet reads/writes via *net.UDPConn.
	// Returning 1 prevents wireguard-go from allocating IdealBatchSize (128)
	// element buffer arrays per routine until vectorized recvmmsg/sendmmsg is implemented.
	return 1
}
