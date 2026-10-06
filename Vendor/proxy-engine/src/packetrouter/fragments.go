// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type fragmentKey struct {
	scope    string
	src, dst netip.Addr
	id       uint32
	protocol byte
}
type fragmentMeta struct {
	ipv6         bool
	id           uint32
	at, previous int
	next         byte
}
type fragmentPart struct {
	offset int
	data   []byte
}
type fragmentGroup struct {
	parts     []fragmentPart
	header    []byte
	meta      fragmentMeta
	total     int
	created   time.Time
	signature []byte
}
type reassembler struct {
	mu     sync.Mutex
	closed bool
	groups map[fragmentKey]*fragmentGroup
	denied map[fragmentKey]time.Time
	bytes  int
}

func fragmentInfo(raw []byte, scope string) (fragmentKey, fragmentMeta, int, bool, int, bool, error) {
	k := fragmentKey{scope: scope}
	m := fragmentMeta{}
	if len(raw) < 20 || len(raw) > 65535 {
		return k, m, 0, false, 0, false, ErrPacket
	}
	if raw[0]>>4 == 4 {
		at := int(raw[0]&15) * 4
		if at < 20 || at > len(raw) || int(binary.BigEndian.Uint16(raw[2:])) != len(raw) {
			return k, m, 0, false, 0, false, ErrPacket
		}
		flags := binary.BigEndian.Uint16(raw[6:])
		if flags&0x8000 != 0 || flags&0x4000 != 0 && flags&0x3fff != 0 {
			return k, m, 0, false, 0, false, ErrPacket
		}
		if flags&0x3fff == 0 {
			return k, m, 0, false, 0, false, nil
		}
		if sum(raw[:at]) != 0xffff {
			return k, m, 0, false, 0, true, ErrChecksum
		}
		k.src, k.dst = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
		k.id, k.protocol = uint32(binary.BigEndian.Uint16(raw[4:])), raw[9]
		m.id, m.at = k.id, at
		return k, m, int(flags&0x1fff) * 8, flags&0x2000 != 0, at, true, nil
	}
	if raw[0]>>4 != 6 || len(raw) < 40 || int(binary.BigEndian.Uint16(raw[4:]))+40 != len(raw) {
		return k, m, 0, false, 0, false, ErrPacket
	}
	previous, at, next := 6, 40, raw[6]
	for count := 0; count < 8; count++ {
		if next == 44 {
			if at+8 > len(raw) || raw[at+1] != 0 || binary.BigEndian.Uint16(raw[at+2:])&6 != 0 {
				return k, m, 0, false, 0, true, ErrPacket
			}
			k.src, k.dst = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
			k.id, k.protocol = binary.BigEndian.Uint32(raw[at+4:]), raw[at]
			m = fragmentMeta{true, k.id, at, previous, k.protocol}
			flags := binary.BigEndian.Uint16(raw[at+2:])
			return k, m, int(flags & 0xfff8), flags&1 != 0, at + 8, true, nil
		}
		if next != 0 && next != 60 {
			return k, m, 0, false, 0, false, nil
		}
		if at+2 > len(raw) {
			return k, m, 0, false, 0, false, ErrPacket
		}
		length := (int(raw[at+1]) + 1) * 8
		if at+length > len(raw) {
			return k, m, 0, false, 0, false, ErrPacket
		}
		previous, next, at = at, raw[at], at+length
	}
	return k, m, 0, false, 0, false, ErrProtocol
}

// No fragment is forwarded until the complete datagram is validated. Overlap
// kills the entire group. All scopes share strict context, segment and memory
// ceilings; peer/generation are part of the incoming scope.
func (a *reassembler) accept(raw []byte, scope string) ([]byte, *fragmentMeta, bool, error) {
	k, meta, offset, more, at, fragmented, err := fragmentInfo(raw, scope)
	if err != nil || !fragmented {
		return raw, nil, false, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, nil, false, errors.New("routing session stopped")
	}
	now := time.Now()
	if a.groups == nil {
		a.groups = make(map[fragmentKey]*fragmentGroup)
		a.denied = make(map[fragmentKey]time.Time)
	}
	for key, group := range a.groups {
		if now.Sub(group.created) > 10*time.Second {
			a.remove(key)
		}
	}
	for key, expiry := range a.denied {
		if now.After(expiry) {
			delete(a.denied, key)
		}
	}
	if _, denied := a.denied[k]; denied {
		return nil, nil, false, errors.New("overlapping fragment group")
	}
	payload := raw[at:]
	if len(payload) == 0 || more && len(payload)%8 != 0 || offset+len(payload)+meta.at > 65535 {
		a.remove(k)
		return nil, nil, false, ErrPacket
	}
	group := a.groups[k]
	if group == nil {
		if len(a.groups) >= 128 {
			return nil, nil, false, errors.New("fragment context limit")
		}
		group = &fragmentGroup{meta: meta, total: -1, created: now}
		if meta.ipv6 {
			group.signature = bytes.Clone(raw[:meta.at])
			group.signature[4], group.signature[5], group.signature[7] = 0, 0, 0
		}
		a.groups[k] = group
	}
	bad := len(group.parts) >= 128 || a.bytes+len(payload) > 4*1024*1024 || group.meta != meta
	if meta.ipv6 {
		signature := bytes.Clone(raw[:meta.at])
		signature[4], signature[5], signature[7] = 0, 0, 0
		if !bytes.Equal(signature, group.signature) {
			bad = true
		}
	}
	for _, part := range group.parts {
		if offset < part.offset+len(part.data) && part.offset < offset+len(payload) {
			bad = true
		}
	}
	if group.total >= 0 && offset+len(payload) > group.total {
		bad = true
	}
	if !more {
		if group.total >= 0 && group.total != offset+len(payload) {
			bad = true
		}
		for _, part := range group.parts {
			if part.offset+len(part.data) > offset+len(payload) {
				bad = true
			}
		}
		group.total = offset + len(payload)
	}
	if bad {
		a.remove(k)
		if len(a.denied) < 256 {
			a.denied[k] = now.Add(10 * time.Second)
		}
		return nil, nil, false, errors.New("fragment overlap or resource limit")
	}
	if offset == 0 {
		group.header = bytes.Clone(raw[:meta.at])
	}
	group.parts = append(group.parts, fragmentPart{offset, bytes.Clone(payload)})
	a.bytes += len(payload)
	sort.Slice(group.parts, func(i, j int) bool { return group.parts[i].offset < group.parts[j].offset })
	end := 0
	for _, part := range group.parts {
		if part.offset != end {
			return nil, nil, true, nil
		}
		end += len(part.data)
	}
	if end != group.total || group.header == nil {
		return nil, nil, true, nil
	}
	packet := append([]byte(nil), group.header...)
	for _, part := range group.parts {
		packet = append(packet, part.data...)
	}
	if meta.ipv6 {
		packet[meta.previous] = meta.next
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
	} else {
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		packet[6], packet[7], packet[10], packet[11] = 0, 0, 0, 0
		binary.BigEndian.PutUint16(packet[10:], ^sum(packet[:meta.at]))
	}
	a.remove(k)
	return packet, &meta, false, nil
}

func (a *reassembler) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.groups = nil
	a.denied = nil
	a.bytes = 0
}

func (a *reassembler) remove(key fragmentKey) {
	if group := a.groups[key]; group != nil {
		for _, part := range group.parts {
			a.bytes -= len(part.data)
		}
	}
	delete(a.groups, key)
}

// Fragment IPv4 without DF, or re-fragment an IPv6 datagram the host already
// fragmented. Never originate IPv6 fragments for an unfragmented host packet.
func fragmentPacket(p packet, mtu int, original *fragmentMeta) ([][]byte, error) {
	if len(p.raw) <= mtu {
		return [][]byte{p.raw}, nil
	}
	meta := fragmentMeta{at: p.ipHeader}
	if p.src.Is4() {
		if binary.BigEndian.Uint16(p.raw[6:])&0x4000 != 0 {
			return nil, errors.New("MTU")
		}
		if p.ipHeader != 20 {
			return nil, ErrProtocol
		}
	} else {
		if original == nil || !original.ipv6 {
			return nil, errors.New("MTU")
		}
		meta = *original
	}
	headerLength := meta.at
	if meta.ipv6 {
		headerLength += 8
	}
	chunk := (mtu - headerLength) / 8 * 8
	if chunk < 8 {
		return nil, errors.New("MTU")
	}
	var output [][]byte
	payload := p.raw[meta.at:]
	for offset := 0; offset < len(payload); offset += chunk {
		end := min(offset+chunk, len(payload))
		raw := bytes.Clone(p.raw[:meta.at])
		if meta.ipv6 {
			raw[meta.previous] = 44
			header := make([]byte, 8)
			header[0] = meta.next
			flags := uint16(offset)
			if end != len(payload) {
				flags |= 1
			}
			binary.BigEndian.PutUint16(header[2:], flags)
			binary.BigEndian.PutUint32(header[4:], meta.id)
			raw = append(raw, header...)
		}
		raw = append(raw, payload[offset:end]...)
		if meta.ipv6 {
			binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		} else {
			binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
			flags := uint16(offset / 8)
			if end != len(payload) {
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(raw[6:], flags)
			raw[10], raw[11] = 0, 0
			binary.BigEndian.PutUint16(raw[10:], ^sum(raw[:20]))
		}
		output = append(output, raw)
	}
	return output, nil
}
