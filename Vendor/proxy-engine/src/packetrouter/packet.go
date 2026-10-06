// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrPacket   = errors.New("malformed packet")
	ErrFragment = errors.New("fragment requires reassembly")
	ErrProtocol = errors.New("unsupported packet protocol")
	ErrChecksum = errors.New("invalid packet checksum")
)

type packet struct {
	raw                                                       []byte
	src, dst                                                  netip.Addr
	ipHeader, transport, srcOffset, dstOffset, checksumOffset int
	protocol                                                  uint8
	srcPort, dstPort                                          uint16
	echo, icmpError, udpZero, truncated                       bool
}

// Parsing never trusts a length, offset, extension count or transport checksum.
// Quotes in ICMP errors may truncate the original datagram, but must contain its
// complete IP header and the first eight bytes identifying the original flow.
func parse(raw []byte, quote bool) (packet, error) {
	p := packet{raw: raw, checksumOffset: -1, truncated: quote}
	if len(raw) < 20 || len(raw) > 65535 {
		return p, ErrPacket
	}
	var total int
	switch raw[0] >> 4 {
	case 4:
		p.ipHeader = int(raw[0]&15) * 4
		total = int(binary.BigEndian.Uint16(raw[2:4]))
		if p.ipHeader < 20 || p.ipHeader > len(raw) || total < p.ipHeader {
			return p, ErrPacket
		}
		if sum(raw[:p.ipHeader]) != 0xffff {
			return p, ErrChecksum
		}
		if binary.BigEndian.Uint16(raw[6:8])&0xbfff != 0 {
			return p, ErrFragment
		}
		// Source routes would make the destination in the header misleading.
		for at := 20; at < p.ipHeader; {
			kind := raw[at]
			if kind == 0 {
				break
			}
			if kind == 1 {
				at++
				continue
			}
			if at+2 > p.ipHeader || raw[at+1] < 2 || at+int(raw[at+1]) > p.ipHeader {
				return p, ErrPacket
			}
			if kind == 131 || kind == 137 {
				return p, ErrProtocol
			}
			at += int(raw[at+1])
		}
		p.protocol, p.transport = raw[9], p.ipHeader
		p.srcOffset, p.dstOffset = 12, 16
		p.src = netip.AddrFrom4([4]byte(raw[12:16]))
		p.dst = netip.AddrFrom4([4]byte(raw[16:20]))
	case 6:
		if len(raw) < 40 {
			return p, ErrPacket
		}
		total = 40 + int(binary.BigEndian.Uint16(raw[4:6]))
		if total == 40 {
			return p, ErrProtocol
		} // no jumbograms
		p.ipHeader, p.transport, p.protocol = 40, 40, raw[6]
		p.srcOffset, p.dstOffset = 8, 24
		p.src = netip.AddrFrom16([16]byte(raw[8:24]))
		p.dst = netip.AddrFrom16([16]byte(raw[24:40]))
		for count := 0; ; count++ {
			if count > 8 {
				return p, ErrProtocol
			}
			switch p.protocol {
			case 0, 60: // Hop-by-Hop and Destination Options
				if p.transport+2 > len(raw) {
					return p, ErrPacket
				}
				length := (int(raw[p.transport+1]) + 1) * 8
				if p.transport+length > len(raw) || p.transport+length > total {
					return p, ErrPacket
				}

				// Only padding has no address-dependent meaning. Home Address,
				// Jumbo Payload and unknown options must not bypass translation.
				for option := p.transport + 2; option < p.transport+length; {
					kind := raw[option]
					if kind == 0 {
						option++
						continue
					}
					if option+2 > p.transport+length {
						return p, ErrPacket
					}
					size := int(raw[option+1]) + 2
					if option+size > p.transport+length {
						return p, ErrPacket
					}
					if kind != 1 {
						return p, ErrProtocol
					}
					option += size
				}
				p.protocol = raw[p.transport]
				p.transport += length
				continue
			case 44:
				return p, ErrFragment
			case 43, 50, 51:
				return p, ErrProtocol // routing / encrypted / authenticated headers
			}
			break
		}
	default:
		return p, ErrPacket
	}
	if total < len(raw) && quote {
		raw = raw[:total]
		p.raw = raw
	}
	if total > len(raw) && !quote || total < len(raw) {
		return p, ErrPacket
	}
	if p.transport+8 > len(raw) {
		return p, ErrPacket
	}
	l4 := raw[p.transport:]
	switch p.protocol {
	case 6:
		p.srcPort, p.dstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		if !quote {
			if len(l4) < 20 || int(l4[12]>>4)*4 < 20 || int(l4[12]>>4)*4 > len(l4) {
				return p, ErrPacket
			}
		}
		if len(l4) >= 18 {
			p.checksumOffset = p.transport + 16
		}
	case 17:
		p.srcPort, p.dstPort = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		if !quote && int(binary.BigEndian.Uint16(l4[4:6])) != len(l4) {
			return p, ErrPacket
		}
		p.checksumOffset = p.transport + 6
		p.udpZero = binary.BigEndian.Uint16(l4[6:8]) == 0 && p.src.Is4()
		if !p.src.Is4() && binary.BigEndian.Uint16(l4[6:8]) == 0 {
			return p, ErrChecksum
		}
	case 1, 58:
		if p.src.Is4() != (p.protocol == 1) {
			return p, ErrProtocol
		}
		p.checksumOffset = p.transport + 2
		p.echo = p.protocol == 1 && (l4[0] == 0 || l4[0] == 8) || p.protocol == 58 && (l4[0] == 128 || l4[0] == 129)
		p.icmpError = p.protocol == 1 && (l4[0] == 3 || l4[0] == 11 || l4[0] == 12) || p.protocol == 58 && l4[0] >= 1 && l4[0] <= 4
		if !p.echo && !p.icmpError {
			return p, ErrProtocol
		}
		if p.echo {
			p.srcPort = binary.BigEndian.Uint16(l4[4:6])
			p.dstPort = p.srcPort
		}
	default:
		return p, ErrProtocol
	}
	if !quote && !p.udpZero {
		checksum := uint32(sum(l4))
		if p.protocol != 1 {
			checksum += p.pseudoSum()
		}
		if fold(checksum) != 0xffff {
			return p, ErrChecksum
		}
	}
	return p, nil
}

func sum(raw []byte) uint16 {
	var value uint32
	for len(raw) >= 2 {
		value += uint32(binary.BigEndian.Uint16(raw))
		raw = raw[2:]
	}
	if len(raw) == 1 {
		value += uint32(raw[0]) << 8
	}
	return fold(value)
}

func fold(value uint32) uint16 {
	for value > 0xffff {
		value = value>>16 + value&0xffff
	}
	return uint16(value)
}

func (p packet) pseudoSum() uint32 {
	length := len(p.raw) - p.transport
	return uint32(sum(p.src.AsSlice())) + uint32(sum(p.dst.AsSlice())) + uint32(p.protocol) + uint32(length)
}

// RFC 1624 update also works for a quoted TCP header whose payload is absent.
// A complete packet's checksums are subsequently rebuilt, including ICMPv6's
// pseudo header. UDP's optional IPv4 zero checksum remains zero.
func (p *packet) replaceAddress(source bool, address netip.Addr) {
	offset, old := p.dstOffset, p.dst
	if source {
		offset, old = p.srcOffset, p.src
	}
	before, after := old.AsSlice(), address.AsSlice()
	if p.checksumOffset >= 0 && !p.udpZero && (p.protocol != 1) {
		checksum := binary.BigEndian.Uint16(p.raw[p.checksumOffset:])
		value := uint32(^checksum)
		for at := 0; at < len(before); at += 2 {
			value += uint32(^binary.BigEndian.Uint16(before[at:])) + uint32(binary.BigEndian.Uint16(after[at:]))
		}
		updated := ^fold(value)
		if updated == 0 && p.protocol == 17 {
			updated = 0xffff
		}
		binary.BigEndian.PutUint16(p.raw[p.checksumOffset:], updated)
	}
	copy(p.raw[offset:], after)
	if source {
		p.src = address
	} else {
		p.dst = address
	}
	p.fixIPChecksum()
}

func (p packet) fixIPChecksum() {
	if !p.src.Is4() {
		return
	}
	p.raw[10], p.raw[11] = 0, 0
	binary.BigEndian.PutUint16(p.raw[10:], ^sum(p.raw[:p.ipHeader]))
}

func (p packet) fixTransportChecksum() {
	if p.udpZero {
		return
	}
	p.raw[p.checksumOffset], p.raw[p.checksumOffset+1] = 0, 0
	value := uint32(sum(p.raw[p.transport:]))
	if p.protocol != 1 {
		value += p.pseudoSum()
	}
	checksum := ^fold(value)
	if checksum == 0 && p.protocol == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(p.raw[p.checksumOffset:], checksum)
}
