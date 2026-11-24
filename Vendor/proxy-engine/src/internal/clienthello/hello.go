// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package clienthello

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

const MaxBytes = 16 << 10

// A visible TLS server name always contains a valid hostname. Unknown and
// incomplete observations never produce a lookup key.
type NameStatus uint8

const (
	Invalid NameStatus = iota
	Incomplete
	Absent
	Encrypted
	Visible
)

// Return incomplete only if the available bytes remain a plausible TLS record.
// Normal TCP segmentation and ClientHello fragmentation across records both work.
// The caller discards partial bytes after a gap, timeout or size limit.
func ServerName(data []byte) (name string, status NameStatus) {
	var chunks [8][]byte
	var header [4]byte
	seen, needed := 0, 0
	for n := 0; n < len(chunks); n++ {
		if len(data) > 0 && data[0] != 22 || len(data) > 1 && data[1] != 3 || len(data) > 2 && (data[2] < 1 || data[2] > 3) {
			return "", Invalid
		}
		if len(data) < 5 {
			return "", Incomplete
		}
		size := int(binary.BigEndian.Uint16(data[3:5]))
		if size == 0 || seen+size > MaxBytes {
			return "", Invalid
		}
		if len(data) < 5+size {
			return "", Incomplete
		}
		chunk := data[5 : 5+size]
		data = data[5+size:]
		chunks[n] = chunk
		if seen < 4 {
			copy(header[seen:], chunk)
		}
		seen += size
		if header[0] != 1 {
			return "", Invalid
		}
		if seen < 4 {
			continue
		}
		if needed == 0 {
			needed = 4 + (int(header[1]) << 16) + (int(header[2]) << 8) + int(header[3])
			if needed > MaxBytes || needed < 4+34 {
				return "", Invalid
			}
		}
		if seen >= needed {
			if n == 0 {
				return helloName(chunk[4:needed])
			}
			body := make([]byte, 0, seen)
			for _, part := range chunks[:n+1] {
				body = append(body, part...)
			}
			name, status = helloName(body[4:needed])
			clear(body)
			return name, status
		}
	}
	return "", Invalid
}

type helloFields []byte

func (p *helloFields) take(n int) ([]byte, bool) {
	if n > len(*p) {
		return nil, false
	}
	b := (*p)[:n]
	*p = (*p)[n:]
	return b, true
}
func (p *helloFields) vec8() ([]byte, bool) {
	size, ok := p.take(1)
	if !ok {
		return nil, false
	}
	return p.take(int(size[0]))
}
func (p *helloFields) vec16() ([]byte, bool) {
	size, ok := p.take(2)
	if !ok {
		return nil, false
	}
	return p.take(int(binary.BigEndian.Uint16(size)))
}

func helloName(body []byte) (string, NameStatus) {
	p := helloFields(body)
	fixed, ok := p.take(34)
	if !ok || fixed[0] != 3 || fixed[1] > 3 {
		return "", Invalid
	}
	session, ok := p.vec8()
	if !ok || len(session) > 32 {
		return "", Invalid
	}
	ciphers, ok := p.vec16()
	if !ok || len(ciphers) < 2 || len(ciphers)%2 != 0 {
		return "", Invalid
	}
	compression, ok := p.vec8()
	if !ok || len(compression) == 0 {
		return "", Invalid
	}
	if len(p) == 0 {
		return "", Absent
	}
	extensions, ok := p.vec16()
	if !ok || len(p) != 0 {
		return "", Invalid
	}
	ext := helloFields(extensions)
	name := ""
	for i := 0; len(ext) > 0; i++ {
		if i >= 128 {
			return "", Invalid
		}
		header, ok := ext.take(2)
		if !ok {
			return "", Invalid
		}
		value, ok := ext.vec16()
		if !ok {
			return "", Invalid
		}
		switch binary.BigEndian.Uint16(header) {
		case 0xfe0d: // Encrypted ClientHello or its GREASE equivalent.
			return "", Encrypted
		case 0:
			if name != "" {
				return "", Invalid
			}
			entry := helloFields(value)
			list, ok := entry.vec16()
			if !ok || len(entry) != 0 {
				return "", Invalid
			}
			names := helloFields(list)
			for len(names) > 0 {
				kind, ok := names.take(1)
				if !ok {
					return "", Invalid
				}
				s, ok := names.vec16()
				if !ok {
					return "", Invalid
				}
				if kind[0] == 0 {
					if name != "" {
						return "", Invalid
					}
					name, ok = Hostname(string(s))
					if !ok {
						return "", Invalid
					}
				}
			}
			if name == "" {
				return "", Invalid
			}
		}
	}
	if name == "" {
		return "", Absent
	}
	return name, Visible
}

// Only plain hostnames are displayed. Reject IP literals, opaque labels,
// malformed names and unsafe display characters without retaining their bytes.
func Hostname(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i == start || i-start > 63 || s[start] == '-' || s[i-1] == '-' {
				return "", false
			}
			start = i + 1
		} else if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return "", false
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	return strings.ToLower(s), true
}
