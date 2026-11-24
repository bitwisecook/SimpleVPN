// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestEventMutationsPreserveChecksumsAndDeclarationOrder(t *testing.T) {
	program, err := CompileEvents("on q tcp.syn => count\non mark tcp.syn port 443 source selected => mark-dscp 46\non narrow tcp.syn port 443 => clamp-mss 1200\non skip tcp.syn port 80 => drop\non hit tcp.syn dst 192.0.2.0/24 => drop\non after tcp.syn => count")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"198.19.255.1", "192.0.2.1"}, {"2001:db8::1", "2001:db8::2"}} {
		data := sizedDatagram(pair[0], pair[1], 40000, 6, []byte{2, 4, 0x05, 0xb4})
		p, err := parse(data, false)
		if err != nil {
			t.Fatal(err)
		}
		p.raw[p.transport+12] = 0x60
		p.fixTransportChecksum()
		permitted := program.Apply(&p, true, present("selected"))
		if permitted == p.src.Is4() {
			t.Fatal("wrong decision")
		}
		tc := p.raw[1] >> 2
		if !p.src.Is4() {
			tc = (p.raw[0]&0xf)<<2 | p.raw[1]>>6
		}
		if tc != 46 || binary.BigEndian.Uint16(p.raw[p.transport+22:]) != 1200 {
			t.Fatal("missing header edit")
		}
		assertChecksums(t, p.raw)
	}
	for i, want := range []uint64{2, 2, 2, 0, 1, 1} {
		if program.counts[i].PacketsOut != want {
			t.Fatalf("counter %d: %d", i, program.counts[i].PacketsOut)
		}
	}
}
func TestEventCompilerRejectsInvalidAndOversizedPrograms(t *testing.T) {
	for _, code := range []string{"on wrong tcp.syn name test.example => count", "on q dns.query => set-dns-rd 7", "on q quic.initial => clamp-mss 1280", "on a udp.open => mark-dscp 64", "on a udp.open port 0 => count", "on a tcp.syn dst 10.0.0.1/8 => drop", "on a tcp.syn => count\non a tcp.syn => drop", "on bad ftp.command => count", strings.Repeat("#", 32769)} {
		if _, err := CompileEvents(code); err == nil {
			t.Errorf("accepted invalid handler %.80s", code)
		}
	}
}
func TestQUICInitialInvariantHeader(t *testing.T) {
	header := make([]byte, 1200)
	header[0] = 0xc0
	header[4] = 1
	header[5] = 8
	header[14] = 0
	header[15] = 0
	header[16] = 0x40
	header[17] = 80
	if !isQUICInitial(header) {
		t.Fatal("v1 initial rejected")
	}
	binary.BigEndian.PutUint32(header[1:], 0x6b3343cf)
	header[0] = 0xd0
	if !isQUICInitial(header) {
		t.Fatal("v2 initial rejected")
	}
	header[5] = 255
	if isQUICInitial(header) {
		t.Fatal("malformed ID accepted")
	}
}
func BenchmarkEventIndexedDispatch(b *testing.B) {
	for _, n := range []int{1, 128} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var src strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&src, "on r%d tcp.syn port %d => count\n", i, 443+i)
			}
			prog, err := CompileEvents(src.String())
			if err != nil {
				b.Fatal(err)
			}
			pkt, err := parse(testDatagram("198.19.255.1", "192.0.2.1", 40000, 6), false)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				prog.Apply(&pkt, true, observed[string]{})
			}
		})
	}
}
