// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// This development-only test is overlaid onto package routelang by run.py.
package routelang

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only a typed, forward-only program within this instruction and local bound
// can be emitted. Integer cells hold scalar values or packed IPv4 prefix masks.
// Each emitted branch retains the evaluation order chosen by the DSL compiler.
func lowerScalar(p *Program) (string, error) {
	hs := p.handlers["tcp.syn"]
	if len(p.handlers) != 1 || len(hs) != 1 || len(hs[0].code) > 32 {
		return "", fmt.Errorf("requires a single bounded tcp.syn handler")
	}
	var text strings.Builder
	out := func(format string, args ...any) { fmt.Fprintf(&text, format, args...) }
	out("#include <stdint.h>\nuint32_t evaluate(uint8_t kind, uint8_t present, uint16_t port, uint32_t ip) {\n if(kind!=1)return 0; uint64_t s[32], locals[32]; unsigned n=0, result=0;\n")
	for pc, ins := range hs[0].code {
		out("L%d: ", pc)
		switch ins.op {
		case literal:
			switch ins.v.Type() {
			case TInt:
				out("s[n++]=UINT64_C(%d);", uint64(ins.v.AsInt()))
			case TPrefix:
				prefix := ins.v.AsPrefix().Masked()
				if !prefix.Addr().Is4() {
					return "", fmt.Errorf("IPv4 ABI only")
				}
				b := prefix.Addr().As4()
				m := ^uint32(0) << (32 - prefix.Bits())
				out("s[n++]=UINT64_C(%d);", uint64(m)<<32|uint64(binary.BigEndian.Uint32(b[:])))
			default:
				return "", fmt.Errorf("unsupported literal %v", ins.v.Type())
			}
		case read:
			switch ins.name {
			case "port.server":
				out("if(!(present&1))return 2; s[n++]=port;")
			case "ip.server_address":
				out("if(!(present&2))return 2; s[n++]=ip;")
			default:
				return "", fmt.Errorf("unknown field %s", ins.name)
			}
		case write:
			if ins.name != "ip.dscp" {
				return "", fmt.Errorf("unknown write")
			}
			out("{uint64_t v=s[--n]; if(v>63)return 2; result=1|((unsigned)v<<8);}")
		case load, store:
			if ins.arg < 0 || ins.arg >= 32 {
				return "", fmt.Errorf("local outside ABI")
			}
			if ins.op == load {
				out("s[n++]=locals[%d];", ins.arg)
			} else {
				out("locals[%d]=s[--n];", ins.arg)
			}
		case binaryOp:
			switch ins.name {
			case "==":
				out("{uint64_t b=s[--n]; s[n-1]=s[n-1]==b;}")
			case "in":
				out("{uint64_t p=s[--n]; s[n-1]=((uint32_t)s[n-1] & (p>>32))==(uint32_t)p;}")
			default:
				return "", fmt.Errorf("unsupported binary %s", ins.name)
			}
		case jump, branch, andThen, orElse:
			if ins.target <= pc || ins.target > len(hs[0].code) {
				return "", fmt.Errorf("nonforward branch")
			}
			switch ins.op {
			case jump:
				out("goto L%d;", ins.target)
			case branch:
				out("if(!s[--n])goto L%d;", ins.target)
			case andThen:
				out("if(!s[n-1])goto L%d; --n;", ins.target)
			case orElse:
				out("if(s[n-1])goto L%d; --n;", ins.target)
			}
		case deny:
			out("return 3;")
		default:
			return "", fmt.Errorf("unsupported opcode %d at %d", ins.op, pc)
		}
		out("\n")
	}
	out("L%d:return result;\n}\n", len(hs[0].code))
	return text.String(), nil
}

type scalarInput struct {
	event   uint8
	present uint8
	port    uint16
	ip      uint32
}
type scalarHost struct {
	scalarInput
	effect uint32
}

func (h *scalarHost) Read(field string) (Value, bool) {
	switch field {
	case "port.server":
		return Int(int64(h.port)), h.present&1 != 0
	case "ip.server_address":
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], h.ip)
		return Addr(netip.AddrFrom4(bytes)), h.present&2 != 0
	default:
		return Value{}, false
	}
}
func (h *scalarHost) Write(field string, v Value) error {
	if field != "ip.dscp" || v.Type() != TInt || v.AsInt() < 0 || v.AsInt() > 63 {
		return fmt.Errorf("invalid DSCP effect")
	}
	h.effect = 1 | (uint32(v.AsInt()) << 8)
	return nil
}
func (*scalarHost) Action(name string, _ []Value) error {
	return fmt.Errorf("unsupported action %q", name)
}

func (h *scalarHost) evaluate(p *Program, e scalarInput, scratch []string) uint32 {
	*h = scalarHost{scalarInput: e}
	name := "udp.open"
	if e.event == 1 {
		name = "tcp.syn"
	}
	r, err := p.RunInto(name, h, scratch)
	if err != nil {
		if !r.Dropped {
			panic("runtime error without a drop")
		}
		return 2
	}
	if r.Dropped {
		return 3
	}
	return h.effect
}

func experimentProgram(t testing.TB, name string) *Program {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(os.Getenv("AOT_SOURCE"), name+".dsl"))
	if err != nil {
		t.Fatal(err)
	}
	return compile(t, string(source))
}

func xorshift(seed *uint32) uint32 {
	*seed ^= *seed << 13
	*seed ^= *seed >> 17
	*seed ^= *seed << 5
	return *seed
}
func mixedCorpus() []scalarInput {
	events := make([]scalarInput, 8192)
	seed := uint32(0x71c8b619)
	for i := range events {
		x, ip := xorshift(&seed), xorshift(&seed)
		e := scalarInput{present: 3, port: 80, ip: ip}
		if x&3 != 0 {
			e.event = 1
		}
		if x&4 != 0 {
			e.port = 443
		}
		if x>>3&15 == 0 {
			e.present &^= 1
		}
		if x>>7&15 == 0 {
			e.present &^= 2
		}
		switch x >> 11 & 3 {
		case 1:
			e.ip = 0x0a000000 | ip&0xffffff
		case 2:
			e.ip = 0xc0000200 | ip&255
		}
		events[i] = e
	}
	return events
}

func oracleCases() []scalarInput {
	var events []scalarInput
	for event := range 2 {
		for present := range 4 {
			for _, port := range []uint16{0, 80, 442, 443, 444, 65535} {
				for _, ip := range []uint32{0, 0x09ffffff, 0x0a000000, 0x0affffff, 0x0b000000, 0xc00001ff, 0xc0000200, 0xc00002ff, 0xc0000300, 0xffffffff} {
					events = append(events, scalarInput{uint8(event), uint8(present), port, ip})
				}
			}
		}
	}
	seed := uint32(0x12345678)
	for range 16384 {
		a, ip := xorshift(&seed), xorshift(&seed)
		port := uint16(a)
		if a&2 != 0 {
			port = 443
		}
		if a&64 != 0 {
			ip = 0xc0000200 | ip&255
		}
		events = append(events, scalarInput{uint8(a & 1), uint8(a >> 2 & 3), port, ip})
	}
	return events
}

func writeOracle(t *testing.T, name string, p *Program, es []scalarInput) {
	t.Helper()
	file, err := os.Create(filepath.Join(os.Getenv("AOT_OUTPUT"), name+".tsv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := file.Close(); e != nil {
			t.Error(e)
		}
	})
	out := bufio.NewWriter(file)
	h := new(scalarHost)
	matches := make([]string, 0, 1)
	for _, e := range es {
		fmt.Fprintf(out, "%d %d %d %d %d\n", e.event, e.present, e.port, e.ip, h.evaluate(p, e, matches))
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestAOTExperiment(t *testing.T) {
	baseline := experimentProgram(t, "rule")
	writeOracle(t, "oracle", baseline, oracleCases())
	writeOracle(t, "mixed", baseline, mixedCorpus())
	for _, name := range []string{"rule", "shortcircuit"} {
		prog := experimentProgram(t, name)
		if name == "shortcircuit" {
			count := 0
			for _, i := range prog.handlers["tcp.syn"][0].code {
				if i.op == andThen {
					count++
				}
			}
			if count != 2 {
				t.Fatalf("expected two short circuits, got %d", count)
			}
		}
		emitted, err := lowerScalar(prog)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(os.Getenv("AOT_OUTPUT"), name+".c"), []byte(emitted), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{
		`on wrong:tls.hidden {drop();}`,
		`on loop:tcp.syn {for n in range(0,3) {count();}}`,
		`on unknown:tcp.syn {let s=tls.sni;}`,
	} {
		if _, err := lowerScalar(compile(t, source)); err == nil {
			t.Fatalf("accepted unsupported program %q", source)
		}
	}
}

func BenchmarkAOTExperimentMixedVM(b *testing.B) {
	prog := experimentProgram(b, "rule")
	corpus := mixedCorpus()
	h := new(scalarHost)
	matches := make([]string, 0, 1)
	var i int
	var checksum uint64
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		checksum += uint64(h.evaluate(prog, corpus[i%len(corpus)], matches))
		i++
	}
	if i >= len(corpus) && checksum == 0 {
		b.Fatal("lost effects")
	}
}
