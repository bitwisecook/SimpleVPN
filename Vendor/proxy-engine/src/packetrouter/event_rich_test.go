// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestRichPacketPolicyChecksOwnershipAndCommitsChecksum(t *testing.T) {
	code, err := CompileEvents("on office: tcp.syn { if port.server == 443 { ip.dscp = 16; count(); } }")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(code.Close)
	raw := testDatagram("198.19.255.1", "192.0.2.30", 40000, 6)
	p, err := parse(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if !code.Apply(&p, true, observed[string]{}) || p.raw[1]>>2 != 16 {
		t.Fatal("failed typed edit")
	}
	assertChecksums(t, p.raw)
	stats := code.InspectionCounters()
	if len(stats) != 1 || stats[0].ID != "office" || stats[0].PacketsOut != 1 || stats[0].BytesOut != uint64(len(raw)) {
		t.Fatal("missing accounting", stats)
	}
	for _, invalid := range []string{
		"on a: tcp.syn { ip.server_address = addr(\"203.0.113.2\"); }",
		"on a: udp.owned_datagram { udp.payload = bytes(\"ff\"); }",
		"on a: tls.client_hello { proxy.select_backend(\"unowned\"); }",
		"on a: ftp.command { count(); }",
	} {
		if _, err := CompileEvents(invalid); err == nil {
			t.Fatal("accepted an unavailable raw hook or effect", invalid)
		}
	}
}

func TestRichPacketPolicyRollsBackEarlierEventOnErrorOrDrop(t *testing.T) {
	raw := testDatagram("198.19.255.1", "192.0.2.30", 40000, 6)
	for _, stmt := range []string{"ip.dscp = 512;", "drop();", "tcp.mss = 800;", `if ip.server_address in prefix("192.0.2.0/24") {ip.dscp=512;}`} {
		code, err := CompileEvents("on first: ip.packet { ip.dscp = 16; }\non stop: tcp.syn { " + stmt + " }")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(code.Close)
		p, err := parse(bytes.Clone(raw), false)
		if err != nil {
			t.Fatal(err)
		}
		if code.Apply(&p, true, observed[string]{}) || !bytes.Equal(p.raw, raw) {
			t.Fatal("failed event retained mutation", stmt)
		}
		if code.rich.host != (packetEventHost{}) {
			t.Fatal("denied packet retained staged evidence")
		}
	}
}

func TestRichPacketPolicyDispatchDoesNotEvaluateAbsentEvidence(t *testing.T) {
	prog, err := CompileEvents("on hello: tls.client_hello { drop(); }")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prog.Close)
	p, err := parse(testDatagram("198.19.255.1", "192.0.2.10", 40000, 17), false)
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		if !prog.Apply(&p, true, observed[string]{}) {
			panic("unrelated packet denied")
		}
	}); n != 0 {
		t.Fatal("unrelated protocol allocated", n)
	}
}

func TestPacketFieldsDistinguishObservationFromEmptyOrZero(t *testing.T) {
	raw := testDatagram("198.19.255.1", "192.0.2.30", 40000, 6)
	p, err := parse(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	h := packetEventHost{packet: &p}
	for _, key := range []string{"flow.source", "dns.id", "dns.type", "dns.rd", "tls.sni", "tcp.mss"} {
		if _, known := h.Read(key); known {
			t.Fatal("absent field reported as a value", key)
		}
	}
	h.source = present("")
	if v, known := h.Read("flow.source"); !known || v.AsString() != "" {
		t.Fatal("lost explicit source value")
	}
	h.question = present(evidenceQuestion{id: 0})
	if v, known := h.Read("dns.id"); !known || v.AsInt() != 0 {
		t.Fatal("lost DNS transaction zero")
	}
}

func BenchmarkInstalledRichPacket(b *testing.B) {
	for _, workload := range []struct {
		name      string
		size      int
		condition string
	}{{"1", 1, "port.server == 443"}, {"8", 8, "port.server == 443"}, {"address", 1, `ip.server_address in prefix("192.0.2.0/24")`}, {"bounded-loop", 1, `contains(string(ip.server_address),"192.") && has_port(port.server)`}} {
		size := workload.size
		var src strings.Builder
		if workload.name == "bounded-loop" {
			src.WriteString(`fn has_port(p:int)->bool {for v in [53,80,443,8443] {if v==p {return true;}}return false;}`)
		}
		for i := 0; i < size; i++ {
			fmt.Fprintf(&src, "on h%d: tcp.syn { if %s { ip.dscp = %d; count(); } }\n", i, workload.condition, i+1)
		}
		b.Run(workload.name, func(b *testing.B) {
			program, err := CompileEvents(src.String())
			if err != nil {
				b.Fatal(err)
			}
			defer program.Close()
			p, err := parse(testDatagram("198.19.255.1", "192.0.2.30", 40000, 6), false)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if !program.Apply(&p, true, observed[string]{}) {
					b.Fatal("dropped")
				}
			}
		})

	}
}

func TestRichPacketInstallAndRetirement(t *testing.T) {
	const first = "on first:tcp.syn {ip.dscp=1;}"
	const second = `on later:tcp.syn {if ip.server_address in prefix("192.0.2.0/24"){ip.dscp=2;}}`
	r, err := New([]netip.Addr{netip.MustParseAddr("198.19.255.1")}, nil, Policy{Revision: 1, EventSource: first}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	before := r.events
	for _, src := range []string{first, second} {
		if err := r.Check(Policy{Revision: 2, EventSource: src}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Apply(Policy{Revision: 2, EventSource: "on invalid:wrong {}"}); err == nil {
		t.Fatal("invalid replacement installed")
	}
	dispatch := func(p *EventProgram, want byte) bool {
		t.Helper()
		pkt, err := parse(testDatagram("198.19.255.1", "192.0.2.5", 40000, 6), false)
		if err != nil {
			t.Fatal(err)
		}
		return p.Apply(&pkt, true, observed[string]{}) && pkt.raw[1]>>2 == want
	}
	if before != r.events || !dispatch(r.events, 1) {
		t.Fatal("check or rejected apply modified the installed plan")
	}
	if err := r.Apply(Policy{Revision: 2, EventSource: second}); err != nil {
		t.Fatal(err)
	}
	if dispatch(before, 1) || !dispatch(r.events, 2) {
		t.Fatal("retired or new plan has incorrect lifetime")
	}
	active := r.events
	r.Close()
	if dispatch(active, 2) {
		t.Fatal("stopped router retained live plan")
	}
}
