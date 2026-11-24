// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//go:build routing_rust && cgo

package routelang

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Match the shared-router host's staged writes and packet count marker. Unlike
// a general playground host it does not export a per-statement count action.
type scalarPacketHost map[string]Value

func (h scalarPacketHost) Read(name string) (Value, bool) { v, ok := h[name]; return v, ok }
func (h scalarPacketHost) Write(name string, v Value) error {
	switch name {
	case "ip.dscp":
		if v.Type() != TInt || v.AsInt() < 0 || v.AsInt() > 63 {
			return errors.New("invalid packet field write")
		}
	case "tcp.mss":
		old, ok := h[name]
		if !ok || v.Type() != TInt || v.AsInt() < 536 || v.AsInt() > old.AsInt() {
			return errors.New("invalid packet field write")
		}
	case "dns.rd":
		if v.Type() != TBool {
			return errors.New("invalid packet field write")
		}
	default:
		return errors.New("invalid packet field write")
	}
	h[name] = v
	return nil
}
func (h scalarPacketHost) Action(name string, args []Value) error {
	if name == "count" && len(args) == 0 {
		return nil
	}
	return errors.New("unexpected packet action")
}

func TestPacketNativeMatchesInterpreter(t *testing.T) {
	schema := Schema{"packet": {Fields: map[string]Field{
		"port.server": {TInt, false}, "ip.dscp": {TInt, true}, "tcp.mss": {TInt, true}, "dns.rd": {TBool, true},
	}}}
	for _, tt := range []struct{ name, source string }{
		{"empty", "on empty: packet {}"},
		{"boolean arithmetic and staged edits", `fn offset(v:int)->int {return v * 3 - 1;}
on first: packet {let a = port.server + 1; if a >= 2 && offset(a) != 4 {ip.dscp=7;}else{ip.dscp=2;}}
on second: packet {if ip.dscp==7 || tcp.mss > 1000 {ip.dscp=ip.dscp+1;} if !dns.rd {dns.rd=true;}}`},
		{"conditional missing MSS", "on short: packet {if port.server==0 || tcp.mss > 1100 {count();}}"},
		{"earlier update changes write limit", "on a: packet {tcp.mss=1000;}\non b: packet {tcp.mss=1010;}"},
		{"missing on write", "on request: packet {tcp.mss=800;}"},
		{"native drop", "on first: packet {count();}\non dropper: packet {drop();}\non late: packet {count();}"},
		{"negative divide remainder", "on a: packet { let n= -7 / 3; if n == -2 && -7 % 3 == -1 {ip.dscp=8;} }"},
		{"division by zero", "on a: packet { let n=40 / port.server; }"},
		{"overflow", "on a: packet { let n=9223372036854775807 + port.server; }"},
		{"invalid packet write", "on a: packet {ip.dscp=64;}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, err := Compile(tt.source, schema, nil)
			if err != nil {
				t.Fatal(err)
			}
			native, err := code.NewPacketExecutor()
			if err != nil {
				t.Fatal(err)
			}
			defer native.Close()
			if native.native["packet"] == nil {
				t.Fatal("expected native plan")
			}
			for _, port := range []int64{0, 1, 443} {
				for _, mss := range []bool{true, false} {
					start := scalarPacketHost{"port.server": Int(port), "ip.dscp": Int(0), "dns.rd": Bool(false)}
					if mss {
						start["tcp.mss"] = Int(1460)
					}
					goHost, nativeHost := maps.Clone(start), maps.Clone(start)
					want, werr := code.RunInto("packet", goHost, nil)
					got, gerr := native.RunInto("packet", nativeHost, nil)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(gerr) != fmt.Sprint(werr) {
						t.Fatalf("Go %+v %v; Rust %+v %v", want, werr, got, gerr)
					}
					if !got.Dropped && !reflect.DeepEqual(goHost, nativeHost) {
						t.Fatalf("Go %+v; Rust %+v", goHost, nativeHost)
					}
				}
			}
		})
	}
}

func TestPacketNativeBudgetAndCompileTimeSelection(t *testing.T) {
	// The event's instruction allowance is shared across all handlers, exactly
	// as it is for RunInto. A failure belongs to the handler that exceeded it.
	a := make([]instruction, MaxInstructions)
	for i := range a {
		a[i] = instruction{op: hostAction, name: "count", line: 1}
	}
	code := &Program{handlers: map[string][]handler{"bounded": {{id: "first", code: a}, {id: "excess", code: []instruction{{op: deny, line: 9}}}}}}
	exec, err := code.NewPacketExecutor()
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Close()
	if exec.native["bounded"] == nil {
		t.Fatal("expected native budget fixture")
	}
	h := scalarPacketHost{}
	got, err := exec.RunInto("bounded", h, nil)
	want, werr := code.RunInto("bounded", h, nil)
	if !reflect.DeepEqual(got, want) || fmt.Sprint(err) != fmt.Sprint(werr) || got.Instructions != MaxInstructions+1 {
		t.Fatalf("%+v %v vs %+v %v", got, err, want, werr)
	}

	mixed := compile(t, `on scalar: tls.hidden {count();}
on first: tcp.syn {ip.dscp=1;}
on address: tcp.syn {if ip.server_address == addr("192.0.2.1") {count();}}`)
	e, err := mixed.NewPacketExecutor()
	if err != nil {
		t.Fatal(err)
	}
	if scalar, general := e.NativeEventCounts(); scalar != 1 || general != 1 {
		t.Fatal("all event groups must have a native backend")
	}
	e.Close()
	e.Close()
	if result, err := e.RunInto("tls.hidden", h, nil); err == nil || !result.Dropped {
		t.Fatal("closed native program accepted an event")
	}
}

func TestGeneralPacketExecutorDifferential(t *testing.T) {
	schema := schema()
	schema["tcp.syn"].Fields["flow.source"] = Field{TString, false}
	input := scalarPacketHost(fixtureHost().values)
	input["flow.source"] = String("UsEr.Å")
	input["udp.payload"] = fixtureBytes(t, []byte{0, 7, 2, 3})
	input["tls.sni"], _ = DNS("www.example.test")
	smallInput := maps.Clone(input)
	delete(smallInput, "tls.sni")
	smallInput["flow.source"] = String("")
	smallInput["udp.payload"] = fixtureBytes(t, nil)
	smallInput["port.server"] = Int(0)
	address6 := maps.Clone(input)
	address6["ip.server_address"] = Addr(netip.MustParseAddr("2001:db8:1234::1"))
	address6["port.server"] = Int(22)
	for _, tt := range []struct{ name, source string }{
		{"functions loops and locals", `fn score(port:int)->int {let n=0;for x in [0,1,2,3] {if port!=x {n=n+x;}} return n;} on loop:tcp.syn { ip.dscp=score(port.server); }`},
		{"longest prefix and staged read across handlers", `table routes:prefix->int={prefix("0.0.0.0/0"):1,prefix("10.2.0.0/16"):20,prefix("2001:db8::/32"):4,prefix("2001:db8:1234::/48"):30}; on route:tcp.syn { match lookup(routes, ip.server_address) {found(n){ip.dscp=n;}missing{drop();}}} on mark:tcp.syn {ip.dscp=ip.dscp+1;}`},
		{"stored empty false and absent", `table labels:int->string={443:"",22:"member"};table permitted:string->bool={"":false,"member":true};on test:tcp.syn {match lookup(labels,port.server){found(name){match lookup(permitted,name){found(ok){if ok{ip.dscp=15;}else{ip.dscp=0;}}missing{drop();}}}missing{ip.dscp=1;}}}`},
		{"dns strings missing evidence and short circuit", `on test:tcp.syn {if port.server==0 || ends_with(tls.sni,"example.test") && starts_with(lower(flow.source),"user.") {ip.dscp=len(flow.source);} }`},
		{"missing field error", `on first:tcp.syn {ip.dscp=3;} on test:tcp.syn {if dns("www.example.test")==tls.sni {count();}}`},
		{"bytes mutation indexing", `on change:tcp.syn {let a=udp.payload;let b=replace(a,0,1,bytes("04")); let c=write_u16be(b,0,7); ip.dscp=u16be(c,0)+byte(slice(a,0,2),1);}`},
		{"normalise and coerce", `on conv:tcp.syn {let s=string(mask(ip.server_address,16)); if ip.server_address in prefix(s) {ip.dscp=int(string(12))+int(contains(lower(flow.source),"å"));}}`},
		{"errors in generated inputs", `on test:tcp.syn {ip.dscp=int(flow.source);}`},
		{"budget across general handlers", `on a:tcp.syn{for i in range(0,64){for j in range(0,24){count();}}}on b:tcp.syn{for i in range(0,64){for j in range(0,24){count();}}}`},
		{"byte budget and range", `on test:tcp.syn { for n in range(0,64) { let b=write_u16be(udp.payload,0,n); } }`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(tt.source, schema, nil)
			if err != nil {
				t.Fatal(err)
			}
			n, err := p.NewPacketExecutor()
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			if scalar, general := n.NativeEventCounts(); scalar != 0 || general != 1 {
				t.Fatal("not dispatched by general Rust VM")
			}
			huge := maps.Clone(input)
			huge["udp.payload"] = fixtureBytes(t, make([]byte, MaxBytes))
			huge["flow.source"] = String(strings.Repeat("a", MaxString))
			for _, values := range []scalarPacketHost{input, smallInput, address6, huge} {
				a, b := maps.Clone(values), maps.Clone(values)
				want, werr := p.Run("tcp.syn", a)
				got, gerr := n.RunInto("tcp.syn", b, nil)
				if !reflect.DeepEqual(got, want) || fmt.Sprint(gerr) != fmt.Sprint(werr) || (!got.Dropped && !reflect.DeepEqual(a, b)) {
					t.Fatalf("Go %+v %v mark=%v; Rust %+v %v mark=%v", want, werr, a["ip.dscp"].n, got, gerr, b["ip.dscp"].n)
				}
			}
		})
	}
}

func TestPacketInstallRejectsAProgramRequiringANonpacketHost(t *testing.T) {
	// The reference language permits this test host's string mutation. The live
	// adapter cannot stage such a write, even if another handler can be native.
	p := compile(t, `on ready:tls.hidden {count();} on unsupported:tcp.syn {mark="x";}`)
	if applied, err := p.NewPacketExecutor(); err == nil || applied != nil {
		t.Fatal("partially native policy installed", applied, err)
	}
}
