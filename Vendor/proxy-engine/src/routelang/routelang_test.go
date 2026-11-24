// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fixture struct {
	values  map[string]Value
	actions []string
	args    [][]Value
}

func (h *fixture) Read(s string) (Value, bool)   { v, ok := h.values[s]; return v, ok }
func (h *fixture) Write(s string, v Value) error { h.values[s] = v; return nil }
func (h *fixture) Action(s string, v []Value) error {
	h.actions = append(h.actions, s)
	h.args = append(h.args, v)
	return nil
}
func schema() Schema {
	return Schema{"tcp.syn": {Fields: map[string]Field{"ip.server_address": {TAddr, false}, "port.server": {TInt, false}, "ip.dscp": {TInt, true}, "tls.sni": {TDNS, false}, "udp.payload": {TBytes, true}, "mark": {TString, true}}, Actions: map[string][]Type{"route": {TString, TInt}}}, "tls.hidden": {}}
}
func compile(t testing.TB, source string) *Program {
	t.Helper()
	p, e := Compile(source, schema(), nil)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func fixtureBytes(t testing.TB, b []byte) Value {
	t.Helper()
	v, e := Bytes(b)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func fixtureHost() *fixture {
	return &fixture{values: map[string]Value{"port.server": Int(443), "ip.server_address": Addr(netip.MustParseAddr("10.2.3.4")), "ip.dscp": Int(0)}}
}
func TestFunctionsTablesAndTrace(t *testing.T) {
	src := `table members: prefix -> string = {prefix("10.0.0.0/8"): "office", 10.2.0.0/16: "dev", prefix("2001:db8::/32"): "v6"};
fn eligible(ip: addr, port: int) -> bool {
 for candidate in [443, 8443] { if candidate == port { return ip in prefix("10.0.0.0/8"); } }
 return false;
}
on choose: tcp.syn {
 if eligible(ip.server_address, port.server) {
   let subnet = mask(ip.server_address, 24);
   if ip.server_address in subnet { match lookup(members,ip.server_address) { found(member) {route(member,port.server);} missing {drop();} } }
 } else { mark = "skipped"; }
}
on other: tls.hidden { drop(); }`
	p := compile(t, src)
	h := fixtureHost()
	r, e := p.RunTrace("tcp.syn", h)
	if e != nil || r.Dropped || !slices.Equal(r.Matches, []string{"choose"}) || len(r.Trace) != 4 || !r.Trace[3].Lookup || !r.Trace[3].Taken {
		t.Fatal(r, e)
	}
	if len(h.args) != 1 || h.args[0][0].s != "dev" || h.args[0][1].n != 443 {
		t.Fatal(h.args)
	}
	h.values["port.server"] = Int(22)
	r, e = p.Run("tcp.syn", h)
	if e != nil || len(r.Trace) != 0 || h.values["mark"].s != "skipped" {
		t.Fatal(r, e)
	}
	r, e = p.Run("tls.hidden", h)
	if e != nil || !r.Dropped {
		t.Fatal(r, e)
	}
	ids := p.HandlerIDs()
	ids[0] = "changed"
	if p.HandlerIDs()[0] != "choose" {
		t.Fatal("mutable program")
	}
}
func TestImmutableExternalLongestPrefix(t *testing.T) {
	dataset := Table{Key: TPrefix, Element: TString}
	for _, s := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/32", "2001:db8:1::/48"} {
		dataset.Entries = append(dataset.Entries, Entry{Prefix(netip.MustParsePrefix(s)), String(s)})
	}
	p, e := Compile(`table members: prefix -> string = external "members"; on choose: tcp.syn { match lookup(members,ip.server_address) { found(member) {mark=member;} missing {drop();} } }`, schema(), map[string]Table{"members": dataset})
	if e != nil {
		t.Fatal(e)
	}
	dataset.Entries[0].Value = String("mutated")
	h := fixtureHost()
	for raw, want := range map[string]string{"192.0.2.1": "0.0.0.0/0", "2001:db8:1::2": "2001:db8:1::/48", "2001:db8:7::": "2001:db8::/32", "fd00::1": "::/0", "10.0.0.1": "10.0.0.0/8"} {
		h.values["ip.server_address"] = Addr(netip.MustParseAddr(raw))
		r, e := p.Run("tcp.syn", h)
		if r.Dropped || e != nil || h.values["mark"].s != want {
			t.Fatal(raw, h.values["mark"], e)
		}
	}
}
func TestMutableLocalsAndImmutablePayloads(t *testing.T) {
	p := compile(t, `fn add(a: int, b:int) -> int { return a+b; }
 on edit: tcp.syn { let total:int = 0; for n in range(1,4) { total=add(total,n); }
 let original = udp.payload; udp.payload = write_u16be(udp.payload,1,total);
 if u16be(udp.payload,1)==6 && original[1]==2 && len(slice(original,1,3))==2 {
 udp.payload=replace(udp.payload,1,3,bytes("ff"));
 }
 }`)
	original := []byte{1, 2, 3, 4}
	h := fixtureHost()
	h.values["udp.payload"] = fixtureBytes(t, original)
	r, e := p.Run("tcp.syn", h)
	if e != nil || r.Dropped || !bytes.Equal(h.values["udp.payload"].b, []byte{1, 255, 4}) || !bytes.Equal(original, []byte{1, 2, 3, 4}) {
		t.Fatal(r, e, h.values["udp.payload"])
	}
	b := h.values["udp.payload"].AsBytes()
	b[0] = 77
	if h.values["udp.payload"].b[0] != 1 {
		t.Fatal("mutable byte alias")
	}
}
func TestRejectInvalidPrograms(t *testing.T) {
	cases := []string{
		`on x: missing { count(); }`, `on x: tls.hidden { tls.sni = dns("x"); }`, `on x: tls.hidden { route("x",1); }`,
		`on x: tcp.syn { ip.server_address = addr("192.0.2.1"); }`, `on x: tcp.syn { mark = 3; }`, `on x: tcp.syn { if "yes" { count(); } }`,
		`fn cycle() -> int { return cycle(); }`, `fn missing() -> int { if false {return 0;} }`,
		`fn steal() -> addr {return ip.server_address;}`, `fn f(x:int) -> int { return x; count(); }`,
		`on x: tcp.syn { if true { let y = 7; } ip.dscp = y; }`, `on x: tcp.syn { ip.dscp = "x"[2]; }`,
		`table a: string -> int = {"same":1,"same":2};`, `table a: prefix -> int = {prefix("10.0.0.1/8"):2};`,
		`table a: addr -> int = external "does-not-exist";`, `on x: tcp.syn { let i = range(0,65); }`,
		`on x: tcp.syn { let a = [1, "x"]; }`, `on x: tcp.syn { if true {drop();}`,
	}
	for _, src := range cases {
		if _, e := Compile(src, schema(), nil); e == nil {
			t.Errorf("accepted %s", src)
		}
	}
	deep := "on x: tcp.syn { let x = " + strings.Repeat("(", 1000) + "1" + strings.Repeat(")", 1000) + "; }"
	if _, e := Compile(deep, schema(), nil); e == nil {
		t.Error("deep input accepted")
	}
}
func TestShortCircuitAndConditionalDeny(t *testing.T) {
	p := compile(t, `on first: tcp.syn { if port.server == 443 || tls.sni == dns("absent.test") { count(); } }
 on deny: tcp.syn { drop(); } on late: tcp.syn { count(); }`)
	r, e := p.Run("tcp.syn", fixtureHost())
	if e != nil || !r.Dropped || !slices.Equal(r.Matches, []string{"first", "deny"}) {
		t.Fatal(r, e)
	}
	h := fixtureHost()
	h.values["port.server"] = Int(22)
	r, e = p.Run("tcp.syn", h)
	if e == nil || !r.Dropped || len(r.Matches) != 1 {
		t.Fatal("missing field accepted", r, e)
	}
}
func TestBoundsAndOverflowDeny(t *testing.T) {
	for _, expr := range []string{"9223372036854775807 + port.server", "9223372036854775807 * port.server", "1 / (port.server-443)", "len(range(-9223372036854775807,port.server))", "byte(udp.payload,port.server)", "u16be(udp.payload,port.server-442)", "len(write_u16be(udp.payload,0,port.server*1000))", "len(slice(udp.payload,1,port.server-443))"} {
		p := compile(t, "on check: tcp.syn { ip.dscp = "+expr+"; }")
		h := fixtureHost()
		h.values["udp.payload"] = fixtureBytes(t, []byte{1, 2})
		r, e := p.Run("tcp.syn", h)
		if e == nil || !r.Dropped {
			t.Fatal(expr, r, e)
		}
	}
	p := compile(t, `on budget: tcp.syn { for a in range(0,64) {for b in range(0,64){ count(); }} }`)
	r, e := p.Run("tcp.syn", fixtureHost())
	if e == nil || !r.Dropped || r.Instructions > MaxInstructions+1 {
		t.Fatal(r, e)
	}
	p = compile(t, `on copies: tcp.syn { for a in range(0,64) { udp.payload = write_u16be(udp.payload,0,a); } }`)
	h := fixtureHost()
	h.values["udp.payload"] = fixtureBytes(t, make([]byte, MaxBytes))
	r, e = p.Run("tcp.syn", h)
	if e == nil || !r.Dropped {
		t.Fatal(r, e)
	}
}
func TestDNSValidation(t *testing.T) {
	v, e := DNS("WWW.Example.TEST.")
	if e != nil || v.AsString() != "www.example.test" {
		t.Fatal(v, e)
	}
	for _, s := range []string{"", "host..test", "-bad.test", "bad-.test", "K.example", string([]byte{255})} {
		if _, e := DNS(s); e == nil {
			t.Fatal(s)
		}
	}
}
func TestConcurrentRunners(t *testing.T) {
	p := compile(t, `on tcp: tcp.syn { if port.server in [80,443] {ip.dscp=16;} }`)
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := fixtureHost()
			for i := 0; i < 100; i++ {
				r, e := p.Run("tcp.syn", h)
				if e != nil || r.Dropped || h.values["ip.dscp"].n != 16 {
					t.Error(r, e)
					return
				}
			}
		}()
	}
	wg.Wait()
}
func BenchmarkCompiledDispatch(b *testing.B) {
	p := compile(b, `on tcp: tcp.syn { if port.server == 443 && ip.server_address in prefix("10.0.0.0/8") {ip.dscp=16;} }`)
	for _, event := range []string{"udp.open", "tcp.syn"} {
		for _, reuse := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/reuse=%v", event, reuse), func(b *testing.B) {
				h := fixtureHost()
				scratch := make([]string, 0, len(p.ids))
				b.ReportAllocs()
				for b.Loop() {
					if reuse {
						_, _ = p.RunInto(event, h, scratch)
					} else {
						_, _ = p.Run(event, h)
					}
				}
			})
		}
	}
}
func FuzzCompileAndRun(f *testing.F) {
	for _, s := range []string{`on x: tcp.syn { if port.server==443 { ip.dscp=4; } }`, `fn id(a:int)->int{return a;} on f:tcp.syn { let a=id(1)+id(2); }`, `table t: string -> int={"a":1};`, `on bad: { [" }`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, e := Compile(s, schema(), nil)
		if e == nil {
			_, _ = p.RunTrace("tcp.syn", fixtureHost())
		}
	})
}

func TestRepeatedLargePayloadComparisonsAreBudgeted(t *testing.T) {
	p := compile(t, `on compare:tcp.syn { for n in range(0,64) { if udp.payload in [udp.payload] {count();} } }`)
	h := fixtureHost()
	h.values["udp.payload"] = fixtureBytes(t, make([]byte, MaxBytes))
	r, e := p.Run("tcp.syn", h)
	if e == nil || !r.Dropped || r.Instructions > 100 {
		t.Fatal("large reads escaped byte budget", r, e)
	}
}

func TestLookupFoundIsIndependentOfStoredValue(t *testing.T) {
	const src = `
 table text: int -> string = {443: ""};
 table numbers: int -> int = {443: 0};
 table flags: int -> bool = {443: false};
 fn classify(port:int) -> string {
    match lookup(flags,port) {
      missing { return "missing"; }
      found(flag) { if flag {return "yes";} else {return "no";} }
    }
 }
 on sample:tcp.syn {
   match lookup(text,port.server) {
      found(s) {mark=s;}
      missing {mark="missing";}
   }
   match lookup(numbers,port.server) {
      found(n) {ip.dscp=n;}
      missing {ip.dscp=17;}
   }
   route(classify(port.server),port.server);
 }`
	p := compile(t, src)
	for _, tc := range []struct {
		key   int64
		found bool
		text  string
		n     int64
		flag  string
	}{
		{443, true, "", 0, "no"}, {22, false, "missing", 17, "missing"},
	} {
		h := fixtureHost()
		h.values["port.server"] = Int(tc.key)
		r, e := p.RunTrace("tcp.syn", h)
		if e != nil || r.Dropped || h.values["mark"].t != TString || h.values["mark"].s != tc.text || h.values["ip.dscp"].n != tc.n || len(h.args) != 1 || h.args[0][0].s != tc.flag {
			t.Fatal(tc, r, h, e)
		}
		matches := 0
		for _, trace := range r.Trace {
			if trace.Lookup {
				matches++
				if trace.Taken != tc.found {
					t.Fatal(tc, trace)
				}
			}
		}
		if matches != 3 {
			t.Fatal("unexpected lookup traces", r.Trace)
		}
	}
}

func TestLookupMustBeExhaustivelyUnwrapped(t *testing.T) {
	const pre = `table flags: int -> bool={0:false}; `
	cases := []string{
		`on x:tcp.syn {match lookup(flags,0) {found(x) {count();}}}`,
		`on x:tcp.syn {match lookup(flags,0) {missing {drop();}}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(x) {} found(y) {} missing {}}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(x) {} missing {} missing {}}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(false) {} missing {}}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(x) {} missing {if x {count();}}}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(x) {} missing {}} if x {count();}}`,
		`on x:tcp.syn {match lookup(flags,0) {found(x) {ip.dscp=x;} missing {}}}`,
		`on x:tcp.syn {let x=true;match lookup(flags,0) {found(x) {} missing {}}}`,
		`on x:tcp.syn {match lookup(flags,"key") {found(x) {} missing {}}}`,
		`on x:tcp.syn {match lookup(flags,0,false) {found(x) {} missing {}}}`,
		`on x:tcp.syn {let x=lookup(flags,0,false);}`,
		`on x:tcp.syn {let x=lookup(flags,0);}`,
		`on x:tcp.syn {if lookup(flags,0) {count();}}`,
		`on x:tcp.syn {if lookup(flags,0)==false {count();}}`,
		`on x:tcp.syn {mark=string(lookup(flags,0));}`,
		`on x:tcp.syn {let x=[lookup(flags,0)];}`,
		`on x:tcp.syn {lookup(flags,0);}`,
		`fn unchecked(p:int)->bool {return lookup(flags,p);}`,
		`fn incomplete(p:int)->bool {match lookup(flags,p) {found(f){return f;} missing {}}}`,
	}
	for _, source := range cases {
		if _, e := Compile(pre+source, schema(), nil); e == nil {
			t.Fatal("accepted unhandled or invalid option", source)
		}
	}
}

func TestLookupErrorsNeverEnterMissingArm(t *testing.T) {
	const src = `table flags:int -> bool={0:false}; on x:tcp.syn {
 match lookup(flags,u16be(udp.payload,0)) {
   found(f) {count();} missing {mark="missing";}
 }}`
	p := compile(t, src)
	for _, key := range []Value{{}, String("invalid"), fixtureBytes(t, []byte{1})} {
		h := fixtureHost()
		if key.Type() != "" {
			h.values["udp.payload"] = key
		}
		r, e := p.RunTrace("tcp.syn", h)
		if e == nil || !r.Dropped || len(r.Trace) != 0 || h.values["mark"].Type() != "" {
			t.Fatal("key failure treated as a miss", r, h, e)
		}
	}
	// A valid key with no entry reaches missing.
	h := fixtureHost()
	h.values["udp.payload"] = fixtureBytes(t, []byte{1, 2})
	r, e := p.RunTrace("tcp.syn", h)
	if e != nil || r.Dropped || len(r.Trace) != 1 || !r.Trace[0].Lookup || r.Trace[0].Taken || h.values["mark"].s != "missing" {
		t.Fatal(r, e, h)
	}
}
func TestBoundedByteConstructionDistinguishesEmptyFromInvalid(t *testing.T) {
	v, e := Bytes(nil)
	if e != nil || v.Type() != TBytes || len(v.AsBytes()) != 0 {
		t.Fatal("empty byte string must be valid")
	}
	v, e = Bytes(make([]byte, MaxBytes+1))
	if e == nil || v.Type() == TBytes {
		t.Fatal("oversized byte string conflated with empty")
	}
}
func BenchmarkTaggedLookup(b *testing.B) {
	p := compile(b, `table ranges:prefix -> int={10.0.0.0/8:0}; on packet:tcp.syn {
 match lookup(ranges,ip.server_address){found(n){ip.dscp=n;} missing {drop();}}
 }`)
	for _, addr := range []string{"10.1.2.3", "192.0.2.1"} {
		b.Run(addr, func(b *testing.B) {
			h := fixtureHost()
			h.values["ip.server_address"] = Addr(netip.MustParseAddr(addr))
			scratch := make([]string, 0, 1)
			b.ReportAllocs()
			for b.Loop() {
				_, _ = p.RunInto("tcp.syn", h, scratch)
			}
		})
	}
}
