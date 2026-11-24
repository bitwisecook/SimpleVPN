// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package catalog

import (
	"pxengine/routelang"
	"testing"
)

func TestInventoryAndPermissionBoundaries(t *testing.T) {
	all := Schema()
	rows := Inventory()
	seen := map[string]bool{}
	for _, entry := range rows {
		if _, ok := all[entry.Event]; !ok || seen[entry.Event] || entry.Boundary == "" || entry.Live == "" {
			t.Fatal("invalid inventory", entry)
		}
		seen[entry.Event] = true
	}
	if len(seen) != len(all) {
		t.Fatal("schema missing an inventory row")
	}
	if _, err := routelang.Compile("on packet: udp.owned_datagram { udp.payload = slice(udp.payload, 0, 2); }", all, nil); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{
		"on select: proxy.pre_connect { proxy.select_backend(\"work\"); }",
		"on change: tls.backend_connect { tls.upstream_sni = dns(\"backend.example\"); }",
		"on offer: ftp.data_offer { session.expect(ftp.peer, ftp.port, 5); }",
	} {
		if _, err := routelang.Compile(src, all, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := routelang.Compile(src, Packet(), nil); err == nil {
			t.Fatal("privileged endpoint operation available on raw packets", src)
		}
	}
	for name, event := range Packet() {
		for f, d := range event.Fields {
			if d.Writable && f != "ip.dscp" && f != "tcp.mss" && f != "dns.rd" {
				t.Fatalf("%s can mutate unsupported field %s", name, f)
			}
		}
	}
}

func TestFTPCompositionAndCompatibilityCapabilities(t *testing.T) {
	schema := Schema()
	if _, old := schema["ftps.handshake"]; old {
		t.Fatal("legacy FTPS is still a canonical protocol")
	}
	if _, ok := schema.Resolve("ftps.handshake"); !ok {
		t.Fatal("old programs no longer compile")
	}
	for _, name := range []string{"ftp.command", "ftp.command.passive", "ftp.reply", "ftp.data_offer"} {
		for _, field := range []string{"tls.version", "tls.alpn", "tls.peer_verified", "ftp.control_encrypted", "ftp.tls_mode", "ftp.data_private"} {
			if f, ok := schema[name].Fields[field]; !ok || f.Writable {
				t.Fatal(name, field)
			}
		}
	}
	for _, src := range []string{`on old:ftps.handshake {if ftps.data_private {count();}}`, `on cmd:ftp.command.passive {if tls.peer_verified {proxy.reply_client(200);}}`} {
		if _, e := routelang.Compile(src, schema, nil); e != nil {
			t.Fatal(e)
		}
		if _, e := routelang.Compile(src, Packet(), nil); e == nil {
			t.Fatal("endpoint hook reached raw packet path")
		}
	}
	if _, e := routelang.Compile(`on cmd:ftp.command.passive {session.expect(ip.dst,21,10);}`, schema, nil); e == nil {
		t.Fatal("unvalidated request can authorize a data channel")
	}
}
