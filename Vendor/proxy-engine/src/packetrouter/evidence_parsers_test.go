// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func fixtureHello(name string, ech bool) []byte {
	vec := func(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) }
	entry := append([]byte{0}, vec([]byte(name))...)
	extensions := append([]byte{0, 0}, vec(vec(entry))...)
	if ech {
		extensions = append(extensions, 0xfe, 0x0d, 0, 1, 0)
	}
	fixed := make([]byte, 34)
	fixed[0], fixed[1] = 3, 3
	body := append(fixed, 0, 0, 2, 0x13, 1, 1, 0)
	body = append(body, vec(extensions)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}
func fixtureRecord(body []byte) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(body))), body...)
}

func TestEvidenceClientHelloBoundaries(t *testing.T) {
	msg := fixtureHello("Portal.Example", false)
	for i := 1; i < len(msg); i++ {
		records := append(fixtureRecord(msg[:i]), fixtureRecord(msg[i:])...)
		if name, ok := eventTLSHello(records); !ok || name != "portal.example" {
			t.Fatalf("record split at %d lost SNI", i)
		}
		if _, ok := eventTLSHello(records[:len(records)-1]); ok {
			t.Fatal("incomplete record disclosed SNI")
		}
	}
	for _, data := range [][]byte{fixtureRecord(fixtureHello("front.example", true)), fixtureRecord(fixtureHello("127.0.0.1", false)),
		fixtureRecord(fixtureHello("bad\nname", false)), {23, 3, 3, 0, 1, 1}, nil} {
		if _, ok := eventTLSHello(data); ok {
			t.Fatal("unsupported TLS evidence")
		}
	}
}

func fixtureDNS(t *testing.T, host string, reply bool, ip [4]byte, ttl uint32) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(host + ".")
	edge := dnsmessage.MustNewName("edge.example.")
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 19, Response: reply}, Questions: []dnsmessage.Question{q}}
	if reply {
		msg.Answers = []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: edge, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}},
			{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.example."), Class: dnsmessage.ClassINET, TTL: 20}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}}},
			{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.CNAMEResource{CNAME: edge}},
		}
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEvidenceDNSCNAMEChainAndTTL(t *testing.T) {
	ip := [4]byte{192, 0, 2, 10}
	query := fixtureDNS(t, "Portal.Example", false, ip, 2)
	reply := fixtureDNS(t, "Portal.Example", true, ip, 2)
	if name, ok := eventDNSQuestion(query); !ok || name != "portal.example" {
		t.Fatal("lost question")
	}
	if _, ok := eventDNSQuestion(reply); ok {
		t.Fatal("response classified as a question")
	}
	p, q, ok := parseEvidenceQuestion(reply, true)
	if !ok {
		t.Fatal("bad question")
	}
	hints := evidenceAnswers(reply, p, q)
	if len(hints) != 1 || hints[0].address != netip.AddrFrom4(ip) || hints[0].ttl != 2*time.Second {
		t.Fatalf("unexpected hints %v", hints)
	}
}
