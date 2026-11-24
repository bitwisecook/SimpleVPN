// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package catalog

import (
	"regexp"
	"slices"
	"testing"
)

func TestAdapterPolicyAndOperatingModeBoundaries(t *testing.T) {
	rows := Adapters()
	seen := map[string]bool{}
	validID := regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	for _, row := range rows {
		if !validID.MatchString(row.ID) || seen[row.ID] || row.Name == "" || len(row.Profiles) == 0 || row.Boundary == "" || row.Description == "" {
			t.Fatalf("invalid or duplicate adapter: %+v", row)
		}
		seen[row.ID] = true
		packet := slices.Contains([]string{"wireguard-shared", "wireguard", "wireguard-teleport", "tailscale-node", "openvpn3", "openconnect-packet", "openconnect-proxy", "proxy-socks5", "proxy-http", "proxy-https", "sshnet", "ssh-tun", "ikev2-strongswan", "ipsec-strongswan", "l2tp-strongswan"}, row.ID)
		if row.PacketPolicy() != packet {
			t.Fatalf("wrong live rich packet policy capability for %q", row.ID)
		}
		if row.Availability != "shipped" && row.Availability != "export-only" && row.Availability != "unavailable" {
			t.Fatalf("unknown availability on %q", row.ID)
		}
		if (len(row.VPNKinds) == 0) != (row.ID == "dns-query-proxy") {
			t.Fatalf("unexpected saved profile kind coverage on %q", row.ID)
		}
	}
	for id, availability := range map[string]string{
		"wireguard-shared": "shipped", "wireguard": "shipped", "wireguard-teleport": "shipped",
		"ikev2-strongswan": "shipped", "ipsec-strongswan": "shipped", "l2tp-strongswan": "shipped", "ssh-tun": "shipped", "l2tp-export": "export-only",
	} {
		row, ok := AdapterByID(id)
		if !ok || row.Availability != availability {
			t.Fatalf("%q reports %q; want %q", id, row.Availability, availability)
		}
	}
	if _, ok := AdapterByID("unrecognized"); ok {
		t.Fatal("unknown mode selected an adapter")
	}
	// Both preset and helper modes can share a saved kind. Checking the kind
	// alone would incorrectly admit SSH -w or silently attach an OpenConnect packet policy to a proxy subprocess.
	local, _ := AdapterByID("ssh-libssh")
	external, _ := AdapterByID("ssh-openssh")
	if !slices.Contains(local.ProfileModes, "portForward") || !slices.Contains(external.ProfileModes, "portForward") || slices.Contains(local.ProfileModes, "netTunnel") {
		t.Fatal("incorrect SSH forwarding coverage")
	}
}

func TestL2TPOnlyOffersNegotiatedIPFamilies(t *testing.T) {
	schema, ok := LiveForAdapter("l2tp-strongswan")
	if !ok {
		t.Fatal("owned L2TP has no packet hooks")
	}
	for _, prefix := range []string{"", "inbound."} {
		if _, present := schema[prefix+"ipv4.packet"]; !present {
			t.Fatal("missing IPCP packet hook")
		}
		for _, event := range []string{"ipv6.packet", "icmpv6.message"} {
			if _, present := schema[prefix+event]; present {
				t.Fatalf("L2TP advertised %s%s without IPv6CP", prefix, event)
			}
		}
	}
}
