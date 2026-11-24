// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// Package catalog describes event fields at specific protocol boundaries.
// A schema permits operations inside that adapter only. It does not grant an
// application permission to inspect another process or decrypt a transport.
package catalog

import (
	"slices"
	"strings"

	"pxengine/routelang"
)

type Entry struct {
	Event       string `json:"event"`
	Protocol    string `json:"protocol"`
	Boundary    string `json:"boundary"`
	Live        string `json:"live"`
	Description string `json:"description"`
}

// Live labels identify the source of comparable evidence in the shipping app.
// Only an adapter registering this particular schema can execute OO rules.
const (
	inspector   = "packet-inspector"
	proxyTunnel = "proxy-tunnel"
	lifecycle   = "lifecycle-observed"
	simulation  = "simulation"
)

type declaration struct {
	entry Entry
	event routelang.Event
}

func combine(groups ...map[string]routelang.Field) map[string]routelang.Field {
	fields := map[string]routelang.Field{}
	for _, group := range groups {
		for name, field := range group {
			fields[name] = field
		}
	}
	return fields
}
func fields(t routelang.Type, writable bool, names string) map[string]routelang.Field {
	result := map[string]routelang.Field{}
	for _, name := range strings.Fields(names) {
		result[name] = routelang.Field{Type: t, Writable: writable}
	}
	return result
}

func definitions() []declaration {
	const i = routelang.TInt
	const s = routelang.TString
	const b = routelang.TBool
	const a = routelang.TAddr
	const d = routelang.TDNS
	const raw = routelang.TBytes
	ro := func(t routelang.Type, names string) map[string]routelang.Field { return fields(t, false, names) }
	rw := func(t routelang.Type, names string) map[string]routelang.Field { return fields(t, true, names) }
	var out []declaration
	add := func(name, protocol, boundary, live, description string, groups ...map[string]routelang.Field) {
		out = append(out, declaration{Entry{name, protocol, boundary, live, description}, routelang.Event{Fields: combine(groups...)}})
	}
	ip := combine(ro(a, "ip.src ip.dst"), ro(i, "ip.version ip.protocol ip.length ip.ecn"), rw(i, "ip.dscp"))
	scope := combine(ro(s, "flow.source flow.member flow.direction flow.adapter flow.exit_node"), ro(i, "flow.generation"), ro(b, "flow.has_exit_node"))
	transport := combine(ip, scope, ro(i, "port.src port.dst"))
	roles := combine(ro(a, "ip.client_address ip.server_address"), ro(i, "port.client port.server"))
	tcpTransport := combine(transport, roles)
	observeFlow := combine(ro(a, "ip.src ip.dst"), ro(i, "port.src port.dst"), scope, roles)
	life := combine(ro(s, "vpn.profile vpn.state"), ro(i, "vpn.generation"))
	advert := combine(ro(s, "route.member route.family"), ro(i, "route.generation"))
	tlsSession := combine(ro(s, "tls.version tls.alpn"), ro(b, "tls.peer_verified"))
	ftpProtection := combine(ro(s, "ftp.tls_mode"), ro(b, "ftp.control_encrypted ftp.data_private"))
	ftpCommand := combine(observeFlow, ftpProtection, tlsSession, ro(s, "ftp.command"), ro(i, "ftp.control_generation"))
	add("socket.open", "Outbound socket", "Before source policy selection", simulation,
		"One attributable outbound flow opens for a destination at TCP connect, UDP connect or the first UDP send-to for a new flow. Socket allocation alone supplies no destination. This offline event runs before source policy selection. Live packet callbacks observe packets later.",
		ro(s, "socket.transport socket.family"), ro(a, "socket.local_address socket.remote_address"), ro(i, "socket.local_port socket.remote_port"),
		ro(s, "process.signing_identifier process.executable_name process.executable_path process.proxy_variable process.expected_proxy_endpoint"),
		ro(b, "process.signature_verified process.proxy_endpoint_matched"), ro(routelang.ArrayType(s), "process.ancestor_paths"))
	add("ethernet.frame", "Ethernet", "Ethernet interface", simulation, "A layer-2 adapter can observe link headers. The macOS packet tunnel supplies raw IP without Ethernet framing.", ro(raw, "ethernet.src ethernet.dst"), ro(i, "ethernet.type ethernet.length"))
	add("vlan.tag", "802.1Q", "VLAN-aware link", simulation, "The VLAN ID and priority are available only to an adapter that receives an Ethernet tag.", ro(i, "vlan.id vlan.priority vlan.ether_type"))
	add("ip.packet", "IP", "Inner packet", inspector, "The inner IP header is visible before encapsulation or after authenticated decapsulation. The source rule identifier is available only for an attributed flow.", ip, scope)
	add("ipv4.packet", "IPv4", "Inner packet", inspector, "Packet length, protocol, fragmentation metadata and traffic class belong to this IPv4 packet.", ip, scope, ro(i, "ipv4.ttl ipv4.id ipv4.fragment_offset"), ro(b, "ipv4.more_fragments"))
	add("ipv6.packet", "IPv6", "Inner packet", inspector, "The IPv6 header exposes its flow label and hop limit. A transport header may be absent from a fragment.", ip, scope, ro(i, "ipv6.flow_label ipv6.hop_limit"))
	add("tcp.syn", "TCP", "Opening TCP segment", inspector, "A SYN exposes ports, flags and the MSS option when present. Existing MSS can be reduced.", tcpTransport, ro(i, "tcp.flags tcp.sequence"), rw(i, "tcp.mss"))
	add("tcp.data", "TCP", "Inner TCP segment", inspector, "Segment direction and sequence are visible. Stream-level parsers must handle segmentation separately.", tcpTransport, ro(i, "tcp.flags tcp.sequence tcp.payload_length"))
	add("udp.open", "UDP", "Opening UDP datagram", inspector, "The first admitted outgoing datagram opens a tracked tuple.", transport, ro(i, "udp.length"))
	add("udp.datagram", "UDP", "Inner UDP datagram", inspector, "The datagram exposes a payload length and ports. Application contents depend on the carried protocol.", transport, ro(i, "udp.length"))
	add("icmp.message", "ICMP", "Inner IPv4 control packet", inspector, "A validated IPv4 ICMP type and code describe the control message.", ip, scope, ro(i, "icmp.type icmp.code"))
	add("icmpv6.message", "ICMPv6", "Inner IPv6 control packet", inspector, "A validated IPv6 ICMP type and code describe the control message.", ip, scope, ro(i, "icmp.type icmp.code"))
	add("dns.query", "DNS", "Plain UDP DNS question", inspector, "A complete single-question datagram exposes its name, type and recursion-desired flag.", tcpTransport, ro(d, "dns.name"), ro(i, "dns.id dns.type"), rw(b, "dns.rd"))
	add("dns.answer", "DNS", "Matched resolver response", inspector, "A matched UDP answer supplies a TTL-limited address association within its VPN and source scope.", observeFlow, ro(d, "dns.name"), ro(a, "dns.address"), ro(i, "dns.ttl dns.type"))
	add("tls.client_hello", "TLS", "Visible ClientHello", proxyTunnel, "The proxy can select an explicit backend before dialing. Missing, encrypted or incomplete names are unavailable.", observeFlow, ro(d, "tls.sni"), ro(b, "tls.ech"))
	add("tls.negotiated", "TLS", "Locally terminated TLS", simulation, "The owning endpoint can supply negotiated TLS evidence. An explicitly identified FTP control session may additionally report its observed protection state.", observeFlow, ftpProtection, tlsSession, ro(s, "tls.application_protocol"))
	add("proxy.pre_connect", "Split proxy", "Locally accepted frontend", proxyTunnel, "A local proxy can wait for a visible server name before choosing an approved backend. A local reply uses only the endpoint already owned.", roles, ro(d, "tls.sni"))
	add("udp.owned_datagram", "UDP endpoint", "Owned datagram builder", simulation, "A testing endpoint may transform a bounded payload before serializing a new UDP/IP datagram with new lengths and checksums.", transport, rw(raw, "udp.payload"))
	add("tls.backend_connect", "TLS", "Independent backend TLS client", simulation, "A locally terminated frontend may configure its own TLS client before dialing an authorized backend. Certificate and name verification remain required.", roles, ro(d, "tls.frontend_name"), rw(d, "tls.upstream_sni"), rw(s, "tls.backend_alpn"), ro(b, "tls.verify_peer"))
	add("quic.initial", "QUIC", "QUIC Initial header", inspector, "A validated v1 or v2 Initial exposes its public version and destination connection ID. The packet router does not decrypt its handshake.", transport, ro(i, "quic.version"), ro(raw, "quic.dcid"))
	add("quic.crypto_hello", "QUIC", "Decoded Initial CRYPTO frames", simulation, "This fixture supplies a reassembled ClientHello from an Initial decoder. Encrypted ClientHello can still conceal the inner name.", observeFlow, ro(d, "tls.sni"))
	add("quic.stream", "QUIC", "Terminated QUIC session", simulation, "Decrypted stream identity and offsets are available to the owning endpoint.", observeFlow, ro(i, "quic.stream_id quic.offset quic.length"), ro(b, "quic.fin"))
	add("http.request", "HTTP", "Owned HTTP frontend", simulation, "Request method, authority and path require cleartext HTTP or an explicitly terminated client session. The backend request can be rebuilt before sending.", observeFlow, ro(s, "http.method http.authority"), rw(s, "http.path"), ro(i, "http.version_major"))
	add("http.response", "HTTP", "Owned HTTP frontend", simulation, "An HTTP endpoint can construct its reply before the response headers have been committed.", observeFlow, rw(i, "http.status"), ro(s, "http.content_type"))
	add("http.connect", "HTTP CONNECT", "Configured upstream proxy", proxyTunnel, "The proxy client knows the chosen target and the upstream reply. The established byte stream remains opaque.", ro(s, "proxy.target"), ro(i, "proxy.port http.status"))
	add("socks.request", "SOCKS5", "Configured upstream proxy", proxyTunnel, "SimpleVPN creates the SOCKS request for a chosen target. Authentication secrets are excluded.", ro(s, "socks.command socks.target"), ro(i, "socks.port"))
	add("socks.reply", "SOCKS5", "Configured upstream proxy", proxyTunnel, "The SOCKS response reports the status and optional bound address before a relay is established.", ro(i, "socks.status socks.bound_port"), ro(a, "socks.bound_address"))
	add("ftp.command", "FTP", "Owned FTP control parser", simulation, "One complete parsed command verb from a cleartext or locally decrypted FTP control stream. A passive command dispatches its specialized hook after the general hook. Arguments and credentials are excluded.", ftpCommand)
	add("ftp.command.passive", "FTP", "Derived from a parsed PASV or EPSV", simulation, "After ftp.command succeeds, PASV and EPSV dispatch this hook once. The request has no server data port yet. A later validated offer can authorize a data flow.", ftpCommand)
	add("ftp.reply", "FTP", "Owned FTP control parser", simulation, "The endpoint can read a complete numeric reply after handling multiline FTP responses.", observeFlow, ftpProtection, tlsSession, ro(i, "ftp.code ftp.control_generation"))
	add("ftp.data_offer", "FTP", "Validated FTP control exchange", simulation, "A passive or active endpoint proposal is scoped to its control session. A related data flow needs an independently validated peer and bounded expectation.", observeFlow, ftpProtection, tlsSession, ro(s, "ftp.mode"), ro(a, "ftp.peer"), ro(i, "ftp.port ftp.control_generation"))
	add("sip.request", "SIP", "Parsed signaling endpoint", simulation, "A cleartext or locally terminated SIP transaction exposes its method and sequence number.", observeFlow, ro(s, "sip.method"), ro(i, "sip.cseq"))
	add("sip.response", "SIP", "Parsed signaling endpoint", simulation, "A parsed SIP response supplies a status tied to its signaling transaction.", observeFlow, ro(i, "sip.status sip.cseq"))
	add("sip.media_offer", "SIP/SDP", "Validated signaling endpoint", simulation, "A parsed media proposal alone does not authorize an RTP flow. Direction, peer, generation and expiry constrain any expectation.", observeFlow, ro(s, "sdp.media sdp.transport"), ro(a, "sdp.address"), ro(i, "sdp.port"))
	add("ssh.session", "SSH", "Owned SSH session", lifecycle, "The SSH engine knows its own session state and host verification result. Keys, passwords and agent traffic remain private.", life, ro(b, "ssh.host_verified"))
	add("ssh.forward_open", "SSH", "Owned forwarding channel", proxyTunnel, "The SSH flow dialer receives the explicitly requested target before opening a channel through the established session.", ro(s, "ssh.direction ssh.target ssh.mode"), ro(i, "ssh.port"))
	add("ssh.reverse_delivery", "SSH", "Managed OpenSSH reverse delivery", proxyTunnel, "The app checks the configured destination after OpenSSH accepts a remote channel and before opening a local service connection.", ro(s, "ssh.direction ssh.target ssh.mode"), ro(i, "ssh.port"))
	add("wireguard.handshake", "WireGuard", "WireGuard peer status", lifecycle, "The engine exposes a peer’s most recent handshake time from status. Payloads of the cryptographic handshake are opaque.", life, ro(i, "wireguard.handshake_age"))
	add("wireguard.peer", "WireGuard", "WireGuard peer status", lifecycle, "Configured peer prefixes and traffic counters are available through the owning engine.", life, ro(i, "wireguard.rx_bytes wireguard.tx_bytes"), ro(routelang.TPrefix, "wireguard.allowed_prefix"))
	add("openvpn.connected", "OpenVPN", "OpenVPN 3 tunnel establishment", lifecycle, "The bridge reports its tunnel state and negotiated addresses. Credentials and control-channel ciphertext are excluded.", life, ro(a, "vpn.address"))
	add("openconnect.connected", "OpenConnect", "Owned OpenConnect session", lifecycle, "The bridge reports tunnel state, assigned address and protocol family across Cisco, Fortinet, F5, GlobalProtect, Juniper, Pulse and Array profiles.", life, ro(s, "openconnect.protocol"), ro(a, "vpn.address"))
	add("tailscale.state", "Tailscale", "Owned node status", lifecycle, "The node reports backend state, local addresses and route advertisements through its control interface.", life, ro(s, "tailscale.backend_state"), ro(a, "vpn.address"))
	add("headscale.state", "Headscale", "Owned Tailscale node", lifecycle, "A Headscale profile uses the same local node engine and state callbacks as a Tailscale profile.", life, ro(s, "tailscale.backend_state"), ro(a, "vpn.address"))
	add("ike.state", "IKEv2", "macOS VPN status", lifecycle, "A native profile exposes macOS connection status. Its on-wire IKE handshake and security associations are owned by the OS.", life)
	add("ipsec.sa", "IPsec", "Controlled IPsec test endpoint", simulation, "SPI and transform details require endpoint visibility. The native macOS personal VPN does not provide these packet hooks.", ro(i, "ipsec.spi"), ro(s, "ipsec.transform ipsec.direction"))
	add("l2tp.state", "L2TP/IPsec", "Externally managed L2TP session", simulation, "SimpleVPN exports the L2TP profile. A fixture can supply state from an external owner. The app has no live session or packet callback for that profile.", life)
	add("vpn.state", "VPN lifecycle", "Owned profile status", lifecycle, "Connection and generation changes are reported by the profile owner independently of packet inspection.", life)
	add("route.advertised", "Routing", "Owned route proposal", lifecycle, "A member proposes a prefix before policy admission. The owner must validate every resulting prefix against its authorized routes.", advert, rw(routelang.TPrefix, "route.prefix"), rw(i, "route.metric"), ro(b, "route.default"))
	add("route.withdrawn", "Routing", "Owned route withdrawal", lifecycle, "A withdrawal identifies the member and generation whose prefix is no longer offered.", advert, ro(routelang.TPrefix, "route.prefix"))
	add(ExitSelectionEvent, "Routing", "New outbound connection before egress", inspector,
		"Choose an authenticated exit node for a captured destination. A TCP connection evaluates the opening SYN. A datagram flow evaluates its first packet.",
		ro(a, "ip.src ip.dst"), ro(i, "ip.version ip.protocol ip.length port.src port.dst"), ro(s, "flow.source flow.direction flow.adapter"))
	for i := range out {
		event := &out[i]
		switch event.entry.Event {
		case "tls.negotiated":
			event.event.Compatibility = map[string]routelang.Event{
				"ftps.handshake": {Fields: combine(observeFlow, ro(s, "ftps.mode"), ro(b, "ftps.control_encrypted ftps.data_private"))},
			}
		case "socket.open":
			event.event.Actions = map[string][]routelang.Type{"source.select_member": {s}}
		case ExitSelectionEvent:
			event.event.Actions = map[string][]routelang.Type{"route.exit_node": {s}}
		case "proxy.pre_connect":
			event.event.Actions = map[string][]routelang.Type{"proxy.select_backend": {s}, "proxy.reply_client": {routelang.TInt}}
		case "http.request":
			event.event.Actions = map[string][]routelang.Type{"proxy.select_backend": {s}, "proxy.reply_client": {routelang.TInt}}
		case "http.response":
			event.event.Actions = map[string][]routelang.Type{"proxy.reply_client": {routelang.TInt}}
		case "ftp.command", "ftp.command.passive", "sip.request":
			event.event.Actions = map[string][]routelang.Type{"proxy.reply_client": {routelang.TInt}}
		case "ftp.reply", "sip.response":
			event.event.Actions = map[string][]routelang.Type{"proxy.reply_server": {routelang.TInt}}
		case "ftp.data_offer", "sip.media_offer":
			event.event.Actions = map[string][]routelang.Type{"session.expect": {a, routelang.TInt, routelang.TInt}}
		}
	}
	// The captured return leg has its own hooks. Adding policy to an existing
	// installation cannot turn an outbound subscription into an inbound one.
	for _, hook := range PacketHooks() {
		for i := range out {
			if out[i].entry.Event != hook {
				continue
			}
			e := &out[i]
			for _, name := range []string{"flow.direction", "flow.adapter", "flow.profile", "vpn.kind"} {
				e.event.Fields[name] = routelang.Field{Type: routelang.TString}
			}
			in := declaration{entry: e.entry, event: routelang.Event{Fields: combine(e.event.Fields)}}
			in.entry.Event = "inbound." + hook
			in.entry.Boundary = "Decrypted or decapsulated inner traffic before delivery to macOS"
			in.entry.Live = inspector
			in.entry.Description = "The VPN engine supplied an incoming " + hook + " observation. A dropped packet never reaches the local interface."
			for _, name := range []string{"ip.client_address", "ip.server_address", "port.client", "port.server", "tls.ech"} {
				delete(in.event.Fields, name)
			}
			out = append(out, in)
			break
		}
	}

	return out
}

// Schema builds an independent copy for an offline interpreter. Live adapters
// should supply only their own supported fields and effects.
func Schema() routelang.Schema {
	out := routelang.Schema{}
	for _, d := range definitions() {
		out[d.entry.Event] = d.event
	}
	return out
}
func Inventory() []Entry {
	ds := definitions()
	out := make([]Entry, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.entry)
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Event, b.Event) })
	return out
}

const packetHooks = "ip.packet ipv4.packet ipv6.packet tcp.syn tcp.data udp.open udp.datagram icmp.message icmpv6.message dns.query tls.client_hello quic.initial"

const ExitSelectionEvent = "route.select"

// PacketHooks lists the base names; ingress uses the inbound. prefix.
func PacketHooks() []string { return strings.Fields(packetHooks) }

// Packet returns the capability set of the shared virtual interface.
func Packet() routelang.Schema { return packetSchema(true) }

// PacketForAdapter rejects tunnels whose packets are owned by an external
// process or macOS. The configured profile kind alone cannot identify the hook.
func PacketForAdapter(id string) (routelang.Schema, bool) {
	a, ok := AdapterByID(id)
	if !ok || !a.PacketPolicy() {
		return nil, false
	}
	schema := packetSchema(id == "wireguard-shared")
	if id == "l2tp-strongswan" {
		// PPP negotiates IPCP only, so these events cannot be observed.
		for _, name := range []string{"ipv6.packet", "icmpv6.message", "inbound.ipv6.packet", "inbound.icmpv6.message"} {
			delete(schema, name)
		}
	}
	return schema, true
}

func packetSchema(shared bool) routelang.Schema {
	offline := Schema()
	out := routelang.Schema{}
	for _, name := range PacketHooks() {
		base := offline[name]
		for _, prefix := range []string{"", "inbound."} {
			event := routelang.Event{Fields: combine(base.Fields)}
			if !shared {
				delete(event.Fields, "flow.member")
				delete(event.Fields, "flow.generation")
				delete(event.Fields, "flow.source")
				delete(event.Fields, "flow.exit_node")
				delete(event.Fields, "flow.has_exit_node")
			}
			delete(event.Fields, "tls.ech")
			if name == "quic.initial" {
				delete(event.Fields, "tls.sni")
			}
			if prefix != "" || name == "quic.initial" {
				for _, f := range []string{"ip.client_address", "ip.server_address", "port.client", "port.server"} {
					delete(event.Fields, f)
				}
			}
			event.Fields["flow.direction"] = routelang.Field{Type: routelang.TString}
			event.Fields["flow.adapter"] = routelang.Field{Type: routelang.TString}
			out[prefix+name] = event
		}
	}
	if shared {
		out[ExitSelectionEvent] = offline[ExitSelectionEvent]
	}
	return out
}

// LiveForAdapter is shared by the checker, editor and offline manual.
func LiveForAdapter(adapter string) (routelang.Schema, bool) {
	if events := SSHEvents(adapter); len(events) > 0 {
		schema := routelang.Schema{}
		all := Schema()
		for _, event := range events {
			schema[event] = all[event]
		}
		return schema, true
	}
	return PacketForAdapter(adapter)
}
