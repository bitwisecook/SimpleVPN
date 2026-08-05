// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingRelations.swift
//  THE relation map: which settings a user reading about one setting needs to
//  know about. Every "Related settings" link in a help popover comes from here.
//
//  The knowledge is not new — it was already written down as caveats and
//  disabledReasons ("Proxies only carry TCP…", "Turn on XAuth to use these",
//  "Use TLS 1.3 ciphersuites below instead") — but only ever as prose the user
//  had to act on by hand: read the sentence, remember the other setting's name,
//  go and find it. A relation turns each of those sentences into a link.
//
//  DECLARED AS CLIQUES, not as a `related:` list per spec, and deliberately:
//  relations are symmetric ("A relates to B" means "B relates to A"), and a
//  per-spec list makes symmetry a thing thirty-odd declarations have to
//  remember. A clique is one declaration that produces both directions, so a
//  half-declared relation — a link that works one way and dead-ends the other —
//  cannot be written. `oneWay` exists for the case where a relation genuinely
//  runs in one direction only; it is empty on purpose, and adding to it should
//  be argued for in a comment.
//
//  Ids here MUST exist in some catalog: a dangling relation is a dead link, and
//  SettingRelationTests fails the build on one.
//

import Foundation

nonisolated enum SettingRelations {

    /// Mutually-related groups. Every member relates to every other member, in
    /// declaration order (so a clique's first-named settings lead the list).
    ///
    /// A clique is kept SMALL on purpose: it is rendered as a list of links in a
    /// popover, and "related to nine things" is another way of saying "related to
    /// nothing". Where a hub setting gates several others (the proxy master
    /// toggle, the sign-in method) the hub gets its own clique with them, and the
    /// leaves get pairs.
    static let cliques: [[String]] = [

        // MARK: OpenVPN

        // The proxy sub-form: the master toggle and the five rows it unhides.
        // Every one of these already disabled itself with "Enter a proxy host
        // first" / "Enter a proxy username first" — the reason named a setting
        // the user then had to go and find.
        ["openvpn.proxy-enabled", "openvpn.proxy-host", "openvpn.proxy-port",
         "openvpn.proxy-username", "openvpn.proxy-password", "openvpn.proxy-cleartext-auth"],
        // "Proxies only carry TCP. UDP won't work while a proxy is configured."
        // — said on BOTH rows already, because either is where the user is
        // looking when they make the pair impossible.
        ["openvpn.protocol", "openvpn.proxy-host"],
        ["openvpn.protocol", "openvpn.port", "openvpn.server"],
        // "This list only names TLS 1.2-and-below ciphers, and Minimum TLS
        // Version is TLS 1.3 — use TLS 1.3 ciphersuites below instead."
        ["openvpn.tls-version-min", "openvpn.tls-cipher-list", "openvpn.tls-ciphersuites"],
        ["openvpn.tls-cert-profile", "openvpn.tls-version-min"],
        ["openvpn.legacy-algorithms", "openvpn.non-preferred-ciphers"],
        ["openvpn.local-lan", "openvpn.unused-families"],
        // The private key's password unlocks the key the certificate row shows,
        // and "don't send a client certificate" is the way to stop needing it.
        ["openvpn.private-key-password", "openvpn.no-client-cert"],

        // MARK: WireGuard

        // The Allowed IPs decide whether a DNS server inside the tunnel is even
        // reachable — the split-tunnel footgun WireGuardConfig.dnsCoverageWarning
        // already spells out row-side.
        ["wg.allowed-ips", "wg.dns", "wg.address"],
        // "off tells wg-quick to install no routes at all, so the Allowed IPs
        // above route nothing there."
        ["wg.allowed-ips", "wg.table"],
        // Two export-only routing escape hatches, each other's siblings.
        ["wg.table", "wg.fwmark"],
        ["wg.private-key", "wg.public-key", "wg.preshared-key"],
        ["wg.endpoint", "wg.listen-port", "wg.keepalive"],

        // MARK: Tailscale / Headscale

        // The exit-node cluster: every caveat in the Traffic section names
        // another member ("With shared networks off, only your internet traffic
        // goes through the other machine", "your traffic goes through the other
        // machine but your name lookups don't").
        ["ts.exit-node", "ts.exit-node-machine", "ts.exit-node-lan",
         "ts.accept-routes", "ts.accept-dns"],
        // Accepting networks others share and sharing this Mac's are converses.
        ["ts.accept-routes", "ts.advertise-routes"],
        // The preset decides whether a server address is asked for at all, and
        // which shape of setup key is the right one.
        ["ts.preset", "ts.control-url", "ts.auth-key"],

        // MARK: SSH

        // "Automatic tries your key, then the SSH agent, then the password;
        // choosing one method uses exactly that method" — the method decides
        // which of the three below is the one that matters.
        ["ssh.auth-method", "ssh.identity-file", "ssh.certificate-file",
         "ssh.password", "ssh.username"],
        // Signing in through an agent is the method, and the socket says WHICH
        // agent — the two are useless apart, and the socket is the part nobody
        // guesses (a vendor agent doesn't listen where macOS's own does).
        ["ssh.auth-method", "ssh.agent-socket"],
        // The alternative to handing us a key file is letting an agent hold it.
        ["ssh.identity-file", "ssh.agent-socket"],
        // A certificate vouches for a key, so it is useless without one.
        ["ssh.identity-file", "ssh.certificate-file"],
        // The jump host's sign-in is independent of the server's, which is
        // exactly why its four fields need to be findable together.
        ["ssh.proxy-jump", "ssh.jump-port", "ssh.jump-username", "ssh.jump-identity-file"],
        ["ssh.server", "ssh.port", "ssh.proxy-jump"],
        // The mode decides which of the traffic controls does anything.
        ["ssh.mode", "ssh.socks-port", "ssh.forwards", "ssh.system-proxy"],
        // Pinning a host key overrides host-key checking entirely.
        ["ssh.strict-host-key", "ssh.pinned-host-key"],

        // MARK: OpenConnect SSL VPNs

        ["oc.client-cert", "oc.client-key", "oc.key-password", "oc.cafile"],
        // The three sign-in shapes are alternatives to each other.
        ["oc.password", "oc.client-cert", "oc.sso-browser"],
        ["oc.token-mode", "oc.token-secret", "oc.password"],
        // The AGENTS.md MTU split, stated as a link: one is the tunnel's, the
        // other the path underneath it.
        ["oc.mtu", "oc.base-mtu"],
        // Both answer "how fast is a dropped tunnel noticed and retried".
        ["oc.reconnect-timeout", "oc.force-dpd"],
        // The two ways to verify the SERVER — the only two these seven kinds have.
        // A private-CA gateway is covered by the CA file; a self-signed one only
        // by the pin, and a user who found the wrong one needs the other.
        ["oc.pinned-server-cert", "oc.cafile"],
        // "Overridden by the host-checker wrapper below, which runs instead.
        // Clear that wrapper to skip the check." — the disabledReason on the skip
        // toggle already named the wrapper; now it links to it.
        ["oc.disable-csd", "oc.csd-wrapper"],
        // The SOCKS pair, exactly as the SSH surface declares it — and the
        // in-process engine, which replaces both with a full system tunnel.
        ["oc.socks-port", "oc.system-proxy", "oc.prefer-in-process"],
        // What this client claims to BE. Four fields answering one question
        // ("what does the gateway think is connecting?"), so someone who found
        // one has found them all.
        ["oc.os", "oc.local-hostname", "oc.user-agent", "oc.version-string"],

        // MARK: Native (IKEv2 / IPsec / L2TP)

        // "With the Diffie-Hellman Group above on Automatic, the data channel
        // rekeys with Group 14 — Automatic can't be honoured for it."
        ["native.pfs", "native.dh-group", "native.ike-lifetime"],
        ["native.encryption", "native.integrity", "native.dh-group"],
        ["native.auth-method", "native.username", "native.password", "native.shared-secret"],
        // "Turn on Also sign in with a username and password (XAuth) to use
        // these." — the disabledReason on two rows at once.
        ["native.xauth", "native.username", "native.xauth-password",
         "native.shared-secret", "native.group"],
        ["native.include-all", "native.exclude-local"],
        // The remote identifier is checked against the server this address names.
        ["native.protocol", "native.server", "native.remote-id"],
        ["native.on-demand", "native.disconnect-sleep"],
        ["native.dpd", "native.mobike"],

        // MARK: Proxy Tunnel

        ["px.kind", "px.address"],
        ["px.requires-auth", "px.username", "px.password", "px.address"],
        ["px.default-route", "px.included", "px.excluded"],
        // Lookups have to go through the proxy too or they leak — which is only
        // true if the resolver's own address is one of the networks carried.
        ["px.dns", "px.included", "px.excluded"],

        // MARK: Custom Routing ↔ the kind's own Traffic settings
        //
        // Custom Routing is the ONE surface every kind has, and it edits exactly
        // what the kind's Traffic group produces. Each clique below is one
        // engine's Traffic decision paired with the Custom Routing control that
        // rewrites it — the cross-TAB link the audit asked for, in both
        // directions, declared once.

        ["cr.routes-default", "cr.route-rule"],
        ["cr.route-rule", "openvpn.local-lan"],
        ["cr.route-rule", "wg.allowed-ips"],
        ["cr.route-rule", "ts.accept-routes"],
        ["cr.route-rule", "px.included"],
        ["cr.route-rule", "native.include-all"],
        // SSH's Mode is its routing decision (a network tunnel installs routes;
        // SOCKS and forwards install none), so it is the ssh.* end of this pair.
        // The OpenConnect kinds have no route spec at all — the gateway decides —
        // so nothing there is linked rather than something approximate.
        ["cr.route-rule", "ssh.mode"],

        ["cr.dns-default", "cr.dns-rule"],
        ["cr.dns-rule", "openvpn.google-dns-fallback"],
        ["cr.dns-rule", "wg.dns"],
        ["cr.dns-rule", "ts.accept-dns"],
        ["cr.dns-rule", "px.dns"],

        ["cr.ignore-pushed-search", "cr.add-search-domains"],
        ["cr.ignore-pushed-match", "cr.match-domains"],
        // "Ignored while a PAC URL is set — that wins."
        ["cr.proxy-mode", "cr.proxy-manual-url", "cr.proxy-pac-url", "cr.proxy-auth"],

        // The connection proxy (reaching the VPN server) and the Custom Routing
        // proxy (what the Mac uses while connected) are different things with
        // similar names — linking them is how a user who found the wrong one
        // gets to the right one.
        ["openvpn.proxy-host", "cr.proxy-manual-url"],
    ]

    /// Relations that genuinely run one way only, as (from, to). Empty, and that
    /// is the point: a one-way relation is a link that dead-ends when followed
    /// back, so it needs a reason written beside it.
    static let oneWay: [(from: String, to: String)] = []

    /// id → related ids, deduped, in declaration order. Symmetric by
    /// construction — there is no way to declare half a relation.
    static let related: [String: [String]] = {
        var out: [String: [String]] = [:]
        func add(_ from: String, _ to: String) {
            guard from != to else { return }
            var list = out[from] ?? []
            guard !list.contains(to) else { return }
            list.append(to)
            out[from] = list
        }
        for clique in cliques {
            for a in clique {
                for b in clique { add(a, b) }
            }
        }
        for (from, to) in oneWay { add(from, to) }
        return out
    }()

    /// Every id named anywhere in the map — what the existence test walks.
    static var referencedIDs: Set<String> {
        Set(cliques.flatMap { $0 }).union(oneWay.map(\.from)).union(oneWay.map(\.to))
    }
}
