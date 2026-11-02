# DNS routing review — 2026-11-02

The normal configuration path is DNS servers, search domains and supplied DNS.
Custom Routing is an expert surface, with precise semantics rather than tutorials.

## Findings addressed

1. **Query-name routing was absent.** Resolver rules edit offered server IPs;
   match domains become native macOS suffix scopes. Neither implements exact/glob
   QNAME matching. The advanced editor now separates Query Rules, DNS Server
   Filters, Search List Overrides and native Resolver Scopes. Stable existing
   setting IDs remain unchanged.
2. **Domain collision arbitration used raw strings.** Case differences and trailing
   root dots could assign the same DNS suffix to two VPNs. Canonicalisation now
   precedes collision arbitration and explicit scope removal.
3. **Invalid commits could lose rules silently.** The sanitizer removed invalid
   rows before saving the remainder. Both UI persistence and the controller now
   reject invalid drafts before any profile/keychain write. Inline errors retain
   the draft; the previous configuration remains stored.
4. **Runtime matching must agree with previews.** One shared bounded matcher drives
   the query proxy, hostname tester and railroad. The query preview explicitly
   includes the selected disconnected draft; disabled rules can be dry-run without
   activating the proxy. Glob matching uses bounded dynamic programming, without
   recursive backtracking. Configuration acknowledgement does not claim successful
   resolver reachability or provider liveness.

5. **Advanced list fields rewrote comma separators while typing.** Search-domain
   and resolver-scope fields now use the shared list editor, retaining the user's
   draft separator across typing and focus changes.

6. **Query-only edits must not reassert IP routes or system proxy state.** The
   persistence path now compares resource changes. Route changes still reconcile
   dependent DNS/proxy ownership; query-only changes update only the DNS query
   proxy. A controller regression test pins that boundary.

## Query rules

Rules activate only for connected VPNs whose Query-name Routing switch is enabled.
This is off by default. Across profiles: default-route owner, newest connection,
then ID; within a profile: first enabled match. Exact matches the whole QNAME;
Suffix includes apex + descendants; Glob matches the whole name using *, ?,
bracket classes/ranges/negation and escapes. Wildcards include dots. ASCII/punycode,
case-insensitive, one trailing root dot ignored. Native scopes retain suffix
semantics; existing configurations are not automatically converted.

A resolver target uses explicit literal IPs or the VPN's filtered resolver list.
An Original resolver target preserves macOS's endpoint, which may itself belong
to a VPN. Query overrides act after macOS selects an original resolver; native
suffix scopes still determine that original choice. Unmatched queries also
retain that endpoint. Selected resolver failure yields SERVFAIL without fallback
outside the rule. Existing IP routing determines the packet path to each resolver;
query rules do not choose interfaces or add routes. Application-managed encrypted
DNS bypasses this feature.

## Runtime and deployment

The existing system-extension bundle additionally declares a DNS proxy provider;
its Developer ID provisioning profiles already grant dns-proxy-systemextension.
The query proxy handles standard single-question UDP and length-framed TCP DNS
(excluding zone transfers/DSO), bounds message size, active
flows and transaction lifetimes, validates responses, and logs no queried names.
UDP transactions run independently with a global concurrency cap, so one stalled
resolver does not serialize unrelated lookups on the same flow. Cancellation closes
flow resources. Normal DNS setup makes no DNS proxy preference
calls. Query configuration changes restart the DNS proxy, not VPN connections.

Enabling query routing replaces another app's DNS proxy: macOS allows one active
DNS proxy. The UI states this at the explicit advanced opt-in. External proxy
disablement is observed without automatically fighting another app for ownership;
explicit Reapply is required. Tests never enable this Mac's proxy. A rebuilt, notarised and approved installed extension is required
for live proxy acceptance; compilation, loopback tests and saved-preference
acknowledgement are not substitutes for that check.

Primary platform references:

- [NEDNSSettings.matchDomains](https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains)
- [DNS proxy provider](https://developer.apple.com/documentation/networkextension/dns-proxy-provider)
- [Provider configuration](https://developer.apple.com/documentation/networkextension/nednsproxyproviderprotocol/providerconfiguration)
- [Only one enabled DNS proxy](https://developer.apple.com/documentation/networkextension/nednsproxymanager/isenabled)
