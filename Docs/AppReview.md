# SimpleVPN application review October 2026

This review covers the app, packet-tunnel extension, native VPN manager, imported
configuration, credential stores, SSH networking, state mediators and visualizations.
It found and fixed a reproducible SSH shutdown crash, secret leakage in additional
WireGuard peers, unsafe credential replacement, parser failures and configuration
portability gaps. Several architectural and UI state issues remain open below.

This is a source and automated-test review. It is not proof that every VPN backend
works against a real service. Local SSH integration uses disposable keys and a
loopback sshd; no live production VPN credentials were used for those tests.

## Fixes in this change

| Priority | Problem and trigger | Result and evidence |
|---|---|---|
| P1 | Stop an SSH engine while a channel read is queued: `ssh_free` frees channel memory while `SSHChannel` retains its pointer. The supplied build 232 crash occurs in `ssh_channel_read_nonblocking`. | The bridge closes surviving wrappers before freeing the session. The app cancels active client flows, stops queued pumps and suppresses late state publications after stop. Retained-wrapper, stopped-connect and real SOCKS/file-key/Keychain-key tests cover teardown. |
| P1 | Additional WireGuard peer PSKs remain in `rawExtraPeers`, leaking through stored configuration and default export. | Store PSKs in the user Keychain by peer public key, redact text, hydrate only for use/export, migrate existing writable profiles. Canary tests cover additional-peer-only configurations and both export encodings. |
| P1 | Credential replacement deletes an old Keychain item before attempting the new write. Failure loses the old value and native VPN persistent references change. | Generic, biometric and KeePassXC association stores update existing items first. Native secret references survive updates. Legacy WireGuard saves retain their configuration on Keychain failure. |
| P2 | A corrupt or inaccessible ordinary Keychain record looks like a missing value during export. | Export uses strict reads and stops with a sanitized error. A real disposable Keychain test covers corrupt data without quoting its contents; import and persistent-reference tests use separate generated accounts. |
| P1 | Tailscale starts with an exit node even when connect-time gateway arbitration says it is not the owner. | The transient start payload gates exit-node use, selection and LAN access on gateway ownership. A regression test covers both owner cases without changing the saved preference. |
| P1 | Import accepts whitespace variants such as `StrictHostKeyChecking = no` although it promises to refuse verification downgrades. | Normalize whitespace around options before checking the unsafe-token list; also refuse discarded known-hosts files. Tests cover the bypass. |
| P1 | A large/nonfinite floating-point config value traps when converted to `Int`. | Use checked exact conversion. Tests cover huge JSON numbers, NaN, infinity and non-integral values. |
| P2 | SSH partial-write retries can interleave with the next client receive, and one peer's FIN closes the other direction too early. | Wait for a full write before receiving more; close only after both halves drain. Live tests compare 512 KiB transfers after client FIN and after server FIN. |
| P2 | The SOCKS parser selects a method the client did not offer, waits indefinitely for malformed headers, and drops application bytes received with CONNECT. | Refuse unsupported methods and invalid frames, flush the refusal before cancellation, preserve trailing payload and a handshake-time FIN. Live tests cover fragmented IPv4/domain requests, coalesced payload and seven malformed request shapes. Negotiation and frame validation follow [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928). |
| P2 | In-process SOCKS/local forwards listen more broadly than the user's ordinary local-forward expectation; bracketed IPv6 specs are split incorrectly. | Default to loopback, retain explicit bind addresses and parse brackets. Listener startup also uses one consistent required-endpoint API, fixing POSIX EINVAL on this OS. |
| P2 | Old native VPN profiles fail synthesized decoding when newly added fields are missing. | Decode missing fields with defaults while preserving type errors. A legacy-profile test covers the old field set. |
| P2 | Cisco XML returns completed entries from a truncated document; SSH inline comments and CRLF imports are mishandled. | Reject incomplete XML, honor quoted/escaped SSH comments, split newline forms explicitly, and trim WireGuard lists. Regression fixtures exercise each case. |
| P2 | Full config export drops subprocess/native Custom Routing, and imported proxy auth references point at old profile identities. | Export fallback routing and rebind authentication references to the newly created profile. |
| P2 | Swift 27 rejects actor-isolated implicit captures in existing callback setup. | Capture local observable dependencies explicitly; app and extension targets compile under the configured warnings-as-errors policy. |

## SSH and export behavior

The app SSH editor supports file keys from the user's `.ssh` folder, an explicit
user-agent socket including 1Password, and **User Keychain** private-key import.
The Keychain mode reads PEM into memory and supports in-process SOCKS/local/dynamic
forwards. Reverse forwards, jump hosts and extra SSH arguments require the subprocess
path and give an actionable refusal for Keychain PEM mode. The SSH diagnostic ladder
recognizes an imported Keychain key using the existing file-key probe rules. Password
probes remain behind explicit account-level consent.

JSON/YAML export offers placeholders by default and saved secrets by explicit choice,
for all VPNs or one selected VPN. OpenVPN has an explicit secret-bearing `.ovpn` action;
WireGuard retains its named key export; L2TP profiles offer the same placeholder/secret
choice. Secret-bearing files warn in the UI/header and are created with mode 0600 before
any bytes are written. Import validates a closed secret vocabulary, saves to new profile
identities and never treats a placeholder as a password. Recovery exports omit secrets.

## Secret storage audit

| Material | Current storage and transfer | Remaining qualification |
|---|---|---|
| Saved VPN passwords, service tokens, proxy/jump passwords and key passphrases | `KeychainCredentialStore`, user Keychain; transient memory at connect | Export reports inaccessible/corrupt records instead of silently omitting them. Normal connection reads still return nil on unavailable records. |
| OpenVPN inline private/static keys and auth blocks | User Keychain, redacted provider configuration, reassembled in memory | Managed locked profiles and failed migrations can retain original inline material with a migration notice. |
| WireGuard private key and all imported peer PSKs | User Keychain; redacted profile/legacy defaults | The live engine supports the first peer only. A failed legacy migration retains original data rather than losing keys. |
| SSH app imported private key | `tunnel.<id>.sshKey` in user Keychain; memory PEM at connect | In-process paths only; user-selected file mode intentionally remains file-backed. |
| SSH Network Tunnel PEM/password | User Keychain; transient extension start options | No user-agent signing channel in the root extension. |
| Touch ID VPN records, remembered vault unlocks | Data-protection Keychain with user-presence access control | Only per-VPN protected records are exported, after authentication. Provider-wide unlocks are excluded. |
| KeePassXC pairing credentials | User Keychain; update preserves existing association on failure | External database/key files remain user-selected files. |
| Native IKE/IPsec credentials | User Keychain with stable OS persistent references | Native proxy credentials are attached to saved `NEProxyServer`; verify the OS storage boundary. |
| Tailscale authentication key | User Keychain and transient start payload | Tailscale node identity is separately persisted by the root-owned Tailscale state file. |
| External vaults, SSH agents and Apple Passwords | Vendor/system-owned stores; fetched password or signing result | Config export does not extract agent private keys or external vault contents. Apple Passwords' picker exposes password credentials, not this PEM storage feature. |

The requirement that **all actual secrets live in the user's Keychain is not fully met**.
Tailscale state, locked/failed inline migrations and the native-proxy persistence boundary
must be resolved before making that claim. These are registered in `Docs/Drift.md`.

## Open findings

P1 affects confidentiality, crash safety or routing correctness. P2 affects persisted
state, diagnostics or reliable operation. Source-path risks are labeled when no live
reproduction has been performed.

| Priority | Finding and evidence | Next verification or repair |
|---|---|---|
| P1 | Tailscale node identity uses `store.New` on `tailscaled.state` in `Vendor/tailscale-engine/src/main.go`. Owner-only permissions are not user-Keychain storage. | Design an authenticated app/extension state broker or a Keychain-backed store, with root/user session, restart and lock tests. |
| P1 | Locked OpenVPN profiles retain inline secrets: `VPNController+CRUD.migrateInlineOVPNSecrets` deliberately skips policy-locked configuration. Failed writes retain originals too. | Coordinate a policy-approved migration; preserve the existing notice and never discard the only copy. |
| P1 | Native proxy auth is inserted into `NEProxyServer` and `NativeVPNManager.connect` saves that protocol to preferences. Source establishes the handoff, not the OS's at-rest representation. | Inspect OS persistence with a disposable proxy credential and define a supported memory-only or referenced-secret path. |
| P1 | Route/DNS/proxy reconciliation launches fresh tasks without awaiting previous applies. `RouteMediator.reconcileGateway` captures an owner across awaits; a later owner change can interleave with the old grant. **Source-path race risk, not live reproduced.** | Hold a fake host at strip/apply suspension points, switch owners, and assert only the latest plan is granted. Serialize and coalesce application. |
| P1 | Drift handlers call reconcile with the same desired plan, while `DNSRealizer`/`ProxyRealizer` skip `plan == lastPlan`; route reassert also retains `appliedRole`. A published reassert can issue no write. | Fake-host tests must assert writes after external drift, not just the pure drift decision. Invalidate/re-read the applied cache and handle failed acknowledgments. |
| P2 | DNS intent projection in `VPNController+Gateway.dnsProfiles` always sends `searchDomains: []`; OpenVPN/OpenConnect/Tailscale pushed DNS is not projected. `DNSPlan.applyRequests` also discards search lists. | Capture actual engine DNS intent, preserve search domains through arbitration/application and test two simultaneous VPNs. |
| P2 | `ProxyTunnelView`, `TailscaleView` and `SSHNetworkTunnelView` return from save while `saving` is true. A blur/close event during an awaited earlier save has no pending retry. **Source-path lost-save risk.** | Suspend a host save, edit again and close; verify the latest valid draft persists. Queue a final save or coalesce revisions. |
| P2 | `NativeVPNManager.refreshStatus` restores OS status but never restores `activeConfigID`; only connect assigns it. | Restart while a disposable native connection is active. Persist and verify the installed profile identity against the OS protocol before showing its row as connected. |
| P2 | Config models using `try? decodeIfPresent` can default a wrong-typed imported setting rather than refuse it, despite the manual's promise. `ConfigImport.apply` relies on those model decoders. | Validate input types against descriptor/template shape before decoding; add malformed settings fixtures for every engine. |
| P2 | `DiagnosticBundle.run` drains stdout fully before stderr. A child filling stderr while keeping stdout open can stall until termination. The endpoint-discovery runner has the same sequential pipe pattern. **Source-path deadlock risk.** | Use a disposable child that fills both pipes; drain concurrently and enforce a deadline/cancellation in both runners. |
| P2 | SSH Network Tunnel cannot use 1Password or the user's SSH agent, unlike app SSH. | An authenticated signing broker is needed; moving a signature from a different SSH session cannot authenticate this one. |
| P2 | The globe chooses the first located tunnel in the egress country in `WorldMapModel`, without the arbiter's owner identity. Two tunnels in one country can draw a plausible but wrong egress link. This is an explicit heuristic in source. | Pass the effective route owner to the model, and render unresolved attribution as ambiguous. Test same-country simultaneous tunnels. |
| P2 | The shared comma-list binding normalizes separators during editing. **UI hypothesis, not confirmed:** an in-progress trailing separator may be removed. | Type multiple values through real focus/blur interactions; preserve an editing buffer if normalization changes what can be entered. |

## Verification

The complete unit and local SSH integration run passed **2,787 tests in 306 suites**
with **two iterations of every selected test** (95.743 seconds).
The live SSH suite actually ran against the disposable loopback fixture, including
file-key and Keychain authentication, both half-close directions, repeated connections,
session loss, keepalive, compression and channel-wrapper invalidation. Keychain tests
verified import identity rebinding, corrupt-record refusal and persistent-reference updates.
`git diff --check` passed.

Repeated validation exposed a fixture teardown stall after successful SSH transfers.
A stack sample located it in `LiveSSHServer.reap` → `Process.waitUntilExit`.
The fixture now registers a termination handler before launching sshd, waits with a
deadline and kills only its own child if needed. Echo targets also stop their accept
and client workers before closing/reusing descriptors. The final repeated run passed
without that timeout or Thread Performance Checker findings.

The Metal compiler component is unavailable on this machine, so the shader source and its dedicated compile test
are excluded from local test builds. A normal complete production build and real
globe rendering still require that component. No shader source or test was disabled
in the project to hide this limit.

The broad UI run reported a disabled system Siri dialog without an accessibility
description during the report-window audit, also reproduced in isolated reruns.
Its only button is the system `siri` orb; another audit snapshot referenced that
element's system process rather than the target app and failed to resolve it.
This UI audit remains failing on this machine, with its existing checks intact.
Other executed UI tests passed; profile-dependent walkthroughs skipped when their
required screen was absent. A fully green UI result is not claimed.
