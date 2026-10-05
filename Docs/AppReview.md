# SimpleVPN application review October 2026

This review covers the app, packet-tunnel extension, native VPN manager, imported
configuration, credential stores, SSH networking, state mediators and visualizations.
It found and fixed a reproducible SSH shutdown crash, secret leakage in additional
WireGuard peers, unsafe credential replacement, parser failures and configuration
portability gaps. The follow-up repairs and remaining platform verification are recorded below.

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
| OpenVPN inline private/static keys and auth blocks | User Keychain, redacted provider configuration, reassembled in memory | Failed Keychain or OS saves retain the only copy with a migration notice; editing locks no longer skip migration. |
| WireGuard private key and all imported peer PSKs | User Keychain; redacted profile/legacy defaults | The live engine supports the first peer only. A failed legacy migration retains original data rather than losing keys. |
| SSH app imported private key | `tunnel.<id>.sshKey` in user Keychain; memory PEM at connect | In-process paths only; user-selected file mode intentionally remains file-backed. |
| SSH Network Tunnel PEM/password | User Keychain; transient extension start options | Private signing broker to the user agent; no private-key extraction. |
| Touch ID VPN records, remembered vault unlocks | Data-protection Keychain with user-presence access control | Only per-VPN protected records are exported, after authentication. Provider-wide unlocks are excluded. |
| KeePassXC pairing credentials | User Keychain; update preserves existing association on failure | External database/key files remain user-selected files. |
| Native IKE/IPsec credentials | User Keychain with stable OS persistent references | Authenticated native proxy saves are refused; verified legacy migration removes passwords from the OS protocol. |
| Tailscale authentication key | User Keychain and transient start payload | Node identity is revisioned into the user Keychain; root legacy files are deleted after verified acknowledgement. |
| External vaults, SSH agents and Apple Passwords | Vendor/system-owned stores; fetched password or signing result | Config export does not extract agent private keys or external vault contents. Apple Passwords' picker exposes password credentials, not this PEM storage feature. |

App-owned new secret writes use the user's Keychain, including Tailscale node identity.
A failed legacy migration deliberately preserves the only copy with a visible notice;
an OS or locked-Keychain refusal must be resolved before claiming that every existing
profile has completed migration. External vaults and selected `.ssh` files retain their
user-selected storage. These boundaries are registered in `Docs/Drift.md`.

## Resolution of the follow-up findings

| Finding | Repair and regression evidence |
|---|---|
| Tailscale root-file identity | Revisioned user-Keychain state broker; acknowledgement and legacy deletion happen only after verified persistence. Race tests cover blocked writes, failure, shutdown and nil/empty values. |
| Locked OpenVPN inline secrets | Verified storage migration runs even when editing is locked; failure preserves the only copy with a notice. |
| Native proxy secrets in OS preferences | New authenticated native proxy saves are refused; legacy credentials are verified in user Keychain before redacting and verifying the OS protocol. |
| Overlapping mediator applies and ineffective reassert | Shared serialized latest-plan loop; forced writes, acknowledged caches and delayed/failure integration tests. |
| Missing pushed DNS/search intent | Engine stats project pushed resolvers/search lists; arbitration preserves them and readback checks scoped service DNS. |
| Dropped editor saves | Shared queued latest valid draft; suspended-save tests. |
| Competing connection starts and late starts after cancellation | WireGuard/virtual profile reservations and a FIFO configuration gate; overlap, cancellation and held-write removal regressions. |
| Native status restored to the wrong row | Public installed-identity fingerprint must match the current OS protocol before restoring attribution. |
| Wrong-typed imported settings | Scalar, enum, list and nested structural import checks refuse malformed values before permissive legacy migration decoders can default them. |
| Diagnostic child pipe deadlocks | Shared runner drains both pipes, bounds output, enforces cancellation/deadlines and handles inherited descendant pipes. Disposable subprocess tests exercise all paths. |
| SSH Network agent capability | Provider-local signing socketpair and private session broker to the user agent; real ssh-agent/sshd authentication and descriptor cleanup tests. |
| Incorrect map egress attribution | Confirmed route owner determines the arc; blocked virtual capture has no egress arc. |
| Old telemetry restores a superseded gateway | Revision fence rejects samples begun before acknowledged changes or older confirmed settings; CLI rejects failed pause/resume/gateway acknowledgements. |
| Comma-list editing desync | A separate editing buffer preserves trailing separators while storage remains normalized. |

The remaining checks concern external platform behavior, not silently skipped code:
interactive 1Password approval, locked-Keychain/OS-managed migration failures, live
Tailscale enrollment/restart, actual focus/blur list entry, and notarized virtual capture
on macOS 26 and 27 including provider crash and sleep/wake. The explicit virtual mode
currently supports WireGuard; other backends and advanced routing are visibly gated and
registered in `Docs/Drift.md` §18 with a source guard.

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

The official Metal toolchain is now installed and the full signed app/extension test
build includes the actual shader source and its compiler test. No source or test is
excluded from the current full build.

The broad UI run reported a disabled system Siri dialog without an accessibility
description during the report-window audit, also reproduced in isolated reruns.
Its only button is the system `siri` orb; another audit snapshot referenced that
element's system process rather than the target app and failed to resolve it.
This UI audit remains failing on this machine, with its existing checks intact.
Other executed UI tests passed; profile-dependent walkthroughs skipped when their
required screen was absent. A fully green UI result is not claimed.

Latest follow-up validation: the complete signed run executed **2,833 Swift tests /
320 suites in 52.460 seconds**. The only failing test was the existing Data Protection
Keychain probe: `SecItemAdd` returned `errSecInteractionNotAllowed` (-25308), followed
by its dependent read assertions. It was not disabled or weakened. An earlier full
signed run passed 2,829 tests before the final telemetry/reservation regressions were
added; a fully green final run still requires a usable interactive Keychain session.

TS/WG and proxy/router Go race suites passed. Two repeated real encrypted virtual-session
runs covered IPv4/IPv6 TCP/UDP, overlapping member addresses, return translation, policy
pinning and independent member stop. Packet-parser fuzzing executed 5,393,226 cases in
15 seconds. Structural parser and connection cancellation guards passed in the final run.

The new focus/blur XCUITest did not begin: the runner timed out enabling automation
mode. Direct computer-use validation was also blocked awaiting Accessibility and Screen
Recording permission. These checks are open, not counted as passing. Notarization/upload
and replacement of `/Applications/SimpleVPN.app` were rejected by automatic approval
review pending explicit user authorization; no new installed extension acceptance test
has run. No production VPN or external Tailscale connection was changed for these checks.

The clean Release build **279** passed with no compiler warnings (only the documented
PacketTunnel App Intents metadata notice). After signing Sparkle's nested helpers,
`codesign --verify --deep --strict` passed outside the filesystem sandbox. Both app and
system extension carry the expected Developer ID/system-extension entitlements and
neither contains `get-task-allow`. This is a local build, not a notarized installation.
