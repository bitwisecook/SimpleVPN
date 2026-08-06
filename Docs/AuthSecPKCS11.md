# Smartcards & security keys (PKCS#11) — REMOVED, and why

**SimpleVPN does not sign in with a certificate held on a smartcard, a PIV-enabled YubiKey or an HSM.**
Not on the SSL VPN kinds, not on OpenVPN, not anywhere. There was an implementation; it was deleted.

This file is the record of **why**, kept rather than deleted for two reasons. The obstacles are
structural — they will still be there for whoever asks the question again — and the argument against the
one apparently obvious fix (rebuild the vendored OpenConnect with GnuTLS and p11-kit) is not obvious at
all and cost real measurement to establish. Deleting it would guarantee that work is redone.

The **user-facing** page is `Resources/Manual/manual.html`, `#oc-smartcards`. It says the same thing in
the user's words and tells them where to ask. The in-app ask is
`FeatureRequestNotice.smartcardSignIn`, rendered by `FeatureRequestBanner` and submitted through the
existing diagnostic-report flow.

**This is not about YubiKeys that type a code.** A YubiKey acting as a keyboard (Yubico OTP, a static
password) or computing an OATH code that SimpleVPN reads back through `ykman` is a *different
mechanism on the same piece of plastic*. It is built, it is a priority, and nothing here touched it —
see `Docs/AuthSecYubiKey.md`. The removal shared no code with it: `YubiKeyCapture`, `Presence`,
`TouchCapture`, `Conflicts`, `YubiKeySlot` and the `ykman` path never referenced any PKCS#11 type. The
single point of contact was a `PKCS11Module.Vendor.yubiKey` case naming a *module file*
(`libykcs11.dylib`), which went with the enum.

---

## Why it was removed rather than repaired

It had **never been run against a real card or a real gateway.** The machine SimpleVPN is built on has
neither. Everything about it was either fixture-tested against transcripts, or exercised against
SoftHSM — a *software* token, which proves a parser and proves nothing about a card reader, a PIV
applet, or a gateway's willingness to accept the certificate on one.

That is normally what `FeatureMaturityRegistry` is for: ship it, say plainly that nobody has seen it
work, and let a report clear the label. A sign-in method is the case where that trade does not hold,
and the reason is the **PIN retry counter**. Finding out whether SimpleVPN's smartcard code worked cost
attempts from a counter that is three or four deep, and on a YubiKey PIV **exhausting it destroys the
key material** — the certificate on the device becomes permanently useless. "Try it and tell us" is
not a reasonable thing to ask of somebody whose employer issued that card. An untested VPN *kind* fails
and disturbs nothing; an untested smartcard sign-in can brick the credential it is trying to use.

So the choice was between carrying unverifiable code on the one path where failure is destructive, or
removing it and asking the people who need it to describe what they need. The second is what happened,
and the ask is deliberately for a **use case** — which gateway, which card, what the organisation
requires — rather than for a vote, because the thing that was missing when this was written was
precisely a real situation to build against.

---

## Obstacle 1 — the TLS backend split (the lesser one)

OpenConnect's PKCS#11 support lives **entirely in its GnuTLS backend**. Its OpenSSL backend answers a
`pkcs11:` URI with *"This binary built without PKCS#11 support"*.

`Tools/build-openconnect-xcframework.sh` configures `--with-openssl --without-gnutls
--without-libpcsclite`. So the in-process engine (`OpenConnectEngine.xcframework`, driven by
`OpenConnectBridge` in the packet-tunnel extension) and `ocauth-helper` could never do it. Homebrew's
`openconnect` **can**, because its formula depends on `gnutls` + `p11-kit` — which is why smartcard
sign-in existed on the *subprocess* path only.

That asymmetry is the whole reason the feature shaped the architecture the way it did, and it is why
removing it changes more than one file: see "What this unblocked" below.

## Obstacle 2 — AMFI forbids the `dlopen` (the real one)

A PKCS#11 provider module is a **third-party dylib the user installs** (`opensc-pkcs11.so`,
`libykcs11.dylib`). Loading one needs `com.apple.security.cs.disable-library-validation`, and that
entitlement is **the single relaxation AMFI refuses on a system-extension-embedding app** — SimpleVPN
embeds `PacketTunnel`, so neither the app nor the extension may carry it. This is not a preference; it
is why `opnative-helper` exists as a separate process at all (AGENTS.md).

The shipped design worked around it by never loading a module: SimpleVPN *named* one and the user's own
`openconnect` did the loading, with enumeration farmed out to the user's `p11tool` / `pkcs11-tool`.
That is a real design, and it is also the reason the feature could never come in-process.

### Why rebuilding the xcframework with GnuTLS + p11-kit would NOT have fixed it

This is the assumption worth killing, because it is the first thing anybody proposes and it is
backwards. **p11-kit's entire job is to `dlopen` a third-party provider module.** Linking GnuTLS and
p11-kit into the extension changes the failure from *"this binary built without PKCS#11 support"* to
*"could not load the module"*, and buys nothing. Obstacle 2 is upstream of obstacle 1.

And the rebuild is not free. Three things weigh against it even ignoring the above:

1. **It buys almost nothing else.** Swapping OpenConnect's TLS backend from OpenSSL to GnuTLS gains
   exactly two capabilities: PKCS#11 (blocked by AMFI anyway) and TPM key support (no Mac has one).
   Everything else OpenConnect does is backend-independent.
2. **It makes the `OPENSSL_PIN` hazard worse.** Three static archives in this build carry OpenSSL —
   `OpenVPNEngine`, `OpenConnectEngine` and `SSHEngine` — and all three build scripts pin
   `OPENSSL_PIN` to the *same* version deliberately, so their object files are byte-identical and
   ld64's lazy archive loading pulls exactly one copy. A pin divergence between them surfaces as
   duplicate symbols, which is the good failure; the bad one is two subtly different OpenSSL ABIs
   linked into one binary. `Docs/SSHNetworkTunnel.md` R1 and `Docs/Release.md` record the guard.
   Moving *one* of the three to GnuTLS does not remove that archive's OpenSSL — GnuTLS brings nettle,
   gmp, libtasn1, p11-kit and libffi *alongside* whatever OpenSSL the other two still pin — so it
   converts a solved problem (three identical pins) into an unsolved one (two crypto stacks, one of
   them newly unpinned) in exchange for a capability the platform forbids.
3. **`libpcsclite` and `libstoken` would follow.** They are the same shape of dependency for the
   soft-token modes below, with the same absence of a way to verify them here.

## Obstacle 3 — OpenVPN could never do it at all, and fatally

There is no `openvpn` subprocess anywhere in the tree; OpenVPN is the linked openvpn3 core. openvpn3
does not implement the `pkcs11-*` family, and — importantly — does not ignore unknown options either:
`ClientOptions::handle_unused_options` (`openvpn/client/cliopt.hpp`) collects anything untouched into
`OPENVPN_UNUSED_OPTIONS` and **throws** `Error::UNUSED_OPTIONS` with `fatal = true`.

That behaviour is unrelated to this removal and is unchanged. `ProfileEvaluation.pkcs11Directives`
still detects `pkcs11-` lines at import and still refuses with an explanation naming the directive,
because the alternative is openvpn3 rejecting the profile with a message about an unknown option — which
says nothing about the card the user is holding. What changed is the *last sentence* of that
explanation: it used to point at the SSL VPN kinds as the route that works, and now says SimpleVPN
cannot do it anywhere and where to ask.

openvpn3's own route, if it were ever wanted, is its **external PKI** callbacks
(`ExternalPKICertRequest` / `ExternalPKISignRequest` in `client/ovpncli.hpp`), which are compiled out
here — `ENABLE_EXTERNAL_PKI` is not in the xcframework's `DEFS`. Enabling them means doing the signing
in one of our own processes, which means the `dlopen` of obstacle 2, which means a **third** helper
binary carrying the library-validation relaxation alongside `opnative-helper`. Not attempted.

---

## Soft tokens (`--token-mode`) — a separate gate, closed for its own reasons

Removed in the same batch and for **different** reasons, so the two are not one decision:

- **The seed is a long-lived secret with no channel to the extension.** A TOTP/HOTP seed generates
  every future code — strictly worse to hold than a password. On the subprocess path it rode a private
  `0600` temp file (`--token-secret=@FILE`); in-process there is no equivalent, because the app→sysext
  handoff carries per-connect secrets in `startTunnel(options:)` and a seed is not a per-connect
  secret. Building one is a design decision about storing a stronger secret, not plumbing.
- **`rsa` and `yubioath` need libraries this build does not carry** — `libstoken` and `libpcsclite`
  respectively, and the xcframework is configured `--without-libpcsclite`.
- **The user can always type the code**, and a password app that holds verification codes can fill it
  in (`Docs/CredentialSources.md`). Nothing is unreachable; one convenience is missing.

`FeatureRequestNotice.verificationCodeToken` carries that ask, and it asks a different question:
which gateway wants the code, where the code comes from today, and what stops the user typing it.

**Not to be confused with the YubiKey hardware-OTP path**, which is built and stays.

---

## What was removed

Deleted outright:

- `Shared/PKCS11.swift` — the RFC 7512 URI parser, `PKCS11Module`, `PKCS11TokenStatus`,
  `PKCS11Certificate`, `PKCS11Failure`.
- `SimpleVPN/ControlPlane/PKCS11Discovery.swift` — `PKCS11ModuleDiscovery`, `PKCS11Enumerator`,
  `PKCS11Tool`, `PKCS11ProcessRunner`, `PKCS11Survey`, `PKCS11ConnectWatcher`.
- `SimpleVPNTests/ControlPlane/PKCS11Tests.swift`, `PKCS11LiveIntegrationTests.swift`,
  `Tools/pkcs11-live-test-fixture.sh`.
- The four `pkcs11*` fields on `SubprocessTunnelConfig` and every validator over them; the five
  `oc.pkcs11-*` descriptors and the two `oc.token-*` ones, with their `manual.html` sections; the
  smartcard sub-form in `SubprocessTunnelView`; `AuthSourceID.pkcs11Token`,
  `AuthSourceCatalog.pkcs11Token` and `AuthPossession.pkcs11Object`;
  `VendorConfigFieldKind.pkcs11Module` (declared by nothing — a promise for this same feature);
  `DiagnosticReportInventory.pkcs11Fields()`; the five PKCS#11 acknowledgement rows (p11tool, OpenSC,
  p11-kit, yubico-piv-tool's libykcs11, SoftHSM — `ykman` stays).

**Deliberately kept**, each for a stated reason:

| Kept | Why |
|---|---|
| `authMode == "token"` as a stored value, and the picker option that writes it | An existing profile must not be silently converted. It still says what it is; Connect is refused with an explanation; nothing is sent to a gateway that the profile did not ask for. And somebody who comes looking for smartcard finds the page instead of finding nothing. |
| `tokenMode` as a stored value | Same rule. Not offered, never in an argv, refused with an explanation. |
| The keychain items `tunnel.<id>.pkcs11` and `tunnel.<id>.token` | Deleting a user's secret as a side effect of a feature removal is not ours to do. No upgrade touches them, and neither does opening or saving the profile. Deleting the *profile* still removes them (`SubprocessTunnelStore.remove`) because that is the user's own explicit act, and leaving them then would orphan them for ever. |
| `AuthKind.tokenPIN` | Its raw value is an on-disk contract (`CredentialSource.fieldMap`), and it still names the PIN a hardware security key asks for. |
| `ProfileEvaluation.pkcs11Advice` | The openvpn3 import refusal is unrelated to this removal and still needed. Only its final clause changed. |

---

## What this unblocked

**Smartcard sign-in was the last thing keeping the subprocess path alive for SSL VPNs.** It was the one
capability the Homebrew `openconnect` tool had that the bundled engine structurally could not have —
`sslAuthBlockReason` said as much, and it was the mirror image of `sshPinBlockReason` (which can only
run in-process). Everything else on that list is an ordinary setting somebody has not plumbed yet.

With it gone, `inProcessOpenConnectSupports` refuses for exactly four reasons, all of them ordinary:

1. a host checker / endpoint-posture wrapper (`csdWrapper`, `disableCSD`) — `openconnect_setup_csd`
   works by forking a child, and the extension is sandboxed *and* root;
2. a base MTU (`baseMTU`) — no library setter exists;
3. HTTP keepalive off (`noHTTPKeepalive`) — likewise;
4. extra arguments (`extraArgs`) — arbitrary argv has no in-process equivalent by construction.

(Two further clauses refuse an *invalid* value — a compression mode or a reported OS OpenConnect
hasn't got — rather than a capability.)

So `Docs/Networking.md` §3.3 no longer needs the row "OpenConnect SSL VPNs, subprocess (smartcard, or a
knob the bridge can't carry)", and the claim that the subprocess path "cannot be retired for smartcard
sign-in, whatever the xcframework is configured with" is now moot rather than wrong.

---

## What would be needed to build it properly

For whoever picks this up with a real gateway and a real card in hand. In order of what actually blocks:

1. **A helper process.** The `dlopen` cannot happen in the app or the extension. A third signed helper
   carrying `com.apple.security.cs.disable-library-validation`, alongside `opnative-helper`, doing the
   PKCS#11 signing and speaking a narrow IPC — never handing over key material, and never receiving a
   PIN on argv. This is the whole of the work; everything else is a consequence.
2. **A PIN channel with no retries.** The old design's one genuinely good property: `--passwd-on-stdin`
   to OpenConnect's first password-type form field (its `gnutls_pin_callback` builds a form with
   `auth_id` `"pkcs11_pin"`), one `write(2)`, pipe closed, so a second prompt reads EOF and fails
   instead of spending a second attempt. Every alternative puts the PIN or a path to it on a command
   line (`--key-password=`, `pin-value=`, `pin-source=`) or in the environment (`GNUTLS_PIN`, which
   OpenConnect does not consult once it has installed its own callback). Keep the property; keep the
   URI-level refusal of `pin-value=`/`pin-source=`.
3. **A pre-flight counter read that spends nothing.** `CKF_USER_PIN_COUNT_LOW` /
   `CKF_USER_PIN_FINAL_TRY` / `CKF_USER_PIN_LOCKED`, before any PIN is entered, with a hard refusal on
   locked. Enumeration must never log in. This is the anti-bricking property and it has to exist before
   the first real test, not after.
4. **The p11-kit registration trap.** OpenConnect has no "use this module" option: it resolves a URI
   through p11-kit, which loads only modules a registration file declares. RFC 7512's `module-path=`
   query attribute does **not** fill the gap — measured: `p11tool --list-all-certs
   'pkcs11:token=…?module-path=…'` returns "No matching objects found", and the same query finds the
   token immediately once a `.module` file exists. So "installed" and "registered" are different
   states, and an unregistered module fails as *"no certificate found"*, which reads like a wrong URI
   and is not. The per-user fix needs no admin rights:
   `mkdir -p ~/.config/pkcs11/modules && printf 'module: /path/to/module\n' > ~/.config/pkcs11/modules/x.module`
   (`~/.pkcs11_modules/` is **not** a p11-kit path; the real ones, read out of the installed
   `libp11-kit.0.dylib`, are `<prefix>/etc/pkcs11/modules` and `~/.config/pkcs11/modules`.)
5. **`LC_ALL=C` on any GnuTLS enumeration.** `p11tool` prints the expiry line with locale-dependent
   `strftime("%c")` and is otherwise unparseable. Also: GnuTLS emits `type=cert` where OpenConnect's
   own documentation says `object-type=cert`; accept both and rewrite neither.
6. **Do not rewrite a user's URI to "help".** OpenConnect 7.01+ adds `type=cert` / `type=private`
   itself and strips the label when it has to hunt for the key.

Facts 4, 5 and 6 were measured out of band during the original work and are the reason this section
exists at all.

---

## Vendor documentation

Their pages are the authority.

| | |
|---|---|
| OpenSC (smartcards, PIV) | <https://github.com/OpenSC/OpenSC/wiki> |
| Yubico PIV tool / YKCS11 | <https://developers.yubico.com/yubico-piv-tool/> |
| OpenConnect PKCS#11 | <https://www.infradead.org/openconnect/pkcs11.html> |
| p11-kit configuration | <https://p11-glue.github.io/p11-glue/p11-kit/manual/config.html> |
| RFC 7512 (the URI scheme) | <https://www.rfc-editor.org/info/rfc7512/> |

`manual.html` deliberately names sources in prose rather than linking out: ALL user documentation is
embedded in the app (AGENTS.md), because a VPN client's help has to work exactly when the network
doesn't.
