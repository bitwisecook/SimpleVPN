# Smartcards & security keys (PKCS#11)

Hardware-backed certificate sign-in for the SSL VPN kinds: the certificate and its private key live on
a smartcard, a PIV-enabled YubiKey or an HSM, the key never leaves the device, and every signature the
VPN needs is made on it after the PIN unlocks it.

The **user-facing** documentation is embedded in the app (`Resources/Manual/manual.html`,
`#oc-smartcards` and the five `#oc-pkcs11-*` sections) — that is the binding home for anything a user
reads. This file is the engineering record: what each engine actually supports, where the PIN is at
each moment, and which claims here are really tested versus fixture-tested.

---

## What each engine supports, and how that was established

| Path | PKCS#11? | How we know |
|---|---|---|
| `openconnect` **subprocess** (Homebrew 9.21) | **Yes** | Homebrew's formula depends on `gnutls` + `p11-kit`, which is the backend OpenConnect's PKCS#11 support lives in. `--certificate`/`--sslkey` take a URI wherever they take a path; if no key is given OpenConnect derives both from the one URI, adding `type=cert` / `type=private` itself (its `gnutls.c` does this with `p11_kit_uri_set_attribute` on `CKA_CLASS`). |
| `OpenConnectEngine.xcframework` (**in-process**, the packet tunnel) | **No** | `Tools/build-openconnect-xcframework.sh` configures `--with-openssl --without-gnutls --without-libpcsclite`. OpenConnect's OpenSSL backend answers a `pkcs11:` URI with *"This binary built without PKCS#11 support"*. `inProcessOpenConnectSupports` therefore refuses token configs, and `sslAuthBlockReason` says so. |
| `ocauth-helper` (SSO sign-in) | **No** | Same static library, same reason. |
| **OpenVPN** (`OpenVPNEngine.xcframework`, OpenVPN 3 core) | **No — and fatally so** | There is no `openvpn` subprocess anywhere in the tree (`TunnelCLI` has no such case); OpenVPN is the linked openvpn3 core. openvpn3 does not implement the `pkcs11-*` family, and does not ignore unknown options either: `ClientOptions::handle_unused_options` (`openvpn/client/cliopt.hpp`) collects anything untouched into `OPENVPN_UNUSED_OPTIONS` and **throws** `Error::UNUSED_OPTIONS` with `fatal = true`. Emitting `pkcs11-providers` would turn a working import into a profile that refuses to load. |

**So token auth is implemented for the OpenConnect SSL VPN kinds only, on the subprocess path only.**
For OpenVPN, `ProfileEvaluation.pkcs11Directives` detects the directives at import/edit time and refuses
with an explanation naming the directive and the route that does work — instead of letting openvpn3
reject the profile as an unknown option, which says nothing about the smartcard the user is holding.

### What we would need to support OpenVPN, if it is ever wanted

openvpn3's route is its **external PKI** callbacks (`ExternalPKICertRequest` /
`ExternalPKISignRequest` in `client/ovpncli.hpp`), which are compiled out here — `ENABLE_EXTERNAL_PKI`
is not in the xcframework's `DEFS`. Enabling them means rebuilding the xcframework *and* doing the
signing in one of our own processes, which means `dlopen`ing the user's provider dylib. That is the one
thing this design cannot do (see below), so it would need a third helper binary carrying the
library-validation relaxation, alongside `opnative-helper`. Not attempted.

---

## The three architectural facts that shaped the design

### 1. We can never load a provider module ourselves

A provider module is a third-party dylib. Both the app and the packet-tunnel extension run under the
hardened runtime, and `com.apple.security.cs.disable-library-validation` — the entitlement that would
allow a foreign dylib — is the single relaxation AMFI forbids on a system-extension-embedding app
(AGENTS.md; it is why `opnative-helper` exists as a separate process at all). So SimpleVPN *names* a
module and lets the user's `openconnect` load it.

### 2. Enumeration therefore goes through the user's own PKCS#11 tools

`p11tool` (GnuTLS) first, `pkcs11-tool` (OpenSC) second. Choosing `p11tool` as primary is not
arbitrary: it is the **same p11-kit/GnuTLS stack Homebrew's `openconnect` uses**, so what it lists is
exactly what will be usable at connect time. OpenSC contributes two things GnuTLS cannot: the
certificate's subject DN, and a definite `user PIN locked` reading (GnuTLS's own printer tests the
final-try bit twice and never prints the locked bit — verified in `gnutls/src/pkcs11.c`, and the parser
compensates).

Neither tool is required to *connect*. Missing both costs the certificate picker, never the ability to
sign in: the URI field stays usable with inline validation and examples.

Both are resolved and run through **`LocalToolRunner`** (`SimpleVPN/Credentials/`, the sign-in-source
seam): an allow-list of documented install locations instead of `PATH`, a refusal to execute from a
world- or non-admin-group-writable directory, an environment built from scratch rather than inherited,
`/dev/null` on stdin, and a hard deadline with cancellation. `PKCS11ProcessRunner` adds exactly one
thing to its environment — `LC_ALL=C`, without which GnuTLS's `strftime("%c")` expiry line is
unparseable — and merges stdout with stderr, which is safe *here* because no secret crosses this
boundary in either direction (no PIN goes to these tools and none comes back).

### 3. openconnect only sees modules p11-kit has been told about

This is the one that bites users. OpenConnect has no "use this module" option; it resolves a `pkcs11:`
URI through p11-kit, which loads only the modules a registration file declares. RFC 7512's
`module-path=` query attribute does **not** fill the gap — p11-kit knows the attribute but GnuTLS's URI
path ignores it. Measured: `p11tool --list-all-certs 'pkcs11:token=…?module-path=/opt/homebrew/lib/softhsm/libsofthsm2.so'`
returns *"No matching objects found"*, and the same query finds the token immediately once a
`.module` file exists.

So the editor distinguishes *installed* from *registered*, and for an unregistered module blocks Connect
with the one-line fix beside it (copy-to-clipboard). SimpleVPN never runs it — we show the command, the
user runs it. Verified working end to end (created, checked, removed):

```
mkdir -p ~/.config/pkcs11/modules && printf 'module: /opt/homebrew/lib/opensc-pkcs11.so\n' > ~/.config/pkcs11/modules/opensc-pkcs11.module
```

Per-user, no admin rights, nothing system-owned touched. (`~/.pkcs11_modules/` is **not** a p11-kit
path; the real ones, read out of the installed `libp11-kit.0.dylib`, are `<prefix>/etc/pkcs11/modules`
and `~/.config/pkcs11/modules`.)

---

## Where the PIN is, at every moment

The token PIN is a secret and obeys the existing invariant: nothing in `providerConfiguration`, nothing
in argv, nothing in a log or an error.

| Moment | Where the PIN is | Notes |
|---|---|---|
| Typed | `SubprocessTunnelView.pkcs11PIN`, a `@State` string behind a `SecureField` | Never written into `draft`, which is persisted to `UserDefaults` in the clear |
| Save, "Remember PIN" **off** (default) | nowhere | The keychain item is *deleted* on every such save, so turning the toggle off is a real revocation |
| Save, "Remember PIN" **on** | login keychain, `tunnel.<id>.pkcs11`, via `KeychainCredentialStore` | Deleted with the tunnel (`SubprocessTunnelStore.remove`) |
| Connect | `SubprocessTunnelManager.connect(_:password:tokenPIN:)` → `command(for:password:pin:)` → the returned `Data` | Its own parameter, never the `password` slot: the two go to different places |
| Handover | `TunnelProcess.start()` writes it to the child's stdin pipe and closes the pipe | One `write(2)`. Not argv, not the environment, not a file |
| In openconnect | its in-memory `pin_cache`, keyed by the token URI | Which is how one PIN serves both the certificate and the key object |
| Failure | the classifier never quotes the PIN — `PKCS11Failure.pinWrong` reports the *counter*, not the value | |

### Why stdin, and why that is safe under `--non-inter`

OpenConnect raises the PKCS#11 PIN as an ordinary **password-type form field** (`gnutls_pin_callback`
builds a form with `auth_id` `"pkcs11_pin"`), and its CLI gives a `--passwd-on-stdin` value to the first
password field it meets. The PIN is asked for while the certificate is loaded, before any gateway form,
so it *is* that first field. Confirmed by reading `openconnect/main.c` and `gnutls.c`.

The alternatives were all worse and all rejected:

- `--key-password=<PIN>` — OpenConnect's *documented* way to pass a PKCS#11 PIN, and it puts the PIN on
  a command line every local process can read with `ps`.
- `pin-value=` in the URI — same problem. `PKCS11URI.problem` **refuses** a URI containing it, by name,
  with the reason.
- `pin-source=file://…` in the URI — puts a path to the PIN on argv. Also refused, and it would not work
  anyway: OpenConnect installs its own PIN callback, which never consults the URI's PIN attributes.
- `GNUTLS_PIN` in the environment — better than argv but still readable by same-uid processes, and again
  not consulted once OpenConnect has installed its own callback.

`--passwd-on-stdin` also sets OpenConnect's internal `allow_stdin_read`, so a *second* prompt reads the
already-closed pipe, gets EOF and fails immediately. That is not just hang-avoidance: it is why **one
wrong PIN costs exactly one attempt**. There is no retry loop anywhere in this design.

### `pkcs11-id-management`

Not applicable and not implemented. It is an OpenVPN 2.x option, and OpenVPN is the engine that cannot
do tokens here at all. On the OpenConnect side the equivalent — interactive object selection — is
replaced by our own certificate picker, which enumerates without logging in.

---

## The PIN retry counter (anti-bricking)

Exhausting a YubiKey PIV PIN does not lock the key out temporarily; it **destroys** the key material.
Three measures, all verified:

1. **Pre-flight.** `surveyPKCS11` reads `CKF_USER_PIN_COUNT_LOW` / `CKF_USER_PIN_FINAL_TRY` /
   `CKF_USER_PIN_LOCKED` from the token before any PIN is entered, via `p11tool --list-tokens`
   (`Flags: … uPIN low count`) and `pkcs11-tool --list-token-slots`
   (`token flags: … user PIN count low`). Both parsers were exercised against a real token whose
   counter was really run down. The warning renders in red beside the rows and is announced to
   VoiceOver.
2. **Refusal.** A token reporting `user PIN locked` (or no PIN set) blocks Connect entirely — further
   attempts achieve nothing but confusion.
3. **No retries, and no spending on our behalf.** Enumeration never logs in, so filling the certificate
   picker costs nothing. At connect time the stdin pipe is closed after one PIN, so a wrong PIN produces
   one refusal. OpenConnect's own escalating banners ("Only a few tries left before locking!", "This is
   the final try before locking!") are parsed and folded into the failure message.

`pkcs11-tool`'s flag names were read out of the shipped binary (`user PIN count low`,
`final user PIN try`, `user PIN locked`, `user PIN to be changed`), and the numeric
`other flags=0x…` bucket is bit-tested as well so a future OpenSC that stops naming them still warns.

---

## Really tested vs fixture-tested

Be precise about this; the distinction is the point.

**Really tested** — `SimpleVPNTests/ControlPlane/PKCS11LiveIntegrationTests.swift`, run against a real
provider module (SoftHSM 2.7.0) holding a real RSA-2048 certificate, through our own Swift code and the
real `p11tool` 3.8.13 / `pkcs11-tool` 0.27.1:

- token discovery and its flags;
- certificate enumeration: label, id, key type, **expiry** (which only parses because
  `PKCS11ProcessRunner` pins `LC_ALL=C` — GnuTLS prints that line with locale-dependent `strftime("%c")`);
- subject extraction by exporting the certificate and parsing it with Security.framework;
- the enumerated URI surviving our own validator *and* the argv builder unchanged;
- a non-module path (`/usr/lib/libSystem.dylib`) reported as `.moduleUnusable`, not as an empty list.

These tests **skip without the fixture**, and `livePKCS11FixtureMode` always runs and prints which mode
the run was in, so a green suite cannot be mistaken for a proven one. Create it with
`./Tools/pkcs11-live-test-fixture.sh` and remove it with `--remove`.

**Really measured out of band** (recorded here, not automated): the p11-kit registration command; that
`?module-path=` is ignored; that GnuTLS emits `type=cert` where OpenConnect's docs say
`object-type=cert`; the escalating `uPIN low count` flag as a real counter was run down; and OpenSC's
exact flag strings.

**Fixture-tested** — `SimpleVPNTests/ControlPlane/PKCS11Tests.swift`, driven by transcripts captured
verbatim from those same real runs (tabs, space-padded days and all), plus fakes for the filesystem and
the process boundary:

- the RFC 7512 validator, including the `pin-value`/`pin-source` refusal;
- module discovery and the registered/unregistered distinction;
- both tools' parsers, including a hardware PIV token on its final attempt and a locked YubiKey;
- the argv/stdin contract (the PIN is in the pipe and nowhere else);
- all eleven failure modes, each asserted to have its own actionable, jargon-free sentence.

**Not verified, and cannot be here:** a physical token; a real gateway accepting or refusing a
token-held certificate; `libykcs11.dylib`'s and OpenSC's behaviour with real hardware; and the exact
wording OpenConnect emits when a *gateway* refuses a token certificate (the classifier attributes that
case by elimination — material loaded, no PIN complaint, no tunnel — rather than by matching a string).

---

## Manual test recipe for someone with a YubiKey

The parts that need hardware. Everything before step 4 costs nothing; step 6 is the only one that
touches the PIN counter.

1. `brew install opensc gnutls openconnect` — OpenSC provides the provider module, GnuTLS the reader
   SimpleVPN enumerates with, and `openconnect` is what actually signs in. (Yubico's own module,
   `brew install yubico-piv-tool` → `libykcs11.dylib`, is an alternative to OpenSC and SimpleVPN finds
   either.)
2. Load a certificate onto the key's PIV applet with **Yubico's** tool, following
   <https://developers.yubico.com/yubico-piv-tool/> — not with SimpleVPN, which never writes to a token.
3. Register the module: SimpleVPN shows the exact command on the module row; copy and run it. Confirm
   with `p11tool --list-tokens` (no `--provider`) that the key appears.
4. In SimpleVPN: Manage VPNs → an SSL VPN kind → **Sign-In** → method **Smartcard or security key**.
   The module list should already name OpenSC (or YKCS11). Press **Find Certificates**: the PIV
   certificates should list with their subject and expiry. *This is the step that proves enumeration
   against real hardware; it uses no PIN.*
5. Pick the certificate your administrator enrolled — on a PIV card that is normally
   "Certificate for PIV Authentication" (id `01`), not the signature or card-authentication one.
6. Enter the PIN and **Connect**. Watch for: a red PIN-retry warning if the counter is already down
   (stop if it says one attempt remains); "Token … is present" once the card is seen; and — on failure
   — one specific sentence rather than an exit code.
7. Negative checks worth doing once: unplug the key and connect (should say *no token is inserted*);
   point at a certificate the gateway hasn't enrolled (should blame the **server**, not the token);
   deliberately mistype the PIN once and confirm exactly one attempt was spent (`pkcs11-tool -T` shows
   `user PIN count low`, and a correct login clears it).

---

## Vendor documentation

Their pages are the authority; the commands above are a nudge, current as of the latest releases only.

| | |
|---|---|
| OpenSC (smartcards, PIV) | <https://github.com/OpenSC/OpenSC/wiki> |
| Yubico PIV tool / YKCS11 | <https://developers.yubico.com/yubico-piv-tool/> |
| OpenConnect PKCS#11 | <https://www.infradead.org/openconnect/pkcs11.html> |
| p11-kit configuration | <https://p11-glue.github.io/p11-glue/p11-kit/manual/config.html> |
| RFC 7512 (the URI scheme) | <https://www.rfc-editor.org/info/rfc7512/> |

All five were checked to return 200 (post-redirect form recorded above) as part of this work. Note that
`manual.html` deliberately names these sources in prose rather than linking out: ALL user documentation
is embedded in the app (AGENTS.md), because a VPN client's help has to work exactly when the network
doesn't.
