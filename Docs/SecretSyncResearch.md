# Syncing configuration and secrets across a user's own Macs

What other people actually built, what it cost them, and what SimpleVPN should do.

This is a research record and a recommendation, not a design document and not an implementation.
It exists because "optional, default-off sync of configuration and secrets, protected properly" is
easy to say and has about six wrong answers, four of which look right for a week.

**The short version.** Sync the config through CloudKit, encrypted and *signed* by a key that lives in
iCloud Keychain; sync the SimpleVPN-custodied secrets by marking those keychain items synchronizable
and letting Apple's device circle and escrow HSMs do the work. Do **not** build a recovery key — Apple
already runs the hardware that makes one unnecessary, and the only thing our own would add is a piece
of paper to lose. Ship encrypted export/import first, because it is cheap, it is the migration tool,
and nobody else in this market ships one. And spend the real engineering effort on **integrity**, not
confidentiality, because that is the part every precedent got wrong.

**One prerequisite before any of it:** strip inline `<key>` material out of imported `.ovpn` files.
Today an OpenVPN profile can carry a client private key in `providerConfiguration`, which means the
claim that profiles are secret-free is narrower than it reads.

---

## 1. What SimpleVPN actually holds today

Verified by reading the tree, not inferred.

| What | Where it lives now | Notes for sync |
|---|---|---|
| Profile / connection settings | `NETunnelProviderProtocol.providerConfiguration`, per-kind blobs | the point of the feature |
| **The raw `.ovpn` text** | `providerConfiguration["ovpn"]` — `VPNController+CRUD.swift:30` | **contains a private key when the import had an inline `<key>`** |
| Username / password | keychain, `com.bragi0.SimpleVPN.creds` | small generic password |
| Proxy password, key passphrase | keychain, `…secrets` | small generic password |
| Custom-Routing proxy auth | keychain, `…customrouting-proxyauth` | small generic password |
| Native VPN secret (persistent ref) | keychain, `…native` | **must not sync** — see §6 |
| Read-once connect payload | keychain, `…session` | **must never sync** — transient by design |
| Touch-ID-protected copies | data-protection keychain, `.userPresence` — `CredentialProvider.swift:81` | **cannot** sync |
| WireGuard private key / PSK | keychain; redacted out of the blob (`WireGuardTests.swift:395`) | small |
| Sign-in source *references* | in the profile, never a secret | config, not secret |
| Policy-routing script | IPC blob into the sysext (`Docs/PolicyRouting.md`) | **the most security-determining thing we have** |

### The finding that changes the shape of the feature

Q9 says profiles and settings are "asserted secret-free … by construction, not by remembering to be
careful". That is true of the **structured** per-kind configs. `WireGuardConfig.redactedForStorage()`
is real and `neitherKeyReachesThePersistedBlob` pins it.

It is **not** true of the OpenVPN path. `CertificateImport.swift`'s own header says "The raw .ovpn
stays the source of truth", and `OVPNInline.setBlock("key", …)` writes a PEM private key *into* that
stored text. The tests that grep for secrets cover `CredentialSource.fieldMap`, `VPNAuthConfig`,
`WireGuardConfig` and the YubiKey setup. **None of them greps the `ovpn` string.**

The existing **Export .ovpn…** (`ManageVPNsView.swift:625`) therefore already writes client private
keys to disk in the clear, with no warning. That is a bug today, independent of sync.

What is *not* affected, so the finding is not overstated: the **diagnostic bundle is already safe.**
`SecretScrubber.redactBlocks` strips every `-----BEGIN … -----END …-----` block, PuTTY keys and plist
`<data>` blobs before any other pass. The exposure paths are `providerConfiguration` at rest, Export,
and — if built naively — sync. Not logs, not diagnostics.

### One honesty note on the `.userPresence` fact

Q9 leans on "a keychain item with a `.userPresence` ACL can never be `kSecAttrSynchronizable`". The
constraint is real and the code is right to assume it. But **Apple does not document it.** What Apple
documents is that synchronizable items may not use an accessibility class "whose names end with
`ThisDeviceOnly`", that they "cannot specify `SecAccessRef`-based access control with
`kSecAttrAccess`", and that ACLs "are evaluated inside the Secure Enclave". There is no sentence about
biometric `SecAccessControl` and syncing. If this repo ever needs a citation, the citable one is the
`ThisDeviceOnly` sentence — which `CredentialProvider.swift:81` satisfies by pairing `.userPresence`
with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Recorded so nobody goes looking for a quote that
is not there.

---

## 2. The comparison table

"What the cloud sees" means what a malicious or compelled operator of the sync service could obtain.

| Mechanism | What the cloud sees | Second-device enrolment | Recovery when the credential is lost | UX cost |
|---|---|---|---|---|
| **1Password** | SRP verifier, KDF params, encrypted keysets (public halves clear), wrapped vault keys, encrypted item overviews + details. Never the password, Secret Key, AUK, or plaintext | Add-device link (or Emergency Kit QR) carrying the **Secret Key**, *plus* the account password. Server relays, learns neither | **None from AgileBits, by design.** Emergency Kit is the user's own escrow. Teams get a Recovery Group holding vault keys wrapped to a recovery public key — cryptographic, but bounded by *server* policy | High: two secrets, one of them a printed artefact |
| **Bitwarden** | Protected Symmetric Key, doubly-hashed password hash, RSA keypair (private half wrapped), all ciphers | **Password alone reconstructs everything.** Optional emailed OTP for new devices (server-side only), or "log in with device" which wraps the user key to an ephemeral device public key | **None for individuals.** Emergency Access grants the user key to a contact's RSA public key; Enterprise admin reset wraps the user key to the org public key | Low — and that is the trade: low friction, no recovery, password-only device enrolment |
| **KeePassXC / KDBX4** | Nothing but an opaque file (the "cloud" is Dropbox/iCloud/Syncthing) | Copy the file; supply password + optional key file + optional YubiKey HMAC-SHA1 challenge-response | **None.** Composite key or nothing. A YubiKey component needs its HMAC secret backed up separately or the database is bricked | Medium-high: you operate the sync, and merges are a **manual** menu item |
| **Keeper** | Encrypted Data Key (one wrap per method), record/folder ciphertext + wrapped keys, device EC **public** keys, auth token hash | **Device verification is mandatory** (email code / 2FA / Keeper Push) and happens *before* the master password. For SSO accounts it is a real key transfer: the new device's EC public key gets the Data Key wrapped to it | 24-word **BIP39 recovery phrase** (HKDF-HMAC-SHA512 → AES-GCM wrap of a second Data Key copy), generated on device. Enterprises can disable it, leaving Vault Transfer | High: phrase + mandatory per-device approval |
| **Proton Pass** | Account salt, SRP verifier, bcrypt-wrapped user key, signed+encrypted vault keys, encrypted item keys and items | **Not documented.** The hierarchy implies password alone is sufficient; no per-device key or approval appears anywhere | 12-word recovery phrase, or a recovery file. **Email/SMS recovery restores the account but not the data**: "if you recover your account by email or SMS verification, your data remains encrypted" | Medium; the sharp edge is that the account and the data have different recovery stories |
| **iCloud Keychain** | Signed lists of per-device **P-384 syncing identities** (in CloudKit) and the legacy signed circle (in iCloud KVS). Items are exchanged **between peers**, each holding its peer's public key — "encrypted so that it can be decrypted only by a device within the user's circle of trust; it can't be decrypted by any other devices or by Apple" | **Sponsorship by an existing device** (which issues a signed voucher), **or** iCloud Keychain recovery | **HSM escrow.** Record wrapped to the iCloud Security Code (or, on 2FA accounts, the **device passcode**) and to the HSM cluster's public key; SRP so "the code itself isn't sent to Apple"; **10 attempts**, then "the HSM cluster destroys the escrow record and the keychain is lost forever" | **Near zero** — it is an OS feature the user has already set up |
| **FileVault** | n/a (local) | n/a | **24-character personal recovery key** — and note Apple's own answer to "the user will lose the paper": by default it is **stored in the keychain and synced via iCloud Keychain**. Institutional recovery keys are now deprecated: "the use of an IRK is no longer recommended" | High if held on paper; near zero if delegated to iCloud |
| **Signal SVR3** | An Argon2id-derived `access_key` and a 48-byte SIV blob, secret-shared across SGX + Nitro + SEV-SNP with client-pinned measurements | Device linking is **out-of-band and high-entropy** — QR code, Curve25519 provisioning, one-time linking token. The PIN is not involved | 4–6 digit PIN, rate-limited **in the enclave**: on the 10th wrong guess the row is zeroed and erased and the client is told `MISSING` | Low for the user, enormous for the operator |
| **WhatsApp E2E backups** | An OPAQUE registration record in an HSM Backup Key Vault across "seven or more datacenter sites"; fleet keys pinned, now published via Cloudflare Key Transparency | n/a (per-device restore) | Password (OPAQUE against the HSM, finite attempts then permanent lockout) **or** a 64-digit key the user keeps. Forget both and the backup is gone | Low, with a cliff |
| **Firefox Sync** | Ciphertext, plus per-record ids/sizes/timestamps and **collection names** — Mozilla sees that you have 300 passwords and when they changed. The auth server sees `authPW`, a deterministic function of the password, at every sign-in | Password (which *reconstructs* `kB` — no second secret exists), **or** the pairing flow: scan a QR whose fragment is a **TLS 1.3 PSK**, then run the scoped-keys OAuth exchange over that channel. No password typed on the new device | **Password reset destroys `kB` and all synced data** unless a **32-character base32 account recovery key** (2018) was made first. It is single-use, user-custodied, and *not* escrowed | E2E is the default and there is no extra secret to enter. The cost landed elsewhere: key strength bounded by the password, and a trust dependency on Mozilla-served JavaScript |
| **Chrome Sync** | By default **the key itself** — the keystore key is generated, stored, rotated and transmitted by Google. Their words: "you lock up your valuables, and the bank looks after the key … you trust Google to hold the key". With a custom passphrase, ciphertext only | Sign in; then re-enter the passphrase **on every device**, including a special Android handoff so Play Services can decrypt | **None.** "The passphrase is not sent to or stored by Google." Reset deletes the server copy — and the 2026 help page now warns it deletes "your passwords and other info … from your Google Account **and your device**", advising an export first | High and concrete: **history sync stops and is wiped** (`kMustStopAndClearData`), cross-device history *deletion* stops propagating, passwords.google.com and Smart Lock break, Wallet data isn't covered anyway, and it cannot be turned off without resetting sync |
| **Google Password Manager on-device encryption** | Ciphertext only. Escrow is a **Titan HSM cohort**; Chrome's `trusted_vault` client talks to `cryptauthvault.googleapis.com` with SecureBox v2 against certs from `gstatic.com/cryptauthvault/v0/cert.xml` — **the same Cloud Key Vault as Android backup E2EE** | Screen-lock PIN or Google password on an eligible device | **Rate-limited escrow: exactly 10 attempts**, `TRUSTED_HARDWARE_MAX_ATTEMPTS = 10` in AOSP, cryptographically bound into the vault parameters the Titan enforces — not a server policy knob. Then permanently irretrievable | Low, deliberately: it "lets you set up **multiple ways** to lock and unlock data … making it **less likely you will lose access**". Irreversible once on, and Google intends it to become universal |
| **Tailscale** | Node **public** keys and ACL-derived policy. "the private key never, ever leaves its node" | Log in via your IdP; `--auth-key` for headless. Nothing secret is copied from another device | Nothing to recover — mint a new key. (Tailnet Lock's disablement secrets *are* unrecoverable: "the tailnet cannot be recovered") | Near zero |
| **WireGuard (official Apple app)** | Nothing. `kSecAttrSynchronizable = false` **and** `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on macOS | Type it in, import a `.conf`, scan a QR, or push a `.mobileconfig` | Nothing to recover | Zero features, all friction |
| **Mullvad** | Up to 5 device records, each a **public** key. `PrivateKey::new_from_random()` on device; only `pubkey` crosses the API | Sign in with the 16-digit account number; the app mints a fresh key | Account-number recovery is **best-effort, payment-traceable for ≤20 days, and costs you anonymity** | Low |
| **Proton VPN** | Per-device public key → certificate, for the apps. **The dashboard generates the private key server-side and keeps it re-readable** | Sign in | Proton account recovery restores VPN service outright — there is no user-encrypted VPN payload to lose | Low |
| **Viscosity** | Nothing — no cloud sync exists, and hasn't in ~8 years of requests | Manual. `.visc`/`.visz` bundle, or Import From Server | n/a | Manual; and the bundle is a **plaintext tar.gz containing the client key** |
| **Tunnelblick** | Nothing — no sync | Manual. `.tblkSetup` export/import, with a username-mapping UI | n/a | Manual; unencrypted, but **"Saved usernames and passwords are not exported"** |
| **Passepartout** (indie OpenVPN/WG client) | Plaintext `name`/`uuid`/`lastUpdate` for querying; the whole profile **including credentials** in one CloudKit **encrypted field** | Sign into iCloud; the key arrives via iCloud Keychain | Apple's | **Opt-in, disabled by default** |

---

## 3. Testing the hypothesis: do VPN clients sync secrets?

**Substantially confirmed, with two corrections that matter.**

Not one of Tailscale, the official WireGuard apps, Mullvad, Proton VPN's apps, Viscosity, Tunnelblick,
OpenVPN Connect, Cisco Secure Client or GlobalProtect syncs a private key between a user's devices. The
universal model is a per-device keypair generated locally with only the public half registered. Two of
them add machinery to make a *copied* secret fail elsewhere — CloudConnexa's DIVE "validates the
device's unique UUID to verify that the digital certificate belongs to it", and OpenVPN AS issues
per-device certificates precisely so one device can be revoked.

**Correction 1: "the account is the source of truth" is two different mechanisms, not one.**
*Enrollment* — the device authenticates and mints its own key (Tailscale, the Mullvad app, Proton's
apps, Cisco's SCEP proxy). *Provisioning* — the server generates the private key and pushes it down
(OpenVPN Access Server, CloudConnexa, **Proton's web dashboard**, and **GlobalProtect's SCEP**, where
"the portal submits a CSR to the SCEP server" and "then deploys the certificate to the app
transparently", with "the client certificate passphrase saved in the portal configuration"). The
keypair-on-device property holds for macOS/MDM SCEP because *the OS* does it, not because GlobalProtect
does. Worth knowing before citing SCEP as a good example.

**Correction 2 — and this is the important one for us: the hypothesis is right about commercial
clients and wrong in general.** **Passepartout**, an open-source OpenVPN/WireGuard client for
macOS/iOS/tvOS and the closest structural analogue to SimpleVPN that exists, syncs profiles *including
credentials*, using `NSPersistentCloudKitContainer` and a Core Data attribute declared
`allowsCloudEncryption="YES"` — a CloudKit encrypted field keyed from the user's iCloud Keychain. The
whole profile is serialised to JSON into that one attribute; `name`, `uuid`, `lastUpdate` and
`fingerprint` stay plaintext so they remain queryable; a separate non-synced keychain repository serves
the extension. It is **opt-in and disabled by default** since 2.2.0, and offers "erase the existing
store so that your profiles only stay on your device".

So the recommendation below is not novel and not speculative. Somebody with the same problem picked the
same answer and shipped it. What they did *not* build is any integrity or rollback story — which is
where our effort should go.

### Why we cannot use the pattern the commercial clients use

Q9's framing is right and worth restating because it is the whole constraint: the reason every VPN
client can avoid this problem is that **each of them has an account, a control plane, or a gateway that
is the source of truth**. Tailscale has an IdP. Mullvad has an account number. Cisco and Palo Alto push
config from the headend — the gateway *is* the sync mechanism. SimpleVPN is a client for **other
people's** servers and has no account of its own. There is nothing to re-issue from. That is precisely
why we are in this document and they are not.

---

## 4. The integrity problem, which dominates

Q9 treats sync as a confidentiality problem. It is mostly an **integrity** problem.

Config is not very secret but it *is* security-determining. Concretely, in this codebase, someone who
can modify a synced profile can:

- change `remote` to their own server;
- delete `remote-cert-tls server` or `verify-x509-name`, or swap `<ca>` — turning verified TLS into
  trust-anything;
- flip the stored SSH host-key pin. `SSHHostKeyDecision` resolves trust in the app and hands **one**
  fingerprint to the extension, which is pin-only and faithful — so poisoning the pin makes the
  extension enforce the attacker's key;
- add a connection proxy pointing at a machine they control;
- weaken WireGuard's `AllowedIPs`, or repoint `Endpoint` and `PublicKey` together;
- turn a full tunnel into a split tunnel so the interesting traffic leaves in clear.

And the sharpest case, which did not exist when Q9 was written: **a policy-routing script.**
`Docs/PolicyRouting.md` describes a Tcl 9 policy interp inside the root packet-tunnel sysext, the script
arriving "over the existing IPC as a blob", deciding which egress every flow takes and able to
`NAT::snat`/`NAT::dnat`. A modified policy script does not weaken the tunnel — it **chooses where your
traffic goes**.

Two things keep that from being catastrophic, and both should be stated rather than assumed. Scripts run
in a **safe interp** with no file, exec or socket access, and "Scripts never see credentials or keychain
material; `VPN::require` resolves app-side". So it is not code-execution-as-root and not a credential
leak. But it is traffic redirection, and the doc already names the control that matters: "Policy/MDM can
disable PBR, **pin the script**, or forbid `FLOW_COLLECT`." **If policy scripts sync, that pin stops
being optional.**

The prior art is Tunnelblick's **shadow copy**: every private config exists twice, once user-editable and
once root-owned, and on connect the two are compared with an **admin password prompt** gating
propagation, because configs "can contain scripts which run with administrator (root) privileges". Our
interp is sandboxed where Tunnelblick's up/down scripts are not, so we need the compare-and-confirm, not
the authorisation prompt. The shape of the answer is still theirs.

### The finding I did not expect: nobody solves this

I went looking for how the password managers handle rollback, assuming the mature ones would have an
answer to copy. **None of the five does.** All of them use authenticated encryption, which proves a blob
was made by someone with the key and says **nothing about when**. In none of them is there a monotonic
counter, a signature chain, or client-side version pinning:

- **1Password** generates an ECDSA P-256 key at signup and the whitepaper says it "is not used in the
  current version of 1Password" — the machinery is provisioned and idle. Item history means the server
  legitimately holds older valid ciphertexts of everything.
- **Bitwarden**'s `revisionDate` is server-supplied and unauthenticated; it is a sync optimisation. Worse,
  its `EncString` MAC covers only `IV ‖ ciphertext` with **no associated data**, so a malicious store can
  not merely roll back but **relocate** a valid ciphertext from one field or item to another, and every
  client accepts the MAC.
- **Keeper**'s audit logs are server-generated, so a compromised backend rewrites them with the data.
- **Proton Pass** signs *keys* with OpenPGP — genuinely better, and it defeats key injection, including
  in sharing flows. But nothing documented signs vault *state*, and whether item **contents** are signed
  is not stated anywhere.
- **KDBX4** has no version counter; an old `.kdbx` has a perfectly valid HMAC.
- **Passepartout**, our closest analogue, has none of this either.
- And the browsers are no better — **Chrome's Nigori does not authenticate the IV**, still, by default:
  `BASE_FEATURE(kSyncNigoriAuthenticateIV, base::FEATURE_DISABLED_BY_DEFAULT)` in
  `components/sync/base/features.cc`, against a tracker entry titled "Nigori does not use authenticated
  encryption, it forgets to compute the HMAC on the IV". A MAC that does not cover the IV is a MAC with a
  malleable first block. This is the same class of omission as Bitwarden's missing associated data, in a
  product with two billion users.

A related finding that generalises: in all four SaaS products **write authorisation is server policy,
not cryptography.** 1Password says so outright — a read-only member can extract the vault key,
re-encrypt modified items, and only "server policy prevents her from uploading modified data".

Two consequences. First, this is not a solved problem we are neglecting; if SimpleVPN does it, it will be
ahead of the password managers. Second — the reassuring half — **it is cheap for us**, because we have
one user and no sharing, so we need a counter and a signature, not a transparency log.

### What actually stops rollback

The literature answer is *fork consistency*: against an untrusted server with no trusted third party you
cannot **prevent** forking, only make it **eventually detectable** (SUNDR). Two shipped systems do the
practical version, and both are small:

- **TUF** — every metadata file carries a monotonic version number and an expiry; a version lower than
  the trusted one is discarded and reported as a rollback attack, and root metadata must increment by
  exactly one. Expiry provides freshness and blocks freeze attacks.
- **Tailnet Lock** — an append-only hash chain of Authority Update Messages: "with the exception of the
  genesis update, all AUMs reference the hash of the previous update", each must be signed by a key
  trusted *at the state immediately preceding it*, and forks resolve by a deterministic rule. Tailscale
  built it precisely so that **their own infrastructure need not be trusted** — the closest thing in the
  VPN world to what we need.

And one mitigation worth stealing that costs almost nothing because it is a workflow property rather
than a cryptographic one. **KeePassXC's timestamp merge mechanically reverses a rollback in normal
operation**: the sync host lacks the composite key, so it can only replay whole old files — it cannot
backdate the per-entry `LastModificationTime` values *inside* the database. Merging with KeepNewer
therefore files every rolled-back entry into history, and deleted-object records stop deletions being
undone. Its two gaps are the fresh-install case (no local state to compare) and the fact that the merge
is **manual** — the cloud conflict file sits there until someone finds the menu item.

So the whole answer reduces to: **sign a manifest, chain it, number it monotonically, remember the
highest number seen locally, refuse to go backwards, and merge per profile rather than overwrite.**

CloudKit hands us the write half for free. The default `RecordSavePolicy` is `.ifServerRecordUnchanged`
— a compare-and-swap on `recordChangeTag` that errors with `CKError.serverRecordChanged`. That is
`git push --force-with-lease`, and it turns "two Macs wrote" into a detected conflict rather than a
silent overwrite.

### Should a security-relevant change require confirmation with a diff?

**Yes — and only for a defined, enumerated set.** Not for every change: a confirmation on every sync is
a confirmation nobody reads, which is worse than none.

The house already has the idiom and the sentence explaining it. `SSHHostKeyDecision.swift`: *"trust on
first use is a decision someone makes, never something that happens."* A synced change to a
security-determining field is the same event as a changed SSH host key — usually benign (you edited it
on the other Mac), occasionally an attack, never something to apply silently.

So: a declared **security-determining field set** — server address, `<ca>`, `remote-cert-tls`,
`verify-x509-name`, SSH host-key pin, WireGuard `PublicKey`/`Endpoint`/`AllowedIPs`, connection proxy,
full-tunnel→split-tunnel, any weakening of certificate verification, and **any policy-routing script** —
and an inbound change to any of them lands **pending, not applied**, with a field-level diff and one
confirmation. Everything else (names, ports, comments, labels, MTU) applies silently. The set is a
declared list with a test, not a judgement made at each call site — the discipline the settings catalog
already uses.

Three details that make this honest rather than theatrical:

- **Direction matters.** Loosening needs confirmation; tightening does not. Adding
  `remote-cert-tls server` is never something to interrogate the user about.
- **A pending change must be visible in the connect path**, not only in the editor, or a profile sits
  half-synced and nobody knows. That is Q4's rule again: never hide something the user made.
- **A policy script has no benign-change category.** It is always pending-with-diff.

---

## 5. The four options, priced

### (a) Sync config only, never secrets
- Cost: CloudKit container, iCloud entitlement, per-profile records, conflict UI, the integrity layer.
- Recovery: nothing to recover; config is re-importable.
- Weakness: **it does not do what was asked.** On a second Mac every profile is present but nothing
  connects until each sign-in is re-entered — annoying for a stored password, and *impossible* for a
  WireGuard private key SimpleVPN generated, because that key is the only copy in existence.

### (b) FileVault-style user-held recovery key wrapping a data key, Touch-ID per device
- Cost: everything (a) costs, plus recovery-key generation, display, print, verification, re-key on
  device add/remove, the "lost your key" dead end, and the copy explaining all of it.
- Recovery: user-held. Strong, and entirely on the user.
- **Verdict: rejected**, and the FileVault comparison is what rejects it. FileVault needs a recovery key
  because there is **no other custodian** — the volume key is wrapped only by things on that one machine.
  iCloud Keychain has a custodian (the device circle) *and* an escrow (HSMs, SRP-verified so "the code
  itself isn't sent to Apple", ten attempts and then the record is destroyed). We are in the second
  situation.

  Notice also what Apple itself did with the artefact: the personal recovery key is 24 characters and by
  default macOS **stores it in the keychain and syncs it through iCloud Keychain**, and Apple has
  *deprecated* the institutional recovery key outright — "the use of an IRK is no longer recommended".
  The direction of travel in Apple's own most-recovery-key-ish feature is away from user-held artefacts
  and towards the account. §9 reaches the same verdict from Mozilla and Google, in their own words and
  their own source trees: **the extra secret did not win; rate-limited escrow of a low-entropy secret did.**

  What FileVault *should* be borrowed for is the **key-wrapping shape**, not the recovery key. APFS
  associates several independent *cryptographic users* with one encrypted volume — each secure-token
  account, plus special-purpose recovery users — and Apple's stated design goal is to let users change
  "the cryptographic keys used to protect their files" **"without requiring reencryption of the entire
  volume"**. One data key, several independent wrappers. Adopt that internally and option (b) can be
  **added later without redesigning anything** — which is the real argument for not building it now.

  The Touch-ID-per-device half should stay, because it already exists (`BiometricCredentialStore`). But
  it is a local unlock convenience, not a sync mechanism, precisely because `.userPresence` items cannot
  be synchronizable.

### (c) A two-secret model like 1Password's
- What it is: the account password NFKD-normalised, its salt HKDF-stretched with the lowercase email,
  then PBKDF2-HMAC-SHA256 at 650,000 iterations; the 26-character Secret Key (~128 bits) through HKDF;
  the two 32-byte results **XORed** into the Account Unlock Key. A second, independently-salted run of
  the same procedure yields SRP-x for authentication.
- Cost: **an account we do not have.** The Secret Key earns its keep only because AgileBits runs a server
  that participates in SRP and holds the wrapped keyset while learning neither secret.
- **Verdict: rejected as structurally unavailable**, not merely expensive. Strip the server out and 2SKD
  degenerates into "a passphrase plus a second thing the user must also keep" — option (b) with extra
  steps and two artefacts to lose instead of one.

### (d) Don't sync; encrypted export/import
- Cost: small. One file format, one passphrase, one importer. No entitlement, no container, no conflict
  resolution, no rollback problem — a file the user carried is a file the user chose.
- Recovery: the passphrase, and the original still exists.
- Weakness: manual. It is a migration tool, not sync. But it is the honest floor, and — see below — it is
  the thing this market does not have.

---

## 6. Recommendation

**Ship (d) first and unconditionally. Then ship a two-track version of (a) that also carries the secrets
SimpleVPN itself custodies. Do not build (b) or (c).**

### Track 0 — Strip inline key material at import (prerequisite, ships alone)

Independent of sync. Makes the secret-free claim true and testable by the grep that already covers the
other blobs, and fixes the existing plaintext Export leak. See §7.

### Track 1 — Encrypted export / import (ships alone, no entitlement)

**This is unoccupied ground, and that is the argument for doing it.** Both commercial analogues ship
*plaintext* bundles. A Viscosity `.visc`/`.visz` is a tar.gz containing "all certificates, keys, and
other files referenced in the configuration file", with no password protection available anywhere in the
product. Tunnelblick's `.tblkSetup` is also unencrypted but sidesteps the problem by carrying no secrets
at all. And both server-fetch mechanisms — Tunnelblick's `TBConfigurationUpdateURL` and Viscosity's
Import From Server — **trust HTTPS alone with no signature over the profile**, even though Tunnelblick
signs its own app.

So: one bundle, profiles plus optionally the SimpleVPN-custodied secrets, under a passphrase, AEAD, with
a **signed manifest inside** so a tampered bundle fails closed. Use **Argon2id**, not PBKDF2 — 1Password
is on PBKDF2 only "as a consequence of" what WebCrypto offers browsers, which is not a constraint a
native Mac app has, and Proton's bcrypt is worse still (72-byte input truncation, fixed 4 KiB memory,
cost factor not even published). This is the whole feature for someone with one Mac and a backup, the
answer for "moving to a new Mac", the fallback when sync is off or MDM-forbidden, and it gives the sync
work its serialisation format for free.

Steal Tunnelblick's import semantics rather than rediscovering them: importing overwrites a
same-named configuration; importing to a user first removes that user's existing ones; a user's settings
are not imported until they next launch. Those are the edge cases, already found the hard way by someone
else.

### Track 2 — iCloud sync, two tracks, default off

**Secrets → iCloud Keychain directly.** Mark the specific generic-password items (`…creds`, `…secrets`,
`…customrouting-proxyauth`, WireGuard keys) `kSecAttrSynchronizable`. No key hierarchy of ours, no
ciphertext to manage, Apple's E2E plus device circle plus escrow HSMs, and recovery that already works.

Excluded by construction: `.userPresence` items (cannot sync) and `…session` (read-once, transient).
`…native` is excluded too, for a reason easily missed: it exists only to mint a *persistent keychain
reference* for `NEVPNProtocol`, and Apple warns that "persistent references to synchronizable items
should be avoided; while they may work locally, they cannot be moved between devices". A synced
native-VPN secret would sync a ref that resolves to nothing.

One trap to take from WireGuard's app while we are here. On macOS it sets **both**
`kSecAttrSynchronizable = false` *and* `…AfterFirstUnlockThisDeviceOnly`; on iOS it sets neither
`Synchronizable` nor a `ThisDeviceOnly` class, only `AfterFirstUnlock` — so the iOS item stays out of
iCloud but remains eligible for an encrypted device backup and restore onto *a different device*.
**`Synchronizable = false` alone does not keep a secret on one Mac; only the `ThisDeviceOnly` class
does.** `KeychainCredentialStore` already passes `…AfterFirstUnlockThisDeviceOnly` and already documents
that the attribute is a **no-op** on the file-based keychain. Moving to the data-protection keychain makes
it start meaning something, so "syncs / never leaves this Mac" must be decided explicitly for all five
services rather than inherited.

**Config → CloudKit private database, one record per profile, encrypted and signed by us.**

- A 256-bit data key and an Ed25519 signing key in **iCloud Keychain**. Since macOS 11 the keychain syncs
  "passwords, certificates, and cryptographic keys", so `kSecClassKey` would work — but keep the key bytes
  in a **generic password** anyway: better-trodden, and it sidesteps the persistent-reference warning.
- Per-profile AEAD, so a conflict is per-profile and can never lose an unrelated VPN. **Bind the profile
  id, the field name and the version into the associated data** — this is the Bitwarden `EncString`
  lesson; it costs nothing and removes the whole relocation attack class.
- A **signed manifest record**: monotonic counter, parent-manifest hash, and the hash of every profile
  record. Devices cache the highest counter and head hash in the **non-syncing** keychain and refuse a
  manifest that goes backwards or fails to chain. TUF's version rule plus Tailnet Lock's hash chain, and
  that is the entire rollback answer.
- Writes use CloudKit's default `.ifServerRecordUnchanged`, so concurrent edits surface as
  `serverRecordChanged` rather than a silent overwrite.
- Conflicts: **merge per profile on last-modified, never blindly replace** — KeePassXC's KeepNewer, but
  automatic rather than a menu item nobody finds. Keep a **deletion tombstone** per profile id so a
  rollback cannot resurrect a VPN you removed (KDBX's deleted-object records exist for exactly this).
  When both Macs changed the same profile, keep both: the loser becomes a visible
  "… (conflict from ⟨Mac name⟩)" profile. Never a silent field merge, never a vanished VPN.
- Security-determining inbound changes land **pending with a diff** (§4).
- `CKRecord.encryptedValues` used **as well**, so ADP users get a second Apple-enforced layer — but never
  relied on alone (§8).

### Where it goes, and the words

**Settings ▸ Privacy**, not Advanced and not a new pane. That pane is already where "does data leave this
Mac" opt-ins live (`SettingsView.swift:188`, "Look up my public address"), and its copy shape is the one
to match: *"Off means no such requests are ever made."* Two settings, both default off, the second
appearing only when the first is on:

- `sync.config` — **Keep my VPNs on my other Macs** — "Your connections and settings are encrypted on
  this Mac and stored in your iCloud account, so your other Macs see the same list. The key stays in your
  iCloud Keychain and never reaches Apple. Default: off."
- `sync.secrets` — **Also keep my saved sign-ins** — "Passwords and keys you asked SimpleVPN to remember
  go to your other Macs through iCloud Keychain. Sign-ins protected by Touch ID stay on the Mac that made
  them. Default: off."

Ids `sync.*`, manual anchors `sync-config` / `sync-secrets` (`ManualAnchorParityTests` will fail the build
without them). MDM keys `DisableCloudSync` and `ForbidSecretSync`, respecting `LockConfiguration`; per
`Docs/MDM.md`, an absent key means the user is free.

Two pieces of copy that must not be fudged:

- **Turning it off** must say what happens to the copy already in iCloud and offer to remove it — and
  removal must be a real delete of the CloudKit zone *and* the synchronizable keychain items, not a local
  flag.
- **The honest limit.** This protects against Apple and against anyone who obtains the ciphertext. It does
  **not** protect against someone holding the user's Apple Account *and* the passcode of one of their
  Macs. Say that, rather than implying the guarantee is unconditional.

Where Q9 says "be honest in the copy … not 'end-to-end encrypted, only you can read it' unless that is
precisely true" — with the key in iCloud Keychain, it *is* precisely true, and the hedge is owed
elsewhere. iCloud Keychain is one of the 15 categories Apple lists as end-to-end encrypted under
**standard** data protection: "Keychain items are transferred from device to device, travelling through
Apple servers, but are encrypted end-to-end so that Apple and other devices can't read their contents."
No ADP required. So the sentence to write is *only your Macs can read it — the key never reaches Apple*,
and the hedge is about what that key rests on: the Apple Account, the Macs' passcodes, and Apple's escrow
HSMs.

### What this design does not claim

- **It does not survive an iCloud Keychain reset.** This is the biggest engineering obligation and it is
  inherited, not chosen: if the user resets their keychain, the key material is gone and the ciphertext is
  undecryptable for ever. CloudKit signals it as `zoneNotFound` carrying
  `CKErrorUserDidResetEncryptedDataKey`, and Apple's words are "**When this error occurs, data becomes
  permanently lost.**" **The local Mac must stay the source of truth** — sync is a replica, never the only
  copy — and the app must handle that error by deleting and recreating the zone and re-uploading from
  local state, never by treating the cloud as authoritative.
- **It does not give us rate-limited PIN recovery of our own**, and that is structural rather than
  budgetary. A PIN has 13–20 bits of entropy, so the ciphertext must never be obtainable offline, so some
  party must be online, stateful across attempts, and **unable to override its own counter** — and only
  tamper-resistant hardware buys the last property. All four deployed instances pay the same price: Apple
  destroys "the administrative access cards that permit the firmware to be changed"; Google's Titan treats
  a firmware update as "functionally equivalent to destroying the existing hardware"; Signal pins
  MRENCLAVE/PCR measurements and keeps the guess counter in in-memory Raft; WhatsApp runs OPAQUE against
  an HSM fleet across "seven or more datacenter sites". The literature name is password-protected secret
  sharing / hardware-backed rate-limited key escrow (SafetyPin, OSDI '20, frames it exactly this way).

  Two datapoints that should settle any temptation. **Signal** — which *operates* an attested enclave
  fleet — chose "a 64-character recovery key that is generated on your device", "never shared with
  Signal's servers", for its actual message backups, reserving the PIN path for low-value metadata. And
  1Password refuses escrow outright and hands users a PDF. We borrow Apple's, which is exactly why option
  (b) is unnecessary rather than merely expensive.
- **It detects forking, it does not prevent it** — which is the best any client can do against an
  untrusted store with no trusted third party.

---

## 7. The inline-private-key problem

**Recommendation: strip inline `<key>` (and `<tls-crypt>`/`<tls-auth>`, and PKCS#12-derived keys) into
the keychain at import and reference them — Q9's option 1. Do it before any sync work, and do it whether
or not sync ever ships.**

Why it is right independently of sync: it makes the secret-free claim true rather than nearly-true;
`WireGuardConfig.redactedForStorage()` already establishes the pattern for this exact problem in this
codebase (OpenVPN is the outlier, not the precedent); it fixes the existing plaintext **Export** leak;
and it is what lets inline keys and hardware keys be described by one model.

| Inline block | Secret? | Action |
|---|---|---|
| `<key>` | **yes** — client private key | move to keychain, leave a reference |
| `<tls-crypt>` / `<tls-auth>` | **yes** — a shared symmetric key; `tls-crypt` protects the control channel | move to keychain |
| `<cert>` | no — a public certificate | leave inline |
| `<ca>` | no — **and integrity-critical**, so it must stay where the diff can see it | leave inline |
| a PKCS#12 the user imported | yes — it *is* the key | split at import; never store the `.p12` |
| `askpass` / inline passwords | yes | already handled via `…secrets` |

Four facts make this cheap:

- **There is exactly one hook.** `ProfileImport.swift`: "The single import pipeline every entry point
  funnels into: the file-open panels, drag-and-drop onto any window, Finder double-click/Dock drops, and
  the File ▸ Import menu."
- **The parsing already exists.** `CertificateImport.pemBlocks(in:label:)` and `firstPEMPrivateKey` find
  and classify the blocks; `OVPNInline.setBlock` rewrites them. Nothing new to write, only to reorder.
- **The keychain slot already exists.** `KeychainCredentialStore.ProfileSecrets` is the per-profile
  "engine secrets that must never touch providerConfiguration" store, and its fields are Optional
  precisely so older blobs still decode.
- **The re-injection path already exists and is already the right shape.** The engine needs the key at
  connect time and the extension reads the `.ovpn` from `providerConfiguration`
  (`PacketTunnelProvider.swift:128`), so a stripped key must arrive separately — and it already would:
  the extension takes `proxyPassword`, `privateKeyPassword` and `challengeResponse` from
  `startTunnel(options:)` because it "runs as root in the SYSTEM context and cannot see the user's
  keychain". Adding `privateKeyPEM` and splicing it in before the bridge sees it is the same move once
  more, not a new mechanism.

**Two traps, both cheap to avoid if named now:**

- Import detects duplicates by content hash (`ProfileEvaluation.contentHash`). Strip the key and the hash
  changes, so re-importing the same file after a strip reads as a *new* profile. Hash the original text or
  hash after a canonical strip — but decide deliberately, because getting it wrong produces duplicate
  profiles rather than an error.
- `ovpnText(id:)` has ~35 call sites, and every one currently gets a complete, connectable config. After
  the strip they get a config with a hole in it, and the ones that matter are **Export**, the Configuration
  tab, the Doctor's fix-apply path and `contentHash`. Decide per call site whether it wants the stored text
  or the reassembled one — a single `ovpnText(id:)` silently meaning two different things is exactly how
  the key ends up back in an export.

The migration must not be hand-waved: existing profiles already have keys inline, so the strip has to run
once over stored profiles, and a failure to write the keychain item must **abort rather than delete the
key from the text** — write-then-rewrite, never rewrite-then-write. Do the migration before enabling sync
for a profile, and **refuse to sync a profile that still has inline key material.** That is a far better
guard than a warning at the opt-in, because it cannot be clicked through.

**Q9's option 2 — include it deliberately and say so — should be rejected.** Not because the copy could
not be written, but because it makes the feature's safety depend on a sentence, and because the same fix
is owed to Export anyway. It is also, empirically, the option the market took and got wrong: Viscosity's
bundle is a plaintext tarball with the client key in it. Tunnelblick took the other road — unencrypted,
but "Saved usernames and passwords are not exported", so there is nothing in it to leak. **Tunnelblick's
choice is the right one and it is the one this recommendation follows.**

### The better long-term answer, borrowed from Viscosity

Worth naming because it is strictly better than stripping-to-a-blob, and Viscosity already ships it:
**"SSL/TLS Client (System Identity)"**. Instead of carrying key material at all, the config names a
**keychain identity by DN pattern** — a `Match DN` filter over CN/OU/O/L/ST/C with wildcards and an
`issuer:` prefix — and the client searches the System keychain, the login keychain *and attached
smartcards* at connect time. SparkLabs call it "the recommended approach for deployment in enterprise
environments" because one config file works for every user.

For us that would make a profile **secret-free and portable by construction** — it says *which* identity
it needs, not *what* the key is — and it unifies the inline-key case with the PKCS#11/smartcard case that
`Docs/PKCS11.md` currently keeps on a separate path. That is a bigger change than the strip and should not
block it, but it is the direction the strip should be shaped towards, so the reference left behind in the
`.ovpn` should be a **selector**, not an opaque keychain row id.

---

## 8. Where I disagree with Q9

Three places, all in the same direction: **the platform already solves more of this than Q9 assumes, so
the design should be smaller.** Plus two things Q9 assumes that are not yet true.

### (i) The E2E claim is available to us, and Q9's hedge is aimed at the wrong thing

Covered in §6. iCloud Keychain is E2E under standard data protection; a key living there gives us a claim
we can make honestly.

### (ii) `encryptedValues` is not the load-bearing thing and must not be treated as one

`CKRecord.encryptedValues` looks like the answer and is a trap if relied on alone. Apple's ADP page says
"Advanced Data Protection **also** automatically protects CloudKit fields that third-party developers
choose to mark as encrypted, and all CloudKit assets" — the *also* is doing the work. And Apple is
explicit about the default state: CloudKit service keys "are divided into two categories: end-to-end
encrypted and available-after-authentication", and for the second kind "the service keys are stored in
iCloud Hardware Security Modules in Apple data centers … these keys can be accessed by Apple servers
without further user interaction or input."

Apple is also, in fairness, genuinely ambiguous, and the honest record should say so. Against the
"not-E2E-without-ADP" reading: WWDC21 says the field key material "is stored in the iCloud Keychain
belonging to the iCloud account signed in on the device", and — the strongest evidence —
`CKErrorUserDidResetEncryptedDataKey` exists and its documented consequence is permanent data loss. If
Apple's HSMs held a recoverable copy of that key, a keychain reset could not destroy the data. The likely
reconciliation is that **two different keys** are in play: field contents keyed from iCloud Keychain, and
the surrounding container/record structure keyed by an available-after-authentication service key that ADP
is what removes from Apple's HSMs. Apple states this nowhere; it is inference.

**The engineering conclusion does not depend on resolving it**, which is why it is the right call:
encrypt with our own key from iCloud Keychain and use CloudKit as a dumb blob store. Two further reasons
to own the layer regardless: encrypted fields **cannot be indexed, queried or sorted**, and the
plaintext/encrypted split is a **one-way schema decision** — "CloudKit does not allow encryption on fields
that already exist in your app's schema."

### (iii) The recovery-key proposal

Covered in §5(b). Rejected, with the FileVault comparison doing the rejecting, and with the
several-independent-wrappers shape adopted so it can be added later if the threat model changes.

### (iv) The prerequisites are smaller than Q9 fears — and one comment in the tree is stale

Q9 worries that CloudKit "touches signing and notarisation — this project has been bitten by entitlement
changes producing unlaunchable builds". Half of that is already discharged, and the code says so.

**The embedded profile is already there.** `project.yml:92` sets
`PROVISIONING_PROFILE_SPECIFIER: "SimpleVPN App DirectDist"`, and `SimpleVPN.entitlements` already carries
`keychain-access-groups`. Apple's rule is that a Developer ID app needs an embedded provisioning profile
for "advanced capabilities such as CloudKit", that the profile "is also evaluated, both at app
installation time and at every app launch", and that "if your Developer ID provisioning profile expires,
the app will no longer launch". Profiles issued after 22 Feb 2017 are valid **18 years**, so expiry is not
the risk. The risk is a *wrong* profile making the app unlaunchable — the AMFI class of failure this
project already knows — so re-verify the launch check after the entitlement edit. But no new mechanism is
being adopted.

**The data-protection keychain already works in this app, and `KeychainCredentialStore.swift`'s comment is
out of date.** It says the data-protection keychain "silently failed writes for this app type".
`CredentialProvider.swift:55` records the resolution: biometric access control "requires the
data-protection keychain, which on macOS requires the `com.apple.application-identifier` +
`keychain-access-groups` entitlements to be validated by an EMBEDDED provisioning profile. The app has
shipped with `Contents/embedded.provisionprofile` and both entitlements since the sysext profiles landed —
the old failures (-34018) predate that."

Since setting `kSecAttrSynchronizable` *forces* the data-protection keychain, this is the difference
between "we cannot do the secrets track" and "the secrets track is a migration". It is the latter: move
the credential services to the data-protection keychain with the existing access group, then mark them
synchronizable, using the same read-and-migrate fallback `get()` already implements, run the other way.
**Fix the stale comment as part of it**, or the next reader will re-derive the wrong conclusion.

### (v) The maturity registry does not yet have a slot for this

Q9 says "the `untested` maturity registry applies". It cannot, as written. `FeatureMaturityRegistry` has
exactly **two** tables, `vpnKinds` and `signInSources`, and sync is neither. This feature needs a third
table or a general feature axis, with `FeatureMaturityRegistryTests`' totality assertions extended. Small,
but real work rather than a dictionary line — and the kind of thing that gets discovered at the end.

---

## 9. Honest UX cost

- **A recovery key costs a real user a real thing**: a printed artefact stored somewhere that is neither
  with the Mac nor lost. FileVault and 1Password's Emergency Kit both justify it by the stakes *and* by
  having no alternative custodian. We have an alternative custodian, so the stakes do not justify it here.
- **Losing config is recoverable; losing a secret may not be.** Re-import the `.ovpn` from the provider and
  the config is back. A WireGuard private key that existed only in SimpleVPN, or a generated password the
  user never knew, is gone. This asymmetry is the strongest argument for keeping the two tracks separate,
  and for making the secrets track lean on Apple's escrow rather than on anything we invent.
- **The extra-secret tax is not a guess. Both browser vendors measured it, wrote down what it cost, and
  refused to make it the default — and they reached that conclusion from opposite starting points.**

  **Mozilla, which is E2E by default, has refused for twelve years to add a Sync-only passphrase.**
  Bug 1034526 ("New Sync should have an option to encrypt data with a secret that's not used for anything
  else") is still `NEW` with five duplicates, and Ryan Kelly's answer is the sentence to quote at anyone
  proposing an extra secret: *"the obvious approach of adding a second passphrase just for Firefox Sync
  remains off the table; … **it's a bad user experience, and it's contagiously bad — it forces you to
  enter two passphrases on every device.**"* Mozilla's own architecture record ADR 0005 generalises it:
  *"**Password entry, especially on mobile devices, is difficult and a source of user dropoff.**"* And in
  *Private by Design* they evaluate Chrome's separate-passphrase model explicitly and reject it as
  *"confusing to users"* and *"very easy to choose the same (or similar) passphrase and negate the
  security."*

  **Google, which is not E2E by default, is actively migrating users *off* its extra secret.**
  `nigori_specifics.proto` carries a `TrustedVaultAutoUpgradeExperimentGroup` with 99 cohorts and
  TREATMENT/CONTROL/VALIDATION arms — a server-driven rollout moving people from custom passphrases to
  the HSM-escrowed trusted vault. Google's own help centre states the reason as a comparison:
  a passphrase means *"**You will lose access to your data if you forget your sync passphrase**"*, whereas
  on-device encryption *"lets you set up **multiple ways** to lock and unlock data … making it **less
  likely you will lose access to your data**."* And they intend it to become universal: *"Over time, this
  security measure **will be set up for everyone**."*

  **Neither vendor publishes an adoption figure** — though Google measures it forever, via a
  `Sync.PassphraseType5` histogram marked `expires_after="never"`. Draw no conclusion from the silence
  beyond the obvious one.

  So the verdict of the two organisations best placed to absorb the friction is unanimous and recorded in
  their own source trees: **the extra secret did not win. Rate-limited escrow of a low-entropy secret
  did.** That is exactly the trade §6 makes by borrowing Apple's escrow instead of minting a recovery key.

- **One caution about that convergence, because it cuts our way too.** Google's Titan escrow is *attested
  and third-party audited*, not publicly verifiable — firmware updates wipe the chip, which is the same
  "destroy the hardware" move Apple makes with its escrow access cards. Nobody in this class of design
  gets a *verifiable* guarantee; they get a hardware-enforced one from a vendor. Choosing Apple's is
  therefore not a weaker choice than choosing Google's or building our own — it is the same choice, with
  the operator already in place.
- **The cheapest honest thing we can offer instead of a recovery key** is Track 1: an encrypted export the
  user can take *themselves*, on their own schedule, to their own backup. It gives the same
  independent-of-Apple property to anyone who wants it, without imposing a ritual on everyone who does
  not.

---

## 10. What I could not verify

Named rather than smoothed over.

1. **Does CloudKit work for an app with `ENABLE_APP_SANDBOX: NO`?** SimpleVPN's container app is
   deliberately unsandboxed (`project.yml:90` — "a sandboxed app can't talk to systemextensionsd"), and
   iCloud entitlements are conventionally paired with the sandbox. I believe CloudKit does not *require*
   the App Sandbox, but I did not confirm it from Apple. **This is the one thing to spike before committing
   to CloudKit.** If it turns out sandbox-only, the config track needs a different transport, and the
   fallback is `NSUbiquitousKeyValueStore` — 1 MB total per user, 1 MB per value, 1024 keys, which is
   perhaps 20–100 profiles with compressed certificates and a hard wall after that — or a ubiquity
   container.
2. **Keychain item size limits for iCloud Keychain sync.** Apple publishes none, and the "few KB" figure in
   circulation is not traceable to Apple. Apple only frames the keychain as being for "passwords and other
   short but sensitive bits of data". Design for small secrets and key the bulk from them.
3. **Whether biometric `SecAccessControl` items are *documented* as non-syncable.** They are not (§1). The
   constraint is real in practice.
4. **The exact wording of TN3137's data-protection-keychain requirements.** Apple's developer pages are
   JS-rendered and did not yield text to automated fetch. The repo's own
   `CredentialProvider.swift:55` records the empirical finding and cites TN3137; that is what §8(iv) relies
   on.
5. **Whether any password manager's client enforces monotonicity on server-supplied revision fields**
   (1Password item versions, Bitwarden `revisionDate`, Keeper record revisions, Proton Pass `revision`). No
   vendor documents client-side enforcement, and rollback resistance would be a headline claim if they had
   it — so assume none do, but it is an assumption.
6. **WhatsApp's exact HSM attempt limit.** The whitepaper says only "a certain number" and "permanently
   inaccessible". Secondary sources describe 5 attempts then a *temporary* wait, which is a different,
   softer control. The qualitative behaviour (finite, then permanent) is confirmed; the number is not.
7. **Whether Mullvad's and Proton's *web* WireGuard config generators produce the private key client-side
   or server-side.** Neither vendor says. Do not extend their app-path guarantees to the dashboard path.
8. **Whether Proton Pass signs item *contents*** as well as keys. The blog only ever says keys are signed.
9. **Bitwarden's server-side iteration count.** Its whitepaper says 600,000; its KDF page says the hash
   totals 700,000 including "additional iterations beyond what is configured". Two primary docs contradict
   each other.
10. **WebAuthn PRF as an alternative key source.** A passkey synced through iCloud Keychain can in principle
    derive a stable secret gated by the platform authenticator's own rate limiting. Reported working in
    Safari; I found no evidence that native `AuthenticationServices` exposes the `prf` extension at all.
    Low confidence, mostly secondary sources — verify before designing around it.
11. **KeePassXC's default KDF for new databases** (Argon2**d**, and its cost parameters). The official user
    guide never states the default; this is from the project's GitHub. Relevant only as a cautionary note:
    the default is the side-channel-vulnerable variant, chosen for KeePass2 compatibility.
12. **Signal's SVR2/SVR3 blog posts do not exist** at the URLs commonly cited — both 404. The primary
    sources are the AGPL source (`signalapp/SecureValueRecovery2`, `signalapp/libsignal`) and the OSDI '24
    paper. The 10-attempt limit is confirmed in enclave source, not just in folklore.
13. **Custom-passphrase and recovery-key adoption rates.** No public figure exists for either Chrome's sync
    passphrase or Firefox's account recovery key. Google collects the former permanently
    (`Sync.PassphraseType5`, `expires_after="never"`) and has never published the aggregate. Do not quote a
    percentage; the argument in §9 rests on what the vendors *built and wrote*, not on take-up numbers.
14. **The status of Chrome's unauthenticated-IV bug.** `issues.chromium.org/issues/40078517` is sign-in
    gated; the title is from search metadata and the body was not read. The *code* is primary and current:
    `kSyncNigoriAuthenticateIV` is `FEATURE_DISABLED_BY_DEFAULT` on `main`.
15. **The launch date of Google Password Manager on-device encryption.** The help page is undated, the
    earliest Wayback capture is 2022-05-05, and the client plumbing (`TRUSTED_VAULT_PASSPHRASE`,
    `securebox.h`) already existed at M88 in Dec 2020. "During 2022" is consistent but not confirmed.
16. **Whether a Chrome custom passphrase breaks "Send to your devices", Assistant, price tracking or
    Autofill Assistant.** Widely claimed; no help-page statement and no `IsEncryptEverythingEnabled()` gate
    found. The breakages listed in §2 are the ones with a primary source behind each.

**Two corrections to figures commonly cited, worth recording so they are not reintroduced:**
Firefox's account recovery key is **32** base32 characters, not 24 or 28. And Chrome's custom-passphrase
scrypt salt is **32 random bytes per passphrase**, not a constant — the notorious constant salt belongs to
the *legacy* PBKDF2-HMAC-SHA1 path (and even there, the famous `"saltsalt"` is one level of indirection
away: it salted the precomputation that produced the live hardcoded 16-byte constant).

---

## 11. Sources

**Apple — Platform Security**
- Secure keychain syncing — https://support.apple.com/guide/security/secure-keychain-syncing-sec0a319b35f/web
- Secure iCloud Keychain recovery — https://support.apple.com/guide/security/secure-icloud-keychain-recovery-secdeb202947/web
- Escrow security for iCloud Keychain — https://support.apple.com/guide/security/escrow-security-for-icloud-keychain-sec3e341e75d/web
- Keychain data protection — https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web
- iCloud encryption — https://support.apple.com/guide/security/icloud-encryption-sec3cac31735/web
- Advanced Data Protection for iCloud — https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f/web
- Volume encryption with FileVault — https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web
- Managing FileVault in macOS — https://support.apple.com/guide/security/managing-filevault-sec8447f5049/web
- iCloud data security overview (the authoritative category table) — https://support.apple.com/en-us/102651

**Apple — Developer**
- `kSecAttrSynchronizable` — https://developer.apple.com/documentation/security/ksecattrsynchronizable
- Restricting keychain item accessibility — https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility
- TN3137: On Mac keychain APIs and implementations — https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
- Encrypting user data (CloudKit) — https://developer.apple.com/documentation/cloudkit/encrypting-user-data
- `CKRecord.encryptedValues` — https://developer.apple.com/documentation/cloudkit/ckrecord/encryptedvalues-swift.property
- `RecordSavePolicy.ifServerRecordUnchanged` — https://developer.apple.com/documentation/cloudkit/ckmodifyrecordsoperation/recordsavepolicy/ifserverrecordunchanged
- `NSUbiquitousKeyValueStore` — https://developer.apple.com/documentation/foundation/nsubiquitouskeyvaluestore
- WWDC21 10086, What's new in CloudKit — https://developer.apple.com/videos/play/wwdc2021/10086/
- Developer ID (provisioning-profile evaluation and expiry) — https://developer.apple.com/support/developer-id/
- Also: `<Security/SecItem.h>` in the SDK (fuller than the web docs), and `man diskutil` (`apfs listCryptoUsers`)

**Password managers**
- 1Password Security Design white paper — https://1passwordstatic.com/files/security/1password-white-paper.pdf
- Bitwarden Security Whitepaper — https://bitwarden.com/help/bitwarden-security-white-paper/
- Bitwarden KDF algorithms — https://bitwarden.com/help/kdf-algorithms/
- Bitwarden emergency access — https://bitwarden.com/help/emergency-access/ · account recovery — https://bitwarden.com/help/account-recovery/
- KeePass KDBX 4 changes — https://keepass.info/help/kb/kdbx4.html · KDBX format — https://keepass.info/help/kb/kdbx.html · Security — https://keepass.info/help/base/security.html
- KeePassXC User Guide (merge, credentials) — https://keepassxc.org/docs/KeePassXC_UserGuide.html
- Keeper encryption model — https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model · device approvals — https://docs.keeper.io/sso-connect-cloud/device-approvals
- Proton Pass security model — https://proton.me/blog/proton-pass-security-model · recovery — https://proton.me/support/recover-encrypted-messages-files

**Rate-limited escrow / integrity**
- Signal, Secure Value Recovery — https://signal.org/blog/secure-value-recovery/ · SVR3 paper — https://eprint.iacr.org/2024/887 · source — https://github.com/signalapp/SecureValueRecovery2
- Signal Secure Backups (the 64-character key) — https://signal.org/blog/introducing-secure-backups/
- WhatsApp, Security of End-To-End Encrypted Backups — https://www.whatsapp.com/security/WhatsApp_Security_Encrypted_Backups_Whitepaper.pdf
- Google, Android Cloud Key Vault whitepaper — https://developer.android.com/about/versions/pie/security/ckv-whitepaper

**Browser sync — Firefox**
- onepw protocol — https://mozilla.github.io/ecosystem-platform/explanation/onepw-protocol
- Scoped keys — https://mozilla.github.io/ecosystem-platform/explanation/scoped-keys
- Pairing flow architecture — https://mozilla.github.io/ecosystem-platform/explanation/pairing-flow-architecture · channel — https://github.com/mozilla/fxa-pairing-channel
- Sync Storage Format 5 — https://mozilla-services.readthedocs.io/en/latest/sync/storageformat5.html
- Key stretching source (the 650,000-iteration v2 constants) — `packages/fxa-auth-client/lib/crypto.ts` and `lib/salt.ts` in https://github.com/mozilla/fxa
- Recovery keys — `fxa-auth-server/docs/recovery_keys.md` and `packages/fxa-auth-client/lib/recoveryKey.ts` in https://github.com/mozilla/fxa · announcement — https://blog.mozilla.org/services/2018/09/26/account-recovery-keys-in-firefox-accounts/
- **ADR 0005, "Minimizing password entry"** — https://github.com/mozilla/fxa/blob/main/docs/adr/0005-minimize-password-entry.md
- **Bug 1034526** (the refusal to add a Sync-only passphrase, and Ryan Kelly's "contagiously bad") — https://bugzilla.mozilla.org/show_bug.cgi?id=1034526
- Bug 1320222 (key-stretching parameters, 2016→2024) — https://bugzilla.mozilla.org/show_bug.cgi?id=1320222 · Bug 1444866 — https://bugzilla.mozilla.org/show_bug.cgi?id=1444866
- "Private by Design: How we built Firefox Sync" — https://hacks.mozilla.org/2018/11/firefox-sync-privacy/
- Why J-PAKE pairing was abandoned (Brian Warner) — https://www.lothar.com/blog/50-new-sync-protocol/

**Browser sync — Chrome / Google**
- Chromium sync threat model — `components/sync/SECURITY.md`; passphrase constants — `components/sync/base/passphrase_enums.h`, `components/sync/model/crypto/nigori.cc`, `components/sync/protocol/nigori_specifics.proto`; the unauthenticated-IV flag — `components/sync/base/features.cc`; history gating — `components/history/core/browser/sync/history_data_type_controller.cc`; trusted vault — `components/trusted_vault/` (incl. `securebox.h`, `recovery_key_store_connection_impl.cc`). Browse via https://github.com/chromium/chromium (gitiles 404s under plain fetch)
- Google Chrome Help, sync passphrase — https://support.google.com/chrome/answer/165139#passphrase (note: the older `answer/1181035` is dead; historic wording via Wayback)
- Google Password Manager on-device encryption — https://support.google.com/accounts/answer/11350823
- **Google Cloud Key Vault Service whitepaper** (Walfish, 2018) — https://developer.android.com/about/versions/pie/security/ckv-whitepaper
- "Google and Android have your back by protecting your backups" — https://security.googleblog.com/2018/10/google-and-android-have-your-back-by.html
- The 10-attempt constant — `services/core/java/com/android/server/locksettings/recoverablekeystore/KeySyncTask.java` in https://github.com/aosp-mirror/platform_frameworks_base
- `RecoveryController` API — https://developer.android.com/reference/android/security/keystore/recovery/RecoveryController
- NCC Group, *Android Cloud Backup/Restore* (SECONDARY — commissioned audit) — https://research.nccgroup.com/2018/10/12/public-report-android-cloud-backup-restore/
- SafetyPin (OSDI '20) — https://www.usenix.org/conference/osdi20/presentation/dauterman-safetypin
- OPAQUE — https://eprint.iacr.org/2018/163.pdf · RFC 9807 — https://datatracker.ietf.org/doc/rfc9807/
- SUNDR (fork consistency) — https://www.usenix.org/legacy/event/osdi04/tech/full_papers/li_j/li_j.pdf
- TUF specification (rollback protection) — https://theupdateframework.github.io/specification/latest/ · https://theupdateframework.io/docs/security/

**VPN clients**
- Tailscale: how it works — https://tailscale.com/blog/how-tailscale-works · identity — https://tailscale.com/docs/concepts/tailscale-identity · node keys — https://tailscale.com/kb/1010/node-keys · Tailnet Lock — https://tailscale.com/kb/1226/tailnet-lock · **Tailnet Lock white paper** — https://tailscale.com/docs/concepts/tailnet-lock-whitepaper
- WireGuard for Apple platforms, `Sources/Shared/Keychain.swift` — https://github.com/WireGuard/wireguard-apple
- Mullvad account recovery — https://mullvad.net/en/account/recover/cash · daemon source — https://github.com/mullvad/mullvadvpn-app
- Proton VPN WireGuard configurations — https://protonvpn.com/support/wireguard-configurations · `go-vpn-lib` — https://github.com/ProtonVPN/go-vpn-lib
- Viscosity: exporting and distributing connections — https://www.sparklabs.com/support/kb/article/exporting-and-distributing-connections/ · backing up settings — https://www.sparklabs.com/support/kb/article/backing-up-viscosity-s-settings/ · keychain — https://www.sparklabs.com/support/kb/article/managing-and-deleting-saved-credentials/
- Tunnelblick: documents index — https://tunnelblick.net/documents.html · package format — https://tunnelblick.net/cPkgs.html · file locations / shadow copies — https://tunnelblick.net/cFileLocations.html · exporting and importing setups — https://tunnelblick.net/cExportingAndImportingTunnelblickSetups.html · updatable configurations — https://tunnelblick.net/cNewUpdatableConfigurations.html
- Passepartout — https://passepartoutvpn.app/ · source — https://github.com/passepartoutvpn/passepartout-apple

**In-tree references**
`Docs/CredentialSources.md` · `Docs/PolicyRouting.md` · `Docs/PKCS11.md` · `Docs/MDM.md` · `ONTOLOGY.md` ·
`Shared/KeychainCredentialStore.swift` · `Shared/SSHHostKeyDecision.swift` ·
`SimpleVPN/Credentials/CredentialProvider.swift` · `SimpleVPN/Import/CertificateImport.swift` ·
`SimpleVPN/Import/ProfileImport.swift` · `SimpleVPN/ControlPlane/VPNController+CRUD.swift` ·
`SimpleVPN/ControlPlane/FeatureMaturity.swift` · `SimpleVPN/Diagnostics/SecretScrubber.swift` ·
`PacketTunnel/PacketTunnelProvider.swift`
