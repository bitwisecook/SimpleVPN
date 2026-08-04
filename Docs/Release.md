# Releasing SimpleVPN

This is the runbook for cutting a signed, notarized, drag-install DMG release
via GitHub Actions (`.github/workflows/release.yml`).

Two build paths exist and serve different purposes:

- **`Tools/build-notarize-install.sh`** — the local live-test path. Builds,
  notarizes, staples, and installs straight to `/Applications` so you can
  confirm the system extension activates on this Mac. Not used by CI.
- **`Tools/build-release-dmg.sh`** — the distribution path. Builds, notarizes
  + staples the `.app`, packages it into a DMG, notarizes + staples the DMG
  too, and stops (does not install anywhere). This is what CI runs, and it is
  written to behave identically whether run by hand or by the workflow.

**This build is Apple Silicon (arm64) only** — `ARCHS: arm64` is set
project-wide because the vendored engine xcframeworks are arm64-only slices.
The release asset is named `SimpleVPN-<version>-arm64.dmg` on purpose so this
is never ambiguous.

## Required GitHub secrets

Set these under **Settings > Secrets and variables > Actions > Repository
secrets**. Nothing here is optional — `release.yml` fails fast with a clear
message if any is missing.

| Secret | What it is |
|---|---|
| `DEVID_APP_CERT_P12_BASE64` | base64 of the exported `Developer ID Application: James Deucker (QVUFB5676H)` certificate + private key, as a `.p12` |
| `DEVID_APP_CERT_P12_PASSWORD` | the password the `.p12` was exported with |
| `CI_KEYCHAIN_PASSWORD` | any strong random string — password for the throwaway keychain `import-signing.sh` creates fresh on every run and destroys at the end |
| `PROFILE_APP_BASE64` | base64 of the `SimpleVPN App DirectDist.provisionprofile` |
| `PROFILE_TUNNEL_BASE64` | base64 of the `SimpleVPN Tunnel DirectDist.provisionprofile` |
| `ASC_API_KEY_P8_BASE64` | base64 of the App Store Connect API `.p8` private key used for notarization |
| `ASC_API_KEY_ID` | that key's Key ID |
| `ASC_API_ISSUER_ID` | that key's Issuer ID |
| `SPARKLE_ED_PRIVATE_KEY` | the Sparkle EdDSA private key, fed to `sign_update --ed-key-file -` to sign the DMG for the appcast. **This one does NOT fail fast** — the appcast step runs after signing and notarization, so a missing value wastes a whole release run under `set -euo pipefail`. |

`gh release create` needs no secret of its own — it authenticates with the
workflow's built-in `${{ github.token }}`, scoped by the job's
`permissions: contents: write`.

### Producing each secret value

**The Developer ID Application certificate.** This cannot be created via the
App Store Connect API (it 403s) — per `AGENTS.md`, only the account holder can
create it, in Xcode ▸ Settings ▸ Accounts ▸ Manage Certificates. Once it
exists in your login keychain:

```sh
# Export from Keychain Access (or `security export`) as DeveloperIDApplication.p12
# with a password, then:
base64 -i DeveloperIDApplication.p12 | pbcopy
# paste into the DEVID_APP_CERT_P12_BASE64 secret
```

Set `DEVID_APP_CERT_P12_PASSWORD` to whatever password you exported it with.

**Provisioning profiles.** `SimpleVPN App DirectDist` and
`SimpleVPN Tunnel DirectDist` can be created/downloaded via the ASC API or
Xcode's UI (unlike the certificate itself, profiles are scriptable). Download
each `.provisionprofile` / `.mobileprovision` file, then:

```sh
base64 -i "SimpleVPN App DirectDist.provisionprofile" | pbcopy
# paste into PROFILE_APP_BASE64

base64 -i "SimpleVPN Tunnel DirectDist.provisionprofile" | pbcopy
# paste into PROFILE_TUNNEL_BASE64
```

To confirm which profile is which (or debug a "Name mismatch" failure from
`Tools/ci/import-signing.sh`), read a profile's embedded name and expiry
locally:

```sh
security cms -D -i "SimpleVPN App DirectDist.provisionprofile" | plutil -extract Name raw -
security cms -D -i "SimpleVPN App DirectDist.provisionprofile" | plutil -extract ExpirationDate raw -
```

**The App Store Connect API key.** This is the same `.p8` the `asc` CLI and
`~/.asc/credentials.json` use locally for notarization
(`~/.asc/AuthKey_<keyID>.p8`). Find the Key ID and Issuer ID in App Store
Connect ▸ Users and Access ▸ Integrations ▸ Keys, or read them out of
`~/.asc/credentials.json` on a Mac that already has `asc auth login` set up.

```sh
base64 -i AuthKey_XXXXXXXXXX.p8 | pbcopy
# paste into ASC_API_KEY_P8_BASE64; the "XXXXXXXXXX" part is ASC_API_KEY_ID
```

**`CI_KEYCHAIN_PASSWORD`** — just generate a random string, e.g.
`openssl rand -base64 32`. It only ever protects a keychain that exists for
the lifetime of one job run on an ephemeral runner.

## Cutting a release

```sh
git tag -a v0.2.0 -m "0.2.0"
git push origin v0.2.0
```

Pushing a tag matching `v*` triggers `.github/workflows/release.yml`. The
version embedded in the app (`MARKETING_VERSION`) comes from the tag with the
leading `v` stripped; the build number (`CURRENT_PROJECT_VERSION`) is the
**committed `BUILDNUMBER` file at the repo root**, read verbatim by
`release.yml` (`CURRENT_PROJECT_VERSION="$(cat BUILDNUMBER)"`). That is the
same counter `Tools/build-notarize-install.sh` bumps on every local live-test
build, and the sharing is deliberate: a released app reports the same
`v0.3 (114)` the dev loop showed, and the appcast's `sparkle:version` is that
same number, so Sparkle's version comparison lines up with what users see.
`github.run_number` is deliberately NOT used. (`Tools/build-release-dmg.sh`
has a `build/buildnumber.txt` fallback for standalone local runs; CI always
sets `CURRENT_PROJECT_VERSION`, so that path never fires in CI.)

The Sparkle appcast is generated in the same job: it is written to
`build/dist/appcast.xml`, uploaded as an artifact, and served from
`releases/latest/download/appcast.xml`.

Pre-release tags (`v1.2.3-beta.1`, `v1.2.3-rc1`, …) are automatically created
as GitHub prereleases.

## Rehearsing without publishing

Run the workflow manually from the Actions tab (or `gh workflow run release.yml
-f dry_run=true`). This exercises the entire pipeline — engine build/cache,
signing import, build, both notarization passes, DMG packaging, verification
— and uploads the DMG as a workflow artifact, but skips `gh release create` so
nothing public is published. Useful before a real tag, or to warm the engines
cache ahead of a release (see below).

## Keeping the engines cache warm

`Tools/build-*-xcframework.sh` compile three third-party C/C++ libraries from
source and are the slow part of a cold build (20-45 minutes). GitHub evicts an
`actions/cache` entry unused for 7 days; since tags are typically cut less
often than that, `.github/workflows/engines-cache.yml` runs weekly (Mondays,
04:17 UTC) purely to touch that cache entry so it stays warm. It can also be
triggered by hand (`workflow_dispatch`) right before cutting a release. A
release build never *depends* on the cache being warm — the `engines` job in
`release.yml` is a complete cold-build path on its own — but a cache hit is
the difference between a ~10-25 minute release build and a ~1 hour one.

## When notarization is rejected

`Tools/lib/notary.sh`'s `notary_submit` prints the full `notarytool submit
--wait` output, and if the status isn't `Accepted`, automatically fetches and
prints `xcrun notarytool log <submission-id>` before failing the step — so the
actual rejection reason (an unsigned nested binary, a missing hardened-runtime
flag, etc.) is right there in the workflow log, not something you have to go
fetch by hand afterward.

There is deliberately no automatic retry around a notary *submission* itself
(as opposed to the codesign `--timestamp` retry, which does retry — see
`build_once` in `Tools/build-release-dmg.sh`): retrying a submission blindly
risks two submissions racing or double-charging Apple's build-info logging.
If Apple's notary service is transiently down or slow, just re-run the failed
job from the Actions tab; the DMG artifact is uploaded on failure too, so nothing
already built is lost.

## What CI cannot validate

A green `release.yml` run proves the DMG is correctly signed, notarized, and
Gatekeeper-passing. It does **not** prove the system extension activates —
that requires a real Mac: install the DMG, launch the app from
`/Applications`, and approve the extension in **System Settings ▸ General ▸
Login Items & Extensions**. Every release still needs that manual smoke test
(see `AGENTS.md`'s local runbook) before being announced as good; CI is not a
substitute for it.

## Provisioning profile expiry

Both `SimpleVPN App DirectDist` and `SimpleVPN Tunnel DirectDist` expire
annually. `Tools/ci/import-signing.sh` warns in the job log if either profile
is within 30 days of expiring, but does **not** renew them. Profiles can be
regenerated via the ASC API; the Developer ID Application **certificate**
cannot (403 — must be done by the account holder in Xcode). If the
certificate itself has expired, CI is blocked until that manual step happens
and the `DEVID_APP_CERT_P12_BASE64` / `DEVID_APP_CERT_P12_PASSWORD` secrets
are re-exported and updated.

## Known risks (read before relying on this pipeline)

- **Runner SDK availability.** The `engines` and `release` jobs both run on
  `runs-on: macos-26` and hard-fail with an explicit message if
  `xcodebuild -showsdks` lacks a macOS 26 SDK. Whether GitHub's hosted image
  actually ships one could not be confirmed until the workflow is actually
  run — GitHub-hosted images have historically lagged new Xcode releases. If
  this check fails, the fallback is a self-hosted runner on a Mac that
  already has the right Xcode.
- **The `OPENSSL_PIN` drift guard.** All three engine scripts hard-fail if
  Homebrew's `openssl@3` isn't exactly the pinned version. On a cache miss,
  CI runs `Tools/ci/install-pinned-openssl.sh` to force that version via a
  local Homebrew tap — a workaround, not a first-class Homebrew feature, and
  unverified beyond this repo's own reasoning until it's actually exercised
  by a real cache-miss CI run. See that script's header comment for the
  honest fallback if it proves fragile.
- **Cache eviction is the default case, not the edge case.** Tags are cut far
  less often than the 7-day cache eviction window, so `engines-cache.yml`
  mitigates but does not eliminate the "next release pays for a cold engine
  build" scenario.
- **Secrets exposure surface.** The `release` job decodes a Developer ID
  private key onto the runner's disk for the job's duration. Keep the
  workflow's trigger tag-only — never add a `pull_request` trigger to
  `release.yml`.
