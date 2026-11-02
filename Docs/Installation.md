# Launch and installation

Opening a distributed copy outside Applications is an installation request.
`SimpleVPNLauncher` runs before SwiftUI initializes VPN stores, tunnel managers,
the control socket or Sparkle. Debug builds outside read-only volumes bypass
installation so development and tests remain usable.

The behavior is informed by [HankLedger's DMGInstaller](https://github.com/bitwisecook/HankLedger/blob/630ea74d1c50bd018ab073a2b719a94c0ef177a1/HankLedger/HankLedger/DMGInstaller.swift).
Its source/helper/finisher chain is replaced with one staged installer process.

1. Match the source volume against `hdiutil info -plist`. Only an exact mounted
   DMG match supplies an image to eject or trash. A translocated launch must
   match one signed bundle on a mounted image; ambiguous locations fail with
   Finder instructions. No private translocation APIs or quarantine removal.
2. Verify the source and embedded helper against Apple's signing anchor, our
   Team ID and the expected bundle identifiers. Copy the helper to a fresh
   user-private temporary directory, verify it again, and write its request
   beside it. The signed helper bundle is never modified.
3. Open the helper through Launch Services without activation. `LSUIElement`
   prevents an initial Dock tile. The original process quits without starting a
   VPN session. The helper checks its PID and launch date and waits for its
   exit, asynchronously and with a deadline.
4. One per-user `flock` lease admits one helper. Additional staged helpers
   activate it and exit invisibly, removing their temporary directories. The
   lease file remains in place; unlinking it would allow independent lock owners.
   Only the admitted helper becomes a regular app, after the launcher exits.
5. Inspect `/Applications` and `~/Applications`, including renamed bundles.
   Multiple copies get a native destination pop-up. Prefer an existing location;
   fresh installs use system Applications when writable, otherwise the user's
   Applications folder. Never overwrite an unrelated app. Unreadable version
   information produces an error rather than an assumed upgrade.
6. Compare numeric versions, then builds. Offer Install, Upgrade, Reinstall or
   an explicit Downgrade warning, plus Quit. Show versions, the full destination
   and a source-to-Trash checkbox. Return defaults to Quit for downgrades; Escape
   quits. AppKit supplies native keyboard/accessibility behavior. Cmd-Q works.
7. Request normal termination of a running destination after confirmation.
   Respect its VPN disconnect/cancel flow; never force-quit it. Show a
   cancellable waiting window. Cmd-Q is deferred during actual replacement.
8. Copy beside the destination, verify the staged candidate and its version,
   recheck the destination snapshot and running process, and retain the previous
   bundle until final verification succeeds. Roll back on failure. Trash the
   old bundle only after success. If Trash or rollback fails, preserve the
   recovery directory and show its path.
9. Eject the exact source image without force. Only after successful ejection,
   trash the downloaded image if selected. A writable original app is similarly
   trashed after installation. Cleanup failures produce a successful-install
   notice with manual instructions.
10. Remove the helper's Dock tile, explicitly close its lease (independently of
    retained references in async frames), and launch a new instance of the installed
    app by explicit URL. Await Launch Services before quitting and deleting the
    helper's own temporary directory in `applicationWillTerminate`. No second
    finisher, shell or delayed delete.
    Subsequent helpers remove abandoned private sessions older than a day,
    excluding sessions with running helpers.

The helper links only system frameworks and has no sandbox, VPN, keychain,
provisioning-profile or privileged-helper entitlements. It does not elevate
permissions. An existing installation this account cannot replace reports the
filesystem error; Finder/admin-assisted replacement remains available.
XcodeGen embeds the signed helper in `Contents/Helpers` before sealing the main
app. Sparkle retains responsibility for in-app updates.

## Verification and release acceptance

`bash Tools/test-installer.sh` runs filesystem/decision tests without launching
the VPN app, and checks that the installer icon matches the main app plus its
bubble. The complete app and helper must build with warnings treated as errors.
The icon must compile with Xcode's asset compiler: `ictool` previews alone do not
check its four-visible-group limit.

Run this matrix on a signed, notarized DMG in an unlocked test Mac before shipping:

- Fresh install, newer-build upgrade, equal-build reinstall, older-build warning
  with Quit as default. Test both Applications folders, renamed copies and two
  installed copies. Preserve settings and unrelated apps.
- Repeated double-clicks while prompting, waiting and copying: one visible
  installer Dock tile, no source VPN window, one active helper lease.
- Accept/cancel the installed app's disconnect confirmation. Cancel the helper's
  wait and try Cmd-Q before and during replacement.
- Failed copies, a destination changed during the prompt, an unwritable
  destination, and an unrelated app occupying `SimpleVPN.app`.
- Success opens the exact installed URL, ejects the image, trashes the selected
  source, preserves the old app in Trash, and leaves no staged helper process or
  directory. Repeat with cleanup disabled and a busy image that cannot eject.
- Force-stop an idle helper in the test environment, then confirm the next run
  can acquire its lease. Abandoned sessions are swept after a day; destination
  recovery bundles are deliberately preserved.
- Keyboard-only and VoiceOver operation of prompts, the destination pop-up,
  source checkbox and waiting window; dark/tinted Dock icons.

These runtime checks remain a release gate. Unit tests cannot establish
Gatekeeper, live Dock transitions, VPN shutdown, Finder Trash permissions or
behavior under machine shutdown.
