# SimpleVPN 0.6

SimpleVPN 0.6 adds a dedicated DNS tab, live routing diagrams, and advanced query-name routing while keeping the normal configuration path simple.

- DNS settings now have their own tab. Custom DNS routing stays in a collapsible advanced group, with separate query rules, server filters, search list overrides, and native resolver scopes.
- Routing-related tabs show live railroad diagrams with zoom and pan, including unsaved configuration changes.
- Advanced DNS query rules support Exact, Suffix, and Glob matching, ordered first-match selection, explicit resolver lists, and a draft hostname tester. Query routing is opt-in and disabled by default.
- DNS arbitration handles case and trailing-dot differences consistently, and custom list fields preserve comma entry. Invalid custom settings remain visible for correction instead of being partially saved.
- Query-only edits avoid reapplying unrelated routes, native DNS settings, or system proxy settings. External DNS proxy disablement requires an explicit Reapply.
- Includes network-state and secret-storage fixes, shared WireGuard routing improvements, Teleport support, updated engines and dependencies, native VPN setup improvements, and a staged DMG installer with version-aware replacement and cleanup.
- The installer explicitly releases its installation lock before opening a new instance of the exact installed app in Applications, then quits and removes its temporary helper. This fixes an upgrade handoff where a retained async reference could cause the newly installed app to exit immediately.

Requires macOS 27.2 or later on Apple Silicon.

The optional DNS query router uses a macOS DNS proxy system extension. Enabling it replaces any DNS proxy configured by another app. It handles standard DNS queries; application-managed DoH/DoT and DNS zone transfers are outside its scope. Live OS-level query capture has not yet been verified with the updated installed extension; parser, matcher, transport, forwarding-policy, and configuration behavior are covered by automated tests.

The initial build 458 was withdrawn and replaced by build 460 with the installer handoff fix. Existing 0.6 users receive build 460 through the updater.

Validation: the DNS and routing work passed 2,920 unit tests and four native UI checks, including DNS and custom routing accessibility audits. The installer fix passed all 14 installer regression tests and a live DMG upgrade from build 458: the exact installed build 460 opened automatically, the helper exited, and the source image was ejected and cleaned up. About reported 0.6 (460), and macOS reports extension 0.6/460 activated and enabled. Both replacement-build notarization logs report acceptance with no issues, and the Sparkle update signature verifies.

[Full changelog](https://github.com/bitwisecook/SimpleVPN/compare/v0.5...v0.6)
