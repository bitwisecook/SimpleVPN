// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderServerListDiff.swift
//  WHAT A LIST UPDATE IS ALLOWED TO DO ON ITS OWN, and what has to be confirmed
//  first. A server list decides where the user's traffic goes, so this is the file
//  that decides whether the feature is safe.
//
//  THE THREAT IS NOT SECRECY. Docs/SecretsAndSync.md §4 settled this reasoning for
//  synced configuration and every line of it applies: a server list is not very
//  secret and is entirely security-DETERMINING. The attacks are SUBSTITUTION (this
//  server is now at my address, with my key) and ROLLBACK (here is last month's
//  list, which happens to be the one I can beat). Neither is stopped by encryption
//  and neither is stopped by freshness.
//
//  FOUR RULES, and the third is the one most designs miss:
//
//   1. A NEW server is added quietly, and STAYS MARKED until it is used. Cheap, and
//      it is the only defence WireGuard has against "the attacker added one very
//      fast-looking server in your country".
//   2. A CHANGED address or — far worse — a changed PEER KEY on a server the user
//      already has is held PENDING and shown as a diff, exactly as a changed CA is.
//      For WireGuard this is not a nicety: there is no certificate, the peer public
//      key IS the authentication, and it arrives in the same payload as the address
//      it authenticates. Swap both together and every packet goes to the attacker
//      with no error at all.
//   3. A REMOVED server is KEPT AND MARKED RETIRED, never deleted. **Removal is an
//      attack too.** Somebody who can shrink your list to the one server they control
//      has chosen your exit as surely as somebody who substitutes an address — and a
//      deletion is the one change that leaves no evidence behind. So nothing is ever
//      deleted by an update, and a list that lost more than a third of its servers is
//      held pending whether or not the user had selected any of them.
//   4. NOTHING is applied if the payload did not parse, or parsed to nothing. A stale
//      list that works beats a fresh list that might not be the provider's.
//
//  WHAT THIS DOES NOT SOLVE, said plainly rather than hidden. None of these four
//  providers publishes a signature over its list (Docs/ServiceBundles.md §3 rule 6 —
//  and that is the highest-value open question in the design), so there is no
//  monotonic counter and a replayed older-but-genuine list is indistinguishable from
//  a current one. What blunts it is rules 2 and 3: the only shapes of rollback that
//  hurt are the ones that remove servers or revert keys, and both are held pending.
//
//  PURE. Nothing here reaches the network, the keychain or a view.
//

import Foundation

// MARK: - What changed

/// One server's fate in an update.
nonisolated enum ProviderServerChange: Sendable, Equatable {
    /// Not in the stored list. Applied, and marked new until used.
    case added
    /// In both, unchanged in every field this app acts on.
    case unchanged
    /// In both, and something the connection depends on moved. Held pending.
    case moved(ProviderServerListDiff.Movement)
    /// In the stored list and not in the new one. Kept, marked retired.
    case retired
}

// MARK: - The diff

/// The result of comparing a freshly parsed list against the stored one.
///
/// A value, not an action: producing this never changes anything. `applied` is what
/// an update may write without asking, `pending` is what it may not, and the caller
/// cannot get the second without going through a confirmation — which is the whole
/// reason the two are separate fields rather than one list with a flag.
nonisolated struct ProviderServerListDiff: Sendable, Equatable {

    /// Which security-determining field moved. Named individually because the
    /// confirmation sentence has to say WHICH — "this server changed" is the kind of
    /// message that gets clicked through, and a changed peer key deserves different
    /// words from a changed IPv6 address.
    nonisolated struct Movement: Sendable, Equatable, OptionSet {
        let rawValue: Int
        init(rawValue: Int) { self.rawValue = rawValue }
        static let address = Movement(rawValue: 1 << 0)
        /// The one that can hand an attacker the whole tunnel silently.
        static let peerKey = Movement(rawValue: 1 << 1)
    }

    /// Servers in the new list that were not in the stored one.
    let added: [ProviderServer]
    /// Servers whose address or peer key moved, as (stored, incoming, what moved).
    let moved: [(before: ProviderServer, after: ProviderServer, movement: Movement)]
    /// Servers the stored list has that the new one does not. Kept, never deleted.
    let retired: [ProviderServer]
    /// Servers present and identical in both.
    let unchangedCount: Int

    /// Does this update need the user to look at it before any of it applies?
    ///
    /// Deliberately ALL-OR-NOTHING rather than per-server. Applying the safe half of
    /// an update and holding the rest would let an attacker land the additions they
    /// wanted while the confirmation sits unanswered, and it would make the
    /// confirmation itself read as optional.
    var needsConfirmation: Bool { !moved.isEmpty || lostTooMany }

    /// Rule 3's threshold: more than a third of the stored servers gone.
    ///
    /// A third rather than "any at all" because providers really do retire hardware,
    /// and a confirmation raised on every routine update is a confirmation nobody
    /// reads. A third rather than "nearly all" because by the time a list is down to
    /// a handful the choice has already been made for the user.
    var lostTooMany: Bool {
        let storedCount = unchangedCount + moved.count + retired.count
        guard storedCount > 0 else { return false }
        return retired.count * 3 > storedCount
    }

    /// Nothing moved and nothing vanished: the ordinary case, applied silently.
    var isRoutine: Bool { !needsConfirmation }

    static func == (a: ProviderServerListDiff, b: ProviderServerListDiff) -> Bool {
        a.added == b.added && a.retired == b.retired && a.unchangedCount == b.unchangedCount
            && a.moved.count == b.moved.count
            && zip(a.moved, b.moved).allSatisfy {
                $0.before == $1.before && $0.after == $1.after && $0.movement == $1.movement
            }
    }

    // MARK: Producing one

    /// Compare an incoming list against what is stored.
    ///
    /// `stored` empty ⇒ everything is `added` and nothing is pending: a first fetch
    /// has nothing to be substituted for. That is not a hole — the user is choosing
    /// to trust this provider's list at that moment, and asking them to confirm 567
    /// servers they have never seen would be a ritual, not a check.
    static func between(stored: ProviderServerList?,
                        incoming: ProviderServerList) -> ProviderServerListDiff {
        let storedByHost = Dictionary(
            (stored?.servers ?? []).map { ($0.hostname.value, $0) },
            uniquingKeysWith: { first, _ in first })
        var added: [ProviderServer] = []
        var moved: [(before: ProviderServer, after: ProviderServer, movement: Movement)] = []
        var unchanged = 0
        var seen: Set<String> = []
        for server in incoming.servers {
            seen.insert(server.hostname.value)
            guard let before = storedByHost[server.hostname.value] else {
                added.append(server)
                continue
            }
            let movement = self.movement(from: before, to: server)
            if movement.isEmpty { unchanged += 1 } else {
                moved.append((before: before, after: server, movement: movement))
            }
        }
        let retired = (stored?.servers ?? []).filter { !seen.contains($0.hostname.value) }
        return ProviderServerListDiff(added: added, moved: moved,
                                      retired: retired, unchangedCount: unchanged)
    }

    /// WHICH FIELDS COUNT AS A MOVE, and the omissions are as deliberate as the
    /// inclusions.
    ///
    /// Counted: the IPv4 address, the IPv6 address, the peer key. These three are
    /// what a connection is actually made of.
    ///
    /// NOT counted: the city name, the country code, `active`. A provider recording
    /// that a server moved from "Tirana" to "Tirana, Albania", or taking one out of
    /// service for the afternoon, is not a security event, and raising a
    /// confirmation for it is how a confirmation stops being read. Over-confirming
    /// is its own failure, exactly as over-redaction is in the export path.
    static func movement(from before: ProviderServer, to after: ProviderServer) -> Movement {
        var out: Movement = []
        if before.ipv4 != after.ipv4 || before.ipv6 != after.ipv6 { out.insert(.address) }
        if before.peerKey != after.peerKey { out.insert(.peerKey) }
        return out
    }
}

// MARK: - Applying one

nonisolated enum ProviderServerListUpdate {

    /// The list to store, given a diff the caller is entitled to apply.
    ///
    /// `confirmed` is not a courtesy flag. When the diff needs confirmation and it
    /// has not been given, this returns the STORED list unchanged — so a caller that
    /// forgets to ask cannot accidentally apply a substitution, and the failure mode
    /// of forgetting is "nothing happened", which is the safe one.
    ///
    /// Retired servers are carried into the result with `active: false`, which is how
    /// rule 3 is implemented: the row stays, the Servers table can show it as retired,
    /// and nothing an update does can make a server disappear from under somebody who
    /// had chosen it.
    static func apply(_ diff: ProviderServerListDiff,
                      stored: ProviderServerList?,
                      incoming: ProviderServerList,
                      confirmed: Bool) -> ProviderServerList {
        if diff.needsConfirmation && !confirmed {
            return stored ?? ProviderServerList(providerID: incoming.providerID, servers: [],
                                                dropped: 0, fetchedAt: incoming.fetchedAt)
        }
        let retired = diff.retired.map {
            ProviderServer(hostname: $0.hostname, ipv4: $0.ipv4, ipv6: $0.ipv6,
                           countryCode: $0.countryCode, cityCode: $0.cityCode,
                           cityName: $0.cityName, peerKey: $0.peerKey, active: false)
        }
        return ProviderServerList(providerID: incoming.providerID,
                                  servers: incoming.servers + retired,
                                  dropped: incoming.dropped,
                                  fetchedAt: incoming.fetchedAt)
    }
}
