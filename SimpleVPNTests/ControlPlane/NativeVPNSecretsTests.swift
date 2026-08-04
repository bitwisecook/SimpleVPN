// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNSecretsTests.swift
//  The native (IKEv2 / IPsec) editor used to write a secret only when the field
//  was non-empty, with no else — so emptying a password left the old one in the
//  keychain AND in use at the next Connect: a password the user believed they
//  had removed still signed them in. The rule is now a plan, and this pins it.
//

import Foundation
import Testing
@testable import SimpleVPN

struct NativeVPNSecretsTests {

    @Test func clearingASecretDeletesItInsteadOfLeavingTheOldOne() {
        // IKEv2: emptying the password/PSK field removes the stored secret.
        #expect(NativeVPNSecrets.plan(kind: .ikev2, secret: "", sharedSecret: "")
                == .init(base: .delete, groupPSK: .delete))
        #expect(NativeVPNSecrets.plan(kind: .ikev2, secret: "pw", sharedSecret: "")
                == .init(base: .write("pw"), groupPSK: .delete))
    }

    /// IPsec carries two independent secrets: the group PSK and the OPTIONAL
    /// XAuth password. Clearing either must not disturb — or preserve — the other.
    @Test func ipsecTracksItsTwoSecretsIndependently() {
        #expect(NativeVPNSecrets.plan(kind: .ipsec, secret: "xauth", sharedSecret: "psk")
                == .init(base: .write("xauth"), groupPSK: .write("psk")))
        #expect(NativeVPNSecrets.plan(kind: .ipsec, secret: "", sharedSecret: "psk")
                == .init(base: .delete, groupPSK: .write("psk")))
        #expect(NativeVPNSecrets.plan(kind: .ipsec, secret: "xauth", sharedSecret: "")
                == .init(base: .write("xauth"), groupPSK: .delete))
    }

    /// Only IPsec has a group PSK — switching a VPN to another kind must not
    /// leave its group secret behind in the keychain.
    @Test func onlyIPsecKeepsAGroupPSK() {
        for kind in [VPNKind.ikev2, .l2tp] {
            #expect(NativeVPNSecrets.plan(kind: kind, secret: "s", sharedSecret: "psk").groupPSK == .delete,
                    "\(kind) must not retain a group PSK")
        }
    }

    /// The row ids are a storage contract (the migration in NativeVPNView and
    /// the cleanup in NativeVPNManager.remove(_:) both key on them).
    @Test func rowIdsAreStable() {
        #expect(NativeVPNSecrets.baseProfile("abc") == "native.abc")
        #expect(NativeVPNSecrets.groupPSKProfile("abc") == "native.abc.secret")
    }
}

// MARK: - Field validation
//
// Save and Connect only ever checked `server.isEmpty`, so a typo'd address
// reached NEVPNManager and came back minutes later as an opaque IKE timeout —
// and `ikeLifetimeMinutes` had no control anywhere, so an imported value could
// neither be seen nor corrected.

struct NativeVPNConfigValidationTests {

    @Test func aRealServerAddressIsAccepted() {
        for good in ["vpn.example.com", "vpn", "192.0.2.10", "2001:db8::1",
                     "vpn-1.eu.example.co.uk"] {
            #expect(NativeVPNConfig.serverProblem(good) == nil, "\(good) should be accepted")
        }
        // Whitespace from a paste is not the user's mistake.
        #expect(NativeVPNConfig.serverProblem("  vpn.example.com \n") == nil)
    }

    @Test func aBadServerAddressIsRefusedInsteadOfTimingOut() {
        for bad in ["", "   ", "https://vpn.example.com", "vpn.example.com/path",
                    "vpn.example.com:4500", "user@vpn.example.com",
                    "vpn..example.com", ".example.com", "example.com.",
                    "vpn example com", "vpn_example.com"] {
            #expect(NativeVPNConfig.serverProblem(bad) != nil, "\(bad) should be rejected")
        }
    }

    /// Apple's accepted `lifetimeMinutes` window. Outside it, saveToPreferences
    /// refuses the whole configuration as "invalid" with nothing naming the field.
    @Test func lifetimeRangeIsApplesOwn() {
        #expect(NativeVPNConfig.ikeLifetimeRange == 10...1440)
        #expect(!NativeVPNConfig.ikeLifetimeRange.contains(0))
        #expect(!NativeVPNConfig.ikeLifetimeRange.contains(9))
        #expect(NativeVPNConfig.ikeLifetimeRange.contains(10))
        #expect(NativeVPNConfig.ikeLifetimeRange.contains(60))    // the OS default for the IKE SA
        #expect(NativeVPNConfig.ikeLifetimeRange.contains(30))    // …and for the child SA
        #expect(NativeVPNConfig.ikeLifetimeRange.contains(1440))
        #expect(!NativeVPNConfig.ikeLifetimeRange.contains(1441))
    }

    @Test func normalizedTrimsAndDropsAnOutOfRangeLifetime() {
        var c = NativeVPNConfig()
        c.name = "  Work  "
        c.server = " vpn.example.com\n"
        c.username = " alex "
        c.remoteID = " vpn.example.com "
        c.groupOrRealm = " staff "
        c.ikeLifetimeMinutes = 5
        let n = c.normalized()
        #expect(n.name == "Work")
        #expect(n.server == "vpn.example.com")
        #expect(n.username == "alex")
        #expect(n.remoteID == "vpn.example.com")
        #expect(n.groupOrRealm == "staff")
        #expect(n.ikeLifetimeMinutes == nil)                     // back to the OS default
        c.ikeLifetimeMinutes = 480
        #expect(c.normalized().ikeLifetimeMinutes == 480)
        c.ikeLifetimeMinutes = 100_000
        #expect(c.normalized().ikeLifetimeMinutes == nil)
    }

    /// The picker's first option is "" and must mean "leave macOS's own choice
    /// alone" — it used to be applied as `.medium`, so the option named a state
    /// it didn't produce.
    @Test func deadPeerDetectionDefaultIsAnEmptyString() {
        #expect(NativeVPNConfig().deadPeerDetection.isEmpty)
    }
}
