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
