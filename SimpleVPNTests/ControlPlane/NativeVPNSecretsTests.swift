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
        // IKEv2: emptying the password/PSK field removes the stored secret. The
        // OTHER kinds' rows are `.leave` — IKEv2 has no field for them, so
        // "empty" there means "not loaded", not "the user removed it".
        #expect(NativeVPNSecrets.plan(kind: .ikev2, secret: "", sharedSecret: "")
                == .init(base: .delete, groupPSK: .leave, pppPassword: .leave))
        #expect(NativeVPNSecrets.plan(kind: .ikev2, secret: "pw", sharedSecret: "")
                == .init(base: .write("pw"), groupPSK: .leave, pppPassword: .leave))
    }

    /// REGRESSION (data loss). Switching the Protocol picker to look at a config
    /// and switching back — or pressing Export, which saves first — used to DELETE
    /// the rows the newly-selected kind doesn't own, because the editor loaded only
    /// the current kind's secret and the plan deleted the rest. The group PSK and
    /// the PPP password went out of the keychain unrecoverably, with no warning.
    @Test func switchingProtocolLeavesTheOtherKindsSecretsAlone() {
        // Standing on IKEv2 with an IPsec group PSK and an L2TP PPP password in
        // the keychain and nothing in those (unrendered) fields.
        let viewingIKEv2 = NativeVPNSecrets.plan(kind: .ikev2, secret: "pw",
                                                 sharedSecret: "", pppPassword: "")
        #expect(viewingIKEv2.groupPSK == .leave, "a kind switch deleted the IPsec group PSK")
        #expect(viewingIKEv2.pppPassword == .leave, "a kind switch deleted the L2TP PPP password")

        // Standing on IPsec: the PPP row is not IPsec's to touch…
        let viewingIPsec = NativeVPNSecrets.plan(kind: .ipsec, secret: "xauth",
                                                 sharedSecret: "psk", pppPassword: "")
        #expect(viewingIPsec.pppPassword == .leave)
        // …but its OWN emptied row still really clears (the original rule).
        #expect(NativeVPNSecrets.plan(kind: .ipsec, secret: "x", sharedSecret: "").groupPSK == .delete)

        // Standing on L2TP: the group PSK is not L2TP's to touch.
        let viewingL2TP = NativeVPNSecrets.plan(kind: .l2tp, secret: "psk",
                                                sharedSecret: "", pppPassword: "userpw")
        #expect(viewingL2TP.groupPSK == .leave)
        #expect(NativeVPNSecrets.plan(kind: .l2tp, secret: "psk", pppPassword: "").pppPassword == .delete)
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

    /// Only IPsec OWNS a group PSK — but a kind that doesn't own the row also has
    /// no field for it, so it may not delete it either. Deletion belongs to the
    /// kind that owns it (an emptied field) and to `remove(_:)` (profile deleted).
    @Test func onlyIPsecOwnsTheGroupPSKRow() {
        for kind in [VPNKind.ikev2, .l2tp] {
            #expect(NativeVPNSecrets.plan(kind: kind, secret: "s", sharedSecret: "psk").groupPSK == .leave,
                    "\(kind) must not write OR delete the group PSK")
        }
    }

    /// REGRESSION (data loss). Turning XAuth off used to `.delete` the XAuth
    /// password — while the row stayed on screen showing dots — so a toggle flip
    /// destroyed a password unrecoverably. The security goal is that nothing
    /// username/password-shaped is SENT, which `connect()` already guarantees; the
    /// only thing this save may drop is the persistent-reference copy.
    /// `CustomRoutingTabView.syncCustomRoutingProxyAuth` documents the same choice
    /// for the same situation ("a mode flip shouldn't lose what was typed").
    @Test func turningXAuthOffKeepsThePasswordAndOnlyDropsTheReference() {
        let off = NativeVPNSecrets.plan(kind: .ipsec, secret: "xauth", sharedSecret: "psk", xauth: false)
        #expect(off.base == .write("xauth"), "turning XAuth off destroyed the stored password")
        #expect(off.groupPSK == .write("psk"))
        #expect(off.dropBaseReference, "the persistent-reference copy must still go")
        // Turning it back on keeps it and references it again.
        let on = NativeVPNSecrets.plan(kind: .ipsec, secret: "xauth", sharedSecret: "psk", xauth: true)
        #expect(on.base == .write("xauth"))
        #expect(!on.dropBaseReference)
        // Emptying the FIELD is still a real removal — that rule is untouched.
        #expect(NativeVPNSecrets.plan(kind: .ipsec, secret: "", sharedSecret: "psk", xauth: true).base == .delete)
        // The flag is IPsec's alone — IKEv2's one secret is never an XAuth password.
        let ikev2 = NativeVPNSecrets.plan(kind: .ikev2, secret: "pw", sharedSecret: "", xauth: false)
        #expect(ikev2.base == .write("pw"))
        #expect(!ikev2.dropBaseReference)
    }

    /// Only L2TP OWNS a PPP (user) password. Clearing it while ON L2TP must really
    /// clear — otherwise the next export writes a password the user thought they
    /// removed — and no other kind may touch the row.
    @Test func onlyL2TPOwnsThePPPPasswordRow() {
        #expect(NativeVPNSecrets.plan(kind: .l2tp, secret: "psk", pppPassword: "userpw")
                == .init(base: .write("psk"), groupPSK: .leave, pppPassword: .write("userpw")))
        #expect(NativeVPNSecrets.plan(kind: .l2tp, secret: "psk", pppPassword: "").pppPassword == .delete)
        for kind in [VPNKind.ikev2, .ipsec] {
            #expect(NativeVPNSecrets.plan(kind: kind, secret: "s", sharedSecret: "psk",
                                          pppPassword: "userpw").pppPassword == .leave,
                    "\(kind) must not write OR delete the PPP password")
        }
    }

    /// `native.xauth`'s DECLARED default has to match the model's, or an untouched
    /// VPN reads as changed: the row is bold and VoiceOver says "changed from
    /// default". `usesXAuth` is `xauth ?? !username.isEmpty`, which is ON for every
    /// config that reaches this row with a username — every Cisco `.pcf` import,
    /// since they always carry one.
    @MainActor
    @Test func theXAuthSpecDefaultMatchesTheModelsOwn() {
        var imported = NativeVPNConfig()
        imported.kind = .ipsec
        imported.username = "alex"          // what a .pcf import leaves behind
        #expect(imported.usesXAuth)
        #expect(!NativeVPNSettings.catalog["native.xauth"].isChanged(imported.usesXAuth),
                "an untouched imported IPsec VPN reads as changed from default")
        // Explicitly turning it off IS a change.
        imported.xauth = false
        #expect(NativeVPNSettings.catalog["native.xauth"].isChanged(imported.usesXAuth))
    }

    /// The row ids are a storage contract (the migration in NativeVPNView and
    /// the cleanup in NativeVPNManager.remove(_:) both key on them).
    @Test func rowIdsAreStable() {
        #expect(NativeVPNSecrets.baseProfile("abc") == "native.abc")
        #expect(NativeVPNSecrets.groupPSKProfile("abc") == "native.abc.secret")
        #expect(NativeVPNSecrets.pppPasswordProfile("abc") == "native.abc.ppp")
    }
}

// MARK: - L2TP configuration profile
//
// The generator wrote `PPP.AuthName` with no password at all, so every exported
// profile prompted at connect — which reads as a broken export, not a design.

@MainActor
struct L2TPMobileconfigTests {

    private func config() -> NativeVPNConfig {
        var c = NativeVPNConfig()
        c.kind = .l2tp
        c.name = "Work"
        c.server = "vpn.example.com"
        c.username = "alex"
        return c
    }

    @Test func thePasswordIsEmittedAsAuthPassword() {
        let xml = NativeVPNProfile.l2tpMobileconfig(config(), secret: "psk", pppPassword: "s3cret")
        #expect(xml.contains("<key>AuthName</key><string>alex</string>"))
        #expect(xml.contains("<key>AuthPassword</key><string>s3cret</string>"))
    }

    /// An empty `AuthPassword` element is an empty-password attempt, not "ask me"
    /// — so with nothing entered the key is left out entirely.
    @Test func noPasswordMeansNoAuthPasswordKey() {
        let xml = NativeVPNProfile.l2tpMobileconfig(config(), secret: "psk")
        #expect(!xml.contains("AuthPassword"))
        #expect(xml.contains("<key>AuthName</key><string>alex</string>"))
    }

    /// The password is user-controlled text, so it must go through the same XML
    /// escaping as every other interpolation — unescaped, `</string>` in a
    /// password breaks out of its element and corrupts the plist.
    @Test func thePasswordIsXMLEscaped() {
        let xml = NativeVPNProfile.l2tpMobileconfig(
            config(), secret: "psk", pppPassword: "a</string><key>Bad</key><string>b&c\"'<>")
        #expect(!xml.contains("a</string><key>Bad"))
        #expect(xml.contains("&lt;/string&gt;"))
        #expect(xml.contains("&amp;c&quot;&apos;&lt;&gt;"))
        // Still a well-formed plist after all that.
        #expect((try? PropertyListSerialization.propertyList(
            from: Data(xml.utf8), options: [], format: nil)) != nil)
    }

    @Test func theSharedSecretStaysBase64AndSeparate() throws {
        let xml = NativeVPNProfile.l2tpMobileconfig(config(), secret: "psk", pppPassword: "s3cret")
        #expect(xml.contains("<key>SharedSecret</key><data>\(Data("psk".utf8).base64EncodedString())</data>"))
        let plist = try #require(try PropertyListSerialization.propertyList(
            from: Data(xml.utf8), options: [], format: nil) as? [String: Any])
        let payloads = try #require(plist["PayloadContent"] as? [[String: Any]])
        let ppp = try #require(payloads.first?["PPP"] as? [String: Any])
        #expect(ppp["AuthPassword"] as? String == "s3cret")
        #expect(ppp["AuthName"] as? String == "alex")
    }
}

// MARK: - IPsec XAuth

struct NativeVPNXAuthTests {

    /// `nil` means "never answered", which must read as the old behaviour — XAuth
    /// is in play exactly when a username exists — so no stored config changes
    /// meaning just because the field appeared.
    @Test func anUnansweredXAuthFlagFollowsTheUsername() {
        var c = NativeVPNConfig()
        c.kind = .ipsec
        #expect(!c.usesXAuth)
        c.username = "alex"
        #expect(c.usesXAuth)
    }

    @Test func anExplicitAnswerWinsOverTheUsername() {
        var c = NativeVPNConfig()
        c.kind = .ipsec
        c.username = "alex"
        c.xauth = false
        #expect(!c.usesXAuth)
        c.username = ""
        c.xauth = true
        #expect(c.usesXAuth)
    }

    /// Adding the field must not stop previously-stored configs decoding — this
    /// type uses the synthesized Codable, and `NativeVPNManager.load()` drops the
    /// WHOLE list on a decode failure.
    @Test func aStoredConfigWithoutTheFieldStillDecodes() throws {
        let json = Data("""
        {"id":"abc","name":"Work","kind":"ipsec","server":"vpn.example.com","remoteID":"",
         "username":"alex","usesSharedSecret":true,"groupOrRealm":"","onDemand":false,
         "ikeEncryption":"","ikeIntegrity":"","ikeDHGroup":"","deadPeerDetection":"",
         "disableMOBIKE":false,"enablePFS":false,"disconnectOnSleep":false,
         "includeAllNetworks":false,"excludeLocalNetworks":true}
        """.utf8)
        let c = try JSONDecoder().decode(NativeVPNConfig.self, from: json)
        #expect(c.xauth == nil)
        #expect(c.usesXAuth)          // a username was stored ⇒ XAuth as before
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
