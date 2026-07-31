//
//  SimpleVPNTests.swift
//  SimpleVPNTests
//
//  Created by Jim Deucker on 27/07/2026.
//

import Testing
import Security
@testable import SimpleVPN

struct SimpleVPNTests {

    /// TN3137 tripwire: the biometric credential store depends on the
    /// data-protection keychain, which on macOS only works when the app is
    /// signed with an App ID + keychain-access-groups validated by an EMBEDDED
    /// provisioning profile. This proves that end-to-end in the signed test
    /// host (write → read → delete, no access control so no prompt). If it
    /// ever fails with -34018 the signing setup regressed and Touch ID
    /// protection is silently broken — fix the profile, not this test.
    @Test func dataProtectionKeychainIsUsable() throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.bragi0.SimpleVPN.tests.dp-probe",
            kSecAttrAccount as String: "probe",
            kSecAttrAccessGroup as String: "QVUFB5676H.com.bragi0.SimpleVPN.shared",
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data("probe".utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        #expect(addStatus == errSecSuccess,
                "data-protection keychain write failed (OSStatus \(addStatus)) — embedded profile/entitlements regressed (TN3137)")

        var q = base
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        let readStatus = SecItemCopyMatching(q as CFDictionary, &out)
        #expect(readStatus == errSecSuccess)
        #expect((out as? Data).map { String(decoding: $0, as: UTF8.self) } == "probe")

        SecItemDelete(base as CFDictionary)
    }

    /// The store's prompt-free presence check must not false-positive on a
    /// profile that has no protected item.
    @Test func biometricStoreInfoOnMissingItem() {
        let info = BiometricCredentialStore.info(profile: "no-such-profile-\(UUID().uuidString)")
        #expect(!info.exists)
        #expect(!info.hasTOTP)
    }

}
