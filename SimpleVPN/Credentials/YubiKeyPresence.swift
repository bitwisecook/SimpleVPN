// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyPresence.swift
//  Is a security key plugged in, and what does it advertise?
//
//  THE PRIVACY DESIGN, WHICH IS THE WHOLE REASON THIS FILE IS SHAPED THIS WAY.
//  A YubiKey's OTP applet is a USB HID keyboard. There are two ways an app could
//  learn about it:
//
//   1. Open the HID device and read its input reports. On macOS 10.15 and later
//      opening a keyboard-class HID device requires the user to grant SimpleVPN
//      **Input Monitoring** in System Settings ▸ Privacy & Security — a
//      permission that lets an app read EVERY keystroke on the Mac, in every
//      application, for ever. A VPN client asking for that is indefensible, and
//      it is explicitly forbidden for this feature.
//   2. Read the IORegistry: the device tree macOS already publishes, listing
//      every attached device and its descriptors. No permission, no prompt, no
//      TCC service, and no access to a single keystroke.
//
//  This file does (2), only, and it must stay that way. It calls
//  `IOServiceGetMatchingServices` and `IORegistryEntryCreateCFProperty` and
//  NOTHING else — there is no `IOHIDManagerOpen`, no `IOHIDDeviceOpen`, no
//  `IOHIDDeviceRegisterInputValueCallback` and no `IOHIDManagerSetDeviceMatching`
//  with an input callback anywhere in SimpleVPN. If a future change appears to
//  need one of those, the design is wrong: we do not read the key, the key TYPES
//  into the field we have focused, which is why capture is a text-field problem
//  (YubiKeyTouchCapture.swift) and not a HID problem.
//
//  WHAT THE REGISTRY CAN AND CANNOT TELL US, since the UI must not overclaim:
//   • The OTP applet — the HID keyboard interface — is VISIBLE. That is the one
//     that matters most here, because it is the thing that types.
//   • FIDO is visible (its own HID usage page, 0xF1D0).
//   • CCID/smartcard — which is where PIV, OATH and OpenPGP live — is NOT a HID
//     interface and is invisible from here. The product id hints at whether the
//     key was built with it, but whether the applet is enabled needs `ykman`
//     (see YubiKeyManagerTool.swift). So `oathVisible` is deliberately absent
//     from this type: a field we could only guess at is worse than no field.
//

import Foundation
import IOKit
import IOKit.hid
import os

// MARK: - One attached key

nonisolated struct AttachedSecurityKey: Sendable, Equatable, Identifiable, Hashable {

    /// Registry entry id — unique per attachment, so two identical keys in two
    /// ports stay two rows.
    let id: UInt64
    /// The name the device reports, e.g. "YubiKey OTP+FIDO+CCID". Vendor-supplied
    /// and safe to show.
    let productName: String
    let vendorID: Int
    let productID: Int
    /// The device presents a keyboard interface — so touching it will TYPE.
    let typesAsKeyboard: Bool
    /// The device presents the FIDO usage page.
    let presentsFIDO: Bool

    /// The family, from the product id. Falls back to the reported product name,
    /// which is what a key we have never seen still gives us.
    var familyName: String {
        YubicoUSB.family(productID: productID) ?? productName
    }

    /// What the interfaces say the key was built with. "Built with", not "enabled":
    /// see the file header on CCID.
    var interfaceSummary: String {
        YubicoUSB.interfaces(productID: productID)
    }
}

// MARK: - Yubico's own identifiers

/// The vendor and product ids Yubico ships, taken from `yubikit.core.PID` in
/// Yubico's own `yubikey-manager` (BSD-2-Clause). The product id encodes WHICH
/// USB interfaces the key was built with, which is why the table carries the
/// interface set rather than only a marketing name.
///
/// The YubiKey 5 series reuses the YubiKey 4 product ids — that is Yubico's
/// choice, not an omission here, and it is why `family` says "YubiKey" for the
/// 0x04xx range rather than guessing a generation the id does not carry.
nonisolated enum YubicoUSB {

    /// Yubico's USB vendor id.
    static let vendorID = 0x1050

    /// Product id → (family, interfaces built in).
    static let products: [Int: (family: String, interfaces: String)] = [
        0x0010: ("YubiKey Standard", "OTP"),
        0x0110: ("YubiKey NEO", "OTP"),
        0x0111: ("YubiKey NEO", "OTP+CCID"),
        0x0112: ("YubiKey NEO", "CCID"),
        0x0113: ("YubiKey NEO", "FIDO"),
        0x0114: ("YubiKey NEO", "OTP+FIDO"),
        0x0115: ("YubiKey NEO", "FIDO+CCID"),
        0x0116: ("YubiKey NEO", "OTP+FIDO+CCID"),
        0x0120: ("Security Key by Yubico", "FIDO"),
        0x0401: ("YubiKey", "OTP"),
        0x0402: ("YubiKey", "FIDO"),
        0x0403: ("YubiKey", "OTP+FIDO"),
        0x0404: ("YubiKey", "CCID"),
        0x0405: ("YubiKey", "OTP+CCID"),
        0x0406: ("YubiKey", "FIDO+CCID"),
        0x0407: ("YubiKey", "OTP+FIDO+CCID"),
        0x0410: ("YubiKey Plus", "OTP+FIDO"),
    ]

    static func family(productID: Int) -> String? { products[productID]?.family }

    /// The interfaces this product id was built with, or a plain "unknown" —
    /// never a guess dressed up as a fact.
    static func interfaces(productID: Int) -> String {
        products[productID]?.interfaces ?? "interfaces not known to SimpleVPN"
    }

    /// Whether the product id says the key carries the OTP interface — the one
    /// that types. Independent of the HID scan, and used to tell "your key has no
    /// OTP applet" from "your key's OTP applet is switched off".
    static func builtWithOTP(productID: Int) -> Bool {
        products[productID]?.interfaces.contains("OTP") ?? false
    }
}

// MARK: - The scan

/// Every Yubico key attached right now, from the IORegistry alone.
///
/// Injectable through `SecurityKeyScanning` so every caller above this line can
/// be tested on a machine with nothing plugged in — which is the normal case,
/// including the machine this was written on.
@MainActor
protocol SecurityKeyScanning: Sendable {
    func scan() -> [AttachedSecurityKey]
}

/// The real scan. Registry reads only — see the file header.
struct IORegistrySecurityKeyScanner: SecurityKeyScanning {

    /// FIDO's HID usage page (FIDO Alliance, `0xF1D0`).
    static let fidoUsagePage = 0xF1D0
    /// Generic Desktop / Keyboard — the pair a typing key presents.
    static let keyboardUsagePage = kHIDPage_GenericDesktop
    static let keyboardUsage = kHIDUsage_GD_Keyboard

    func scan() -> [AttachedSecurityKey] {
        // Class-match every HID device belonging to Yubico. Filtering in the
        // matching dictionary rather than in our own loop keeps the kernel from
        // handing back every keyboard and mouse on the Mac.
        guard let matching = IOServiceMatching(kIOHIDDeviceKey) as NSMutableDictionary? else {
            return []
        }
        matching[kIOHIDVendorIDKey] = YubicoUSB.vendorID

        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS
        else { return [] }
        defer { IOObjectRelease(iterator) }

        // One key presents several HID interfaces (keyboard + FIDO), each its own
        // registry entry, so the interfaces are folded together per PHYSICAL key.
        // The registry entry id of the FIRST interface seen becomes the row's id,
        // which is stable for as long as the key stays plugged in.
        var byKey: [String: AttachedSecurityKey] = [:]
        var order: [String] = []

        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            guard let productID = intProperty(service, kIOHIDProductIDKey) else { continue }
            let name = stringProperty(service, kIOHIDProductKey) ?? "Security key"
            let usagePage = intProperty(service, kIOHIDPrimaryUsagePageKey) ?? 0
            let usage = intProperty(service, kIOHIDPrimaryUsageKey) ?? 0
            var entryID: UInt64 = 0
            IORegistryEntryGetRegistryEntryID(service, &entryID)

            // "This physical device": the location id is the port, which is what
            // distinguishes two identical keys. Falling back to the product id
            // merges two same-model keys into one row rather than inventing a
            // second — the honest failure, since we cannot tell them apart.
            let location = intProperty(service, kIOHIDLocationIDKey).map(String.init)
                ?? "pid:\(productID)"

            let isKeyboard = usagePage == Self.keyboardUsagePage && usage == Self.keyboardUsage
            let isFIDO = usagePage == Self.fidoUsagePage

            if var existing = byKey[location] {
                existing = AttachedSecurityKey(
                    id: existing.id,
                    productName: existing.productName,
                    vendorID: existing.vendorID,
                    productID: existing.productID,
                    typesAsKeyboard: existing.typesAsKeyboard || isKeyboard,
                    presentsFIDO: existing.presentsFIDO || isFIDO)
                byKey[location] = existing
            } else {
                byKey[location] = AttachedSecurityKey(
                    id: entryID, productName: name,
                    vendorID: YubicoUSB.vendorID, productID: productID,
                    typesAsKeyboard: isKeyboard, presentsFIDO: isFIDO)
                order.append(location)
            }
        }
        return order.compactMap { byKey[$0] }
    }

    private func intProperty(_ service: io_service_t, _ key: String) -> Int? {
        guard let value = IORegistryEntryCreateCFProperty(
            service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
        else { return nil }
        return (value as? NSNumber)?.intValue
    }

    private func stringProperty(_ service: io_service_t, _ key: String) -> String? {
        guard let value = IORegistryEntryCreateCFProperty(
            service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
        else { return nil }
        return value as? String
    }
}

// MARK: - What the app asks

/// What a surface needs to know before it offers to capture a code. Pure data, so
/// every rule that reads it is testable with no key attached.
nonisolated struct SecurityKeyPresence: Sendable, Equatable {

    var keys: [AttachedSecurityKey] = []
    /// Whether `ykman` is installed somewhere SimpleVPN will run it. Gathered
    /// separately (see YubiKeyManagerTool) and folded in here so one value answers
    /// "what can this Mac do with a security key right now".
    var managerToolInstalled = false

    var isAttached: Bool { !keys.isEmpty }
    /// A key that will TYPE when touched. The one that matters for Yubico OTP,
    /// for password+code composition and for a static password.
    var typingKeys: [AttachedSecurityKey] { keys.filter(\.typesAsKeyboard) }
    var hasTypingKey: Bool { !typingKeys.isEmpty }

    /// A key is plugged in, but its OTP applet is not presenting a keyboard — so
    /// touching it will do nothing. Distinguished from "no key at all" because the
    /// fix is completely different (turn the applet back on, vs plug one in).
    var hasKeyWithoutTypingInterface: Bool {
        isAttached && !hasTypingKey
    }

    /// One plain sentence about what is plugged in. No jargon; the glossary's
    /// "security key" throughout.
    var summary: String {
        switch keys.count {
        case 0:
            return "No security key is plugged in."
        case 1:
            let key = keys[0]
            return key.typesAsKeyboard
                ? "\(key.familyName) is plugged in and ready to type a code when you touch it."
                : "\(key.familyName) is plugged in, but its code applet isn\u{2019}t switched on, so "
                    + "touching it won\u{2019}t type anything."
        default:
            let typing = typingKeys.count
            return typing == keys.count
                ? "\(keys.count) security keys are plugged in."
                : "\(keys.count) security keys are plugged in; \(typing) will type a code when touched."
        }
    }
}
