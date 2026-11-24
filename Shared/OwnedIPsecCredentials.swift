// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Decode only the exact authentication method selected by the saved profile.
/// The same start-only inputs are required for independent and shared ports.
nonisolated struct OwnedIPsecCredentials: Sendable {
    let psk: Data?
    let password: Data?

    init(config: OwnedIPsecConfiguration, options: [String: Any]) throws {
        func credential(_ key: String, required: Bool) throws -> Data? {
            guard required else {
                guard options[key] == nil else {
                    throw OwnedIPsecNetworkSettings.error("The credentials do not match the selected IPsec sign-in method.")
                }
                return nil
            }
            guard let value = options[key] as? Data, (1...8192).contains(value.count) else {
                throw OwnedIPsecNetworkSettings.error("A required IPsec credential is missing or too long.")
            }
            return value
        }
        let usesEAP = config.usesEAP == true
        psk = try credential(OwnedIPsecConfiguration.pskOption, required: !usesEAP)
        let eap = try credential(OwnedIPsecConfiguration.eapPasswordOption, required: usesEAP)
        let xauth = try credential(OwnedIPsecConfiguration.xauthPasswordOption, required: config.usesXAuth)
        let ppp = try credential(OwnedIPsecConfiguration.pppPasswordOption, required: config.usesL2TP == true)
        if let ppp, ppp.count > 255 || !ppp.allSatisfy({ (32...126).contains($0) }) {
            throw OwnedIPsecNetworkSettings.error("The PPP password must contain 1 to 255 printable ASCII characters.")
        }
        password = ppp ?? eap ?? xauth
    }
}
