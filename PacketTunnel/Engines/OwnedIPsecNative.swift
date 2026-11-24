// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// The engine drains callbacks in SVIKEStop. Each owner retains this target
/// from before native start until its matching stop returns.
final class OwnedIPsecNativeCallbacks: Sendable {
    let stateChanged: @Sendable (OwnedIPsecNetworkSettings?) -> Void
    let receive: @Sendable (UnsafePointer<UInt8>, Int) -> Void

    init(stateChanged: @escaping @Sendable (OwnedIPsecNetworkSettings?) -> Void,
         receive: @escaping @Sendable (UnsafePointer<UInt8>, Int) -> Void) {
        self.stateChanged = stateChanged
        self.receive = receive
    }
}

enum OwnedIPsecNative {
    struct Worker {
        let executable: URL
        let interfaceIndex: UInt32
    }

    static func start(config: OwnedIPsecConfiguration, address: String, credentials: OwnedIPsecCredentials,
                      callbackTarget: OwnedIPsecNativeCallbacks, worker: Worker? = nil) -> UInt64 {
        let callbacks = SVIKECallbacks(state: { ctx, value, addresses, ac, routes, rc, dns, dc in
            guard let ctx else { return }
            let engine = Unmanaged<OwnedIPsecNativeCallbacks>.fromOpaque(ctx).takeUnretainedValue()
            func strings(_ list: UnsafePointer<UnsafePointer<CChar>?>?, _ count: Int, _ limit: Int) -> [String]? {
                guard count <= limit, list != nil || count == 0 else { return nil }
                let text = UnsafeBufferPointer(start: list, count: count).compactMap { $0.flatMap(String.init(validatingCString:)) }
                return text.count == count ? text : nil
            }
            let settings: OwnedIPsecNetworkSettings?
            if value == 1, let ips = strings(addresses, ac, 8), let cidrs = strings(routes, rc, 128),
               let resolvers = strings(dns, dc, 8) {
                settings = OwnedIPsecNetworkSettings(addresses: ips, routes: cidrs, dns: resolvers)
            } else { settings = nil }
            engine.stateChanged(settings)
        }, packet: { ctx, bytes, count in
            guard let ctx, let bytes, (1...65575).contains(count) else { return }
            Unmanaged<OwnedIPsecNativeCallbacks>.fromOpaque(ctx).takeUnretainedValue().receive(bytes, count)
        })
        return address.withCString { host in
            config.localID.withCString { local in
                config.remoteID.withCString { remote in
                    (config.username ?? "").withCString { user in
                        (credentials.psk ?? Data()).withUnsafeBytes { key in
                            (credentials.password ?? Data()).withUnsafeBytes { pw in
                                var native = SVIKEConfig()
                                native.gateway = host; native.local_id = local; native.remote_id = remote
                                native.version = config.kind == .ikev2 ? 2 : 1
                                if config.usesEAP == true {
                                    native.eap_user = user
                                    native.eap_password = pw.bindMemory(to: UInt8.self).baseAddress
                                    native.eap_password_length = pw.count
                                } else {
                                    native.shared_secret = key.bindMemory(to: UInt8.self).baseAddress
                                    native.shared_secret_length = key.count
                                }
                                if config.usesXAuth {
                                    native.xauth_user = user
                                    native.xauth_password = pw.bindMemory(to: UInt8.self).baseAddress
                                    native.xauth_password_length = pw.count
                                }
                                let context = Unmanaged.passUnretained(callbackTarget).toOpaque()
                                if let worker {
                                    return worker.executable.withUnsafeFileSystemRepresentation { path in
                                        let isPPP = config.usesL2TP == true
                                        return SVWorkerStart(path, &native, isPPP ? user : nil,
                                                             isPPP ? pw.bindMemory(to: UInt8.self).baseAddress : nil,
                                                             isPPP ? pw.count : 0, worker.interfaceIndex,
                                                             callbacks, context)
                                    }
                                }
                                if config.usesL2TP == true {
                                    return SVL2TPStart(&native, user, pw.bindMemory(to: UInt8.self).baseAddress,
                                                       pw.count, callbacks, context)
                                }
                                return SVIKEStart(&native, callbacks, context)
                            }
                        }
                    }
                }
            }
        }
    }
}
