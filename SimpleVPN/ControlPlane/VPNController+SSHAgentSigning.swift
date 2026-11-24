// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

extension VPNController {
    func watchSSHAgentSigning(_ id: String, session: NETunnelProviderSession, socket: String, virtual: Bool = false) {
        sshNetworkAgentBrokers.removeValue(forKey:id)?.cancel()
        let epoch=UUID(); sshNetworkAgentEpochs[id]=epoch
        sshNetworkAgentBrokers[id]=Task { [weak self] in
            defer {
                if self?.sshNetworkAgentEpochs[id] == epoch {
                    self?.sshNetworkAgentBrokers[id]=nil; self?.sshNetworkAgentEpochs[id]=nil
                }
            }
            @MainActor func send(_ message: String, timeout: TimeInterval) async -> Data? {
                guard let self else { return nil }
                if virtual {
                    guard self.virtualManager(for: id)?.connection === session,
                          !self.virtualStoppedMembers.contains(id),
                          let payload = try? JSONEncoder().encode(VirtualRoutingMessage(profile: id, message: message)) else { return nil }
                    return await self.sendSessionMessageData(Data("router:message:".utf8) + payload, session: session, timeout: timeout)
                }
                return await self.sendSessionMessageData(Data(message.utf8), session: session, timeout: timeout)
            }
            let started=Date(); var observedActive=false
            let transport: any SSHAgentTransport
            do { transport=try await Task.detached { try SSHAgentSystemEnvironment(timeout:120).connect(toSocketAt:socket) }.value }
            catch {
                guard !Task.isCancelled else { return }
                self?.lastError="Your SSH agent could not be reached."; session.stopVPNTunnel(); return
            }
            defer { transport.close() }
            // The provider holds one reply until libssh needs the agent. A
            // watchdog renews it if NE loses the reply across sleep or a restart.
            while !Task.isCancelled {
                guard let self else { return }
                if UI.isActive(session.status) { observedActive=true }
                if session.status == .disconnected || session.status == .invalid {
                    if observedActive || Date().timeIntervalSince(started)>12 { return }
                }
                if virtual && self.virtualStoppedMembers.contains(id) { return }
                var bytes = await send("sshnetagent:wait", timeout: 60)
                guard !Task.isCancelled else { return }
                if bytes == nil {
                    // An active extension from a previous build responds nil
                    // to the new message. Its original snapshot remains usable.
                    bytes = await send("sshnetagent:request", timeout: 2)
                }
                if let bytes,
                   let request=try? JSONDecoder().decode(SSHAgentSigningRequest.self,from:bytes), !Task.isCancelled {
                    guard (5...262148).contains(request.request.count), [UInt8(11),13].contains(request.request[4]) else {
                        self.lastError="The VPN sent an invalid signing request."; session.stopVPNTunnel(); return
                    }
                    let response: Data
                    do {
                        response=try await withTaskCancellationHandler {
                            try await Task.detached { try transport.roundTrip(request.request) }.value
                        } onCancel: { transport.close() }
                    } catch {
                        guard !Task.isCancelled else { return }
                        self.lastError="Your SSH agent could not sign for this VPN. Unlock or approve the request in your agent, then reconnect."
                        session.stopVPNTunnel(); return
                    }
                    guard !Task.isCancelled else { return }
                    if let data=try? JSONEncoder().encode(SSHAgentSigningResponse(id:request.id,response:response)),
                       let text=String(data:data,encoding:.utf8) {
                        _ = await send("sshnetagent:reply:" + text, timeout: 2)
                    }
                    continue
                }
                do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
            }
        }
    }

    func restoreSSHAgentSigning(_ id: String) async {
        guard sshNetworkAgentBrokers[id] == nil, !locallyRemovedProfileIDs.contains(id),
              let session=(virtualManager(for: id) ?? managers[id])?.connection as? NETunnelProviderSession, UI.isActive(session.status),
              sshNetworkTunnelConfig(for:id).authMethod == .agent else { return }
        let configured=sshNetworkTunnelConfig(for:id).agentSocketPath
        let state=await Task.detached { SSHAgentProbe().probe(configuredSocketPath:configured) }.value
        guard !locallyRemovedProfileIDs.contains(id), UI.isActive(session.status), let socket=state.socketPath, state.canSignIn else { return }
        watchSSHAgentSigning(id, session: session, socket: socket, virtual: virtualManager(for: id) != nil)
    }
}
