// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

extension VPNController {
    func watchSSHAgentSigning(_ id: String, session: NETunnelProviderSession, socket: String) {
        sshNetworkAgentBrokers.removeValue(forKey:id)?.cancel()
        let epoch=UUID(); sshNetworkAgentEpochs[id]=epoch
        sshNetworkAgentBrokers[id]=Task { [weak self] in
            defer {
                if self?.sshNetworkAgentEpochs[id] == epoch {
                    self?.sshNetworkAgentBrokers[id]=nil; self?.sshNetworkAgentEpochs[id]=nil
                }
            }
            let started=Date(); var observedActive=false
            let transport: any SSHAgentTransport
            do { transport=try await Task.detached { try SSHAgentSystemEnvironment(timeout:120).connect(toSocketAt:socket) }.value }
            catch { self?.lastError="Your SSH agent could not be reached."; session.stopVPNTunnel(); return }
            defer { transport.close() }
            while !Task.isCancelled {
                guard let self else { return }
                if UI.isActive(session.status) { observedActive=true }
                if session.status == .disconnected || session.status == .invalid {
                    if observedActive || Date().timeIntervalSince(started)>12 { return }
                }
                if let bytes=await self.sendSessionMessageData(Data("sshnetagent:request".utf8),session:session,timeout:2),
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
                        _=await self.sendSessionMessageData(Data(("sshnetagent:reply:"+text).utf8),session:session,timeout:2)
                    }
                }
                do { try await Task.sleep(for:.milliseconds(30)) } catch { return }
            }
        }
    }

    func restoreSSHAgentSigning(_ id: String) async {
        guard sshNetworkAgentBrokers[id] == nil, !locallyRemovedProfileIDs.contains(id),
              let session=managers[id]?.connection as? NETunnelProviderSession, UI.isActive(session.status),
              sshNetworkTunnelConfig(for:id).authMethod == .agent else { return }
        let configured=sshNetworkTunnelConfig(for:id).agentSocketPath
        let state=await Task.detached { SSHAgentProbe().probe(configuredSocketPath:configured) }.value
        guard !locallyRemovedProfileIDs.contains(id), UI.isActive(session.status), let socket=state.socketPath, state.canSignIn else { return }
        watchSSHAgentSigning(id,session:session,socket:socket)
    }
}
