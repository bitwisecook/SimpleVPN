package teleport

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const responsePollInterval = 600 * time.Millisecond

type sessionResult struct{ Token, Secret string }

type requestFunc func(string, string, string, interface{}) (*apiResponse, error)

func fetchICEConfiguration(ctx context.Context, sessionToken, sessionSecret string, request requestFunc) ([]iceServer, error) {
	iceBody := apiEnvelope{Token: sessionToken, Payload: map[string]interface{}{"request_type": "GET_ICE_CONFIGURATION", "secret": sessionSecret}}
	iceReq, err := request("POST", "/", "", iceBody)
	if err != nil {
		return nil, err
	}

	poll, err := pollForResponseWithContext(ctx, request, sessionToken, iceReq.TeleportRequestID, "ICE_CONFIGURATION", responsePollInterval, 100)
	if err != nil {
		return nil, err
	}
	var ice []iceServer
	if poll != nil {
		ice = poll.IceConfiguration
	}
	if len(ice) == 0 {
		return nil, errors.New("timed out waiting for ICE_CONFIGURATION")
	}
	_, _ = request("DELETE", "/"+iceReq.TeleportRequestID, sessionToken, nil)
	return ice, nil
}

// gatherLocalCandidates collects interface and server-reflexive candidates
// for the enabled address families. Reflexive gathering failures are logged
// and skipped rather than fatal: an interface candidate can still be
// nominated successfully.
func gatherLocalCandidates(sockets *udpSockets, port int, family networkFamily, ice []iceServer) []candidate {
	local := localCandidates(port, family)
	if family != familyIPv6 {
		if reflex, err := reflexiveCandidateFromConn(sockets.V4, ice, familyIPv4); err == nil {
			local = append(local, reflex)
		} else {
			appLog.Warn("IPv4 reflexive candidate unavailable", "error", err)
		}
	}
	if family != familyIPv4 {
		if reflex, err := reflexiveCandidateFromConn(sockets.V6, ice, familyIPv6); err == nil {
			local = append(local, reflex)
		} else {
			// IPv6 server-reflexive candidates are optional: a public interface
			// candidate can still be nominated successfully. In particular, the
			// supplied STUN hostname may be IPv4-only, which is not a tunnel
			// failure and should not make normal -6 output look broken.
			appLog.Debug("IPv6 reflexive candidate unavailable", "error", err)
		}
	}
	appLog.Info("candidate gathering complete", "family", family.String(), "count", len(local))
	for _, c := range local {
		appLog.Debug("local candidate", "type", c.Type, "address", c.Addr)
	}
	return local
}

// connectAndAwaitResponse sends CONNECT with the gathered candidates and
// polls for CONNECT_RESPONSE.
func connectAndAwaitResponse(ctx context.Context, session sessionResult, name, pub, stunSecret string, local []candidate, ice []iceServer, request requestFunc) (*apiResponse, error) {
	connectPayload := map[string]interface{}{
		"request_type": "CONNECT",
		"secret":       session.Secret,
		"client_name":  name,
		"client_info": map[string]interface{}{
			"wg_pub_key":          pub,
			"stun_session_secret": stunSecret,
			"peer_desc":           peerDesc{Candidates: local, IceConfig: ice, IsMaster: false},
		},
	}
	connectReq, err := request("POST", "/", "", apiEnvelope{Token: session.Token, Payload: connectPayload})
	if err != nil {
		return nil, err
	}

	connResp, err := pollForResponseWithContext(ctx, request, session.Token, connectReq.TeleportRequestID, "CONNECT_RESPONSE", responsePollInterval, 200)
	if err != nil {
		return nil, err
	}
	if connResp == nil {
		return nil, errors.New("timed out waiting for CONNECT_RESPONSE")
	}
	_, _ = request("DELETE", "/"+connectReq.TeleportRequestID, session.Token, nil)
	return connResp, nil
}

// negotiateEndpoint determines which candidate address to use as the
// WireGuard peer endpoint: an explicit --endpoint override, the master's
// per-tuple nomination sequence, an inbound Binding Request observed by the
// early listener, or — as a last resort — concurrent candidate probing via
// probeCandidates. It also returns the ranked queue of candidates that sent
// us a Binding Request, for the post-connect endpoint retry loop.
func negotiateEndpoint(ctx context.Context, endpointOverride string, forceTurn bool, sockets *udpSockets, port int, connResp *apiResponse, stunSecret string, nomination *nominationTracker, early *earlyNominationListener, local []candidate) (endpoint, mode string, candidateQueue []string, candidateTypes map[string]string, err error) {
	peerCandidates := connResp.ServerInfo.PeerDesc.Candidates
	if forceTurn {
		peerCandidates = compatibleCandidates(sockets, candidatesOfType(peerCandidates, "turn"), local)
	}
	appLog.Info("peer candidates received", "count", len(peerCandidates))
	for _, c := range peerCandidates {
		appLog.Debug("peer candidate", "type", c.Type, "address", c.Addr)
	}

	stopCandidateProbes := startPeerCandidateProbes(sockets, peerCandidates, stunSecret)
	defer stopCandidateProbes()
	if endpointOverride != "" {
		endpoint, mode = endpointOverride, "override"
	} else {
		endpoint, mode, candidateQueue, err = resolveNominatedEndpoint(ctx, sockets, port, peerCandidates, stunSecret, nomination, early, local)
		if err != nil {
			return "", "", nil, nil, err
		}
	}
	stopCandidateProbes()
	if endpoint == "" {
		return "", "", nil, nil, errors.New("no endpoint candidate available")
	}
	early.Stop()
	candidateQueue = buildCandidateRetryQueue(endpoint, candidateQueue, compatibleCandidates(sockets, peerCandidates, local))
	candidateTypes = candidateTypeMap(peerCandidates)
	return endpoint, mode, candidateQueue, candidateTypes, nil
}

func candidatesOfType(candidates []candidate, candidateType string) []candidate {
	filtered := make([]candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Type == candidateType {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// resolveNominatedEndpoint tries per-tuple nomination, then an observed
// inbound Binding Request, then the fallback probeCandidates fan-out.
func resolveNominatedEndpoint(ctx context.Context, sockets *udpSockets, port int, peerCandidates []candidate, stunSecret string, nomination *nominationTracker, early *earlyNominationListener, local []candidate) (endpoint, mode string, candidateQueue []string, err error) {
	// The Android bridge waits up to 40s for a verified per-tuple sequence.
	nomination.activate()
	appLog.Debug("waiting for per-tuple nomination", "timeout", "40s")
	endpoint = nomination.waitForSelection(ctx, 40*time.Second)
	if err := ctx.Err(); err != nil {
		return "", "", nil, err
	}
	if endpoint != "" {
		mode = "per_tuple_nomination"
	} else {
		appLog.Debug("per-tuple nomination wait timed out")
	}

	nominationPackets := early.Logs()
	if len(nominationPackets) > 0 {
		seenCandidates := make(map[string]bool)
		for _, p := range nominationPackets {
			if p.Direction == "in" && p.STUN && p.STUNType == "Binding request" {
				if !seenCandidates[p.Addr] {
					seenCandidates[p.Addr] = true
					candidateQueue = append(candidateQueue, p.Addr)
				}
				if endpoint == "" {
					endpoint = p.Addr
					mode = "inbound_binding_request"
				}
			}
		}
	}
	if endpoint == "" {
		early.Stop()
		endpoint = probeCandidates(sockets, peerCandidates, stunSecret, local)
		if err := ctx.Err(); err != nil {
			return "", "", nil, err
		}
		mode = "fallback_probe"
	}
	return endpoint, mode, candidateQueue, nil
}

// candidateTypeMap maps each advertised candidate's address to its type
// (iface/reflex/turn) so the retry loop can size its per-candidate patience
// to how likely that address is to still be establishing a path (e.g. a TURN
// relay allocation) versus simply dead.
func candidateTypeMap(peerCandidates []candidate) map[string]string {
	types := make(map[string]string, len(peerCandidates))
	for _, c := range peerCandidates {
		types[c.Addr] = c.Type
	}
	return types
}

// buildCandidateRetryQueue preserves candidates that actually reached us
// first, then appends every compatible candidate advertised by the peer. A
// late/fallback selection may otherwise leave the retry queue empty even
// though the CONNECT_RESPONSE supplied viable alternatives.
func buildCandidateRetryQueue(endpoint string, observed []string, advertised []candidate) []string {
	seen := map[string]bool{endpoint: true}
	queue := make([]string, 0, len(observed)+len(advertised))
	appendCandidate := func(addr string) {
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		queue = append(queue, addr)
	}
	for _, addr := range observed {
		appendCandidate(addr)
	}
	// Once observed candidates are exhausted, public reflexive/relay tuples
	// are materially more likely to work across networks than peer-private
	// interface addresses. Keep each group's existing rank stable.
	for _, public := range []bool{true, false} {
		for _, candidate := range advertised {
			if isPubliclyRoutableCandidateAddr(candidate.Addr) == public {
				appendCandidate(candidate.Addr)
			}
		}
	}
	return queue
}

func validateLocalCandidates(local []candidate, family networkFamily) error {
	if len(local) == 0 {
		return fmt.Errorf("no viable %s candidate on this host", family)
	}
	return nil
}

func validateTurnPrerequisites(ice []iceServer, local []candidate) error {
	if _, ok := stunServerFromIce(ice); !ok {
		return errors.New("--turn requires a stun: URL in ICE_CONFIGURATION because console teleportd rejects TURN-only ICE configuration")
	}
	if _, ok := turnServerFromIce(ice); !ok {
		return errors.New("--turn requires a turn: URL with transport=udp in ICE_CONFIGURATION")
	}
	for _, c := range local {
		if c.Type == "reflex" {
			return nil
		}
	}
	return errors.New("--turn requires a reflex candidate; console teleportd uses it to create the TURN permission")
}
