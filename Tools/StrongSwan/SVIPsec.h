// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_IPSEC_H
#define SIMPLEVPN_IPSEC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *gateway; // Already resolved numeric outer address.
    const char *local_id;
    const char *remote_id; // Exact authenticated identity.
    const uint8_t *shared_secret;
    size_t shared_secret_length;
    uint16_t remote_port;   // Zero selects UDP-encapsulated IKE on port 4500.
    int version;            // 0 or 2 for IKEv2, 1 for IKEv1.
    const char *xauth_user; // Optional IKEv1 extended authentication.
    const uint8_t *xauth_password;
    size_t xauth_password_length;
    const char *eap_user; // IKEv2 EAP-MSCHAPv2, gateway certificate required.
    const uint8_t *eap_password;
    size_t eap_password_length;
} SVIKEConfig;

typedef struct {
    // IP/CIDR strings and packet bytes are borrowed only for each callback.
    // state 1 has authenticated IKE and an installed CHILD_SA; state 0 is down.
    void (*state)(void *context, int state, const char *const *addresses, size_t address_count,
                  const char *const *routes, size_t route_count, const char *const *dns,
                  size_t dns_count);
    void (*packet)(void *context, const uint8_t *bytes, size_t length);
} SVIKECallbacks;

// One instance per Network Extension process (strongSwan owns process globals).
// Callback handlers must enqueue any stop and return; stop drains callback use.
// A successful start admits negotiation; only state 1 admits inner packets.
uint64_t SVIKEStart(const SVIKEConfig *config, SVIKECallbacks callbacks, void *context);
// IPv4 L2TP/IPsec with IKEv1 Main Mode PSK and PPP MSCHAPv2.
// State 1 follows verified PPP authentication and an assigned IPCP address.
// Username/password are 1–255 printable ASCII bytes. Only runtime copies are kept.
uint64_t SVL2TPStart(const SVIKEConfig *config, const char *ppp_user, const uint8_t *password,
                     size_t password_length, SVIKECallbacks callbacks, void *context);
// Bound starts require a live interface index and bind every carrier socket before use.
uint64_t SVIKEStartBound(const SVIKEConfig *, uint32_t ifindex, SVIKECallbacks, void *);
uint64_t SVL2TPStartBound(const SVIKEConfig *, const char *ppp_user, const uint8_t *password,
                          size_t length, uint32_t ifindex, SVIKECallbacks, void *);
uint16_t SVL2TPMTU(uint64_t session);
bool SVIKESend(uint64_t session, const uint8_t *bytes, size_t length);
void SVIKEStop(uint64_t session);
#endif
