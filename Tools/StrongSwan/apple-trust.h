// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_IKE_APPLE_TRUST_H
#define SIMPLEVPN_IKE_APPLE_TRUST_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef struct {
    const uint8_t *bytes;
    size_t size;
} SVIKECertificate;
typedef void (*SVIKEAnchor)(SVIKECertificate cert, void *context);
bool SVIKEEnumerateAnchors(SVIKEAnchor visit, void *context);
bool SVIKEVerifyGateway(const char *hostname, const SVIKECertificate *chain, size_t length);
#endif
