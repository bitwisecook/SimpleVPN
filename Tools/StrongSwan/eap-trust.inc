// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "apple-trust.h"
static char *expected_gateway;
static void add_trust_anchor(SVIKECertificate der, void *u) {
    certificate_t *c = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509, BUILD_BLOB_ASN1_DER,
                                          chunk_create((uint8_t *)der.bytes, der.size), BUILD_END);
    if (c)
        credentials->add_cert(credentials, true, c);
}
// libcharon calls this authorization hook after verifying the responder AUTH
// and before processing its first EAP request. Reject EAP-only negotiation.
static bool approve_peer(listener_t *listener, ike_sa_t *sa, bool final, bool *ok) {
    if (!*ok || !expected_gateway || final)
        return true;
    auth_cfg_t *auth = sa->get_auth_cfg(sa, false);
    certificate_t *leaf = auth->get(auth, AUTH_RULE_SUBJECT_CERT);
    identification_t *want = identification_create_from_string(expected_gateway);
    identification_t *actual = sa->get_other_id(sa);
    bool matches = actual && actual->equals(actual, want);
    want->destroy(want);
    if (!leaf || !matches) {
#ifdef SIMPLEVPN_IPSEC_FIXTURE
        fprintf(stderr, "fixture peer evidence: leaf %d, matched identity %d\n", leaf != NULL, matches);
#endif
        *ok = false;
        return true;
    }
    chunk_t enc[16];
    size_t count = 0;
    if (leaf->get_encoding(leaf, CERT_ASN1_DER, &enc[count]))
        count++;
    bool complete = count != 0;
    auth_rule_t rule;
    certificate_t *item;
    enumerator_t *e = auth->create_enumerator(auth);
    while (complete && e->enumerate(e, &rule, &item)) {
        if (rule != AUTH_RULE_IM_CERT && rule != AUTH_RULE_CA_CERT)
            continue;
        if (count == countof(enc) || !item->get_encoding(item, CERT_ASN1_DER, &enc[count])) {
            complete = false;
            break;
        }
        count++;
    }
    e->destroy(e);
    SVIKECertificate chain[16];
    for (size_t i = 0; i < count; i++)
        chain[i] = (SVIKECertificate){enc[i].ptr, enc[i].len};
    const char *name = expected_gateway;
    if (name[0] == '@')
        name++;
    *ok = complete && SVIKEVerifyGateway(name, chain, count);
    for (size_t i = 0; i < count; i++)
        chunk_free(&enc[i]);
    return true;
}
