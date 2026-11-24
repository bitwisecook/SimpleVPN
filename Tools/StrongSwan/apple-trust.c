// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "apple-trust.h"
#include <Security/Security.h>
#ifdef SIMPLEVPN_IPSEC_FIXTURE
#include <stdio.h>
#include <stdlib.h>
// An ephemeral root is scoped exclusively to the local test's SecTrustRef.
// No fixture certificate is added to the Mac's keychain or trust settings.
static CFArrayRef isolated_anchors(void) {
    const char *path = getenv("FIXTURE_CA");
    if (!path)
        return NULL;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t bytes[8192];
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    fclose(f);
    if (!n || n == sizeof(bytes))
        return NULL;
    CFDataRef data = CFDataCreate(NULL, bytes, n);
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, data);
    CFRelease(data);
    if (!cert)
        return NULL;
    CFArrayRef a = CFArrayCreate(NULL, (const void **)&cert, 1, &kCFTypeArrayCallBacks);
    CFRelease(cert);
    return a;
}
#endif

static void visit_anchors(CFArrayRef array, SVIKEAnchor visit, void *context) {
    for (CFIndex i = 0; i < CFArrayGetCount(array); i++) {
        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(array, i);
        CFDataRef der = SecCertificateCopyData(cert);
        if (!der)
            continue;
        visit((SVIKECertificate){CFDataGetBytePtr(der), (size_t)CFDataGetLength(der)}, context);
        CFRelease(der);
    }
}
bool SVIKEEnumerateAnchors(SVIKEAnchor visit, void *context) {
    CFArrayRef roots = NULL;
#ifdef SIMPLEVPN_IPSEC_FIXTURE
    roots = isolated_anchors();
    if (!roots)
        return false;
#else
    if (SecTrustCopyAnchorCertificates(&roots) != errSecSuccess || !roots)
        return false;
#endif
    visit_anchors(roots, visit, context);
    CFRelease(roots);
#ifndef SIMPLEVPN_IPSEC_FIXTURE
    // Enterprise/user anchors are candidates. SecTrust must independently
    // authorize the resulting path, including user/admin distrust decisions.
    SecTrustSettingsDomain domains[] = {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin};
    for (size_t i = 0; i < 2; i++) {
        CFArrayRef extra = NULL;
        if (SecTrustSettingsCopyCertificates(domains[i], &extra) == errSecSuccess && extra) {
            visit_anchors(extra, visit, context);
            CFRelease(extra);
        }
    }
#endif
    return true;
}
bool SVIKEVerifyGateway(const char *hostname, const SVIKECertificate *chain, size_t n) {
    if (!hostname || !n || n > 16)
        return false;
    bool ok = false;
    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFStringRef name = NULL;
    CFDictionaryRef properties = NULL;
    SecPolicyRef policy = NULL;
    SecTrustRef trust = NULL;
    if (!certs)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!chain[i].bytes || !chain[i].size || chain[i].size > 1024 * 1024)
            goto out;
        CFDataRef der = CFDataCreate(NULL, chain[i].bytes, chain[i].size);
        if (!der)
            goto out;
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, der);
        CFRelease(der);
        if (!cert)
            goto out;
        CFArrayAppendValue(certs, cert);
        CFRelease(cert);
    }
    name = CFStringCreateWithCString(NULL, hostname, kCFStringEncodingUTF8);
    if (!name)
        goto out;
    const void *key = kSecPolicyName;
    properties = CFDictionaryCreate(NULL, &key, (const void **)&name, 1, &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
    if (!properties)
        goto out;
    policy = SecPolicyCreateWithProperties(kSecPolicyAppleIPSecServer, properties);
    if (!policy || SecTrustCreateWithCertificates(certs, policy, &trust) != errSecSuccess || !trust)
        goto out;
#ifdef SIMPLEVPN_IPSEC_FIXTURE
    CFArrayRef roots = isolated_anchors();
    if (!roots)
        goto out;
    OSStatus anchored = SecTrustSetAnchorCertificates(trust, roots);
    CFRelease(roots);
    if (anchored != errSecSuccess || SecTrustSetAnchorCertificatesOnly(trust, true) != errSecSuccess)
        goto out;
#endif
#ifdef SIMPLEVPN_IPSEC_FIXTURE
    CFErrorRef error = NULL;
    ok = SecTrustEvaluateWithError(trust, &error);
    if (error) {
        CFShow(error);
        CFRelease(error);
    }
#else
    ok = SecTrustEvaluateWithError(trust, NULL);
#endif
out:
    if (trust)
        CFRelease(trust);
    if (policy)
        CFRelease(policy);
    if (properties)
        CFRelease(properties);
    if (name)
        CFRelease(name);
    CFRelease(certs);
    return ok;
}
