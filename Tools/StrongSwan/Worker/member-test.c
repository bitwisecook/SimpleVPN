// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "../SVIPsecWorker.h"
#include <stdatomic.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
typedef struct {
    uint8_t marker;
    atomic_bool up;
    atomic_uint replies;
} Echo;
static void state(void *ctx, int up, const char *const *a, size_t ac, const char *const *r, size_t rc,
                  const char *const *d, size_t dc) {
    Echo *e = ctx;
    if (up && (ac != 1 || rc != 1 || strcmp(a[0], "192.0.2.8") || strcmp(r[0], "0.0.0.0/0")))
        abort();
    atomic_store(&e->up, up);
}
static void packet(void *ctx, const uint8_t *p, size_t n) {
    Echo *e = ctx;
    if (n != 32 || p[31] != e->marker || p[12] != 198 || p[16] != 192)
        abort();
    atomic_fetch_add(&e->replies, 1);
}
static bool exchange(uint64_t member, Echo *e) {
    uint8_t p[] = {69,  0,  0,   32, 0,  1,   0,  0,   64, 17, 142, 137, 192, 0,  2,  8,
                   198, 51, 100, 7,  15, 160, 20, 180, 0,  12, 0,   0,   86,  80, 78, e->marker};
    unsigned prior = atomic_load(&e->replies);
    for (int i = 0; i < 150; i++) {
        if (atomic_load(&e->up) && i % 10 == 0)
            SVWorkerSend(member, p, sizeof(p));
        if (atomic_load(&e->replies) > prior)
            return true;
        usleep(20000);
    }
    return false;
}
int main(int argc, char **argv) {
    if (argc != 4)
        return 1;
    unsigned idx = if_nametoindex("lo0");
    if (!idx)
        return 2;
    Echo e[2] = {{.marker = 'A'}, {.marker = 'B'}};
    uint64_t w[2] = {0};
    SVIKEConfig c = {.version = 1,
                     .gateway = "127.0.0.1",
                     .local_id = "@client.test",
                     .remote_id = "@gateway.test",
                     .shared_secret = (const uint8_t *)"fixture-right-secret",
                     .shared_secret_length = 20};
    SVIKECallbacks cb = {state, packet};
    bool ok = true;
    // The wire representation reserves an empty username for an absent
    // optional mode. Reject it at the API boundary instead of selecting PSK.
    SVIKEConfig empty_method=c;
    empty_method.eap_user="";
    if (SVWorkerStart(argv[1],&empty_method,NULL,NULL,0,idx,cb,&e[0]))return 3;
    if (SVWorkerStart("/usr/bin/true", &c, NULL, NULL, 0, idx, cb, &e[0]))
        return 3;
    for (int i = 0; i < 2; i++) {
        c.remote_port = atoi(argv[i + 2]);
        w[i] = SVWorkerStart(argv[1], &c, NULL, NULL, 0, idx, cb, &e[i]);
        ok = ok && w[i];
    }
    ok = ok && w[0] != w[1] && exchange(w[0], &e[0]) && exchange(w[1], &e[1]);
    SVWorkerStop(w[0]);
    ok = ok && exchange(w[1], &e[1]);
    SVWorkerStop(w[1]);
    if (!ok)
        fprintf(stderr, "worker handles %llu/%llu; replies %u/%u\n", w[0], w[1],
                atomic_load(&e[0].replies), atomic_load(&e[1].replies));
    return ok ? 0 : 1;
}
