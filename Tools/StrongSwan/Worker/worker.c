// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "wire.h"
#include <poll.h>
#include <stdlib.h>
// One member owns one charon/libipsec instance. State messages are reliable and
// bounded; packet backpressure drops datagrams without stalling the ESP workers.
typedef struct {
    pthread_mutex_t lock;
    uint64_t session;
    SVStateFrame pending;
    bool has_pending, started;
} Child;
static void publish(Child *c, SVStateFrame *state) {
    state->mtu = state->up ? SVL2TPMTU(c->session) : 0;
    if (!sv_write(SV_CTL, state, sizeof(*state)))
        shutdown(SV_CTL, SHUT_RDWR);
}
static void changed(void *arg, int up, const char *const *a, size_t ac, const char *const *r, size_t rc,
                    const char *const *d, size_t dc) {
    Child *c = arg;
    SVStateFrame s = {.magic = SV_MAGIC};
    bool ok = up && ac <= 8 && rc <= 128 && dc <= 8 && ac && rc;
    for (size_t i = 0; ok && i < ac; i++)
        ok = sv_string(s.addresses[i], sizeof(s.addresses[i]), a[i]);
    for (size_t i = 0; ok && i < rc; i++)
        ok = sv_string(s.routes[i], sizeof(s.routes[i]), r[i]);
    for (size_t i = 0; ok && i < dc; i++)
        ok = sv_string(s.dns[i], sizeof(s.dns[i]), d[i]);
    if (ok) {
        s.up = 1;
        s.ac = ac;
        s.rc = rc;
        s.dc = dc;
    }
    pthread_mutex_lock(&c->lock);
    if (c->started)
        publish(c, &s);
    else {
        c->pending = s;
        c->has_pending = true;
    }
    pthread_mutex_unlock(&c->lock);
}
static void packet(void *ctx, const uint8_t *b, size_t n) { sv_send_packet(SV_DATA, b, n); }
static bool legal(const SVStartFrame *s) {
    return s->magic == SV_MAGIC && s->ifindex && s->version <= 2 && s->psk_size <= sizeof(s->psk) &&
           s->xauth_size <= sizeof(s->xauth_secret) && s->eap_size <= sizeof(s->eap_secret) &&
           s->ppp_size <= sizeof(s->ppp_secret) && !s->gateway[sizeof(s->gateway) - 1] &&
           !s->local[sizeof(s->local) - 1] && !s->remote[sizeof(s->remote) - 1] &&
           !s->xauth[sizeof(s->xauth) - 1] && !s->eap[sizeof(s->eap) - 1] && !s->ppp[sizeof(s->ppp) - 1];
}
int SVWorkerMain(void) {
    SVStartFrame s = {0};
    if (!sv_read(SV_CTL, &s, sizeof(s)) || !legal(&s)) {
        memset_s(&s, sizeof(s), 0, sizeof(s));
        return 1;
    }
    SVIKEConfig config = {.gateway = s.gateway,
                          .local_id = s.local,
                          .remote_id = s.remote,
                          .version = s.version,
                          .remote_port = s.port,
                          .shared_secret = s.psk_size ? s.psk : NULL,
                          .shared_secret_length = s.psk_size,
                          .xauth_user = *s.xauth ? s.xauth : NULL,
                          .xauth_password = s.xauth_size ? s.xauth_secret : NULL,
                          .xauth_password_length = s.xauth_size,
                          .eap_user = *s.eap ? s.eap : NULL,
                          .eap_password = s.eap_size ? s.eap_secret : NULL,
                          .eap_password_length = s.eap_size};
    Child c = {.lock = PTHREAD_MUTEX_INITIALIZER};
    SVIKECallbacks cb = {changed, packet};
    uint64_t session =
        *s.ppp ? SVL2TPStartBound(&config, s.ppp, s.ppp_secret, s.ppp_size, s.ifindex, cb, &c)
               : SVIKEStartBound(&config, s.ifindex, cb, &c);
    memset_s(&s, sizeof(s), 0, sizeof(s));
    if (!session)
        return 2;
    pthread_mutex_lock(&c.lock);
    c.session = session;
    c.started = true;
    if (c.has_pending)
        publish(&c, &c.pending);
    pthread_mutex_unlock(&c.lock);
    uint8_t bytes[SV_PACKET];
    struct pollfd fds[] = {{SV_CTL, POLLIN, 0}, {SV_DATA, POLLIN, 0}};
    while (true) {
        int n = poll(fds, 2, -1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || fds[0].revents || fds[1].revents & (POLLERR | POLLNVAL | POLLHUP))
            break;
        if (fds[1].revents & POLLIN) {
            ssize_t k = recv(SV_DATA, bytes, sizeof(bytes), 0);
            if (k <= 0)
                break;
            SVIKESend(session, bytes, k);
        }
    }
    SVIKEStop(session);
    pthread_mutex_destroy(&c.lock);
    return 0;
}
