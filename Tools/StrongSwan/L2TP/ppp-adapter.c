// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "ppp-adapter.h"
#include <errno.h>
#include <limits.h>
#include <lwip/init.h>
#include <lwip/ip4.h>
#include <lwip/timeouts.h>
#include <netif/ppp/ppp_impl.h>
#include <netif/ppp/pppol2tp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

// The upstream NO_SYS stack is single-owner. Only this thread touches lwIP.
// Separate control and bounded nonblocking datagram queues keep shutdown
// responsive if packet-flow or the ESP worker falls behind.
enum { carrier_up = 1, carrier_down, inner_ip, protected_udp };
struct control {
    uint8_t event, local[4], remote[4];
};
struct SVPPP {
    int control[2], packets[2];
    pthread_t thread;
    atomic_bool stopping, ready, failed;
    atomic_uint mtu;
    struct netif transport, inner;
    ip4_addr_t peer;
    ppp_pcb *ppp;
    bool transport_added;
    char username[256], password[256];
    SVIKECallbacks cb;
    void *context;
    SVPPPOutput output;
};
static SVPPP *owner;
static pthread_once_t once = PTHREAD_ONCE_INIT;
u32_t sys_now(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint32_t)(now.tv_sec * 1000ULL + now.tv_nsec / 1000000);
}
u32_t sys_jiffies(void) { return sys_now(); }
unsigned lwip_port_rand(void) { return arc4random(); }

static bool printable(const uint8_t *p, size_t n) {
    if (!p || !n || n > 255)
        return false;
    for (size_t i = 0; i < n; i++)
        if (p[i] < 32 || p[i] > 126)
            return false;
    return true;
}
static bool valid_ip(const uint8_t *p, size_t n) {
    return n >= 20 && p[0] >> 4 == 4 && (p[0] & 15) >= 5 && (p[0] & 15) * 4u <= n &&
           n == ((size_t)p[2] << 8 | p[3]);
}
static void failed(SVPPP *s) {
    atomic_store(&s->ready, false);
    if (!atomic_exchange(&s->failed, true) && !atomic_load(&s->stopping))
        s->cb.state(s->context, 0, NULL, 0, NULL, 0, NULL, 0);
}

int sv_l2tp_inner_input(struct pbuf *p, struct netif *netif) {
    SVPPP *s = owner;
    if (!s || netif != &s->inner)
        return 0;
    uint8_t storage[2048];
    if (atomic_load(&s->ready) && p->tot_len <= sizeof(storage) &&
        pbuf_copy_partial(p, storage, p->tot_len, 0) == p->tot_len && valid_ip(storage, p->tot_len))
        s->cb.packet(s->context, storage, p->tot_len);
    pbuf_free(p);
    return 1;
}
static err_t transport_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination) {
    SVPPP *s = owner;
    uint8_t storage[2048];
    if (!s || atomic_load(&s->stopping) || p->tot_len > sizeof(storage) ||
        pbuf_copy_partial(p, storage, p->tot_len, 0) != p->tot_len)
        return ERR_IF;
    return s->output(storage, p->tot_len) ? ERR_OK : ERR_IF;
}
static err_t transport_init(struct netif *n) {
    n->output = transport_output;
    n->mtu = 1500;
    n->name[0] = 'e';
    n->name[1] = 's';
    return ERR_OK;
}
static void ppp_status(ppp_pcb *p, int error, void *ctx) {
    SVPPP *s = ctx;
    if (error || atomic_load(&s->stopping) || atomic_load(&s->failed) ||
        !(p->auth_done & CHAP_MS2_WITHPEER) || ip4_addr_isany(netif_ip4_addr(&s->inner)) ||
        !s->inner.mtu || s->inner.mtu < 576) {
        failed(s);
        return;
    }
    char ip[16], dns_text[2][16];
    const char *dns[2];
    size_t count = 0;
    if (!ip4addr_ntoa_r(netif_ip4_addr(&s->inner), ip, sizeof(ip))) {
        failed(s);
        return;
    }
    for (size_t i = 0; i < 2; i++) {
        ip4_addr_t address = {.addr = p->ipcp_gotoptions.dnsaddr[i]};
        if (!ip4_addr_isany(&address) && ip4addr_ntoa_r(&address, dns_text[count], 16)) {
            dns[count] = dns_text[count];
            count++;
        }
    }
    const char *addresses[] = {ip}, *routes[] = {"0.0.0.0/0"};
    atomic_store(&s->mtu, LWIP_MIN(s->inner.mtu, PPPOL2TP_DEFMRU));
    atomic_store(&s->ready, true);
    s->cb.state(s->context, 1, addresses, 1, routes, 1, dns, count);
}
static bool begin(SVPPP *s, const struct control *c) {
    ip4_addr_t local, remote, mask;
    memcpy(&local.addr, c->local, 4);
    memcpy(&remote.addr, c->remote, 4);
    if (s->transport_added)
        return ip4_addr_cmp(&local, netif_ip4_addr(&s->transport)) && ip4_addr_cmp(&remote, &s->peer);
    IP4_ADDR(&mask, 255, 255, 255, 255);
    if (!netif_add(&s->transport, &local, &mask, IP4_ADDR_ANY, NULL, transport_init, ip4_input))
        return false;
    s->transport_added = true;
    s->peer = remote;
    netif_set_up(&s->transport);
    netif_set_link_up(&s->transport);
    netif_set_default(&s->transport);
    s->ppp = pppol2tp_create(&s->inner, &s->transport, &remote, 1701, NULL, 0, ppp_status, s);
    if (!s->ppp)
        return false;
    ppp_set_auth(s->ppp, PPPAUTHTYPE_MSCHAP_V2, s->username, s->password);
    ppp_set_usepeerdns(s->ppp, 1);
    return ppp_connect(s->ppp, 0) == ERR_OK;
}
static void data(SVPPP *s, const uint8_t *b, size_t n) {
    if (!s->ppp || n < 21 || !valid_ip(b + 1, n - 1))
        return;
    bool inner = b[0] == inner_ip;
    if ((inner && (!atomic_load(&s->ready) || n - 1 > atomic_load(&s->mtu))) ||
        (!inner && b[0] != protected_udp))
        return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)(n - 1), PBUF_RAM);
    if (!p)
        return;
    if (pbuf_take(p, b + 1, n - 1) != ERR_OK) {
        pbuf_free(p);
        return;
    }
    if (inner) {
        ip4_addr_t dst;
        memcpy(&dst.addr, b + 17, 4);
        s->inner.output(&s->inner, p, &dst);
        pbuf_free(p);
    } else
        ip4_input(p, &s->transport);
}
static void *run(void *arg) {
    SVPPP *s = arg;
    owner = s;
    pthread_once(&once, lwip_init);
    while (!atomic_load(&s->stopping) && !atomic_load(&s->failed)) {
        struct pollfd fds[] = {{s->control[1], POLLIN, 0}, {s->packets[1], POLLIN, 0}};
        uint32_t wait = sys_timeouts_sleeptime();
        int result =
            poll(fds, 2, wait == SYS_TIMEOUTS_SLEEPTIME_INFINITE ? -1 : (int)LWIP_MIN(wait, INT_MAX));
        if (result < 0 && errno != EINTR) {
            failed(s);
            break;
        }
        if (atomic_load(&s->stopping))
            break;
        if (fds[0].revents) {
            struct control c;
            if (recv(s->control[1], &c, sizeof(c), 0) != sizeof(c) || c.event != carrier_up ||
                !begin(s, &c))
                failed(s);
        }
        if (fds[1].revents && !atomic_load(&s->failed)) {
            uint8_t bytes[2049];
            ssize_t n = recv(s->packets[1], bytes, sizeof(bytes), 0);
            if (n > 0)
                data(s, bytes, (size_t)n);
        }
        sys_check_timeouts();
    }
    atomic_store(&s->ready, false);
    if (s->ppp) {
        if (s->ppp->phase != PPP_PHASE_DEAD) {
            lcp_lowerdown(s->ppp);
            link_terminated(s->ppp);
        }
        ppp_free(s->ppp);
    }
    if (s->transport_added)
        netif_remove(&s->transport);
    owner = NULL;
    return NULL;
}
SVPPP *sv_ppp_new(const char *user, const uint8_t *password, size_t n, SVIKECallbacks cb, void *ctx,
                  SVPPPOutput out) {
    size_t un = user ? strnlen(user, 256) : 0;
    if (!printable((const uint8_t *)user, un) || !printable(password, n) || !out)
        return NULL;
    SVPPP *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    int *q = s->control;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, q)) {
        free(s);
        return NULL;
    }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, s->packets)) {
        close(q[0]);
        close(q[1]);
        free(s);
        return NULL;
    }
    memcpy(s->username, user, un);
    memcpy(s->password, password, n);
    s->cb = cb;
    s->context = ctx;
    s->output = out;
    if (pthread_create(&s->thread, NULL, run, s)) {
        sv_ppp_free(s);
        return NULL;
    }
    return s;
}
static bool control_send(SVPPP *s, const struct control *c) {
    return send(s->control[0], c, sizeof(*c), MSG_DONTWAIT) == sizeof(*c);
}
bool sv_ppp_carrier_up(SVPPP *s, const uint8_t local[4], const uint8_t remote[4]) {
    struct control c = {.event = carrier_up};
    memcpy(c.local, local, 4);
    memcpy(c.remote, remote, 4);
    return control_send(s, &c);
}
void sv_ppp_carrier_down(SVPPP *s) {
    const struct control c = {.event = carrier_down};
    failed(s);
    control_send(s, &c);
}
static bool enqueue(SVPPP *s, uint8_t kind, const uint8_t *b, size_t n) {
    if (!b || n > 2048 || n < 20 || atomic_load(&s->failed) || atomic_load(&s->stopping))
        return false;
    struct iovec iov[] = {{&kind, 1}, {(void *)b, n}};
    struct msghdr msg = {.msg_iov = iov, .msg_iovlen = 2};
    return sendmsg(s->packets[0], &msg, MSG_DONTWAIT) == (ssize_t)n + 1;
}
bool sv_ppp_send(SVPPP *s, const uint8_t *b, size_t n) {
    return atomic_load(&s->ready) && n <= atomic_load(&s->mtu) && enqueue(s, inner_ip, b, n);
}
bool sv_ppp_input(SVPPP *s, const uint8_t *b, size_t n) { return enqueue(s, protected_udp, b, n); }
uint16_t sv_ppp_mtu(SVPPP *s) { return atomic_load(&s->ready) ? (uint16_t)atomic_load(&s->mtu) : 0; }
void sv_ppp_quiesce(SVPPP *s) {
    atomic_store(&s->stopping, true);
    const struct control c = {.event = carrier_down};
    control_send(s, &c);
    pthread_join(s->thread, NULL);
}
void sv_ppp_free(SVPPP *s) {
    close(s->control[0]);
    close(s->control[1]);
    close(s->packets[0]);
    close(s->packets[1]);
    memset_s(s, sizeof(*s), 0, sizeof(*s));
    free(s);
}
