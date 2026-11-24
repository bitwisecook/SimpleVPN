// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Test-only fixed L2TPv2 responder for one private socketpair. The upstream
// lwIP PPP server performs LCP, MSCHAPv2 and IPCP authentication/negotiation.
// The test succeeds after receiving an actual IPv4/UDP request and sending its
// reply.
#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/pppol2tp.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int carrier, pass, rejected, opened;
static struct netif wire, inner;
static ppp_pcb *session;
static struct udp_pcb *control, *echo;
static ip_addr_t outside;
static uint16_t peer_tunnel, peer_session, next;
static uint16_t u16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static void put(uint8_t *p, unsigned x) {
    p[0] = x >> 8;
    p[1] = x;
}
u32_t sys_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
unsigned lwip_port_rand(void) { return arc4random(); }

static err_t wire_out(struct netif *n, struct pbuf *p, const ip4_addr_t *dest) {
    uint8_t buf[4096];
    if (p->tot_len > sizeof(buf) || pbuf_copy_partial(p, buf, p->tot_len, 0) != p->tot_len)
        return ERR_BUF;
    return send(carrier, buf, p->tot_len, 0) == p->tot_len ? ERR_OK : ERR_IF;
}
static err_t wire_init(struct netif *n) {
    n->output = wire_out;
    n->mtu = 1500;
    n->name[0] = 'e';
    n->name[1] = 's';
    return ERR_OK;
}
static void send_udp(struct udp_pcb *sock, struct netif *n, const ip_addr_t *dest, unsigned port,
                     const uint8_t *buf, size_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p || pbuf_take(p, buf, len) != ERR_OK || udp_sendto_if(sock, p, dest, port, n) != ERR_OK)
        abort();
    pbuf_free(p);
}
static void ctrl_reply(uint16_t msg, uint16_t sid, uint16_t nr) {
    uint8_t b[80] = {0};
    int n = 12;
    put(b, 0xc802);
    put(b + 4, peer_tunnel);
    put(b + 6, sid);
    put(b + 8, next);
    put(b + 10, nr);
    if (msg) {
        next++;
        put(b + n, 0x8008);
        put(b + n + 6, msg);
        n += 8;
        put(b + n, 0x8008);
        put(b + n + 4, msg == 2 ? 9 : 14);
        put(b + n + 6, msg == 2 ? 17 : 19);
        n += 8;
        if (msg == 2) {
            put(b + n, 0x8008);
            put(b + n + 4, 2);
            put(b + n + 6, 0x0100);
            n += 8;
            put(b + n, 0x800a);
            put(b + n + 4, 3);
            put(b + n + 8, 3);
            n += 10;
            put(b + n, 0x800d);
            put(b + n + 4, 7);
            memcpy(b + n + 6, "fixture", 7);
            n += 13;
        }
    }
    put(b + 2, n);
    send_udp(control, &wire, &outside, 1701, b, n);
}
static void received_control(void *ctx, struct udp_pcb *sock, struct pbuf *p, const ip_addr_t *ip,
                             u16_t port) {
    uint8_t b[2048];
    int n = p->tot_len;
    if (port != 1701 || n < 6 || n > sizeof(b) || pbuf_copy_partial(p, b, n, 0) != n) {
        pbuf_free(p);
        return;
    }
    pbuf_free(p);
    if (!(u16(b) & 0x8000)) {
        if (u16(b) != 2 || u16(b + 2) != 17 || u16(b + 4) != 19 || !session)
            return;
        struct pbuf *q = pbuf_alloc(PBUF_RAW, n - 6, PBUF_RAM);
        if (!q)
            abort();
        pbuf_take(q, b + 6, n - 6);
        ppp_input(session, q);
        return;
    }
    if (n < 20 || u16(b) != 0xc802 || u16(b + 2) != n)
        return;
    uint16_t msg = 0, nr = u16(b + 8) + 1;
    for (int i = 12; i < n;) {
        if (i + 6 > n)
            return;
        int z = u16(b + i) & 0x3ff;
        if (z < 6 || i + z > n)
            return;
        if (z == 8 && u16(b + i + 2) == 0) {
            uint16_t a = u16(b + i + 4), v = u16(b + i + 6);
            if (a == 0)
                msg = v;
            else if (a == 9)
                peer_tunnel = v;
            else if (a == 14)
                peer_session = v;
        }
        i += z;
    }
    if (msg == 1)
        ctrl_reply(2, 0, nr);
    if (msg == 10)
        ctrl_reply(11, peer_session, nr);
    if (msg == 12) {
        ctrl_reply(0, 0, nr);
        if (!opened) {
            opened = 1;
            ppp_listen(session);
        }
    }
}
static void emit_data(const uint8_t *data, int n) {
    uint8_t b[2048];
    if (n > 2042)
        abort();
    put(b, 2);
    put(b + 2, peer_tunnel);
    put(b + 4, peer_session);
    memcpy(b + 6, data, n);
    send_udp(control, &wire, &outside, 1701, b, n + 6);
}
static err_t p_write(ppp_pcb *s, void *ctx, struct pbuf *p) {
    uint8_t b[2048];
    if (p->tot_len < 4 || p->tot_len > sizeof(b))
        abort();
    int n = pbuf_copy_partial(p, b, p->tot_len, 0);
    pbuf_free(p);
    emit_data(b + 2, n - 2);
    return ERR_OK;
}
static err_t p_ip(ppp_pcb *s, void *ctx, struct pbuf *p, u_short proto) {
    uint8_t b[2048];
    if (p->tot_len > 2040)
        abort();
    put(b, proto);
    int n = pbuf_copy_partial(p, b + 2, p->tot_len, 0);
    emit_data(b, n + 2);
    return ERR_OK;
}
static void initiate_ppp(ppp_pcb *p, void *ctx) { ppp_start(p); }
static void down_ppp(ppp_pcb *p, void *ctx) { ppp_link_end(p); }
static err_t free_ppp(ppp_pcb *p, void *ctx) { return ERR_OK; }
static const struct link_callbacks link_ops = {.listen = initiate_ppp,
                                               .disconnect = down_ppp,
                                               .free = free_ppp,
                                               .write = p_write,
                                               .netif_output = p_ip};
static void got_echo(void *ctx, struct udp_pcb *u, struct pbuf *p, const ip_addr_t *ip, u16_t port) {
    uint8_t b[4];
    const char *want = "PING";
    if (p->tot_len == 4 && pbuf_copy_partial(p, b, 4, 0) == 4 && !memcmp(b, want, 4)) {
        send_udp(echo, &inner, ip, port, (const uint8_t *)"PONG", 4);
        pass = 1;
    }
    pbuf_free(p);
}
static void status(ppp_pcb *p, int error, void *ctx) {
    if (error) {
        fprintf(stderr, "PPP down %d\n", error);
        rejected = error == PPPERR_AUTHFAIL;
        return;
    }
    const char *expected = "198.51.100.1";
    if (strcmp(ip4addr_ntoa(netif_ip4_addr(&inner)), expected))
        abort();
}
int main(int argc, char **argv) {
    int bad = !strcmp(argv[1], "wrong-user");
    int no_auth = !strcmp(argv[1], "no-ppp-auth");
    carrier = atoi(getenv("INNER_FD"));
    lwip_init();
    ipaddr_aton("127.0.0.1", &outside);
    ip4_addr_t mask;
    ip4addr_aton("255.0.0.0", &mask);
    if (!netif_add(&wire, &outside, &mask, IP4_ADDR_ANY, NULL, wire_init, ip4_input))
        abort();
    netif_set_up(&wire);
    netif_set_link_up(&wire);
    netif_set_default(&wire);
    echo = udp_new();
    if (!echo || udp_bind(echo, IP_ADDR_ANY, 4021))
        abort();
    udp_recv(echo, got_echo, NULL);
    {
        control = udp_new();
        if (!control || udp_bind(control, IP_ADDR_ANY, 1701))
            abort();
        udp_recv(control, received_control, NULL);
        session = ppp_new(&inner, &link_ops, NULL, status, NULL);
        if (!session)
            abort();
        ip4_addr_t addr;
        ip4addr_aton("198.51.100.1", &addr);
        ppp_set_ipcp_ouraddr(session, &addr);
        ip4addr_aton("198.51.100.2", &addr);
        ppp_set_ipcp_hisaddr(session, &addr);
        ip4addr_aton("192.0.2.53", &addr);
        ppp_set_ipcp_dnsaddr(session, 0, &addr);
        ppp_set_auth_required(session, !no_auth);
    }
    ppp_set_auth(session, no_auth ? PPPAUTHTYPE_NONE : PPPAUTHTYPE_MSCHAP_V2, "fixture",
                 "right-password");
    u32_t start = sys_now();
    while (!pass && !rejected && sys_now() - start < 10000) {
        struct pollfd fd = {carrier, POLLIN, 0};
        if (poll(&fd, 1, 10) > 0) {
            uint8_t buf[4096];
            ssize_t n = recv(carrier, buf, sizeof(buf), 0);
            if (n <= 0)
                return 1;
            struct pbuf *p = pbuf_alloc(PBUF_RAW, n, PBUF_RAM);
            if (!p)
                abort();
            pbuf_take(p, buf, n);
            ip4_input(p, &wire);
        }
        sys_check_timeouts();
    }
    fprintf(stderr, "L2TP fixture %s %s\n", argv[1],
            pass       ? "passed"
            : rejected ? "denied"
                       : "timed out");
    return bad ? !rejected : !pass;
}
u32_t sys_jiffies(void) { return sys_now(); }

int sv_l2tp_inner_input(struct pbuf *p, struct netif *n) { return 0; }
