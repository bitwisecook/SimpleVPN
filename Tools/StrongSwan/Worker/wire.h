// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "../SVIPsecWorker.h"
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
enum { SV_CTL = 3, SV_DATA = 4, SV_MAGIC = 0x53564931, SV_PACKET = 65575 };
typedef struct {
    uint32_t magic, ifindex, version;
    uint16_t port, psk_size, xauth_size, eap_size, ppp_size;
    char gateway[INET6_ADDRSTRLEN], local[1025], remote[1025], xauth[1025], eap[1025], ppp[256];
    uint8_t psk[8192], xauth_secret[8192], eap_secret[8192], ppp_secret[255];
} SVStartFrame;
typedef struct {
    uint32_t magic;
    uint16_t up, mtu, ac, rc, dc;
    char addresses[8][INET6_ADDRSTRLEN], routes[128][INET6_ADDRSTRLEN + 4], dns[8][INET6_ADDRSTRLEN];
} SVStateFrame;
static inline bool sv_write(int fd, const void *buf, size_t size) {
    const uint8_t *p = buf;
    while (size) {
        ssize_t n = send(fd, p, size, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += n;
        size -= n;
    }
    return true;
}
static inline bool sv_read(int fd, void *buf, size_t size) {
    uint8_t *p = buf;
    while (size) {
        ssize_t n = recv(fd, p, size, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += n;
        size -= n;
    }
    return true;
}
static inline bool sv_string(char *dst, size_t capacity, const char *s) {
    if (!s) {
        *dst = 0;
        return true;
    }
    size_t n = strnlen(s, capacity);
    if (n == capacity)
        return false;
    memcpy(dst, s, n + 1);
    return true;
}
static inline bool sv_put_secret(uint8_t *dst, size_t cap, uint16_t *out, const uint8_t *s, size_t n) {
    if (n > cap || (!!n != !!s))
        return false;
    if (n)
        memcpy(dst, s, n);
    *out = (uint16_t)n;
    return true;
}
static inline bool sv_send_packet(int fd, const uint8_t *b, size_t n) {
    return b && n >= 20 && n <= SV_PACKET && send(fd, b, n, MSG_DONTWAIT) == (ssize_t)n;
}
