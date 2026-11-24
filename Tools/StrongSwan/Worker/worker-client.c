// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "wire.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/wait.h>

typedef struct Worker {
    struct Worker *next;
    uint64_t id;
    int ctl, lane;
    pid_t pid;
    pthread_t watcher;
    atomic_bool stopping, up;
    atomic_uint mtu;
    SVIKECallbacks cb;
    void *ctx;
} Worker;
static pthread_mutex_t registry = PTHREAD_MUTEX_INITIALIZER;
static Worker *members;
static uint64_t generation;
static Worker *find_worker(uint64_t id) {
    for (Worker *w = members; w; w = w->next)
        if (w->id == id)
            return w;
    return NULL;
}
static bool signed_worker(pid_t pid) {
    SecCodeRef code = NULL;
    SecRequirementRef req = NULL;
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    if (!number)
        return false;
    const void *keys[] = {kSecGuestAttributePid}, *values[] = {number};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFStringRef requirement =
        CFSTR("anchor apple generic and identifier \"com.bragi0.SimpleVPN.IPsecMemberWorker\" and "
              "certificate leaf[subject.OU] = \"QVUFB5676H\"");
#ifdef SIMPLEVPN_WORKER_FIXTURE
    // This separate test object is never placed in the shipping archive.
    requirement = CFSTR("identifier \"com.bragi0.SimpleVPN.IPsecFixture\"");
#endif
    bool ok = attrs &&
              SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code) == errSecSuccess &&
              SecRequirementCreateWithString(requirement, kSecCSDefaultFlags, &req) == errSecSuccess &&
              SecCodeCheckValidity(code, kSecCSStrictValidate, req) == errSecSuccess;
#ifndef SIMPLEVPN_WORKER_FIXTURE
    CFDictionaryRef info = NULL;
    if (ok) {
        ok = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info;
        CFTypeRef entry = ok ? CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict) : NULL;
        ok = entry && CFGetTypeID(entry) == CFDictionaryGetTypeID();
        if (ok) {
            CFDictionaryRef entitlements = (CFDictionaryRef)entry;
            ok = CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.app-sandbox")) == kCFBooleanTrue &&
                 CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.inherit")) == kCFBooleanTrue;
        }
    }
    if (info) CFRelease(info);
#endif
    if (req)
        CFRelease(req);
    if (code)
        CFRelease(code);
    if (attrs)
        CFRelease(attrs);
    CFRelease(number);
    return ok;
}
static bool sockets(int type, int fds[2]) {
    if (socketpair(AF_UNIX, type, 0, fds))
        return false;
    int n = 256 * 1024, on = 1;
    struct timeval timeout = {.tv_sec = 3};
    for (int i = 0; i < 2; i++) {
        if (setsockopt(fds[i], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) ||
            setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) ||
            setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) ||
            setsockopt(fds[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
            fcntl(fds[i], F_SETFD, FD_CLOEXEC)) {
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            return false;
        }
    }
    return true;
}
static bool launch(Worker *w, const char *path, int child_ctl, int child_lane) {
    // Move sources away from reserved destinations before constructing dup2 actions.
    int ctl = fcntl(child_ctl, F_DUPFD_CLOEXEC, 10), data = fcntl(child_lane, F_DUPFD_CLOEXEC, 10);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;
    bool ac = false, at = false, ok = false;
    if (ctl >= 0 && data >= 0 && !(posix_spawn_file_actions_init(&actions))) {
        ac = true;
        if (!posix_spawnattr_init(&attrs)) {
            at = true;
            char *argv[] = {(char *)path, NULL}, *env[] = {NULL};
            if (!posix_spawnattr_setflags(&attrs,
                                          POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED) &&
                !posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) &&
                !posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) &&
                !posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) &&
                !posix_spawn_file_actions_adddup2(&actions, ctl, SV_CTL) &&
                !posix_spawn_file_actions_adddup2(&actions, data, SV_DATA) &&
                !posix_spawn(&w->pid, path, &actions, &attrs, argv, env)) {
                if (signed_worker(w->pid) && !kill(w->pid, SIGCONT))
                    ok = true;
                else {
                    kill(w->pid, SIGKILL);
                    while (waitpid(w->pid, NULL, 0) < 0 && errno == EINTR) {
                    }
                    w->pid = 0;
                }
            }
        }
    }
    if (at)
        posix_spawnattr_destroy(&attrs);
    if (ac)
        posix_spawn_file_actions_destroy(&actions);
    if (ctl >= 0)
        close(ctl);
    if (data >= 0)
        close(data);
    return ok;
}
static void reap(pid_t pid) {
    // This is our unreaped direct child. Closing the reliable channel requests
    // normal teardown even when the worker has no incoming UDP packets.
    if (pid <= 0)
        return;
    for (int i = 0; i < 200; i++) {
        pid_t done = waitpid(pid, NULL, WNOHANG);
        if (done == pid || (done < 0 && errno == ECHILD))
            return;
        if (i == 100)
            kill(pid, SIGTERM);
        usleep(10000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
}
static bool report(Worker *w, const SVStateFrame *s) {
    if (s->magic != SV_MAGIC || s->up > 1 || s->ac > 8 || s->rc > 128 || s->dc > 8 ||
        (s->up && (!s->rc || !s->ac)))
        return false;
    const char *a[8], *r[128], *d[8];
    for (int i = 0; i < s->ac; i++) {
        if (s->addresses[i][sizeof(s->addresses[i]) - 1])
            return false;
        a[i] = s->addresses[i];
    }
    for (int i = 0; i < s->rc; i++) {
        if (s->routes[i][sizeof(s->routes[i]) - 1])
            return false;
        r[i] = s->routes[i];
    }
    for (int i = 0; i < s->dc; i++) {
        if (s->dns[i][sizeof(s->dns[i]) - 1])
            return false;
        d[i] = s->dns[i];
    }
    atomic_store(&w->mtu, s->mtu);
    atomic_store(&w->up, s->up);
    w->cb.state(w->ctx, s->up, a, s->ac, r, s->rc, d, s->dc);
    return true;
}
static void *watch(void *arg) {
    Worker *w = arg;
    struct pollfd fds[] = {{w->ctl, POLLIN, 0}, {w->lane, POLLIN, 0}};
    uint8_t bytes[SV_PACKET];
    bool notified = false;
    while (!atomic_load(&w->stopping)) {
        int n = poll(fds, 2, -1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (fds[0].revents) {
            SVStateFrame s;
            if (!sv_read(w->ctl, &s, sizeof(s)) || atomic_load(&w->stopping) || !report(w, &s))
                break;
            if (!s.up) {
                notified = true;
                break;
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t count = recv(w->lane, bytes, sizeof(bytes), 0);
            if (count <= 0)
                break;
            if (atomic_load(&w->up) && !atomic_load(&w->stopping))
                w->cb.packet(w->ctx, bytes, (size_t)count);
        }
        if (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL))
            break;
    }
    atomic_store(&w->up, false);
    if (!notified && !atomic_load(&w->stopping))
        w->cb.state(w->ctx, 0, NULL, 0, NULL, 0, NULL, 0);
    shutdown(w->ctl, SHUT_RDWR);
    reap(w->pid);
    return NULL;
}
uint64_t SVWorkerStart(const char *path, const SVIKEConfig *c, const char *user, const uint8_t *password,
                       size_t length, uint32_t ifindex, SVIKECallbacks cb, void *ctx) {
    char interface[IFNAMSIZ];
    if (!path || *path != '/' || !c || !cb.packet || !cb.state || !ifindex ||
        !if_indextoname(ifindex, interface) || !c->gateway || !c->local_id || !c->remote_id ||
        (c->xauth_user && !*c->xauth_user) || (c->eap_user && !*c->eap_user) ||
        c->version < 0 || c->version > 2 || ((!user) != (length == 0)) || (user && !*user))
        return 0;
    SVStartFrame s = {
        .magic = SV_MAGIC, .version = c->version, .port = c->remote_port, .ifindex = ifindex};
    Worker *w = NULL;
    uint64_t result = 0;
    int control[2] = {-1, -1}, lane[2] = {-1, -1};
    if (sv_string(s.gateway, sizeof(s.gateway), c->gateway) &&
        sv_string(s.local, sizeof(s.local), c->local_id) &&
        sv_string(s.remote, sizeof(s.remote), c->remote_id) &&
        sv_string(s.xauth, sizeof(s.xauth), c->xauth_user) &&
        sv_string(s.eap, sizeof(s.eap), c->eap_user) && sv_string(s.ppp, sizeof(s.ppp), user) &&
        sv_put_secret(s.psk, sizeof(s.psk), &s.psk_size, c->shared_secret, c->shared_secret_length) &&
        sv_put_secret(s.xauth_secret, sizeof(s.xauth_secret), &s.xauth_size, c->xauth_password,
                      c->xauth_password_length) &&
        sv_put_secret(s.eap_secret, sizeof(s.eap_secret), &s.eap_size, c->eap_password,
                      c->eap_password_length) &&
        sv_put_secret(s.ppp_secret, sizeof(s.ppp_secret), &s.ppp_size, password, length)) {
        w = calloc(1, sizeof(*w));
        if (w && sockets(SOCK_STREAM, control) && sockets(SOCK_DGRAM, lane)) {
            w->ctl = control[0];
            w->lane = lane[0];
            w->ctx = ctx;
            w->cb = cb;
            if (launch(w, path, control[1], lane[1]) && sv_write(w->ctl, &s, sizeof(s))) {
                // Install and launch under one lock so callbacks queued by the
                // caller can look up the member as soon as Start returns.
                pthread_mutex_lock(&registry);
                if (!pthread_create(&w->watcher, NULL, watch, w)) {
                    if (!++generation)
                        ++generation;
                    w->id = result = generation;
                    w->next = members;
                    members = w;
                }
                pthread_mutex_unlock(&registry);
            }
        }
    }
    memset_s(&s, sizeof(s), 0, sizeof(s));
    if (control[1] >= 0)
        close(control[1]);
    if (lane[1] >= 0)
        close(lane[1]);
    if (!result) {
        if (control[0] >= 0)
            close(control[0]);
        if (lane[0] >= 0)
            close(lane[0]);
        if (w)
            reap(w->pid);
        free(w);
    }
    return result;
}
bool SVWorkerSend(uint64_t id, const uint8_t *p, size_t n) {
    pthread_mutex_lock(&registry);
    Worker *w = find_worker(id);
    bool ok = w && atomic_load(&w->up) && sv_send_packet(w->lane, p, n);
    pthread_mutex_unlock(&registry);
    return ok;
}
uint16_t SVWorkerMTU(uint64_t id) {
    pthread_mutex_lock(&registry);
    Worker *w = find_worker(id);
    uint16_t mtu = w && atomic_load(&w->up) ? atomic_load(&w->mtu) : 0;
    pthread_mutex_unlock(&registry);
    return mtu;
}
void SVWorkerStop(uint64_t id) {
    pthread_mutex_lock(&registry);
    Worker **link = &members;
    while (*link && (*link)->id != id)
        link = &(*link)->next;
    Worker *w = *link;
    if (w) {
        *link = w->next;
        atomic_store(&w->stopping, true);
        shutdown(w->ctl, SHUT_RDWR);
    }
    pthread_mutex_unlock(&registry);
    if (w) {
        pthread_join(w->watcher, NULL);
        close(w->ctl);
        close(w->lane);
        free(w);
    }
}
