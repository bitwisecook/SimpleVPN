// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Two separate loopback-only processes each run the same real IKE/ESP engine.
// The responder fixture supplies one private configuration payload address.
#ifndef SIMPLEVPN_IPSEC_FIXTURE
#define SIMPLEVPN_IPSEC_FIXTURE
#endif
#include "engine.c"
#include <poll.h>
#include <unistd.h>
static peer_cfg_t *peer_config;
static bool server, dual_stack, l2tp_test;
static int l2tp_fd = -1;
static atomic_bool authenticated, failed;
static atomic_uint received;
static const uint8_t four_request[] = {69,  0,   0, 32, 0, 1,   0,  0,   64, 17, 142,
                                       137, 192, 0, 2,  8, 198, 51, 100, 7,  15, 160,
                                       20,  180, 0, 12, 0, 0,   86, 80,  78, 33};
static const uint8_t four_reply[] = {69,  0,   0,  32,  0, 1,   0,  0,  64, 17, 142,
                                     137, 198, 51, 100, 7, 192, 0,  2,  8,  15, 160,
                                     20,  180, 0,  12,  0, 0,   86, 80, 78, 33};
static const uint8_t six_request[] = {96,  0,   0,   0,  0,   12, 17, 64,  32,  1,  13, 184, 255,
                                      255, 0,   0,   0,  0,   0,  0,  0,   0,   0,  8,  32,  1,
                                      13,  184, 0,   1,  0,   0,  0,  0,   0,   0,  0,  0,   0,
                                      7,   15,  160, 20, 180, 0,  12, 219, 142, 86, 80, 78,  33};
static const uint8_t six_reply[] = {96, 0,   0,   0,   0,   12, 17, 64,  32,  1,  13, 184, 0,
                                    1,  0,   0,   0,   0,   0,  0,  0,   0,   0,  7,  32,  1,
                                    13, 184, 255, 255, 0,   0,  0,  0,   0,   0,  0,  0,   0,
                                    8,  15,  160, 20,  180, 0,  12, 219, 142, 86, 80, 78,  33};

static const uint8_t ppp_request[] = {69, 0,   0,  32,  0, 1,   0,  0,   64, 17, 38,
                                      98, 198, 51, 100, 2, 198, 51, 100, 1,  15, 181,
                                      15, 181, 0,  12,  0, 0,   80, 73,  78, 71};
static unsigned expected_families(void) { return dual_stack ? 3 : 1; }
static void echo_data(void *u, const uint8_t *p, size_t n) {
    if (l2tp_test) {
        if (server) {
            if (send(l2tp_fd, p, n, 0) != (ssize_t)n)
                abort();
        } else if (n == 32 && !memcmp(p + 12, ppp_request + 16, 4) &&
                   !memcmp(p + 16, ppp_request + 12, 4) && !memcmp(p + 20, ppp_request + 20, 6) &&
                   !memcmp(p + 28, "PONG", 4))
            atomic_store(&received, 1);
        return;
    }
    const uint8_t *request, *reply;
    unsigned family;
    if (n == sizeof(four_request)) {
        request = four_request;
        reply = four_reply;
        family = 1;
    } else if (dual_stack && n == sizeof(six_request)) {
        request = six_request;
        reply = six_reply;
        family = 2;
    } else
        return;
    const char *marker = getenv("FIXTURE_MEMBER_MARK");
    if (server && marker && family==1) {
        if (memcmp(p,request,n-1) || p[n-1]!=(uint8_t)*marker) return;
        chunk_t copy=chunk_clone(chunk_create((uint8_t*)reply,n));
        copy.ptr[n-1]=*marker;
        ip_packet_t *answer=ip_packet_create(copy);
        if(answer) ipsec->processor->queue_outbound(ipsec->processor,answer);
        return;
    }
    if (memcmp(p, server ? request : reply, n))
        return;
    if (server) {
        ip_packet_t *answer = ip_packet_create(chunk_clone(chunk_create((uint8_t *)reply, n)));
        if (!answer)
            return;
        ipsec->processor->queue_outbound(ipsec->processor, answer);
    }
    atomic_fetch_or(&received, family);
}
static void state_change(void *u, int up, const char *const *addrs, size_t ac, const char *const *routes,
                         size_t rc, const char *const *dns_ips, size_t dc) {
    if (!server && !up)
        atomic_store(&failed, true);
    if (l2tp_test) {
        if (!server && up && ac == 1 && rc == 1 && dc == 1 && !strcmp(dns_ips[0], "192.0.2.53") &&
            !strcmp(addrs[0], "198.51.100.2") && !strcmp(routes[0], "0.0.0.0/0"))
            atomic_store(&authenticated, true);
        return;
    }
    unsigned addresses = 0, routed = 0;
    for (size_t i = 0; i < ac; i++) {
        if (!strcmp(addrs[i], "192.0.2.8"))
            addresses |= 1;
        if (!strcmp(addrs[i], "2001:db8:ffff::8"))
            addresses |= 2;
    }
    for (size_t i = 0; i < rc; i++) {
        if (!strcmp(routes[i], "0.0.0.0/0"))
            routed |= 1;
        if (!strcmp(routes[i], "::/0"))
            routed |= 2;
    }
    if (!server && up && (addresses & routed) == expected_families())
        atomic_store(&authenticated, true);
}
static bool server_child(listener_t *l, ike_sa_t *s, child_sa_t *c, bool up) {
    atomic_store(&ready, up);
    if (up) atomic_store(&authenticated, true);
    return true;
}
static enumerator_t *get_peer(backend_t *b, identification_t *l, identification_t *r) {
    return enumerator_create_single(peer_config, NULL);
}
static enumerator_t *get_ike(backend_t *b, host_t *l, host_t *r) {
    return enumerator_create_single(peer_config->get_ike_cfg(peer_config), NULL);
}
static peer_cfg_t *get_named(backend_t *b, char *name) {
    return streq(name, "simplevpn") ? peer_config->get_ref(peer_config) : NULL;
}
static backend_t backend = {.create_peer_cfg_enumerator = get_peer,
                            .create_ike_cfg_enumerator = get_ike,
                            .get_peer_cfg_by_name = get_named};
static host_t *assign_ip(attribute_provider_t *p, linked_list_t *pools, ike_sa_t *s, host_t *request) {
    return request->get_family(request) == AF_INET ? host_create_from_string("192.0.2.8", 0)
           : dual_stack                            ? host_create_from_string("2001:db8:ffff::8", 0)
                                                   : NULL;
}
static attribute_provider_t pool = {.acquire_address = assign_ip,
                                    .release_address = (void *)return_true,
                                    .create_attribute_enumerator = (void *)enumerator_create_empty};
// Exercise an actual CREATE_CHILD_SA rekey before the first data packets.
static bool rekey_child(void) {
    ike_sa_manager_t *manager = charon->ike_sa_manager;
    ike_sa_t *sa = manager->checkout_by_name(manager, "simplevpn", false);
    if (!sa)
        return false;
    uint32_t previous = atomic_load(&active_child);
    enumerator_t *e = sa->create_child_sa_enumerator(sa);
    child_sa_t *child;
    uint32_t spi = 0;
    while (e->enumerate(e, &child))
        if (child->get_unique_id(child) == previous) {
            spi = child->get_spi(child, true);
            break;
        }
    e->destroy(e);
    status_t status = spi ? sa->rekey_child_sa(sa, PROTO_ESP, spi) : FAILED;
    manager->checkin(manager, sa);
    if (status != SUCCESS)
        return false;
    for (int i = 0; i < 40; i++) {
        if (atomic_load(&active_child) != previous)
            return atomic_load(&ready);
        usleep(50000);
    }
    return false;
}
int main(int argc, char **argv) {
#ifndef SIMPLEVPN_IPSEC_UDP_FIXTURE
    fixture_fd = atoi(getenv("PEER_FD"));
#endif
    if (argc != 3)
        return 1;
    server = streq(argv[1], "server");
    bool wrong = streq(argv[1], "wrong"), wrongid = streq(argv[1], "wrong-id"),
         wronguser = streq(argv[1], "wrong-user");
    bool denied =
        wrong || wrongid || wronguser || streq(argv[1], "untrusted") || streq(argv[1], "no-ppp-auth");
    bool eap = streq(argv[2], "eap"), xauth = streq(argv[2], "xauth"),
         v1 = xauth || streq(argv[2], "v1");
    l2tp_test = streq(argv[2], "l2tp");
    if (l2tp_test)
        v1 = true;
    dual_stack = !v1;
    SVIKEConfig c = {
        .gateway = "127.0.0.1",
        .local_id = server ? "@gateway.test" : "@client.test",
        .remote_id = server    ? "@client.test"
                     : wrongid ? "@other.test"
                               : "@gateway.test",
        .shared_secret = (const uint8_t *)(wrong ? "fixture-other-secret" : "fixture-right-secret"),
        .shared_secret_length = 20,
        .remote_port = getenv("FIXTURE_PORT") ? atoi(getenv("FIXTURE_PORT")) : 4500,
        .version = v1 ? 1 : 2,
        .xauth_user = xauth ? "staff" : NULL,
        .xauth_password = xauth ? (const uint8_t *)(wronguser ? "bad-password" : "my-password") : NULL,
        .xauth_password_length = xauth ? (wronguser ? 12 : 11) : 0};
    if (eap) {
        c.shared_secret = NULL;
        c.shared_secret_length = 0;
        c.eap_user = "staff";
        c.eap_password = (const uint8_t *)(wronguser ? "bad-password" : "my-password");
        c.eap_password_length = wronguser ? 12 : 11;
    }
    SVIKECallbacks cb = {state_change, echo_data};
    uint64_t own;
    if (server) {
        if (!boot(0, eap, cb, NULL))
            return 2;
        if (eap) {
            certificate_t *cert =
                lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509, BUILD_FROM_FILE,
                                   getenv("FIXTURE_SERVER_CERT"), BUILD_END);
            private_key_t *key =
                lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, BUILD_FROM_FILE,
                                   getenv("FIXTURE_SERVER_KEY"), BUILD_END);
            if (!cert || !key || !SVIKEEnumerateAnchors(add_trust_anchor, NULL))
                return 2;
            credentials->add_cert(credentials, false, cert);
            credentials->add_key(credentials, key);
        }
        if (l2tp_test) {
            l2tp_fd = atoi(getenv("L2TP_FD"));
            l2tp_carrier = true;
        }
        listener.child_updown = server_child;
        child_cfg_t *child;
        peer_config = configure_peer(&c, true, charon->socket->get_port(charon->socket, true), &child);
        configured_peer = peer_config->get_ref(peer_config);
        child->destroy(child);
        charon->backends->add_backend(charon->backends, &backend);
        charon->attributes->add_provider(charon->attributes, &pool);
        charon->start(charon);
        handle = own = 1;
        printf("READY %u\n", charon->socket->get_port(charon->socket, true));
        fflush(stdout);
    } else {
        if (l2tp_test) {
            const char *pass = wronguser ? "wrong-ppp" : "right-password";
            own = SVL2TPStart(&c, "fixture", (const uint8_t *)pass, strlen(pass), cb, NULL);
        } else
            own = SVIKEStart(&c, cb, NULL);
        if (!own)
            return 3;
    }
    bool require_rekey = !server && !denied && dual_stack;
    for (int i = 0; i < 100 && atomic_load(&received) != expected_families(); i++) {
        if (server && l2tp_test && atomic_load(&ready)) {
            uint8_t packet[4096];
            ssize_t n;
            while ((n = recv(l2tp_fd, packet, sizeof(packet), MSG_DONTWAIT)) > 0)
                if (!SVIKESend(own, packet, n))
                    abort();
        }
        if (!server && atomic_load(&authenticated)) {
            if (l2tp_test) {
                if (SVL2TPMTU(own) != 1360 || !SVIKESend(own, ppp_request, sizeof(ppp_request)))
                    abort();
                usleep(10000);
                continue;
            }
            if (require_rekey) {
                if (!rekey_child())
                    return 4;
                require_rekey = false;
            }
            SVIKESend(own, four_request, sizeof(four_request));
            if (dual_stack)
                SVIKESend(own, six_request, sizeof(six_request));
        }
        usleep(100000);
        if (denied && atomic_load(&failed))
            break;
    }
    // Receipt at the echo server only queues the reply for the ESP worker.
    // Keep its association alive until the test driver confirms the client
    // actually received the reply. Independently tearing down both peers here
    // made this test depend on the workers' relative execution speeds.
    if (server && getenv("FIXTURE_WAIT_FOR_CLIENT")) {
        struct pollfd done={STDIN_FILENO,POLLIN,0};
        char byte;
        if (poll(&done,1,15000)<=0 || read(STDIN_FILENO,&byte,1)!=1) return 1;
    }
    bool pass = denied ? atomic_load(&failed) && !atomic_load(&authenticated) && !atomic_load(&received)
                       : atomic_load(&authenticated) && atomic_load(&received) == expected_families();
    if (server) {
        charon->backends->remove_backend(charon->backends, &backend);
        charon->attributes->remove_provider(charon->attributes, &pool);
        peer_config->destroy(peer_config);
    }
    SVIKEStop(own);
    if (!server && l2tp_test && !denied && pass) {
        // Same extension process may reopen a stopped profile. Old pumps must
        // never be accepted, including during the next IKE/PPP handshake.
        for (int i=0;i<3;i++) {
            uint64_t next=SVL2TPStart(&c,"fixture",(const uint8_t*)"right-password",14,cb,NULL);
            if (!next || next==own || SVIKESend(own,ppp_request,sizeof(ppp_request)) || SVL2TPMTU(own))
                pass=false;
            SVIKEStop(next);
        }
    }
    fprintf(stderr, "fixture %s %s\n",
            server  ? "server"
            : wrong ? "wrong"
                    : "client",
            pass ? "passed" : "failed");
    return pass ? 0 : 1;
}
