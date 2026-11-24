// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#include "SVIPsec.h"
#include "L2TP/ppp-adapter.h"
#include <daemon.h>
#include <ipsec.h>
#include <eap/eap.h>
#include <plugins/kernel_libipsec/kernel_libipsec_ipsec.h>
#include <credentials/sets/mem_cred.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <net/if.h>

// libcharon and libipsec each have a process-wide singleton. The monotonically
// increasing handle prevents a late pump callback from entering a new session.
static pthread_mutex_t api_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t next_handle, handle;
static bool stopping;
static uint32_t carrier_ifindex;
static bool l2tp_carrier;
static SVPPP *ppp;
static atomic_bool ready;
static SVIKECallbacks callbacks;
static void *context;
static mem_cred_t *credentials;
static peer_cfg_t *configured_peer;
static atomic_uint active_child;
static bool initialized, charon_initialized, ipsec_initialized;
static attribute_handler_t attributes;
static char dns[8][INET6_ADDRSTRLEN];
static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned dns_count;

static bool store_dns(attribute_handler_t *handler, ike_sa_t *sa, configuration_attribute_type_t type,
                      chunk_t data) {
    int family = type == INTERNAL_IP4_DNS ? AF_INET : type == INTERNAL_IP6_DNS ? AF_INET6 : 0;
    if (!family || data.len != (family == AF_INET ? 4 : 16))
        return false;
    pthread_mutex_lock(&dns_lock);
    bool ok = dns_count < countof(dns) && inet_ntop(family, data.ptr, dns[dns_count], sizeof(dns[0]));
    if (ok)
        dns_count++;
    pthread_mutex_unlock(&dns_lock);
    return ok;
}

static void release_dns(attribute_handler_t *handler, ike_sa_t *sa, configuration_attribute_type_t type,
                        chunk_t data) {
    char text[INET6_ADDRSTRLEN];
    int family = type == INTERNAL_IP4_DNS ? AF_INET : type == INTERNAL_IP6_DNS ? AF_INET6 : 0;
    if (!family || data.len != (family == AF_INET ? 4 : 16) ||
        !inet_ntop(family, data.ptr, text, sizeof(text)))
        return;
    pthread_mutex_lock(&dns_lock);
    for (unsigned i = 0; i < dns_count; i++) {
        if (strcmp(text, dns[i]) == 0) {
            if (i + 1 < dns_count)
                memmove(dns[i], dns[i + 1], (dns_count - i - 1) * sizeof(dns[0]));
            dns_count--;
            break;
        }
    }
    pthread_mutex_unlock(&dns_lock);
}

typedef struct {
    enumerator_t public;
    int next;
} dns_request_t;
static bool dns_next(enumerator_t *e, va_list args) {
    dns_request_t *r = (dns_request_t *)e;
    if (r->next == 2)
        return false;
    configuration_attribute_type_t *kind;
    chunk_t *value;
    VA_ARGS_VGET(args, kind, value);
    *kind = r->next++ ? INTERNAL_IP6_DNS : INTERNAL_IP4_DNS;
    *value = chunk_empty;
    return true;
}
static enumerator_t *dns_requests(attribute_handler_t *handler, ike_sa_t *sa, linked_list_t *vips) {
    dns_request_t *r = calloc(1, sizeof(*r));
    if (!r)
        return enumerator_create_empty();
    r->public = (enumerator_t){
        .enumerate = enumerator_enumerate_default, .venumerate = dns_next, .destroy = (void *)free};
    return &r->public;
}

static bool child_update(listener_t *unused, ike_sa_t *sa, child_sa_t *child, bool up) {
    if (sa->get_peer_cfg(sa) != configured_peer)
        return true;
    uint32_t child_id = child->get_unique_id(child);
    if (!up && !atomic_compare_exchange_strong(&active_child, &child_id, 0))
        return true;
    if (ppp) {
        if (up) {
            host_t *local = sa->get_my_host(sa), *remote = sa->get_other_host(sa);
            up = child->get_mode(child) == MODE_TRANSPORT && local->get_family(local) == AF_INET &&
                 remote->get_family(remote) == AF_INET;
            if (up) {
                atomic_store(&active_child, child_id);
                atomic_store(&ready, true);
                up = sv_ppp_carrier_up(ppp, local->get_address(local).ptr,
                                       remote->get_address(remote).ptr);
            }
        }
        if (!up) {
            atomic_store(&ready, false);
            sv_ppp_carrier_down(ppp);
        }
        return true;
    }
    char addresses[8][INET6_ADDRSTRLEN], routes[128][INET6_ADDRSTRLEN + 4], servers[8][INET6_ADDRSTRLEN];
    const char *a[countof(addresses)], *r[countof(routes)], *d[countof(servers)];
    size_t ac = 0, rc = 0, dc = 0;
    if (up) {
        host_t *ip;
        enumerator_t *e = sa->create_virtual_ip_enumerator(sa, true);
        while (e->enumerate(e, &ip)) {
            if (ac == countof(a) || !inet_ntop(ip->get_family(ip), ip->get_address(ip).ptr,
                                               addresses[ac], sizeof(addresses[ac]))) {
                up = false;
                break;
            }
            a[ac] = addresses[ac];
            ac++;
        }
        e->destroy(e);
        traffic_selector_t *ts;
        e = child->create_ts_enumerator(child, false);
        while (up && e->enumerate(e, &ts)) {
            uint8_t width;
            host_t *net = NULL;
            bool exact = ts->to_subnet(ts, &net, &width);
            char addr[INET6_ADDRSTRLEN];
            if (!net || !exact || ts->get_protocol(ts) != 0 || ts->get_from_port(ts) != 0 ||
                ts->get_to_port(ts) != 65535 || rc == countof(r) ||
                !inet_ntop(net->get_family(net), net->get_address(net).ptr, addr, sizeof(addr))) {
                up = false;
            } else {
                snprintf(routes[rc], sizeof(routes[rc]), "%s/%u", addr, width);
                r[rc] = routes[rc];
                rc++;
            }
            DESTROY_IF(net);
        }
        e->destroy(e);
        pthread_mutex_lock(&dns_lock);
        dc = dns_count;
        memcpy(servers, dns, dc * sizeof(dns[0]));
        pthread_mutex_unlock(&dns_lock);
        for (size_t i = 0; i < dc; i++)
            d[i] = servers[i];
        // The provider cannot install an unassigned or selector-less tunnel.
        up = up && ac && rc;
    }
    if (up)
        atomic_store(&active_child, child_id);
    atomic_store(&ready, up);
    callbacks.state(context, up, a, ac, r, rc, d, dc);
    return true;
}
static bool state_update(listener_t *unused, ike_sa_t *sa, ike_sa_state_t state) {
    if (sa->get_peer_cfg(sa) == configured_peer && state == IKE_DESTROYING && !atomic_load(&ready)) {
        if (ppp)
            sv_ppp_carrier_down(ppp);
        else
            callbacks.state(context, 0, NULL, 0, NULL, 0, NULL, 0);
    }
    return true;
}
#include "eap-trust.inc"
static bool child_rekey(listener_t *l, ike_sa_t *sa, child_sa_t *old, child_sa_t *next) {
    uint32_t previous = old->get_unique_id(old);
    if (sa->get_peer_cfg(sa) == configured_peer)
        atomic_compare_exchange_strong(&active_child, &previous, next->get_unique_id(next));
    return true;
}
static listener_t listener = {.child_rekey = child_rekey,
                              .child_updown = child_update,
                              .ike_state_change = state_update,
                              .authorize = approve_peer};

static void plain_in(void *unused, ip_packet_t *p) {
    chunk_t data = p->get_encoding(p);
    if (atomic_load(&ready)) {
        if (ppp)
            sv_ppp_input(ppp, data.ptr, data.len);
        else
            callbacks.packet(context, data.ptr, data.len);
    }
    p->destroy(p);
}
static void esp_out(void *unused, esp_packet_t *p, bool encap) {
    // This callback already runs on the dedicated outbound ESP worker.
    // Sending here keeps ESP out of the asynchronous IKE control-message queue.
    if (encap)
        charon->socket->send(charon->socket, (packet_t *)p);
    p->destroy(p);
}
static void esp_in(void *unused, packet_t *p) {
    ipsec->processor->queue_inbound(ipsec->processor, esp_packet_create_from_packet(p));
}
static bool register_flow(plugin_t *plugin, plugin_feature_t *feature, bool reg, void *unused) {
    if (reg) {
        ipsec->processor->register_inbound(ipsec->processor, plain_in, NULL);
        ipsec->processor->register_outbound(ipsec->processor, esp_out, NULL);
        charon->receiver->add_esp_cb(charon->receiver, esp_in, NULL);
    } else {
        charon->receiver->del_esp_cb(charon->receiver, esp_in);
        ipsec->processor->unregister_inbound(ipsec->processor, plain_in);
        ipsec->processor->unregister_outbound(ipsec->processor, esp_out);
    }
    return true;
}
static void shutdown_engine(void) {
    atomic_store(&ready, false);
    // Drain PPP's outgoing work while its upstream SA database is still valid.
    if (ppp)
        sv_ppp_quiesce(ppp);
    if (credentials)
        lib->credmgr->remove_set(lib->credmgr, &credentials->set);
    if (charon_initialized)
        libcharon_deinit();
    if (credentials) {
        credentials->destroy(credentials);
        credentials = NULL;
    }
    DESTROY_IF(configured_peer);
    configured_peer = NULL;
    atomic_store(&active_child, 0);
    if (ipsec_initialized)
        libipsec_deinit();
    if (initialized)
        library_deinit();
    if (ppp)
        sv_ppp_free(ppp);
    ppp = NULL;
    carrier_ifindex = 0;
    l2tp_carrier = false;
    free(expected_gateway);
    expected_gateway = NULL;
    initialized = charon_initialized = ipsec_initialized = false;
    dns_count = 0;
    callbacks = (SVIKECallbacks){0};
    context = NULL;
}

#include "provider-net.inc"
#if defined(SIMPLEVPN_IPSEC_FIXTURE) && !defined(SIMPLEVPN_IPSEC_UDP_FIXTURE)
#include "fixture-socket.inc"
#endif

static bool boot(uint16_t local_natt, bool eap, SVIKECallbacks cb, void *ctx) {
    callbacks = cb;
    context = ctx;
    initialized = true;
    if (!library_init("", "simplevpn"))
        return false;
    // The extension owns all interface, route and DNS changes.
    lib->settings->set_bool(lib->settings, "simplevpn.install_virtual_ip", false);
    lib->settings->set_bool(lib->settings, "simplevpn.install_routes", false);
    lib->settings->set_bool(lib->settings, "simplevpn.close_ike_on_child_failure", true);
    lib->settings->set_bool(lib->settings, "simplevpn.plugins.openssl.load_legacy", false);
    lib->settings->set_int(lib->settings, "simplevpn.port", 0);
    lib->settings->set_int(lib->settings, "simplevpn.port_nat_t", local_natt);
    lib->settings->set_int(lib->settings, "simplevpn.threads", 8);
    if (carrier_ifindex) lib->set(lib,"simplevpn-underlay-index",&carrier_ifindex);
    lib->set(lib, "simplevpn-packet-flow", "SimpleVPN IPsec packet flow / strongSwan " VERSION);
#ifdef SIMPLEVPN_IPSEC_UDP_FIXTURE
    lib->set(lib, "simplevpn-test-loopback", &ready);
#endif
    charon_initialized = true;
    if (!libcharon_init())
        return false;
#ifdef SIMPLEVPN_IPSEC_FIXTURE
    lib->settings->set_double(lib->settings, "simplevpn.retransmit_timeout", 0.4);
    lib->settings->set_int(lib->settings, "simplevpn.retransmit_tries", 2);
    lib->settings->set_str(lib->settings, "simplevpn.filelog.stderr.path", "stderr");
    lib->settings->set_int(lib->settings, "simplevpn.filelog.stderr.default", 1);
    charon->load_loggers(charon);
#endif
    ipsec_initialized = true;
    if (!libipsec_init())
        return false;
    plugin_feature_t f[] = {PLUGIN_CALLBACK(kernel_net_register, provider_net_create),
                            PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
#if defined(SIMPLEVPN_IPSEC_FIXTURE) && !defined(SIMPLEVPN_IPSEC_UDP_FIXTURE)
                            PLUGIN_CALLBACK(socket_register, fixture_socket),
                            PLUGIN_PROVIDE(CUSTOM, "socket"),
#endif
                            PLUGIN_CALLBACK(kernel_ipsec_register, kernel_libipsec_ipsec_create),
                            PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
                            PLUGIN_CALLBACK(register_flow, NULL),
                            PLUGIN_PROVIDE(CUSTOM, "simplevpn-packets"),
                            PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver")};
    lib->plugins->add_static_features(lib->plugins, "simplevpn-flow", f, countof(f), true, NULL, NULL);
    char *plugins = "openssl! random! nonce! kdf! hmac! xauth-generic!"
#if !defined(SIMPLEVPN_IPSEC_FIXTURE) || defined(SIMPLEVPN_IPSEC_UDP_FIXTURE)
                    " socket-default!"
#endif
        ;
    char loaded[256];
    snprintf(loaded, sizeof(loaded), "%s%s%s", eap ? "md4! des! " : "", plugins,
             eap ? " x509! pubkey pem pkcs1 pkcs8 eap-identity! eap-mschapv2!" : "");
    if (!charon->initialize(charon, loaded))
        return false;
    attributes = (attribute_handler_t){
        .handle = store_dns, .release = release_dns, .create_attribute_enumerator = dns_requests};
    charon->attributes->add_handler(charon->attributes, &attributes);
    credentials = mem_cred_create();
    lib->credmgr->add_set(lib->credmgr, &credentials->set);
    charon->bus->add_listener(charon->bus, &listener);
    return true;
}

static bool exact_id(const char *text, identification_t **out) {
    if (!text || !*text || strnlen(text, 1025) > 1024 || strchr(text, '*'))
        return false;
    *out = identification_create_from_string((char *)text);
    return *out && (*out)->get_type(*out) != ID_ANY && !(*out)->contains_wildcards(*out);
}

static peer_cfg_t *configure_peer(const SVIKEConfig *c, bool responder, uint16_t local_natt,
                                  child_cfg_t **out) {
    identification_t *local = NULL, *remote = NULL, *user = NULL;
    const char *username = c->eap_user ?: c->xauth_user;
    if (!exact_id(c->local_id, &local) || !exact_id(c->remote_id, &remote) ||
        (username && !exact_id(username, &user))) {
        DESTROY_IF(user);
        DESTROY_IF(local);
        DESTROY_IF(remote);
        return NULL;
    }
    ike_cfg_create_t ike = {.version = c->version == 1 ? IKEV1 : IKEV2,
                            .local = "%any",
                            .remote = (char *)c->gateway,
                            .local_port = local_natt,
                            .remote_port = c->remote_port ?: 4500,
                            .fragmentation = FRAGMENTATION_YES,
                            .force_encap = true};
    ike_cfg_t *ic = ike_cfg_create(&ike);
    ic->add_proposal(ic, proposal_create_default_aead(PROTO_IKE));
    ic->add_proposal(ic, proposal_create_default(PROTO_IKE));
    peer_cfg_create_t rp = {.unique = UNIQUE_REPLACE,
                            .keyingtries = 1,
                            .rekey_time = 36000,
                            .jitter_time = 600,
                            .over_time = 600,
                            .dpd = 30};
    peer_cfg_t *peer = peer_cfg_create("simplevpn", ic, &rp);
    if (!c->eap_user)
        credentials->add_shared(
            credentials,
            shared_key_create(SHARED_IKE, chunk_clone(chunk_create((uint8_t *)c->shared_secret,
                                                                   c->shared_secret_length))),
            local->clone(local), remote->clone(remote), NULL);
    for (int i = 0; i < 2; i++) {
        auth_cfg_t *auth = auth_cfg_create();
        bool eap_leg = c->eap_user && (responder ? i == 1 : i == 0);
        auth->add(auth, AUTH_RULE_AUTH_CLASS,
                  c->eap_user ? (eap_leg ? AUTH_CLASS_EAP : AUTH_CLASS_PUBKEY) : AUTH_CLASS_PSK);
        if (eap_leg) {
            auth->add(auth, AUTH_RULE_EAP_TYPE, EAP_MSCHAPV2);
            auth->add(auth, AUTH_RULE_EAP_IDENTITY, user->clone(user));
            credentials->add_shared(
                credentials,
                shared_key_create(SHARED_EAP, chunk_clone(chunk_create((uint8_t *)c->eap_password,
                                                                       c->eap_password_length))),
                user, NULL);
        }
        auth->add(auth, AUTH_RULE_IDENTITY, i ? remote : local);
        peer->add_auth_cfg(peer, auth, !i);
    }
    if (c->xauth_user) {
        auth_cfg_t *auth = auth_cfg_create();
        auth->add(auth, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_XAUTH);
        auth->add(auth, AUTH_RULE_XAUTH_IDENTITY, user->clone(user));
        peer->add_auth_cfg(peer, auth, !responder);
        credentials->add_shared(
            credentials,
            shared_key_create(SHARED_EAP, chunk_clone(chunk_create((uint8_t *)c->xauth_password,
                                                                   c->xauth_password_length))),
            user, NULL);
    }
    child_cfg_create_t def = {.mode = l2tp_carrier ? MODE_TRANSPORT : MODE_TUNNEL,
                              .lifetime.time = {.life = 10800, .rekey = 10200, .jitter = 300}};
    child_cfg_t *child = child_cfg_create("simplevpn", &def);
    child->add_proposal(child, proposal_create_default_aead(PROTO_ESP));
    child->add_proposal(child, proposal_create_default(PROTO_ESP));
    if (l2tp_carrier) {
        child->add_traffic_selector(child, true,
                                    traffic_selector_create_dynamic(IPPROTO_UDP, 1701, 1701));
        child->add_traffic_selector(child, false,
                                    traffic_selector_create_dynamic(IPPROTO_UDP, 1701, 1701));
    } else {
        for (int i = 0; i < 2; i++) {
            child->add_traffic_selector(
                child, responder,
                traffic_selector_create_from_cidr(i ? "::/0" : "0.0.0.0/0", 0, 0, 65535));
            if (!responder)
                peer->add_virtual_ip(peer, host_create_from_string(i ? "::" : "0.0.0.0", 0));
        }
        child->add_traffic_selector(child, !responder, traffic_selector_create_dynamic(0, 0, 65535));
        if (responder)
            peer->add_pool(peer, "loopback-fixture");
    }
    peer->add_child_cfg(peer, child->get_ref(child));
    *out = child;
    return peer;
}

static bool send_carrier(const uint8_t *bytes, size_t length) {
    if (!atomic_load(&ready))
        return false;
    ip_packet_t *p = ip_packet_create(chunk_clone(chunk_create((uint8_t *)bytes, length)));
    return p && ipsec->processor->queue_outbound(ipsec->processor, p);
}
static uint64_t start_engine(const SVIKEConfig *c, SVIKECallbacks cb, void *ctx, const char *username,
                             const uint8_t *password, size_t length, uint32_t ifindex) {
    struct in6_addr addr;
    char iface[IFNAMSIZ];
    if (ifindex && !if_indextoname(ifindex, iface)) return 0;
    if (!c ||
        (c->eap_user && (c->version == 1 || c->xauth_user || c->shared_secret ||
                         c->shared_secret_length || !*c->eap_user || !c->eap_password ||
                         !c->eap_password_length || c->eap_password_length > 8192)) ||
        (!c->eap_user && (c->eap_password || c->eap_password_length)) ||
        (c->version != 0 && c->version != 1 && c->version != 2) ||
        (c->xauth_user && (!*c->xauth_user || c->version != 1 || !c->xauth_password ||
                           !c->xauth_password_length || c->xauth_password_length > 8192)) ||
        (!c->xauth_user && (c->xauth_password || c->xauth_password_length)) || !cb.state || !cb.packet ||
        !c->gateway || !c->remote_id || strnlen(c->remote_id, 1025) > 1024 ||
        (!inet_pton(AF_INET, c->gateway, &addr) && !inet_pton(AF_INET6, c->gateway, &addr)) ||
        (!c->eap_user &&
         (!c->shared_secret || c->shared_secret_length < 1 || c->shared_secret_length > 8192)))
        return 0;
    pthread_mutex_lock(&api_lock);
    if (handle || stopping) {
        pthread_mutex_unlock(&api_lock);
        return 0;
    }
    if (username) {
        ppp = sv_ppp_new(username, password, length, cb, ctx, send_carrier);
        if (!ppp) {
            pthread_mutex_unlock(&api_lock);
            return 0;
        }
        l2tp_carrier = true;
    }
    carrier_ifindex = ifindex;
    bool ok = boot(0, c->eap_user != NULL, cb, ctx);
    if (ok && c->eap_user) {
        expected_gateway = c->remote_id ? strdup(c->remote_id) : NULL;
        ok = expected_gateway && SVIKEEnumerateAnchors(add_trust_anchor, NULL);
    }
    if (ok) {
        child_cfg_t *child;
        peer_cfg_t *peer =
            configure_peer(c, false, charon->socket->get_port(charon->socket, true), &child);
        ok = peer != NULL;
        if (ok) {
            configured_peer = peer->get_ref(peer);
            charon->start(charon);
            ok = charon->controller->initiate(charon->controller, peer, child, NULL, NULL, LEVEL_SILENT,
                                              0, false) == SUCCESS;
        }
    }
    if (ok) {
        if (!++next_handle)
            ++next_handle;
        handle = next_handle;
    } else
        shutdown_engine();
    uint64_t result = handle;
    pthread_mutex_unlock(&api_lock);
    return result;
}
uint64_t SVIKEStart(const SVIKEConfig *config, SVIKECallbacks cb, void *ctx) {
    return start_engine(config, cb, ctx, NULL, NULL, 0, 0);
}
uint64_t SVIKEStartBound(const SVIKEConfig *c, uint32_t index, SVIKECallbacks cb, void *ctx) {
    return index ? start_engine(c, cb, ctx, NULL, NULL, 0, index) : 0;
}
static uint64_t start_l2tp(const SVIKEConfig *config, const char *username, const uint8_t *password,
                           size_t length, uint32_t index, SVIKECallbacks cb, void *ctx) {
    struct in_addr addr;
    if (!config || config->version != 1 || config->xauth_user || config->eap_user || !config->gateway ||
        !inet_pton(AF_INET, config->gateway, &addr) || !username) return 0;
    return start_engine(config, cb, ctx, username, password, length, index);
}
uint64_t SVL2TPStart(const SVIKEConfig *config, const char *user, const uint8_t *password,
                     size_t length, SVIKECallbacks cb, void *ctx) {
    return start_l2tp(config,user,password,length,0,cb,ctx);
}
uint64_t SVL2TPStartBound(const SVIKEConfig *config, const char *user, const uint8_t *password,
                          size_t length, uint32_t index, SVIKECallbacks cb, void *ctx) {
    return index ? start_l2tp(config,user,password,length,index,cb,ctx) : 0;
}
uint16_t SVL2TPMTU(uint64_t session) {
    pthread_mutex_lock(&api_lock);
    uint16_t mtu = session && handle == session && ppp ? sv_ppp_mtu(ppp) : 0;
    pthread_mutex_unlock(&api_lock);
    return mtu;
}
bool SVIKESend(uint64_t session, const uint8_t *bytes, size_t length) {
    if (!bytes || length < 20 || length > 65575 || !atomic_load(&ready))
        return false;
    pthread_mutex_lock(&api_lock);
    bool ok = false;
    if (session && handle == session && atomic_load(&ready)) {
        ok = ppp ? sv_ppp_send(ppp, bytes, length) : send_carrier(bytes, length);
    }
    pthread_mutex_unlock(&api_lock);
    return ok;
}
void SVIKEStop(uint64_t session) {
    pthread_mutex_lock(&api_lock);
    if (session && session == handle) {
        handle = 0;
        stopping = true;
        atomic_store(&ready, false);
        pthread_mutex_unlock(&api_lock);
        shutdown_engine();
        pthread_mutex_lock(&api_lock);
        stopping = false;
    }
    pthread_mutex_unlock(&api_lock);
}
