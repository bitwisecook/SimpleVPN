// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Network Extension owns addresses and routes. libcharon needs only outer
// address selection and logical VIP bookkeeping during negotiation.
typedef struct {
    kernel_net_t api;
    pthread_mutex_t lock;
    linked_list_t *addresses;
} provider_net_t;

static host_t *provider_source(kernel_net_t *unused, host_t *destination, host_t *hint) {
#if defined(SIMPLEVPN_IPSEC_FIXTURE) && !defined(SIMPLEVPN_IPSEC_UDP_FIXTURE)
    return host_create_from_string("127.0.0.1", 0);
#else
    int fd = socket(destination->get_family(destination), SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return NULL;
    if (carrier_ifindex && setsockopt(fd, destination->get_family(destination)==AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
            destination->get_family(destination)==AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF,
            &carrier_ifindex, sizeof(carrier_ifindex)) < 0) {
        close(fd);
        return NULL;
    }
    struct sockaddr_storage local;
    socklen_t len = sizeof(local);
    host_t *result = NULL;
    if (connect(fd, destination->get_sockaddr(destination),
                *destination->get_sockaddr_len(destination)) == 0 &&
        getsockname(fd, (struct sockaddr *)&local, &len) == 0)
        result = host_create_from_sockaddr((struct sockaddr *)&local);
    close(fd);
    return result;
#endif
}
static bool provider_interface(kernel_net_t *unused, host_t *ip, char **name) {
    if (name)
        *name = strdup("packet-flow");
    return true;
}
static enumerator_t *provider_addresses(kernel_net_t *net, kernel_address_type_t which) {
    provider_net_t *p = (provider_net_t *)net;
    if (!(which & ADDR_TYPE_VIRTUAL))
        return enumerator_create_empty();
    pthread_mutex_lock(&p->lock);
    return enumerator_create_cleaner(p->addresses->create_enumerator(p->addresses),
                                     (void *)pthread_mutex_unlock, &p->lock);
}
static status_t provider_add(kernel_net_t *net, host_t *ip, int prefix, char *iface) {
    provider_net_t *p = (provider_net_t *)net;
    pthread_mutex_lock(&p->lock);
    p->addresses->insert_last(p->addresses, ip->clone(ip));
    pthread_mutex_unlock(&p->lock);
    return SUCCESS;
}
static status_t provider_del(kernel_net_t *net, host_t *ip, int prefix, bool wait) {
    provider_net_t *p = (provider_net_t *)net;
    pthread_mutex_lock(&p->lock);
    enumerator_t *e = p->addresses->create_enumerator(p->addresses);
    host_t *h;
    while (e->enumerate(e, &h))
        if (h->ip_equals(h, ip)) {
            p->addresses->remove_at(p->addresses, e);
            h->destroy(h);
            break;
        }
    e->destroy(e);
    pthread_mutex_unlock(&p->lock);
    return SUCCESS;
}
static void provider_net_destroy(kernel_net_t *net) {
    provider_net_t *p = (provider_net_t *)net;
    p->addresses->destroy_offset(p->addresses, offsetof(host_t, destroy));
    pthread_mutex_destroy(&p->lock);
    free(p);
}
static kernel_net_t *provider_net_create(void) {
    provider_net_t *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    pthread_mutex_init(&p->lock, NULL);
    p->addresses = linked_list_create();
    p->api = (kernel_net_t){.get_source_addr = provider_source,
                            .get_nexthop = (void *)return_null,
                            .get_interface = provider_interface,
                            .create_address_enumerator = provider_addresses,
                            .create_local_subnet_enumerator = (void *)enumerator_create_empty,
                            .add_ip = provider_add,
                            .del_ip = provider_del,
                            .add_route = (void *)return_failed,
                            .del_route = (void *)return_failed,
                            .destroy = provider_net_destroy};
    return &p->api;
}
