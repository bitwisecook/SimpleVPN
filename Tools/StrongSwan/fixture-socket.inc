// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Test-only transport, both peers inherit endpoints of the same unbound
// AF_UNIX datagram socketpair. IKE and authenticated ESP are real wire bytes.
#include <threading/thread.h>
static int fixture_fd;
static status_t local_receive(socket_t *s, packet_t **out) {
    uint8_t bytes[65536];
    bool old = thread_cancelability(true);
    ssize_t n = recv(fixture_fd, bytes, sizeof(bytes), 0);
    thread_cancelability(old);
    if (n < 0)
        return FAILED;
    *out = packet_create_from_data(host_create_from_string("127.0.0.1", 4500),
                                   host_create_from_string("127.0.0.1", 4500),
                                   chunk_clone(chunk_create(bytes, n)));
    return SUCCESS;
}
static status_t local_send(socket_t *s, packet_t *packet) {
    chunk_t data = packet->get_data(packet);
    return send(fixture_fd, data.ptr, data.len, 0) == (ssize_t)data.len ? SUCCESS : FAILED;
}
static uint16_t local_port(socket_t *s, bool natt) { return natt ? 4500 : 500; }
static socket_family_t local_family(socket_t *s) { return SOCKET_FAMILY_IPV4; }
static socket_t *fixture_socket(void) {
    static socket_t socket = {local_receive, local_send, local_port, local_family, (void *)nop};
    return &socket;
}
