// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#import "VirtualDatagramPort.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <os/lock.h>
#include <sys/socket.h>
#include <unistd.h>

@implementation VirtualDatagramPort {
    BOOL _familyHeader;
    void (^_received)(NSData *);
    os_unfair_lock _lock;
    int _fd;
    dispatch_source_t _reader;
}
- (instancetype)initWithFamilyHeader:(BOOL)familyHeader received:(void (^)(NSData *))received {
    if ((self = [super init])) {
        _familyHeader = familyHeader;
        _received = [received copy];
        _fd = -1;
        _lock = OS_UNFAIR_LOCK_INIT;
    }
    return self;
}
- (int)openEngineDescriptor {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        if (fcntl(pair[i], F_SETFD, FD_CLOEXEC) != 0) { close(pair[0]); close(pair[1]); return -1; }
        int size = 256 * 1024;
        setsockopt(pair[i], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
        setsockopt(pair[i], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    int fd = pair[1];
    dispatch_source_t reader = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0,
        dispatch_queue_create("com.bragi0.SimpleVPN.virtual-datagram", DISPATCH_QUEUE_SERIAL));
    if (!reader) { close(pair[0]); close(fd); return -1; }
    BOOL prefixed = _familyHeader;
    __weak VirtualDatagramPort *weakSelf = self;
    dispatch_source_set_event_handler(reader, ^{
        VirtualDatagramPort *port = weakSelf;
        if (!port) return;
        uint8_t bytes[65580];
        size_t offset = prefixed ? 4 : 0;
        ssize_t count = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (count <= (ssize_t)offset || count == sizeof(bytes)) return;
        uint8_t version = bytes[offset] >> 4;
        if (version != 4 && version != 6) return;
        if (prefixed) {
            uint32_t family;
            memcpy(&family, bytes, sizeof(family));
            if (ntohl(family) != (uint32_t)(version == 6 ? AF_INET6 : AF_INET)) return;
        }
        os_unfair_lock_lock(&port->_lock);
        BOOL live = port->_fd == fd;
        os_unfair_lock_unlock(&port->_lock);
        if (live) port->_received([NSData dataWithBytes:bytes + offset length:(NSUInteger)count - offset]);
    });
    dispatch_source_set_cancel_handler(reader, ^{ close(fd); });
    os_unfair_lock_lock(&_lock);
    BOOL available = _fd < 0;
    if (available) { _fd = fd; _reader = reader; }
    os_unfair_lock_unlock(&_lock);
    if (!available) dispatch_source_cancel(reader);
    dispatch_resume(reader);
    if (!available) { close(pair[0]); return -1; }
    return pair[0];
}
- (BOOL)sendPacket:(NSData *)packet {
    if (!packet.length || packet.length > 65575) return NO;
    const uint8_t version = ((const uint8_t *)packet.bytes)[0] >> 4;
    if (version != 4 && version != 6) return NO;
    uint32_t family = htonl(version == 4 ? AF_INET : AF_INET6);
    struct iovec parts[] = {{ &family, sizeof(family) }, { (void *)packet.bytes, packet.length }};
    struct msghdr msg = {.msg_iov = parts + (_familyHeader ? 0 : 1), .msg_iovlen = _familyHeader ? 2 : 1};
    os_unfair_lock_lock(&_lock);
    ssize_t count = _fd < 0 ? -1 : sendmsg(_fd, &msg, MSG_DONTWAIT);
    os_unfair_lock_unlock(&_lock);
    return count == (ssize_t)(packet.length + (_familyHeader ? sizeof(family) : 0));
}
- (void)close {
    os_unfair_lock_lock(&_lock);
    dispatch_source_t reader = _reader;
    _reader = nil;
    _fd = -1;
    os_unfair_lock_unlock(&_lock);
    if (reader) dispatch_source_cancel(reader);
}
- (void)dealloc { [self close]; }
@end
