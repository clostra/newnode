#include <assert.h>
#include <string.h>

#include "network.h"


#ifndef ANDROID
ssize_t d2d_sendto(const uint8* buf, size_t len, const sockaddr_in6 *sin6)
{
    return -1;
}
#endif

#define LINKLOCAL_PREFIX_LENGTH 2

sockaddr_in6 endpoint_to_addr(const uint8_t *endpoint, size_t len)
{
    sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        // link-local unicast
        .sin6_addr.s6_addr[0] = 0xfe,
        .sin6_addr.s6_addr[1] = 0x80
    };
    const size_t addrmax = sizeof(sin6.sin6_addr.s6_addr) - LINKLOCAL_PREFIX_LENGTH;
    assert(IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr));
    memcpy(&sin6.sin6_addr.s6_addr[LINKLOCAL_PREFIX_LENGTH], endpoint, MIN(len, addrmax));
    if (len > addrmax) {
        memcpy(&sin6.sin6_port, &endpoint[addrmax], MIN(len - addrmax, sizeof(port_t)));
        assert(len <= addrmax + sizeof(port_t));
    }
    return sin6;
}

const uint8_t* addr_to_endpoint(const sockaddr_in6 *sin6)
{
    const size_t addrlen = sizeof(sin6->sin6_addr.s6_addr);
    static uint8_t e[addrlen] = {0};
    memcpy(e, &sin6->sin6_addr.s6_addr[LINKLOCAL_PREFIX_LENGTH], addrlen - LINKLOCAL_PREFIX_LENGTH);
    memcpy(&e[addrlen - LINKLOCAL_PREFIX_LENGTH], &sin6->sin6_port, sizeof(sin6->sin6_port));
    return e;
}
