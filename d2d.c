#include <assert.h>
#include <string.h>

#include "network.h"
#include "d2d.h"


#if (!defined ANDROID && !defined __APPLE__)
ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6)
{
    return -1;
}
#endif

sockaddr_in6 endpoint_to_addr(const endpoint *endpoint)
{
    sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
#ifdef __APPLE__
        .sin6_len = sizeof(sin6),
#endif
        // Unique Local IPv6 Unicast Address
        .sin6_addr.s6_addr[0] = 0xfc,
        .sin6_port = endpoint->port
    };
    memcpy(&sin6.sin6_addr.s6_addr[UNIQUE_LOCAL_PREFIX_LENGTH], endpoint->addr, sizeof(endpoint->addr));
    assert(IN6_IS_ADDR_UNIQUE_LOCAL(&sin6.sin6_addr));
    return sin6;
}

endpoint addr_to_endpoint(const sockaddr_in6 *sin6)
{
    assert(sin6->sin6_family == AF_INET6);
    assert(IN6_IS_ADDR_UNIQUE_LOCAL(&sin6->sin6_addr));
    endpoint e = {.port = sin6->sin6_port};
    memcpy(e.addr, &sin6->sin6_addr.s6_addr[UNIQUE_LOCAL_PREFIX_LENGTH], sizeof(e.addr));
    return e;
}
