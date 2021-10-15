#include <assert.h>
#include <string.h>

#include "network.h"


#ifndf ANDROID
ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6)
{
    return -1;
}
#endif

#define UNIQUE_LOCAL_PREFIX_LENGTH 1

typedef struct {
    uint8_t addr[sizeof(in6_addr) - UNIQUE_LOCAL_PREFIX_LENGTH];
    port_t port;
} PACKED unique_local;

sockaddr_in6 endpoint_to_addr(const uint8_t *endpoint, size_t len)
{
    assert(len <= sizeof(unique_local));
    unique_local u = {0};
    memcpy(&u, endpoint, len);

    sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        //  Unique Local IPv6 Unicast Address
        .sin6_addr.s6_addr[0] = 0xfc,
        .sin6_port = u.port
    };
    memcpy(&sin6.sin6_addr.s6_addr[UNIQUE_LOCAL_PREFIX_LENGTH], u.addr, sizeof(u.addr));
    assert(IN6_IS_ADDR_UNIQUE_LOCAL(&sin6.sin6_addr));

    return sin6;
}

const uint8_t* addr_to_endpoint(const sockaddr_in6 *sin6)
{
    static unique_local u;
    memcpy(u.addr, &sin6->sin6_addr.s6_addr[UNIQUE_LOCAL_PREFIX_LENGTH], sizeof(u.addr));
    u.port = sin6->sin6_port;
    return u.addr;
}
