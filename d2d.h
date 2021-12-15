#ifndef __D2D_H__
#define __D2D_H__

#define UNIQUE_LOCAL_PREFIX_LENGTH 1

typedef struct {
    uint8_t addr[sizeof(in6_addr) - UNIQUE_LOCAL_PREFIX_LENGTH];
    port_t port;
} PACKED endpoint;

ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6);
sockaddr_in6 endpoint_to_addr(const endpoint *endpoint);
endpoint addr_to_endpoint(const sockaddr_in6 *sin6);

#endif // __D2D_H__
