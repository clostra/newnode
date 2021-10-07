#ifndef __D2D_H__
#define __D2D_H__

ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6);
sockaddr_in6 endpoint_to_addr(const uint8_t *endpoint, size_t len);
const uint8_t* addr_to_endpoint(const sockaddr_in6 *sin6);

#endif // __D2D_H__
