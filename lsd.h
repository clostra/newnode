#ifndef __LSD_H__
#define __LSD_H__

#include "network.h"


typedef void (^lsd_sockaddr_callback)(const sockaddr *addr, socklen_t addrlen);

void lsd_setup(network *n);
void lsd_set_sockaddr_callback(lsd_sockaddr_callback cb);
void lsd_send(network *n, bool reply);

#endif // __LSD_H__
