#ifndef __LSD_H__
#define __LSD_H__

#include "network.h"


void lsd_setup(network *n);
void lsd_send(network *n);

// defined by caller
void add_sockaddr(network *n, const sockaddr *addr, socklen_t addrlen);

#endif // __LSD_H__
