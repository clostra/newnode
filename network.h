#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "utp.h"
#include "dht.h"


#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define lenof(x) (sizeof(x)/sizeof(x[0]))
#define alloc(type) calloc(1, sizeof(type))


typedef struct {
    int fd;
    utp_context *utp;
    dht *dht;
} network;

network* network_setup(char *address, char *port);
int network_loop(network *n);

#endif // __NETWORK_H__
