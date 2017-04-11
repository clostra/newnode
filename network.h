#ifndef __NETWORK_H__
#define __NETWORK_H__

#include "utp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define lenof(x) (sizeof(x)/sizeof(x[0]))
#define alloc(type) calloc(1, sizeof(type))


utp_context* network_setup(char *address, char *port);
int network_loop(utp_context *ctx);

#endif // __NETWORK_H__
