#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "libutp/utp_types.h" // byte

typedef struct config config;

config *config_new(const char *swarm_salt);
void config_delete(config*);

const byte* injector_swarm(config*);
const byte* injector_proxy_swarm(config*);

#endif // __CONFIG_H__
