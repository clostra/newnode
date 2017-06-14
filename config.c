#include "config.h"
#include "sha1.h"
#include "string.h"
#include <stdlib.h>
#include <stdio.h>

struct config {
    byte* injector_swarm;
    byte* injector_proxy_swarm;
};

static byte* compute_swarm(const char* base, const char* salt)
{
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, (byte*) base, strlen(base));

    if (salt) {
        SHA1Update(&ctx, (byte*) salt, strlen(salt));
    }

    byte* hash_out = malloc(20);

    SHA1Final(hash_out, &ctx);

    return hash_out;
}

config* config_new(const char *swarm_salt)
{
    config *c = malloc(sizeof(config));

    c->injector_swarm       = compute_swarm("injectors", swarm_salt);
    c->injector_proxy_swarm = compute_swarm("injector proxies", swarm_salt);

    return c;
}

void config_delete(config *c)
{
    free(c->injector_swarm);
    free(c->injector_proxy_swarm);
    free(c);
}

const byte* injector_swarm(config* c)
{
    return c->injector_swarm;
}

const byte* injector_proxy_swarm(config* c)
{
    return c->injector_proxy_swarm;
}
