#ifndef __DCDN_PROXY_H__
#define __DCDN_PROXY_H__

#include "utp.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "network.h"

typedef struct proxy proxy;
typedef struct proxy_injector proxy_injector;
typedef struct proxy_client proxy_client;

proxy* proxy_create(network*);
void proxy_destroy(proxy*);

void proxy_add_injector(proxy*, struct bufferevent*, struct evhttp_connection*);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __DCDN_PROXY_H__
