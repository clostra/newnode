#ifndef __DCDN_PROXY_H__
#define __DCDN_PROXY_H__

#include "utp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proxy proxy;
typedef struct proxy_injector proxy_injector;
typedef struct proxy_client proxy_client;

proxy* proxy_create();
void proxy_destroy(proxy*);

proxy_injector* proxy_add_injector(proxy*, utp_socket*);
proxy_client*   proxy_add_client(proxy*, utp_socket*);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __DCDN_PROXY_H__
