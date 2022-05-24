#include "network.h"


typedef bool (^choose_addr_cb)(evutil_addrinfo *addr);
bool choose_addr(evutil_addrinfo *g, choose_addr_cb cb);
char* make_ip_addr_list(evutil_addrinfo *p);
void dns_prefetch(network *n, const char *host);
void dns_prefetch_store_result(network *n, evutil_addrinfo *nna, const char *host, int ttl);
extern void platform_dns_prefetch(network *n, const char *host);
void newnode_evdns_cache_write(network *n, const char *nodename, evutil_addrinfo *res, int ttl);
int newnode_evdns_cache_lookup(evdns_base *base, const char *host, evutil_addrinfo *hints, uint16_t port, evutil_addrinfo **res);
