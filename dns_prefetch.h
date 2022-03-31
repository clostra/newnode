#include "network.h"

// sigh, different systems implement struct addrinfo in slightly
// different ways, particularly regarding memory allocation/free so we
// define our own.  also add a ai_expiry field so we can capture that
// if our API supplies a TTL.  (note that the TTL is potentially
// different for each address, even though evdns doesn't keep track of
// that in its cache)


struct nn_addrinfo {
    socklen_t ai_addrlen;
    sockaddr *ai_addr;
    time_t ai_expiry;
    struct nn_addrinfo *ai_next;
};
typedef struct nn_addrinfo nn_addrinfo;

typedef struct {
    uint64_t id;
    bool allocated:1;
    nn_addrinfo *result;
    time_t when_allocated;
} dns_prefetch_result;

extern dns_prefetch_result dns_prefetch_results[];

typedef bool (^choose_addr_cb)(nn_addrinfo *addr);
nn_addrinfo *choose_addr(nn_addrinfo *g, choose_addr_cb cb);
char *make_ip_addr_list(nn_addrinfo *p);
nn_addrinfo *dns_prefetch_addrinfo(int64_t key);
int64_t dns_prefetch_alloc(void);
void dns_prefetch_freeaddrinfo(nn_addrinfo *p);
void dns_prefetch_free(int64_t key);
void dns_prefetch(network *n, uint64_t key, const char *host, evdns_base *base);
nn_addrinfo *copy_nn_addrinfo_from_evutil_addrinfo(evutil_addrinfo *p);
evutil_addrinfo *copy_evutil_addrinfo_from_nn_addrinfo(nn_addrinfo *nna);
void dns_prefetch_store_result(network *n, size_t result_index, uint64_t result_id, nn_addrinfo *nna, const char *host, bool fromevdns);
int dns_prefetch_index(uint64_t key);
uint32_t dns_prefetch_id(uint64_t key);
extern void platform_dns_prefetch(network *n, int result_index, unsigned int result_id, const char *host);
void newnode_evdns_cache_write(network *n, const char *nodename, evutil_addrinfo *res, int ttl);
int newnode_evdns_cache_lookup(evdns_base *base, const char *host, evutil_addrinfo *hints, uint16_t port, evutil_addrinfo **res);
