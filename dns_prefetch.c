#include "nn_features.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sodium.h>
#include <netinet/in.h>
#include <pthread.h>

#include "libevent/util-internal.h"

#include "dns_prefetch.h"
#include "log.h"


// choose address - random selection for now
bool choose_addr(evutil_addrinfo *g, choose_addr_cb cb)
{
    if (!g) {
        return NULL;
    }
    int count = 0;
    for (evutil_addrinfo *p = g; p; p = p->ai_next) {
        count++;
    }
    int n = randombytes_uniform(count);
    for (int i = 0; i < count; i++) {
        int try = (n + (i * (count + 1))) % count;
        evutil_addrinfo *result = g;
        for (; try && result->ai_next; try--) {
            result = result->ai_next;
        }
        if (cb(result)) {
            return true;
        }
    }
    debug("%s no valid addresses out of %d\n", __func__, count);
    return false;
}

void newnode_evdns_cache_write(network *n, const char *nodename, evutil_addrinfo *res, int ttl)
{
    // max DNS TTL per RFC 2181 = 2^31 - 1
    if (ttl > 2147483647) {
        ttl = 2147483647;
    }
    evdns_cache_write(n->evdns, (char *)nodename, res, ttl);
}

// allow peek into the evdns cache
int newnode_evdns_cache_lookup(evdns_base *base, const char *host, evutil_addrinfo *hints,
                               uint16_t port, evutil_addrinfo **res)
{
    evutil_addrinfo nullhints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    if (!hints) {
        hints = &nullhints;
    }
    return evdns_cache_lookup(base, host, hints, port, res);
}

// use the host platform's DNS query engine to "pre-query" the hostname,
// so that both the libevent DNS cache and the host's DNS cache can be
// populated from a single query.   The result will be stored in
// dns_prefetch_results[result_index] assuming the IDs match.

void dns_prefetch(network *n, const char *host)
{
    debug("%s host:%s\n", __func__, host);

    // if this is already in libevent's cache, skip the platform DNS
    // lookup and use the already-cached addresses.
    evutil_addrinfo *res;
    if (newnode_evdns_cache_lookup(n->evdns, host, NULL, 443, &res) == 0) {
        debug("%s found %s in libevent dns cache %s\n", __func__, host, make_ip_addr_list(res));
        evutil_freeaddrinfo(res);
        return;
    }
    debug("%s did not find %s in libevent dns cache\n", __func__, host);

    // if not, initiate a DNS query using the platform's DNS library,
    // (and use that result to update libevent's DNS cache)
    platform_dns_prefetch(n, host);
}

char* make_ip_addr_list(evutil_addrinfo *p)
{
    static char result[10240];
    char *ptr = result;

    if (!p) {
        return NULL;
    }
    while (p) {
        const char *a = sockaddr_str_addronly(p->ai_addr);
        size_t l = strlen(a);
        if ((ptr - result) + l + 2 < sizeof(result)) {
            memcpy(ptr, a, l);
            ptr += l;
            if (p->ai_next) {
                *ptr++ = ',';
            }
        }
        p = p->ai_next;
    }
    *ptr++ = '\0';
    assert((ptr - result) < (int)sizeof(result));
    return result;
}

void dns_prefetch_store_result(network *n, evutil_addrinfo *ai, const char *host, int ttl)
{
    debug("%s host:%s\n", __func__, host);

    if (!ttl) {
        // don't have a ttl from DNS query.  add to evdns cache with
        // a minimum ttl (like 60 seconds), but don't overwrite
        // a cache entry that already exists.
        evutil_addrinfo hints = {
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP
        };
        evutil_addrinfo *res;
        if (newnode_evdns_cache_lookup(n->evdns, host, &hints, 0, &res) == 0) {
            debug("%s NOT adding (host:%s=>%s) to evdns cache - already present in cache\n",
                  __func__, host, make_ip_addr_list(ai));
            evutil_freeaddrinfo(res);
            return;
        }
        ttl = 60;
    }

    // have a ttl obtained from DNS query, add to evdns cache
    debug("%s adding (host:%s=>%s) to evdns cache with ttl:%d)\n",
          __func__, host, make_ip_addr_list(ai), ttl);
    newnode_evdns_cache_write(n, host, ai, ttl);
}
