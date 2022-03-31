#include "features.h"

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

static uint64_t result_ids = 1; // ids start at 1, not 0

// Because connect_req can be free'd with no warning, it doesn't work
// well to have a separate thread leaving DNS prefetch results in
// connect_req.
//
// So prefetched DNS results are stored in this statically-allocated
// array.  Instead of free()ing results that are no longer needed, the
// allocated bit is cleared.  Also, each result is assigned a unique
// id which can be checked to make sure it matches the id used when
// requested.
//
// Originally, each element of dns_prefetch_result was referenced by
// both the index into the array and an "id" that was compared against
// the id field.  That way, if some thread tried to modify a
// dns_prefetch_result that it had a stale reference to, it would
// notice the id mismatch and give up.  But it was cumbersome and
// error-prone to check the id everytime, so the index and id were
// encoded as a "key" and new routines were written to provide access
// in terms of "keys".

#define NUM_DNS_RESULTS 100

dns_prefetch_result dns_prefetch_results[NUM_DNS_RESULTS];

static nn_addrinfo* nth_addr(nn_addrinfo *p, int n)
{
    if (!p) {
        return NULL;
    }
    if (n == 0) {
        return p;
    }
    if (!p->ai_next) {
        return NULL;
    }
    return nth_addr(p->ai_next, n-1);
}

static int count_addrs(nn_addrinfo *p)
{
    if (!p) {
        return 0;
    }
    int result = 0;
    while (p) {
        result++;
        p = p->ai_next;
    }
    return result;
}

bool valid_server_address(sockaddr *s)
{
    // Which kinds of addresses are valid?
    //
    // Short answer: Any unicast address to which the local host could
    // potentially connect to a named origin web server using TCP.
    // 
    // These addresses will normally have come from DNS queries and
    // _should_ therefore normally be public (not private) IP
    // addresses.  But we use different APIs on different systems to
    // obtain these addresses, and some of those APIs might return
    // addresses obtained via mDNS or other lookup systems (sigh).  So
    // the addresses returned might include private (IPv4, RFC1918) or
    // linklocal (IPv4 or IPv6) or site-local (IPv6, deprecated), or
    // unique local IPv6 addresses (RFC4193).
    //
    // It helps if the address is unambiguous, i.e. it is bound to the
    // same host everywhere even if not routable.  Loopback addresses
    // are definitely not valid, but RFC 1918 addresses could be.
    //
    // The addresss needs to be routable from the local host to be
    // usable.  So for instance an IPv6 address is not valid for us if
    // we don't have any active IPv6 interfaces.

    if (!s) {
        return false;
    }
    switch (s->sa_family) {
    case AF_INET:
        if (IN_LOOPBACK(((sockaddr_in *)s)->sin_addr.s_addr)) {
            return false;
        } else if (IN_MULTICAST(((sockaddr_in *)s)->sin_addr.s_addr)) {
            return false;
        }
        break;
    case AF_INET6: {
        in6_addr *a6 = &(((sockaddr_in6 *)s)->sin6_addr);
        if (IN6_IS_ADDR_LOOPBACK(a6)) {
            return false;
        } else if (IN6_IS_ADDR_MULTICAST(a6)) {
            return false;
        }
        break;
    }
    default:
        return false;
    }
    return true;
}

// choose address - random selection for now
nn_addrinfo* choose_addr(nn_addrinfo *g, choose_addr_cb cb)
{
    if (!g) {
        return NULL;
    }
    int count = count_addrs(g);
    // debug("%s count_addrs=>%d\n", __func__, count);
    if (count == 0) {
        return NULL;
    }
    int n = randombytes_uniform(count);
    for (int i = 0; i < count; ++i) {
        int try = (n + (i * (count + 1))) % count;
        nn_addrinfo *result = nth_addr(g, try);
        if (cb(result)) {
            return result;
        }
    }
    debug("%s no valid addresses out of %d\n", __func__, count);
    return NULL;
}

static int64_t dns_prefetch_makekey(size_t result_index, uint64_t result_id)
{
    if (result_index < 0 || result_index >= NUM_DNS_RESULTS) {
        return -1;
    }
    return (result_id * NUM_DNS_RESULTS) + result_index;
}

#define PARSE_KEY(key,index,id) do {(index)=(key)%NUM_DNS_RESULTS; (id)=(key)/NUM_DNS_RESULTS;} while(0)

static dns_prefetch_result* dns_prefetch_find(int64_t key)
{
    if (key <= 0) {
        return NULL;
    }
    size_t result_index;
    uint64_t result_id;
    PARSE_KEY(key, result_index, result_id);
    if (dns_prefetch_results[result_index].id != result_id) {
        return NULL;
    }
    return &(dns_prefetch_results[result_index]);
}

nn_addrinfo* dns_prefetch_addrinfo(int64_t key)
{
    dns_prefetch_result *r = dns_prefetch_find(key);
    if (!r) {
        return r->result;
    }
    return NULL;
}

// returns an index into dns_prefetch_results, or -1 on error
int64_t dns_prefetch_alloc()
{
    int64_t key;
    time_t now = time(0);
    time_t oldest_time = now;
    int oldest_index = -1;

    for (int i = 0; i < NUM_DNS_RESULTS; ++i) {
        if (dns_prefetch_results[i].when_allocated < oldest_time) {
            oldest_time = dns_prefetch_results[i].when_allocated;
            oldest_index = i;
        }
        if (dns_prefetch_results[i].allocated) {
            continue;
        }
        memset(&(dns_prefetch_results[i]), 0, sizeof(dns_prefetch_result));
        dns_prefetch_results[i].allocated = true;
        dns_prefetch_results[i].when_allocated = now;
        dns_prefetch_results[i].id = result_ids++;
        key = dns_prefetch_makekey(i, dns_prefetch_results[i].id);
        return key;
    }
    // no unallocated entries found; reuse the oldest entry
    if (oldest_index >= 0) {
        debug("%s reusing index %d\n", __func__, oldest_index);
        dns_prefetch_results[oldest_index].allocated = true;
        dns_prefetch_results[oldest_index].when_allocated = now;
        dns_prefetch_results[oldest_index].id = result_ids++;
        if (dns_prefetch_results[oldest_index].result != NULL) {
            dns_prefetch_freeaddrinfo(dns_prefetch_results[oldest_index].result);
            dns_prefetch_results[oldest_index].result = NULL;
        }
        key = dns_prefetch_makekey(oldest_index,
                                   dns_prefetch_results[oldest_index].id);
        return key;
    }
    // SHOULD NOT HAPPEN
    debug("%s: out of DNS prefix slots\n", __func__);
    return -1;
}


// this is for use in freeing nn_addrinfo * linked lists that we
// create in NewNode-specific code.  Don't use this with lists returned 
// by getaddrinfo() or evutil_getaddrinfo().
//
// implementations of platform_dns_prefetch() MUST create struct
// nn_addrinfo * linked lists that are compatible with this routine.

void dns_prefetch_freeaddrinfo(nn_addrinfo *p)
{
    while (p) {
        nn_addrinfo *next = p->ai_next;
        free(p->ai_addr);
        free(p);
        p = next;
    }
}

static void dns_prefetch_free_internal(size_t result_index, uint64_t result_id)
{
    if (result_index >= NUM_DNS_RESULTS) {
        return;
    }
    addrinfo *p, *next;

    if (dns_prefetch_results[result_index].id != result_id) {
        debug("%s: result_id:%lld does not match [result_index]id:%lld\n",
              __func__, (long long) result_id,
              (long long) dns_prefetch_results[result_index].id);
        return;
    }
    if (dns_prefetch_results[result_index].allocated == false) {
        debug("%s: result_index:%lld not allocated\n", __func__, (long long) result_index);
        return;
    }
    dns_prefetch_freeaddrinfo(dns_prefetch_results[result_index].result);
    dns_prefetch_results[result_index].result = NULL;
    dns_prefetch_results[result_index].allocated = false;
}

void dns_prefetch_free(int64_t key)
{
    if (key <= 0) {
        return;
    }
    size_t result_index;
    uint64_t result_id;
    PARSE_KEY(key, result_index, result_id);
    debug("%s key:%lld index:%zd id:%lld\n", __func__, (long long)key, result_index,
          (long long)result_id);
    dns_prefetch_free_internal(result_index, result_id);
}

nn_addrinfo* copy_nn_addrinfo_from_evutil_addrinfo(evutil_addrinfo *p)
{
    if (!p) {
        return NULL;
    }
    nn_addrinfo *result = NULL;
    if (valid_server_address(p->ai_addr)) {
        result = alloc(nn_addrinfo);
        result->ai_addrlen = p->ai_addrlen;
        result->ai_addr = memdup(p->ai_addr, p->ai_addrlen);
        result->ai_next = copy_nn_addrinfo_from_evutil_addrinfo(p->ai_next);
    } else {
        result = copy_nn_addrinfo_from_evutil_addrinfo(p->ai_next);
    }
    return result;
}

evutil_addrinfo* copy_evutil_addrinfo_from_nn_addrinfo(nn_addrinfo *nna)
{
    evutil_addrinfo *first = NULL;
    evutil_addrinfo *prev = NULL;
    evutil_addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    if (!nna) {
        return NULL;
    }
    for (; nna; nna = nna->ai_next) {
        // call evutil_new_addrinfo_ so that the resulting structure will be allocated
        // in a way that's compatible with evutil_freeaddrinfo()
        evutil_addrinfo *a = evutil_new_addrinfo_(nna->ai_addr, nna->ai_addrlen, &hints);
        if (!a) {
            return first;
        }
        if (!first) {
            first = a;
        } else {
            prev->ai_next = a;
        }
        prev = a;
    }
    return first;
}

void newnode_evdns_cache_write(network *n, const char *nodename, evutil_addrinfo *res, int ttl)
{
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

static void dns_prefetch_internal(network *n, size_t result_index, uint64_t result_id, const char *host, evdns_base *base)
{
    // XXX sigh... more failure of cross-compilation to provide working stdint
    debug("%s result_index:%zu result_id:%llu host:%s base:%p\n", __func__, result_index, 
          (unsigned long long)result_id, host, base);

    // make sure our cache_entry_id matches cache_index
    // (IOW this entry hasn't been re-allocated to something else)
    if (dns_prefetch_results[result_index].id != result_id) {
        debug("%s id mismatch resul_index.id:%lld result_id:%lld\n", __func__,
              (long long)dns_prefetch_results[result_index].id,
              (long long)result_id);
        return;
    }

    if (!dns_prefetch_results[result_index].allocated) {
        debug("%s result_index:%lld not allocated\n", __func__, (long long)result_index);
        return;
    }

    sockaddr_storage ss = {};
    int socklen = sizeof(ss);
    int error = evutil_parse_sockaddr_port(host, (sockaddr*)&ss, &socklen);
    if (!error) {
        nn_addrinfo *result = alloc(nn_addrinfo);
        result->ai_addrlen = socklen;
        result->ai_addr = memdup(&ss, socklen);
        dns_prefetch_results[result_index].result = result;
        return;
    }

    // if this is already in libevent's cache, skip the platform DNS
    // lookup and use the already-cached addresses.
    evutil_addrinfo *res;
    if (newnode_evdns_cache_lookup(base, host, NULL, 443, &res) == 0) {
        debug("%s found %s in libevent dns cache (res:%p)\n", __func__, host, res);
        for (evutil_addrinfo *p = res; p; p=p->ai_next) {
            debug("%s address=%s\n", __func__, sockaddr_str_addronly(p->ai_addr));
        }
        dns_prefetch_results[result_index].result = copy_nn_addrinfo_from_evutil_addrinfo(res);
        evutil_freeaddrinfo(res);
        return;
    }
    debug("%s did not find %s in libevent dns cache\n", __func__, host);

    // if not, initiate a DNS query using the platform's DNS library,
    // (and use that result to update libevent's DNS cache)
    platform_dns_prefetch(n, result_index, result_id, host);
}

void dns_prefetch(network *n, uint64_t key, const char *host, evdns_base *base)
{
    size_t index;
    uint32_t id;
    PARSE_KEY(key, index, id);
    if (key <= 0) {
        return;
    }
    dns_prefetch_internal(n, index, id, host, base);
}

static int minimum_ttl(nn_addrinfo *nna)
{
    time_t now = time(0);
    nn_addrinfo *p;
    time_t min_expiry = 0;
    for (p = nna; p; p = p->ai_next) {
        if (p->ai_expiry == 0) {
            return 0;
        }
        if (min_expiry == 0 || min_expiry < p->ai_expiry) {
            min_expiry = p->ai_expiry;
        }
    }
    if (min_expiry > now) {
        debug("%s minttl=%ld min_expiry=%ld %s", __func__, min_expiry - now, min_expiry, ctime(&min_expiry))
            return min_expiry - now;
    }
    debug("%s returning 0\n", __func__);
    return 0;
}

char *make_ip_addr_list(nn_addrinfo *p)
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

void dns_prefetch_store_result(network *n, size_t result_index, uint64_t result_id, nn_addrinfo *nna, const char *host, bool fromevdns)
{
    debug("%s result_index:%zu result_id:%d host:%s\n", __func__, result_index, (int)result_id, host);
    if (dns_prefetch_results[result_index].id == result_id &&
        dns_prefetch_results[result_index].allocated == true) {
        dns_prefetch_results[result_index].result = nna;
    }
    if (fromevdns) {
        return;
    }
    int minttl = minimum_ttl(nna);

    if (minttl > 0) {
        // have a ttl obtained from DNS query, add to evdns cache
        evutil_addrinfo *addrinfo_copy = copy_evutil_addrinfo_from_nn_addrinfo(nna);
        debug("%s adding (host:%s=>%s) to evdns cache with ttl:%d)\n",
              __func__, host, make_ip_addr_list(nna), minttl);
        newnode_evdns_cache_write(n, host, addrinfo_copy, minttl);
        evutil_freeaddrinfo(addrinfo_copy);
        return;
    }

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
              __func__, host, make_ip_addr_list(nna));
        evutil_freeaddrinfo(res);
    } else {
        evutil_addrinfo *addrinfo_copy = copy_evutil_addrinfo_from_nn_addrinfo(nna);
        debug("%s adding (host:%s=>%s) to evdns cache with default ttl:60\n",
              __func__, host, make_ip_addr_list(nna));
        newnode_evdns_cache_write(n, host, addrinfo_copy, 60);
        evutil_freeaddrinfo(addrinfo_copy);
    }
}

int dns_prefetch_index(uint64_t key)
{
    size_t index;
    uint32_t id;
    if (key <= 0) {
        return -1;
    }
    PARSE_KEY(key, index, id);
    return index;
}

uint32_t dns_prefetch_id(uint64_t key)
{
    size_t index;
    uint32_t id;
    if (key <= 0) {
        return -1;
    }
    PARSE_KEY(key, index, id);
    return id;
}
