#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <string.h>

#include <sodium.h>

#include "dht/dht.h"

#include "dht.h"
#include "log.h"
#include "network.h"


struct dht {
    network *n;
    time_t save_time;
    unsigned char save_hash[crypto_generichash_BYTES];
    const sockaddr *peer_sa;
    bool filter_running:1;
};

uint8_t rand_hash[20];
sockaddr_storage **blacklist;
uint blacklist_len;


void dht_filter_event_callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len)
{
    network *n = (network*)closure;
    if (memeq(rand_hash, info_hash, sizeof(rand_hash))) {
        if (n->dht->peer_sa) {
            debug("dht banned %s\n", sockaddr_str(n->dht->peer_sa));
            blacklist_len++;
            socklen_t sa_len = sockaddr_get_length(n->dht->peer_sa);
            blacklist = realloc(blacklist, blacklist_len * sizeof(sockaddr_storage*));
            blacklist[blacklist_len - 1] = memdup(n->dht->peer_sa, sa_len);
            dht_blacklist_address(n->dht->peer_sa, sa_len);
        }
        if (event == DHT_EVENT_SEARCH_DONE) {
            n->dht->filter_running = false;
        }
        return;
    }
    dht_event_callback(closure, event, info_hash, data, data_len);
}

void dht_add_bootstrap_cb(int result, evutil_addrinfo *ai, void *arg)
{
    //dht *d = (dht*)arg;
    if (!ai) {
        return;
    }
    for (evutil_addrinfo* i = ai; i; i = i->ai_next) {
        dht_ping_node(ai->ai_addr, ai->ai_addrlen);
    }
    evutil_freeaddrinfo(ai);
}

void dht_add_bootstrap(dht *d, const char *host, port_t port)
{
    char portbuf[7];
    evutil_addrinfo hint = {.ai_family = PF_UNSPEC, .ai_protocol = IPPROTO_UDP, .ai_socktype = SOCK_DGRAM};
    snprintf(portbuf, sizeof(portbuf), "%u", port);
    evdns_getaddrinfo(d->n->evdns, host, portbuf, &hint, dht_add_bootstrap_cb, d);
}

dht* dht_setup(network *n)
{
    if (o_debug >= 2) {
        dht_debug = stdout;
    }
    dht *d = alloc(dht);
    d->n = n;
    uint8_t myid[20];
    randombytes_buf(myid, sizeof(myid));
    dht_init(d->n->fd, d->n->fd, myid, NULL);

    FILE *f = fopen("dht.dat", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        sockaddr_in sin[2048];
        size_t num = MIN(lenof(sin), fsize / sizeof(sockaddr_in));
        num = fread(sin, sizeof(sockaddr_in), num, f);
        fclose(f);
        for (uint i = 0; i < num; i++) {
            dht_ping_node((const sockaddr *)&sin[i], sizeof(sockaddr_in));
        }
        if (num) {
            debug("dht loaded num:%zu\n", num);
        }
    }

    f = fopen("dht6.dat", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        sockaddr_in6 sin6[2048];
        size_t num6 = MIN(lenof(sin6), fsize / sizeof(sockaddr_in6));
        num6 = fread(sin6, sizeof(sockaddr_in6), num6, f);
        fclose(f);
        for (uint i = 0; i < num6; i++) {
            dht_ping_node((const sockaddr *)&sin6[i], sizeof(sockaddr_in6));
        }
        if (num6) {
            debug("dht loaded num6:%zu\n", num6);
        }
    }

    dht_add_bootstrap(d, "router.utorrent.com", 6881);
    dht_add_bootstrap(d, "router.bittorrent.com", 6881);
    dht_add_bootstrap(d, "dht.libtorrent.org", 25401);

    return d;
}

void dht_save(dht *d)
{
    if (time(NULL) - d->save_time < 5) {
        return;
    }
    d->save_time = time(NULL);

    sockaddr_in sin[2048];
    int num = lenof(sin);
    sockaddr_in6 sin6[2048];
    int num6 = lenof(sin6);
    dht_get_nodes(sin, &num, sin6, &num6);

    // to avoid frequent writes, we compare the hash. the dht could instead indicate changes.
    unsigned char hash[crypto_generichash_BYTES];
    dht_hash(hash, sizeof(hash), sin, num, sin6, num6, NULL, 0);
    if (memeq(hash, d->save_hash, sizeof(hash))) {
        return;
    }
    memcpy(d->save_hash, hash, sizeof(hash));

    ddebug("dht saving num:%d num6:%d\n", num, num6);
    FILE *f;
    if (num) {
        f = fopen("dht.dat", "wb");
        if (f) {
            fwrite(sin, sizeof(sockaddr_in), num, f);
            fclose(f);
        }
    }
    if (num6) {
        f = fopen("dht6.dat", "wb");
        if (f) {
            fwrite(sin6, sizeof(sockaddr_in6), num6, f);
            fclose(f);
        }
    }
}

time_t dht_tick(dht *d)
{
    time_t tosleep;
    dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_filter_event_callback, d->n);
    dht_save(d);
    return tosleep;
}

bool dht_process_udp(dht *d, const uint8_t *buffer, size_t len, const sockaddr *to, socklen_t tolen, time_t *tosleep)
{
    // XXX: ACK; dht require NULL terminate packet -- I just happen to know there's enough space in the buffer...
    ((uint8_t*)buffer)[len] = '\0';

    d->peer_sa = to;
    int r = dht_periodic(buffer, len, to, tolen, tosleep, dht_filter_event_callback, d->n);
    dht_save(d);
    d->peer_sa = NULL;
    return r != -1;
}

bool dht_process_icmp(dht *d, const uint8_t *buffer, size_t len, const sockaddr *to, socklen_t tolen, time_t *tosleep)
{
    // TODO: parse the buffer, cancel that request
    return false;
}

void dht_filter(dht *d)
{
    if (d->filter_running) {
        return;
    }
    d->filter_running = true;
    dht_random_bytes(rand_hash, sizeof(rand_hash));
    dht_get_peers(d, rand_hash);
}

void dht_announce(dht *d, const uint8_t *info_hash)
{
    sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if (getsockname(d->n->fd, (sockaddr *)&sa, &salen) == -1) {
        fprintf(stderr, "dht getsockname failed %d (%s)\n", errno, strerror(errno));
        return;
    }
    dht_filter(d);
    dht_search(info_hash, sockaddr_get_port((sockaddr*)&sa), sa.ss_family, dht_filter_event_callback, d->n);
}

void dht_get_peers(dht *d, const uint8_t *info_hash)
{
    sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if (getsockname(d->n->fd, (sockaddr *)&sa, &salen) == -1) {
        fprintf(stderr, "dht getsockname failed %d (%s)\n", errno, strerror(errno));
        return;
    }
    dht_filter(d);
    dht_search(info_hash, 0, sa.ss_family, dht_filter_event_callback, d->n);
}

void dht_destroy(dht *d)
{
    dht_uninit();
    free(d);
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const sockaddr *to, int tolen)
{
    ddebug("dht_sendto(%d, %s)\n", len, sockaddr_str(to));
    return (int)udp_sendto(sockfd, buf, len, to, tolen);
}

int dht_blacklisted(const sockaddr *sa, int salen)
{
    for (uint i = 0; i < blacklist_len; i++) {
        if (sa->sa_family != blacklist[i]->ss_family) {
            continue;
        }
        if (memeq(sa, blacklist[i], sockaddr_get_length((const sockaddr *)blacklist[i]))) {
            //debug("dht ignoring blacklisted node\n");
            return 1;
        }
    }
    return 0;
}

void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3)
{
    assert(crypto_generichash_BYTES_MAX >= (uint)hash_size);
    unsigned char hash[MAX(crypto_generichash_BYTES_MIN, hash_size)];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(hash));
    crypto_generichash_update(&state, v1, len1);
    crypto_generichash_update(&state, v2, len2);
    crypto_generichash_update(&state, v3, len3);
    crypto_generichash_final(&state, hash, sizeof(hash));
    memcpy(hash_return, hash, hash_size);
}

int dht_random_bytes(void *buf, size_t size)
{
    randombytes_buf(buf, size);
    return (int)size;
}
