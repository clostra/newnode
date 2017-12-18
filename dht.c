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
    int fd;
    time_t save_time;
    unsigned char save_hash[crypto_generichash_BYTES];
    sockaddr_storage *peer_ss;
};

uint8_t rand_hash[20];
sockaddr_storage **blacklist;
uint blacklist_len;


void dht_filter_event_callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len)
{
    network *n = (network*)closure;
    if (n->dht->peer_ss && memeq(rand_hash, info_hash, sizeof(rand_hash))) {
        socklen_t ss_len = n->dht->peer_ss->ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        char host[NI_MAXHOST];
        char serv[NI_MAXSERV];
        getnameinfo((sockaddr*)n->dht->peer_ss, ss_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
        debug("banned %s:%s\n", host, serv);
        blacklist_len++;
        blacklist = realloc(blacklist, blacklist_len * sizeof(sockaddr_storage*));
        blacklist[blacklist_len - 1] = memdup(n->dht->peer_ss, ss_len);
        dht_blacklist_address((sockaddr*)n->dht->peer_ss, ss_len);
        return;
    }
    dht_event_callback(closure, event, info_hash, data, data_len);
}

void dht_add_bootstrap_cb(int result, evutil_addrinfo *ai, void *arg)
{
    dht *d = (dht*)arg;
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
    evutil_addrinfo hint = {
        .ai_family = AF_INET,
        .ai_protocol = IPPROTO_UDP,
        .ai_socktype = SOCK_DGRAM
    };
    snprintf(portbuf, sizeof(portbuf), "%u", port);
    evdns_getaddrinfo(d->n->evdns, host, portbuf, &hint, dht_add_bootstrap_cb, d);
}

dht* dht_setup(network *n, int fd)
{
    if (o_debug >= 2) {
        dht_debug = stdout;
    }
    dht *d = alloc(dht);
    d->n = n;
    d->fd = fd;
    uint8_t myid[20];
    randombytes_buf(myid, sizeof(myid));
    int rc = dht_init(fd, 0, myid, (unsigned char*)"dc\0\1");

    FILE *f = fopen("dht.dat", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        sockaddr_in sin[2048];
        int num = MIN(lenof(sin), fsize / sizeof(sockaddr_in));
        num = fread(sin, sizeof(sockaddr_in), num, f);
        fclose(f);
        for (int i = 0; i < num; i++) {
            dht_ping_node((const sockaddr *)&sin[i], sizeof(sockaddr_in));
        }
        if (num) {
            debug("dht loaded num:%d\n", num);
        }
    }

    f = fopen("dht6.dat", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        sockaddr_in6 sin6[2048];
        int num6 = MIN(lenof(sin6), fsize / sizeof(sockaddr_in6));
        num6 = fread(sin6, sizeof(sockaddr_in6), num6, f);
        fclose(f);
        for (int i = 0; i < num6; i++) {
            dht_ping_node((const sockaddr *)&sin6[i], sizeof(sockaddr_in6));
        }
        if (num6) {
            debug("dht loaded num6:%d\n", num6);
        }
    }

    dht_add_bootstrap(d, "router.utorrent.com", 6881);
    dht_add_bootstrap(d, "router.bittorrent.com", 6881);
    dht_add_bootstrap(d, "dht.libtorrent.org", 25401);

    dht_random_bytes(rand_hash, sizeof(rand_hash));
    dht_get_peers(d, rand_hash);

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
    FILE *f = fopen("dht.dat", "wb");
    fwrite(sin, sizeof(sockaddr_in), num, f);
    fclose(f);
    f = fopen("dht6.dat", "wb");
    fwrite(sin6, sizeof(sockaddr_in6), num6, f);
    fclose(f);
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

    d->peer_ss = (sockaddr_storage*)to;
    int r = dht_periodic(buffer, len, to, tolen, tosleep, dht_filter_event_callback, d->n);
    dht_save(d);
    d->peer_ss = NULL;
    return r != -1;
}

bool dht_process_icmp(dht *d, const uint8_t *buffer, size_t len, const sockaddr *to, socklen_t tolen, time_t *tosleep)
{
    // TODO: parse the buffer, cancel that request
    return false;
}

void dht_announce(dht *d, const uint8_t *info_hash)
{
    sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if (getsockname(d->fd, (sockaddr *)&sa, &salen) == -1) {
        fprintf(stderr, "dht getsockname failed %d (%s)\n", errno, strerror(errno));
        return;
    }
    port_t port = 0;
    if (sa.ss_family == AF_INET) {
        port = ntohs(((sockaddr_in*)&sa)->sin_port);
    } else if (sa.ss_family == AF_INET6) {
        port = ntohs(((sockaddr_in6*)&sa)->sin6_port);
    }
    dht_search(info_hash, port, sa.ss_family, dht_filter_event_callback, d->n);
}

void dht_get_peers(dht *d, const uint8_t *info_hash)
{
    sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if (getsockname(d->fd, (sockaddr *)&sa, &salen) == -1) {
        fprintf(stderr, "dht getsockname failed %d (%s)\n", errno, strerror(errno));
        return;
    }
    dht_search(info_hash, 0, sa.ss_family, dht_filter_event_callback, d->n);
}

void dht_destroy(dht *d)
{
    dht_uninit();
    free(d);
}

int dht_blacklisted(const sockaddr *sa, int salen)
{
    for (uint i = 0; i < blacklist_len; i++) {
        if (sa->sa_family != blacklist[i]->ss_family) {
            continue;
        }
        if (memeq(sa, blacklist[i], salen)) {
            debug("ignoring blacklisted node\n");
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
    return size;
}
