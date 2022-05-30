#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <Block.h>

#include <sodium.h>

#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>

#include <parson.h>

#include "dht/dht.h"

#include "nn_features.h"
#include "ui.h"
#include "log.h"
#include "lsd.h"
#include "d2d.h"
#include "utp.h"
#include "http.h"
#include "timer.h"
#include "obfoo.h"
#include "thread.h"
#include "base64.h"
#include "network.h"
#include "newnode.h"
#include "constants.h"
#include "bev_splice.h"
#include "hash_table.h"
#include "bufferevent_utp.h"
#include "dns_prefetch.h"
#include "g_https_cb.h"

#ifdef ANDROID
#include <sys/system_properties.h>
#endif


#define NO_DIRECT 0
#define NO_CACHE 0

typedef struct {
    in_addr_t ip;
    port_t port;
} PACKED packed_ipv4;
static_assert(sizeof(packed_ipv4) == 6, "packed_ipv4 should be 6 bytes");

typedef struct {
    in6_addr ip;
    port_t port;
} PACKED packed_ipv6;
static_assert(sizeof(packed_ipv4) == 6, "packed_ipv6 should be 18 bytes");

typedef struct {
    sockaddr_storage addr;
    time_t last_verified;
    time_t last_connect;
    time_t last_connect_attempt;
    char via;
    uint8_t loop;
    bool is_injector:1;
} peer;

typedef struct {
    network *n;
    peer *peer;
    bufferevent *bev;
    evhttp_connection *evcon;
} peer_connection;

typedef struct {
    bool failed:1;
    int64_t last_connect_attempt;
    int64_t time_since_verified;
    bool never_connected:1;
    uint8_t loop;
    uint8_t salt;
    peer *peer;
} PACKED peer_sort;

#define CACHE_PATH "./cache/"
#define CACHE_NAME CACHE_PATH "cache.XXXXXXXX"

typedef bool (^peer_filter)(peer *p);
typedef void (^peer_connected)(peer_connection *p);
typedef struct pending_request {
    char *via;
    peer_connected on_connect;
    TAILQ_ENTRY(pending_request) next;
} pending_request;

struct proxy_request;
typedef struct proxy_request proxy_request;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t chunk_index;
    evbuffer *chunk_buffer;
} chunked_range;

typedef struct {
    pending_request r;
    peer_connection *pc;
    evhttp_request *req;
    proxy_request *p;
    chunked_range range;
} peer_request;

typedef struct {
    evhttp_request *req;
    evhttp_connection *evcon;
    proxy_request *p;
    chunked_range range;
} direct_request;

#define rdelta(r) ((double)(us_clock() - r->start_time) / 1000.0)

struct proxy_request {
    network *n;

    evhttp_request *server_req;
    uint64 start_time;

    char *uri;
    evhttp_cmd_type http_method;

    char *authority;
    char *etag;

    direct_request direct_requests[2];

    int direct_code;
    char *direct_code_line;
    evkeyvalq direct_headers;
    evkeyvalq output_headers;

    merkle_tree *m;
    uint8_t root_hash[crypto_generichash_BYTES];

    peer_request requests[10];

    uint64_t range_start;
    uint64_t range_end;

    char cache_name[sizeof(CACHE_NAME)];
    int cache_file;

    evbuffer *header_buf;
    uint64_t content_length;
    uint64_t total_length;
    uint64_t byte_playhead;
    bool *have_bitfield;

    bool chunked:1;
    bool merkle_tree_finished:1;
    bool dont_free:1;
    bool localhost:1;
};

typedef hash_table peer_array;

typedef struct {
    uint64_t from_browser;
    uint64_t to_browser;
    uint64_t from_peer;
    uint64_t to_peer;
    uint64_t from_direct;
    uint64_t to_direct;
    uint64_t from_p2p;
    uint64_t to_p2p;
    uint64_t last_reported;
} byte_counts;

hash_table *byte_count_per_authority;
timer *stats_report_timer;
network *g_stats_n;
evconnlistener *g_listener;
uint64_t g_cid;
uint64_t g_all_peer;
uint64_t g_all_direct;

typedef struct {
    uint64_t attempts;                  // num tryfirst attempts
    uint64_t successes;                 // num successful attempts
    uint64_t blocked;                   // num likely blocked attempts
    uint64_t bytes_xferred;             // total bytes transferred in tryfirst
    uint64_t xfer_time_us;              // total time required to transfer
    uint64_t last_attempt;              // time of last attempt
    uint64_t last_success;              // time of last successful attempt
    uint64_t last_blocked;              // time of last blocked attempt
} tryfirst_stats;

hash_table *tryfirst_per_origin_server;


char g_ip[46];                          // note: max length of text of ipv6 address == 45
                                        //       (assuming IPv4-mapped notation is used)
char g_country[3];                      // 2-letter ISO country code + '\0'
int g_asn = -1;                         // autonomous system number (if returned by ipinfo)
time_t g_ipinfo_timestamp = 0;          // timestamp of last ipinfo request
time_t g_ipinfo_logged_timestamp = 0;   // last logged g_ipinfo_timestamp
timer *g_ifchange_timer;

bool g_tryfirst = true;                 // set to false to disable try first
unsigned int g_tryfirst_timeout = 7;    // seconds
unsigned int g_tryfirst_bufsize = 10240; // max bytes accepted on a try first attempt
                                         // (even if we're always doing Range:bytes=0,1
                                         // some servers ignore or refuse to do this)
bool g_have_ipv6 = false;                // can communicate directly with public IPv6 addresses

peer_array *injectors;
peer_array *injector_proxies;
peer_array *all_peers;

peer_connection *peer_connections[20];

char via_tag[] = "1.1 _.newnode";
time_t injector_reachable;
time_t last_request;
timer *saving_peers;
uint16_t g_port;
const char *g_app_name;
const char *g_app_id;
https_callback g_https_cb;

static_assert(20 >= crypto_generichash_BYTES_MIN, "dht hash must fit in generichash size");
uint8_t encrypted_injector_swarm_m1[20];
uint8_t encrypted_injector_swarm_p0[20];
uint8_t encrypted_injector_swarm_p1[20];
uint8_t encrypted_injector_proxy_swarm_m1[20];
uint8_t encrypted_injector_proxy_swarm_p0[20];
uint8_t encrypted_injector_proxy_swarm_p1[20];

size_t pending_requests_len;
TAILQ_HEAD(, pending_request) pending_requests;


void save_peers(network *n);

int mkpath(char *file_path)
{
    for (char *p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, 0755) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                return -1;
            }
        }
        *p = '/';
    }
    return 0;
}

void connect_more_injectors(network *n, bool injector_preference);

void pending_request_complete(pending_request *r, peer_connection *pc)
{
    peer_connected on_connect = r->on_connect;
    free(r->via);
    r->via = NULL;
    r->on_connect = NULL;
    on_connect(pc);
    Block_release(on_connect);
}

bool via_contains(const char *via, char v)
{
    if (!via || !v) {
        return false;
    }
    char vtag[] = "_.newnode";
    vtag[0] = v;
    return !!strstr(via, vtag);
}

bool bufferevent_is_utp(bufferevent *bev)
{
    if (BEV_IS_UTP(bev)) {
        return true;
    }
    evutil_socket_t fd = bufferevent_getfd(bev);
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getpeername(fd, (sockaddr *)&ss, &len);
    // AF_LOCAL is from socketpair(), which means utp_bufferevent
    return ss.ss_family == AF_LOCAL;
}

void on_utp_connect(network *n, peer_connection *pc)
{
    const sockaddr *ss = (const sockaddr *)&pc->peer->addr;
    char host[NI_MAXHOST];
    getnameinfo(ss, sockaddr_get_length(ss), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
    bufferevent_disable(pc->bev, EV_READ|EV_WRITE);
    assert(pc->bev);
    // XXX: hack around evhttp requiring fd != -1 to assume the bev is connected. it doesn't have to be a valid fd, though.
    // https://github.com/libevent/libevent/issues/1268
    bufferevent_setfd(pc->bev, -2);
    pc->evcon = evhttp_connection_base_bufferevent_new(n->evbase, n->evdns, pc->bev, host, sockaddr_get_port(ss));
    bufferevent_setfd(pc->bev, EVUTIL_INVALID_SOCKET);
    debug("on_utp_connect %s bev:%p evcon:%p\n", sockaddr_str(ss), pc->bev, pc->evcon);
    pc->bev = NULL;

    // handle waiting requests first
    pending_request *r;
    TAILQ_FOREACH(r, &pending_requests, next) {
        if (via_contains(r->via, pc->peer->via)) {
            continue;
        }
        TAILQ_REMOVE(&pending_requests, r, next);
        pending_requests_len--;
        debug("on_utp_connect request:%p (outstanding:%zu)\n", r, pending_requests_len);
        bool found = false;
        for (uint i = 0; i < lenof(peer_connections); i++) {
            if (peer_connections[i] == pc) {
                peer_connections[i] = NULL;
                found = true;
                break;
            }
        }
        assert(found);
        debug("using new pc:%p evcon:%p via:%c (%s) for request:%p\n", pc, pc->evcon, pc->peer->via ? pc->peer->via : ' ', r->via, r);
        pending_request_complete(r, pc);
        if (!TAILQ_EMPTY(&pending_requests)) {
            connect_more_injectors(n, false);
        }
        break;
    }
}

void utp_connect_event_cb(bufferevent *bufev, short events, void *arg)
{
    peer_connection *pc = (peer_connection *)arg;
    assert(pc->bev == bufev);
    time_t delta = time(NULL) - pc->peer->last_connect_attempt;
    debug("%s pc:%p peer:%p (%lds) events:0x%x %s\n", __func__, pc, pc->peer, delta, events, bev_events_to_str(events));
    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        bufferevent_free(pc->bev);
        pc->bev = NULL;
        if (pc->peer->is_injector) {
            injector_reachable = 0;
        }
        for (uint i = 0; i < lenof(peer_connections); i++) {
            if (peer_connections[i] == pc) {
                peer_connections[i] = NULL;
                break;
            }
        }
        assert(!pc->evcon);
        pending_request *r = TAILQ_FIRST(&pending_requests);
        if (r && time(NULL) - last_request < 30) {
            connect_more_injectors(pc->n, false);
        }
        free(pc);
    } else if (events & BEV_EVENT_CONNECTED) {
        on_utp_connect(pc->n, pc);
    }
}

const char* peer_addr_str(const peer *p)
{
    return sockaddr_str((const sockaddr *)&p->addr);
}

peer_connection* evhttp_utp_connect(network *n, peer *p)
{
    utp_socket *s = utp_create_socket(n->utp);
    debug("evhttp_utp_connect %s\n", peer_addr_str(p));
    p->last_connect_attempt = time(NULL);
    peer_connection *pc = alloc(peer_connection);
    pc->n = n;
    pc->peer = p;
    pc->bev = bufferevent_utp_new(n->evbase, n->utp, NULL, BEV_OPT_CLOSE_ON_FREE);
    if (!pc->bev) {
        debug("bufferevent_utp_new could not allocate %s\n", peer_addr_str(p));
        free(pc);
        return NULL;
    }
    bufferevent_utp_connect(pc->bev, (const sockaddr*)&p->addr, sockaddr_get_length((const sockaddr*)&p->addr));
    bufferevent_setcb(pc->bev, NULL, NULL, utp_connect_event_cb, pc);
    bufferevent_enable(pc->bev, EV_READ);
    return pc;
}

peer* get_peer(peer_array *pa, const sockaddr *a)
{
    return hash_get(pa, sockaddr_str(a));
}

peer* add_peer(peer_array **pa, const sockaddr *a, create_fn c)
{
    return (peer*)hash_get_or_insert(*pa, sockaddr_str(a), ^void* {
        dht_ping_node((const sockaddr *)a, sockaddr_get_length(a));
        return c();
    });
}

void add_address(network *n, peer_array **pa, const sockaddr *addr, socklen_t addrlen)
{
    // paper over a bug in some DHT implementation that winds up with 1 for the port
    if (sockaddr_get_port(addr) == 1) {
        return;
    }

    __block bool inserted = false;
    peer *p = add_peer(pa, addr, ^void* {
        inserted = true;
        peer *np = alloc(peer);
        memcpy(&np->addr, addr, addrlen);
        return np;
    });
    if (!inserted) {
        return;
    }

    const char *label = "peer";
    if (*pa == injectors) {
        label = "injector";
        p->is_injector = true;
    } else if (*pa == injector_proxies) {
        label = "injector proxy";
    } else {
        assert(*pa == all_peers);
    }
    ddebug("new %s %s\n", label, peer_addr_str(p));

    if (!TAILQ_EMPTY(&pending_requests)) {
        for (uint k = 0; k < lenof(peer_connections); k++) {
            if (peer_connections[k]) {
                continue;
            }
            peer_connections[k] = evhttp_utp_connect(n, p);
            break;
        }
    }

    save_peers(n);
}

void add_v4_addresses(network *n, peer_array **pa, const uint8_t *addrs, size_t num_addrs)
{
    for (uint i = 0; i < num_addrs; i++) {
        sockaddr_storage addr;

        packed_ipv4 *a = (packed_ipv4 *)&addrs[sizeof(packed_ipv4) * i];
        sockaddr_in *sin = (sockaddr_in*)&addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = a->ip;
        sin->sin_port = a->port;
#ifdef __APPLE__
        sin->sin_len = sizeof(sockaddr_in);
#endif

        add_address(n, pa, (const sockaddr*)&addr, sockaddr_get_length((const sockaddr*)&addr));

        if (o_debug >= 2) {
            if (i + 1 != num_addrs) {
                printf(", ");
            }
        }
    }
}

void add_v6_addresses(network *n, peer_array **pa, const uint8_t *addrs, size_t num_addrs)
{
    for (uint i = 0; i < num_addrs; i++) {
        sockaddr_storage addr;

        packed_ipv6 *a = (packed_ipv6 *)&addrs[sizeof(packed_ipv6) * i];
        sockaddr_in6 *sin6 = (sockaddr_in6*)&addr;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, &a->ip, sizeof(a->ip));
        sin6->sin6_port = a->port;
#ifdef __APPLE__
        sin6->sin6_len = sizeof(sockaddr_in6);
#endif

        add_address(n, pa, (const sockaddr*)&addr, sockaddr_get_length((const sockaddr*)&addr));

        if (o_debug >= 2) {
            if (i + 1 != num_addrs) {
                printf(", ");
            }
        }
    }
}

void add_sockaddr(network *n, const sockaddr *addr, socklen_t addrlen)
{
    add_address(n, &all_peers, addr, addrlen);
}

void dht_event_callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len)
{
    network *n = (network*)closure;

    peer_array **peer_list = NULL;

    if (memeq(info_hash, encrypted_injector_swarm_m1, sizeof(encrypted_injector_swarm_m1)) ||
        memeq(info_hash, encrypted_injector_swarm_p0, sizeof(encrypted_injector_swarm_p0)) ||
        memeq(info_hash, encrypted_injector_swarm_p1, sizeof(encrypted_injector_swarm_p1))) {
        peer_list = &injectors;
    } else if (memeq(info_hash, encrypted_injector_proxy_swarm_m1, sizeof(encrypted_injector_proxy_swarm_m1)) ||
               memeq(info_hash, encrypted_injector_proxy_swarm_p0, sizeof(encrypted_injector_proxy_swarm_p0)) ||
               memeq(info_hash, encrypted_injector_proxy_swarm_p1, sizeof(encrypted_injector_proxy_swarm_p1))) {
        peer_list = &injector_proxies;
    } else {
        peer_list = &all_peers;
    }

    const uint8_t* peers = data;
    size_t num_peers = data_len / (event == DHT_EVENT_VALUES ? sizeof(packed_ipv4) : sizeof(packed_ipv6));

    if (o_debug >= 2) {
        printf("{\"");
        for (int j = 0; j < 20; j++) {
            printf("%02x", info_hash[j]);
        }
        printf("\": [");
    }

    if (event == DHT_EVENT_VALUES) {
        ddebug("dht_event_callback num_peers:%zu\n", num_peers);
        add_v4_addresses(n, peer_list, peers, num_peers);
    } else if (event == DHT_EVENT_VALUES6) {
        ddebug("dht_event_callback v6 num_peers:%zu\n", num_peers);
        add_v6_addresses(n, peer_list, peers, num_peers);
    } else {
        ddebug("dht_event_callback event:%d\n", event);
    }

    if (o_debug >= 2) {
        printf("]}\n");
    }
}

void update_injector_proxy_swarm(network *n)
{
    time_t t = time(NULL);
    tm *tm = gmtime(&t);
    char name[1024];

    if (injector_reachable) {
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday - 1));
        crypto_generichash(encrypted_injector_proxy_swarm_m1, sizeof(encrypted_injector_proxy_swarm_m1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_m1);
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday + 0));
        crypto_generichash(encrypted_injector_proxy_swarm_p0, sizeof(encrypted_injector_proxy_swarm_p0), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_p0);
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday + 1));
        crypto_generichash(encrypted_injector_proxy_swarm_p1, sizeof(encrypted_injector_proxy_swarm_p1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_p1);
    } else {
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday - 1));
        crypto_generichash(encrypted_injector_proxy_swarm_m1, sizeof(encrypted_injector_proxy_swarm_m1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_m1);
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday + 0));
        crypto_generichash(encrypted_injector_proxy_swarm_p0, sizeof(encrypted_injector_proxy_swarm_p0), (uint8_t*)name, strlen(name), NULL, 0);
        dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_p0);
        snprintf(name, sizeof(name), "injector proxy %d-%d", tm->tm_year, (tm->tm_yday + 1));
        crypto_generichash(encrypted_injector_proxy_swarm_p1, sizeof(encrypted_injector_proxy_swarm_p1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm_p1);
    }
}

void abort_connect(pending_request *r)
{
    if (!r->on_connect) {
        return;
    }
    debug("aborting request:%p\n", r);
    free(r->via);
    r->via = NULL;
    Block_release(r->on_connect);
    r->on_connect = NULL;
    TAILQ_REMOVE(&pending_requests, r, next);
    pending_requests_len--;
    debug("abort_connect request:%p (outstanding:%zu)\n", r, pending_requests_len);
}

void peer_disconnect(peer_connection *pc)
{
    debug("disconnecting pc:%p\n", pc);
    if (pc->evcon) {
        evhttp_connection_free(pc->evcon);
    }
    if (pc->bev) {
        bufferevent_free(pc->bev);
    }
    free(pc);
}

void proxy_cache_delete(proxy_request *p)
{
    if (p->cache_file != -1) {
        close(p->cache_file);
        p->cache_file = -1;
        unlink(p->cache_name);
    }
}

bool proxy_request_any_direct(const proxy_request *p)
{
    for (size_t i = 0; i < lenof(p->direct_requests); i++) {
        if (p->direct_requests[i].req) {
            return true;
        }
    }
    return false;
}

bool proxy_request_any_peers(const proxy_request *p)
{
    for (size_t i = 0; i < lenof(p->requests); i++) {
        if (p->requests[i].req || p->requests[i].r.on_connect) {
            return true;
        }
    }
    return false;
}

void proxy_send_error(proxy_request *p, int error, const char *reason)
{
    if (proxy_request_any_direct(p) || proxy_request_any_peers(p)) {
        return;
    }
    if (p->server_req) {
        if (p->server_req->evcon) {
            evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
        }
        if (p->server_req->response_code) {
            debug("p:%p req:%p evcon:%p (%.2fms) responding can't send error, terminating connection. %d %s\n",
                  p, p->server_req, p->server_req->evcon, rdelta(p), error, reason);
            evhttp_send_reply_end(p->server_req);
        } else {
            debug("p:%p req:%p evcon:%p (%.2fms) responding with %d %s\n",
                  p, p->server_req, p->server_req->evcon, rdelta(p),
                  error, reason);
            evhttp_send_error(p->server_req, error, reason);
        }
        p->server_req = NULL;
    }
}

void proxy_request_cleanup(proxy_request *p, const char *reason)
{
    size_t num_peers = 0;
    size_t num_direct = 0;
    for (size_t i = 0; i < lenof(p->direct_requests); i++) {
        if (p->direct_requests[i].req) {
            num_direct++;
        }
    }
    for (size_t i = 0; i < lenof(p->requests); i++) {
        if (p->requests[i].req || p->requests[i].r.on_connect) {
            num_peers++;
        }
    }
    debug("%s:%d peers:%zu direct:%zu\n", __func__, __LINE__, num_peers, num_direct);
    if (p->dont_free || proxy_request_any_peers(p) || proxy_request_any_direct(p)) {
        return;
    }
    if (p->server_req) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "Bad Gateway (%s)", reason);
        proxy_send_error(p, 502, buf);
    }
    for (size_t i = 0; i < lenof(p->requests); i++) {
        peer_request *r = &p->requests[i];
        if (r->pc) {
            peer_disconnect(r->pc);
            r->pc = NULL;
        }
        assert(!r->range.chunk_buffer);
    }
    for (size_t i = 0; i < lenof(p->direct_requests); i++) {
        direct_request *d = &p->direct_requests[i];
        if (d->evcon) {
            evhttp_connection_free(d->evcon);
            d->evcon = NULL;
        }
        if (d->range.chunk_buffer) {
            evbuffer_free(d->range.chunk_buffer);
            d->range.chunk_buffer = NULL;
        }
    }
    free(p->direct_code_line);
    evhttp_clear_headers(&p->direct_headers);
    evhttp_clear_headers(&p->output_headers);
    if (p->header_buf) {
        evbuffer_free(p->header_buf);
    }
    merkle_tree_free(p->m);
    free(p->have_bitfield);
    proxy_cache_delete(p);
    free(p->authority);
    free(p->etag);
    free(p->uri);
    free(p);
}

void peer_request_cleanup(peer_request *r, const char *reason)
{
    if (r->req) {
        return;
    }
    if (r->pc) {
        peer_disconnect(r->pc);
        r->pc = NULL;
    }
    if (r->range.chunk_buffer) {
        evbuffer_free(r->range.chunk_buffer);
        r->range.chunk_buffer = NULL;
    }
    proxy_request_cleanup(r->p, reason);
}

void peer_reuse(network *n, peer_connection *pc)
{
    if (pc->bev) {
        bufferevent_disable(pc->bev, EV_READ|EV_WRITE);
    }
    // handle waiting requests first
    pending_request *r;
    TAILQ_FOREACH(r, &pending_requests, next) {
        if (via_contains(r->via, pc->peer->via)) {
            continue;
        }
        TAILQ_REMOVE(&pending_requests, r, next);
        pending_requests_len--;
        debug("reusing pc:%p evcon:%p via:%c (%s) for request:%p (outstanding:%zu)\n",
              pc, pc->evcon, pc->peer->via ? pc->peer->via : ' ', r->via, r, pending_requests_len);
        pending_request_complete(r, pc);
        return;
    }
    // add to the pool if there's a slot
    for (uint i = 0; i < lenof(peer_connections); i++) {
        if (!peer_connections[i]) {
            debug("saving pc:%p for reuse\n", pc);
            peer_connections[i] = pc;
            return;
        }
    }
    // replace an in-progress connection if there is one
    for (uint i = 0; i < lenof(peer_connections); i++) {
        peer_connection *old_pc = peer_connections[i];
        if (!old_pc->evcon) {
            debug("replacing old_pc:%p with pc:%p\n", old_pc, pc);
            peer_disconnect(old_pc);
            peer_connections[i] = pc;
            return;
        }
    }
    // oh well
    peer_disconnect(pc);
}

void direct_request_cancel(direct_request *d)
{
    if (d->req) {
        evhttp_cancel_request(d->req);
        d->req = NULL;
    }
}

void proxy_direct_requests_cancel(proxy_request *p)
{
    for (size_t i = 0; i < lenof(p->direct_requests); i++) {
        if (p->direct_requests[i].req) {
            direct_request_cancel(&p->direct_requests[i]);
        }
    }
}

void peer_request_cancel(peer_request *r)
{
    if (r->req) {
        debug("r:%p %s:%d p:%p\n", r, __func__, __LINE__, r->p);
        evhttp_cancel_request(r->req);
        r->req = NULL;
    }
    if (!r->pc) {
        abort_connect(&r->r);
    } else {
        peer_disconnect(r->pc);
        debug("r:%p %s:%d r->pc = NULL\n", r, __func__, __LINE__);
        r->pc = NULL;
    }
    if (r->range.chunk_buffer) {
        evbuffer_free(r->range.chunk_buffer);
        r->range.chunk_buffer = NULL;
    }
}

void proxy_peer_requests_cancel(proxy_request *p)
{
    for (size_t i = 0; i < lenof(p->requests); i++) {
        peer_request_cancel(&p->requests[i]);
    }
}

bool write_header_to_file(int headers_file, int code, const char *code_line, evkeyvalq *input_headers)
{
    evbuffer_auto_free evbuffer *buf = evbuffer_new();
    evbuffer_add_printf(buf, "HTTP/1.1 %d %s\r\n", code, code_line);
    const char *headers[] = hashed_headers;
    for (int i = 0; i < (int)lenof(headers); i++) {
        const char *key = headers[i];
        const char *value = evhttp_find_header(input_headers, key);
        if (!value) {
            continue;
        }
        evbuffer_add_printf(buf, "%s: %s\r\n", key, value);
    }
    const char *sign_headers[] = {"X-MSign", "X-Hashes"};
    for (int i = 0; i < (int)lenof(sign_headers); i++) {
        const char *key = sign_headers[i];
        const char *value = evhttp_find_header(input_headers, key);
        evbuffer_add_printf(buf, "%s: %s\r\n", key, value);
    }
    evbuffer_add_printf(buf, "\r\n");
    return evbuffer_write_to_file(buf, headers_file);
}

bool evcon_is_localhost(evhttp_connection *evcon)
{
    return bufferevent_is_localhost(evhttp_connection_get_bufferevent(evcon));
}

bool evcon_is_utp(evhttp_connection *evcon)
{
    return bufferevent_is_utp(evhttp_connection_get_bufferevent(evcon));
}

void copy_response_headers(evhttp_request *from, evhttp_request *to)
{
    const char *response_header_whitelist[] = hashed_headers;
    for (uint i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(from, to, response_header_whitelist[i]);
    }
    copy_header(from, to, "Content-Length");
    if (!evcon_is_localhost(to->evcon)) {
        copy_header(from, to, "Content-Location");
        copy_header(from, to, "X-MSign");
        copy_header(from, to, "X-Hashes");
    }
}

uint64_t num_chunks(const proxy_request *p)
{
    return DIV_ROUND_UP(p->total_length, LEAF_CHUNK_SIZE);
}

uint64_t chunk_length(const proxy_request *p, uint64_t chunk_index)
{
    if (p->chunked) {
        return LEAF_CHUNK_SIZE;
    }
    if ((chunk_index + 1) * LEAF_CHUNK_SIZE <= p->total_length) {
        return LEAF_CHUNK_SIZE;
    }
    return p->total_length % LEAF_CHUNK_SIZE;
}

void direct_submit_request(proxy_request *p);
void direct_chunked_cb(evhttp_request *req, void *arg);
void proxy_submit_request(proxy_request *p);

void proxy_set_length(proxy_request *p, uint64_t total_length)
{
    debug("%s p:%p total_length:%"PRIu64" num_chunks:%"PRIu64"\n", __func__, p, total_length, num_chunks(p));
    uint64_t old_length = num_chunks(p);
    uint64_t old_chunks = DIV_ROUND_UP(old_length, LEAF_CHUNK_SIZE);
    p->total_length = total_length;
    if (!p->have_bitfield) {
        p->have_bitfield = calloc(1, num_chunks(p));
        return;
    }
    if (num_chunks(p) == old_chunks) {
        return;
    }
    bool *have_bitfield = realloc(p->have_bitfield, num_chunks(p));
    if (num_chunks(p) > old_chunks && have_bitfield) {
        uint64_t diff = num_chunks(p) - old_chunks;
        bzero(&have_bitfield[old_chunks], diff);
    }
    p->have_bitfield = have_bitfield;
}

int proxy_setup_range(proxy_request *p, evhttp_request *req, chunked_range *range)
{
    if (p->cache_file == -1) {
        snprintf(p->cache_name, sizeof(p->cache_name), CACHE_NAME);
        mkpath(p->cache_name);
        p->cache_file = mkstemp(p->cache_name);
        debug("start cache:%s\n", p->cache_name);
    }

    if (!p->etag) {
        const char *etag = evhttp_find_header(req->input_headers, "ETag");
        p->etag = etag?strdup(etag):NULL;
    }

    uint64_t total_length = 0;
    const char *content_range = evhttp_find_header(req->input_headers, "Content-Range");
    const char *content_length = evhttp_find_header(req->input_headers, "Content-Length");
    const char *transfer_encoding = evhttp_find_header(req->input_headers, "Transfer-Encoding");
    if (content_range) {
        debug("Content-Range: %s\n", content_range);
        sscanf(content_range, "bytes %"PRIu64"-%"PRIu64"/%"PRIu64, &range->start, &range->end, &total_length);
        uint64_t header_prefix = p->header_buf ? evbuffer_get_length(p->header_buf) : 0;
        range->chunk_index = (range->start + header_prefix) / LEAF_CHUNK_SIZE;
        debug("p:%p start:%"PRIu64" chunk_index:%"PRIu64"\n", p, range->start, range->chunk_index);
    } else if (content_length) {
        debug("Content-Length: %s\n", content_length);
        char *endp;
        ev_int64_t clen = evutil_strtoll(content_length, &endp, 10);
        if (*content_length == '\0' || *endp != '\0' || clen < 0) {
            debug("%s: illegal content length: %s", __func__, content_length);
            proxy_send_error(p, 502, "Invalid Gateway Content-Length");
            return -1;
        }
        total_length = (uint64_t)clen;
        range->end = clen - 1;
    } else if (transfer_encoding && strstr(transfer_encoding, "chunked")) {
        debug("Transfer-Encoding: %s\n", transfer_encoding);
        // oh, bother.
        p->chunked = true;
    }

    if (!p->header_buf) {
        int code = req->response_code;
        const char *rangeh = evhttp_find_header(p->server_req->input_headers, "Range");
        if (code == 206 && !rangeh) {
            code = 200;
        }
        p->direct_code = code;
        p->direct_code_line = strdup(req->response_code_line);
        p->header_buf = build_request_buffer(code, req->input_headers);
        uint64_t header_prefix = p->header_buf ? evbuffer_get_length(p->header_buf) : 0;
        range->chunk_index = (range->start + header_prefix) / LEAF_CHUNK_SIZE;
    }

    if (p->content_length && p->content_length != total_length) {
        proxy_send_error(p, 502, "Incorrect Gateway Content-Length");
        return -1;
    }

    p->content_length = total_length;
    if (!p->range_end && p->content_length > 0) {
        p->range_end = p->content_length - 1;
    }

    if (req->type == EVHTTP_REQ_HEAD) {
        total_length = 0;
    }

    total_length += evbuffer_get_length(p->header_buf);

    if (p->total_length && p->total_length != total_length) {
        proxy_send_error(p, 502, "Incorrect Gateway Range");
        return -1;
    }

    proxy_set_length(p, total_length);

    return 1;
}

int direct_header_cb(evhttp_request *req, void *arg)
{
    direct_request *d = (direct_request*)arg;
    proxy_request *p = d->p;
    debug("d:%p (%.2fms) direct_header_cb %d %s %s\n", d, rdelta(p), req->response_code, req->response_code_line, p->uri);

    // "416 Range Not Satisfiable" means we can't use additional connections at all.
    if (req->response_code == 416) {
        return -1;
    }

    // TODO: to mix data from origin with peers, we still need to check hashes.
    // if direct data doesn't (or didn't) match, abort all peers. see MIX_DIRECT
    if (!p->server_req->response_code) {
        for (size_t i = 0; i < lenof(p->requests); i++) {
            if (p->requests[i].req) {
                // HACK: a peer might have set the content-length but not written a response yet. discard it.
                p->content_length = 0;
                p->total_length = 0;
            }
        }
    }
    proxy_peer_requests_cancel(p);

    d->evcon = req->evcon;
    copy_all_headers(req, p->server_req);

    evhttp_add_header(req->input_headers, "Content-Location", p->uri);

    evkeyval *header;
    TAILQ_FOREACH(header, req->input_headers, next) {
        //debug("%s: %s\n", header->key, header->value);
        evhttp_add_header(&p->direct_headers, header->key, header->value);
    }

    int res = proxy_setup_range(p, req, &d->range);
    if (res < 1) {
        return res;
    }

    if (req->type == EVHTTP_REQ_GET && p->total_length > LEAF_CHUNK_SIZE * 2) {
        // if the server is capable of range requests, submit more requests
        const char *content_range = evhttp_find_header(req->input_headers, "Content-Range");
        const char *accept_ranges = evhttp_find_header(req->input_headers, "Accept-Ranges");
        if (content_range || (accept_ranges && strstr(accept_ranges, "bytes"))) {
            direct_submit_request(p);
        }
    }

    evhttp_request_set_chunked_cb(req, direct_chunked_cb);
    return 0;
}

bool proxy_needs_any(const proxy_request *p)
{
    if (!p->have_bitfield) {
        return true;
    }
    for (size_t i = 0; i < num_chunks(p); i++) {
        if (!p->have_bitfield[i]) {
            return true;
        }
    }
    return false;
}

bool proxy_is_complete(const proxy_request *p)
{
    if (!p->merkle_tree_finished || !p->have_bitfield) {
        return false;
    }
    return !proxy_needs_any(p);
}

uint64_t proxy_new_range_start(const proxy_request *p)
{
    uint64_t range_start = p->range_start;
    if (p->have_bitfield) {
        uint64_t start_run = 0;
        uint64_t run_length = 0;
        uint64_t longest_run[2] = {0, 0};
        for (size_t i = 0; i < num_chunks(p); i++) {
            //debug("have: %zu/%"PRIu64":%d\n", i, num_chunks, p->have_bitfield[i]);
            if (!p->have_bitfield[i]) {
                if (!run_length) {
                    start_run = i;
                }
                run_length++;
                if (run_length > longest_run[1] - longest_run[0]) {
                    longest_run[0] = start_run;
                    longest_run[1] = start_run + run_length;
                }
            } else {
                run_length = 0;
            }
        }
        debug("num_chunks:%"PRIu64" longest_run:%"PRIu64"-%"PRIu64"\n", num_chunks(p), longest_run[0], longest_run[1]);
        uint64_t mid = longest_run[0] + (longest_run[1] - longest_run[0]) / 2;
        range_start = !mid ? mid : (mid * LEAF_CHUNK_SIZE - evbuffer_get_length(p->header_buf));
        debug("p:%p range_start:%"PRIu64" mid:%"PRIu64" header_buf:%zu\n", p, range_start, mid, evbuffer_get_length(p->header_buf));

        // maybe consider:
        /*
        for (size_t i = 0; i < lenof(p->direct_requests); i++) {
            if (!p->direct_requests[i].req) {
                range_start = MAX(range_start, (p->range_end - p->requests[i].range.start) / 2);
            }
        }
        */
    }
    return range_start;
}

char* cache_name_from_uri(const char *uri)
{
    size_t name_max = NAME_MAX - strlen(".headers");
    char *encoded_uri = evhttp_encode_uri(uri);
    if (strlen(encoded_uri) > name_max) {
        uint8_t uri_hash[crypto_generichash_BYTES];
        crypto_generichash(uri_hash, sizeof(uri_hash), (uint8_t*)uri, strlen(uri), NULL, 0);
        size_t b64_hash_len;
        auto_free char *b64_hash = base64_urlsafe_encode(uri_hash, sizeof(uri_hash), &b64_hash_len);
        assert(b64_hash_len < name_max);
        encoded_uri[name_max - b64_hash_len - 2] = '.';
        strcpy(&encoded_uri[name_max - b64_hash_len - 1], b64_hash);
    }
    return encoded_uri;
}

void proxy_request_reply_start(proxy_request *p, evhttp_request *req)
{
    assert(!p->byte_playhead);
    if (!p->server_req) {
        return;
    }
    copy_response_headers(req, p->server_req);
    evhttp_remove_header(p->server_req->output_headers, "Content-Length");
    p->byte_playhead = evbuffer_get_length(p->header_buf);
    const char *range = evhttp_find_header(p->server_req->input_headers, "Range");
    if (!range && req->response_code == 206) {
        debug("p:%p req:%p evcon:%p (%.2fms) responding with %d %s\n",
              p, p->server_req, p->server_req->evcon, rdelta(p),
              200, "OK");
        evhttp_send_reply_start(p->server_req, 200, "OK");
    } else {
        if (range) {
            char content_range[1024];
            snprintf(content_range, sizeof(content_range), "bytes %"PRIu64"-%"PRIu64"/%"PRIu64,
                     p->range_start, p->range_end, p->content_length);
            overwrite_kv_header(p->server_req->output_headers, "Content-Range", content_range);
            debug("p:%p req:%p evcon:%p (%.2fms) responding with %d %s start:%"PRIu64" end:%"PRIu64" length:%"PRIu64"\n",
                  p, p->server_req, p->server_req->evcon, rdelta(p),
                  req->response_code, req->response_code_line, p->range_start, p->range_end, p->content_length);
        } else {
            debug("p:%p req:%p evcon:%p (%.2fms) responding with %d %s\n",
                  p, p->server_req, p->server_req->evcon, rdelta(p),
                  req->response_code, req->response_code_line);
        }
        evhttp_send_reply_start(p->server_req, req->response_code, req->response_code_line);
    }
}

bool direct_request_process_chunks(direct_request *d, evhttp_request *req)
{
    proxy_request *p = d->p;
    chunked_range *r = &d->range;
    evbuffer *input = req->input_buffer;
    debug("d:%p %s length:%zu\n", d, __func__, evbuffer_get_length(input));

    if (!r->chunk_buffer) {
        r->chunk_buffer = evbuffer_new();
    }

    for (;;) {
        uint64_t this_chunk_len = chunk_length(p, r->chunk_index);

        uint64_t header_prefix = 0;
        if (!r->chunk_index) {
            header_prefix = evbuffer_get_length(p->header_buf);
        }

        uint64_t received = this_chunk_len - header_prefix - evbuffer_get_length(r->chunk_buffer);
        evbuffer_remove_buffer(input, r->chunk_buffer, received);

        if (p->chunked) {
            // always keep the length optimistic. it will set accurately when the transfer finishes
            proxy_set_length(p, p->byte_playhead + this_chunk_len * 2);
        }

        debug("d:%p chunk_index:%"PRIu64"/%"PRIu64" %"PRIu64" < %"PRIu64"\n", d, r->chunk_index, num_chunks(p),
            header_prefix + evbuffer_get_length(r->chunk_buffer), this_chunk_len);
        if (header_prefix + evbuffer_get_length(r->chunk_buffer) < this_chunk_len) {
            return true;
        }

        debug("p->have_bitfield:%p r->chunk_index:%"PRIu64"\n", p->have_bitfield, r->chunk_index);
        if (p->have_bitfield[r->chunk_index]) {
            debug("d:%p duplicate chunk:%"PRIu64"\n", d, r->chunk_index);
        } else {
            debug("d:%p got chunk:%"PRIu64"\n", d, r->chunk_index);
            p->have_bitfield[r->chunk_index] = true;

            crypto_generichash_state content_state;
            crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);

            if (!r->chunk_index) {
                evbuffer_hash_update(p->header_buf, &content_state);
            }
            evbuffer_hash_update(r->chunk_buffer, &content_state);

            uint8_t chunk_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&content_state, chunk_hash, sizeof(chunk_hash));
            
            merkle_tree_set_leaf(p->m, r->chunk_index, chunk_hash);

            if (evbuffer_get_length(r->chunk_buffer)) {
                uint64_t this_chunk_offset = r->chunk_index * LEAF_CHUNK_SIZE;
                if (r->chunk_index > 0) {
                    this_chunk_offset -= evbuffer_get_length(p->header_buf);
                }
                debug("d:%p writing offset:%"PRIu64" length:%zu\n", d, this_chunk_offset, evbuffer_get_length(r->chunk_buffer));
                lseek(p->cache_file, this_chunk_offset, SEEK_SET);
                if (!evbuffer_write_to_file(r->chunk_buffer, p->cache_file)) {
                    return false;
                }
            }

            if (p->byte_playhead == r->chunk_index * LEAF_CHUNK_SIZE) {
                debug("d:%p send chunk:%"PRIu64"/%"PRIu64" p->byte_playhead:%"PRIu64" (r->chunk_index * LEAF_CHUNK_SIZE):%"PRIu64"\n",
                      d, r->chunk_index, num_chunks(p), p->byte_playhead, r->chunk_index * LEAF_CHUNK_SIZE);
                if (!p->byte_playhead) {
                    proxy_request_reply_start(p, req);
                }
                if (p->server_req) {
                    evhttp_send_reply_chunk(p->server_req, r->chunk_buffer);
                }
                p->byte_playhead += this_chunk_len - header_prefix;
            }
        }

        evbuffer_drain(r->chunk_buffer, evbuffer_get_length(r->chunk_buffer));
        r->chunk_index++;

        uint64_t c = p->byte_playhead;
        while (c < p->total_length && p->have_bitfield[c / LEAF_CHUNK_SIZE]) {
            c += LEAF_CHUNK_SIZE;
        }

        if (c > p->byte_playhead) {
            off_t offset = p->byte_playhead - evbuffer_get_length(p->header_buf);
            uint64_t length = c - p->byte_playhead;
            debug("d:%p sending offset:%"PRIu64" length:%"PRIu64"\n", d, (uint64_t)offset, length);
            evbuffer_file_segment *seg = evbuffer_file_segment_new(p->cache_file, offset, length, 0);
            if (!seg) {
                fprintf(stderr, "d:%p evbuffer_file_segment_new %d (%s)\n", d, errno, strerror(errno));
                return false;
            }
            if (p->server_req) {
                evbuffer_auto_free evbuffer *buf = evbuffer_new();
                if (!evbuffer_add_file_segment(buf, seg, 0, length)) {
                    evbuffer_file_segment_free(seg);
                }
                evhttp_send_reply_chunk(p->server_req, buf);
            }
            p->byte_playhead += length;
        }

        debug("d:%p progress p->byte_playhead:%"PRIu64" p->total_length:%"PRIu64"\n", d, p->byte_playhead, p->total_length);
        if (!p->chunked && p->byte_playhead == p->total_length) {
            if (p->server_req) {
                if (p->server_req->evcon) {
                    evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
                }
                evhttp_send_reply_end(p->server_req);
                p->server_req = NULL;
                proxy_direct_requests_cancel(p);
            }

            join_url_swarm(p->n, p->authority);

            merkle_tree_get_root(p->m, p->root_hash);

            // submit a proxy-only request with If-None-Match: "base64(root_hash)" and let it cache
            size_t b64_hash_len;
            auto_free char *b64_hash = base64_urlsafe_encode((uint8_t*)&p->root_hash, sizeof(p->root_hash), &b64_hash_len);
            char etag[2048];
            snprintf(etag, sizeof(etag), "\"%s\"", b64_hash);
            debug("d:%p submitting a cache request %s\n", d, etag);
            evhttp_add_header(&p->output_headers, "If-None-Match", etag);

            proxy_submit_request(p);
            return true;
        }

        assert(r->chunk_index <= num_chunks(p));
        if (r->chunk_index >= num_chunks(p)) {
            // done, let the connection close naturally
            debug("d:%p done, let the connection close naturally\n", d);
            return true;
        }
        if (!p->have_bitfield[r->chunk_index]) {
            continue;
        }

        debug("d:%p terminating connection due to overlap\n", d);
        return false;
    }
    return true;
}

void direct_chunked_cb(evhttp_request *req, void *arg)
{
    direct_request *d = (direct_request*)arg;
    proxy_request *p = d->p;
    if (!direct_request_process_chunks(d, req)) {
        direct_request_cancel(d);
        direct_submit_request(p);
    }
}

void direct_error_cb(evhttp_request_error error, void *arg)
{
    direct_request *d = (direct_request*)arg;
    proxy_request *p = d->p;
    debug("d:%p %s %d %s\n", d, __func__, error, evhttp_request_error_str(error));
    assert(d->req);
    d->req = NULL;
    if (error == EVREQ_HTTP_REQUEST_CANCEL) {
        return;
    }
    proxy_request_cleanup(p, __func__);
}

void direct_request_done_cb(evhttp_request *req, void *arg)
{
    direct_request *d = (direct_request*)arg;
    debug("d:%p %s req:%p\n", d, __func__, req);
    if (!req) {
        return;
    }
    proxy_request *p = d->p;
    debug("p:%p d:%p (%.2fms) %s %s\n", p, d, rdelta(p), __func__, p->uri);
    d->req = NULL;

    if (p->chunked) {
        size_t buffered = d->range.chunk_buffer ? evbuffer_get_length(d->range.chunk_buffer) : 0;
        if (!d->range.chunk_index) {
            proxy_set_length(p, evbuffer_get_length(p->header_buf) + buffered);
        } else {
            proxy_set_length(p, p->byte_playhead + buffered);
        }
        p->chunked = false;
    }

    if (req->response_code != 0) {
        // there may have been no chunks, or a chunked transfer of unknown length. call the chunked_cb one last time
        direct_request_process_chunks(d, req);

        return_connection(d->evcon);
    } else {
        evhttp_connection_free_on_completion(d->evcon);
    }
    d->evcon = NULL;
    if (req->type == EVHTTP_REQ_GET) {
        const char *content_range = evhttp_find_header(req->input_headers, "Content-Range");
        if (content_range) {
            direct_submit_request(p);
        }
    }
    if (!proxy_request_any_direct(p) && !proxy_request_any_peers(p)) {
        proxy_request_cleanup(p, __func__);
    }
}

bool verify_signature(const uint8_t *content_hash, const char *sign)
{
    if (strlen(sign) != BASE64_LENGTH(sizeof(content_sig))) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", strlen(sign), sizeof(content_sig));
        return false;
    }

    size_t out_len = 0;
    auto_free uint8_t *raw_sig = base64_decode(sign, strlen(sign), &out_len);
    if (out_len != sizeof(content_sig)) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", out_len, sizeof(content_sig));
        return false;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES] = injector_pk;

    content_sig *sig = (content_sig*)raw_sig;
    if (crypto_sign_verify_detached(sig->signature, (uint8_t*)sig->sign, sizeof(content_sig) - sizeof(sig->signature), pk)) {
        fprintf(stderr, "Incorrect signature!\n");
        return false;
    }

    if (memcmp(content_hash, sig->content_hash, crypto_generichash_BYTES)) {
        fprintf(stderr, "Incorrect hash!\n");
        for (uint i = 0; i < crypto_generichash_BYTES; i++) {
            fprintf(stderr, "%02X", content_hash[i]);
        }
        fprintf(stderr, "\n");
        for (uint i = 0; i < sizeof(sig->content_hash); i++) {
            fprintf(stderr, "%02X", sig->content_hash[i]);
        }
        fprintf(stderr, "\n");
        return false;
    }

    return true;
}

void peer_request_chunked_cb(evhttp_request *req, void *arg);

void peer_verified(network *n, peer *peer)
{
    peer->last_verified = time(NULL);
    save_peers(n);
    if (peer->is_injector) {
        injector_reachable = time(NULL);
        update_injector_proxy_swarm(n);
    }
}

void proxy_save_cache(proxy_request *p)
{
    char headers_name[PATH_MAX];
    snprintf(headers_name, sizeof(headers_name), "%s.headers", p->cache_name);
    evkeyvalq *headers = &p->direct_headers;
    int headers_file = creat(headers_name, 0600);
    if (!write_header_to_file(headers_file, p->direct_code, p->direct_code_line, headers)) {
        unlink(headers_name);
    }
    fsync(headers_file);
    close(headers_file);

    auto_free char *encoded_uri = cache_name_from_uri(p->uri);
    char cache_path[PATH_MAX];
    char cache_headers_path[PATH_MAX];
    snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, encoded_uri);
    snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
    debug("p:%p (%.2fms) store cache:%s headers:%s\n", p, rdelta(p), cache_path, cache_headers_path);

    fsync(p->cache_file);
    rename(p->cache_name, cache_path);
    rename(headers_name, cache_headers_path);
}

void peer_is_loop(peer *p)
{
    debug("%s:%d peer:%p\n", __func__, __LINE__, p);
    p->loop++;
    /*
    for (uint i = 0; i < lenof(peer_connections); i++) {
        if (peer_connections[i] && is_via) {
            peer_disconnect(pc);
            peer_connections[i] = NULL;
        }
    }
    */
}

int peer_request_header_cb(evhttp_request *req, void *arg)
{
    peer_request *r = (peer_request*)arg;
    proxy_request *p = r->p;
    debug("p:%p r:%p (%.2fms) %s %d %s\n", p, r, rdelta(p), __func__, req->response_code, req->response_code_line);

    int klass = req->response_code / 100;
    switch (klass) {
    case 1:
    case 2:
    case 3:
        break;
    case 4:
    case 5:
        if (req->response_code == 508) {
            peer_is_loop(r->pc->peer);
            proxy_submit_request(p);
        }
        proxy_send_error(p, req->response_code, req->response_code_line);
    default:
        return -1;
    }

    const char *content_location = evhttp_find_header(req->input_headers, "Content-Location");
    if (!content_location || !streq(content_location, p->uri)) {
        debug("p:%p r:%p (%.2fms) Content-Location mismatch: [%s] != [%s]\n", p, r, rdelta(p), content_location, p->uri);
        proxy_send_error(p, 502, "Content-Location mismatch");
        return -1;
    }

    // not the first moment of connection, but does indicate protocol support
    r->pc->peer->last_connect = time(NULL);

    debug("tree finished: %d\n", p->merkle_tree_finished);

    const char *msign = evhttp_find_header(req->input_headers, "X-MSign");
    if (!msign) {
        fprintf(stderr, "no signature!\n");
        debug("p:%p (%.2fms) no signature\n", p, rdelta(p));
        proxy_send_error(p, 502, "Missing Gateway Signature");
        return -1;
    }

    if (!p->merkle_tree_finished) {
        const char *xhashes = evhttp_find_header(req->input_headers, "X-Hashes");
        if (!xhashes) {
            fprintf(stderr, "no hashes!\n");
            debug("p:%p (%.2fms) no hashes\n", p, rdelta(p));
            proxy_send_error(p, 502, "Missing Gateway Hashes");
            return -1;
        }
        size_t out_len = 0;
        auto_free uint8_t *hashes = base64_decode(xhashes, strlen(xhashes), &out_len);

        merkle_tree *m = alloc(merkle_tree);
        if (!merkle_tree_set_leaves(m, hashes, out_len)) {
            debug("merkle_tree_set_leaves failed: %zu\n", out_len);
            r->pc->peer->last_verified = 0;
            proxy_send_error(p, 502, "Bad Gateway Hashes");
            merkle_tree_free(m);
            return -1;
        }
        uint8_t root_hash[crypto_generichash_BYTES];
        merkle_tree_get_root(m, root_hash);
        if (!verify_signature(root_hash, msign)) {
            fprintf(stderr, "signature failed!\n");
            r->pc->peer->last_verified = 0;
            proxy_send_error(p, 502, "Bad Gateway Signature");
            merkle_tree_free(m);
            return -1;
        }
        debug("signature good!\n");
        p->m = m;
        memcpy(p->root_hash, root_hash, sizeof(root_hash));
        p->merkle_tree_finished = true;
        overwrite_kv_header(&p->direct_headers, "X-Hashes", xhashes);
    } else {
        if (!verify_signature(p->root_hash, msign)) {
            fprintf(stderr, "signature failed!\n");
            r->pc->peer->last_verified = 0;
            proxy_send_error(p, 502, "Bad Gateway Signature");
            return -1;
        }
        debug("signature good!\n");
    }

    overwrite_kv_header(&p->direct_headers, "X-MSign", msign);
    const char *response_header_whitelist[] = hashed_headers;
    for (uint i = 0; i < lenof(response_header_whitelist); i++) {
        const char *key = response_header_whitelist[i];
        const char *value = evhttp_find_header(req->input_headers, key);
        if (value) {
            overwrite_kv_header(&p->direct_headers, key, value);
        }
    }
    overwrite_kv_header(&p->direct_headers, "Content-Location", content_location);
    peer_verified(p->n, r->pc->peer);

    debug("tree finished: %d\n", p->merkle_tree_finished);

    if (p->cache_file != -1) {
        if (req->response_code == 304) {
            // have hash, file, and headers.
            proxy_save_cache(p);
            return 0;
        }
        // we probably asked for If-None-Match and it didn't match. forget about the file
        proxy_cache_delete(p);
        free(p->have_bitfield);
        p->have_bitfield = NULL;
    }

    int res = proxy_setup_range(p, req, &r->range);
    if (res < 1) {
        return res;
    }

    evhttp_request_set_chunked_cb(req, peer_request_chunked_cb);
    return 0;
}

bool peer_request_process_chunks(peer_request *r, evhttp_request *req)
{
    proxy_request *p = r->p;
    evbuffer *input = req->input_buffer;
    debug("r:%p %s length:%zu\n", r, __func__, evbuffer_get_length(input));

    if (!r->range.chunk_buffer) {
        r->range.chunk_buffer = evbuffer_new();
    }

    for (;;) {
        uint64_t this_chunk_len = chunk_length(p, r->range.chunk_index);
        //debug("chunk_index:%"PRIu64" this_chunk_len:%"PRIu64"\n", r->range.chunk_index, this_chunk_len);

        uint64_t header_prefix = 0;
        if (!r->range.chunk_index) {
            header_prefix = evbuffer_get_length(p->header_buf);
        }

        evbuffer_remove_buffer(input, r->range.chunk_buffer, this_chunk_len - header_prefix - evbuffer_get_length(r->range.chunk_buffer));

        //debug("chunk_index:%"PRIu64" %"PRIu64"/%"PRIu64"\n", r->range.chunk_index, header_prefix + evbuffer_get_length(r->range.chunk_buffer), this_chunk_len);
        if (header_prefix + evbuffer_get_length(r->range.chunk_buffer) < this_chunk_len) {
            return true;
        }

        if (p->have_bitfield[r->range.chunk_index]) {
            debug("r:%p duplicate chunk:%"PRIu64"\n", r, r->range.chunk_index);
        }

        crypto_generichash_state content_state;
        crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);

        if (!r->range.chunk_index) {
            evbuffer_hash_update(p->header_buf, &content_state);
        }
        evbuffer_hash_update(r->range.chunk_buffer, &content_state);

        uint8_t chunk_hash[crypto_generichash_BYTES];
        crypto_generichash_final(&content_state, chunk_hash, sizeof(chunk_hash));

        if (!memeq(chunk_hash, p->m->nodes[r->range.chunk_index].hash, sizeof(chunk_hash))) {
            fprintf(stderr, "r:%p chunk:%"PRIu64" hash failed\n", r, r->range.chunk_index);
            return false;
        }
        debug("r:%p got chunk:%"PRIu64" hash success\n", r, r->range.chunk_index);
        p->have_bitfield[r->range.chunk_index] = true;

        peer_verified(p->n, r->pc->peer);

        if (evbuffer_get_length(r->range.chunk_buffer)) {
            uint64_t this_chunk_offset = r->range.chunk_index * LEAF_CHUNK_SIZE;
            if (r->range.chunk_index > 0) {
                this_chunk_offset -= evbuffer_get_length(p->header_buf);
            }
            lseek(p->cache_file, this_chunk_offset, SEEK_SET);
            if (!evbuffer_write_to_file(r->range.chunk_buffer, p->cache_file)) {
                return false;
            }
        }

        debug("p->byte_playhead:%"PRIu64" (r->chunk_index * LEAF_CHUNK_SIZE):%"PRIu64"\n", p->byte_playhead, r->range.chunk_index * LEAF_CHUNK_SIZE);
        if (p->byte_playhead == r->range.chunk_index * LEAF_CHUNK_SIZE) {
            if (!p->byte_playhead) {
                // XXX: TODO: MIX_DIRECT
                proxy_direct_requests_cancel(p);
                proxy_request_reply_start(p, req);
            }
            if (p->server_req) {
                evhttp_send_reply_chunk(p->server_req, r->range.chunk_buffer);
            }
            p->byte_playhead += this_chunk_len - header_prefix;
        }

        evbuffer_drain(r->range.chunk_buffer, evbuffer_get_length(r->range.chunk_buffer));

        debug("(r->chunk_index * LEAF_CHUNK_SIZE)):%"PRIu64" r->end:%"PRIu64"\n", r->range.chunk_index * LEAF_CHUNK_SIZE, r->range.end);
        if (r->range.chunk_index * LEAF_CHUNK_SIZE <= r->range.end) {
            r->range.chunk_index++;
        }

        uint64_t c = p->byte_playhead;
        while (c < p->total_length && p->have_bitfield[c / LEAF_CHUNK_SIZE]) {
            c += LEAF_CHUNK_SIZE;
        }

        if (c > p->byte_playhead) {
            off_t offset = p->byte_playhead - evbuffer_get_length(p->header_buf);
            uint64_t length = c - p->byte_playhead;
            evbuffer_file_segment *seg = evbuffer_file_segment_new(p->cache_file, offset, length, 0);
            if (!seg) {
                fprintf(stderr, "r:%p evbuffer_file_segment_new %d (%s)\n", r, errno, strerror(errno));
                return false;
            }
            if (p->server_req) {
                evbuffer_auto_free evbuffer *buf = evbuffer_new();
                if (!evbuffer_add_file_segment(buf, seg, 0, length)) {
                    evbuffer_file_segment_free(seg);
                }
                evhttp_send_reply_chunk(p->server_req, buf);
            }
            p->byte_playhead += length;
        }

        debug("p->byte_playhead:%"PRIu64" p->total_length:%"PRIu64"\n", p->byte_playhead, p->total_length);
        if (p->byte_playhead == p->total_length) {
            if (p->server_req) {
                if (p->server_req->evcon) {
                    evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
                }
                evhttp_send_reply_end(p->server_req);
                p->server_req = NULL;
            }

            // we cannot reuse the connection until we know the reqeust has finished the reply
            for (size_t i = 0; i < lenof(p->requests); i++) {
                peer_request *pr = &p->requests[i];
                if (!pr->req) {
                    continue;
                }
                // give them a tiny grace period
                if ((pr->range.chunk_index * LEAF_CHUNK_SIZE) + 1024 > pr->range.end) {
                    evhttp_request_set_chunked_cb(pr->req, NULL);
                    continue;
                }
                peer_request_cancel(pr);
            }

            join_url_swarm(p->n, p->authority);

            // only cache if have_bitfield is all 1's. otherwise we need to track partials (or hashcheck on upload, which prevents sendfile)
            assert(p->merkle_tree_finished);
            assert(p->have_bitfield);
            if (proxy_is_complete(p)) {
                proxy_save_cache(p);
            }
            return true;
        }

        assert(r->range.chunk_index <= num_chunks(p));
        if (r->range.chunk_index >= num_chunks(p)) {
            // done, let the connection close naturally
            debug("r:%p done, let the connection close naturally\n", r);
            return true;
        }
        if (!p->have_bitfield[r->range.chunk_index]) {
            continue;
        }

        debug("r:%p terminating connection due to overlap\n", r);
        return false;
    }
    return true;
}

void peer_request_chunked_cb(evhttp_request *req, void *arg)
{
    peer_request *r = (peer_request*)arg;
    if (!peer_request_process_chunks(r, req)) {
        peer_request_cancel(r);
    }
}

void peer_request_error_cb(evhttp_request_error error, void *arg)
{
    peer_request *r = (peer_request*)arg;
    debug("r:%p %s %d %s\n", r, __func__, error, evhttp_request_error_str(error));
    r->req = NULL;
    if (error == EVREQ_HTTP_REQUEST_CANCEL) {
        return;
    }
    if (r->pc->peer->is_injector) {
        injector_reachable = 0;
    }
    peer_request_cleanup(r, __func__);
}

void peer_request_done_cb(evhttp_request *req, void *arg)
{
    peer_request *r = (peer_request*)arg;
    debug("r:%p peer_request_done_cb req:%p\n", r, req);
    if (!req) {
        return;
    }
    r->req = NULL;
    proxy_request *p = r->p;
    if (!req->response_code) {
        debug("p:%p (%.2fms) no response code!\n", p, rdelta(p));
        peer_request_cleanup(r, __func__);
        return;
    }

    // there may have been no chunks, or a chunked transfer of unknown length. call the chunked_cb one last time
    peer_request_process_chunks(r, req);

    peer_reuse(p->n, r->pc);
    r->pc = NULL;
    peer_request_cleanup(r, __func__);
}

https_request https_request_alloc(size_t bufsize, unsigned int flags, unsigned timeout)
{
    if ((flags & HTTPS_METHOD_MASK) == 0) {
        flags |= HTTPS_METHOD_GET;
    }
    https_request request = {
        .bufsize = bufsize,
        .flags = flags,
        .timeout_sec = timeout
    };
    return request;
}

https_request tryfirst_request_alloc(void)
{
    https_request result = https_request_alloc(0, HTTPS_TRYFIRST_FLAGS, g_tryfirst_timeout);
    result.bufsize = g_tryfirst_bufsize; // specify max result length without actually capturing result
    return result;
}

void heartbeat_send(network *n)
{
    char url[2048];
    char asn[512] = "";
    if (*g_country && g_asn > 0) {
        snprintf(asn, sizeof(asn),
                 "&geoid=%s" \
                 "&el=ASN&ev=%d",
                 g_country,
                 g_asn);
    }
    snprintf(url, sizeof(url), "https://stats.newnode.com/heartbeat?v=1" \
             "&tid=UA-149896478-2&t=event&ec=byte_counts&ds=app&ni=1" \
             "&an=%s"                                                \
             "&aid=%s"                                                \
             "&cid=%"PRIu64""                                       \
             "%s",
             g_app_name,
             g_app_id,
             g_cid,
             asn);
    https_request req = https_request_alloc(0, HTTPS_STATS_FLAGS, 15);
    g_https_cb(&req, url, NULL);
}

#define MIN_STATS_TIME_MS 7000

void stats_report(network *n);

void stats_set_timer(network *n, uint64_t ms)
{
    if (stats_report_timer) {
        return;
    }
    debug("%s ms:%"PRIu64"\n", __func__, ms);
    stats_report_timer = timer_start(n, ms, ^{
        stats_report_timer = NULL;
        stats_report(n);
    });
}

void stats_report(network *n)
{
    debug("%s\n", __func__);
    __block double next_time = -1;
    hash_iter(byte_count_per_authority, ^bool (const char *authority, void *val) {
        if (streq("stats.newnode.com", authority)) {
            return true;
        }

        byte_counts *b = val;

        if (!(b->from_browser || b->to_browser ||
              b->from_peer || b->to_peer ||
              b->from_direct || b->to_direct ||
              b->from_p2p || b->to_p2p)) {
            return true;
        }

        double next_ms = (us_clock() - b->last_reported) / 1000.0;
        if (next_ms < MIN_STATS_TIME_MS) {
            next_time = next_ms;
            return true;
        }
        next_time = -1;

        byte_counts byte_count = *b;
        bzero(b, sizeof(*b));
        b->last_reported = byte_count.last_reported;

        __auto_type report = ^(const char *type, uint64_t count, void (^failure)(void)) {
            if (!count) {
                return;
            }
            char url[2048];
            snprintf(url, sizeof(url), "https://stats.newnode.com/collect?v=1" \
                     "&tid=UA-149896478-2&t=event&ec=byte_counts&ds=app&ni=1" \
                     "&ea=%s" \
                     "&el=%s" \
                     "&ev=%"PRIu64"" \
                     "&dh=%s" \
                     "&an=%s" \
                     "&aid=%s",
                     type,
                     authority,
                     count,
                     authority,
                     g_app_name,
                     g_app_id);
            failure = Block_copy(failure);
            https_request req = https_request_alloc(0, HTTPS_STATS_FLAGS, 15);
            g_https_cb(&req, url, ^(bool success, const https_result *result) {
                timer_cancel(stats_report_timer);
                stats_report_timer = NULL;
                if (!success) {
                    if (failure) {
                        failure();
                        Block_release(failure);
                    }
                    stats_set_timer(n, MIN_STATS_TIME_MS + randombytes_uniform(3 * MIN_STATS_TIME_MS));
                    return;
                }
                b->last_reported = us_clock();
                stats_set_timer(n, 0);
            });
        };
        report("peer", byte_count.from_peer + byte_count.to_peer, ^{
            b->from_peer += byte_count.from_peer;
            b->to_peer += byte_count.to_peer;
        });
        report("direct", byte_count.from_direct + byte_count.to_direct, ^{
            b->from_direct += byte_count.from_direct;
            b->to_direct += byte_count.to_direct;
        });
        report("p2p", byte_count.from_p2p + byte_count.to_p2p, ^{
            b->from_p2p += byte_count.from_p2p;
            b->to_p2p += byte_count.to_p2p;
        });
        return false;
    });
    if (next_time != -1) {
        stats_set_timer(n, (uint64_t)next_time);
    }
}

void stats_changed(network *n)
{
    if (o_debug > 1) {
        hash_iter(byte_count_per_authority, ^bool (const char *authority, void *val) {
            byte_counts *b = val;
            debug("%s %s %"PRIu64"\n", g_app_id, authority,
                  b->from_browser + b->to_browser +
                  b->from_peer + b->to_peer +
                  b->from_direct + b->to_direct +
                  b->from_p2p + b->to_p2p);
            return true;
        });
    }
    if (ui_display_stats != NULL) {
        ui_display_stats("process", g_all_direct, g_all_peer);
    }
    stats_set_timer(n, 7000 + randombytes_uniform(5000));
}

void byte_count_cb(evbuffer *buf, const evbuffer_cb_info *info, void *userdata)
{
    uint64_t *counter = (uint64_t*)userdata;
    network *n = g_stats_n;
    //debug("%s counter:%p bytes:%zu\n", __func__, counter, info->n_deleted);
    if (info->n_deleted) {
        *counter += info->n_deleted;
        stats_changed(n);
    }
}

void bufferevent_count_bytes(network *n, const char *authority, bool from_localhost, bufferevent *from, bufferevent *to)
{
    debug("%s from:%s to:%s %s\n", __func__,
          from_localhost ? "browser" : "peer",
          bufferevent_is_utp(to) ? "peer" : "direct",
          authority);

    // a little hack instead of making a struct for the uint64_t and network*
    g_stats_n = n;

    if (!byte_count_per_authority) {
        byte_count_per_authority = hash_table_create();
    }
    byte_counts *byte_count = hash_get_or_insert(byte_count_per_authority, authority, ^{
        return alloc(byte_counts);
    });

    // prevent double-counting by removing all previous byte counters
    if (from) {
        evbuffer_remove_all_cb(bufferevent_get_input(from), byte_count_cb);
        evbuffer_remove_all_cb(bufferevent_get_output(from), byte_count_cb);
    }
    evbuffer_remove_all_cb(bufferevent_get_input(to), byte_count_cb);
    evbuffer_remove_all_cb(bufferevent_get_output(to), byte_count_cb);

    if (!from_localhost && bufferevent_is_utp(to)) {
        if (from) {
            evbuffer_add_cb(bufferevent_get_input(from), byte_count_cb, &byte_count->from_p2p);
            evbuffer_add_cb(bufferevent_get_output(from), byte_count_cb, &byte_count->to_p2p);
        }
        evbuffer_add_cb(bufferevent_get_input(to), byte_count_cb, &byte_count->from_p2p);
        evbuffer_add_cb(bufferevent_get_output(to), byte_count_cb, &byte_count->to_p2p);
        return;
    }
    if (from_localhost && from) {
        evbuffer_add_cb(bufferevent_get_input(from), byte_count_cb, &byte_count->from_browser);
        evbuffer_add_cb(bufferevent_get_output(from), byte_count_cb, &byte_count->to_browser);
    }
    if (bufferevent_is_utp(to)) {
        evbuffer_add_cb(bufferevent_get_input(to), byte_count_cb, &byte_count->from_peer);
        evbuffer_add_cb(bufferevent_get_output(to), byte_count_cb, &byte_count->to_peer);
        evbuffer_add_cb(bufferevent_get_input(to), byte_count_cb, &g_all_peer);
        evbuffer_add_cb(bufferevent_get_output(to), byte_count_cb, &g_all_peer);
    } else {
        evbuffer_add_cb(bufferevent_get_input(to), byte_count_cb, &byte_count->from_direct);
        evbuffer_add_cb(bufferevent_get_output(to), byte_count_cb, &byte_count->to_direct);
        evbuffer_add_cb(bufferevent_get_input(to), byte_count_cb, &g_all_direct);
        evbuffer_add_cb(bufferevent_get_output(to), byte_count_cb, &g_all_direct);
    }
}

void direct_submit_request(proxy_request *p)
{
    direct_request *d = NULL;

    if (!proxy_needs_any(p)) {
        return;
    }

    for (size_t i = 0; i < lenof(p->direct_requests); i++) {
        if (!p->direct_requests[i].req) {
            d = &p->direct_requests[i];
            break;
        }
    }
    if (!d) {
        return;
    }

    d->p = p;
    d->req = evhttp_request_new(direct_request_done_cb, d);

    copy_all_headers(p->server_req, d->req);

    evhttp_request_set_header_cb(d->req, direct_header_cb);
    evhttp_request_set_error_cb(d->req, direct_error_cb);

    switch (p->http_method) {
    case EVHTTP_REQ_GET: {
        uint64_t range_start = proxy_new_range_start(p);
        char range[1024];
        snprintf(range, sizeof(range), "bytes=%"PRIu64"-", range_start);
        evhttp_add_header(d->req->output_headers, "Range", range);
        debug("%s: %s\n", "Range", range);
        // if we have an ETag already, add If-Match so we get "416 Range Not Satisfiable" if the second request gets a different copy.
        if (p->etag) {
            evhttp_add_header(d->req->output_headers, "If-Match", p->etag);
        }
        break;
    }
    case EVHTTP_REQ_POST: {
        evbuffer_add_buffer_reference(d->req->output_buffer, p->server_req->input_buffer);
    }
    default:
        break;
    }

    char request_uri[2048];
    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(p->server_req);
    const char *q = evhttp_uri_get_query(uri);
    const char *path = evhttp_uri_get_path(uri);
    if (!strlen(path)) {
        path = "/";
    }
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", path, q?"?":"", q?q:"");
    evhttp_connection *evcon = make_connection(p->n, uri);
    if (!evcon) {
        return;
    }
    bufferevent *server = p->server_req ? evhttp_connection_get_bufferevent(p->server_req->evcon) : NULL;
    bufferevent *bev = evhttp_connection_get_bufferevent(evcon);
    bufferevent_count_bytes(p->n, p->authority, p->localhost, server, bev);
    debug("p:%p d:%p evcon:%p direct request submitted: %s %s\n", p, d, evcon, evhttp_method(p->http_method), p->uri);
    evhttp_make_request(evcon, d->req, p->http_method, request_uri);
}

void append_via(evhttp_request *from, evkeyvalq *to)
{
    const char *via = NULL;
    char viab[2048];
    if (from) {
        via = evhttp_find_header(from->input_headers, "Via");
    }
    assert(!via || strlen(via) < sizeof(viab)/2);
    snprintf(viab, sizeof(viab), "%s%s%s", via?:"", via ? ", " : "", via_tag);
    overwrite_kv_header(to, "Via", viab);
}

void peer_submit_request_on_con(peer_request *r, evhttp_connection *evcon)
{
    proxy_request *p = r->p;
    debug("p:%p r:%p evcon:%p %s: %s %s\n", p, r, evcon, __func__, evhttp_method(p->http_method), p->uri);
    bufferevent *server = p->server_req ? evhttp_connection_get_bufferevent(p->server_req->evcon) : NULL;
    bufferevent *bev = evhttp_connection_get_bufferevent(evcon);
    bufferevent_count_bytes(p->n, p->authority, p->localhost, server, bev);
    evhttp_make_request(evcon, r->req, p->http_method, p->uri);
}

int peer_sort_cmp(const peer_sort *pa, const peer_sort *pb)
{
    return memcmp(pa, pb, sizeof(peer_sort));
}

// XXX This definition of htonll is only correct if the target machine
//     is little-endian (like an x86).  If the target machine is
//     big-endian, it swaps the two 32-bit words with one another when
//     it should do nothing at all.
#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define ntohll htonll
#endif

peer* select_peer(peer_array *pa, peer_filter filter)
{
    __block peer_sort best = {.peer = NULL};
    //debug("select_peer peers:%p length:%u\n", pa, pa->length);
    hash_iter(pa, ^bool (const char *addr, void *val) {
        peer *p = val;
        if (filter && filter(p)) {
            return true;
        }
        peer_sort c;
        c.failed = p->last_connect < p->last_connect_attempt;
        int64_t time_since_verified = time(NULL) - p->last_verified;
        c.time_since_verified = ntohll(time_since_verified);
        int64_t last_connect_attempt = p->last_connect_attempt;
        c.last_connect_attempt = ntohll(last_connect_attempt);
        c.never_connected = !p->last_connect;
        c.loop = p->loop;
        c.salt = randombytes_uniform(0xFF);
        c.peer = p;
        if (0) {
            debug("peer %s failed:%d time_since_verified:%"PRIu64" last_connect_attempt:%"PRIu64" never_connected:%d salt:%d p:%p\n",
                  peer_addr_str(p),
                  c.failed, htonll(c.time_since_verified), htonll(c.last_connect_attempt), c.never_connected, c.salt, c.peer);
            debug("peer_sort_cmp:%d\n", peer_sort_cmp(&c, &best));
        }
        if (!best.peer || peer_sort_cmp(&c, &best) < 0) {
            //debug("better p:%p\n", p);
            best = c;
        }
        return true;
    });
    return best.peer;
}

peer_connection* start_peer_connection(network *n, peer_array *peers, peer_filter filter)
{
    peer *p = select_peer(peers, filter);
    if (!p) {
        //debug("no peer selected from peers:%p\n", peers);
        return NULL;
    }
    //debug("peer selected: %s\n", peer_addr_str(p));
    return evhttp_utp_connect(n, p);
}

void queue_request(network *n, pending_request *r, peer_filter filter, peer_connected on_connect)
{
    debug("%s r:%p pending:%zu first:%p\n", __func__, r, pending_requests_len, TAILQ_FIRST(&pending_requests));
    bool any_connected = false;
    for (uint i = 0; i < lenof(peer_connections); i++) {
        if (peer_connections[i]) {
            if (peer_connections[i]->evcon) {
                any_connected = true;
            }
            continue;
        }
        peer_connections[i] = start_peer_connection(n, all_peers, filter);
        if (!peer_connections[i]) {
            break;
        }
    }

    static time_t last_lsd = 0;
    if (!any_connected && time(NULL) - last_lsd > 10) {
        last_lsd = time(NULL);
        lsd_send(n, false);
    }

    uint filtered = 0;
    for (uint i = 0; i < lenof(peer_connections); i++) {
        peer_connection *pc = peer_connections[i];
        if (!pc || !pc->evcon) {
            continue;
        }
        if (filter && filter(pc->peer)) {
            filtered++;
            continue;
        }
        peer_connections[i] = NULL;
        debug("using pc:%p evcon:%p via:%c for request:%p\n", pc, pc->evcon, pc->peer->via ? pc->peer->via : ' ', r);
        on_connect(pc);
        return;
    }

    // if none of the peer_connections were applicable, disconnect some
    if (filtered >= lenof(peer_connections) / 2) {
        uint disconnected = 0;
        for (uint i = 0; i < lenof(peer_connections); i++) {
            peer_connection *pc = peer_connections[i];
            if (pc && pc->evcon && filter && filter(pc->peer)) {
                debug("discarding pc:%p due to filtering '%c'\n", pc, pc->peer->via ? pc->peer->via : ' ');
                peer_disconnect(pc);
                peer_connections[i] = NULL;
                disconnected++;
                if (disconnected >= 2) {
                    break;
                }
            }
        }
    }

    assert(!r->on_connect);
    r->on_connect = Block_copy(on_connect);
    TAILQ_INSERT_TAIL(&pending_requests, r, next);
    pending_requests_len++;
    last_request = time(NULL);
    debug("queued request:%p (outstanding:%zu)\n", r, pending_requests_len);
}

void connect_more_injectors(network *n, bool injector_preference)
{
    debug("%s injector_pref:%d\n", __func__, injector_preference);
    for (uint i = 0; i < lenof(peer_connections) / 2; i++) {
        if (peer_connections[i]) {
            continue;
        }
        peer_array *o[2] = {injectors, injector_proxies};
        if (!injector_preference && randombytes_uniform(2)) {
            o[0] = injector_proxies;
            o[1] = injectors;
        }
        peer_connections[i] = start_peer_connection(n, o[0], NULL);
        if (!peer_connections[i]) {
            peer_connections[i] = start_peer_connection(n, o[1], NULL);
        }
    }
}

peer_request* proxy_make_request(proxy_request *p)
{
    peer_request *r = NULL;

    for (size_t i = 0; i < lenof(p->requests); i++) {
        if (!p->requests[i].req) {
            r = &p->requests[i];
            break;
        }
    }
    if (!r) {
        return NULL;
    }

    r->p = p;
    r->req = evhttp_request_new(peer_request_done_cb, r);

    evkeyval *header;
    TAILQ_FOREACH(header, &p->output_headers, next) {
        evhttp_add_header(r->req->output_headers, header->key, header->value);
    }

    uint64_t range_start = proxy_new_range_start(p);
    char range[1024];
    snprintf(range, sizeof(range), "bytes=%"PRIu64"-", range_start);
    evhttp_add_header(r->req->output_headers, "Range", range);
    debug("%s: %s\n", "Range", range);
    // XXX: TODO: if we have a complete merkle tree already, add If-Match so we get "416 Range Not Satisfiable" if the other peer has a different copy.

    if (!p->merkle_tree_finished) {
        // TODO: kick off a separate HEAD request for hashes which blocks until hashes are available.
        // then we can use them immediately, before the download is finished.
        evhttp_add_header(r->req->output_headers, "X-HashRequest", "1");
    }

    evhttp_request_set_header_cb(r->req, peer_request_header_cb);
    evhttp_request_set_error_cb(r->req, peer_request_error_cb);

    return r;
}

bool filter_peer(peer *peer, evhttp_request *server_req, const char *via)
{
    if (!server_req) {
        return false;
    }
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    bufferevent *bev = evhttp_connection_get_bufferevent(server_req->evcon);
    bufferevent_getpeername(bev, (sockaddr*)&ss, &len);
    return sockaddr_eq((const sockaddr*)&ss, (const sockaddr*)&peer->addr) || via_contains(via, peer->via);
}

void proxy_submit_request(proxy_request *p)
{
    // TODO: kick off a separate HEAD request for hashes which blocks until hashes are available.
    // then we can use them immediately, before the download is finished.
    peer_request *r = proxy_make_request(p);
    if (!r) {
        return;
    }

    const char *via = evhttp_find_header(r->req->input_headers, "Via");
    r->r.via = via?strdup(via):NULL;

    queue_request(p->n, &r->r, ^bool(peer *peer) {
        return filter_peer(peer, p->server_req, via);
    }, ^(peer_connection *pc) {
        debug("%s:%d r:%p peer:%p\n", __func__, __LINE__, r, pc->peer);
        r->pc = pc;
        peer_submit_request_on_con(r, r->pc->evcon);
    });
}

void proxy_evcon_close_cb(evhttp_connection *evcon, void *ctx)
{
    proxy_request *p = (proxy_request*)ctx;
    debug("p:%p evcon:%p (%.2fms) %s\n", p, evcon, rdelta(p), __func__);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
    p->server_req = NULL;
    p->dont_free = true;
    proxy_direct_requests_cancel(p);
    proxy_peer_requests_cancel(p);
    p->dont_free = false;
    proxy_request_cleanup(p, __func__);
}

void submit_request(network *n, evhttp_request *server_req)
{
    uint64_t range_start = 0;
    uint64_t range_end = 0;
    const char *range = evhttp_find_header(server_req->input_headers, "Range");
    if (range) {
        sscanf(range, "bytes=%"PRIu64"-%"PRIu64, &range_start, &range_end);
        if (range_start > range_end) {
            char content_range[1024];
            evhttp_send_error(server_req, 416, "Range Not Satisfiable");
            return;
        }
    }

    proxy_request *p = alloc(proxy_request);
    p->n = n;
    p->start_time = us_clock();
    TAILQ_INIT(&p->direct_headers);
    TAILQ_INIT(&p->output_headers);
    p->cache_file = -1;
    p->range_start = range_start;
    p->range_end = range_end;
    p->server_req = server_req;
    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(p->server_req);
    const char *host = evhttp_uri_get_host(uri);
    p->authority = strdup(host ?: "");
    p->localhost = evcon_is_localhost(p->server_req->evcon);
    p->http_method = p->server_req->type;
    p->uri = strdup(evhttp_request_get_uri(p->server_req));
    p->m = alloc(merkle_tree);

    debug("p:%p new request %s\n", p, p->uri);

    evhttp_connection_set_closecb(p->server_req->evcon, proxy_evcon_close_cb, p);

    const char *request_header_whitelist[] = {"Referer", "Origin", "Host", "Via", "Range", "Accept-Encoding"};
    for (uint i = 0; i < lenof(request_header_whitelist); i++) {
        const char *key = request_header_whitelist[i];
        const char *value = evhttp_find_header(p->server_req->input_headers, key);
        if (value) {
            evhttp_add_header(&p->output_headers, key, value);
        }
    }
    append_via(p->server_req, &p->output_headers);

    /*
    if (!dht_num_searches()) {
        fetch_url_swarm(p->n, p->uri);
    }
    */
    fetch_url_swarm(p->n, p->authority);

    p->dont_free = true;

    if (!NO_DIRECT && evcon_is_localhost(server_req->evcon)) {
        direct_submit_request(p);
    }

    switch (p->http_method) {
    case EVHTTP_REQ_GET:
    case EVHTTP_REQ_HEAD:
    case EVHTTP_REQ_CONNECT:
    case EVHTTP_REQ_TRACE:
    case EVHTTP_REQ_OPTIONS:
        proxy_submit_request(p);
    default:
        break;
    }

    p->dont_free = false;

    // may need to be cleaned up already
    proxy_request_cleanup(p, __func__);
}

typedef struct {
    network *n;
    pending_request r;
    peer_connection *pc;
} trace_request;

void trace_request_cleanup(trace_request *t)
{
    if (t->pc) {
        peer_disconnect(t->pc);
        t->pc = NULL;
    }
    free(t);
}

void trace_error_cb(evhttp_request_error error, void *arg)
{
    trace_request *t = (trace_request*)arg;
    debug("t:%p %s %d %s\n", t, __func__, error, evhttp_request_error_str(error));
    if (error != EVREQ_HTTP_REQUEST_CANCEL && t->pc->peer->is_injector) {
        injector_reachable = 0;
    }
    trace_request_cleanup(t);
}

void trace_request_done_cb(evhttp_request *req, void *arg)
{
    trace_request *t = (trace_request*)arg;
    debug("t:%p trace_request_done_cb req:%p\n", t, req);
    if (!req) {
        return;
    }
    evbuffer *input = req->input_buffer;
    if (req->response_code != 0) {
        const char *msign = evhttp_find_header(req->input_headers, "X-MSign");
        if (!msign) {
            fprintf(stderr, "no signature on TRACE!\n");
        } else {
            const unsigned char *body = evbuffer_pullup(input, evbuffer_get_length(input));

            merkle_tree *m = alloc(merkle_tree);
            merkle_tree_hash_request(m, req, req->input_headers);
            merkle_tree_add_hashed_data(m, body, evbuffer_get_length(input));
            uint8_t root_hash[crypto_generichash_BYTES];
            merkle_tree_get_root(m, root_hash);
            merkle_tree_free(m);

            debug("verifying sig for TRACE %s %s\n", evhttp_request_get_uri(req), msign);
            if (verify_signature(root_hash, msign)) {
                debug("signature good! %s\n", peer_addr_str(t->pc->peer));
                t->pc->peer->last_connect = time(NULL);
                peer_verified(t->n, t->pc->peer);
                peer_reuse(t->n, t->pc);
                t->pc = NULL;
            } else {
                t->pc->peer->last_verified = 0;
            }
        }
    }
    trace_request_cleanup(t);
}

/*
#include <objc/runtime.h>
#include <objc/message.h>

#include <CoreFoundation/CoreFoundation.h>

char *getsystemversion(void)
{
    char *sv = NULL;
    id Dev = objc_msgSend(objc_getClass("UIDevice"), sel_getUid("currentDevice"));
    CFStringRef SysVer = (CFStringRef) objc_msgSend(Dev, sel_getUid("systemVersion"));
    CFIndex len = CFStringGetLength(SysVer);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    sv = (char *) malloc(max + 1);
    CFStringGetCString(SysVer, sv, max, kCFStringEncodingUTF8);
    return sv;
}
*/

void trace_submit_request_on_con(trace_request *t, evhttp_connection *evcon)
{
    evhttp_request *req = evhttp_request_new(trace_request_done_cb, t);
    char user_agent[2048];
#ifdef ANDROID
    char abi_list[PROP_VALUE_MAX];
    __system_property_get("ro.product.cpu.abilist", abi_list);
    char sdk_ver[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.sdk", sdk_ver);
    char os_ver[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.release", os_ver);
    snprintf(user_agent, sizeof(user_agent), "newnode/%s (Android %s (%s); %s)", VERSION, sdk_ver, os_ver, abi_list);
    debug("user_agent:%s\n", user_agent);
#else
    snprintf(user_agent, sizeof(user_agent), "newnode/%s", VERSION);
#endif
    overwrite_header(req, "User-Agent", user_agent);
    append_via(NULL, req->output_headers);
    evhttp_request_set_error_cb(req, trace_error_cb);
    char request_uri[256];
    static uint32_t instance = 0;
    if (!instance) {
        instance = randombytes_random();
    }
    snprintf(request_uri, sizeof(request_uri), "/%u-%u%u",
             instance, randombytes_random(), randombytes_random());
    debug("t:%p %s trace request submitted: %s\n", t, peer_addr_str(t->pc->peer), request_uri);
    evhttp_make_request(evcon, req, EVHTTP_REQ_TRACE, request_uri);
}

void submit_trace_request(network *n)
{
    trace_request *t = alloc(trace_request);
    t->n = n;
    connect_more_injectors(n, true);
    queue_request(n, &t->r, NULL, ^(peer_connection *pc) {
        debug("%s:%d t:%p peer:%p\n", __func__, __LINE__, t, pc->peer);
        t->pc = pc;
        trace_submit_request_on_con(t, t->pc->evcon);
    });
}

#define SOCKS5_REPLY_GRANTED 0x00 // request granted
#define SOCKS5_REPLY_FAILURE 0x01 // general failure
#define SOCKS5_REPLY_NOT_ALLOWED 0x02 // connection not allowed by ruleset
#define SOCKS5_REPLY_NETUNREACH 0x03 // network unreachable
#define SOCKS5_REPLY_HOSTUNREACH 0x04 // host unreachable
#define SOCKS5_REPLY_CONNREFUSED 0x05 // connection refused by destination host
#define SOCKS5_REPLY_TIMEDOUT 0x06 // TTL expired
#define SOCKS5_REPLY_INVAL 0x07 // command not supported / protocol error
#define SOCKS5_REPLY_AFNOSUPPORT 0x08 // address type not supported

typedef struct {
    // HTTP CONNECT request
    evhttp_request *server_req;
    // SOCKS5 request
    bufferevent *server_bev;

    uint64 start_time;

    // through proxy
    evhttp_request *proxy_req;
    pending_request r;
    peer_connection *pc;
    // direct
    bufferevent *direct;

    network *n;

    evbuffer *intro_data;
    bufferevent *pending_bev;
    bufferevent *bevs[10];

    char *authority;
    int attempts;

    bool dont_free:1;

    // start of TF additions
    bool connected:1;
    bool direct_connect_responded:1;
    char *host;                 // just hostname, no port #
    port_t port;
    char *tryfirst_url;         // URL to be used for "try first" test
    https_request_token tryfirst_request;
    https_result tryfirst_result;
} connect_req;

void connect_tryfirst_requests_cancel(connect_req *c)
{
    debug("c:%p %s (%.2fms)\n", c, __func__, rdelta(c));
    if (c->tryfirst_request) {
        cancel_https_request(c->n, c->tryfirst_request);
        c->tryfirst_request = NULL;
    }
}

void free_write_cb(bufferevent *bev, void *ctx)
{
    debug("%s bev:%p\n", __func__, bev);
    if (!evbuffer_get_length(bufferevent_get_output(bev))) {
        bufferevent_free_checked(bev);
    }
}

void socks_error(bufferevent *bev, uint8_t resp)
{
    debug("%s bev:%p reply:%02x\n", __func__, bev, resp);
    bufferevent_setcb(bev, NULL, free_write_cb, NULL, NULL);
    uint8_t r[] = {0x05, resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bufferevent_write(bev, r, sizeof(r));
}

bool connect_exhausted(connect_req *c)
{
    debug("c:%p %s (%.2fms) direct:%p proxy_req:%p on_connect:%p tryfirst_request:%p\n",
          c, __func__, rdelta(c), c->direct, c->proxy_req, c->r.on_connect, c->tryfirst_request);
    if (c->tryfirst_request) {
        return false;
    }
    if (c->direct || c->proxy_req || c->r.on_connect) {
        return false;
    }
    for (size_t i = 0; i < lenof(c->bevs); i++) {
        if (c->bevs[i]) {
            return false;
        }
    }
    return true;
}

void connect_socks_error(connect_req *c, uint8_t resp)
{
    if (!connect_exhausted(c)) {
        return;
    }
    if (!c->server_bev) {
        return;
    }
    debug("c:%p %s (%.2fms) bev:%p reply:%02x\n", c, __func__, rdelta(c), c->server_bev, resp);
    socks_error(c->server_bev, resp);
    // freed by free_write_cb
    c->server_bev = NULL;
}

void connect_http_error(connect_req *c, int error, const char *reason)
{
    if (!connect_exhausted(c)) {
        return;
    }
    if (!c->server_req) {
        return;
    }
    debug("c:%p %s (%.2fms) req:%p reply:%d %s\n", c, __func__, rdelta(c), c->server_req, error, reason);
    if (c->server_req->evcon) {
        evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
    }
    evhttp_send_error(c->server_req, error, reason);
    c->server_req = NULL;
}

void connect_cleanup(connect_req *c)
{
    debug("c:%p %s (%.2fms)\n", c, __func__, rdelta(c));
    if (c->dont_free || !connect_exhausted(c) || c->tryfirst_request) {
        return;
    }
    assert(!c->server_req);
    assert(!c->server_bev);
    if (c->pending_bev) {
        bufferevent_free(c->pending_bev);
    }
    if (c->intro_data) {
        evbuffer_free(c->intro_data);
    }
    if (c->pc) {
        peer_disconnect(c->pc);
    }
    free(c->authority);
    free(c->host);
    free(c->tryfirst_url);
    connect_tryfirst_requests_cancel(c);
    free(c);
}

void connect_proxy_cancel(connect_req *c)
{
    debug("c:%p %s (%.2fms) req:%p\n", c, __func__, rdelta(c), c->proxy_req);
    if (c->proxy_req) {
        evhttp_cancel_request(c->proxy_req);
        c->proxy_req = NULL;
    }
    if (!c->pc) {
        abort_connect(&c->r);
    }
}

void connect_direct_cancel(connect_req *c)
{
    debug("c:%p %s (%.2fms)\n", c, __func__, rdelta(c));
    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }
}

void connect_server_read_cb(bufferevent *bev, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    evbuffer *input = bufferevent_get_input(bev);
    debug("c:%p %s (%.2fms) length:%zu\n", c, __func__, rdelta(c), evbuffer_get_length(input));

    for (size_t i = 0; i < lenof(c->bevs); i++) {
        if (c->bevs[i]) {
            evbuffer_add_buffer_reference(bufferevent_get_output(c->bevs[i]), input);
        }
    }
    bufferevent_read_buffer(c->pending_bev, c->intro_data);
    debug("c:%p %s (%.2fms) intro_data_length:%zu\n", c, __func__, rdelta(c), evbuffer_get_length(c->intro_data));
}

void connect_server_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p %s (%.2fms) events:0x%x %s\n", c, __func__, rdelta(c), events, bev_events_to_str(events));
    c->dont_free = true;
    connect_proxy_cancel(c);
    connect_direct_cancel(c);
    c->dont_free = false;
    connect_cleanup(c);
}

void connect_other_read_cb(bufferevent *bev, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    evbuffer *input = bufferevent_get_input(bev);
    debug("c:%p %s (%.2fms) length:%zu\n", c, __func__, rdelta(c), evbuffer_get_length(input));

    for (size_t i = 0; i < lenof(c->bevs); i++) {
        if (c->bevs[i] && c->bevs[i] != bev) {
            bufferevent_free(c->bevs[i]);
        }
        c->bevs[i] = NULL;
    }

    // connected!
    bufferevent *server = c->pending_bev;
    debug("c:%p %s (%.2fms) connection complete server:%p bev:%p intro_data_length:%zu\n", c, __func__, rdelta(c), server, bev, evbuffer_get_length(c->intro_data));
    c->pending_bev = NULL;
    c->dont_free = true;
    connect_proxy_cancel(c);
    connect_direct_cancel(c);
    if (strcaseeq(c->host, "stats.newnode.com")) {
        //debug("c:%p (%.2fms) not counting bytes for %s\n", c, rdelta(c), c->host);
    } else {
        bufferevent_count_bytes(c->n, c->host, bufferevent_is_localhost(server), server, bev);
    }
    c->dont_free = false;
    connect_cleanup(c);
    bev_splice(server, bev);
    bufferevent_enable(server, EV_READ|EV_WRITE);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

void connect_other_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p %s (%.2fms) bev:%p events:0x%x %s\n", c, __func__, rdelta(c), bev, events, bev_events_to_str(events));

    for (size_t i = 0; i < lenof(c->bevs); i++) {
        if (c->bevs[i] == bev) {
            c->bevs[i] = NULL;
            break;
        }
        assert(i != lenof(c->bevs) - 1);
    }

    bufferevent_free(bev);
}

void connected(connect_req *c, bufferevent *other)
{
    debug("c:%p %s (%.2fms) other:%p\n", c, __func__, rdelta(c), other);

    c->connected = true;
    if (c->server_req) {
        evhttp_connection *evcon = c->server_req->evcon;
        c->pending_bev = evhttp_connection_detach_bufferevent(evcon);
        evhttp_connection_free(evcon);
        c->server_req = NULL;
        debug("c:%p (%.2fms) detach from server_req req:%p evcon:%p bev:%p\n", c, rdelta(c), c->server_req, evcon, c->pending_bev);

        bufferevent_setcb(c->pending_bev, connect_server_read_cb, NULL, connect_server_event_cb, c);
        bufferevent_setcb(other, connect_other_read_cb, NULL, connect_other_event_cb, c);
        bufferevent_enable(c->pending_bev, EV_READ|EV_WRITE);
        bufferevent_enable(other, EV_READ|EV_WRITE);
        if (c->intro_data) {
            evbuffer_add_buffer_reference(bufferevent_get_output(other), c->intro_data);
        } else {
            c->intro_data = evbuffer_new();
            bufferevent_read_buffer(c->pending_bev, c->intro_data);
            evbuffer_add_printf(bufferevent_get_output(c->pending_bev), "HTTP/1.0 200 Connection established\r\n\r\n");
        }
    } else {
        if (c->server_bev) {
            c->pending_bev = c->server_bev;
            c->server_bev = NULL;
            debug("c:%p (%.2fms) detach from server_bev bev:%p\n", c, rdelta(c), c->pending_bev);
        }
        bufferevent_setcb(c->pending_bev, connect_server_read_cb, NULL, connect_server_event_cb, c);
        bufferevent_setcb(other, connect_other_read_cb, NULL, connect_other_event_cb, c);
        bufferevent_enable(c->pending_bev, EV_READ|EV_WRITE);
        bufferevent_enable(other, EV_READ|EV_WRITE);
        if (c->intro_data) {
            evbuffer_add_buffer_reference(bufferevent_get_output(other), c->intro_data);
        } else {
            c->intro_data = evbuffer_new();
            bufferevent_read_buffer(c->pending_bev, c->intro_data);
            // XXX: should contain ipv4/v6:port instead of 0x00s
            uint8_t r[] = {0x05, SOCKS5_REPLY_GRANTED, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            bufferevent_write(c->pending_bev, r, sizeof(r));
        }
    }
    debug("c:%p %s (%.2fms) intro_data_length:%zu\n", c, __func__, rdelta(c), evbuffer_get_length(c->intro_data));
    for (size_t i = 0; i < lenof(c->bevs); i++) {
        if (!c->bevs[i]) {
            c->bevs[i] = other;
            break;
        }
        assert(i != lenof(c->bevs) - 1);
    }
    connect_tryfirst_requests_cancel(c);
}

void connect_peer(connect_req *c, bool injector_preference);

void connect_peer_invalid_reply(connect_req *c)
{
    c->attempts++;
    debug("c:%p %s (%.2fms) attempts:%d\n", c, __func__, rdelta(c), c->attempts);
    if (c->attempts < 10) {
        connect_peer(c, true);
    }
}

void connect_direct_http_error(connect_req *c, int error, const char *reason)
{
    connect_direct_cancel(c);
    connect_http_error(c, error, reason);
    connect_cleanup(c);
}

void connect_direct_socks_error(connect_req *c, uint8_t resp)
{
    connect_direct_cancel(c);
    connect_socks_error(c, resp);
    connect_cleanup(c);
}

void connect_direct_error(connect_req *c, uint8_t socks_resp, int error, const char *reason)
{
    connect_direct_cancel(c);
    if (c->server_req) {
        connect_http_error(c, error, reason);
    } else {
        connect_socks_error(c, socks_resp);
    }
    connect_cleanup(c);
}

void connect_proxy_done_cb(evhttp_request *req, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p %s req:%p evcon:%p\n", c, __func__, req, req ? req->evcon : NULL);
    if (!req) {
        return;
    }
    c->proxy_req = NULL;
    if (!c->direct && (c->server_req || c->server_bev)) {
        if (c->pc) {
            peer_reuse(c->n, c->pc);
            c->pc = NULL;
        }
        connect_peer_invalid_reply(c);
    }
    connect_direct_error(c, SOCKS5_REPLY_HOSTUNREACH, 523, "Origin Is Unreachable (max-retries)");
}

int connect_peer_header_cb(evhttp_request *req, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p %s (%.2fms) req:%p %d %s\n", c, __func__, rdelta(c), req, req->response_code, req->response_code_line);
    if (req->response_code != 200) {
        debug("%s req->response_code:%d\n", __func__, req->response_code);

        if (req->response_code == 508) {
            peer_is_loop(c->pc->peer);
        }

        const char *msign = evhttp_find_header(req->input_headers, "X-MSign");
        if (msign) {
            debug("c:%p (%.2fms) verifying sig for %s %s\n", c, rdelta(c), evhttp_request_get_uri(req), msign);

            merkle_tree *m = alloc(merkle_tree);
            merkle_tree_hash_request(m, req, req->input_headers);
            uint8_t root_hash[crypto_generichash_BYTES];
            merkle_tree_get_root(m, root_hash);
            merkle_tree_free(m);

            if (verify_signature(root_hash, msign)) {
                debug("c:%p (%.2fms) signature good!\n", c, rdelta(c));

                peer_verified(c->n, c->pc->peer);

                c->proxy_req = NULL;

                if (c->server_req) {
                    if (connect_exhausted(c)) {
                        if (!evcon_is_localhost(c->server_req->evcon)) {
                            copy_header(req, c->server_req, "Content-Location");
                            copy_header(req, c->server_req, "X-MSign");
                        }
                        evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
                        debug("req:%p evcon:%p responding with %d %s\n", c->server_req, c->server_req->evcon,
                              req->response_code, req->response_code_line);
                        evhttp_send_reply(c->server_req, req->response_code, req->response_code_line, NULL);
                        c->server_req = NULL;
                    }
                }
                if (c->server_bev) {
                    switch (req->response_code) {
                    case 504: connect_socks_error(c, SOCKS5_REPLY_TIMEDOUT); break;
                    case 523: connect_socks_error(c, SOCKS5_REPLY_HOSTUNREACH); break;
                    case 521: connect_socks_error(c, SOCKS5_REPLY_CONNREFUSED); break;
                    default:
                    case 0: connect_socks_error(c, SOCKS5_REPLY_FAILURE); break;
                    }
                }
                return 0;
            }
            fprintf(stderr, "signature failed!\n");
            c->pc->peer->last_verified = 0;
        }
        return 0;
    }

    c->pc->peer->last_connect = time(NULL);
    free(c->pc);
    c->pc = NULL;

    debug("c:%p (%.2fms) detach from client req:%p evcon:%p\n", c, rdelta(c), req, req->evcon);
    connected(c, evhttp_connection_detach_bufferevent(req->evcon));
    evhttp_connection_free_on_completion(req->evcon);
    return -1;
}

void connect_peer_error_cb(evhttp_request_error error, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p %s (%.2fms) req:%p %d %s\n", c, __func__, rdelta(c), c->proxy_req, error, evhttp_request_error_str(error));
    c->proxy_req = NULL;
    if (c->server_req) {
        switch (error) {
        case EVREQ_HTTP_TIMEOUT: connect_http_error(c, 504, "Gateway Timeout"); break;
        case EVREQ_HTTP_EOF: connect_http_error(c, 502, "Bad Gateway (EOF)"); break;
        case EVREQ_HTTP_INVALID_HEADER: connect_http_error(c, 502, "Bad Gateway (header)"); break;
        case EVREQ_HTTP_BUFFER_ERROR: connect_http_error(c, 502, "Bad Gateway (buffer)"); break;
        case EVREQ_HTTP_DATA_TOO_LONG: connect_http_error(c, 502, "Bad Gateway (too long)"); break;
        case EVREQ_HTTP_REQUEST_CANCEL: break;
        }
    }
    if (c->server_bev) {
        switch (error) {
        case EVREQ_HTTP_TIMEOUT: connect_socks_error(c, SOCKS5_REPLY_TIMEDOUT); break;
        case EVREQ_HTTP_REQUEST_CANCEL: break;
        default:
        case EVREQ_HTTP_EOF: connect_socks_error(c, SOCKS5_REPLY_FAILURE); break;
        }
    }
    connect_cleanup(c);
}

// Return whether a direct connection is likely to get an unimpeded
// connection to the origin server. Strictly speaking, this doesn't
// only mean not blocked, it also means avoiding other kinds of
// temporary errors.  An HTTP 3-digit error code from the origin
// server is still (in most cases) 'success', as getting an authentic
// error code to  the browser more quickly is better than doing it
// more slowly.
bool direct_likely_to_succeed(const https_result *result)
{
    switch (result->https_error) {
    case HTTPS_NO_ERROR:
    case HTTPS_HTTP_ERROR:
        return true;
    default:
        return false;
    }
}

void connect_direct_completed(connect_req *c, bufferevent *bev)
{
    c->direct_connect_responded = true;
    if (!c->tryfirst_request) {
        if (direct_likely_to_succeed(&(c->tryfirst_result))) {
            c->direct = NULL;
            join_url_swarm(c->n, c->authority);
            connected(c, bev);
            return;
        }
        connect_direct_http_error(c, 523, "Origin Is Unreachable");
        return;
    }
    debug("c:%p %s (%.2fms) %s tryfirst request still pending; not spliced yet\n",
          c, __func__, rdelta(c), c->tryfirst_url);
}

void connect_direct_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p %s (%.2fms) bev:%p req:%s events:0x%x %s\n", c, __func__, rdelta(c), bev,
        c->server_req ? evhttp_request_get_uri(c->server_req) : "(null)", events, bev_events_to_str(events));

    assert(c->direct == bev);

    if (events & BEV_EVENT_TIMEOUT) {
        connect_direct_error(c, SOCKS5_REPLY_TIMEDOUT, 504, "Gateway Timeout");
    } else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        int err = bufferevent_get_error(bev);
        debug("c:%p (%.2fms) bev:%p error:%d %s\n", c, rdelta(c), bev, err, strerror(err));
        switch (err) {
        case ENETUNREACH: connect_direct_error(c, SOCKS5_REPLY_NETUNREACH, 523, "Net Is Unreachable"); break;
        case EHOSTUNREACH: connect_direct_error(c, SOCKS5_REPLY_HOSTUNREACH, 523, "Origin Is Unreachable"); break;
        case ECONNREFUSED: connect_direct_error(c, SOCKS5_REPLY_CONNREFUSED, 521, "Web Server Is Down"); break;
        case ETIMEDOUT: connect_direct_error(c, SOCKS5_REPLY_TIMEDOUT, 504, "Gateway Timeout"); break;
        default:
        case 0: connect_direct_error(c, SOCKS5_REPLY_NETUNREACH, 502, "Bad Gateway (general)"); break;
        }
    } else if (events & BEV_EVENT_CONNECTED) {
        connect_direct_completed(c, bev);
    }
}

void connect_evcon_close_cb(evhttp_connection *evcon, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p %s (%.2fms) evcon:%p\n", c, __func__, rdelta(c), evcon);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
    c->server_req = NULL;
    c->dont_free = true;
    connect_proxy_cancel(c);
    connect_direct_cancel(c);
    c->dont_free = false;
    connect_cleanup(c);
}

void connect_peer(connect_req *c, bool injector_preference)
{
    connect_more_injectors(c->n, injector_preference);

    assert(!c->pc);
    assert(!c->r.on_connect);
    assert(!c->proxy_req);
    const char *via = c->server_req ? evhttp_find_header(c->server_req->input_headers, "Via") : NULL;
    c->r.via = via?strdup(via):NULL;
    queue_request(c->n, &c->r, ^bool(peer *peer) {
        return filter_peer(peer, c->server_req, via);
    }, ^(peer_connection *pc) {
        debug("c:%p %s (%.2fms) peer:%p\n", c, __func__, rdelta(c), pc->peer);
        assert(!c->pc);
        assert(!c->r.on_connect);

        c->pc = pc;
        assert(!c->proxy_req);
        c->proxy_req = evhttp_request_new(connect_proxy_done_cb, c);
        debug("c:%p %s (%.2fms) made req:%p\n", c, __func__, rdelta(c), c->proxy_req);

        append_via(c->server_req, c->proxy_req->output_headers);

        evhttp_request_set_header_cb(c->proxy_req, connect_peer_header_cb);
        evhttp_request_set_error_cb(c->proxy_req, connect_peer_error_cb);
        evhttp_make_request(c->pc->evcon, c->proxy_req, EVHTTP_REQ_CONNECT, c->authority);
    });
}

// Return whether a request probably failed because of blocking.
// Blocked requests are cached, other failures are not cached.
bool likely_blocked(const https_result *result)
{
    switch (result->https_error) {
    // Note: a DNS error might or might not be indicative of
    // blocking but a lot of DNS errors are temporary.  So they
    // shouldn't be cached as if they were blocking.
    case HTTPS_TLS_ERROR:
    case HTTPS_TLS_CERT_ERROR:
    case HTTPS_SOCKET_IO_ERROR:
    case HTTPS_TIMEOUT_ERROR:
    case HTTPS_BLOCKING_ERROR:
        return true;
    default:
        return false;
    }
}

const char *https_strerror(https_result *result)
{
    static char buf[100];

    if (result == NULL) {
        return "";
    }
    switch (result->https_error) {
    case HTTPS_NO_ERROR: return "no error";
    case HTTPS_DNS_ERROR: return "DNS error";
    case HTTPS_HTTP_ERROR: return "HTTP error";
    case HTTPS_TLS_ERROR: return "TLS error";
    case HTTPS_TLS_CERT_ERROR: return "TLS certificate error";
    case HTTPS_SOCKET_IO_ERROR: return "socket i/o error";
    case HTTPS_TIMEOUT_ERROR: return "timeout error";
    case HTTPS_PARAMETER_ERROR: return "parameter error";
    case HTTPS_SYSCALL_ERROR: return "syscall error";
    case HTTPS_GENERIC_ERROR: return "generic error";
    case HTTPS_BLOCKING_ERROR: return "blocking error";
    case HTTPS_RESOURCE_EXHAUSTED: return "resource exhausted";
    default:
        snprintf(buf, sizeof(buf), "unknown error %d", result->https_error);
        return buf;
    }
}

tryfirst_stats* get_tryfirst_stats(const char *host)
{
    if (!g_tryfirst) {
        return NULL;
    }
    // don't ever do try first for stats.newnode.com - it adds too much overhead
    if (strcaseeq(host, "stats.newnode.com")) {
        return NULL;
    }
    if (!tryfirst_per_origin_server) {
        tryfirst_per_origin_server = hash_table_create();
    }
    return hash_get_or_insert(tryfirst_per_origin_server, host, ^{
        return alloc(tryfirst_stats);
    });
}

void update_tryfirst_stats(network *n, tryfirst_stats *tfs, int flags, uint64_t req_time, const https_result *result, char *origin_server)
{
    if (!tfs) {
        return;
    }
    tfs->attempts++;
    tfs->last_attempt = req_time;
    if (likely_blocked(result)) {
        tfs->blocked++;
        tfs->last_blocked = req_time;
    } else if (direct_likely_to_succeed(result)) {
        // "success" here means we managed to talk https to the origin
        // server and verify its certificate, NOT that we made a
        // transfer without errors.  For example, HTTP errors are
        // fine, as are "response too big" errors.
        tfs->successes++;
        tfs->last_success = req_time;
        if ((flags & (HTTPS_METHOD_HEAD|HTTPS_ONE_BYTE)) == 0) {
            // assume that HEAD responses aren't long enough to
            // measure transmission speed (so if all try first probes
            // use HEAD, maybe we shouldn't bother measuring speed at
            // all)
            tfs->bytes_xferred += result->body_length;
            tfs->xfer_time_us += us_clock() - req_time;
        }
    }
    if (o_debug > 0) {
        fprintf(stderr, "tryfirst_stats:\n");
        fprintf(stderr, "attempts = %" PRIu64 "\n", tfs->attempts);
        fprintf(stderr, "successes = %" PRIu64 "\n", tfs->successes);
        fprintf(stderr, "blocked = %" PRIu64 "\n", tfs->blocked);
        fprintf(stderr, "bytes_xferred = %" PRIu64 "\n", tfs->bytes_xferred);
        fprintf(stderr, "xfer_time_us = %f s\n", tfs->xfer_time_us / 1000000.0);
        fprintf(stderr, "last_attempt = %.2fms\n", (us_clock() - tfs->last_attempt) / 1000.0);
        fprintf(stderr, "last_success = %.2fms\n", (us_clock() - tfs->last_success) / 1000.0);
        fprintf(stderr, "last_blocked = %.2fms\n", (us_clock() - tfs->last_blocked) / 1000.0);
    }
    if (*g_country) {
        char url[2048];
        snprintf(url, sizeof(url),
                 "https://stats.newnode.com/collect?v=1"
                 "&tid=UA-149896478-2"                      // our id
                 "&npa=1"                                   // disable ad personalization
                 "&ds=%s"                                   // data source (server name)
                 "&geoid=%s"                                // geographical location = country code
                 "&t=event"                                 // hit type = event
                 "&ni=1"                                    // non interaction hit = 1
                 "&an=%s"                                   // application name
                 "&aid=%s"                                  // application ID
                 "&ec=tryfirst"                             // event category
                 "&ea=q"                                    // event action
                 "&el=https_error"                          // event label
                 "&ev=%d",                                  // event value
                 origin_server, g_country, g_app_name, g_app_id, result->https_error);
        https_request req = https_request_alloc(0, HTTPS_STATS_FLAGS, 15);
        g_https_cb(&req, url, NULL);
    }
}

typedef enum {TF_REACHABLE, TF_UNREACHABLE, TF_CONNECT_B4_TRYFIRST } tryfirst_hint;
const char* tryfirst_hint_names[] = { "REACHABLE", "UNREACHABLE", "CONNECT_BEFORE_TRYFIRST" };

#define TRYFIRST_CACHE_EXPIRY (8 * 60 * 60)

static bool is_ip_literal(const char *host)
{
    sockaddr_storage ss = {};
    int socklen = sizeof(ss);
    return !evutil_parse_sockaddr_port(host, (sockaddr*)&ss, &socklen);
}

tryfirst_hint need_tryfirst(const char *host, tryfirst_stats *tfs)
{
    // Don't do try first for IP literals because most
    // servers named by IP address won't have certificates anyway.
    // 
    // XXX alternatively we could conduct try first test but ignore
    //     cert verification failures?
    if (is_ip_literal(host)) {
        return TF_REACHABLE;
    }
    if (!tfs) {
        // never attempted, or no record
        return TF_CONNECT_B4_TRYFIRST;
    }
    if ((us_clock() - tfs->last_attempt / 1000000.0) > TRYFIRST_CACHE_EXPIRY) {
        // last attempt was too long ago
        return TF_CONNECT_B4_TRYFIRST;
    }
    if (tfs->last_attempt == tfs->last_success) {
        // last attempt was successful
        return TF_REACHABLE;
    }
    if (tfs->last_attempt == tfs->last_blocked) {
        // once a host is blocked, don't try again for 8 hours
        return TF_UNREACHABLE;
    }
    // last attempt wasn't blocked but wasn't successful - try again?
    return TF_CONNECT_B4_TRYFIRST;
}

// this can be used instead of bufferevent_socket_connect_hostname()
// it uses random address selection
int bufferevent_socket_connect_prefetched_address(bufferevent *bev, evdns_base *dns_base, const char *host, port_t port)
{
    debug("bev:%p %s host:%s\n", bev, __func__, host);
    // trust addresses that we've prefetched ourselves (when
    // available) over addresses sent to us via CONNECT request

    __block int err = 0;
    choose_addr_cb try_connect = ^bool (evutil_addrinfo *ai) {
        sockaddr_storage ss = {};
        sockaddr *s = (sockaddr*)&ss;
        memcpy(s, ai->ai_addr, ai->ai_addrlen);
        sockaddr_set_port(s, port);

        //debug("bev:%p %s trying to connect to %s\n", bev, __func__, sockaddr_str_addronly(nn->ai_addr));
        // TODO: if the request is from a peer, use LEDBAT: setsocketopt(sock, SOL_SOCKET, O_TRAFFIC_CLASS, SO_TC_BK, sizeof(int))
        if (bufferevent_socket_connect(bev, s, ai->ai_addrlen) == 0) {
            debug("bev:%p %s connecting to %s\n", bev, __func__, sockaddr_str_addronly(s));
            return true;
        }
        err = errno;
        debug("bev:%p %s connect to %s failed: %s\n", bev, __func__, sockaddr_str_addronly(s), strerror(err));
        return false;
    };

    evutil_addrinfo *res;
    if (newnode_evdns_cache_lookup(dns_base, host, NULL, port, &res) == 0 && res) {
        debug("bev:%p %s host:%s found in evdns cache\n", bev, __func__, host);
        if (!choose_addr(res, try_connect)) {
            debug("bev:%p %s host:%s unable to connect to any of: %s (%s)\n",
                  bev, __func__, host, make_ip_addr_list(res), strerror(err));
            evutil_freeaddrinfo(res);
            errno = err;
            return -1;
        }
        evutil_freeaddrinfo(res);
        return 0;
    }

    // if we don't have any IP addresses for the origin server yet,
    // fall back to bufferevent_socket_connect_hostname which will
    // look them up.
    //
    // XXX apparently evdns can hang up too long waiting for an AAAA
    //     response so just specify AF_INET for now.
    debug("bev:%p %s using bufferevent_socket_connect_hostname host:%s\n", bev, __func__, host);
    return bufferevent_socket_connect_hostname(bev, dns_base, AF_INET, host, port);
}

bool connect_direct_connect(connect_req *c)
{
    network *n = c->n;
    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(c->direct, NULL, NULL, connect_direct_event_cb, c);
    bufferevent_enable(c->direct, EV_READ);
    if (bufferevent_socket_connect_prefetched_address(c->direct, n->evdns, c->host, c->port) < 0) {
        debug("c:%p %s (%.2fms) bufferevent_socket_connect_prefetched_address failed: %s\n",
              c, __func__, rdelta(c), strerror(errno));
        connect_direct_error(c, SOCKS5_REPLY_NETUNREACH, 502, "Bad Gateway (unreachable)");
        return false;
    }
    return true;
}

void connect_request(connect_req *c, const char *host, port_t port)
{
    network *n = c->n;
    c->start_time = us_clock();

    if (!host) {
        connect_direct_error(c, SOCKS5_REPLY_AFNOSUPPORT, 400, "Invalid Host");
        return;
    }

    c->host = strdup(host);
    c->port = port;

    char authority[NI_MAXHOST + strlen(":") + strlen("65535")];
    snprintf(authority, sizeof(authority), "%s:%u", host, port);
    c->authority = strdup(authority);

    char buf[2048];
    snprintf(buf, sizeof(buf), "https://%s:%d/", host, port);
    c->tryfirst_url = strdup(buf);

    debug("c:%p %s (%.2fms) CONNECT %s:%u\n", c, __func__, rdelta(c), host, port);

    c->dont_free = true;

    if (port == 443 || port == 80) {
        connect_peer(c, false);
    }

    if (NO_DIRECT) {
        return;
    }

    if (port != 443 || !g_tryfirst || is_ip_literal(host)) {
        connect_direct_connect(c);
        return;
    }

    tryfirst_stats *tfs = get_tryfirst_stats(host);
    tryfirst_hint tfh = tfs ? need_tryfirst(host, tfs) : TF_REACHABLE;
#if FEATURE_RANDOM_SKIP_TRYFIRST
    // If we're acting as a peer, skip tryfirst 25% of the
    // time. This is to keep from searching forever for a path
    // that doesn't result in a certificate verify error, when
    // the problem is that the origin server actually does
    // have an invalid certificate or one that doesn't match
    // the host name.
    if (tfh == TF_CONNECT_B4_TRYFIRST && c->server_req && evcon_is_utp(c->server_req->evcon) && randombytes_uniform(100) < 25) {
        debug("c:%p (%.2fms) host:%s randomly skipping try first\n", c, rdelta(c), host);
        tfh = TF_REACHABLE;
    }
#endif
    debug("c:%p %s (%.2fms) need_tryfirst(%s) => %s\n", c, __func__, rdelta(c), host, tryfirst_hint_names[tfh]);
    switch (tfh) {
    case TF_UNREACHABLE:
        // couldn't reach directly on last (recent) attempt, don't bother retrying direct again
        break;
    case TF_REACHABLE:
        // reachable on last attempt, skip try first
        connect_direct_connect(c);
        break;
    case TF_CONNECT_B4_TRYFIRST:
    default:
        if (!connect_direct_connect(c)) {
            break;
        }
        https_request req = tryfirst_request_alloc();
        uint64_t req_time = us_clock();
        c->tryfirst_request = g_https_cb(&req, c->tryfirst_url, ^(bool success, const https_result *result) {
            uint64_t xfer_time_us = us_clock() - req_time;
            debug("g_https_cb complete request:%p duration:%f s\n",
                  c->tryfirst_request, xfer_time_us / 1000000.0);
            if (success) {
                debug("g_https_cb speed:%" PRIu64 " b/s\n",
                      (result->body_length * 1000000) / xfer_time_us);
            }
            // save result (except response_body pointer) for possible later examination
            c->tryfirst_result = *result;
            c->tryfirst_request = NULL;

            update_tryfirst_stats(n, tfs, req.flags, req_time, result, c->host);

            if (c->connected) {
                debug("c:%p %s (%.2fms) already connected via a peer\n", c, __func__, rdelta(c));
                return;
            }
            if (!direct_likely_to_succeed(result)) {
                debug("c:%p %s (%.2fms) %s direct connection is unlikely to succeed; cancelling\n",
                      c, __func__, rdelta(c), c->tryfirst_url);
                connect_direct_cancel(c);
                return;
            }
            debug("c:%p %s (%.2fms) %s direct connection appears likely to succeed\n",
                  c, __func__, rdelta(c), c->tryfirst_url);
            if (!c->direct || !c->direct_connect_responded) {
                debug("c:%p (%.2fms) %s try first ok; SYN-ACK not yet received from %s; not spliced yet\n",
                      c, rdelta(c), c->tryfirst_url, c->host);
                return;
            }
            // splice the two ends (browser and direct) together
            //
            // XXX There's something of a timing hazard here.  If the
            //     try first attempt takes too long to complete, the origin
            //     server may give up on the connection.   Keeping 
            //     g_tryfirst_timeout short might be sufficient but only
            //     if the implementation of g_https_cb() enforces the timeout.
            debug("c:%p (%.2fms) %s received SYN-ACK from %s, then try first ok; splicing...\n",
                  c, rdelta(c), c->tryfirst_url, c->host);
            bufferevent *direct = c->direct;
            c->direct = NULL;
            join_url_swarm(c->n, c->authority);
            connected(c, direct);
        });
        debug("%s:%d g_https_cb(%s) => request:%p\n",
              __func__, __LINE__, c->tryfirst_url, c->tryfirst_request);
        break;
    }

    c->dont_free = false;

    // may need to be cleaned up already
    connect_cleanup(c);
}

void http_connect_request(network *n, evhttp_request *req)
{
    connect_req *c = alloc(connect_req);
    c->n = n;
    c->server_req = req;

    char buf[2048];
    snprintf(buf, sizeof(buf), "https://%s", evhttp_request_get_uri(req));
    evhttp_uri_auto_free evhttp_uri *uri = evhttp_uri_parse(buf);
    const char *host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);

    if (port == -1) {
        port = 443;
    }

    evhttp_connection_set_closecb(c->server_req->evcon, connect_evcon_close_cb, c);

    connect_request(c, host, port);
}

int evhttp_parse_firstline_(evhttp_request *, evbuffer*);
int evhttp_parse_headers_(evhttp_request *, evbuffer*);

static void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    const char *e_host;
    ev_uint16_t e_port;
    evhttp_connection_get_peer(req->evcon, &e_host, &e_port);
    debug("req:%p evcon:%p %s:%u received %s %s\n", req, req->evcon, e_host, e_port,
        evhttp_method(req->type), evhttp_request_get_uri(req));

    connect_more_injectors(n, false);

    addrinfo hints = {.ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP};
    addrinfo *res;
    char port_s[6];
    snprintf(port_s, sizeof(port_s), "%u", e_port);
    getaddrinfo(e_host, port_s, &hints, &res);
    peer *peer = get_peer(all_peers, res->ai_addr);
    freeaddrinfo(res);

    const char *via = evhttp_find_header(req->input_headers, "Via");
    if (via) {
        if (peer) {
            char *p = strrchr(via, '.');
            if (p > via && streq(p, ".newnode")) {
                p--;
                peer->via = *p;
            }
        }
        if (strstr(via, via_tag)) {
            debug("Via Loop: %s (contains %s)\n", via, via_tag);
            if (peer) {
                peer_is_loop(peer);
            }
            evhttp_send_error(req, 508, "Via Loop");
            return;
        }
    }

    const evhttp_uri *evuri = evhttp_request_get_evhttp_uri(req);
    const char *scheme = evhttp_uri_get_scheme(evuri);
    const char *host = evhttp_uri_get_host(evuri);
    dns_prefetch(n, host);

    if (req->type == EVHTTP_REQ_CONNECT) {
        http_connect_request(n, req);
        return;
    }

    if (req->type == EVHTTP_REQ_GET && !host &&
        evcon_is_localhost(req->evcon) && streq(evhttp_request_get_uri(req), "/proxy.pac")) {
        evhttp_add_header(req->output_headers, "Content-Type", "application/x-ns-proxy-autoconfig");
        evbuffer_auto_free evbuffer *body = evbuffer_new();
        evbuffer_add_printf(body, "function FindProxyForURL(url, host) {return \""
                            "PROXY 127.0.0.1:%d; SOCKS 127.0.0.1:%d; DIRECT"
                            "\";}", g_port, g_port);
        evhttp_send_reply(req, 200, "OK", body);
        return;
    }
    if (req->type != EVHTTP_REQ_TRACE &&
        (!host || !scheme ||
         (evutil_ascii_strcasecmp(scheme, "http") && evutil_ascii_strcasecmp(scheme, "https")))) {
        debug("invalid proxy request: %s %s %s %s\n", scheme, evhttp_method(req->type), host, evhttp_request_get_uri(req));
        evhttp_send_error(req, 501, "Not Implemented");
        return;
    }

    const char *uri = evhttp_request_get_uri(req);
    auto_free char *encoded_uri = cache_name_from_uri(uri);
    char cache_path[PATH_MAX];
    char cache_headers_path[PATH_MAX];
    snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, encoded_uri);
    snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
    int cache_file = open(cache_path, O_RDONLY);
    int headers_file = open(cache_headers_path, O_RDONLY);
    debug("check hit:%d,%d cache:%s\n", cache_file != -1, headers_file != -1, cache_path);
    if (!NO_CACHE && cache_file != -1 && headers_file != -1) {
        evhttp_request *temp = evhttp_request_new(NULL, NULL);
        evbuffer_auto_free evbuffer *header_buf = evbuffer_new();
        ev_off_t length = lseek(headers_file, 0, SEEK_END);
        evbuffer_add_file(header_buf, headers_file, 0, length);
        evhttp_parse_firstline_(temp, header_buf);
        evhttp_parse_headers_(temp, header_buf);
        copy_response_headers(temp, req);

        length = lseek(cache_file, 0, SEEK_END);

        uint64_t range_start = 0;
        uint64_t range_end = length - 1;
        const char *range = evhttp_find_header(req->input_headers, "Range");
        if (range) {
            sscanf(range, "bytes=%"PRIu64"-%"PRIu64, &range_start, &range_end);
            if (range_start > range_end || (off_t)range_end >= length) {
                char content_range[1024];
                snprintf(content_range, sizeof(content_range), "bytes */%"PRIu64, (uint64_t)length);
                evhttp_add_header(req->output_headers, "Content-Range", content_range);
                evhttp_send_error(req, 416, "Range Not Satisfiable");
                evhttp_request_free(temp);
                close(cache_file);
                close(headers_file);
                return;
            }

            char content_range[1024];
            snprintf(content_range, sizeof(content_range), "bytes %"PRIu64"-%"PRIu64"/%"PRIu64,
                range_start, range_end, (range_end - range_start) + 1);
            evhttp_add_header(req->output_headers, "Content-Range", content_range);
        }

        const char *ifnonematch = evhttp_find_header(req->input_headers, "If-None-Match");
        const char *msign = evhttp_find_header(temp->output_headers, "X-MSign");
        if (ifnonematch && msign) {
            size_t out_len = 0;
            auto_free uint8_t *content_hash = base64_decode(ifnonematch, strlen(ifnonematch), &out_len);
            if (out_len == crypto_generichash_BYTES &&
                verify_signature(content_hash, msign)) {
                temp->response_code = 304;
                free(temp->response_code_line);
                temp->response_code_line = strdup("Not Modified");
                close(cache_file);
                cache_file = -1;
            }
        }

        evbuffer_auto_free evbuffer *content = NULL;
        if (cache_file != -1) {
            content = evbuffer_new();
            evbuffer_add_file(content, cache_file, range_start, (range_end - range_start) + 1);
        }
        // XXX: temp
        if (!evhttp_find_header(req->output_headers, "Content-Location")) {
            evhttp_add_header(req->output_headers, "Content-Location", uri);
        }
        debug("req:%p evcon:%p responding with cache %d %s start:%"PRIu64" end:%"PRIu64" length:%"PRIu64"\n", req, req->evcon,
            temp->response_code, temp->response_code_line, range_start, range_end, (range_end - range_start) + 1);
        evhttp_send_reply(req, temp->response_code, temp->response_code_line, content);
        evhttp_request_free(temp);
        return;
    }
    close(cache_file);
    close(headers_file);

    submit_request(n, req);
}

void save_peer_file(const char *s, peer_array *pa)
{
    FILE *f = fopen(s, "wb");
    if (f) {
        hash_iter(pa, ^bool (const char *addr, void *val) {
            peer *p = val;
            if (time(NULL) - p->last_verified < 7 * 24 * 60 * 60) {
                fwrite(p, sizeof(peer), 1, f);
            }
            return true;
        });
        fclose(f);
    }
}

void save_peers(network *n)
{
    if (saving_peers) {
        return;
    }
    saving_peers = timer_start(n, 1000, ^{
        saving_peers = NULL;
        save_peer_file("injectors.dat", injectors);
        save_peer_file("injector_proxies.dat", injector_proxies);
        save_peer_file("peers.dat", all_peers);
    });
}

void load_peer_file(const char *s, peer_array **pa)
{
    // XXX Note that dissimilar machines represent sockaddr_storage
    //     differently.  This will cause us to add lots of garbage
    //     peers if different clients start from a directory shared
    //     between dissimilar machines.
    FILE *f = fopen(s, "rb");
    if (f) {
        peer p;
        while (fread(&p, sizeof(p), 1, f) == 1) {
            if (p.addr.ss_family == AF_INET || p.addr.ss_family == AF_INET6) {
                add_peer(pa, (const sockaddr *)&p.addr, ^{
                    return memdup(&p, sizeof(p));
                });
            }
        }
        const char *label = "peers";
        if (*pa == injectors) {
            label = "injectors";
        } else if (*pa == injector_proxies) {
            label = "injector proxies";
        }
        debug("loaded %zu %s\n", hash_length(*pa), label);
        fclose(f);
    }
}

void load_peers(network *n)
{
    load_peer_file("injectors.dat", &injectors);
    load_peer_file("injector_proxies.dat", &injector_proxies);
    load_peer_file("peers.dat", &all_peers);
}

void connect_socks_req_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = ctx;
    debug("%s bev:%p events:0x%x %s\n", __func__, bev, events, bev_events_to_str(events));
    connect_cleanup(c);
}

void socks_event_cb(bufferevent *bev, short events, void *ctx)
{
    debug("%s bev:%p events:0x%x %s\n", __func__, bev, events, bev_events_to_str(events));
    bufferevent_free(bev);
}

void connect_socks_request(network *n, bufferevent *bev, const char *host, port_t port)
{
    connect_req *c = alloc(connect_req);
    c->n = n;
    c->server_bev = bev;
    connect_request(c, host, port);
}

void socks_read_req_cb(bufferevent *bev, void *ctx);

void socks_read_auth_cb(bufferevent *bev, void *ctx)
{
    evbuffer *input = bufferevent_get_input(bev);
    uint8_t *p = evbuffer_pullup(input, 2);
    if (!p) {
        return;
    }
    if (p[0] != 0x05) {
        bufferevent_free(bev);
        return;
    }
    p = evbuffer_pullup(input, 2 + p[1]);
    if (!p) {
        return;
    }
    if (!p[1] || !memchr(&p[2], 0x00, p[1])) {
        bufferevent_free(bev);
        return;
    }
    evbuffer_drain(input, 2 + p[1]);
    uint8_t r[] = {0x05, 0x00};
    bufferevent_write(bev, r, sizeof(r));

    bufferevent_setcb(bev, socks_read_req_cb, NULL, socks_event_cb, ctx);
}

void socks_read_req_cb(bufferevent *bev, void *ctx)
{
    network *n = ctx;
    evbuffer *input = bufferevent_get_input(bev);
    uint8_t *p = evbuffer_pullup(input, 4);
    if (!p) {
        return;
    }
    if (p[0] != 0x05 || p[1] != 0x01 || p[2] != 0x00) {
        debug("%s bev:%p error: %02x%02x%02x\n", __func__, bev, p[0], p[1], p[2]);
        bufferevent_free(bev);
        return;
    }
    debug("%s bev:%p cmd:%u\n", __func__, bev, p[3]);
    switch (p[3]) {
    // ipv4
    case 0x01: {
        p = evbuffer_pullup(input, 4 + sizeof(in_addr_t) + sizeof(port_t));
        if (!p) {
            return;
        }
        sockaddr_in sin = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = *(in_addr_t*)&p[4],
            .sin_port = *(port_t*)&p[4 + sizeof(in_addr_t)],
#ifdef __APPLE__
            .sin_len = sizeof(sin)
#endif
        };
        evbuffer_drain(input, 4 + sizeof(in_addr_t) + sizeof(port_t));

        char host[NI_MAXHOST];
        getnameinfo((sockaddr*)&sin, sizeof(sin), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        connect_socks_request(n, bev, host, ntohs(sin.sin_port));
        break;
    }
    // domain name
    case 0x03: {
        p = evbuffer_pullup(input, 4 + sizeof(uint8_t));
        if (!p) {
            return;
        }
        p = evbuffer_pullup(input, 4 + sizeof(uint8_t) + p[4] + sizeof(port_t));
        if (!p) {
            return;
        }
        port_t port;
        memcpy(&port, &p[4 + sizeof(uint8_t) + p[4]], sizeof(port_t));
        port = ntohs(port);

        char host[NI_MAXHOST];
        snprintf(host, sizeof(host), "%.*s", p[4], &p[4 + sizeof(uint8_t)]);
        evbuffer_drain(input, 4 + sizeof(uint8_t) + p[4] + sizeof(port_t));

        // SOCKS5h does not [] wrap IPv6 addresses
        char *final_host = host;
        char wrapped_host[NI_MAXHOST + 2];
        addrinfo hints = {
            .ai_family = AF_INET6,
            .ai_flags = AI_NUMERICHOST
        };
        addrinfo *res;
        int error = getaddrinfo(host, NULL, &hints, &res);
        if (!error) {
            snprintf(wrapped_host, sizeof(wrapped_host), "[%s]", host);
            final_host = wrapped_host;
            freeaddrinfo(res);
        }

        connect_socks_request(n, bev, final_host, port);
        break;
    }
    // ipv6
    case 0x04: {
        p = evbuffer_pullup(input, 4 + sizeof(in6_addr) + sizeof(port_t));
        if (!p) {
            return;
        }
        sockaddr_in6 sin6 = {
            .sin6_family = AF_INET6,
            .sin6_port = *(port_t*)&p[4 + sizeof(in6_addr)],
#ifdef __APPLE__
            .sin6_len = sizeof(sin6)
#endif
        };
        memcpy(&sin6.sin6_addr, &p[4], sizeof(sin6.sin6_addr));
        evbuffer_drain(input, 4 + sizeof(in6_addr) + sizeof(port_t));

        char addr[NI_MAXHOST];
        getnameinfo((sockaddr*)&sin6, sizeof(sin6), addr, sizeof(addr), NULL, 0, NI_NUMERICHOST);
        char host[NI_MAXHOST];
        snprintf(host, sizeof(host), "[%s]", addr);
        connect_socks_request(n, bev, host, ntohs(sin6.sin6_port));
        break;
    }
    }
}

void socks_accept_cb(evutil_socket_t nfd, sockaddr *peer_sa, int peer_socklen, void *arg)
{
    network *n = arg;
    bufferevent *bev = bufferevent_socket_new(n->evbase, nfd, BEV_OPT_CLOSE_ON_FREE);
    debug("%s bev:%p\n", __func__, bev);
    bufferevent_setcb(bev, socks_read_auth_cb, NULL, socks_event_cb, n);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

void accept_read_rb(evutil_socket_t fd, short what, void *arg)
{
    network *n = arg;
    //debug("%s fd:%d what:0x%x\n", __func__, fd, what);
    char buf[1] = {0};
    ssize_t r = recv(fd, buf, sizeof(buf), MSG_PEEK);
    if (r < 0) {
        //log_errno("recv");
        evutil_closesocket(fd);
        return;
    }
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getpeername(fd, (sockaddr *)&ss, &len);
    if (buf[0] == 0x05) {
        //debug("%s fd:%d type:socks5\n", __func__, fd);
        socks_accept_cb(fd, (sockaddr *)&ss, len, n);
        return;
    }
    //debug("%s fd:%d type:http\n", __func__, fd);
    evhttp_get_request(n->http, fd, (sockaddr *)&ss, len);
}

void accept_cb(evconnlistener *listener, evutil_socket_t nfd, sockaddr *peer_sa, int peer_socklen, void *arg)
{
    network *n = arg;
    evutil_make_socket_closeonexec(nfd);
    evutil_make_socket_nonblocking(nfd);
    event *e = event_new(n->evbase, nfd, EV_READ, accept_read_rb, n);
    debug("%s fd:%d e:%p\n", __func__, nfd, e);
    timeval tv = {.tv_sec = 30};
    event_add(e, &tv);
}

void listener_error_cb(evconnlistener *listener, void *ptr)
{
    network *n = ptr;
    int err = EVUTIL_SOCKET_ERROR();
    debug("%s %p %d (%s)\n", __func__, listener, err, evutil_socket_error_to_string(err));
}

port_t recreate_listener(network *n, port_t port)
{
    sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
        .sin_port = htons(port),
#ifdef __APPLE__
        .sin_len = sizeof(sin)
#endif
    };
    if (g_listener) {
        evconnlistener_free(g_listener);
    }
    g_listener = evconnlistener_new_bind(n->evbase, accept_cb, n,
        LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_CLOSE_ON_FREE, 128,
        (sockaddr *)&sin, sizeof(sin));
    if (!g_listener) {
        fprintf(stderr, "could not bind port %d\n", port);
        g_port = 0;
        return g_port;
    }
    evconnlistener_set_error_cb(g_listener, listener_error_cb);
    evutil_socket_t fd = evconnlistener_get_fd(g_listener);
    sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    getsockname(fd, (sockaddr *)&ss, &sslen);
    g_port = sockaddr_get_port((sockaddr *)&ss);
    printf("listening on TCP: %s\n", sockaddr_str((sockaddr *)&ss));
    return g_port;
}

void network_recreate_sockets_cb(network *n)
{
    if (!recreate_listener(n, g_port)) {
        // try again with 0 port
        recreate_listener(n, g_port);
    }
}

void maybe_update_ipinfo(network *n)
{
    if (g_ip[0] == '\0' || g_country[0] == '\0' || g_asn == 0) {
        return;
    }
    if (g_ipinfo_timestamp <= g_ipinfo_logged_timestamp) {
        return;
    }
    char url[2048];
    // update server with a GET request
    // XXX maybe add timestamp of the ipinfo?
    snprintf(url, sizeof(url),
             "https://stats.newnode.com/collect?v=1" // version = 1
             "&tid=UA-149896478-2"                   // our id
             "&npa=1"                        // disable ad personalization
             "&ds=ipinfo.io"                 // data source
             "&cid=%"PRIu64""                    // client id
             "&geoid=%s"                         // geographical location = country code
             "&t=event"                          // hit type = event
             "&ni=1"                             // non interaction hit = 1
             "&an=%s"                            // application name
             "&aid=%s"                           // application ID
             "&ec=ipinfo"                        // event category
             "&ea=q"                             // event action
             "&el=ASN"                           // event label
             "&ev=%d",                           // event value (AS #)
             g_cid, g_country, g_app_name, g_app_id, g_asn);
    https_request req = https_request_alloc(0, HTTPS_STATS_FLAGS, 15);
    g_https_cb(&req, url, NULL);
}

void query_ipinfo(network *n)
{
#define IPINFO_RESPONSE_SIZE 10240
    https_request req = https_request_alloc(IPINFO_RESPONSE_SIZE, HTTPS_GEOIP_FLAGS, 30);
    uint64_t req_time = us_clock();
    g_https_cb(&req, "https://ipinfo.io", ^(bool success, const https_result *result) {
        uint64_t xfer_time_us = us_clock() - req_time;
        debug("GET https://ipinfo.io success:%d, response_length:%zu, https_error:%d duration:%f s\n",
              success, result->body_length, result->https_error, xfer_time_us / 1000000.0);
        if (success &&
            (result->flags & HTTPS_RESULT_TRUNCATED) == 0 &&
            (result->body_length > 0) &&
            (result->body_length <= IPINFO_RESPONSE_SIZE)) {
            // make a copy of response body so we can safely
            // append a 0 byte (because the response_body is
            // allocated by the caller and might not be longer
            // than needed)
            auto_free char *response_body_copy = calloc(1, result->body_length + 1);
            memcpy(response_body_copy, result->body, result->body_length);

            // XXX: TODO: json_auto_free
            JSON_Value *v = json_parse_string(response_body_copy);
            if (json_value_get_type(v) != JSONObject) {
                json_value_free(v);
                return;
            }

            JSON_Object *jo = json_value_get_object(v);
            time_t t = time(NULL);

            const char *ip = json_string(json_object_get_value(jo, "ip"));
            const char *country = json_string(json_object_get_value(jo, "country"));
            const char *org = json_string(json_object_get_value(jo, "org"));
            int asn = -1;
            if (org != NULL) {
                // try to parse AS number embedded in org
                if (strlen(org) > 3 && org[0] == 'A' && org[1] == 'S' && isdigit(org[2])) {
                    asn = atoi(org + 2);
                }
            }
            debug("IP:%s CC:%s ASN:%d time:%s", ip, country, asn, ctime(&t));

            // now write the result to stats server if they've changed
            if (ip && ip[0] && country && country[0] && asn > 0 &&
                (strcmp (ip, g_ip) != 0 || strcmp(country, g_country) != 0 || asn != g_asn)) {
                // save new values iff they fit (don't truncate them)
                if (strlen(ip) < sizeof(g_ip)) {
                    strcpy(g_ip, ip);
                } else {
                    *g_ip = '\0';
                }
                if (strlen(country) < sizeof(g_country)) {
                    strcpy(g_country, country);
                } else {
                    *g_country = '\0';
                }
                g_asn = asn;
                g_ipinfo_timestamp = req_time;
                maybe_update_ipinfo(n);
            }
        } else {
            debug("https://ipinfo.io => success:%d response_length:%zu https_error:%d\n",
                  success, result->body_length, result->https_error);
        }
    });
}

void network_ifchange(network *n)
{
    timer_cancel(g_ifchange_timer);
    g_ifchange_timer = timer_start(n, 5 * 1000, ^{
        g_ifchange_timer = NULL;
        query_ipinfo(n);
    });
}

network* client_init(const char *app_name, const char *app_id, port_t *port, https_callback https_cb)
{
    //network_set_log_level(1);

    g_app_name = strdup(app_name);
    g_app_id = strdup(app_id);
    g_https_cb = Block_copy(https_cb);

    injectors = hash_table_create();
    injector_proxies = hash_table_create();
    all_peers = hash_table_create();
    TAILQ_INIT(&pending_requests);

    // 1.1 is the version of HTTP, not newnode
    // "1.1 _.newnode"
    via_tag[4] = 'a' + randombytes_uniform(26);

    port_t port_pref = 0;
    FILE *f = fopen("port.dat", "rb");
    if (f) {
        fread(&port_pref, sizeof(port_pref), 1, f);
        fclose(f);
    }
    network *n = network_setup("::", port_pref);
    if (!n) {
        return n;
    }

    port_pref = n->port;
    f = fopen("port.dat", "wb");
    if (f) {
        fwrite(&port_pref, sizeof(port_pref), 1, f);
        fclose(f);
    }

    f = fopen("cid.dat", "rb");
    if (f) {
        fread(&g_cid, sizeof(g_cid), 1, f);
        fclose(f);
    } else {
        randombytes_buf(&g_cid, sizeof(g_cid));
        f = fopen("cid.dat", "wb");
        if (f) {
            fwrite(&g_cid, sizeof(g_cid), 1, f);
            fclose(f);
        }
    }

    evhttp_set_allowed_methods(n->http,
                               EVHTTP_REQ_GET |
                               EVHTTP_REQ_POST |
                               EVHTTP_REQ_HEAD |
                               EVHTTP_REQ_PUT |
                               EVHTTP_REQ_DELETE |
                               EVHTTP_REQ_OPTIONS |
                               EVHTTP_REQ_TRACE |
                               EVHTTP_REQ_CONNECT |
                               EVHTTP_REQ_PATCH);

    evhttp_set_gencb(n->http, http_request_cb, n);

    *port = recreate_listener(n, *port);
    if (!*port) {
        network_free(n);
        return NULL;
    }

    network_async(n, ^{
        load_peers(n);

        // for local debugging
        /*
        sin.sin_port = htons(8004);
        add_sockaddr(n, (sockaddr *)&sin, sizeof(sin));
        */

        sockaddr_in iin = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr("52.88.7.21"),
            .sin_port = htons(9000),
#ifdef __APPLE__
            .sin_len = sizeof(iin)
#endif
        };
        add_sockaddr(n, (sockaddr *)&iin, sizeof(iin));

        timer_callback cb = ^{
            time_t t = time(NULL);
            tm *tm = gmtime(&t);
            char name[1024];

            snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday - 1));
            crypto_generichash(encrypted_injector_swarm_m1, sizeof(encrypted_injector_swarm_m1), (uint8_t*)name, strlen(name), NULL, 0);
            dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_swarm_m1);
            snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday + 0));
            crypto_generichash(encrypted_injector_swarm_p0, sizeof(encrypted_injector_swarm_p0), (uint8_t*)name, strlen(name), NULL, 0);
            dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_swarm_p0);
            snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday + 1));
            crypto_generichash(encrypted_injector_swarm_p1, sizeof(encrypted_injector_swarm_p1), (uint8_t*)name, strlen(name), NULL, 0);
            dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_swarm_p1);

            submit_trace_request(n);
            update_injector_proxy_swarm(n);
        };
        cb();
        timer_repeating(n, 25 * 60 * 1000, cb);
        // random intervals between 6-12 hours
        timer_repeating(n, 1000 * (6 + randombytes_uniform(6)) * 60 * 60, ^{ heartbeat_send(n); });
        network_ifchange(n);
    });

    return n;
}

network* newnode_init(const char *app_name, const char *app_id, port_t *port, https_callback https_cb)
{
    return client_init(app_name, app_id, port, https_cb);
}

#if TEST_STALL_DETECTOR
#include "stall_detector.h"
#endif

int newnode_run(network *n)
{
#if TEST_STALL_DETECTOR
    stall_detector(n->evbase);
#endif
    return network_loop(n);
}

void newnode_thread(network *n)
{
    thread(^{
        newnode_run(n);
    });
}

port_t newnode_get_port(network *n)
{
    return g_port;
}
