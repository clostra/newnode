#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
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

#include "dht/dht.h"

#include "log.h"
#include "lsd.h"
#include "utp.h"
#include "http.h"
#include "timer.h"
#include "obfoo.h"
#include "base64.h"
#include "network.h"
#include "constants.h"
#include "bev_splice.h"
#include "hash_table.h"
#include "utp_bufferevent.h"

#ifdef ANDROID
#include <sys/system_properties.h>
#endif


#define NO_DIRECT 0
#define NO_CACHE 0

typedef struct {
    in_addr_t ip;
    port_t port;
} PACKED address;

typedef struct {
    address addr;
    uint32_t last_verified;
    uint32_t last_connect;
    uint32_t last_connect_attempt;
    bool encrypted:1;
} peer;

typedef struct {
    network *n;
    peer *peer;
    bufferevent *bev;
    evhttp_connection *evcon;
} peer_connection;

typedef struct {
    bool failed:1;
    uint32_t time_since_verified;
    uint32_t last_connect_attempt;
    bool never_connected:1;
    uint8_t salt;
    peer *peer;
} PACKED peer_sort;

#define CACHE_PATH "./cache/"
#define CACHE_NAME CACHE_PATH "cache.XXXXXXXX"

typedef void (^peer_connected)(peer_connection *p);
typedef struct pending_request {
    peer_connected on_connect;
    TAILQ_ENTRY(pending_request) next;
} pending_request;

typedef struct {
    network *n;

    evhttp_request *server_req;
    uint64 start_time;

    evhttp_request *direct_req;
    evhttp_connection *direct_req_evcon;

    evkeyvalq direct_headers;
    crypto_generichash_state content_state;

    uint8_t content_hash[crypto_generichash_BYTES];

    pending_request r;
    peer_connection *pc;
    evhttp_request *proxy_req;

    char cache_name[sizeof(CACHE_NAME)];
    int cache_file;

    bool dont_free:1;
} proxy_request;

typedef struct {
    uint length;
    peer *peers[];
} peer_array;

peer_array *injectors;
peer_array *injector_proxies;
peer_array *all_peers;

peer_connection *peer_connections[10];

char via_tag[] = "1.1 _.newnode";
time_t injector_reachable;
time_t last_request;
timer *saving_peers;

size_t pending_requests_len;
TAILQ_HEAD(, pending_request) pending_requests;


void save_peers(network *n);

uint64_t us_clock()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

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

bool peer_is_injector(peer *p)
{
    for (uint i = 0; i < injectors->length; i++) {
        if (injectors->peers[i] == p) {
            return true;
        }
    }
    return false;
}

void connect_more_injectors(network *n, bool injector_preference);

void pending_request_complete(pending_request *r, peer_connection *pc)
{
    peer_connected on_connect = r->on_connect;
    r->on_connect = NULL;
    on_connect(pc);
    Block_release(on_connect);
}

void on_utp_connect(network *n, peer_connection *pc)
{
    address *a = &pc->peer->addr;
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    getnameinfo((sockaddr*)&sin, sizeof(sin), host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    bufferevent_disable(pc->bev, EV_READ|EV_WRITE);
    assert(pc->bev);
    assert(bufferevent_getfd(pc->bev) != -1);
    pc->evcon = evhttp_connection_base_bufferevent_new(n->evbase, n->evdns, pc->bev, host, atoi(serv));
    debug("on_utp_connect %s:%s bev:%p con:%p\n", host, serv, pc->bev, pc->evcon);
    pc->bev = NULL;
    // handle waiting requests first
    pending_request *r = TAILQ_FIRST(&pending_requests);
    if (r) {
        TAILQ_REMOVE(&pending_requests, r, next);
        pending_requests_len--;
        debug("on_utp_connect request:%p (outstanding:%zu)\n", r, pending_requests_len);
        bool found = false;
        for (uint i = 0; i < lenof(peer_connections); i++) {
            if (peer_connections[i] == pc) {
                peer_connections[i] = NULL;
                found = true;
            }
        }
        assert(found);
        debug("using new pc:%p con:%p for request:%p\n", pc, pc->evcon, r);
        pending_request_complete(r, pc);
        if (!TAILQ_EMPTY(&pending_requests)) {
            connect_more_injectors(n, false);
        }
    }
}

void bev_event_cb(bufferevent *bufev, short events, void *arg)
{
    peer_connection *pc = (peer_connection *)arg;
    assert(pc->bev == bufev);
    debug("bev_event_cb pc:%p peer:%p events:0x%x\n", pc, pc->peer, events);
    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        bufferevent_free(pc->bev);
        pc->bev = NULL;
        if (peer_is_injector(pc->peer)) {
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

const char* peer_addr_str(peer *p)
{
    static char buf[64];
    address *a = &p->addr;
    snprintf(buf, sizeof(buf), "%s:%d e:%d", inet_ntoa((in_addr){.s_addr = a->ip}), ntohs(a->port), p->encrypted);
    return buf;
}

peer_connection* evhttp_utp_connect(network *n, peer *p)
{
    utp_socket *s = utp_create_socket(n->utp);
    address *a = &p->addr;
    debug("evhttp_utp_connect %s\n", peer_addr_str(p));
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
    p->last_connect_attempt = time(NULL);
    peer_connection *pc = alloc(peer_connection);
    pc->n = n;
    pc->peer = p;
    pc->bev = utp_socket_create_bev(n->evbase, s, p->encrypted);
    utp_connect(s, (sockaddr*)&sin, sizeof(sin));
    bufferevent_setcb(pc->bev, NULL, NULL, bev_event_cb, pc);
    bufferevent_enable(pc->bev, EV_READ);
    return pc;
}

peer* get_peer(peer_array *pa, address *a)
{
    for (uint i = 0; i < pa->length; i++) {
        peer *p = pa->peers[i];
        if (memeq(a, (const uint8_t *)&p->addr, sizeof(address))) {
            return p;
        }
    }
    return NULL;
}

void add_peer(peer_array **pa, peer *p)
{
    (*pa)->length++;
    *pa = realloc(*pa, sizeof(peer_array) + (*pa)->length * sizeof(peer*));
    (*pa)->peers[(*pa)->length - 1] = p;

    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = p->addr.ip, .sin_port = p->addr.port};
    dht_ping_node((const sockaddr *)&sin, sizeof(sin));
}

void add_addresses(network *n, peer_array **pa, const uint8_t *addrs, uint num_addrs, bool encrypted)
{
    for (uint i = 0; i < num_addrs; i++) {
        address *a = (address *)&addrs[sizeof(address) * i];
        peer *p = get_peer(*pa, a);
        if (p) {
            p->encrypted = encrypted;
            return;
        }
        // paper over a bug in some DHT implementation that winds up with 1 for the port
        if (ntohs(a->port) == 1) {
            continue;
        }
        p = alloc(peer);
        p->addr = *a;
        p->encrypted = encrypted;
        add_peer(pa, p);

        const char *label = "peer";
        if (*pa == injectors) {
            label = "injector";
        } else if (*pa == injector_proxies) {
            label = "injector proxy";
        }
        debug("new %s %s\n", label, peer_addr_str(p));

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
}

void add_sockaddr(network *n, const sockaddr *addr, socklen_t addrlen)
{
    dht_ping_node(addr, addrlen);
    address a = {.ip = ((sockaddr_in*)addr)->sin_addr.s_addr, .port = ((sockaddr_in*)addr)->sin_port};
    add_addresses(n, &all_peers, (const byte*)&a, 1, false);
}

void dht_event_callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len)
{
    network *n = (network*)closure;
    debug("dht_event_callback event:%d\n", event);
    // TODO: DHT_EVENT_VALUES6
    if (event != DHT_EVENT_VALUES) {
        return;
    }
    const uint8_t* peers = data;
    size_t num_peers = data_len / 6;
    debug("dht_event_callback num_peers:%zu\n", num_peers);
    if (memeq(info_hash, injector_swarm, sizeof(injector_swarm))) {
        add_addresses(n, &injectors, peers, num_peers, false);
    } else if (memeq(info_hash, injector_proxy_swarm, sizeof(injector_proxy_swarm))) {
        add_addresses(n, &injector_proxies, peers, num_peers, false);
    } else if (memeq(info_hash, encrypted_injector_swarm, sizeof(encrypted_injector_swarm))) {
        add_addresses(n, &injectors, peers, num_peers, true);
    } else if (memeq(info_hash, encrypted_injector_proxy_swarm, sizeof(encrypted_injector_proxy_swarm))) {
        add_addresses(n, &injector_proxies, peers, num_peers, true);
    } else {
        add_addresses(n, &all_peers, peers, num_peers, true);
    }
    if (o_debug >= 2) {
        printf("Received %d values.\n", (int)(data_len / 6));
        printf("{\"");
        for (int j = 0; j < 20; j++) {
            printf("%02x", info_hash[j]);
        }
        printf("\": [");
        for (uint i = 0; i < data_len / 6; i++) {
            address *a = (address *)&data[i * 6];
            printf("\"%s:%d\"", inet_ntoa((in_addr){.s_addr = a->ip}), ntohs(a->port));
            if (i + 1 != data_len / 6) {
                printf(", ");
            }
        }
        printf("]}\n");
        if (data_len / 6 == 7) {
            dht_dump_tables(stdout);
        }
    }
}

void update_injector_proxy_swarm(network *n)
{
    if (injector_reachable) {
        //dht_announce(n->dht, (const uint8_t *)injector_proxy_swarm);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm);
    } else {
        //dht_get_peers(n->dht, (const uint8_t *)injector_proxy_swarm);
        dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_proxy_swarm);
    }
}

void abort_connect(pending_request *r)
{
    if (!r->on_connect) {
        return;
    }
    debug("aborting request:%p\n", r);
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
        pc->evcon = NULL;
    }
    if (pc->bev) {
        bufferevent_free(pc->bev);
        pc->bev = NULL;
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

void proxy_send_error(proxy_request *p, int error, const char *reason)
{
    if (p->direct_req) {
        return;
    }
    if (p->server_req) {
        assert(!p->server_req->response_code);
        if (p->server_req->evcon) {
            evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
        }
        evhttp_send_error(p->server_req, error, reason);
        p->server_req = NULL;
    }
}

void proxy_request_cleanup(proxy_request *p)
{
    if (p->dont_free || p->proxy_req || p->direct_req || p->r.on_connect) {
        return;
    }
    if (p->server_req) {
        proxy_send_error(p, 502, "Bad Gateway (default)");
    }
    if (p->pc) {
        peer_disconnect(p->pc);
        p->pc = NULL;
    }
    if (p->direct_req_evcon) {
        evhttp_connection_free(p->direct_req_evcon);
        p->direct_req_evcon = NULL;
    }
    evhttp_clear_headers(&p->direct_headers);
    proxy_cache_delete(p);
    free(p);
}

void peer_reuse(network *n, peer_connection *pc)
{
    // handle waiting requests first
    pending_request *r = TAILQ_FIRST(&pending_requests);
    if (r) {
        TAILQ_REMOVE(&pending_requests, r, next);
        pending_requests_len--;
        debug("reusing pc:%p con:%p for request:%p (outstanding:%zu)\n", pc, pc->evcon, r, pending_requests_len);
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

double pdelta(proxy_request *p)
{
    return (double)(us_clock() - p->start_time) / 1000.0;
}

void proxy_cancel_direct(proxy_request *p)
{
    if (p->direct_req) {
        evhttp_cancel_request(p->direct_req);
        p->direct_req = NULL;
    }
}

void proxy_cancel_proxy(proxy_request *p)
{
    if (p->proxy_req) {
        proxy_cache_delete(p);
        evhttp_cancel_request(p->proxy_req);
        p->proxy_req = NULL;
    }
    if (!p->pc) {
        abort_connect(&p->r);
    } else {
        peer_disconnect(p->pc);
        p->pc = NULL;
    }
}

bool write_header_to_file(int headers_file, int code, const char *code_line, evkeyvalq *input_headers)
{
    const char *headers[] = hashed_headers;
    char buf[1024];
    int s = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n", code, code_line);
    if (s >= (ssize_t)sizeof(buf)) {
        return false;
    }
    ssize_t w = write(headers_file, buf, s);
    if (s != w) {
        return false;
    }
    for (int i = 0; i < (int)lenof(headers) + 1; i++) {
        const char *key = i == lenof(headers) ? "X-Sign" : headers[i];
        const char *value = evhttp_find_header(input_headers, key);
        if (!value) {
            continue;
        }
        s = snprintf(buf, sizeof(buf), "%s: %s\r\n", key, value);
        if (s >= (ssize_t)sizeof(buf)) {
            return false;
        }
        w = write(headers_file, buf, s);
        if (s != w) {
            return false;
        }
    }
    write(headers_file, "\r\n", 2);
    return true;
}

void direct_chunked_cb(evhttp_request *req, void *arg);
void proxy_make_request(proxy_request *p);
void proxy_submit_request(proxy_request *p);

int direct_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p (%.2fms) direct_header_cb %d %s %s\n", p, pdelta(p), req->response_code, req->response_code_line, evhttp_request_get_uri(p->server_req));
    proxy_cancel_proxy(p);
    p->direct_req_evcon = req->evcon;
    copy_all_headers(req, p->server_req);

    evhttp_add_header(req->input_headers, "Content-Location", evhttp_request_get_uri(p->server_req));

    evkeyval *header;
    TAILQ_FOREACH(header, req->input_headers, next) {
        evhttp_add_header(&p->direct_headers, header->key, header->value);
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(req->input_headers, &p->content_state);

    evhttp_send_reply_start(p->server_req, req->response_code, req->response_code_line);

    snprintf(p->cache_name, sizeof(p->cache_name), CACHE_NAME);
    mkpath(p->cache_name);
    p->cache_file = mkstemp(p->cache_name);

    evhttp_request_set_chunked_cb(req, direct_chunked_cb);
    return 0;
}

void direct_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = req->input_buffer;
    //debug("p:%p direct_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    evbuffer_ptr ptr;
    evbuffer_iovec v;
    evbuffer_ptr_set(input, &ptr, 0, EVBUFFER_PTR_SET);
    while (evbuffer_peek(input, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(&p->content_state, v.iov_base, v.iov_len);
        ssize_t w = write(p->cache_file, v.iov_base, v.iov_len);
        if (w != (ssize_t)v.iov_len) {
            fprintf(stderr, "p:%p cache write failed %d (%s)\n", p, errno, strerror(errno));
            proxy_cancel_proxy(p);
            break;
        }
        if (evbuffer_ptr_set(input, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
    if (p->server_req) {
        evhttp_send_reply_chunk(p->server_req, input);
    }
}

void direct_error_cb(evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_error_cb %d\n", p, error);
    p->direct_req = NULL;
    proxy_request_cleanup(p);
}

void direct_request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_request_done_cb %p\n", p, req);
    if (!req) {
        return;
    }
    debug("p:%p (%.2fms) direct server_request_done_cb %s\n", p, pdelta(p), evhttp_request_get_uri(p->server_req));
    if (req->response_code != 0) {
        crypto_generichash_final(&p->content_state, p->content_hash, sizeof(p->content_hash));

        return_connection(p->direct_req_evcon);
        p->direct_req_evcon = NULL;

        // submit a proxy-only request with If-None-Match: "base64(content_hash)" and let it cache
        assert(!p->proxy_req);
        proxy_make_request(p);
        size_t b64_hash_len;
        char *b64_hash = base64_urlsafe_encode((uint8_t*)&p->content_hash, sizeof(p->content_hash), &b64_hash_len);
        char etag[2048];
        snprintf(etag, sizeof(etag), "\"%s\"", b64_hash);
        free(b64_hash);
        debug("submitting a cache request %s\n", etag);
        evhttp_add_header(p->proxy_req->output_headers, "If-None-Match", etag);
        proxy_submit_request(p);

        if (p->server_req->evcon) {
            evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
        }
        evhttp_send_reply_end(p->server_req);
        p->server_req = NULL;
    }
    p->direct_req = NULL;
    if (!p->proxy_req) {
        proxy_request_cleanup(p);
    }
}

bool verify_signature(const uint8_t *content_hash, const char *sign)
{
    if (strlen(sign) != BASE64_LENGTH(sizeof(content_sig))) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", strlen(sign), sizeof(content_sig));
        return false;
    }

    size_t out_len = 0;
    uint8_t *raw_sig = base64_decode(sign, strlen(sign), &out_len);
    if (out_len != sizeof(content_sig)) {
        fprintf(stderr, "Incorrect length! %zu != %zu\n", out_len, sizeof(content_sig));
        free(raw_sig);
        return false;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES] = injector_pk;

    content_sig *sig = (content_sig*)raw_sig;
    if (crypto_sign_verify_detached(sig->signature, (uint8_t*)sig->sign, sizeof(content_sig) - sizeof(sig->signature), pk)) {
        fprintf(stderr, "Incorrect signature!\n");
        free(raw_sig);
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
        free(raw_sig);
        return false;
    }

    free(raw_sig);
    return true;
}

bool addr_is_localhost(const sockaddr *sa, socklen_t salen)
{
    if (sa->sa_family == AF_INET) {
        const sockaddr_in *sin = (sockaddr_in *)sa;
        uint8_t *ip = (uint8_t*)&sin->sin_addr;
        return ip[0] == 127;
    }
    return false;
}

bool evcon_is_local_browser(evhttp_connection *evcon)
{
    int fd = bufferevent_getfd(evhttp_connection_get_bufferevent(evcon));
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getsockname(fd, (sockaddr *)&ss, &len);
    // AF_LOCAL is from socketpair(), which means utp
    if (ss.ss_family == AF_LOCAL) {
        return false;
    }
    return addr_is_localhost((sockaddr *)&ss, len);
}

void copy_response_headers(evhttp_request *from, evhttp_request *to)
{
    const char *response_header_whitelist[] = hashed_headers;
    for (uint i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(from, to, response_header_whitelist[i]);
    }
    copy_header(from, to, "Content-Length");
    if (!evcon_is_local_browser(to->evcon)) {
        copy_header(from, to, "Content-Location");
        copy_header(from, to, "X-Sign");
    }
}

void proxy_chunked_cb(evhttp_request *req, void *arg);

int proxy_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p (%.2fms) proxy_header_cb %d %s\n", p, pdelta(p), req->response_code, req->response_code_line);

    int klass = req->response_code / 100;
    switch (klass) {
    case 1:
    case 2:
    case 3:
        break;
    case 4:
    case 5:
        proxy_send_error(p, req->response_code, req->response_code_line);
    default:
        return -1;
    }

    // not the first moment of connection, but does indicate protocol support
    p->pc->peer->last_connect = time(NULL);

    if (p->cache_file != -1) {
        if (req->response_code == 304) {
            // have hash, file, and headers.
            return 0;
        }
        proxy_cache_delete(p);
    }

    if (p->cache_file == -1) {
        snprintf(p->cache_name, sizeof(p->cache_name), CACHE_NAME);
        mkpath(p->cache_name);
        p->cache_file = mkstemp(p->cache_name);
        debug("start cache:%s\n", p->cache_name);
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(req->input_headers, &p->content_state);

    evhttp_request_set_chunked_cb(req, proxy_chunked_cb);
    return 0;
}

void proxy_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = req->input_buffer;
    //debug("p:%p proxy_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    evbuffer_ptr ptr;
    evbuffer_iovec v;
    evbuffer_ptr_set(input, &ptr, 0, EVBUFFER_PTR_SET);
    while (evbuffer_peek(input, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(&p->content_state, v.iov_base, v.iov_len);
        ssize_t w = write(p->cache_file, v.iov_base, v.iov_len);
        if (w != (ssize_t)v.iov_len) {
            fprintf(stderr, "p:%p cache write failed %d (%s)\n", p, errno, strerror(errno));
            proxy_cancel_proxy(p);
            break;
        }
        if (evbuffer_ptr_set(input, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
}

void proxy_error_cb(evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_error_cb %d\n", p, error);
    if (error != EVREQ_HTTP_REQUEST_CANCEL && peer_is_injector(p->pc->peer)) {
        injector_reachable = 0;
    }
    p->proxy_req = NULL;
    proxy_request_cleanup(p);
}

char* cache_name_from_uri(const char *uri)
{
    size_t name_max = NAME_MAX - strlen(".headers");
    char *encoded_uri = evhttp_encode_uri(uri);
    if (strlen(encoded_uri) > name_max) {
        uint8_t uri_hash[crypto_generichash_BYTES];
        crypto_generichash(uri_hash, sizeof(uri_hash), (uint8_t*)uri, strlen(uri), NULL, 0);
        size_t b64_hash_len;
        char *b64_hash = base64_urlsafe_encode(uri_hash, sizeof(uri_hash), &b64_hash_len);
        encoded_uri[name_max - b64_hash_len - 2] = '.';
        strcpy(&encoded_uri[name_max - b64_hash_len - 1], b64_hash);
        free(b64_hash);
    }
    return encoded_uri;
}

void proxy_request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_request_done_cb req:%p\n", p, req);
    if (!req) {
        return;
    }
    if (!req->response_code) {
        debug("p:%p (%.2fms) no response code!\n", p, pdelta(p));
        p->proxy_req = NULL;
        proxy_request_cleanup(p);
        return;
    }

    const char *sign = evhttp_find_header(req->input_headers, "X-Sign");
    if (!sign) {
        fprintf(stderr, "no signature!\n");
        debug("p:%p (%.2fms) no signature\n", p, pdelta(p));
        proxy_send_error(p, 502, "Missing Gateway Signature");
        p->proxy_req = NULL;
        proxy_request_cleanup(p);
        return;
    }
    if (req->chunk_cb) {
        crypto_generichash_final(&p->content_state, p->content_hash, sizeof(p->content_hash));
    }

    debug("p:%p (%.2fms) verifying sig for %s %s\n", p, pdelta(p), evhttp_request_get_uri(req), sign);
    if (!verify_signature(p->content_hash, sign)) {
        fprintf(stderr, "signature failed!\n");
        p->pc->peer->last_verified = 0;
        proxy_send_error(p, 502, "Bad Gateway Signature");
        p->proxy_req = NULL;
        proxy_request_cleanup(p);
        return;
    }
    fprintf(stderr, "p:%p (%.2fms) signature good!\n", p, pdelta(p));

    p->pc->peer->last_verified = time(NULL);
    save_peers(p->n);
    if (peer_is_injector(p->pc->peer)) {
        injector_reachable = time(NULL);
        update_injector_proxy_swarm(p->n);
    }

    char headers_name[PATH_MAX];
    snprintf(headers_name, sizeof(headers_name), "%s.headers", p->cache_name);
    evkeyvalq *headers = req->input_headers;
    int code = req->response_code;
    const char *code_line = req->response_code_line;
    if (!req->chunk_cb) {
        assert(req->response_code == 304);
        code = 200;
        code_line = "OK";
        overwrite_kv_header(&p->direct_headers, "X-Sign", sign);
        headers = &p->direct_headers;
    }
    int headers_file = creat(headers_name, 0600);
    if (!write_header_to_file(headers_file, code, code_line, headers)) {
        unlink(headers_name);
    }
    fsync(headers_file);
    close(headers_file);

    const char *uri = evhttp_request_get_uri(req);
    char *encoded_uri = cache_name_from_uri(uri);
    char cache_path[PATH_MAX];
    char cache_headers_path[PATH_MAX];
    snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, encoded_uri);
    snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
    free(encoded_uri);
    debug("p:%p (%.2fms) store cache:%s headers:%s\n", p, pdelta(p), cache_path, cache_headers_path);

    fsync(p->cache_file);
    rename(p->cache_name, cache_path);
    rename(headers_name, cache_headers_path);

    if (p->server_req) {
        off_t length = lseek(p->cache_file, 0, SEEK_END);
        evbuffer *content = evbuffer_new();
        evbuffer_add_file(content, p->cache_file, 0, length);
        p->cache_file = -1;
        debug("p:%p (%.2fms) server_request_done_cb %d %s length:%u\n", p, pdelta(p),
            req->response_code, req->response_code_line, (uint32_t)length);
        proxy_cancel_direct(p);
        copy_response_headers(req, p->server_req);
        if (p->server_req->evcon) {
            evhttp_connection_set_closecb(p->server_req->evcon, NULL, NULL);
        }
        evhttp_send_reply(p->server_req, req->response_code, req->response_code_line, content);
        p->server_req = NULL;
        evbuffer_free(content);
    }

    //join_url_swarm(p->n, uri);
    evhttp_uri *evuri = evhttp_uri_parse_with_flags(req->uri, EVHTTP_URI_NONCONFORMANT);
    const char *host = evhttp_uri_get_host(evuri);
    if (host) {
        join_url_swarm(p->n, host);
    }
    evhttp_uri_free(evuri);

    peer_reuse(p->n, p->pc);
    p->pc = NULL;
    p->proxy_req = NULL;
    proxy_request_cleanup(p);
}

void direct_submit_request(proxy_request *p)
{
    assert(!p->direct_req);
    p->direct_req = evhttp_request_new(direct_request_done_cb, p);

    copy_all_headers(p->server_req, p->direct_req);

    evhttp_request_set_header_cb(p->direct_req, direct_header_cb);
    evhttp_request_set_error_cb(p->direct_req, direct_error_cb);

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
    evhttp_make_request(evcon, p->direct_req, p->server_req->type, request_uri);
    if (p->direct_req) {
        debug("p:%p con:%p direct request submitted: %s\n", p, p->direct_req->evcon, evhttp_request_get_uri(p->server_req));
    }
}

address parse_address(const char *addr)
{
    address a;
    char *port = strchr(addr, ':');
    *port = '\0';
    a.ip = inet_addr(addr);
    a.port = htons(atoi(port+1));
    return a;
}

void append_via(evhttp_request *from, evhttp_request *to)
{
    const char *via = NULL;
    char viab[2048];
    if (from) {
        via = evhttp_find_header(from->input_headers, "Via");
    }
    assert(!via || strlen(via) < sizeof(viab)/2);
    snprintf(viab, sizeof(viab), "%s%s%s", via?:"", via ? ", " : "", via_tag);
    overwrite_header(to, "Via", viab);
}

void proxy_make_request(proxy_request *p)
{
    assert(!p->proxy_req);
    p->proxy_req = evhttp_request_new(proxy_request_done_cb, p);
    const char *request_header_whitelist[] = {"Referer", "Host", "Via"};
    for (uint i = 0; i < lenof(request_header_whitelist); i++) {
        copy_header(p->server_req, p->proxy_req, request_header_whitelist[i]);
    }
    overwrite_header(p->proxy_req, "TE", "trailers");

    append_via(p->server_req, p->proxy_req);

    // TODO: range requests / partial content handling
    evhttp_remove_header(p->proxy_req->output_headers, "Range");
    evhttp_remove_header(p->proxy_req->output_headers, "If-Range");

    evhttp_request_set_header_cb(p->proxy_req, proxy_header_cb);
    evhttp_request_set_error_cb(p->proxy_req, proxy_error_cb);

    // a hack to keep the request method/url, even if the server_req dies
    p->proxy_req->type = p->server_req->type;
    p->proxy_req->uri = strdup(evhttp_request_get_uri(p->server_req));
}

void proxy_submit_request_on_con(proxy_request *p, evhttp_connection *evcon)
{
    char *uri = p->proxy_req->uri;
    p->proxy_req->uri = NULL;
    evhttp_make_request(evcon, p->proxy_req, p->proxy_req->type, uri);
    free(uri);
    debug("p:%p con:%p proxy request submitted: %s\n", p, evhttp_request_get_connection(p->proxy_req), evhttp_request_get_uri(p->proxy_req));
}

int peer_sort_cmp(const peer_sort *pa, const peer_sort *pb)
{
    return memcmp(pa, pb, sizeof(peer_sort));
}

peer* select_peer(peer_array *pa)
{
    peer_sort best = {.peer = NULL};
    for (uint i = 0; i < pa->length; i++) {
        peer *p = pa->peers[i];
        peer_sort c;
        c.failed = p->last_connect < p->last_connect_attempt;
        c.time_since_verified = time(NULL) - p->last_verified;
        c.last_connect_attempt = p->last_connect_attempt;
        c.never_connected = !p->last_connect;
        c.salt = random() & 0xFF;
        c.peer = p;
        address *a = &p->addr;
        sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
        /*
        debug("peer %s failed:%d verified_ago:%d last_connect:%d never_connected:%d salt:%d p:%p\n",
            peer_addr_str(p),
            c.failed, c.time_since_verified, c.last_connect_attempt, c.never_connected, c.salt, c.peer);
        */
        if (!i || peer_sort_cmp(&c, &best) < 0) {
            //debug("better p:%p\n", p);
            best = c;
        }
    }
    return best.peer;
}

peer_connection* start_peer_connection(network *n, peer_array *peers)
{
    peer *p = select_peer(peers);
    if (!p) {
        return NULL;
    }
    return evhttp_utp_connect(n, p);
}

void queue_request(network *n, pending_request *r, peer_connected on_connect)
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
        peer_connections[i] = start_peer_connection(n, all_peers);
        if (!peer_connections[i]) {
            break;
        }
    }

    static time_t last_lsd = 0;
    if (!any_connected && time(NULL) - last_lsd > 10) {
        last_lsd = time(NULL);
        lsd_send(n, false);
    }

    for (uint i = 0; i < lenof(peer_connections); i++) {
        peer_connection *pc = peer_connections[i];
        if (pc && pc->evcon) {
            peer_connections[i] = NULL;
            debug("using pc:%p evcon:%p for request:%p\n", pc, pc->evcon, r);
            on_connect(pc);
            return;
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
    for (uint i = 0; i < lenof(peer_connections); i++) {
        if (peer_connections[i]) {
            continue;
        }
        peer_array *o[2] = {injectors, injector_proxies};
        if (!injector_preference && random() & 1) {
            o[0] = injector_proxies;
            o[1] = injectors;
        }
        peer_connections[i] = start_peer_connection(n, o[0]);
        if (!peer_connections[i]) {
            peer_connections[i] = start_peer_connection(n, o[1]);
        }
    }
}

void proxy_submit_request(proxy_request *p)
{
    if (!p->proxy_req) {
        proxy_make_request(p);
    }

    network *n = p->n;

    /*
    if (!dht_num_searches()) {
        fetch_url_swarm(p->n, evhttp_request_get_uri(p->server_req));
    }
    */

    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(p->server_req);
    const char *host = evhttp_uri_get_host(uri);
    if (host) {
        fetch_url_swarm(p->n, host);
    }

    queue_request(p->n, &p->r, ^(peer_connection *pc) {
        p->pc = pc;
        proxy_submit_request_on_con(p, p->pc->evcon);
    });
}

void server_evcon_close_cb(evhttp_connection *evcon, void *ctx)
{
    proxy_request *p = (proxy_request*)ctx;
    debug("p:%p server_evcon_close_cb\n", p);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
    p->server_req = NULL;
    p->dont_free = true;
    proxy_cancel_direct(p);
    proxy_cancel_proxy(p);
    p->dont_free = false;
    proxy_request_cleanup(p);
}

void submit_request(network *n, evhttp_request *server_req)
{
    proxy_request *p = alloc(proxy_request);
    p->n = n;
    p->start_time = us_clock();
    TAILQ_INIT(&p->direct_headers);
    p->cache_file = -1;
    p->server_req = server_req;
    evhttp_connection_set_closecb(p->server_req->evcon, server_evcon_close_cb, p);

    p->dont_free = true;

    // https://github.com/libevent/libevent/issues/510
    int fd = bufferevent_getfd(evhttp_connection_get_bufferevent(server_req->evcon));
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getpeername(fd, (sockaddr *)&ss, &len);
    // TODO: we could request directly if we then fetched the signature
    if (!NO_DIRECT && addr_is_localhost((sockaddr *)&ss, len)) {
        direct_submit_request(p);
    }
    proxy_submit_request(p);

    p->dont_free = false;

    // may need to be cleaned up already
    proxy_request_cleanup(p);
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
    debug("t:%p trace_error_cb %d\n", t, error);
    if (error != EVREQ_HTTP_REQUEST_CANCEL && peer_is_injector(t->pc->peer)) {
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
        const char *sign = evhttp_find_header(req->input_headers, "X-Sign");
        if (!sign) {
            fprintf(stderr, "no signature on TRACE!\n");
        } else {
            crypto_generichash_state content_state;
            crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);
            hash_headers(req->input_headers, &content_state);
            unsigned char *body = evbuffer_pullup(input, evbuffer_get_length(input));
            crypto_generichash_update(&content_state, body, evbuffer_get_length(input));
            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&content_state, content_hash, sizeof(content_hash));
            debug("verifying sig for TRACE %s %s\n", evhttp_request_get_uri(req), sign);
            if (verify_signature(content_hash, sign)) {
                debug("signature good! %s\n", peer_addr_str(t->pc->peer));
                t->pc->peer->last_connect = time(NULL);
                t->pc->peer->last_verified = time(NULL);
                save_peers(t->n);
                if (peer_is_injector(t->pc->peer)) {
                    injector_reachable = time(NULL);
                    update_injector_proxy_swarm(t->n);
                }
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
    append_via(NULL, req);
    evhttp_request_set_error_cb(req, trace_error_cb);
    char request_uri[256];
    static uint32_t instance = 0;
    if (!instance) {
        instance = randombytes_random();
    }
    snprintf(request_uri, sizeof(request_uri), "/%u-%u%u",
             instance, randombytes_random(), randombytes_random());
    evhttp_make_request(evcon, req, EVHTTP_REQ_TRACE, request_uri);
    debug("t:%p con:%p %s trace request submitted: %s\n", t, req->evcon, peer_addr_str(t->pc->peer), request_uri);
}

void submit_trace_request(network *n)
{
    trace_request *t = alloc(trace_request);
    t->n = n;
    connect_more_injectors(n, true);
    queue_request(n, &t->r, ^(peer_connection *pc) {
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
    char *host;
    port_t port;

    evhttp_request *proxy_req;
    bufferevent *direct;
    pending_request r;
    peer_connection *pc;
    network *n;
    int attempts;
} connect_req;

void free_write_cb(bufferevent *bev, void *ctx)
{
    debug("%s bev:%p\n", __func__, bev);
    bufferevent_free(bev);
}

void socks_reply(bufferevent *bev, uint8_t resp)
{
    debug("%s bev:%p reply:%02x\n", __func__, bev, resp);
    bufferevent_setcb(bev, NULL, free_write_cb, NULL, NULL);
    uint8_t r[] = {0x05, resp};
    bufferevent_write(bev, r, sizeof(r));
}

bool connect_exhausted(connect_req *c)
{
    debug("%s direct:%p proxy_req:%p on_connect:%p\n", __func__, c->direct, c->proxy_req, c->r.on_connect);
    return !(c->direct || c->proxy_req || c->r.on_connect);
}

void connect_socks_reply(connect_req *c, uint8_t resp)
{
    if (!connect_exhausted(c)) {
        return;
    }
    debug("c:%p %s bev:%p reply:%02x\n", c, __func__, c->server_bev, resp);
    socks_reply(c->server_bev, resp);
    c->server_bev = NULL;
}

void connect_send_error(connect_req *c, int error, const char *reason)
{
    if (!connect_exhausted(c)) {
        return;
    }
    debug("c:%p %s req:%p reply:%d %s\n", c, __func__, c->server_req, error, reason);
    if (c->server_req->evcon) {
        evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
    }
    evhttp_send_error(c->server_req, error, reason);
    c->server_req = NULL;
}

void connect_cleanup(connect_req *c)
{
    if (!connect_exhausted(c)) {
        return;
    }
    assert(!c->server_req);
    assert(!c->server_bev);
    if (c->pc) {
        peer_disconnect(c->pc);
        c->pc = NULL;
    }
    free(c->host);
    free(c);
}

void connected(connect_req *c, bufferevent *other)
{
    debug("c:%p connected other:%p\n", c, other);
    bufferevent *bev;
    if (c->server_req) {
        evhttp_connection *evcon = c->server_req->evcon;
        bev = evhttp_connection_detach_bufferevent(evcon);
        debug("c:%p detach from server r:%p evcon:%p bev:%p\n", c, c->server_req, evcon, bev);
        bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
        evhttp_connection_set_closecb(evcon, NULL, NULL);
        c->server_req = NULL;
        evbuffer_add_printf(bufferevent_get_output(bev), "HTTP/1.0 200 Connection established\r\n\r\n");
    } else {
        bev = c->server_bev;
        c->server_bev = NULL;
        bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
        // XXX: should contain ipv4/v6:port instead of 0x00s
        uint8_t r[] = {0x05, SOCKS5_REPLY_GRANTED, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        bufferevent_write(bev, r, sizeof(r));
    }
    connect_cleanup(c);
    bev_splice(bev, other);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_enable(other, EV_READ|EV_WRITE);
}

void connect_proxy_cancel(connect_req *c)
{
    debug("c:%p %s req:%p\n", c, __func__, c->proxy_req);
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
    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }
}

void connect_peer(connect_req *c, bool injector_preference);

void connect_invalid_reply(connect_req *c)
{
    c->attempts++;
    debug("c:%p %s attempts:%d\n", c, __func__, c->attempts);
    if (c->attempts < 10) {
        connect_peer(c, true);
    }
}

void connect_done_cb(evhttp_request *req, void *arg)
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
        connect_invalid_reply(c);
    }
    if (connect_exhausted(c)) {
        if (c->server_req) {
            connect_send_error(c, 523, "Origin Is Unreachable (max-retries)");
        }
        if (c->server_bev) {
            connect_socks_reply(c, SOCKS5_REPLY_HOSTUNREACH);
        }
    }
    connect_cleanup(c);
}

int connect_header_cb(evhttp_request *req, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p connect_header_cb req:%p %d %s\n", c, req, req->response_code, req->response_code_line);
    if (req->response_code != 200) {
        debug("%s req->response_code:%d\n", __func__, req->response_code);

        const char *sign = evhttp_find_header(req->input_headers, "X-Sign");
        if (sign) {
            debug("c:%p verifying sig for %s %s\n", c, evhttp_request_get_uri(req), sign);

            crypto_generichash_state content_state;
            crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);
            hash_request(req, req->input_headers, &content_state);

            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&content_state, content_hash, sizeof(content_hash));

            if (verify_signature(content_hash, sign)) {
                debug("c:%p signature good!\n", c);

                c->pc->peer->last_verified = time(NULL);
                save_peers(c->n);
                if (peer_is_injector(c->pc->peer)) {
                    injector_reachable = time(NULL);
                    update_injector_proxy_swarm(c->n);
                }

                c->proxy_req = NULL;

                if (c->server_req) {
                    if (connect_exhausted(c)) {
                        if (!evcon_is_local_browser(c->server_req->evcon)) {
                            copy_header(req, c->server_req, "Content-Location");
                            copy_header(req, c->server_req, "X-Sign");
                        }
                        evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
                        evhttp_send_reply(c->server_req, req->response_code, req->response_code_line, NULL);
                        c->server_req = NULL;
                    }
                }
                if (c->server_bev) {
                    switch (req->response_code) {
                    case 504: connect_socks_reply(c, SOCKS5_REPLY_TIMEDOUT); break;
                    case 523: connect_socks_reply(c, SOCKS5_REPLY_HOSTUNREACH); break;
                    case 521: connect_socks_reply(c, SOCKS5_REPLY_CONNREFUSED); break;
                    default:
                    case 0: connect_socks_reply(c, SOCKS5_REPLY_FAILURE); break;
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

    connect_direct_cancel(c);

    debug("c:%p detach from client r:%p evcon:%p\n", c, req, req->evcon);
    connected(c, evhttp_connection_detach_bufferevent(req->evcon));
    return -1;
}

void connect_error_cb(evhttp_request_error error, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p %s req:%p %d\n", c, __func__, c->proxy_req, error);
    c->proxy_req = NULL;
    if (c->server_req) {
        switch (error) {
        case EVREQ_HTTP_TIMEOUT: connect_send_error(c, 504, "Gateway Timeout"); break;
        case EVREQ_HTTP_EOF: connect_send_error(c, 502, "Bad Gateway (EOF)"); break;
        case EVREQ_HTTP_INVALID_HEADER: connect_send_error(c, 502, "Bad Gateway (header)"); break;
        case EVREQ_HTTP_BUFFER_ERROR: connect_send_error(c, 502, "Bad Gateway (buffer)"); break;
        case EVREQ_HTTP_DATA_TOO_LONG: connect_send_error(c, 502, "Bad Gateway (too long)"); break;
        case EVREQ_HTTP_REQUEST_CANCEL: break;
        }
    }
    if (c->server_bev) {
        switch (error) {
        case EVREQ_HTTP_TIMEOUT: connect_socks_reply(c, SOCKS5_REPLY_TIMEDOUT); break;
        case EVREQ_HTTP_REQUEST_CANCEL: break;
        default:
        case EVREQ_HTTP_EOF: connect_socks_reply(c, SOCKS5_REPLY_FAILURE); break;
        }
    }
    connect_cleanup(c);
}

void connect_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p connect_event_cb events:0x%x bev:%p req:%s\n", c, events, bev,
        c->server_req ? evhttp_request_get_uri(c->server_req) : "(null)");

    if (events & BEV_EVENT_TIMEOUT) {
        bufferevent_free(bev);
        c->direct = NULL;
        connect_send_error(c, 504, "Gateway Timeout");
        connect_cleanup(c);
    } else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        int err = bufferevent_get_error(bev);
        bufferevent_free(bev);
        c->direct = NULL;
        debug("err:%d\n", err);
        int code = 502;
        const char *reason = "Bad Gateway";
        switch (err) {
        case ENETUNREACH:
        case EHOSTUNREACH: code = 523; reason = "Origin Is Unreachable"; break;
        case ECONNREFUSED: code = 521; reason = "Web Server Is Down"; break;
        case ETIMEDOUT: code = 504; reason = "Gateway Timeout"; break;
        }
        connect_send_error(c, code, reason);
        connect_cleanup(c);
    } else if (events & BEV_EVENT_CONNECTED) {
        connect_proxy_cancel(c);
        c->direct = NULL;
        connected(c, bev);
    }
}

void connect_evcon_close_cb(evhttp_connection *evcon, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p connect_evcon_close_cb\n", c);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
    c->server_req = NULL;
    connect_proxy_cancel(c);
    connect_direct_cancel(c);
    connect_cleanup(c);
}

void connect_peer(connect_req *c, bool injector_preference)
{
    connect_more_injectors(c->n, injector_preference);

    assert(!c->pc);
    assert(!c->r.on_connect);
    assert(!c->proxy_req);
    queue_request(c->n, &c->r, ^(peer_connection *pc) {
        debug("c:%p %s on_connect\n", c, __func__);
        assert(!c->pc);
        assert(!c->r.on_connect);
        c->pc = pc;
        assert(!c->proxy_req);
        c->proxy_req = evhttp_request_new(connect_done_cb, c);
        debug("c:%p %s made req:%p\n", c, __func__, c->proxy_req);

        append_via(c->server_req, c->proxy_req);

        evhttp_request_set_header_cb(c->proxy_req, connect_header_cb);
        evhttp_request_set_error_cb(c->proxy_req, connect_error_cb);
        if (c->server_req) {
            evhttp_make_request(c->pc->evcon, c->proxy_req, EVHTTP_REQ_CONNECT, evhttp_request_get_uri(c->server_req));
        } else {
            assert(c->server_bev);
            char authority[1024];
            snprintf(authority, sizeof(authority), "%s:%u", c->host, c->port);
            evhttp_make_request(c->pc->evcon, c->proxy_req, EVHTTP_REQ_CONNECT, authority);
        }
    });
}

void connect_request(network *n, evhttp_request *req)
{
    char buf[2048];
    snprintf(buf, sizeof(buf), "https://%s", evhttp_request_get_uri(req));
    evhttp_uri *uri = evhttp_uri_parse(buf);
    const char *host = evhttp_uri_get_host(uri);
    if (!host) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 400, "Invalid Host");
        return;
    }
    int port = evhttp_uri_get_port(uri);
    if (port == -1) {
        port = 443;
    } else if (port != 443) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 403, "Port is not 443");
        return;
    }

    connect_req *c = alloc(connect_req);
    c->n = n;
    c->server_req = req;

    evhttp_connection_set_closecb(c->server_req->evcon, connect_evcon_close_cb, c);

#if !NO_DIRECT
    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(c->direct, NULL, NULL, connect_event_cb, c);
    bufferevent_enable(c->direct, EV_READ);
#endif

    connect_peer(c, false);

#if !NO_DIRECT
    bufferevent_socket_connect_hostname(c->direct, n->evdns, AF_INET, host, port);
    evhttp_uri_free(uri);
#endif
}

int evhttp_parse_firstline_(evhttp_request *, evbuffer*);
int evhttp_parse_headers_(evhttp_request *, evbuffer*);

void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    char *e_host;
    ev_uint16_t e_port;
    evhttp_connection_get_peer(req->evcon, &e_host, &e_port);
    debug("req:%p evcon:%p %s:%u received %s %s\n", req, req->evcon, e_host, e_port,
        evhttp_method(req->type), evhttp_request_get_uri(req));

    connect_more_injectors(n, false);

    const char *via = evhttp_find_header(req->input_headers, "Via");
    if (via && strstr(via, via_tag)) {
        evhttp_send_error(req, 508, "Via Loop");
        return;
    }

    if (req->type == EVHTTP_REQ_CONNECT) {
        connect_request(n, req);
        return;
    }

    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    const char *scheme = evhttp_uri_get_scheme(uri);
    const char *host = evhttp_uri_get_host(uri);
    if (req->type != EVHTTP_REQ_TRACE &&
        (!host || !scheme ||
         (evutil_ascii_strcasecmp(scheme, "http") && evutil_ascii_strcasecmp(scheme, "https")))) {
        debug("invalid proxy request: %s %s\n", evhttp_method(req->type), evhttp_request_get_uri(req));
        evhttp_send_error(req, 501, "Not Implemented");
        return;
    }

    scheme = evhttp_uri_get_scheme(req->uri_elems);

    char *encoded_uri = cache_name_from_uri(evhttp_request_get_uri(req));
    char cache_path[PATH_MAX];
    char cache_headers_path[PATH_MAX];
    snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, encoded_uri);
    snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
    free(encoded_uri);
    int cache_file = open(cache_path, O_RDONLY);
    int headers_file = open(cache_headers_path, O_RDONLY);
    debug("check hit:%d,%d cache:%s\n", cache_file != -1, headers_file != -1, cache_path);
    if (!NO_CACHE && cache_file != -1 && headers_file != -1) {
        evhttp_request *temp = evhttp_request_new(NULL, NULL);
        evbuffer *header_buf = evbuffer_new();
        off_t length = lseek(headers_file, 0, SEEK_END);
        evbuffer_add_file(header_buf, headers_file, 0, length);
        evhttp_parse_firstline_(temp, header_buf);
        evhttp_parse_headers_(temp, header_buf);
        copy_response_headers(temp, req);
        evbuffer_free(header_buf);

        evbuffer *content = NULL;
        length = lseek(cache_file, 0, SEEK_END);

        const char *ifnonematch = evhttp_find_header(req->input_headers, "If-None-Match");
        if (ifnonematch) {
            const char *sign = evhttp_find_header(temp->output_headers, "X-Sign");
            size_t out_len = 0;
            uint8_t *content_hash = base64_decode(ifnonematch, strlen(ifnonematch), &out_len);
            if (out_len == crypto_generichash_BYTES && verify_signature(content_hash, sign)) {
                temp->response_code = 304;
                free(temp->response_code_line);
                temp->response_code_line = strdup("Not Modified");
                close(cache_file);
                cache_file = -1;
            }
            free(content_hash);
        }

        if (cache_file != -1) {
            content = evbuffer_new();
            evbuffer_add_file(content, cache_file, 0, length);
        }
        debug("responding with %d %s length:%u\n", temp->response_code, temp->response_code_line, (uint32_t)length);
        evhttp_send_reply(req, temp->response_code, temp->response_code_line, content);
        evhttp_request_free(temp);
        if (content) {
            evbuffer_free(content);
        }
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
        for (size_t i = 0; i < pa->length; i++) {
            if (time(NULL) - pa->peers[i]->last_verified < 7 * 24 * 60 * 60) {
                fwrite(pa->peers[i], sizeof(peer), 1, f);
            }
        }
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
    FILE *f = fopen(s, "rb");
    if (f) {
        peer p;
        while (fread(&p, sizeof(p), 1, f) == 1) {
            if (!get_peer(*pa, &p.addr)) {
                add_peer(pa, memdup(&p, sizeof(p)));
            }
        }
        const char *label = "peers";
        if (*pa == injectors) {
            label = "injectors";
        } else if (*pa == injector_proxies) {
            label = "injector proxies";
        }
        debug("loaded %u %s\n", (*pa)->length, label);
        fclose(f);
    }
}

void load_peers(network *n)
{
    load_peer_file("injectors.dat", &injectors);
    load_peer_file("injector_proxies.dat", &injector_proxies);
    load_peer_file("peers.dat", &all_peers);
}

void socks_connect_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = ctx;
    debug("c:%p %s events:0x%x bev:%p req:%s\n", c, __func__, events, bev,
        c->server_req ? evhttp_request_get_uri(c->server_req) : "(null)");

    if (events & BEV_EVENT_TIMEOUT) {
        socks_reply(bev, SOCKS5_REPLY_TIMEDOUT);
        c->direct = NULL;
        connect_cleanup(c);
    } else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        int err = bufferevent_get_error(bev);
        switch (err) {
        case ENETUNREACH: socks_reply(bev, SOCKS5_REPLY_NETUNREACH); break;
        case EHOSTUNREACH: socks_reply(bev, SOCKS5_REPLY_HOSTUNREACH); break;
        case ECONNREFUSED: socks_reply(bev, SOCKS5_REPLY_CONNREFUSED); break;
        case ETIMEDOUT: socks_reply(bev, SOCKS5_REPLY_TIMEDOUT); break;
        default:
        case 0: socks_reply(bev, SOCKS5_REPLY_FAILURE); break;
        }
        c->direct = NULL;
        connect_cleanup(c);
    } else if (events & BEV_EVENT_CONNECTED) {
        connect_proxy_cancel(c);
        c->direct = NULL;
        connected(c, bev);
    }
}

void socks_connect_req_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = ctx;
    debug("%s bev:%p events:0x%x\n", __func__, bev, events);
    connect_cleanup(c);
}

void socks_event_cb(bufferevent *bev, short events, void *ctx)
{
    debug("%s bev:%p events:0x%x\n", __func__, bev, events);
    bufferevent_free(bev);
}

bufferevent* socks_connect_request(network *n, bufferevent *bev, const char *host, port_t port)
{
    // proxied CONNECT requests to port 80 will be rejected, but direct connections might work
    if (port != 443 && port != 80) {
        debug("SOCK5 port not allowed %s:%u\n", host, port);
        socks_reply(bev, SOCKS5_REPLY_NOT_ALLOWED);
        return NULL;
    }

    connect_req *c = alloc(connect_req);
    c->n = n;
    c->server_bev = bev;
    c->host = strdup(host);
    c->port = port;

    debug("c:%p %s bev:%p SOCKS5 CONNECT %s:%u\n", c, __func__, bev, host, port);

    bufferevent_setcb(bev, NULL, NULL, socks_connect_req_event_cb, c);

#if !NO_DIRECT
    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    debug("%s bev:%p direct:%p\n", __func__, bev, c->direct);
    bufferevent_setcb(c->direct, NULL, NULL, socks_connect_event_cb, c);
    bufferevent_enable(c->direct, EV_READ);
#endif

    connect_peer(c, false);

    return c->direct;
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
            .sin_port = *(port_t*)&p[4 + sizeof(in_addr_t)]
        };
        evbuffer_drain(input, 4 + sizeof(in_addr_t) + sizeof(port_t));
        bufferevent_setcb(bev, NULL, NULL, socks_event_cb, ctx);

        char host[NI_MAXHOST];
        getnameinfo((sockaddr*)&sin, sizeof(sin), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        bufferevent *b = socks_connect_request(n, bev, host, ntohs(sin.sin_port));
        if (b) {
            bufferevent_socket_connect(b, (sockaddr*)&sin, sizeof(sin));
        }
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
        bufferevent_setcb(bev, NULL, NULL, socks_event_cb, ctx);

        bufferevent *b = socks_connect_request(n, bev, host, port);
        if (b) {
            // XXX: disable IPv6, since evdns waits for *both* and the v6 request often times out
            bufferevent_socket_connect_hostname(b, n->evdns, AF_INET, host, port);
        }
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
        };
        memcpy(&sin6.sin6_addr, &p[4], sizeof(sin6.sin6_addr));
        evbuffer_drain(input, 4 + sizeof(in6_addr) + sizeof(port_t));
        bufferevent_setcb(bev, NULL, NULL, socks_event_cb, ctx);

        char host[NI_MAXHOST];
        getnameinfo((sockaddr*)&sin6, sizeof(sin6), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        bufferevent *b = socks_connect_request(n, bev, host, ntohs(sin6.sin6_port));
        if (b) {
            bufferevent_socket_connect(b, (sockaddr*)&sin6, sizeof(sin6));
        }
        break;
    }
    }
}

void socks_accept_cb(evconnlistener *listener, evutil_socket_t nfd, sockaddr *peer_sa, int peer_socklen, void *arg)
{
    network *n = arg;
    bufferevent *bev = bufferevent_socket_new(n->evbase, nfd, BEV_OPT_CLOSE_ON_FREE);
    debug("%s bev:%p\n", __func__, bev);
    bufferevent_setcb(bev, socks_read_auth_cb, NULL, socks_event_cb, n);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

network* client_init(port_t port)
{
    //o_debug = 1;

    injectors = alloc(peer_array);
    injector_proxies = alloc(peer_array);
    all_peers = alloc(peer_array);
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

    network *n = network_setup("0.0.0.0", port_pref);

    sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    getsockname(n->fd, (sockaddr *)&ss, &sslen);
    port_pref = sockaddr_get_port((sockaddr *)&ss);
    f = fopen("port.dat", "wb");
    if (f) {
        fwrite(&port_pref, sizeof(port_pref), 1, f);
        fclose(f);
    }

    evhttp_set_allowed_methods(n->http, EVHTTP_REQ_GET | EVHTTP_REQ_HEAD | EVHTTP_REQ_CONNECT | EVHTTP_REQ_TRACE);
    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "127.0.0.1", port);

    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = inet_addr("127.0.0.1"), .sin_port = htons(port + 1)};
    evconnlistener *l = evconnlistener_new_bind(n->evbase, socks_accept_cb, n,
        LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_CLOSE_ON_FREE, 128,
        (sockaddr *)&sin, sizeof(sin));

    printf("listening on TCP:%s:%d,%d\n", "127.0.0.1", port, port+1);

    load_peers(n);

    timer_callback cb = ^{
        //dht_get_peers(n->dht, (const uint8_t *)injector_swarm);
        dht_get_peers(n->dht, (const uint8_t *)encrypted_injector_swarm);
        submit_trace_request(n);
        update_injector_proxy_swarm(n);
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);

    return n;
}

int client_run(network *n)
{
    return network_loop(n);
}

void* client_thread(void *userdata)
{
    client_run((network*)userdata);
    return NULL;
}

void client_thread_start(port_t port)
{
    network *n = client_init(port);
    pthread_t t;
    pthread_create(&t, NULL, client_thread, n);
}

void newnode_init()
{
    static bool started = false;
    if (started) {
        return;
    }
    started = true;
    client_thread_start(8006);
}
