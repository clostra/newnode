#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <sodium.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "utp.h"
#include "http.h"
#include "base64.h"
#include "timer.h"
#include "network.h"
#include "constants.h"
#include "bev_splice.h"
#include "hash_table.h"
#include "utp_bufferevent.h"


typedef struct {
    in_addr_t ip;
    port_t port;
} PACKED address;

typedef struct {
    address addr;
    bufferevent *bev;
    evhttp_connection *evcon;
    uint32_t last_verified;
    uint32_t last_connect;
    uint32_t last_connect_attempt;
} peer;

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
#define CACHE_HEADERS_NAME CACHE_NAME ".headers"

typedef void (^connected_peer)(peer *p);
typedef struct pending_request {
    connected_peer connected;
    TAILQ_ENTRY(pending_request) next;
} pending_request;

typedef struct {
    network *n;
    evhttp_request *direct_req;
    evhttp_request *proxy_req;
    evhttp_request *proxy_head_req;
    evhttp_request *server_req;
    void (*evhttp_handle_request)(struct evhttp_request *, void *);
    crypto_generichash_state content_state;
    char cache_name[sizeof(CACHE_NAME)];
    int cache_file;
    pending_request r;
    peer *peer;
    bool dont_free:1;
} proxy_request;

typedef struct {
    uint length;
    peer *peers[];
} peer_array;

peer_array *injectors;
peer_array *injector_proxies;
peer_array *all_peers;

peer *pending_connections[10];

time_t last_trace;
time_t injector_reachable;

TAILQ_HEAD(, pending_request) pending_requests;


bool memeq(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
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

void add_addresses(peer_array **pa, const byte *addrs, uint num_addrs)
{
    for (uint i = 0; i < num_addrs; i++) {
        for (uint j = 0; j < (*pa)->length; j++) {
            if (memeq(&addrs[sizeof(address) * i], (const uint8_t *)&((*pa)->peers)[j]->addr, sizeof(address))) {
                return;
            }
        }
        address *a = (address *)&addrs[sizeof(address) * i];
        // XXX: paper over a bug in some DHT implementation that winds up with 1 for the port
        if (ntohs(a->port) == 1) {
            continue;
        }
        (*pa)->length++;
        *pa = realloc(*pa, sizeof(peer_array) + (*pa)->length * sizeof(peer*));
        peer *p = alloc(peer);
        (*pa)->peers[(*pa)->length-1] = p;
        p->addr = *a;
        const char *label = "peer";
        if (*pa == injectors) {
            label = "injector";
        } else if (*pa == injector_proxies) {
            label = "injector proxy";
        }
        debug("new %s %s:%d\n", label, inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
    }
}

void update_injector_proxy_swarm(network *n)
{
    add_nodes_callblock c = ^(const byte *peers, uint num_peers) {
        if (peers) {
            add_addresses(&injector_proxies, peers, num_peers);
        }
    };
    if (injector_reachable) {
        dht_announce(n->dht, injector_proxy_swarm, c);
    } else {
        dht_get_peers(n->dht, injector_proxy_swarm, c);
    }
}

bool peer_is_injector(peer *p)
{
    for (size_t i = 0; i < injectors->length; i++) {
        if (injectors->peers[i] == p) {
            return true;
        }
    }
    return false;
}

void remove_server_req_cb(proxy_request *p)
{
    p->server_req->cb = p->evhttp_handle_request;
    p->server_req->cb_arg = p->n->http;
    evhttp_request_set_error_cb(p->server_req, NULL);
}

void proxy_cache_delete(proxy_request *p)
{
    close(p->cache_file);
    p->cache_file = -1;
    unlink(p->cache_name);
}

void proxy_request_cleanup(proxy_request *p)
{
    debug("df:%d preq:%p phr:%p dr:%p\n", p->dont_free, p->proxy_req, p->proxy_head_req, p->direct_req);
    if (p->dont_free || p->proxy_req || p->proxy_head_req || p->direct_req || !p->peer) {
        return;
    }
    if (p->server_req) {
        if (!p->server_req->response_code) {
            evhttp_send_error(p->server_req, 504, "Gateway Timeout");
        } else {
            evhttp_send_reply_end(p->server_req);
        }
        remove_server_req_cb(p);
        p->server_req = NULL;
    }
    proxy_cache_delete(p);
    free(p);
}

void abort_connect(pending_request *r)
{
    if (r->connected) {
        Block_release(r->connected);
        r->connected = NULL;
        TAILQ_REMOVE(&pending_requests, r, next);
    }
}

void proxy_cancel_proxy(proxy_request *p)
{
    if (p->proxy_req) {
        evhttp_cancel_request(p->proxy_req);
        p->proxy_req = NULL;
    }
    if (p->proxy_head_req) {
        evhttp_cancel_request(p->proxy_head_req);
        p->proxy_head_req = NULL;
    }
    if (!p->peer) {
        abort_connect(&p->r);
    }
}

void direct_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = evhttp_request_get_input_buffer(req);
    //debug("p:%p direct_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    evhttp_send_reply_chunk(p->server_req, input);
}

int direct_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p direct_header_cb %d %s\n", p, req->response_code, req->response_code_line);
    proxy_cancel_proxy(p);
    copy_all_headers(req, p->server_req);
    evhttp_send_reply_start(p->server_req, req->response_code, req->response_code_line);
    evhttp_request_set_chunked_cb(req, direct_chunked_cb);
    return 0;
}

void direct_error_cb(enum evhttp_request_error error, void *arg)
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
    debug("p:%p direct server_request_done_cb con:%p %s\n", p, req->evcon, evhttp_request_get_uri(p->server_req));
    p->direct_req = NULL;
    proxy_request_cleanup(p);
}

void proxy_chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = evhttp_request_get_input_buffer(req);
    //debug("p:%p proxy_chunked_cb length:%zu\n", p, evbuffer_get_length(input));
    struct evbuffer_ptr ptr;
    struct evbuffer_iovec v;
    evbuffer_ptr_set(input, &ptr, 0, EVBUFFER_PTR_SET);
    while (evbuffer_peek(input, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(&p->content_state, v.iov_base, v.iov_len);
        ssize_t w = write(p->cache_file, v.iov_base, v.iov_len);
        if (w != (ssize_t)v.iov_len) {
            fprintf(stderr, "p:%p cache write failed %d (%s)\n", p, errno, strerror(errno));
            proxy_cache_delete(p);
            proxy_cancel_proxy(p);
            proxy_request_cleanup(p);
            break;
        }
        if (evbuffer_ptr_set(input, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
}

int proxy_header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_header_cb %d %s\n", p, req->response_code, req->response_code_line);

    int code = req->response_code;
    int klass = code / 100;
    switch (klass) {
    case 3:
    case 2:
        break;
    case 4:
    case 5:
    evhttp_send_error(p->server_req, code, req->response_code_line);
        remove_server_req_cb(p);
        p->server_req = NULL;
    default:
        return -1;
    }

    // not the first moment of connection, but does indicate protocol support
    p->peer->last_connect = time(NULL);

    if (req == p->proxy_head_req) {
        return 0;
    }

    if (p->proxy_head_req) {
        const char *sign = evhttp_find_header(req->input_headers, "X-Sign");
        if (sign) {
            evhttp_cancel_request(p->proxy_head_req);
            p->proxy_head_req = NULL;
        }
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(req->input_headers, &p->content_state);

    mkpath(p->cache_name);
    p->cache_file = mkstemp(p->cache_name);
    debug("start cache:%s\n", p->cache_name);

    evhttp_request_set_chunked_cb(req, proxy_chunked_cb);
    return 0;
}

void proxy_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_error_cb %d\n", p, error);
    if (error != EVREQ_HTTP_REQUEST_CANCEL && peer_is_injector(p->peer)) {
        injector_reachable = 0;
    }
    p->proxy_req = NULL;
    proxy_request_cleanup(p);
}

void proxy_head_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_head_error_cb %d\n", p, error);
    p->proxy_head_req = NULL;
    proxy_request_cleanup(p);
}

bool verify_signature(crypto_generichash_state *content_state, const char *sign)
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

    uint8_t content_hash[crypto_generichash_BYTES];
    crypto_generichash_final(content_state, content_hash, sizeof(content_hash));

    if (memcmp(content_hash, sig->content_hash, sizeof(content_hash))) {
        fprintf(stderr, "Incorrect hash!\n");
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
    const char *response_header_whitelist[] = {"Content-Length", "Content-Type", "Location"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(from, to, response_header_whitelist[i]);
    }
    if (!evcon_is_local_browser(evhttp_request_get_connection(to))) {
        copy_header(from, to, "Content-Location");
        copy_header(from, to, "X-Sign");
    }
}

bool write_header_to_file(int headers_file, evhttp_request *req)
{
    const char *headers[] = hashed_headers;
    char buf[1024];
    int s = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n", req->response_code, req->response_code_line);
    if (s >= (ssize_t)sizeof(buf)) {
        return false;
    }
    ssize_t w = write(headers_file, buf, s);
    if (s != w) {
        return false;
    }
    for (int i = -1; i < (int)lenof(headers); i++) {
        const char *key = i == -1 ? "X-Sign" : headers[i];
        const char *value = evhttp_find_header(req->input_headers, key);
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

void proxy_request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p proxy_request_done_cb req:%p\n", p, req);
    if (!req) {
        return;
    }
    if (!req->evcon) {
        // connection failed
        if (peer_is_injector(p->peer)) {
            injector_reachable = 0;
        }
    }
    if (p->server_req) {
        const char *sign = evhttp_find_header(req->input_headers, "X-Sign");
        if (!sign) {
            if (req == p->proxy_req) {
                debug("no signature; waiting for HEAD request.\n");
            } else {
                fprintf(stderr, "no signature!\n");
            }
        } else {
            assert(req == p->proxy_req || !p->proxy_req);
            debug("verifying sig for %s %s\n", evhttp_request_get_uri(p->server_req), sign);
            if (!verify_signature(&p->content_state, sign)) {
                evhttp_send_error(p->server_req, 502, "Bad Gateway Signature");
                remove_server_req_cb(p);
                p->server_req = NULL;
            } else {
                p->peer->last_verified = time(NULL);
                if (peer_is_injector(p->peer)) {
                    injector_reachable = time(NULL);
                    update_injector_proxy_swarm(p->n);
                }
                char headers_name[] = CACHE_HEADERS_NAME;
                int headers_file = mkstemps(headers_name, sizeof(headers_name) - sizeof(p->cache_name));
                if (!write_header_to_file(headers_file, req)) {
                    unlink(headers_name);
                }
                close(headers_file);
                close(p->cache_file);
                p->cache_file = -1;
                const char *content_location = evhttp_find_header(req->input_headers, "Content-Location");
                char *uri = evhttp_encode_uri(content_location);
                char cache_path[2048];
                char cache_headers_path[2048];
                snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, uri);
                snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
                free(uri);
                debug("store cache:%s headers:%s\n", cache_path, cache_headers_path);
                rename(p->cache_name, cache_path);
                rename(headers_name, cache_headers_path);
                int fd = open(cache_path, O_RDONLY);
                off_t length = lseek(fd, 0, SEEK_END);
                evbuffer *content = evbuffer_new();
                evbuffer_add_file(content, fd, 0, length);
                debug("responding with %d %s %u\n", req->response_code,
                    req->response_code_line, length);
                if (p->direct_req) {
                    evhttp_cancel_request(p->direct_req);
                    p->direct_req = NULL;
                }
                copy_response_headers(req, p->server_req);
                evhttp_send_reply(p->server_req, req->response_code, req->response_code_line, content);
                if (content) {
                    evbuffer_free(content);
                }
                remove_server_req_cb(p);
                p->server_req = NULL;
                join_url_swarm(p->n, content_location);
            }
        }
    }
    if (req == p->proxy_head_req) {
        p->proxy_head_req = NULL;
    } else {
        p->proxy_req = NULL;
    }
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
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", evhttp_uri_get_path(uri), q?"?":"", q?q:"");
    evhttp_connection *evcon = make_connection(p->n, uri);
    evhttp_make_request(evcon, p->direct_req, EVHTTP_REQ_GET, request_uri);
    debug("p:%p con:%p direct request submitted: %s\n", p, evhttp_request_get_connection(p->direct_req), evhttp_request_get_uri(p->direct_req));
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

void proxy_submit_request_on_con(proxy_request *p, evhttp_connection *evcon)
{
    assert(!p->proxy_req);
    p->proxy_req = evhttp_request_new(proxy_request_done_cb, p);
    const char *request_header_whitelist[] = {"Referer", "Host"};
    for (size_t i = 0; i < lenof(request_header_whitelist); i++) {
        copy_header(p->server_req, p->proxy_req, request_header_whitelist[i]);
    }
    overwrite_header(p->proxy_req, "Proxy-Connection", "Keep-Alive");

    // TODO: range requests / partial content handling
    evhttp_remove_header(p->proxy_req->output_headers, "Range");
    evhttp_remove_header(p->proxy_req->output_headers, "If-Range");

    evhttp_request_set_header_cb(p->proxy_req, proxy_header_cb);
    evhttp_request_set_error_cb(p->proxy_req, proxy_error_cb);

    p->proxy_head_req = evhttp_request_new(proxy_request_done_cb, p);
    copy_all_headers(p->proxy_req, p->proxy_head_req);

    evhttp_request_set_header_cb(p->proxy_head_req, proxy_header_cb);
    evhttp_request_set_error_cb(p->proxy_head_req, proxy_head_error_cb);

    char request_uri[2048];
    evhttp_uri_join(evhttp_request_get_evhttp_uri(p->server_req), request_uri, sizeof(request_uri));
    evhttp_make_request(evcon, p->proxy_req, EVHTTP_REQ_GET, request_uri);
    evhttp_make_request(evcon, p->proxy_head_req, EVHTTP_REQ_HEAD, request_uri);
    debug("p:%p con:%p proxy request submitted: %s\n", p, evhttp_request_get_connection(p->proxy_req), evhttp_request_get_uri(p->proxy_req));
}

void on_evcon(network *n, peer *p)
{
    if (TAILQ_EMPTY(&pending_requests)) {
        return;
    }
    pending_request *r = TAILQ_FIRST(&pending_requests);
    TAILQ_REMOVE(&pending_requests, r, next);
    for (size_t i = 0; i < lenof(pending_connections); i++) {
        if (pending_connections[i] == p) {
            pending_connections[i] = NULL;
            break;
        }
    }
    r->connected(p);
    Block_release(r->connected);
    r->connected = NULL;
}

void on_utp_connect(network *n, peer *p)
{
    address *a = &p->addr;
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    getnameinfo((sockaddr*)&sin, sizeof(sin), host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    debug("on_utp_connect %s:%s\n", host, serv);
    p->evcon = evhttp_connection_base_bufferevent_new(n->evbase, n->evdns, p->bev, host, atoi(serv));
    on_evcon(n, p);
}

void bev_error_cb(struct bufferevent *bufev, short what, void *arg)
{
    peer *p = (peer *)arg;
    debug("bev_error_cb p:%p\n", p);
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        bufferevent_free(p->bev);
        p->bev = NULL;
        for (size_t i = 0; i < lenof(pending_connections); i++) {
            if (pending_connections[i] == p) {
                pending_connections[i] = NULL;
                break;
            }
        }
    }
}

void evhttp_utp_connect(network *n, peer *p)
{
    utp_socket *s = utp_create_socket(n->utp);
    address *a = &p->addr;
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
    debug("utp_socket_connect_fd %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
    p->last_connect_attempt = time(NULL);
    int fd = utp_socket_connect_fd(n->evbase, s, (sockaddr*)&sin, sizeof(sin), ^{
        on_utp_connect(n, p);
    });
    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);
    p->bev = bufferevent_socket_new(n->evbase, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(p->bev, NULL, NULL, bev_error_cb, p);
    bufferevent_enable(p->bev, EV_READ);
}

int peer_sort_cmp(const peer_sort *pa, const peer_sort *pb)
{
    return memcmp(pa, pb, sizeof(peer_sort));
}

peer* select_peer(peer_array *pa)
{
    peer_sort best = {.peer = NULL};
    for (size_t i = 0; i < pa->length; i++) {
        peer *p = pa->peers[i];
        // XXX: there's no reason the peer couldn't have multiple connections...
        if (p->bev) {
            continue;
        }
        peer_sort c;
        c.failed = p->last_connect < p->last_connect_attempt;
        c.time_since_verified = time(NULL) - p->last_verified;
        c.last_connect_attempt = p->last_connect_attempt;
        c.never_connected = !p->last_connect;
        c.salt = random() & 0xFF;
        c.peer = p;
        address *a = &p->addr;
        if (!i || peer_sort_cmp(&c, &best) < 0) {
            best = c;
        }
    }
    return best.peer;
}

peer* start_peer_connection(network *n, peer_array *peers)
{
    peer *p = select_peer(peers);
    if (p) {
        evhttp_utp_connect(n, p);
    }
    return p;
}

void on_connect(pending_request *r, connected_peer connected)
{
    for (size_t i = 0; i < lenof(pending_connections); i++) {
        peer *p = pending_connections[i];
        if (p && p->evcon) {
            pending_connections[i] = NULL;
            connected(p);
            return;
        }
    }
    r->connected = Block_copy(connected);
    TAILQ_INSERT_TAIL(&pending_requests, r, next);
}

void proxy_submit_request(proxy_request *p)
{
    assert(!p->proxy_req);

    const char *xdht = evhttp_find_header(p->server_req->input_headers, "X-DHT");
    if (!xdht) {
        const char *xpeer = evhttp_find_header(p->server_req->input_headers, "X-Peer");
        if (xpeer) {
            address xa = parse_address(xpeer);
            add_addresses(&all_peers, (const byte*)&xa, 1);
            for (size_t i = 0; i < all_peers->length; i++) {
                if (!memeq((const uint8_t *)&xa, (const uint8_t *)&all_peers->peers[i]->addr, sizeof(address))) {
                    continue;
                }
                p->peer = all_peers->peers[i];
                address *a = &p->peer->addr;
                sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = a->ip, .sin_port = a->port};
                debug("X-Peer %s:%d\n", inet_ntoa((struct in_addr){.s_addr = a->ip}), ntohs(a->port));
                network *n = p->n;
                utp_socket *s = utp_create_socket(n->utp);
                p->peer->last_connect_attempt = time(NULL);
                int fd = utp_socket_connect_fd(n->evbase, s, (sockaddr*)&sin, sizeof(sin), NULL);
                evutil_make_socket_closeonexec(fd);
                evutil_make_socket_nonblocking(fd);
                bufferevent *bev = bufferevent_socket_new(n->evbase, fd, BEV_OPT_CLOSE_ON_FREE);
                char host[NI_MAXHOST];
                char serv[NI_MAXSERV];
                getnameinfo((sockaddr*)&sin, sizeof(sin), host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
                p->peer->evcon = evhttp_connection_base_bufferevent_new(n->evbase, n->evdns, bev, host, atoi(serv));
                proxy_submit_request_on_con(p, p->peer->evcon);
                break;
            }
            return;
        }
        for (size_t i = 0; i < lenof(pending_connections); i++) {
            if (pending_connections[i]) {
                continue;
            }
            peer_array *o[2] = {injectors, injector_proxies};
            if (random() & 1) {
                o[0] = injector_proxies;
                o[1] = injectors;
            }
            pending_connections[i] = start_peer_connection(p->n, o[0]);
            if (!pending_connections[i]) {
                pending_connections[i] = start_peer_connection(p->n, o[1]);
            }
        }
    }

    for (size_t i = 0; i < lenof(pending_connections); i++) {
        if (pending_connections[i]) {
            continue;
        }
        pending_connections[i] = start_peer_connection(p->n, all_peers);
        if (!pending_connections[i]) {
            break;
        }
    }

    network *n = p->n;
    fetch_url_swarm(p->n, evhttp_request_get_uri(p->server_req), ^(const byte *peers, uint num_peers) {
        if (peers) {
            add_addresses(&all_peers, peers, num_peers);
            for (size_t i = 0; i < lenof(pending_connections); i++) {
                if (pending_connections[i]) {
                    continue;
                }
                pending_connections[i] = start_peer_connection(n, all_peers);
                if (!pending_connections[i]) {
                    break;
                }
            }
        }
    });

    on_connect(&p->r, ^(peer *peer) {
        p->peer = peer;
        proxy_submit_request_on_con(p, p->peer->evcon);
    });
}

void server_error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p server_error_cb %d\n", p, error);
    p->server_req = NULL;
    p->dont_free = true;
    if (p->direct_req) {
        evhttp_cancel_request(p->direct_req);
        p->direct_req = NULL;
    }
    proxy_cancel_proxy(p);
    p->dont_free = false;
    proxy_request_cleanup(p);
}

void server_handle_request(struct evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    p->evhttp_handle_request(req, p->n->http);
}

void submit_request(network *n, evhttp_request *server_req)
{
    proxy_request *p = alloc(proxy_request);
    p->n = n;
    snprintf(p->cache_name, sizeof(p->cache_name), CACHE_NAME);
    p->cache_file = -1;
    p->server_req = server_req;
    p->evhttp_handle_request = p->server_req->cb;
    p->server_req->cb = server_handle_request;
    p->server_req->cb_arg = p;
    evhttp_request_set_error_cb(p->server_req, server_error_cb);

    evhttp_connection *evcon = evhttp_request_get_connection(server_req);

    // https://github.com/libevent/libevent/issues/510
    int fd = bufferevent_getfd(evhttp_connection_get_bufferevent(evcon));
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    getpeername(fd, (sockaddr *)&ss, &len);
    const char *xdht = evhttp_find_header(server_req->input_headers, "X-DHT");
    const char *xpeer = evhttp_find_header(server_req->input_headers, "X-Peer");
    if (!xdht && !xpeer && addr_is_localhost((sockaddr *)&ss, len)) {
        direct_submit_request(p);
    }
    proxy_submit_request(p);
}

typedef struct {
    network *n;
    pending_request r;
    peer *peer;
} trace_request;

void trace_error_cb(enum evhttp_request_error error, void *arg)
{
    trace_request *t = (trace_request*)arg;
    debug("t:%p trace_error_cb %d\n", t, error);
    if (error != EVREQ_HTTP_REQUEST_CANCEL && peer_is_injector(t->peer)) {
        injector_reachable = 0;
    }
    free(t);
}

void trace_request_done_cb(evhttp_request *req, void *arg)
{
    trace_request *t = (trace_request*)arg;
    debug("t:%p trace_request_done_cb req:%p\n", t, req);
    if (!req) {
        return;
    }
    if (!req->evcon) {
        // connection failed
        if (peer_is_injector(t->peer)) {
            injector_reachable = 0;
        }
    } else {
        t->peer->last_connect = time(NULL);
    }
    evbuffer *input = evhttp_request_get_input_buffer(req);
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
            debug("verifying sig for TRACE %s %s\n", evhttp_request_get_uri(req), sign);
            if (verify_signature(&content_state, sign)) {
                debug("signature good!\n");
                t->peer->last_verified = time(NULL);
                if (peer_is_injector(t->peer)) {
                    injector_reachable = time(NULL);
                    update_injector_proxy_swarm(t->n);
                }
                for (size_t i = 0; i < lenof(pending_connections); i++) {
                    if (!pending_connections[i]) {
                        pending_connections[i] = t->peer;
                        on_evcon(t->n, t->peer);
                        break;
                    }
                }
            }
        }
    }
    free(t);
}

void trace_submit_request_on_con(trace_request *t, evhttp_connection *evcon)
{
    evhttp_request *req = evhttp_request_new(trace_request_done_cb, t);
    overwrite_header(req, "Proxy-Connection", "Keep-Alive");
    evhttp_request_set_error_cb(req, trace_error_cb);
    char request_uri[256];
    snprintf(request_uri, sizeof(request_uri), "/%u%u%u",
             randombytes_random(), randombytes_random(), randombytes_random());
    evhttp_make_request(evcon, req, EVHTTP_REQ_TRACE, request_uri);
    debug("t:%p con:%p trace request submitted: %s\n", t, evhttp_request_get_connection(req), request_uri);
}

void submit_trace_request(network *n)
{
    trace_request *t = alloc(trace_request);
    t->n = n;
    on_connect(&t->r, ^(peer *peer) {
        t->peer = peer;
        trace_submit_request_on_con(t, t->peer->evcon);
    });
}

typedef struct {
    evhttp_request *server_req;
    evhttp_request *proxy;
    bufferevent *direct;
    pending_request r;
    peer *peer;
} connect_req;

void connect_cleanup(connect_req *c)
{
    if (c->direct || c->proxy) {
        return;
    }
    if (c->server_req) {
        evhttp_send_error(c->server_req, 504, "Gateway Timeout");
    }
    abort_connect(&c->r);
    free(c);
}

void connected(connect_req *c, bufferevent *other)
{
    debug("c:%p connected %p\n", c, other);
    evhttp_connection *evcon = evhttp_request_get_connection(c->server_req);
    if (!evcon) {
        // XXX: could remove this case by using the error_cb hack
        c->server_req = NULL;
        bufferevent_free(other);
        return;
    }
    bufferevent *bev = evhttp_connection_detach_bufferevent(evcon);
    c->server_req = NULL;
    connect_cleanup(c);
    evbuffer_add_printf(bufferevent_get_output(bev), "HTTP/1.0 200 Connection established\r\n\r\n");
    bev_splice(bev, other);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_enable(other, EV_READ|EV_WRITE);
}

int connect_header_cb(evhttp_request *req, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p connect_header_cb %d %s\n", c, req->response_code, req->response_code_line);
    if (req->response_code != 200) {
        return -1;
    }

    c->peer->last_connect = time(NULL);

    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }

    bufferevent *other = evhttp_connection_detach_bufferevent(evhttp_request_get_connection(req));
    connected(c, other);
    return -1;
}

void connect_error_cb(enum evhttp_request_error error, void *arg)
{
    connect_req *c = (connect_req *)arg;
    debug("c:%p connect_error_cb %d\n", c, error);
    c->proxy = NULL;
    connect_cleanup(c);
}

void connect_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("connect_event_cb events:%x bev:%p req:%s\n", events, bev, evhttp_request_get_uri(c->server_req));

    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        c->direct = NULL;
        connect_cleanup(c);
    } else if (events & BEV_EVENT_CONNECTED) {
        if (c->proxy) {
            evhttp_cancel_request(c->proxy);
            c->proxy = NULL;
        }
        c->direct = NULL;
        connected(c, bev);
    }
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
    c->server_req = req;

    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(c->direct, NULL, NULL, connect_event_cb, c);
    bufferevent_socket_connect_hostname(c->direct, n->evdns, AF_INET, host, port);
    evhttp_uri_free(uri);
    bufferevent_enable(c->direct, EV_READ);

    on_connect(&c->r, ^(peer *p) {
        c->peer = p;
        c->proxy = evhttp_request_new(NULL, c);
        evhttp_request_set_header_cb(c->proxy, connect_header_cb);
        evhttp_request_set_error_cb(c->proxy, connect_error_cb);
        evhttp_make_request(p->evcon, c->proxy, EVHTTP_REQ_CONNECT, evhttp_request_get_uri(c->server_req));
    });
}

int evhttp_parse_firstline_(struct evhttp_request *, struct evbuffer*);
int evhttp_parse_headers_(struct evhttp_request *, struct evbuffer*);

void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    debug("con:%p request received: %s\n", evhttp_request_get_connection(req), evhttp_request_get_uri(req));
    if (evhttp_request_get_command(req) == EVHTTP_REQ_CONNECT) {
        connect_request(n, req);
        return;
    }

    const char *xcache = evhttp_find_header(req->input_headers, "X-Cache");
    const char *xdht = evhttp_find_header(req->input_headers, "X-DHT");
    const char *xpeer = evhttp_find_header(req->input_headers, "X-Peer");
    if (xcache || (!xdht && !xpeer)) {
        char *uri = evhttp_encode_uri(evhttp_request_get_uri(req));
        char cache_path[2048];
        char cache_headers_path[2048];
        snprintf(cache_path, sizeof(cache_path), "%s%s", CACHE_PATH, uri);
        snprintf(cache_headers_path, sizeof(cache_headers_path), "%s.headers", cache_path);
        free(uri);
        int cache_file = open(cache_path, O_RDONLY);
        int headers_file = open(cache_headers_path, O_RDONLY);
        debug("check hit:%d,%d cache:%s\n", cache_file != -1, headers_file != -1, cache_path);
        if (cache_file != -1 && headers_file != -1) {
            evhttp_request *temp = evhttp_request_new(NULL, NULL);
            evbuffer *header_buf = evbuffer_new();
            off_t length = lseek(headers_file, 0, SEEK_END);
            evbuffer_add_file(header_buf, headers_file, 0, length);
            evhttp_parse_firstline_(temp, header_buf);
            evhttp_parse_headers_(temp, header_buf);
            copy_response_headers(temp, req);
            evbuffer_free(header_buf);

            evbuffer *content = evbuffer_new();
            length = lseek(cache_file, 0, SEEK_END);
            evbuffer_add_file(content, cache_file, 0, length);
            debug("responding with %d %s %u\n", temp->response_code, temp->response_code_line, length);
            evhttp_send_reply(req, temp->response_code, temp->response_code_line, content);
            evhttp_request_free(temp);
            evbuffer_free(content);
            return;
        }
        close(cache_file);
        close(headers_file);
    }
    if (xcache) {
        evhttp_send_error(req, 404, "Not in cache");
        return;
    }

    submit_request(n, req);
}

network* client_init(port_t port)
{
    o_debug = 0;

    injectors = alloc(peer_array);
    injector_proxies = alloc(peer_array);
    all_peers = alloc(peer_array);
    TAILQ_INIT(&pending_requests);

    network *n = network_setup("0.0.0.0", port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    evhttp_set_allowed_methods(n->http, EVHTTP_REQ_GET | EVHTTP_REQ_CONNECT | EVHTTP_REQ_TRACE);
    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "0.0.0.0", port);
    printf("listening on TCP:%s:%d\n", "0.0.0.0", port);

    timer_callback cb = ^{
        dht_get_peers(n->dht, injector_swarm, ^(const byte *peers, uint num_peers) {
            if (peers) {
                add_addresses(&injectors, peers, num_peers);
            }
        });
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

int main(int argc, char *argv[])
{
    char *port_s = "8006";

    for (;;) {
        int c = getopt(argc, argv, "p:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            port_s = optarg;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    network *n = client_init(atoi(port_s));
    return client_run(n);
}
