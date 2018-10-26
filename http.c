#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/keyvalq_struct.h>

#include "log.h"
#include "sha1.h"
#include "utp.h"
#include "base64.h"
#include "timer.h"
#include "network.h"
#include "constants.h"
#include "hash_table.h"
#include "utp_bufferevent.h"
#include "http.h"


evhttp_connection *connections[10];

void join_url_swarm(network *n, const char *url)
{
    __block struct {
        uint8_t url_hash[20];
    } hash_state;
    SHA1(hash_state.url_hash, (const unsigned char *)url, strlen(url));

    // TODO: stop after 24hr
    timer_callback cb = ^{
        dht_announce(n->dht, hash_state.url_hash);
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);
}

void fetch_url_swarm(network *n, const char *url)
{
    uint8_t url_hash[20];
    SHA1(url_hash, (const unsigned char *)url, strlen(url));
    dht_get_peers(n->dht, url_hash);
}

const char *evhttp_method(evhttp_cmd_type type)
{
    switch (type) {
    case EVHTTP_REQ_GET: return "GET";
    case EVHTTP_REQ_POST: return "POST";
    case EVHTTP_REQ_HEAD: return "HEAD";
    case EVHTTP_REQ_PUT: return "PUT";
    case EVHTTP_REQ_DELETE: return "DELETE";
    case EVHTTP_REQ_OPTIONS: return "OPTIONS";
    case EVHTTP_REQ_TRACE: return "TRACE";
    case EVHTTP_REQ_CONNECT: return "CONNECT";
    case EVHTTP_REQ_PATCH: return "PATCH";
    }
    return NULL;
}

int get_port_for_scheme(const char *scheme)
{
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *res;
    int error = getaddrinfo(NULL, scheme, &hints, &res);
    if (error) {
        fprintf(stderr, "getaddrinfo failed %s\n", gai_strerror(error));
        return -1;
    }
    int port = -1;
    for (addrinfo *r = res; r; r = r->ai_next) {
        char portstr[NI_MAXSERV];
        error = getnameinfo(r->ai_addr, r->ai_addrlen, NULL, 0, portstr, sizeof(portstr), NI_NUMERICSERV);
        if (error) {
            fprintf(stderr, "getnameinfo failed %s\n", gai_strerror(error));
            continue;
        }
        port = atoi(portstr);
        if (port != -1) {
            break;
        }
    }
    freeaddrinfo(res);
    return port;
}

void overwrite_kv_header(evkeyvalq *out, const char *key, const char *value)
{
    while (evhttp_find_header(out, key)) {
        evhttp_remove_header(out, key);
    }
    evhttp_add_header(out, key, value);
}

void overwrite_header(evhttp_request *to, const char *key, const char *value)
{
    overwrite_kv_header(to->output_headers, key, value);
}

void copy_header(evhttp_request *from, evhttp_request *to, const char *key)
{
    const char *value = evhttp_find_header(from->input_headers, key);
    if (value) {
        overwrite_header(to, key, value);
    }
}

void copy_all_headers(evhttp_request *from, evhttp_request *to)
{
    evkeyvalq *in = from->input_headers;
    evkeyval *header;
    TAILQ_FOREACH(header, in, next) {
        overwrite_header(to, header->key, header->value);
    }
}

void hash_headers(evkeyvalq *in, crypto_generichash_state *content_state)
{
    const char *headers[] = hashed_headers;
    for (size_t i = 0; i < lenof(headers); i++) {
        const char *key = headers[i];
        const char *value = evhttp_find_header(in, key);
        if (!value) {
            continue;
        }
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s: %s\r\n", key, value);
        crypto_generichash_update(content_state, (const uint8_t *)buf, strlen(buf));
    }
}

void hash_request(evhttp_request *req, evkeyvalq *hdrs, crypto_generichash_state *content_state)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%d\r\n", req->response_code);
    crypto_generichash_update(content_state, (const uint8_t *)buf, strlen(buf));
    hash_headers(hdrs, content_state);
}

void merkle_tree_hash_request(merkle_tree *m, evhttp_request *req, evkeyvalq *hdrs)
{
    char code_buf[16];
    snprintf(code_buf, sizeof(code_buf), "%d\r\n", req->response_code);
    printf("merkle_tree_hash_request: %lu '%s'\n", strlen(code_buf), code_buf);
    assert(req->response_code);
    merkle_tree_add_hashed_data(m, (const uint8_t *)code_buf, strlen(code_buf));
    const char *headers[] = hashed_headers;
    for (size_t i = 0; i < lenof(headers); i++) {
        const char *key = headers[i];
        const char *value = evhttp_find_header(hdrs, key);
        if (!value) {
            continue;
        }
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s: %s\r\n", key, value);
        merkle_tree_add_hashed_data(m, (const uint8_t *)buf, strlen(buf));
    }
}

evhttp_connection *make_connection(network *n, const evhttp_uri *uri)
{
    const char *scheme = evhttp_uri_get_scheme(uri);
    const char *host = evhttp_uri_get_host(uri);
    if (!host) {
        return NULL;
    }
    int port = evhttp_uri_get_port(uri);
    if (port == -1) {
        port = get_port_for_scheme(scheme);
    }
    for (size_t i = 0; i < lenof(connections); i++) {
        evhttp_connection *evcon = connections[i];
        if (evcon) {
            char *e_host;
            ev_uint16_t e_port;
            evhttp_connection_get_peer(evcon, &e_host, &e_port);
            if (port == e_port && strcasecmp(host, e_host) == 0) {
                connections[i] = NULL;
                evhttp_connection_set_closecb(evcon, NULL, NULL);
                debug("re-using %s:%d evcon:%p\n", e_host, e_port, evcon);
                return evcon;
            }
        }
    }
    debug("connecting to %s:%d\n", host, port);
    // XXX: doesn't handle SSL
    evhttp_connection *evcon = evhttp_connection_base_new(n->evbase, n->evdns, host, port);
    // XXX: disable IPv6, since evdns waits for *both* and the v6 request often times out
    evhttp_connection_set_family(evcon, AF_INET);
    return evcon;
}

void evcon_close_cb(evhttp_connection *evcon, void *ctx)
{
    for (size_t i = 0; i < lenof(connections); i++) {
        if (connections[i] == evcon) {
            connections[i] = NULL;
            break;
        }
    }
    evhttp_connection_free_on_completion(evcon);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
}

void return_connection(evhttp_connection *evcon)
{
    for (size_t i = 0; i < lenof(connections); i++) {
        if (!connections[i]) {
            connections[i] = evcon;
            evhttp_connection_set_closecb(evcon, evcon_close_cb, NULL);
            return;
        }
    }
    evhttp_connection_free(evcon);
}

uint64 utp_on_accept(utp_callback_arguments *a)
{
    network *n = (network*)utp_context_get_userdata(a->context);
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (utp_getpeername(a->socket, (sockaddr *)&addr, &addrlen) == -1) {
        debug("utp_getpeername failed\n");
    }
    /*
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    getnameinfo((sockaddr *)&addr, addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    debug("utp_on_accept %p %s:%s\n", a->socket, host, serv);
    */
    add_sockaddr(n, (sockaddr *)&addr, addrlen);
    int fd = utp_socket_create_fd(n->evbase, a->socket);
    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);
    evhttp_get_request(n->http, fd, (sockaddr *)&addr, addrlen);
    return 0;
}
