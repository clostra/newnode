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


void join_url_swarm(network *n, const char *url)
{
    __block struct {
        uint8_t url_hash[20];
    } hash_state;
    SHA1(hash_state.url_hash, (const unsigned char *)url, strlen(url));

    // TODO: stop after 24hr
    timer_callback cb = ^{
        dht_announce(n->dht, hash_state.url_hash, ^(const byte *peers, uint num_peers) {
            if (!peers) {
                printf("announce complete\n");
            }
        });
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);
}

int get_port_for_scheme(const char *scheme)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res;
    int error = getaddrinfo(NULL, scheme, &hints, &res);
    if (error) {
        fprintf(stderr, "getaddrinfo failed %s\n", gai_strerror(error));
        return -1;
    }
    int port = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
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

void overwrite_header(evhttp_request *to, const char *key, const char *value)
{
    evkeyvalq *out = evhttp_request_get_output_headers(to);
    while (evhttp_find_header(out, key)) {
        evhttp_remove_header(out, key);
    }
    evhttp_add_header(out, key, value);
}

void copy_header(evhttp_request *from, evhttp_request *to, const char *key)
{
    evkeyvalq *in = evhttp_request_get_input_headers(from);
    const char *value = evhttp_find_header(in, key);
    if (value) {
        overwrite_header(to, key, value);
    }
}

void copy_all_headers(evhttp_request *from, evhttp_request *to)
{
    evkeyvalq *in = evhttp_request_get_input_headers(from);
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
    debug("connecting to %s %d\n", host, port);
    // XXX: doesn't handle SSL
    evhttp_connection *evcon = evhttp_connection_base_new(n->evbase, n->evdns, host, port);
    // XXX: disable IPv6, since evdns waits for *both* and the v6 request often times out
    evhttp_connection_set_family(evcon, AF_INET);
    return evcon;
}

uint64 utp_on_accept(utp_callback_arguments *a)
{
    debug("Accepted inbound socket %p\n", a->socket);
    network *n = (network*)utp_context_get_userdata(a->context);
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (utp_getpeername(a->socket, (sockaddr *)&addr, &addrlen) == -1) {
        debug("utp_getpeername failed\n");
    }
    int fd = utp_socket_create_fd(n->evbase, a->socket);
    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);
    evhttp_get_request(n->http, fd, (sockaddr *)&addr, addrlen);
    return 0;
}