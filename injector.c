#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include <sodium.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "sha1.h"
#include "utp.h"
#include "timer.h"
#include "network.h"
#include "utp_bufferevent.h"
#include "http_util.h"


typedef struct evbuffer evbuffer;
typedef struct evkeyvalq evkeyvalq;
typedef struct evhttp_uri evhttp_uri;
typedef struct bufferevent bufferevent;
typedef struct evhttp_request evhttp_request;
typedef struct evhttp_connection evhttp_connection;

void inject_url(network *n, const char *url, const uint8_t *content_hash)
{
    // TODO
    /*
    dht_put(n->dht, g_public_key, g_secret_key, value_str, 0, ^{
        printf("put complete\n");
    });
    */

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

typedef struct {
    network *n;
    evhttp_request *server_req;
    crypto_generichash_state content_state;
} proxy_request;

void chunked_cb(struct evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = evhttp_request_get_input_buffer(req);
    //debug("p:%p chunked_cb length:%zu\n", p, evbuffer_get_length(input));

    struct evbuffer_ptr ptr;
    struct evbuffer_iovec v;
    evbuffer_ptr_set(input, &ptr, 0, EVBUFFER_PTR_SET);
    while (evbuffer_peek(input, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(&p->content_state, v.iov_base, v.iov_len);
        if (evbuffer_ptr_set(input, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }

    if (evhttp_request_get_connection(p->server_req)) {
        evhttp_send_reply_chunk(p->server_req, input);
    }
}

void submit_request(network *n, evhttp_request *server_req, evhttp_connection *evcon, const evhttp_uri *uri);
evhttp_connection *make_connection(network *n, const evhttp_uri *uri);

int header_cb(struct evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p header_cb %d %s\n", p, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));

    int code = evhttp_request_get_response_code(req);
    switch(evhttp_request_get_response_code(req)) {
    case HTTP_MOVEPERM:
    case HTTP_MOVETEMP: {
        const char *new_location = evhttp_find_header(evhttp_request_get_input_headers(req), "Location");
        if (new_location) {
            evhttp_uri *new_uri = evhttp_uri_parse(new_location);
            if (new_uri) {
                debug("redirect to %s\n", new_location);
                const char *scheme = evhttp_uri_get_scheme(new_uri);
                evhttp_connection *evcon = evhttp_request_get_connection(req);
                if (scheme) {
                    // XXX: make a new connection for absolute uris. we could reuse the existing one in some cases
                    evcon = make_connection(p->n, new_uri);
                }
                submit_request(p->n, p->server_req, evcon, new_uri);
                // we made a new proxy_request, so disconnect the original request
                p->server_req = NULL;
                evhttp_uri_free(new_uri);
            }
        }
        return 0;
    }
    case HTTP_OK:
    case HTTP_NOCONTENT:
        break;
    default:
        // XXX: if the code is not HTTP_OK or HTTP_NOCONTENT, we probably don't want to hash and store the value
        break;
    }

    const char *response_header_whitelist[] = {"Content-Length", "Content-Type"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(req, p->server_req, response_header_whitelist[i]);
    }
    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    if (evhttp_request_get_connection(p->server_req)) {
        evhttp_send_reply_start(p->server_req, code, evhttp_request_get_response_code_line(req));
        evhttp_request_set_chunked_cb(req, chunked_cb);
    }

    return 0;
}

void error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    fprintf(stderr, "p:%p error_cb %d\n", p, error);
}

void request_done_cb(struct evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p request_done_cb\n", p);
    if (p->server_req) {
        if (req) {
            debug("p:%p server_request_done_cb: %s\n", p, evhttp_request_get_uri(req));
            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&p->content_state, content_hash, sizeof(content_hash));

            inject_url(p->n, evhttp_request_get_uri(p->server_req), content_hash);
        }
        if (evhttp_request_get_connection(p->server_req)) {
            evhttp_send_reply_end(p->server_req);
        }
        p->server_req = NULL;
    }

    free(p);
}

void submit_request(network *n, evhttp_request *server_req, evhttp_connection *evcon, const evhttp_uri *uri)
{
    proxy_request *p = alloc(proxy_request);
    p->n = n;
    p->server_req = server_req;
    evhttp_request *client_req = evhttp_request_new(request_done_cb, p);
    const char *request_header_whitelist[] = {"Referer"};
    for (size_t i = 0; i < lenof(request_header_whitelist); i++) {
        copy_header(p->server_req, client_req, request_header_whitelist[i]);
    }

    char *address;
    ev_uint16_t port;
    evhttp_connection_get_peer(evcon, &address, &port);
    overwrite_header(client_req, "Host", address);

    evhttp_request_set_header_cb(client_req, header_cb);
    evhttp_request_set_error_cb(client_req, error_cb);

    char request_uri[2048];
    const char *q = evhttp_uri_get_query(uri);
    const char *path = evhttp_uri_get_path(uri);
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", (!path || path[0] == '\0') ? "/" : path, q?"?":"", q?q:"");
    evhttp_make_request(evcon, client_req, EVHTTP_REQ_GET, request_uri);
    debug("p:%p con:%p request submitted: %s\n", p, evhttp_request_get_connection(client_req), evhttp_request_get_uri(client_req));
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
    evhttp_connection *evcon = evhttp_connection_base_new(n->evbase, n->evdns, host, port);
    // XXX: disable IPv6, since evdns waits for *both* and the v6 request often times out
    evhttp_connection_set_family(evcon, AF_INET);
    return evcon;
}

void http_request_cb(struct evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    debug("con:%p request received: %s\n", evhttp_request_get_connection(req), evhttp_request_get_uri(req));
    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    evhttp_connection *evcon = make_connection(n, uri);
    if (!evcon) {
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }
    submit_request(n, req, evcon, uri);
}

uint64 utp_on_accept(utp_callback_arguments *a)
{
    debug("Accepted inbound socket %p\n", a->socket);
    network *n = (network*)utp_context_get_userdata(a->context);
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(8005)
    };
    utp_connect_tcp(n->evbase, a->socket, (const struct sockaddr *)&dest, sizeof(dest));
    return 0;
}

void usage(char *name)
{
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr, "    %s [options] -p <listening-port>\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -h              Help\n");
    fprintf(stderr, "    -p <port>       Local port\n");
    fprintf(stderr, "    -s <IP>         Source IP\n");
    fprintf(stderr, "    -d              Print debug output\n");
    fprintf(stderr, "    -a <swarm-salt> Use <swarm-salt> to calculate swarm locations.\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port = NULL;
    const char* swarm_salt = "";

    for (;;) {
        int c = getopt(argc, argv, "hp:s:nda:");
        if (c == -1)
            break;
        switch (c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'p':
            port = optarg;
            break;
        case 's':
            address = optarg;
            break;
        case 'd':
            o_debug++;
            break;
        case 'a':
            swarm_salt = optarg;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    if (!port) {
        usage(argv[0]);
    }

    config *conf = config_new(swarm_salt);
    network *n = network_setup(address, conf, port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    timer_callback cb = ^{
        dht_announce(n->dht, injector_swarm(n->conf), ^(const byte *peers, uint num_peers) {
            if (!peers) {
                printf("announce complete\n");
            }
        });
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);

    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "0.0.0.0", 8005);

    return network_loop(n);
}
