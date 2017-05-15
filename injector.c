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
#include "base64.h"
#include "timer.h"
#include "network.h"
#include "constants.h"
#include "hash_table.h"
#include "utp_bufferevent.h"


typedef struct evbuffer evbuffer;
typedef struct evkeyvalq evkeyvalq;
typedef struct evhttp_uri evhttp_uri;
typedef struct bufferevent bufferevent;
typedef struct evhttp_request evhttp_request;
typedef struct evhttp_connection evhttp_connection;

hash_table *url_table;
unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

#define SIG_MSG_LENGTH (sizeof("sign") + sizeof("2011-10-08T07:07:09Z") + crypto_generichash_BYTES)
#define SIG_LENGTH (crypto_sign_BYTES + SIG_MSG_LENGTH)


void inject_url(network *n, const char *url, const uint8_t *sig)
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

void overwrite_header(struct evhttp_request *to, const char *key, const char *value)
{
    evkeyvalq *out = evhttp_request_get_output_headers(to);
    while (evhttp_find_header(out, key)) {
        evhttp_remove_header(out, key);
    }
    evhttp_add_header(out, key, value);
}

void copy_header(struct evhttp_request *from, struct evhttp_request *to, const char *key)
{
    evkeyvalq *in = evhttp_request_get_input_headers(from);
    const char *value = evhttp_find_header(in, key);
    if (value) {
        overwrite_header(to, key, value);
    }
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
            const evhttp_uri *new_uri = evhttp_uri_parse(new_location);
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

    if (!evhttp_request_get_connection(p->server_req)) {
        return 0;
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);

    const char *response_header_whitelist[] = {"Content-Length", "Content-Type"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(req, p->server_req, response_header_whitelist[i]);
    }
    overwrite_header(p->server_req, "Content-Location", evhttp_request_get_uri(req));

    const char *hashed_headers[] = {"Content-Length", "Content-Location", "Content-Type"};
    evkeyvalq *in = evhttp_request_get_input_headers(req);
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        const char *key = hashed_headers[i];
        const char *value = evhttp_find_header(in, key);
        if (!value) {
            continue;
        }
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s: %s\r\n", key, value);
        crypto_generichash_update(&p->content_state, (const uint8_t *)buf, strlen(buf));
    }

    evhttp_send_reply_start(p->server_req, code, evhttp_request_get_response_code_line(req));
    evhttp_request_set_chunked_cb(req, chunked_cb);

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
            uint8_t *content_hash_p = content_hash;
            crypto_generichash_final(&p->content_state, content_hash, sizeof(content_hash));

            const char *uri = evhttp_request_get_uri(p->server_req);
            uint8_t *sig = hash_get_or_insert(url_table, uri, ^{

                debug("storing sig for %s\n", uri);

                // duplicate the memory because the hash_table owns it now
                p->server_req->uri = strdup(uri);

                // base64(sign("sign" + timestamp + hash(headers + content)))
                time_t now = time(NULL);
                char ts[sizeof("2011-10-08T07:07:09Z")];
                strftime(ts, sizeof(ts), "%FT%TZ", gmtime(&now));
                assert(sizeof(ts) - 1 == strlen(ts));

                uint8_t message[SIG_MSG_LENGTH];
                uint8_t *w = message;
                memcpy(w, "sign", sizeof("sign") - 1);
                w += sizeof("sign");
                memcpy(w, ts, sizeof(ts) - 1);
                w += sizeof(ts);
                memcpy(w, content_hash_p, crypto_generichash_BYTES);
                w += crypto_generichash_BYTES;
                assert(w == message + sizeof(message));

                uint8_t *signed_message = malloc(SIG_LENGTH);
                unsigned long long signed_message_len;

                crypto_sign(signed_message, &signed_message_len, message, sizeof(message), sk);
                assert(signed_message_len == SIG_LENGTH);

                return (void*)signed_message;
            });
            inject_url(p->n, uri, sig);
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

    const char *uri_s = evhttp_request_get_uri(p->server_req);
    const uint8_t *sig = hash_get(url_table, uri_s);
    if (sig) {
        size_t out_len;
        char *hex_sig = base64_urlsafe_encode(sig, SIG_LENGTH, &out_len);
        debug("returning sig for %s %s\n", uri_s, hex_sig);
        overwrite_header(p->server_req, "X-Sign", hex_sig);
        free(hex_sig);
    }

    evhttp_request_set_header_cb(client_req, header_cb);
    evhttp_request_set_error_cb(client_req, error_cb);

    char request_uri[2048];
    const char *q = evhttp_uri_get_query(uri);
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", evhttp_uri_get_path(uri), q?"?":"", q?q:"");
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
    fprintf(stderr, "    -h          Help\n");
    fprintf(stderr, "    -p <port>   Local port\n");
    fprintf(stderr, "    -s <IP>     Source IP\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port = NULL;

    for (;;) {
        int c = getopt(argc, argv, "hp:s:n");
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
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    if (!port) {
        usage(argv[0]);
    }

    crypto_sign_keypair(pk, sk);

    network *n = network_setup(address, port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    url_table = hash_table_create();

    timer_callback cb = ^{
        dht_announce(n->dht, injector_swarm, ^(const byte *peers, uint num_peers) {
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
