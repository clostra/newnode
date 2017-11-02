#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/queue.h>

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
#include "bev_splice.h"
#include "hash_table.h"
#include "utp_bufferevent.h"
#include "http.h"


typedef struct {
    network *n;
    evhttp_request *server_req;
    crypto_generichash_state content_state;
} proxy_request;

hash_table *url_table;
unsigned char pk[crypto_sign_PUBLICKEYBYTES] = injector_pk;
#ifdef injector_sk
unsigned char sk[crypto_sign_SECRETKEYBYTES] = injector_sk;
#else
unsigned char sk[crypto_sign_SECRETKEYBYTES];
#endif


void submit_request(network *n, evhttp_request *server_req, evhttp_connection *evcon, const evhttp_uri *uri);

void content_sign(content_sig *sig, const uint8_t *content_hash)
{
    // base64(sign("sign" + timestamp + hash(headers + content)))
    time_t now = time(NULL);
    char ts[sizeof("2011-10-08T07:07:09Z")];
    strftime(ts, sizeof(ts), "%FT%TZ", gmtime(&now));
    assert(sizeof(ts) - 1 == strlen(ts));

    memcpy(sig->sign, "sign", sizeof(sig->sign));
    memcpy(sig->timestamp, ts, sizeof(sig->timestamp));
    memcpy(sig->content_hash, content_hash, sizeof(sig->content_hash));
    crypto_sign_detached(sig->signature, NULL, (uint8_t*)sig->sign, sizeof(content_sig) - sizeof(sig->signature), sk);
}

void request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p request_done_cb %p\n", p, req);
    if (!req) {
        return;
    }
    if (p->server_req) {
        debug("p:%p server_request_done_cb: %s\n", p, evhttp_request_get_uri(p->server_req));

        const char *uri = evhttp_request_get_uri(p->server_req);
        content_sig *s = hash_get_or_insert(url_table, uri, ^{

            debug("storing sig for %s\n", uri);

            // duplicate the memory because the hash_table owns it now
            p->server_req->uri = strdup(uri);

            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&p->content_state, content_hash, sizeof(content_hash));
            content_sig *sig = alloc(content_sig);
            content_sign(sig, content_hash);

            return (void*)sig;
        });
        evhttp_send_reply_end(p->server_req);
        p->server_req = NULL;
    }

    free(p);
}

void chunked_cb(evhttp_request *req, void *arg)
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

int header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p header_cb %d %s\n", p, evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));

    int klass = evhttp_request_get_response_code(req) / 100 - 1;
    switch (klass) {
    case 3: {
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
    case 2:
        break;
    default:
        // XXX: if the code is an error, we probably don't want to hash and store the value
        return -1;
    }

    const char *response_header_whitelist[] = {"Content-Length", "Content-Type"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(req, p->server_req, response_header_whitelist[i]);
    }
    overwrite_header(p->server_req, "Content-Location", evhttp_request_get_uri(p->server_req));

    if (evhttp_request_get_command(p->server_req) == EVHTTP_REQ_HEAD) {
        evhttp_send_reply(p->server_req, 200, "OK", evbuffer_new());
        p->server_req = NULL;
        return 0;
    }

    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(evhttp_request_get_output_headers(p->server_req), &p->content_state);

    if (evhttp_request_get_connection(p->server_req)) {
        evhttp_send_reply_start(p->server_req, code, evhttp_request_get_response_code_line(req));
    }
    evhttp_request_set_chunked_cb(req, chunked_cb);

    return 0;
}

void error_cb(enum evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p error_cb %d\n", p, error);
    if (p->server_req) {
        evhttp_send_error(p->server_req, 502, "Bad Gateway");
        p->server_req = NULL;
    }
    free(p);
}

void conn_close_cb(evhttp_connection *evcon, void *ctx)
{
    debug("conn_close_cb\n");
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

    // TODO: range requests / partial content handling
    evhttp_remove_header(evhttp_request_get_output_headers(client_req), "Range");
    evhttp_remove_header(evhttp_request_get_output_headers(client_req), "If-Range");

    overwrite_header(client_req, "User-Agent", "dcdn/0.1");

    evhttp_request_set_header_cb(client_req, header_cb);
    evhttp_request_set_error_cb(client_req, error_cb);

    evhttp_connection_set_closecb(evcon, conn_close_cb, NULL);

    char request_uri[2048];
    const char *q = evhttp_uri_get_query(uri);
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", evhttp_uri_get_path(uri), q?"?":"", q?q:"");
    evhttp_make_request(evcon, client_req, evhttp_request_get_command(p->server_req), request_uri);
    debug("p:%p con:%p request submitted: %s\n", p, evhttp_request_get_connection(client_req), evhttp_request_get_uri(client_req));
}

typedef struct {
    evhttp_request *server_req;
    bufferevent *direct;
} connect_req;

void connect_cleanup(connect_req *c)
{
    if (c->direct) {
        return;
    }
    if (c->server_req) {
        evhttp_send_error(c->server_req, 502, "Bad Gateway");
    }
    free(c);
}

void connected(connect_req *c, bufferevent *other)
{
    bufferevent *bev = evhttp_connection_detach_bufferevent(evhttp_request_get_connection(c->server_req));
    c->server_req = NULL;
    connect_cleanup(c);
    evbuffer_add_printf(bufferevent_get_output(bev), "HTTP/1.0 200 Connection established\r\n\r\n");
    bev_splice(bev, other);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
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
        c->direct = NULL;
        connected(c, bev);
    }
}

void close_cb(evhttp_connection *evcon, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p close_cb\n", c);
    c->server_req = NULL;
    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }
    connect_cleanup(c);
}

void connect_request(network *n, evhttp_request *req)
{
    char buf[2048];
    snprintf(buf, sizeof(buf), "https://%s", evhttp_request_get_uri(req));
    evhttp_uri *uri = evhttp_uri_parse(buf);
    const char *host = evhttp_uri_get_host(uri);
    if (!host) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }
    int port = evhttp_uri_get_port(uri);
    if (port == -1) {
        port = 443;
    } else if (port != 443) {
        evhttp_uri_free(uri);
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }

    connect_req *c = alloc(connect_req);
    c->server_req = req;

    evhttp_connection_set_closecb(evhttp_request_get_connection(req), close_cb, c);

    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(c->direct, NULL, NULL, connect_event_cb, c);
    bufferevent_socket_connect_hostname(c->direct, n->evdns, AF_INET, host, port);
    evhttp_uri_free(uri);
    bufferevent_enable(c->direct, EV_READ);
}

void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    debug("con:%p request received: %s\n", evhttp_request_get_connection(req), evhttp_request_get_uri(req));

    if (evhttp_request_get_command(req) == EVHTTP_REQ_CONNECT) {
        connect_request(n, req);
        return;
    }

    const char *connection = evhttp_find_header(evhttp_request_get_input_headers(req), "Proxy-Connection");
    if (connection && strcasecmp(connection, "keep-alive") == 0) {
        overwrite_header(req, "Proxy-Connection", "Keep-Alive");
    }

    if (evhttp_request_get_command(req) == EVHTTP_REQ_TRACE) {
        evbuffer *output = evbuffer_new();
        evbuffer_add_printf(output, "TRACE %s HTTP/%d.%d\r\n", req->uri, req->major, req->minor);
        evkeyval *header;
        TAILQ_FOREACH(header, evhttp_request_get_input_headers(req), next) {
            evbuffer_add_printf(output, "%s: %s\r\n", header->key, header->value);
        }
        evbuffer_add(output, "\r\n", 2);
        char size[22];
        snprintf(size, sizeof(size), "%zu", evbuffer_get_length(output));
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", size);
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "message/http");
        crypto_generichash_state content_state;
        crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);
        hash_headers(evhttp_request_get_output_headers(req), &content_state);
        unsigned char *out_body = evbuffer_pullup(output, evbuffer_get_length(output));
        crypto_generichash_update(&content_state, out_body, evbuffer_get_length(output));
        uint8_t content_hash[crypto_generichash_BYTES];
        crypto_generichash_final(&content_state, content_hash, sizeof(content_hash));
        content_sig sig;
        content_sign(&sig, content_hash);
        size_t out_len;
        char *hex_sig = base64_urlsafe_encode((uint8_t*)&sig, sizeof(content_sig), &out_len);
        debug("returning sig for TRACE %s %s\n", req->uri, hex_sig);
        evhttp_add_header(evhttp_request_get_output_headers(req), "X-Sign", hex_sig);
        free(hex_sig);

        evhttp_send_reply(req, 200, "OK", output);
        return;
    }

    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    evhttp_connection *evcon = make_connection(n, uri);
    if (!evcon) {
        evhttp_send_error(req, 502, "Bad Gateway");
        return;
    }

    const char *uri_s = evhttp_request_get_uri(req);
    const content_sig *sig = hash_get(url_table, uri_s);
    if (sig) {
        size_t out_len;
        char *hex_sig = base64_urlsafe_encode((uint8_t*)sig, sizeof(content_sig), &out_len);
        debug("returning sig for %s %s\n", uri_s, hex_sig);
        overwrite_header(req, "X-Sign", hex_sig);
        free(hex_sig);
        // XXX: if we had Content-Length, Content-Type and Content-Location, we could respond to HEAD right here
        //copy_headers(old_get, req);
        //evhttp_send_reply(req, 200, "OK", evbuffer_new());
        //return;
    }

    submit_request(n, req, evcon, uri);
}

void usage(char *name)
{
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr, "    %s [options] -p <listening-port>\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -s <IP>     Source IP\n");
    fprintf(stderr, "\n");
    exit(1);
}



int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port_s = NULL;

    o_debug = 1;

    for (;;) {
        int c = getopt(argc, argv, "p:s:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            port_s = optarg;
            break;
        case 's':
            address = optarg;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    if (!port_s) {
        usage(argv[0]);
    }

#ifndef injector_sk
    FILE *f = fopen("injector_sk", "rb");
    if (!f) {
        die("no injector_sk\n");
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize != sizeof(sk)) {
        die("wrong size injector_sk\n");
    }
    fseek(f, 0, SEEK_SET);
    fread(sk, fsize, 1, f);
    fclose(f);
#endif

    url_table = hash_table_create();

    port_t port = atoi(port_s);
    network *n = network_setup(address, port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    timer_callback cb = ^{
        dht_announce(n->dht, injector_swarm, ^(const byte *peers, uint num_peers) {
            if (!peers) {
                printf("announce complete\n");
            }
        });
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);

    evhttp_set_allowed_methods(n->http, EVHTTP_REQ_GET | EVHTTP_REQ_HEAD | EVHTTP_REQ_CONNECT | EVHTTP_REQ_TRACE);
    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "0.0.0.0", port);

    return network_loop(n);
}
