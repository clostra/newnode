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

#include "dht/dht.h"

#include "log.h"
#include "sha1.h"
#include "utp.h"
#include "base64.h"
#include "timer.h"
#include "network.h"
#include "constants.h"
#include "bev_splice.h"
#include "merkle_tree.h"
#include "utp_bufferevent.h"
#include "http.h"


typedef struct {
    network *n;
    evhttp_request *server_req;
    evbuffer *pending_output;
    evhttp_connection *evcon;

    // XXX: remove after no X-Sign clients exist
    crypto_generichash_state content_state;

    merkle_tree *m;
} proxy_request;

unsigned char pk[crypto_sign_PUBLICKEYBYTES] = injector_pk;
#ifdef injector_sk
unsigned char sk[crypto_sign_SECRETKEYBYTES] = injector_sk;
#else
unsigned char sk[crypto_sign_SECRETKEYBYTES];
#endif


void dht_event_callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len)
{
    debug("dht_event_callback event:%d data_len:%zu ", event, data_len);
    for (uint i = 0; i < 20; i++) {
        debug("%02X", info_hash[i]);
    }
    debug("\n");
}

void add_sockaddr(network *n, const sockaddr *addr, socklen_t addrlen)
{
    dht_ping_node(addr, addrlen);
}

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

void request_cleanup(proxy_request *p)
{
    if (p->evcon) {
        evhttp_connection_free(p->evcon);
        p->evcon = NULL;
    }
    if (p->pending_output) {
        evbuffer_free(p->pending_output);
    }
    merkle_tree_free(p->m);
    free(p);
}

void request_done_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p request_done_cb %p\n", p, req);
    if (!req) {
        return;
    }
    if (req->response_code != 0 && p->server_req) {
        debug("p:%p server_request_done_cb: %s\n", p, evhttp_request_get_uri(p->server_req));

        const char *uri = evhttp_request_get_uri(p->server_req);

        // XXX: remove after no X-Sign clients exist
        uint8_t content_hash[crypto_generichash_BYTES];
        char *b64_sign = NULL;
        {
            crypto_generichash_final(&p->content_state, content_hash, sizeof(content_hash));
            content_sig sig;
            content_sign(&sig, content_hash);
            size_t out_len;
            b64_sign = base64_urlsafe_encode((uint8_t*)&sig, sizeof(sig), &out_len);
            debug("returning X-Sign for %s %s\n", uri, b64_sign);
        }

        uint8_t root_hash[crypto_generichash_BYTES];
        merkle_tree_get_root(p->m, root_hash);
        content_sig sig;
        content_sign(&sig, root_hash);
        size_t out_len;
        char *b64_msign = base64_urlsafe_encode((uint8_t*)&sig, sizeof(sig), &out_len);
        debug("returning X-MSign for %s %s\n", uri, b64_msign);

        evhttp_add_header(p->server_req->output_headers, "X-Sign", b64_sign);
        free(b64_sign);
        evhttp_add_header(p->server_req->output_headers, "X-MSign", b64_msign);
        free(b64_msign);

        char *hashrequest = (char*)evhttp_find_header(p->server_req->input_headers, "X-HashRequest");
        char *b64_hashes = NULL;
        if (hashrequest) {
            static_assert(sizeof(node) == member_sizeof(node, hash), "node hash packing");
            size_t node_len = p->m->leaves_num * member_sizeof(node, hash);
            b64_hashes = base64_urlsafe_encode((uint8_t*)p->m->nodes, node_len, &out_len);
            evhttp_add_header(p->server_req->output_headers, "X-Hashes", b64_hashes);
            free(b64_hashes);
        }

        bool matches = false;
        char *ifnonematch = (char*)evhttp_find_header(p->server_req->input_headers, "If-None-Match");
        if (ifnonematch) {
            size_t content_etag_len;
            char *content_etag = base64_urlsafe_encode((uint8_t*)&content_hash, sizeof(content_hash), &content_etag_len);
            size_t root_etag_len;
            char *root_etag = base64_urlsafe_encode((uint8_t*)&root_hash, sizeof(root_hash), &root_etag_len);
            size_t if_len = strlen(ifnonematch);
            if (if_len > 0) {
                if (ifnonematch[if_len - 1] == '"') {
                    ifnonematch[if_len - 1] = '\0';
                }
                ifnonematch++;
            }
            matches = streq(ifnonematch, content_etag) || streq(ifnonematch, root_etag);
            if (!matches) {
                debug("If-None-Match: %s != %s || %s\n", ifnonematch, content_etag, root_etag);
            }
            free(content_etag);
            free(root_etag);
        }
        if (matches) {
            evhttp_send_reply(p->server_req, 304, "Not Modified", NULL);
        } else {
            debug("pending_output:%zu uri:%s\n", p->pending_output ? evbuffer_get_length(p->pending_output) : 0,
                evhttp_request_get_uri(p->server_req));
            evhttp_send_reply(p->server_req, req->response_code, req->response_code_line, p->pending_output);
        }
        p->server_req = NULL;
    }
    if (req->response_code != 0) {
        return_connection(p->evcon);
        p->evcon = NULL;
    }
    request_cleanup(p);
}

void chunked_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    evbuffer *input = req->input_buffer;
    //debug("p:%p chunked_cb length:%zu\n", p, evbuffer_get_length(input));

    evbuffer_hash_update(input, &p->content_state);
    merkle_tree_add_evbuffer(p->m, input);
    if (!p->pending_output) {
        p->pending_output = evbuffer_new();
    }
    evbuffer_add_buffer(p->pending_output, input);
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

int header_cb(evhttp_request *req, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p header_cb %d %s\n", p, req->response_code, req->response_code_line);

    int klass = req->response_code / 100;

    const char *response_header_whitelist[] = hashed_headers;
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(req, p->server_req, response_header_whitelist[i]);
    }
    overwrite_header(p->server_req, "Content-Location", evhttp_request_get_uri(p->server_req));

    char *content_length = (char*)evhttp_find_header(req->input_headers, "Content-Length");
    debug("Content-Length:%s uri:%s\n", content_length, evhttp_request_get_uri(p->server_req));

    // XXX: remove after no X-Sign clients exist
    crypto_generichash_init(&p->content_state, NULL, 0, crypto_generichash_BYTES);
    hash_headers(p->server_req->output_headers, &p->content_state);

    merkle_tree_hash_request(p->m, req, p->server_req->output_headers);

    evhttp_request_set_chunked_cb(req, chunked_cb);
    return 0;
}

void error_cb(evhttp_request_error error, void *arg)
{
    proxy_request *p = (proxy_request*)arg;
    debug("p:%p error_cb %d\n", p, error);
    if (p->server_req) {
        switch (error) {
        case EVREQ_HTTP_TIMEOUT: evhttp_send_error(p->server_req, 504, "Gateway Timeout"); break;
        case EVREQ_HTTP_EOF: evhttp_send_error(p->server_req, 502, "Bad Gateway (EOF)"); break;
        case EVREQ_HTTP_INVALID_HEADER: evhttp_send_error(p->server_req, 502, "Bad Gateway (header)"); break;
        case EVREQ_HTTP_BUFFER_ERROR: evhttp_send_error(p->server_req, 502, "Bad Gateway (buffer)"); break;
        case EVREQ_HTTP_DATA_TOO_LONG: evhttp_send_error(p->server_req, 502, "Bad Gateway (too long)"); break;
        default:
        case EVREQ_HTTP_REQUEST_CANCEL: break;
        }
        p->server_req = NULL;
    }
    request_cleanup(p);
}

void submit_request(network *n, evhttp_request *server_req, evhttp_connection *evcon, const evhttp_uri *uri)
{
    proxy_request *p = alloc(proxy_request);
    p->n = n;
    p->server_req = server_req;
    p->evcon = evcon;
    p->m = alloc(merkle_tree);
    evhttp_request *client_req = evhttp_request_new(request_done_cb, p);
    const char *request_header_whitelist[] = {"Referer", "Host", "Origin"};
    for (size_t i = 0; i < lenof(request_header_whitelist); i++) {
        copy_header(p->server_req, client_req, request_header_whitelist[i]);
    }

    // TODO: range requests / partial content handling
    evhttp_remove_header(client_req->output_headers, "Range");
    evhttp_remove_header(client_req->output_headers, "If-Range");

    overwrite_header(client_req, "User-Agent", "newnode/" VERSION);

    evhttp_request_set_header_cb(client_req, header_cb);
    evhttp_request_set_error_cb(client_req, error_cb);

    char request_uri[2048];
    const char *q = evhttp_uri_get_query(uri);
    snprintf(request_uri, sizeof(request_uri), "%s%s%s", evhttp_uri_get_path(uri), q?"?":"", q?q:"");
    evhttp_make_request(evcon, client_req, p->server_req->type, request_uri);
    debug("p:%p con:%p request submitted: %s\n", p, client_req->evcon, evhttp_request_get_uri(client_req));
}

typedef struct {
    evhttp_request *server_req;
    bufferevent *direct;
} connect_req;

void connect_cleanup(connect_req *c, int err)
{
    if (c->direct) {
        return;
    }
    if (c->server_req) {
        if (c->server_req->evcon) {
            evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
        }
        char buf[2048];
        snprintf(buf, sizeof(buf), "https://%s", evhttp_request_get_uri(c->server_req));
        overwrite_header(c->server_req, "Content-Location", buf);

        int code = 502;
        const char *reason = "Bad Gateway";
        switch (err) {
        case ENETUNREACH:
        case EHOSTUNREACH: code = 523; reason = "Origin Is Unreachable"; break;
        case ECONNREFUSED: code = 521; reason = "Web Server Is Down"; break;
        case ETIMEDOUT: code = 504; reason = "Gateway Timeout"; break;
        }

        // set the code early so we can hash it
        c->server_req->response_code = code;

        // XXX: remove after no X-Sign clients exist
        crypto_generichash_state content_state;
        crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);
        evbuffer *request_buf = build_request_buffer(c->server_req->response_code, c->server_req->output_headers);
        evbuffer_hash_update(request_buf, &content_state);
        evbuffer_free(request_buf);

        uint8_t content_hash[crypto_generichash_BYTES];
        crypto_generichash_final(&content_state, content_hash, sizeof(content_hash));
        content_sig sig;
        content_sign(&sig, content_hash);
        size_t out_len;
        char *b64_sig = base64_urlsafe_encode((uint8_t*)&sig, sizeof(sig), &out_len);
        debug("returning sig for %s %d %s %s\n", evhttp_request_get_uri(c->server_req), code, reason, b64_sig);

        // XXX: remove after no X-Sign clients exist
        overwrite_header(c->server_req, "X-Sign", b64_sig);

        overwrite_header(c->server_req, "X-MSign", b64_sig);
        free(b64_sig);

        evhttp_send_reply(c->server_req, code, reason, NULL);
    }
    free(c);
}

void connected(connect_req *c, bufferevent *other)
{
    bufferevent *bev = evhttp_connection_detach_bufferevent(c->server_req->evcon);
    evhttp_connection_set_closecb(c->server_req->evcon, NULL, NULL);
    c->server_req = NULL;
    connect_cleanup(c, 0);
    evbuffer_add_printf(bufferevent_get_output(bev), "HTTP/1.0 200 Connection established\r\n\r\n");
    bev_splice(bev, other);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

void connect_event_cb(bufferevent *bev, short events, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p connect_event_cb bev:%p req:%s events:0x%x %s\n", c, bev, evhttp_request_get_uri(c->server_req), events, bev_events_to_str(events));

    if (events & BEV_EVENT_TIMEOUT) {
        connect_cleanup(c, ETIMEDOUT);
    } else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        int err = bufferevent_get_error(bev);
        bufferevent_free(bev);
        c->direct = NULL;
        connect_cleanup(c, err);
    } else if (events & BEV_EVENT_CONNECTED) {
        bufferevent_set_timeouts(c->direct, NULL, NULL);
        c->direct = NULL;
        connected(c, bev);
    }
}

void close_cb(evhttp_connection *evcon, void *ctx)
{
    connect_req *c = (connect_req *)ctx;
    debug("c:%p close_cb\n", c);
    evhttp_connection_set_closecb(evcon, NULL, NULL);
    c->server_req = NULL;
    if (c->direct) {
        bufferevent_free(c->direct);
        c->direct = NULL;
    }
    connect_cleanup(c, 0);
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

    evhttp_connection_set_closecb(req->evcon, close_cb, c);

    c->direct = bufferevent_socket_new(n->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(c->direct, NULL, NULL, connect_event_cb, c);
    const timeval conn_tv = { 45, 0 };
    bufferevent_set_timeouts(c->direct, &conn_tv, &conn_tv);
    bufferevent_enable(c->direct, EV_READ);
    bufferevent_socket_connect_hostname(c->direct, n->evdns, AF_INET, host, port);
    evhttp_uri_free(uri);
}

void http_request_cb(evhttp_request *req, void *arg)
{
    network *n = (network*)arg;
    char *e_host;
    ev_uint16_t e_port;
    evhttp_connection_get_peer(req->evcon, &e_host, &e_port);
    debug("con:%p %s:%u request received %s %s\n", req->evcon, e_host, e_port,
        evhttp_method(req->type), evhttp_request_get_uri(req));

    if (req->type == EVHTTP_REQ_CONNECT) {
        connect_request(n, req);
        return;
    }

    if (req->type == EVHTTP_REQ_TRACE) {

        char *useragent = (char*)evhttp_find_header(req->input_headers, "User-Agent");
        debug("%s:%d %s %s %s\n", e_host, e_port, useragent, evhttp_method(req->type), evhttp_request_get_uri(req));

        evbuffer *output = evbuffer_new();
        evbuffer_add_printf(output, "TRACE %s HTTP/%d.%d\r\n", req->uri, req->major, req->minor);
        evkeyval *header;
        TAILQ_FOREACH(header, req->input_headers, next) {
            evbuffer_add_printf(output, "%s: %s\r\n", header->key, header->value);
        }
        evbuffer_add(output, "\r\n", 2);
        char size[22];
        snprintf(size, sizeof(size), "%zu", evbuffer_get_length(output));
        evhttp_add_header(req->output_headers, "Content-Length", size);
        evhttp_add_header(req->output_headers, "Content-Type", "message/http");
        evhttp_add_header(req->output_headers, "Content-Location", evhttp_request_get_uri(req));

        // set the code early so we can hash it
        req->response_code = 200;

        const unsigned char *out_body = evbuffer_pullup(output, evbuffer_get_length(output));

        merkle_tree *m = alloc(merkle_tree);
        merkle_tree_hash_request(m, req, req->output_headers);
        merkle_tree_add_hashed_data(m, out_body, evbuffer_get_length(output));

        // XXX: remove after no X-Sign clients exist
        {
            crypto_generichash_state content_state;
            crypto_generichash_init(&content_state, NULL, 0, crypto_generichash_BYTES);
            hash_headers(req->output_headers, &content_state);
            crypto_generichash_update(&content_state, out_body, evbuffer_get_length(output));
            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&content_state, content_hash, sizeof(content_hash));
            content_sig sig;
            content_sign(&sig, content_hash);
            size_t out_len;
            char *b64_sign = base64_urlsafe_encode((uint8_t*)&sig, sizeof(sig), &out_len);
            debug("returning X-Sign for TRACE %s %s\n", req->uri, b64_sign);

            evhttp_add_header(req->output_headers, "X-Sign", b64_sign);
            free(b64_sign);
        }

        uint8_t root_hash[crypto_generichash_BYTES];
        merkle_tree_get_root(m, root_hash);
        content_sig sig;
        content_sign(&sig, root_hash);

        size_t out_len;
        static_assert(sizeof(node) == member_sizeof(node, hash), "node hash packing");
        size_t node_len = m->leaves_num * member_sizeof(node, hash);
        char *b64_hashes = base64_urlsafe_encode((uint8_t*)m->nodes, node_len, &out_len);
        evhttp_add_header(req->output_headers, "X-Hashes", b64_hashes);
        free(b64_hashes);

        merkle_tree_free(m);

        char *b64_msign = base64_urlsafe_encode((uint8_t*)&sig, sizeof(sig), &out_len);
        debug("returning X-MSign for TRACE %s %s\n", req->uri, b64_msign);
        evhttp_add_header(req->output_headers, "X-MSign", b64_msign);
        free(b64_msign);

        evhttp_send_reply(req, 200, "OK", output);
        evbuffer_free(output);
        return;
    }

    const evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    // TODO: could look up uri in a table of {uri => headers}
    evhttp_connection *evcon = make_connection(n, uri);
    if (!evcon) {
        evhttp_send_error(req, 503, "Service Unavailable");
        return;
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
    char *address = "::";
    char *port_s = NULL;

    o_debug = 0;

    for (;;) {
        int c = getopt(argc, argv, "p:s:v");
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
        case 'v':
            o_debug++;
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

    port_t port = atoi(port_s);
    network *n = network_setup(address, port);

    timer_callback cb = ^{
#define SHA1BA(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t) (const uint8_t[]){0x##a,0x##b,0x##c,0x##d,0x##e,0x##f,0x##g,0x##h,0x##i,0x##j,0x##k,0x##l,0x##m,0x##n,0x##o,0x##p,0x##q,0x##r,0x##s,0x##t}

#define injector_swarm SHA1BA(DF,54,48,F4,78,17,1B,51,63,4C,E1,EB,58,18,20,05,18,5D,8C,05)
#define encrypted_injector_swarm SHA1BA(DC,1B,08,0B,E3,A1,F3,34,16,32,19,F0,F8,B4,17,16,23,92,D4,BB)

        dht_announce(n->dht, (const uint8_t *)injector_swarm);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_swarm);

static_assert(20 >= crypto_generichash_BYTES_MIN, "dht hash must fit in generichash size");
        uint8_t encrypted_injector_swarm_m1[20];
        uint8_t encrypted_injector_swarm_p0[20];
        uint8_t encrypted_injector_swarm_p1[20];

        time_t t = time(NULL);
        tm *tm = gmtime(&t);
        char name[1024];

        snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday - 1));
        crypto_generichash(encrypted_injector_swarm_m1, sizeof(encrypted_injector_swarm_m1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_swarm_m1);
        snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday + 0));
        crypto_generichash(encrypted_injector_swarm_p0, sizeof(encrypted_injector_swarm_p0), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_swarm_p0);
        snprintf(name, sizeof(name), "injector %d-%d", tm->tm_year, (tm->tm_yday + 1));
        crypto_generichash(encrypted_injector_swarm_p1, sizeof(encrypted_injector_swarm_p1), (uint8_t*)name, strlen(name), NULL, 0);
        dht_announce(n->dht, (const uint8_t *)encrypted_injector_swarm_p1);
    };
    cb();
    timer_repeating(n, 25 * 60 * 1000, cb);

    evhttp_set_allowed_methods(n->http, EVHTTP_REQ_GET | EVHTTP_REQ_CONNECT | EVHTTP_REQ_TRACE | EVHTTP_REQ_OPTIONS);
    evhttp_set_gencb(n->http, http_request_cb, n);
    evhttp_bind_socket_with_handle(n->http, "127.0.0.1", port);
    printf("listening on TCP: %s:%d\n", "127.0.0.1", port);

    return network_loop(n);
}
