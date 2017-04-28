// pseudocode:
/*

injector_get_connection()
{
    injector_connection = pop(_idle_injector_connections);
    if (injector_connection) {
        return injector_connection;
    }
    injectors = dht_get_peers(injector_swarm);
    injector_connection = utp_connect_to_one(shuffle(injectors));
    return injector_connection;
}

handle_connection(utp_socket *s)
{
    injector = injector_get_connection();
    for (;;) {
        request(injector, read_request(s));
        respond(s, read_response(injector));
    }
}

*/
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h> // calloc

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent.h>

#include <sys/queue.h>

#include "log.h"
#include "timer.h"
#include "constants.h"
#include "network.h"

typedef struct proxy proxy;
typedef struct proxy_injector proxy_injector;
typedef struct proxy_client proxy_client;

void proxy_add_injector(proxy* p, struct evhttp_connection *http_con);

struct proxy_injector {
    STAILQ_ENTRY(proxy_injector) tailq;

    struct evhttp_connection *http_con;
};

struct proxy {
    network *net;
    struct evhttp *http;
    timer *injector_search_timer;

    STAILQ_HEAD(, proxy_injector) injectors;
};

static proxy_injector* pick_random_injector(proxy* p)
{
    // XXX: This would be a faster if p->injectors was an array.
    size_t cnt = 0;
    struct proxy_injector* inj;
    STAILQ_FOREACH(inj, &p->injectors, tailq) { cnt += 1; }
    size_t n = rand() % cnt;
    STAILQ_FOREACH(inj, &p->injectors, tailq) { if (n-- == 0) return inj; }
    return NULL;
}

static void handle_injector_response(struct evhttp_request *res, void *ctx)
{
    // TODO: Remove the injector on ERR_CONNECTION_REFUSED or if !res.

    struct evhttp_request *req = ctx;

    if (!res) {
        int errcode = EVUTIL_SOCKET_ERROR();

        debug("handle_injector_response: socket error = %s (%d)\n",
            evutil_socket_error_to_string(errcode),
            errcode);

        evhttp_request_free(req);
        return;
    }

    struct evbuffer* evb_out = evbuffer_new();
    struct evbuffer *evb_in = evhttp_request_get_input_buffer(res);
    int response_code = evhttp_request_get_response_code(res);
    const char *response_code_line = evhttp_request_get_response_code_line(res);

    int nread;
	while ((nread = evbuffer_remove_buffer(evb_in,
		    evb_out, evbuffer_get_length(evb_in))) > 0) { }

    evhttp_send_reply(req, response_code, response_code_line, evb_out);
    evbuffer_free(evb_out);
}

void handle_client_request(struct evhttp_request *req_in, void *arg)
{
    proxy *p = (proxy*) arg;

    // XXX: Ignore or respond with error if too many requests per client.

    // Proxy doesn't try to connect to injectors, instead, it is expected that
    // the client will provide them through the `proxy_add_injector` function.
    proxy_injector* inj = pick_random_injector(p);

    if (!inj) {
        evhttp_send_reply(req_in, 502 /* Bad Gateway */, "Proxy has no injectors", NULL);
        return;
    }

    struct evhttp_request *req_out = evhttp_request_new(handle_injector_response, req_in);

    if (req_out == NULL) {
        die("evhttp_request_new() failed\n");
        return;
    }

    enum evhttp_cmd_type type = evhttp_request_get_command(req_in);
    const char *uri = evhttp_request_get_uri(req_in);

    struct evkeyvalq *hdr_out = evhttp_request_get_output_headers(req_out);

    {
        struct evkeyvalq *hdr_in = evhttp_request_get_input_headers(req_in);

        const char *host_hdr = evhttp_find_header(hdr_in, "Host");
        if (host_hdr) {
            evhttp_add_header(hdr_out, "Host", host_hdr);
        }
    }

    evhttp_add_header(hdr_out, "Connection", "close");

    int result = evhttp_make_request(inj->http_con, req_out, type, uri);

    if (result != 0) {
        die("evhttp_make_request() failed\n");
    }
}

static int start_taking_requests(proxy *p)
{
    const char *address = "0.0.0.0";
    uint16_t port = 5678;

    /* Create a new evhttp object to handle requests. */
    struct evhttp *http = evhttp_new(p->net->evbase);

    if (!http) {
        die("couldn't create evhttp. Exiting.\n");
        return -1;
    }

    p->http = http;

    evhttp_set_gencb(http, handle_client_request, p);

    /* Now we tell the evhttp what port to listen on */
    struct evhttp_bound_socket *handle
        = evhttp_bind_socket_with_handle(http, address, port);

    if (!handle) {
        die("couldn't bind to port %d. Exiting.\n", (int)port);
        return 1;
    }

    {
        /* Extract and display the address we're listening on. */
        struct sockaddr_storage ss;
        evutil_socket_t fd;
        ev_socklen_t socklen = sizeof(ss);
        char addrbuf[128];
        void *inaddr;
        const char *addr;
        int got_port = -1;
        fd = evhttp_bound_socket_get_fd(handle);
        memset(&ss, 0, sizeof(ss));
        if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
            perror("getsockname() failed");
            return 1;
        }
        if (ss.ss_family == AF_INET) {
            got_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
            inaddr = &((struct sockaddr_in*)&ss)->sin_addr;
        } else if (ss.ss_family == AF_INET6) {
            got_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
            inaddr = &((struct sockaddr_in6*)&ss)->sin6_addr;
        } else {
            fprintf(stderr, "Weird address family %d\n",
                ss.ss_family);
            return 1;
        }
        addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf,
            sizeof(addrbuf));
        if (addr) {
            char uri_root[512];
            printf("Listening on TCP:%s:%d\n", addr, got_port);
            evutil_snprintf(uri_root, sizeof(uri_root),
                "http://%s:%d",addr,got_port);
        } else {
            fprintf(stderr, "evutil_inet_ntop failed\n");
            return 1;
        }
    }

    return 0;
}

static void on_injectors_found(proxy *proxy, const byte *peers, uint num_peers) {
    printf("Found %d injectors\n", num_peers);

    typedef struct { byte ip[4]; byte port[2]; } raw_peer;

    for (uint i = 0; i < num_peers; ++i) {
        raw_peer p = *((raw_peer*) peers + i * sizeof(raw_peer));

        char addr[32];

        sprintf(addr, "%d.%d.%d.%d", p.ip[0], p.ip[1], p.ip[2], p.ip[3]);

        uint16_t port = ntohs(*((uint16_t*) p.port));

        printf("    %s:%d\n", addr, (int)port);

        // Connect to injector
        struct evhttp_connection *evcon
            = evhttp_connection_base_new(proxy->net->evbase, NULL, addr, port);

        proxy_add_injector(proxy, evcon);
    }
}

static void start_injector_search(proxy *p)
{
    dht_get_peers(p->net->dht, injector_swarm,
            ^(const byte *peers, uint num_peers) {
                // TODO: Ensure safety after p is destroyed.
                on_injectors_found(p, peers, num_peers);
            });

    const unsigned int minute = 60 * 1000;

    const unsigned int retry_timeout = STAILQ_EMPTY(&p->injectors)
                                     ? minute
                                     : 25 * minute;

    p->injector_search_timer = timer_start(p->net,
            retry_timeout,
            ^{ start_injector_search(p); });
}

void proxy_destroy(proxy* p)
{
    if (p->injector_search_timer)
        timer_cancel(p->injector_search_timer);

    while (!STAILQ_EMPTY(&p->injectors)) {
        proxy_injector *i = STAILQ_FIRST(&p->injectors);
        free(i);
        STAILQ_REMOVE_HEAD(&p->injectors, tailq);
    }

    free(p);
}

proxy* proxy_create(network *n)
{
    proxy* p = alloc(proxy);

    STAILQ_INIT(&p->injectors);

    p->net = n;
    p->http = NULL;
    p->injector_search_timer = NULL;

    if (start_taking_requests(p) != 0) {
        proxy_destroy(p);
        return NULL;
    }

    start_injector_search(p);

    return p;
}

void proxy_add_injector(proxy* p, struct evhttp_connection *http_con)
{
    proxy_injector* c = alloc(proxy_injector);
    c->http_con = http_con;
    STAILQ_INSERT_TAIL(&p->injectors, c, tailq);
}

static
void connect_to_test_injector(struct event_base *base, proxy *p)
{
    const char *url = "http://rubblers.com";
    uint16_t port = 80;

    struct evhttp_uri *http_uri = evhttp_uri_parse(url);

    if (http_uri == NULL) {
        evhttp_uri_free(http_uri);
        die("malformed url");
    }

    const char *host = evhttp_uri_get_host(http_uri);

    struct evhttp_connection *evcon
        = evhttp_connection_base_new(base, NULL, host, port);

    proxy_add_injector(p, evcon);

    evhttp_uri_free(http_uri);
}

int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port = "5678";

    network *n = network_setup(address, port);

    proxy *p = proxy_create(n);

    assert(p);

    connect_to_test_injector(n->evbase, p);

    // TODO
    //utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    int result = network_loop(n);

    proxy_destroy(p);

    return result;
}
