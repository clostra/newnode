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
#include <event2/listener.h>

#include <sys/queue.h>

#include "log.h"
#include "timer.h"
#include "constants.h"
#include "network.h"
#include "utp_bufferevent.h"
#include "http_util.h"

typedef struct proxy proxy;
typedef struct injector injector;
typedef struct proxy_client proxy_client;

static const bool TEST_LOCAL_INJECTOR = false;

#if false
#   define LOG(...) printf(__VA_ARGS__)
#else
#   define LOG(...) do {} while(false)
#endif

// Returns true on error
static bool fd_local_info(int fd, const char **addr, uint16_t *port)
{
    struct sockaddr_storage ss;
    ev_socklen_t socklen = sizeof(ss);
    char addrbuf[128];
    void *inaddr;
    memset(&ss, 0, sizeof(ss));
    if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
        perror("getsockname() failed");
        return 1;
    }
    if (ss.ss_family == AF_INET) {
        if (port) {
            *port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        }
        inaddr = &((struct sockaddr_in *)&ss)->sin_addr;
    } else if (ss.ss_family == AF_INET6) {
        if (port) {
            *port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        }
        inaddr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
    } else {
        LOG("Weird address family %d\n", ss.ss_family);
        return 1;
    }
    if (addr) {
        *addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf, sizeof(addrbuf));
        if (!*addr) {
            LOG("evutil_inet_ntop failed\n");
            return 1;
        }
    }
    return 0;
}

static uint16_t local_port(struct evhttp_connection* con)
{
    struct bufferevent *bev = evhttp_connection_get_bufferevent(con);
    int fd = bufferevent_getfd(bev);
    uint16_t port = 0;
    fd_local_info(fd, NULL, &port);
    return port;
}

static uint16_t fd_remote_port(int fd)
{
    // XXX: Support for IPv6
    struct sockaddr_in peeraddr;
    socklen_t peeraddrlen = sizeof(peeraddr);
    getpeername(fd, (struct sockaddr*) &peeraddr, &peeraddrlen);
    return ntohs(peeraddr.sin_port);
}

typedef struct {
    uint8_t ip[4];
    uint16_t port;
} endpoint;

struct injector {
    STAILQ_ENTRY(injector) tailq;

    endpoint ep;
};

injector *create_injector(endpoint ep)
{
    injector *c = alloc(injector);
    c->ep = ep;
    return c;
}

void destroy_injector(injector *i)
{
    free(i);
}

struct proxy {
    network *net;
    struct evhttp *http;
    timer *injector_search_timer;

    // Timer for announcing ourselves in "injector_proxy_swarm". Is set to NULL
    // when we're not announcing (iff we know zero injectors).
    timer *announce_timer;

    endpoint endpoint_map[65536];

    struct evconnlistener *tcp_out_listener;
    uint16_t tcp_out_port;

    STAILQ_HEAD(, injector) injectors;
};

static bool same_endpoint(endpoint ep1, endpoint ep2) {
    return memcmp(&ep1, &ep2, sizeof(endpoint)) == 0;
}

static void start_announcing_self_in_dht(proxy *p)
{
    if (p->announce_timer) return;

    timer_callback do_announce = ^{
        dht_announce(p->net->dht, injector_proxy_swarm, ^(const byte *peers, uint num_peers) {
            if (!peers) {
                LOG("announce to injector_proxy_swarm complete\n");
            }
        });
    };

    unsigned int one_hour = 60 * 60 * 1000;
    do_announce();
    p->announce_timer = timer_start(p->net, one_hour, do_announce);
}

static void proxy_add_injector(proxy *p, endpoint ep)
{
    // I was seeing addresses 0.0.0.0 reported by the DHT which seems bogus.
    if (!ep.ip[0] && !ep.ip[1] && !ep.ip[2] && !ep.ip[3]) {
        //LOG("Not adding 0.0.0.0:%d\n", ep.port);
        return;
    }

    // Ignore duplicates
    struct injector *i;
    STAILQ_FOREACH(i, &p->injectors, tailq) {
        if (same_endpoint(i->ep, ep)) {
            //LOG("Not adding duplicate endpoint %d.%d.%d.%d:%d\n",
            //        ep.ip[0], ep.ip[1], ep.ip[2], ep.ip[3], ep.port);
            return;
        }
    }

    LOG("Added injector %d.%d.%d.%d:%d\n",
            ep.ip[0], ep.ip[1], ep.ip[2], ep.ip[3], ep.port);

    // TODO: Don't add if too many injectors.
    // TODO: Stop announcing once injector count drops to zero.
    start_announcing_self_in_dht(p);

    injector *c = create_injector(ep);
    STAILQ_INSERT_TAIL(&p->injectors, c, tailq);
}

static size_t count_injectors(proxy *p)
{
    size_t cnt = 0;
    struct injector *inj;
    STAILQ_FOREACH(inj, &p->injectors, tailq) { cnt += 1; }
    return cnt;
}

static
injector * pick_random_injector(proxy *p)
{
    // XXX: This would be a faster if p->injectors was an array.
    size_t cnt = count_injectors(p);
    struct injector *inj;

    if (cnt) {
        size_t n = rand() % cnt;
        STAILQ_FOREACH(inj, &p->injectors, tailq) { if (n-- == 0) return inj; }
    }

    return NULL;
}

typedef struct {
    struct evhttp_request *req;
    endpoint injector_ep;
} request_ctx;

static
void handle_injector_response(struct evhttp_request *res, void *ctx_void)
{
    // TODO: Remove (or blacklist) the injector on ERR_CONNECTION_REFUSED or if !res.
    // TODO: Retry request with another injector (if any left).

    request_ctx *ctx = ctx_void;

    if (!res) {
        int errcode = EVUTIL_SOCKET_ERROR();

        debug("handle_injector_response: socket error = %s (%d)\n",
            evutil_socket_error_to_string(errcode),
            errcode);

        evhttp_send_reply(ctx->req, 502 /* Bad Gateway */,
                "Error while waiting for injector response", NULL);

        goto finish;
    }

    struct evbuffer *evb_out = evbuffer_new();
    struct evbuffer *evb_in = evhttp_request_get_input_buffer(res);
    int response_code = evhttp_request_get_response_code(res);
    const char *response_code_line = evhttp_request_get_response_code_line(res);

    const char *response_header_whitelist[] = {"Content-Length", "Content-Type"};
    for (size_t i = 0; i < lenof(response_header_whitelist); i++) {
        copy_header(res, ctx->req, response_header_whitelist[i]);
    }

    int nread;
    while ((nread = evbuffer_remove_buffer(evb_in,
            evb_out, evbuffer_get_length(evb_in))) > 0) { }

    evhttp_send_reply(ctx->req, response_code, response_code_line, evb_out);
    evbuffer_free(evb_out);

finish:
    free(ctx);
}

typedef struct {
    struct evhttp_request *req;
    struct bufferevent *origin_bev;
} tunnel;

static
struct bufferevent* tunnel_bev1(tunnel *t)
{
    return evhttp_connection_get_bufferevent(evhttp_request_get_connection(t->req));
}

static
struct bufferevent* tunnel_bev2(tunnel *t)
{
    return t->origin_bev;
}

static
void destroy_tunnel(tunnel *t)
{
    bufferevent_setcb(tunnel_bev1(t), NULL, NULL, NULL, NULL);
    bufferevent_setcb(tunnel_bev2(t), NULL, NULL, NULL, NULL);

    evhttp_request_free(t->req);
    bufferevent_free(t->origin_bev);

    free(t);
}

static
void on_origin_event(struct bufferevent* bev, short what, void *ctx)
{
    if (what & BEV_EVENT_CONNECTED) {
        return;
    } 

    // Case of BEV_EVENT_EOF, BEV_EVENT_ERROR, BEV_EVENT_TIMEOUT
    destroy_tunnel(ctx);
}

static
void on_origin_read(struct bufferevent* bev, void *ctx)
{
    tunnel *t = ctx;

    struct bufferevent *other = (bev == tunnel_bev2(t))
                              ? tunnel_bev1(t)
                              : tunnel_bev2(t);

    bufferevent_write_buffer(other, bufferevent_get_input(bev));
}

/*
 * Parse a string of the form "en.wikipedia.org:80". Return
 * 'true' on success.
 */
static
bool parse_host_uri(const char* uri, char*host, size_t host_max_len, uint16_t* port)
{
    size_t uri_size = strlen(uri);

    const char *uri_end = uri + uri_size;
    const char *addr_end = uri_end;

    for (const char* c = uri; c != uri_end; ++c) {
        if (*c == ':') {
            addr_end = c;
            break;
        }
    }

    if (addr_end == uri_end) {
        assert(0 && "No ':' in the uri string");
        memcpy(host, uri, MIN(host_max_len, uri_end - uri));
        *port = 0;
        return false;
    }

    size_t addr_len = MIN((size_t) (addr_end - uri), host_max_len);

    memcpy(host, uri, addr_len);
    host[addr_len] = 0;

    *port = atoi(addr_end + 1);

    return true;
}

static
void create_tunnel(proxy *p, struct evhttp_request *req_in)
{
    const char *uri = evhttp_request_get_uri(req_in);
    char addr[512];
    uint16_t port;
    bool parsed = parse_host_uri(uri, addr, sizeof(addr), &port);

    if (!parsed) {
        assert(0);
        return;
    }

    struct evhttp_connection *con_in = evhttp_request_get_connection(req_in);
    struct bufferevent *bev_in = evhttp_connection_get_bufferevent(con_in);
    struct bufferevent *bev_out = bufferevent_socket_new(p->net->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    tunnel *t = alloc(tunnel);

    t->req = req_in;
    t->origin_bev = bev_out;

    bufferevent_setcb(bev_out, on_origin_read, NULL, on_origin_event, t);
    bufferevent_setcb(bev_in, on_origin_read, NULL, on_origin_event, t);

    // XXX: Check result.
    bufferevent_socket_connect_hostname(bev_out, p->net->evdns, AF_INET, addr, port);

	bufferevent_enable(bev_in, EV_WRITE | EV_READ);
	bufferevent_enable(bev_out, EV_WRITE | EV_READ);

    const char *response =
        "HTTP/1.0 200 Connection established\r\n"
        "Proxy-agent: Ceno-injector-helper/1.0\r\n"
        "\r\n";

    bufferevent_write(bev_in, response, strlen(response));
}

static void
handle_client_request(struct evhttp_request *req_in, void *arg)
{
    proxy *p = (proxy *)arg;

    enum evhttp_cmd_type type = evhttp_request_get_command(req_in);

    if (type == EVHTTP_REQ_CONNECT) {
        return create_tunnel(p, req_in);
    }

    // XXX: Ignore or respond with error if too many requests per client.

    if (count_injectors(p) == 0) {
        evhttp_send_reply(req_in, 502 /* Bad Gateway */, "Proxy has no injectors", NULL);
        return;
    }

    injector *i = pick_random_injector(p);

    request_ctx *ctx = alloc(request_ctx);
    ctx->req = req_in;
    ctx->injector_ep = i->ep;

    struct evhttp_request *req_out = evhttp_request_new(handle_injector_response, ctx);

    if (req_out == NULL) {
        die("evhttp_request_new() failed\n");
        return;
    }

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

    struct evhttp_connection *http_con
        = evhttp_connection_base_new(p->net->evbase, NULL, "127.0.0.1", p->tcp_out_port);

    int result = evhttp_make_request(http_con, req_out, type, uri);

    // XXX: Explain why we pick the injector here and not only after the
    // localhost receives this HTTP request.
    p->endpoint_map[local_port(http_con)] = i->ep;

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

	evhttp_set_allowed_methods(http,
	    EVHTTP_REQ_GET |
	    EVHTTP_REQ_POST |
	    EVHTTP_REQ_CONNECT);

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
        uint16_t port;
        const char *addr;
        if (fd_local_info(evhttp_bound_socket_get_fd(handle), &addr, &port) == 0) {
            printf("Listening on TCP:%s:%d\n", addr, port);
        }
    }

    return 0;
}

static void on_injectors_found(proxy *proxy, const byte *peers, uint num_peers) {
    for (uint i = 0; i < num_peers; ++i) {
        endpoint ep = *((endpoint *)peers + i * sizeof(endpoint));
        ep.port = ntohs(ep.port);

        //LOG("%d.%d.%d.%d:%d\n", ep.ip[0], ep.ip[1], ep.ip[2], ep.ip[3], (int)ep.port);

        proxy_add_injector(proxy, ep);
    }
}

static void start_injector_search(proxy *p)
{
    if (TEST_LOCAL_INJECTOR) {
        endpoint test_ep;

        test_ep.ip[0] = 127;
        test_ep.ip[1] = 0;
        test_ep.ip[2] = 0;
        test_ep.ip[3] = 1;
        test_ep.port = 7000;

        return proxy_add_injector(p, test_ep);
    }

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

void proxy_destroy(proxy *p)
{
    if (p->injector_search_timer)
        timer_cancel(p->injector_search_timer);

    if (p->announce_timer)
        timer_cancel(p->announce_timer);

    if (p->tcp_out_listener) {
        evconnlistener_free(p->tcp_out_listener);
    }

    while (!STAILQ_EMPTY(&p->injectors)) {
        injector *i = STAILQ_FIRST(&p->injectors);
        destroy_injector(i);
        STAILQ_REMOVE_HEAD(&p->injectors, tailq);
    }

    free(p);
}

proxy *proxy_create(network *n)
{
    proxy *p = alloc(proxy);

    STAILQ_INIT(&p->injectors);

    p->net = n;
    p->http = NULL;
    p->injector_search_timer = NULL;
    p->announce_timer = NULL;
    p->tcp_out_listener = NULL;
    p->tcp_out_port = 0;

    if (start_taking_requests(p) != 0) {
        proxy_destroy(p);
        return NULL;
    }

    start_injector_search(p);

    return p;
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    LOG("Proxy: Accepted TCP\n");
    proxy *p = user_data;
    struct event_base *base = p->net->evbase;

    endpoint ep = p->endpoint_map[fd_remote_port(fd)];

    {
        char addr[32];
        sprintf(addr, "%d.%d.%d.%d", ep.ip[0], ep.ip[1], ep.ip[2], ep.ip[3]);
        LOG("Proxy: Connecting to UTP:%s:%d\n", addr, (int) ep.port);
    }

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = *((uint32_t*)ep.ip),
        .sin_port = htons(ep.port),
    };

    tcp_connect_utp(base, p->net->utp, fd, (const struct sockaddr *)&dest, sizeof(dest));
}

static
int start_tcp_to_utp_redirect(proxy *p)
{
    event_base *evbase = p->net->evbase;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(p->tcp_out_port);

    p->tcp_out_listener = evconnlistener_new_bind(evbase, listener_cb, p,
        LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
        (struct sockaddr*)&sin,
        sizeof(sin));

    if (!p->tcp_out_listener) {
        LOG("Could not create a listener!\n");
        return 1;
    }

    if (fd_local_info(evconnlistener_get_fd(p->tcp_out_listener), NULL, &p->tcp_out_port)) {
        LOG("Could not get out lister port\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port = "5678";

    network *n = network_setup(address, port);

    proxy *p = proxy_create(n);

    assert(p);

    start_tcp_to_utp_redirect(p);

    // TODO
    //utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    int result = network_loop(n);

    proxy_destroy(p);

    return result;
}
