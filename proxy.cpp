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

#include <set>
#include <memory>
#include <string>
#include <queue>
#include <algorithm> // std::min
#include <assert.h>
#include <string.h>
#include <sstream>

#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "proxy.h"

extern "C" {
#include "log.h"
#include "constants.h"
#include "timer.h"
}

using std::unique_ptr;
using std::move;
using std::make_unique;
using std::string;
using std::queue;

struct proxy;

// XXX
extern "C" {
    void proxy_add_injector(proxy* p, struct evhttp_connection *http_con);
}

struct proxy_injector {
    evhttp_connection *http_con;
    queue<evhttp_request*> active_requests;
};

struct proxy {
    ::network *network = nullptr;
    struct evhttp *http = nullptr;
    timer *injector_search_timer = nullptr;

    std::set<unique_ptr<proxy_injector>> injectors;

    proxy(::network *n) : network(n) {}

    ~proxy() {
        if (injector_search_timer)
            timer_cancel(injector_search_timer);
    }
};

static void handle_injector_response(struct evhttp_request *req, void *ctx)
{
    if (!req) {
        int errcode = EVUTIL_SOCKET_ERROR();

        debug("handle_injector_response: socket error = %s (%d)\n",
            evutil_socket_error_to_string(errcode),
            errcode);

        return;
    }

    debug("handle_injector_response %p\n", req);

    proxy_injector *i = (proxy_injector*) ctx;
    auto &rs = i->active_requests;

    assert(!rs.empty());

    auto *req_out = rs.front();
    rs.pop();

    assert(req_out);

    struct evbuffer* evb_out = evbuffer_new();

    auto *evb_in = evhttp_request_get_input_buffer(req);

    int response_code = evhttp_request_get_response_code(req);
    const char *response_code_line = evhttp_request_get_response_code_line(req);

    {
        int nread;
	    while ((nread = evbuffer_remove_buffer(evb_in,
	    	    evb_out, evbuffer_get_length(evb_in))) > 0) { }
    }

    evhttp_send_reply(req_out, response_code, response_code_line, evb_out);
    evbuffer_free(evb_out);
}

static void forward_request(proxy_injector* i, evhttp_request* req_in)
{
    printf("forward_request\n");

    evhttp_request *req_out = evhttp_request_new(handle_injector_response, i);

    if (req_out == NULL) {
        die("evhttp_request_new() failed\n");
        return;
    }

    i->active_requests.push(req_in);

    evhttp_cmd_type type = evhttp_request_get_command(req_in);
    const char *uri = evhttp_request_get_uri(req_in);

    struct evkeyvalq *hdr_out = evhttp_request_get_output_headers(req_out);

    {
        struct evkeyvalq *hdr_in = evhttp_request_get_input_headers(req_in);

        const char *host_hdr = evhttp_find_header(hdr_in, "Host");
        if (host_hdr) {
            evhttp_add_header(hdr_out, "Host", host_hdr);
        }
    }

    evhttp_add_header(hdr_out, "Connection", "keep-alive");

    int r = evhttp_make_request(i->http_con, req_out, type, uri);

    if (r != 0) {
        die("evhttp_make_request() failed\n");
    }
}

static proxy_injector* pick_random_injector(proxy* p)
{
    auto& is = p->injectors;
    if (is.empty()) return nullptr;
    auto i = is.begin();
    std::advance(i, rand() % is.size());
    return i->get();
}

void handle_client_request(struct evhttp_request *req, void *arg)
{
    proxy *p = (proxy*) arg;

    // XXX: Ignore or respond with error if too many requests per client.

    // Proxy doesn't try to connect to injectors, instead, it is expected that
    // the client will provide them through the `proxy_add_injector` function.
    auto* proxy_injector = pick_random_injector(p);

    if (!proxy_injector) {
        evhttp_send_reply(req, 502 /* Bad Gateway */, "Proxy has no injectors", NULL);
        return;
    }

    forward_request(proxy_injector, req);
}

static int start_taking_requests(proxy *p)
{
    const char *address = "0.0.0.0";
    uint16_t port = 5678;

    /* Create a new evhttp object to handle requests. */
    struct evhttp *http = evhttp_new(p->network->evbase);

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

static void connect_to_injector(proxy *p, const string& addr, uint16_t port) {
    auto evbase = p->network->evbase;

    struct bufferevent *bev
        = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);

    struct evhttp_connection *evcon
        = evhttp_connection_base_bufferevent_new(evbase, NULL, bev, addr.c_str(), port);

    proxy_add_injector(p, evcon);
}

static void on_injectors_found(proxy *proxy, const byte *peers, uint num_peers) {
    printf("Found %d injectors\n", num_peers);

    struct raw_peer {
        byte ip[4];
        byte port[2];
    };

    for (uint i = 0; i < num_peers; ++i) {
        raw_peer p = *((raw_peer*) peers + i * sizeof(raw_peer));

        std::stringstream ss;

        ss << p.ip[0] << '.' << p.ip[1] << '.'
           << p.ip[2] << '.' << p.ip[3];

        uint16_t port = ntohs(*((uint16_t*) p.port));

        connect_to_injector(proxy, ss.str(), port);
    }
}

static void start_injector_search(proxy *p)
{
    dht_get_peers(p->network->dht, injector_swarm,
            ^(const byte *peers, uint num_peers) {
                // TODO: Ensure safety after p is destroyed.
                on_injectors_found(p, peers, num_peers);
            });

    const unsigned int minute = 60 * 1000;

    const unsigned int retry_timeout = p->injectors.empty()
                                     ? minute
                                     : 25 * minute;

    p->injector_search_timer = timer_start(p->network,
            retry_timeout,
            ^{ start_injector_search(p); });
}

extern "C" {
    proxy* proxy_create(network *n)
    {
        auto* p = new proxy(n);

        if (start_taking_requests(p) != 0) {
            delete p;
            return nullptr;
        }

        start_injector_search(p);

        return p;
    }
    
    void proxy_destroy(proxy* p)
    {
        delete p;
    }
    
    void proxy_add_injector(proxy* p, struct evhttp_connection *http_con)
    {
        debug("proxy_add_injector\n");
        auto c = make_unique<proxy_injector>();

        c->http_con = http_con;

        p->injectors.insert(move(c));
    }
} // extern "C"
