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

#include "proxy.h"
#include "log.h"

using std::unique_ptr;
using std::move;
using std::make_unique;
using std::string;
using std::queue;

// XXX: temp
struct connection;
void send(connection*, const void*, size_t) { assert(0 && "TODO"); }


struct proxy;

struct proxy_client {
    proxy* p = nullptr;
    connection* con = nullptr;
};

struct active_request {
    // How many bytes of the `bytes_remaining` variable we have yet to receive.
    unsigned int header_bytes_missing = sizeof(bytes_remaining);
    // This is only valid iff header_bytes_missing == 0, indicates how many
    // bytes of the payload are still missing.
    uint32_t bytes_remaining = 0;
    proxy_client* c;
    string request;

    active_request(proxy_client* c, string rq) :
        c(c), request(move(rq)) {}
};

struct pending_request {
    proxy_client* c = nullptr;
    string request;
};

struct proxy_injector {
    connection* con = nullptr;
    queue<active_request> active_requests;
};

struct proxy {
    std::set<unique_ptr<proxy_client>> clients;
    std::set<unique_ptr<proxy_injector>> injectors;

    queue<pending_request> pending_requests;
};

static void forward_request(proxy_injector* i, proxy_client* c, const char* request)
{
    send(i->con, request, strlen(request));
    i->active_requests.emplace(c, string(request));
}

static proxy_injector* pick_random_injector(proxy* p)
{
    auto& is = p->injectors;
    if (is.empty()) return nullptr;
    auto i = is.begin();
    std::advance(i, rand() % is.size());
    return i->get();
}

void handle_request(proxy_client* c, const char* request)
{
    proxy* p = c->p;

    // XXX: Check validity of the request.

    // XXX: Ignore or respond with error if too many requests per client.

    // Proxy doesn't try to connect to injectors, instead, it is expected that
    // the client will provide them through the `proxy_add_injector` function.
    auto* proxy_injector = pick_random_injector(p);

    if (!proxy_injector) {
        p->pending_requests.push({c, string(request)});
        return;
    }

    forward_request(proxy_injector, c, request);
}

bool on_recv_from_injector(proxy_injector* i, const uint8_t* data, size_t size)
{
    auto& rs = i->active_requests;

    if (rs.empty()) {
        debug("An injector sent us a response, but there is no request");
        return false;
    }

    auto* r = &rs.front();

    while (size) {
        if (r->header_bytes_missing != 0) {
            size_t take = std::min<size_t>(r->header_bytes_missing, size);
            size_t s = sizeof(r->bytes_remaining) - r->header_bytes_missing;
            uint8_t* d = reinterpret_cast<uint8_t*>(r->bytes_remaining) + s;

            // XXX: Endianness, but ATM the injector doesn't do it neither.
            for (size_t i = 0; i < take; ++i) {
                *d++ = *data++;
            }

            size -= take;
            r->header_bytes_missing -= take;

            if (r->header_bytes_missing != 0) return true;
        }

        size_t take = std::min<size_t>(size, r->bytes_remaining);

        if (take) {
            size -= take;
            r->bytes_remaining -= take;

            send(r->c->con, data, take);

            data += take;
        }

        if (r->bytes_remaining == 0) {
            rs.pop();
            r = &rs.front();
        }
    }

    return true;
}

void on_recv_from_client(proxy_client* c, const char* data, size_t size)
{
    // XXX: Ignore or respond with error if too many requests in total.

    //auto read_line_ctx = create_read_line_ctx(data, size);

    //for (auto line = read_line(&read_line_ctx)) {
    //    handle_request(c, line);
    //}
}

extern "C" {
    proxy* proxy_create()
    {
        auto* r = new proxy();
        return r;
    }
    
    void proxy_destroy(proxy* p)
    {
        delete p;
    }
    
    proxy_injector* proxy_add_injector(proxy* p, utp_socket* s)
    {
        auto c = make_unique<proxy_injector>();
        auto cp = c.get();
        p->injectors.insert(move(c));
        return cp;
    }

    proxy_client* proxy_add_client(proxy* p, utp_socket* s)
    {
        auto c = make_unique<proxy_client>();
        auto cp = c.get();
        p->clients.insert(move(c));
        return cp;
    }
} // extern "C"
