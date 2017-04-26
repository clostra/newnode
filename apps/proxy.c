#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent.h>

#include "proxy.h"
#include "log.h"

void connect_to_injector(struct event_base *base, proxy *p)
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

    connect_to_injector(n->evbase, p);

    // TODO
    //utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);

    int result = network_loop(n);

    proxy_destroy(p);

    return result;
}
