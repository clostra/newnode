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
		die("malformed url");
	}

	const char* host = evhttp_uri_get_host(http_uri);

	struct bufferevent *bev
        = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	struct evhttp_connection *evcon
        = evhttp_connection_base_bufferevent_new(base, NULL, bev, host, port);

    proxy_add_injector(p, bev, evcon);
}

int main(int argc, char *argv[])
{
    struct event_base *base = event_base_new();

	if (!base) {
		fprintf(stderr, "Couldn't create an event_base: exiting\n");
		return 1;
	}

    proxy *p = proxy_create(base);

    assert(p);

    connect_to_injector(base, p);

    event_base_dispatch(base);
}
