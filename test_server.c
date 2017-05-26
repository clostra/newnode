#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <signal.h>
#endif

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void
send_document_cb(struct evhttp_request *req, void *arg)
{
    struct evbuffer *evb = evbuffer_new();

    evbuffer_add_printf(evb,
        "<!DOCTYPE html>\n"
        "<html>\n <head>\n"
        "  <meta charset='utf-8'>\n"
        "  <title>Test page</title>\n"
        " </head>\n"
        " <body>\n"
        "  It works\n"
        " </body>\n"
        "</html>\n");

    evhttp_send_reply(req, 200, "OK", evb);
    evbuffer_free(evb);
}

static void signal_cb(evutil_socket_t sig, short events, void * ctx)
{
    struct event_base *base = ctx;
    struct timeval delay = { 0, 0 };
    event_base_loopexit(base, &delay);
}

int
main(int argc, char **argv)
{
    struct event_base *base;
    struct evhttp *http;
    struct evhttp_bound_socket *handle;

    ev_uint16_t port = 8080;

#ifdef _WIN32
    WSADATA WSAData;
    WSAStartup(0x101, &WSAData);
#endif

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't create an event_base: exiting\n");
        return 1;
    }

    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base);
    if (!http) {
        fprintf(stderr, "couldn't create evhttp. Exiting.\n");
        return 1;
    }

    /* We want to accept arbitrary requests, so we need to set a "generic"
     * cb.  We can also add callbacks for specific paths. */
    evhttp_set_gencb(http, send_document_cb, NULL);

    /* Now we tell the evhttp what port to listen on */
    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
    if (!handle) {
        evhttp_free(http);
        fprintf(stderr, "couldn't bind to port %d. Exiting.\n",
            (int)port);
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
            printf("Listening on %s:%d\n", addr, got_port);
            char uri_root[512];
            evutil_snprintf(uri_root, sizeof(uri_root),
                "http://%s:%d",addr,got_port);
        } else {
            fprintf(stderr, "evutil_inet_ntop failed\n");
            return 1;
        }
    }

    struct event *signal_event = evsignal_new(base, SIGINT, signal_cb, base);

    if (!signal_event || event_add(signal_event, NULL)<0) {
        fprintf(stderr, "Could not create/add a signal event!\n");
        return 1;
    }

    event_base_dispatch(base);

    event_free(signal_event);
    evhttp_free(http);

    return 0;
}
