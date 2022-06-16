#include <stdlib.h>

#include "newnode.h"
#include "network.h"
#include "thread.h"
#include "log.h"
#include "g_https_cb.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

https_request *https_request_alloc(size_t bufsize, unsigned int flags, unsigned timeout);

void ui_display_stats(const char *type, uint64_t direct, uint64_t peers) {}
bool network_process_udp_cb(network *n, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen) { return false; }
ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6) { return -1; }

int main(int argc, char *argv[])
{
    char *port_s = "8006";

    for (;;) {
        int c = getopt(argc, argv, "T:p:v");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            port_s = optarg;
            break;
        case 'v':
            o_debug++;
            break;
        default:
            log_error("Unhandled argument: %c\n", c);
            return 1;
        }
    }

    port_t port = atoi(port_s);
    __block network *n = newnode_init("client", "com.newnode.client", &port, ^(const https_request *request, const char *url, https_complete_callback cb) {
        debug("https: %s\n", url);
        // note: do_https will call the completion callback if the request fails immediately
        return do_https(n, request, url, cb);
    });
    if (!n) {
        return 1;
    }

#ifdef __APPLE__
    newnode_thread(n);
    CFRunLoopRun();
    return 0;
#else
    return newnode_run(n);
#endif
}
