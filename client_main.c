#include <stdlib.h>

#include "newnode.h"
#include "network.h"
#include "thread.h"
#include "log.h"
#include "g_https_cb.h"
#include "https_wget.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

https_request *https_request_alloc(size_t bufsize, unsigned int flags, unsigned timeout);

void ui_display_stats(const char *type, uint64_t direct, uint64_t peers) {}

int main(int argc, char *argv[])
{
    char *port_s = "8006";

    for (;;) {
        int c = getopt(argc, argv, "p:v");
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
    __block network *n = newnode_init("client", "com.newnode.client", &port, ^(const char *url, https_complete_callback cb) {
        // can't reference 'n' here because 'n' is uninitialized when this block callback is declared
        debug("https: %s\n", url);
        https_request *request = https_request_alloc(0, 0, 15);
        // note: do_https will call the completion callback if the request fails immediately
        int64_t do_https(network *n, port_t port, const char *url, https_complete_callback cb, https_request *request);
        do_https(n, port, url, cb, request);
        free(request);
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
