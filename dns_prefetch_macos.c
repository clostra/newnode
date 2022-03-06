#include <dns_sd.h>
#include <fcntl.h>
#include <stdbool.h>
#include "features.h"
#include "log.h"
#include "network.h"
#include "dns_prefetch.h"


typedef struct {
    DNSServiceRef sd;
    char *host;
    nn_addrinfo *result;
    nn_addrinfo *lastresult;
    event *event;
    uint64_t result_id;
    size_t result_index;
} dns_prefetch_request;

void dns_prefetch_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                           DNSServiceErrorType errorCode, const char *fullname,
                           const sockaddr *address, uint32_t ttl, void *context)
{
    dns_prefetch_request *result = (dns_prefetch_request *) context;
    unsigned int sockaddrsize = sockaddr_get_length(address);

    if (errorCode != 0) {
        debug("%s host:%s errorCode:%d\n", __func__, result->host, errorCode);
        return;
    }

    nn_addrinfo *n = alloc(nn_addrinfo);
    time_t now = time(0);
    n->ai_addr = calloc(1, sockaddrsize);
    n->ai_addrlen = sockaddrsize;
    memcpy((void *) n->ai_addr, (void *) address, sockaddrsize);
    n->ai_expiry = now + ttl;
    debug("%s host:%s address:%s ttl:%d expiry:%s", __func__, result->host, sockaddr_str_addronly(n->ai_addr), ttl, ctime(&n->ai_expiry));
    // this callback will often get called more than once per
    // query.  in each case we append the new address to the
    // result list, and store the head of that list in result->result.
    if (result->result == 0) {
        result->result = n;
    } else {
        if (result->lastresult) {
            result->lastresult->ai_next = n;
        }
    }
    result->lastresult = n;
    if (o_debug) {
        debug("%s addresses for %s are now:\n", __func__, result->host);
        nn_addrinfo *nn;
        for (nn = result->result; nn; nn=nn->ai_next) {
            debug("    %s\n", sockaddr_str_addronly(nn->ai_addr));
        }
    }
    if ((flags & kDNSServiceFlagsMoreComing) == 0) {
        // no more DNS responses immediately queued, go ahead and update result
        extern network *g_n;
        // XXX are we assured that if there are multiple calls to
        //     dns_prefetch_callback (e.g. because both A and AAAA
        //     records were returned from separate queries), that the
        //     timer callbacks will happen in order?
        network_async(g_n, ^{
            dns_prefetch_store_result(result->result_index, result->result_id, result->result, result->host, false);
        });
    }
}

void platform_dns_event_cb(evutil_socket_t fd, short what, void *arg)
{
    dns_prefetch_request *request = (dns_prefetch_request *) arg;

    if (what & EV_READ) {
        // debug("%s EV_READ\n", __func__);
        if (request && request->sd) {
            // this arranges to call dns_prefetch_callback() above 
            // (the Apple DNS library lets you use your own event handler)
            int err = DNSServiceProcessResult(request->sd);
            if (err != kDNSServiceErr_NoError) {
                debug("%s: host:%s error %d\n", __func__, request->host, err);
            }
        }
    }
    if (what & EV_TIMEOUT) {
        // debug("%s EV_TIMEOUT\n", __func__);
        event_free(request->event);
        DNSServiceRefDeallocate(request->sd);
        free(request->host);
        request->host = NULL;
        request->result_index = 0;
        request->result_id = 0;
        free(request);
    }
}


void platform_dns_prefetch(int result_index, unsigned int result_id, const char *host)
{
    if (host == NULL || *host == '\0') {
        return;
    }

    dns_prefetch_request *request = alloc(dns_prefetch_request);
    request->host = strdup(host);
    request->result_index = result_index;
    request->result_id = result_id;

    // No matter which kinds of addresses we request,
    // DNSServiceGetAddrInfo won't return A records unless we have a
    // routable IPv4 address, and and won't return AAAA records unless
    // we have a routable IPv6 address.  This is great for initiating
    // connections from the local host, not so great if we pass these
    // addresses to a peer.
    DNSServiceErrorType error = DNSServiceGetAddrInfo(&(request->sd),               // DNSServiceRef
                                    kDNSServiceFlagsTimeout,      // flags
                                    0,                            // interfaceIndex (0 = all)
                                    kDNSServiceProtocol_IPv4|kDNSServiceProtocol_IPv6, // protocol
                                    host,                         // hostname
                                    dns_prefetch_callback,
                                    (void *) request);             // context
    if (error != kDNSServiceErr_NoError) {
        debug("%s error:%d\n", __func__, error);
        return;
    }

    int fd = DNSServiceRefSockFD(request->sd);
    extern network *g_n;
    timeval timeout = { 10, 0 }; // ten seconds

    // make socket nonblocking
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    // arrange for query results to be processed
    request->event = event_new(g_n->evbase, fd, EV_READ|EV_TIMEOUT, platform_dns_event_cb, (void *) request);
    event_add(request->event, &timeout);

    debug("%s queued request for %s\n", __func__, host);
}
