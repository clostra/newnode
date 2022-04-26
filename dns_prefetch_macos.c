#include <dns_sd.h>
#include <fcntl.h>
#include <stdbool.h>
#include "nn_features.h"
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
    network *n;
} dns_prefetch_request;

void dns_prefetch_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                           DNSServiceErrorType errorCode, const char *fullname,
                           const sockaddr *address, uint32_t ttl, void *context)
{
    dns_prefetch_request *result = (dns_prefetch_request*)context;
    socklen_t sockaddrsize = sockaddr_get_length(address);

    if (errorCode != 0) {
        debug("%s host:%s errorCode:%d\n", __func__, result->host, errorCode);
        return;
    }

    nn_addrinfo *a = alloc(nn_addrinfo);
    time_t now = time(0);
    a->ai_addr = memdup(address, sockaddrsize);
    a->ai_addrlen = sockaddrsize;
    a->ai_expiry = now + ttl;
    debug("%s host:%s address:%s ttl:%d expiry:%s", __func__, result->host, sockaddr_str_addronly(a->ai_addr), ttl, ctime(&a->ai_expiry));
    // this callback will often get called more than once per
    // query.  in each case we append the new address to the
    // result list, and store the head of that list in result->result.
    if (result->result == 0) {
        result->result = a;
    } else {
        if (result->lastresult) {
            result->lastresult->ai_next = a;
        }
    }
    result->lastresult = a;
    // if (o_debug) {
    //     debug("%s addresses for %s are now:\n", __func__, result->host);
    //     nn_addrinfo *nn;
    //     for (nn = result->result; nn; nn=nn->ai_next) {
    //         debug("    %s\n", sockaddr_str_addronly(nn->ai_addr));
    //     }
    // }
    if ((flags & kDNSServiceFlagsMoreComing) == 0) {
        network *n = result->n;
        // no more DNS responses immediately queued, go ahead and update result
        network_async(n, ^{
            dns_prefetch_store_result(n, result->result_index, result->result_id, result->result, result->host, false);
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
        free(request);
    }
}

void platform_dns_prefetch(network *n, size_t result_index, uint64_t result_id, const char *host)
{
    if (host == NULL || *host == '\0') {
        return;
    }

    dns_prefetch_request *request = alloc(dns_prefetch_request);
    request->host = strdup(host);
    request->result_index = result_index;
    request->result_id = result_id;
    request->n = n;

    // No matter which kinds of addresses we request,
    // DNSServiceGetAddrInfo won't return A records unless we have a
    // routable IPv4 address, and won't return AAAA records unless we
    // have a routable IPv6 address.  This is great for initiating
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

    evutil_socket_t fd = DNSServiceRefSockFD(request->sd);
    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);

    // arrange for query results to be processed
    request->event = event_new(n->evbase, fd, EV_READ|EV_TIMEOUT, platform_dns_event_cb, (void *) request);
    timeval timeout = { 10, 0 }; // ten seconds
    event_add(request->event, &timeout);

    debug("%s queued request for %s\n", __func__, host);
}
