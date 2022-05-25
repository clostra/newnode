#include <dns_sd.h>
#include <fcntl.h>
#include <stdbool.h>

#include "libevent/util-internal.h"

#include "nn_features.h"
#include "log.h"
#include "network.h"
#include "dns_prefetch.h"


typedef struct {
    DNSServiceRef sd;
    char *host;
    evutil_addrinfo *ai;
    uint32_t min_ttl;
    event *event;
    network *n;
} dns_prefetch_request;

void dns_prefetch_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                           DNSServiceErrorType errorCode, const char *fullname,
                           const sockaddr *address, uint32_t ttl, void *context)
{
    dns_prefetch_request *reqeust = (dns_prefetch_request*)context;

    if (errorCode != 0) {
        debug("%s host:%s errorCode:%d\n", __func__, reqeust->host, errorCode);
        return;
    }

    socklen_t addrlen = sockaddr_get_length(address);
    evutil_addrinfo nullhints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    evutil_addrinfo *a = evutil_new_addrinfo_((sockaddr*)address, addrlen, &nullhints);
    debug("%s host:%s address:%s ttl:%d\n", __func__, reqeust->host, sockaddr_str_addronly(a->ai_addr), ttl);
    reqeust->min_ttl = !reqeust->min_ttl ? ttl : MIN(reqeust->min_ttl, ttl);
    request->ai = evutil_addrinfo_append_(reqeust->ai, a);
    if (!(flags & kDNSServiceFlagsMoreComing)) {
        network *n = reqeust->n;
        // no more DNS responses immediately queued, go ahead and update result
        network_async(n, ^{
            dns_prefetch_store_result(n, reqeust->ai, reqeust->host, reqeust->min_ttl);
        });
    }
}

void platform_dns_event_cb(evutil_socket_t fd, short what, void *arg)
{
    dns_prefetch_request *request = (dns_prefetch_request*)arg;

    if (what & EV_READ) {
        // this arranges to call dns_prefetch_callback() above
        // (the Apple DNS library lets you use your own event handler)
        DNSServiceErrorType error = DNSServiceProcessResult(request->sd);
        if (error != kDNSServiceErr_NoError) {
            debug("%s: host:%s error:%d\n", __func__, request->host, error);
        }
        return;
    }

    if (what & EV_TIMEOUT) {
        event_free(request->event);
        DNSServiceRefDeallocate(request->sd);
        evutil_freeaddrinfo(request->ai);
        free(request->host);
        free(request);
    }
}

void platform_dns_prefetch(network *n, const char *host)
{
    if (host == NULL || *host == '\0') {
        return;
    }

    dns_prefetch_request *request = alloc(dns_prefetch_request);
    request->host = strdup(host);
    request->n = n;

    // No matter which kinds of addresses we reaquest,
    // DNSServiceGetAddrInfo won't return A records unless we have a
    // routable IPv4 address, and won't return AAAA records unless we
    // have a routable IPv6 address.  This is great for initiating
    // connections from the local host, not so great if we pass these
    // addresses to a peer.
    DNSServiceErrorType error = DNSServiceGetAddrInfo(&request->sd,
                                    kDNSServiceFlagsTimeout,
                                    0,
                                    kDNSServiceProtocol_IPv4|kDNSServiceProtocol_IPv6,
                                    host,
                                    dns_prefetch_callback,
                                    (void*)request);
    if (error != kDNSServiceErr_NoError) {
        debug("%s error:%d\n", __func__, error);
        return;
    }

    evutil_socket_t fd = DNSServiceRefSockFD(request->sd);
    evutil_make_socket_closeonexec(fd);
    evutil_make_socket_nonblocking(fd);

    // arrange for query results to be processed
    request->event = event_new(n->evbase, fd, EV_READ|EV_TIMEOUT, platform_dns_event_cb, (void*)request);
    timeval timeout = { 10, 0 }; // ten seconds
    event_add(request->event, &timeout);

    debug("%s queued request for %s\n", __func__, host);
}
