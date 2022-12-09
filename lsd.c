#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __linux__
#include <asm/types.h>
#include <linux/netlink.h>
#endif

#include <event2/event-config.h>

#include "network.h"
#include "log.h"
#include "lsd.h"
#include "newnode.h"


typedef struct ip_mreq ip_mreq;
void lsd_setup(network *n);

static int lsd_fd = -1;
static int route_fd = -1;
static event lsd_event;
static event route_event;
static timer *route_timer;


#ifndef __APPLE__
/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char* strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}
#endif

void lsd_send(network *n, bool reply)
{
#if defined TARGET_OS_IOS && TARGET_OS_IOS
    // iOS 14 decided multicast sendto() should prompt the user
    if (!n->request_discovery_permission) {
        return;
    }
#endif

    sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    getsockname(n->fd, (sockaddr *)&ss, &sslen);

    char buf[1500];
    // XXX: TODO: remove SEARCH/REPLY once we have bidirectional peer connections
    int len = snprintf(buf, sizeof(buf),
                       "NN-%s * HTTP/1.1\r\n"
                       "Host: 239.192.0.0:9190\r\n"
                       "Port: %d\r\n"
                       "\r\n", reply?"REPLY":"SEARCH", sockaddr_get_port((sockaddr*)&ss));

    for (int i = 0; i < 3; i++) {
        sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr("239.192.0.0"),
            .sin_port = htons(9190),
#ifdef __APPLE__
            .sin_len = sizeof(addr)
#endif
        };
        if (sendto(lsd_fd, buf, len, 0, (sockaddr *)&addr, sizeof(addr)) == -1) {
            if (errno == ENETDOWN ||
                errno == ENETUNREACH ||
                errno == ENOBUFS) {
                return;
            }
            fprintf(stderr, "lsd error %d %s\n", errno, strerror(errno));
            return;
        }
    }
}

void lsd_read_cb(evutil_socket_t fd, short events, void *arg)
{
    network *n = arg;

    for (;;) {
        uint8_t packet[1500];
        sockaddr_storage addr;
        ev_socklen_t addrlen = sizeof(addr);
        ssize_t r = recvfrom(fd, (void*)packet, sizeof(packet), 0, (sockaddr*)&addr, &addrlen);
        if (r < 0) {
            int err = evutil_socket_geterror(fd);
            if (err == EAGAIN) {
                break;
            }
            fprintf(stderr, "recvfrom %d (%s)\n", err, evutil_socket_error_to_string(err));
            return;
        }
        // XXX: TODO: remove SEARCH/REPLY once we have bidirectional peer connections
        if (strnstr((char*)packet, "NN-SEARCH ", r) == 0) {
            lsd_send(n, true);
        } else if (strnstr((char*)packet, "NN-REPLY ", r) != 0) {
            continue;
        }
        char *p = strnstr((char*)packet, "Port: ", r);
        if (!p) {
            continue;
        }
        p += strlen("Port: ");
        char *e = strnstr(p, "\r\n", p - (char*)packet);
        if (!e) {
            continue;
        }
        *e = '\0';
        sockaddr_set_port((sockaddr*)&addr, (port_t)atoi(p));
        if (o_debug) {
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            getnameinfo((sockaddr *)&addr, addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
            debug("lsd peer %s:%s\n", host, serv);
        }
        if (n->sockaddr_cb) {
            n->sockaddr_cb((sockaddr *)&addr, addrlen);
        }
    }
}

void route_read_cb(evutil_socket_t fd, short events, void *arg)
{
    network *n = arg;
    char buf[2048];
    recv(fd, buf, sizeof(buf), 0);
    timer_cancel(route_timer);
    route_timer = timer_start(n, 500, ^{
        route_timer = NULL;
        lsd_setup(n);
    });
    if (n->ifchange_cb) {
        n->ifchange_cb();
    }
}

void lsd_setup(network *n)
{
    if (lsd_fd == -1 && route_fd == -1) {
        timer_repeating(n, 25 * 60 * 1000, ^{
            lsd_send(n, false);
        });
    }
    if (lsd_fd != -1) {
        evutil_closesocket(lsd_fd);
        event_del(&lsd_event);
    }
    if (route_fd != -1) {
        evutil_closesocket(route_fd);
        event_del(&route_event);
    }

#ifdef __linux__
    route_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
#else
    route_fd = socket(PF_ROUTE, SOCK_RAW, 0);
#endif

    evutil_make_socket_closeonexec(route_fd);
    evutil_make_socket_nonblocking(route_fd);

    event_assign(&route_event, n->evbase, route_fd, EV_READ|EV_PERSIST, route_read_cb, n);
    event_add(&route_event, NULL);

    lsd_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    int optval = 1;
    setsockopt(lsd_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(lsd_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(9190),
#ifdef __APPLE__
        .sin_len = sizeof(addr)
#endif
    };
    if (bind(lsd_fd, (sockaddr*)&addr, sizeof(addr))) {
        fprintf(stderr, "lsd bind %d %s\n", errno, strerror(errno));
    }

    // http://www.iana.org/assignments/multicast-addresses
    ip_mreq mreqv4 = {
        .imr_multiaddr.s_addr = inet_addr("239.192.0.0"),
        .imr_interface.s_addr = inet_addr("0.0.0.0")
    };
    if (setsockopt(lsd_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&mreqv4, sizeof(mreqv4))) {
        fprintf(stderr, "lsd IP_ADD_MEMBERSHIP %d %s\n", errno, strerror(errno));
    }
    in_addr mc_addr = {0};
    if (setsockopt(lsd_fd, IPPROTO_IP, IP_MULTICAST_IF, (const void *)&mc_addr, sizeof(mc_addr))) {
        fprintf(stderr, "lsd IP_MULTICAST_IF %d %s\n", errno, strerror(errno));
    }
    int option = 0;
    if (setsockopt(lsd_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (const void *)&option, sizeof(option))) {
        fprintf(stderr, "lsd IP_MULTICAST_LOOP %d %s\n", errno, strerror(errno));
    }
    option = 255;
    if (setsockopt(lsd_fd, IPPROTO_IP, IP_TTL, (const void *)&option, sizeof(option))) {
        fprintf(stderr, "lsd IP_TTL %d %s\n", errno, strerror(errno));
    }
    option = 255;
    if (setsockopt(lsd_fd, IPPROTO_IP, IP_MULTICAST_TTL, (const void *)&option, sizeof(option))) {
        fprintf(stderr, "lsd IP_MULTICAST_TTL %d %s\n", errno, strerror(errno));
    }

    evutil_make_socket_closeonexec(lsd_fd);
    evutil_make_socket_nonblocking(lsd_fd);

    event_assign(&lsd_event, n->evbase, lsd_fd, EV_READ|EV_PERSIST, lsd_read_cb, n);
    event_add(&lsd_event, NULL);

    network_async(n, ^{
        lsd_send(n, false);
    });
}
