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


typedef struct ip_mreq ip_mreq;
void lsd_setup(network *n);

int lsd_fd = -1;
event lsd_event;
event route_event;

bool starts_with(const char *restrict string, const char *restrict prefix)
{
    while (*prefix) {
        if (*prefix++ != *string++) {
            return false;
        }
    }
    return true;
}

void lsd_send(network *n, bool reply)
{
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
            if (errno == ENETDOWN || errno == ENETUNREACH) {
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
        if (starts_with((char*)packet, "NN-SEARCH ")) {
            lsd_send(n, true);
        } else if (!starts_with((char*)packet, "NN-REPLY ")) {
            continue;
        }
        char *p = strstr((char*)packet, "Port: ");
        if (p) {
            p += strlen("Port: ");
            char *e = strstr(p, "\r\n");
            *e = '\0';
            sockaddr_set_port((sockaddr*)&addr, (port_t)atoi(p));
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            getnameinfo((sockaddr *)&addr, addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
            //debug("lsd peer %s:%s\n", host, serv);
            add_sockaddr(n, (sockaddr *)&addr, addrlen);
        }
    }
}

void route_read_cb(evutil_socket_t fd, short events, void *arg)
{
    network *n = arg;
    char buf[2048];
    read(fd, buf, sizeof(buf));
    lsd_setup(n);
}

void lsd_setup(network *n)
{
    timer_callback cb = ^{
        lsd_send(n, false);
    };
    if (lsd_fd != -1) {
        evutil_closesocket(lsd_fd);
        event_del(&lsd_event);
    } else {
#ifdef __linux__
        int route_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
#else
        int route_fd = socket(PF_ROUTE, SOCK_RAW, 0);
#endif

        evutil_make_socket_closeonexec(route_fd);
        evutil_make_socket_nonblocking(route_fd);

        event_assign(&route_event, n->evbase, route_fd, EV_READ|EV_PERSIST, route_read_cb, n);
        event_add(&route_event, NULL);

        timer_repeating(n, 25 * 60 * 1000, cb);
    }
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

    cb();
}
