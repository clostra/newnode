#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <netdb.h>
#include <signal.h>

#include "network.h"
#include "log.h"
#include "icmp_handler.h"


int exit_code;
int quit_flag;

uint64 callback_on_firewall(utp_callback_arguments *a)
{
    debug("Firewall allowing inbound connection\n");
    return 0;
}

uint64 callback_sendto(utp_callback_arguments *a)
{
    int fd = (intptr_t)utp_context_get_userdata(a->context);
    struct sockaddr_in *sin = (struct sockaddr_in *)a->address;

    debug("sendto: %zd byte packet to %s:%d%s\n", a->len, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
          (a->flags & UTP_UDP_DONTFRAG) ? "  (DF bit requested, but not yet implemented)" : "");

    if (o_debug >= 3) {
        hexdump(a->buf, a->len);
    }

    sendto(fd, a->buf, a->len, 0, a->address, a->address_len);
    return 0;
}

uint64 callback_log(utp_callback_arguments *a)
{
    fprintf(stderr, "log: %s\n", a->buf);
    return 0;
}

void handler(int number)
{
    debug("caught signal\n");
    quit_flag = 1;
    exit_code++;
}

utp_context* network_setup(char *address, char *port)
{
    struct sigaction sigIntHandler = {.sa_handler = handler, .sa_flags = 0};
    sigemptyset(&sigIntHandler.sa_mask);
    sigaction(SIGINT, &sigIntHandler, NULL);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *res;
    int error = getaddrinfo(address, port, &hints, &res);
    if (error) {
        die("getaddrinfo: %s\n", gai_strerror(error));
    }

    int fd = socket(((struct sockaddr*)res->ai_addr)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        pdie("socket");
    }

#ifdef __linux__
    int on = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        pdie("setsockopt");
    }
#endif

    if (bind(fd, res->ai_addr, res->ai_addrlen) != 0) {
        pdie("bind");
    }

    freeaddrinfo(res);

    struct sockaddr_storage sin;
    socklen_t len = sizeof(sin);
    if (getsockname(fd, (struct sockaddr *)&sin, &len) != 0) {
        pdie("getsockname");
    }
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    getnameinfo((struct sockaddr *)&sin, sin.ss_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
    printf("listening on %s:%s\n", host, serv);

    utp_context *ctx = utp_init(2);
    debug("UTP context %p\n", ctx);

    utp_context_set_userdata(ctx, (void*)(intptr_t)fd);

    utp_set_callback(ctx, UTP_LOG, &callback_log);
    utp_set_callback(ctx, UTP_SENDTO, &callback_sendto);
    utp_set_callback(ctx, UTP_ON_FIREWALL, &callback_on_firewall);

    /*
    utp_set_callback(ctx, UTP_ON_ACCEPT, &callback_on_accept);
    utp_set_callback(ctx, UTP_ON_STATE_CHANGE, &callback_on_state_change);
    utp_set_callback(ctx, UTP_ON_READ, &callback_on_read);
    utp_set_callback(ctx, UTP_ON_ERROR, &callback_on_error);
    */

    if (o_debug >= 2) {
        utp_context_set_option(ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(ctx, UTP_LOG_DEBUG, 1);
    }

    return ctx;
}

void network_poll(utp_context *ctx)
{
    int fd = (intptr_t)utp_context_get_userdata(ctx);

    struct pollfd p[1];

    p[0].fd = fd;
    p[0].events = POLLIN;

    int ret = poll(p, lenof(p), 500);
    if (ret < 0) {
        if (errno == EINTR) {
            debug("poll() returned EINTR\n");
        } else {
            pdie("poll");
        }
    } else if (ret == 0) {
        if (o_debug >= 3) {
            debug("poll() timeout\n");
        }
    } else {

#ifdef __linux__
        if ((p[0].revents & POLLERR) == POLLERR) {
            icmp_handler(ctx);
        }
#endif

        if ((p[0].revents & POLLIN) == POLLIN) {
            for (;;) {
                struct sockaddr_storage src_addr;
                socklen_t addrlen = sizeof(src_addr);
                unsigned char socket_data[4096];
                ssize_t len = recvfrom(fd, socket_data, sizeof(socket_data), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);
                if (len < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        utp_issue_deferred_acks(ctx);
                        break;
                    }
                    pdie("recv");
                }

                char host[NI_MAXHOST];
                char serv[NI_MAXSERV];
                getnameinfo((struct sockaddr *)&src_addr, src_addr.ss_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
                debug("Received %zd byte UDP packet from %s:%\n", len, host, serv);
                if (o_debug >= 3) {
                    hexdump(socket_data, len);
                }

                if (!utp_process_udp(ctx, socket_data, len, (struct sockaddr *)&src_addr, addrlen)) {
                    debug("UDP packet not handled by UTP.  Ignoring.\n");
                }
            }
        }
    }

    utp_check_timeouts(ctx);
}

int network_loop(utp_context *ctx)
{
    while (!quit_flag) {
        network_poll(ctx);
    }

    utp_context_stats *stats = utp_get_context_stats(ctx);

    if (stats) {
        debug("           Bucket size:    <23    <373    <723    <1400    >1400\n");
        debug("Number of packets sent:  %5d   %5d   %5d    %5d    %5d\n",
              stats->_nraw_send[0], stats->_nraw_send[1], stats->_nraw_send[2], stats->_nraw_send[3], stats->_nraw_send[4]);
        debug("Number of packets recv:  %5d   %5d   %5d    %5d    %5d\n",
              stats->_nraw_recv[0], stats->_nraw_recv[1], stats->_nraw_recv[2], stats->_nraw_recv[3], stats->_nraw_recv[4]);
    } else {
        debug("utp_get_context_stats() failed?\n");
    }

    debug("Destorying context\n");
    utp_destroy(ctx);

    return exit_code;
}