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

#include <event2/thread.h>
#include <event2/event-config.h>

#include "network.h"
#include "timer.h"
#include "log.h"
#include "icmp_handler.h"
#include "utp_bufferevent.h"


uint64 utp_on_firewall(utp_callback_arguments *a)
{
    debug("Firewall allowing inbound connection\n");
    return 0;
}

uint64 utp_callback_sendto(utp_callback_arguments *a)
{
    network *n = (network*)utp_context_get_userdata(a->context);
    struct sockaddr_in *sin = (struct sockaddr_in *)a->address;

    //debug("sendto: %zd byte packet to %s:%d%s\n", a->len, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
    //      (a->flags & UTP_UDP_DONTFRAG) ? "  (DF bit requested, but not yet implemented)" : "");

    if (o_debug >= 3) {
        hexdump(a->buf, a->len);
    }

    sendto(n->fd, a->buf, a->len, 0, a->address, a->address_len);
    return 0;
}

uint64 utp_callback_log(utp_callback_arguments *a)
{
    fprintf(stderr, "log: %s\n", a->buf);
    return 0;
}

uint64 utp_on_error(utp_callback_arguments *a)
{
    fprintf(stderr, "Error: %s\n", utp_error_code_names[a->error_code]);
    return 0;
}

void udp_read(evutil_socket_t fd, short events, void *arg)
{
    network *n = (network*)arg;

#ifdef __linux__
    // ugg, libevent doesn't tell us about POLLERR
    // https://github.com/libevent/libevent/issues/495
    icmp_handler(n);
#endif

    for (;;) {
        struct sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        unsigned char buf[4096];
        ssize_t len = recvfrom(n->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED || errno == ECONNRESET) {
                utp_issue_deferred_acks(n->utp);
                break;
            }
            pdie("recv");
        }

        if (o_debug) {
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            getnameinfo((struct sockaddr *)&src_addr, addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
            //debug("Received %zd byte UDP packet from %s:%s\n", len, host, serv);
        }

        if (o_debug >= 3) {
            hexdump(buf, len);
        }

        if (utp_process_udp(n->utp, buf, len, (struct sockaddr *)&src_addr, addrlen)) {
            continue;
        }
        if (dht_process_udp(n->dht, buf, len, (struct sockaddr *)&src_addr, addrlen)) {
            continue;
        }
    }
}

void libevent_log_cb(int severity, const char *msg)
{
    debug("[libevent] %d %s\n", severity, msg);
}

void evdns_log_cb(int severity, const char *msg)
{
    debug("[evdns] %d %s\n", severity, msg);
}

network* network_setup(char *address, char *port)
{
    signal(SIGPIPE, SIG_IGN);

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

    network *n = alloc(network);

    n->fd = socket(((struct sockaddr*)res->ai_addr)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (n->fd < 0) {
        pdie("socket");
    }

#ifdef __linux__
    int on = 1;
    if (setsockopt(n->fd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        pdie("setsockopt");
    }
#endif

    if (bind(n->fd, res->ai_addr, res->ai_addrlen) != 0) {
        pdie("bind");
    }

    freeaddrinfo(res);

    struct sockaddr_storage sin;
    socklen_t len = sizeof(sin);
    if (getsockname(n->fd, (struct sockaddr *)&sin, &len) != 0) {
        pdie("getsockname");
    }

    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    error = getnameinfo((struct sockaddr *)&sin, len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    if (error) {
        die("getnameinfo: %s\n", gai_strerror(error));
    }

    printf("listening on UDP:%s:%s\n", host, serv);

    n->dht = dht_setup(n->fd);

    n->utp = utp_init(2);

    utp_context_set_userdata(n->utp, n);

    utp_set_callback(n->utp, UTP_LOG, &utp_callback_log);
    utp_set_callback(n->utp, UTP_SENDTO, &utp_callback_sendto);
    utp_set_callback(n->utp, UTP_ON_FIREWALL, &utp_on_firewall);
    utp_set_callback(n->utp, UTP_ON_ERROR, &utp_on_error);
    utp_set_callback(n->utp, UTP_ON_STATE_CHANGE, &utp_on_state_change);
    utp_set_callback(n->utp, UTP_ON_READ, &utp_on_read);

    if (o_debug >= 2) {
        utp_context_set_option(n->utp, UTP_LOG_NORMAL, 1);
        utp_context_set_option(n->utp, UTP_LOG_MTU, 1);
        utp_context_set_option(n->utp, UTP_LOG_DEBUG, 1);
    }

#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
    evthread_use_pthreads();
#elif defined(EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED)
    evthread_use_windows_threads();
#endif

    event_enable_debug_mode();
    //event_enable_debug_logging(EVENT_DBG_ALL);

    event_set_log_callback(libevent_log_cb);
    evdns_set_log_fn(evdns_log_cb);

    n->evbase = event_base_new();
    if (!n->evbase) {
        fprintf(stderr, "event_base_new failed\n");
        return NULL;
    }

    n->evdns = evdns_base_new(n->evbase, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    if (!n->evdns) {
        fprintf(stderr, "evdns_base_new failed\n");
        return NULL;
    }

    n->http = evhttp_new(n->evbase);
    if (!n->http) {
        fprintf(stderr, "evhttp_new failed\n");
        return NULL;
    }

    debug("libevent method: %s\n", event_base_get_method(n->evbase));

    if (evthread_make_base_notifiable(n->evbase)) {
        fprintf(stderr, "evthread_make_base_notifiable failed\n");
        return NULL;
    }

    evutil_make_socket_closeonexec(n->fd);
    evutil_make_socket_nonblocking(n->fd);

    event_assign(&n->udp_event, n->evbase, n->fd, EV_READ|EV_PERSIST, udp_read, n);
    if (event_add(&n->udp_event, NULL) < 0) {
        fprintf(stderr, "event_add udp_read failed\n");
        return NULL;
    }

    timer_repeating(n, 500, ^{
        utp_check_timeouts(n->utp);
        dht_tick(n->dht);
    });

    return n;
}

int network_loop(network *n)
{
    event_base_dispatch(n->evbase);

    utp_context_stats *stats = utp_get_context_stats(n->utp);

    if (stats) {
        debug("           Bucket size:    <23    <373    <723    <1400    >1400\n");
        debug("Number of packets sent:  %5d   %5d   %5d    %5d    %5d\n",
              stats->_nraw_send[0], stats->_nraw_send[1], stats->_nraw_send[2], stats->_nraw_send[3], stats->_nraw_send[4]);
        debug("Number of packets recv:  %5d   %5d   %5d    %5d    %5d\n",
              stats->_nraw_recv[0], stats->_nraw_recv[1], stats->_nraw_recv[2], stats->_nraw_recv[3], stats->_nraw_recv[4]);
    } else {
        debug("utp_get_context_stats() failed?\n");
    }

    debug("Destroying network context\n");
    utp_destroy(n->utp);
    dht_destroy(n->dht);
    close(n->fd);

    return 0;
}
