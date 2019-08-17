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
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <netdb.h>
#include <signal.h>

#include <sodium.h>

#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>

#ifdef ANDROID
#include <sys/system_properties.h>
#endif

#include "log.h"
#include "lsd.h"
#include "http.h"
#include "timer.h"
#include "network.h"
#include "icmp_handler.h"
#include "utp_bufferevent.h"


uint64 utp_on_firewall(utp_callback_arguments *a)
{
    return 0;
}

uint64 utp_callback_sendto(utp_callback_arguments *a)
{
    network *n = (network*)utp_context_get_userdata(a->context);

    //sockaddr_in *sin = (sockaddr_in *)a->address;
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

void dht_schedule(network *n, time_t tosleep)
{
    if (n->dht_timer) {
        timer_cancel(n->dht_timer);
    }
    n->dht_timer = timer_start(n, tosleep * 1000, ^{
        n->dht_timer = NULL;
        dht_schedule(n, dht_tick(n->dht));
    });
}

void udp_read(evutil_socket_t fd, short events, void *arg);

bool network_make_socket(network *n)
{
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo *res;
    char port_s[6];
    snprintf(port_s, sizeof(port_s), "%u", n->port);
    int error = getaddrinfo(n->address, port_s, &hints, &res);
    if (error) {
        die("getaddrinfo: %s\n", gai_strerror(error));
    }

    n->fd = socket(((sockaddr*)res->ai_addr)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (n->fd < 0) {
        pdie("socket");
    }

#ifdef __linux__
    int on = 1;
    if (setsockopt(n->fd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        pdie("setsockopt");
    }
#endif

    port_t port = n->port;
    for (;;) {
        if (bind(n->fd, res->ai_addr, res->ai_addrlen) != 0) {
            debug("bind fail %d %s\n", errno, strerror(errno));
            if (port == 0) {
                pdie("bind");
            }
            freeaddrinfo(res);
            port = 0;
            snprintf(port_s, sizeof(port_s), "%u", port);
            error = getaddrinfo(n->address, port_s, &hints, &res);
            if (error) {
                die("getaddrinfo: %s\n", gai_strerror(error));
            }
            continue;
        }
        freeaddrinfo(res);
        break;
    }

    evutil_make_socket_closeonexec(n->fd);
    evutil_make_socket_nonblocking(n->fd);

    sockaddr_storage sin;
    socklen_t len = sizeof(sin);
    if (getsockname(n->fd, (sockaddr *)&sin, &len) != 0) {
        pdie("getsockname");
    }

    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    error = getnameinfo((sockaddr *)&sin, len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    if (error) {
        die("getnameinfo: %s\n", gai_strerror(error));
    }

    event_assign(&n->udp_event, n->evbase, n->fd, EV_READ|EV_PERSIST, udp_read, n);
    if (event_add(&n->udp_event, NULL) < 0) {
        fprintf(stderr, "event_add udp_read failed\n");
        return false;
    }

    if (n->dht) {
        // the dht has to be re-created when the fd changes
        dht_destroy(n->dht);
        n->dht = NULL;
    }
    n->dht = dht_setup(n);

    printf("listening on UDP:%s:%s\n", host, serv);

    return true;
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
        sockaddr_storage src_addr;
        socklen_t addrlen = sizeof(src_addr);
        unsigned char buf[64 * 1024 + 1];
        ssize_t len = recvfrom(n->fd, buf, sizeof(buf), 0, (sockaddr *)&src_addr, &addrlen);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED ||
                errno == ECONNRESET || errno == EHOSTUNREACH || errno == ENETUNREACH) {
                utp_issue_deferred_acks(n->utp);
                break;
            }
            debug("%s recvfrom error %d %s\n", __func__, errno, strerror(errno));
            if (errno == ENOTCONN) {
                // recreate socket
                debug("%s recreating socket\n", __func__);
                event_del(&n->udp_event);
                evutil_closesocket(n->fd);
                network_make_socket(n);
            }
            break;
        }

        if (o_debug) {
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            getnameinfo((sockaddr *)&src_addr, addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
            //debug("Received %zd byte UDP packet from %s:%s\n", len, host, serv);
        }

        if (o_debug >= 3) {
            hexdump(buf, len);
        }

        if (utp_process_udp(n->utp, buf, len, (sockaddr *)&src_addr, addrlen)) {
            continue;
        }
        time_t tosleep;
        bool r = dht_process_udp(n->dht, buf, len, (sockaddr *)&src_addr, addrlen, &tosleep);
        dht_schedule(n, tosleep);
        if (r) {
            continue;
        }
    }
}

void evbuffer_hash_update(evbuffer *buf, crypto_generichash_state *content_state)
{
    evbuffer_ptr ptr;
    evbuffer_ptr_set(buf, &ptr, 0, EVBUFFER_PTR_SET);
    evbuffer_iovec v;
    while (evbuffer_peek(buf, -1, &ptr, &v, 1) > 0) {
        crypto_generichash_update(content_state, v.iov_base, v.iov_len);
        if (evbuffer_ptr_set(buf, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
}

bool evbuffer_write_to_file(evbuffer *buf, int fd)
{
    uint vecs_len = 0;
    iovec vecs[16384];
    ssize_t byte_total = 0;
    evbuffer_ptr ptr;
    evbuffer_ptr_set(buf, &ptr, 0, EVBUFFER_PTR_SET);
    evbuffer_iovec v;
    while (evbuffer_peek(buf, -1, &ptr, &v, 1) > 0) {
        vecs[vecs_len].iov_base = v.iov_base;
        vecs[vecs_len].iov_len = v.iov_len;
        vecs_len++;
        assert(vecs_len < lenof(vecs));
        byte_total += v.iov_len;
        if (evbuffer_ptr_set(buf, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
    ssize_t w = writev(fd, vecs, vecs_len);
    if (w != byte_total) {
        fprintf(stderr, "fd:%d write failed %d (%s)\n", fd, errno, strerror(errno));
        return false;
    }
    return true;
}

void evbuffer_clear(evbuffer *buf)
{
    // XXX: should unfreeze/freeze start depnding on input or output
    int start = 1;
    evbuffer_unfreeze(buf, start);
    evbuffer_drain(buf, evbuffer_get_length(buf));
    evbuffer_freeze(buf, start);
    assert(!evbuffer_get_length(buf));
}

void bufferevent_free_checked(bufferevent *bev)
{
    assert(!bufferevent_get_enabled(bev));
    assert(!evbuffer_get_length(bufferevent_get_input(bev)));
    assert(!evbuffer_get_length(bufferevent_get_output(bev)));
    bufferevent_free(bev);
}

int bufferevent_get_error(bufferevent *bev)
{
    int dns_err = bufferevent_socket_get_dns_error(bev);
    int err = evutil_socket_geterror(bufferevent_getfd(bev));
    if (dns_err) {
        err = EHOSTUNREACH;
    }
    return err;
}

void libevent_log_cb(int severity, const char *msg)
{
    if (severity > EVENT_LOG_DEBUG || o_debug > 1) {
        debug("[libevent] %d %s\n", severity, msg);
    }
}

void evdns_log_cb(int severity, const char *msg)
{
    if (severity > EVENT_LOG_DEBUG || o_debug > 1) {
        debug("[evdns] %d %s\n", severity, msg);
    }
}

bufferevent* create_bev(event_base *base, void *userdata)
{
    return bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
}

uint64 utp_callback_get_random(utp_callback_arguments *args)
{
    uint64_t r;
    randombytes_buf(&r, sizeof(r));
    return r;
}

const char* bev_events_to_str(short events)
{
    static char s[1024];
    snprintf(s, sizeof(s), "%s%s%s%s%s%s",
             events & BEV_EVENT_READING ? "reading " : "",
             events & BEV_EVENT_WRITING ? "writing " : "",
             events & BEV_EVENT_EOF ? "eof " : "",
             events & BEV_EVENT_ERROR ? "error " : "",
             events & BEV_EVENT_TIMEOUT ? "timeout " : "",
             events & BEV_EVENT_CONNECTED ? "connected " : ""
             );
    return s;
}

port_t sockaddr_get_port(const sockaddr* sa)
{
    switch (sa->sa_family) {
    default:
    case AF_INET:
        return ntohs(((sockaddr_in*)sa)->sin_port);
    case AF_INET6:
        return ntohs(((sockaddr_in6*)sa)->sin6_port);
    }
}

void sockaddr_set_port(sockaddr* sa, port_t port)
{
    switch (sa->sa_family) {
    case AF_INET:
        ((sockaddr_in*)sa)->sin_port = htons(port);
        return;
    case AF_INET6: {
        ((sockaddr_in6*)sa)->sin6_port = htons(port);
        return;
    }
    }
}

void set_max_nofile()
{
    rlimit nofile;
    int r = getrlimit(RLIMIT_NOFILE, &nofile);
    debug("getrlimit: r:%d cur:%zu max:%zu\n", r, (size_t)nofile.rlim_cur, (size_t)nofile.rlim_max);
    for (rlim_t max = nofile.rlim_max; ;) {
        rlim_t mid = (max - nofile.rlim_cur) / 2;
        if (!mid) {
            break;
        }
        nofile.rlim_cur += mid;
        r = setrlimit(RLIMIT_NOFILE, &nofile);
        if (r) {
            max = nofile.rlim_cur;
            nofile.rlim_cur -= mid;
        }
    }
    r = getrlimit(RLIMIT_NOFILE, &nofile);
    debug("getrlimit: r:%d cur:%zu max:%zu\n", r, (size_t)nofile.rlim_cur, (size_t)nofile.rlim_max);
}

void network_free(network *n)
{
    utp_destroy(n->utp);
    dht_destroy(n->dht);
    free(n->address);
    evutil_closesocket(n->fd);
    evdns_base_free(n->evdns, 0);
    event_base_free(n->evbase);
    free(n);
}

network* network_setup(char *address, port_t port)
{
    signal(SIGPIPE, SIG_IGN);

    set_max_nofile();

    network *n = alloc(network);

    n->address = strdup(address);
    n->port = port;

#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
    evthread_use_pthreads();
#elif defined(EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED)
    evthread_use_windows_threads();
#endif

    event_enable_debug_mode();
    if (o_debug) {
        event_enable_debug_logging(EVENT_DBG_ALL);
    }

    event_set_log_callback(libevent_log_cb);
    evdns_set_log_fn(evdns_log_cb);

    n->evbase = event_base_new();
    if (!n->evbase) {
        fprintf(stderr, "event_base_new failed\n");
        network_free(n);
        return NULL;
    }

    fprintf(stderr, "libevent method: %s\n", event_base_get_method(n->evbase));

    // EVDNS_BASE_INITIALIZE_NAMESERVERS is broken on Android
    // https://github.com/libevent/libevent/issues/569
    n->evdns = evdns_base_new(n->evbase, 0);
    if (!n->evdns) {
        fprintf(stderr, "evdns_base_new failed\n");
        network_free(n);
        return NULL;
    }
#ifdef _WIN32
    evdns_base_config_windows_nameservers(n->evdns);
#else
    evdns_base_resolv_conf_parse(n->evdns, DNS_OPTION_HOSTSFILE, "/etc/resolv.conf");
#endif

#ifdef ANDROID
    char buf[PROP_VALUE_MAX];
    if (__system_property_get("net.dns1", buf)) {
        evdns_base_nameserver_ip_add(n->evdns, buf);
    }
    if (__system_property_get("net.dns2", buf)) {
        evdns_base_nameserver_ip_add(n->evdns, buf);
    }
#endif

    evdns_base_nameserver_ip_add(n->evdns, "8.8.8.8");
    evdns_base_nameserver_ip_add(n->evdns, "8.8.4.4");

    n->http = evhttp_new(n->evbase);
    if (!n->http) {
        fprintf(stderr, "evhttp_new failed\n");
        network_free(n);
        return NULL;
    }
    // don't add any content type automatically
    evhttp_set_default_content_type(n->http, NULL);
    evhttp_set_bevcb(n->http, create_bev, NULL);

    if (evthread_make_base_notifiable(n->evbase)) {
        fprintf(stderr, "evthread_make_base_notifiable failed\n");
        network_free(n);
        return NULL;
    }

    if (!network_make_socket(n)) {
        network_free(n);
        return NULL;
    }

    n->utp = utp_init(2);
    lsd_setup(n);

    utp_context_set_userdata(n->utp, n);

    utp_set_callback(n->utp, UTP_GET_RANDOM, &utp_callback_get_random);
    utp_set_callback(n->utp, UTP_LOG, &utp_callback_log);
    utp_set_callback(n->utp, UTP_SENDTO, &utp_callback_sendto);
    utp_set_callback(n->utp, UTP_ON_FIREWALL, &utp_on_firewall);
    utp_set_callback(n->utp, UTP_ON_ACCEPT, &utp_on_accept);
    utp_set_callback(n->utp, UTP_ON_ERROR, &utp_on_error);
    utp_set_callback(n->utp, UTP_ON_STATE_CHANGE, &utp_on_state_change);
    utp_set_callback(n->utp, UTP_ON_READ, &utp_on_read);

    if (o_debug >= 2) {
        utp_context_set_option(n->utp, UTP_LOG_NORMAL, 1);
        utp_context_set_option(n->utp, UTP_LOG_MTU, 1);
        utp_context_set_option(n->utp, UTP_LOG_DEBUG, 1);
    }

    // XXX: TODO: only run while (ctx->utp_sockets->GetCount() && ctx->rst_info.GetCount())
    timer_repeating(n, 500, ^{
        utp_check_timeouts(n->utp);
    });

    dht_schedule(n, 0);

    return n;
}

void sigterm_cb(evutil_socket_t sig, short events, void *ctx)
{
    event_base_loopexit((event_base*)ctx, NULL);
}

int network_loop(network *n)
{
    event *sigterm = evsignal_new(n->evbase, SIGTERM, sigterm_cb, n->evbase);
    event_add(sigterm, NULL);

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
    event_free(sigterm);
    network_free(n);

    return 0;
}
