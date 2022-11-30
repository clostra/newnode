#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <netdb.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>

#include <sodium.h>

#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include "libevent/event-internal.h"

#ifdef ANDROID
#include <sys/system_properties.h>
#endif

#include "log.h"
#include "lsd.h"
#include "d2d.h"
#include "http.h"
#include "timer.h"
#include "network.h"
#include "icmp_handler.h"
#include "bufferevent_utp.h"


uint64 utp_on_firewall(utp_callback_arguments *a)
{
    network *n = (network*)utp_context_get_userdata(a->context);
    if (n->http && evhttp_get_connection_count(n->http) > 100000) {
        return 1;
    }
    return 0;
}

const in6_addr v4_anyaddr = {.s6_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }};
const in6_addr v4_noaddr = {.s6_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

void map4to6(const in_addr *in, in6_addr *out)
{
    if (in->s_addr == 0x00000000) {
        *out = v4_anyaddr;
    } else if (in->s_addr == 0xFFFFFFFF) {
        *out = v4_noaddr;
    } else {
        *out = v4_anyaddr;
        out->s6_addr[12] = ((uint8_t *)&in->s_addr)[0];
        out->s6_addr[13] = ((uint8_t *)&in->s_addr)[1];
        out->s6_addr[14] = ((uint8_t *)&in->s_addr)[2];
        out->s6_addr[15] = ((uint8_t *)&in->s_addr)[3];
    }
}

void map6to4(const in6_addr *in, in_addr *out)
{
    bzero(out, sizeof(in_addr));
    ((uint8_t *)&out->s_addr)[0] = in->s6_addr[12];
    ((uint8_t *)&out->s_addr)[1] = in->s6_addr[13];
    ((uint8_t *)&out->s_addr)[2] = in->s6_addr[14];
    ((uint8_t *)&out->s_addr)[3] = in->s6_addr[15];
}

ssize_t udp_sendto(int fd, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen)
{
    ddebug("sendto(%zd, %s)\n", len, sockaddr_str(sa));

    if (o_debug >= 3) {
        hexdump(buf, len);
    }

    sockaddr_in6 sin6 = {0};
    if (sa->sa_family == AF_INET) {
        const sockaddr_in *sin = (const sockaddr_in *)sa;
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = sin->sin_port;
#ifdef __APPLE__
        sin6.sin6_len = sizeof(sin6);
#endif
        map4to6(&sin->sin_addr, &sin6.sin6_addr);
        sa = (sockaddr*)&sin6;
        salen = sizeof(sin6);
    }

    if (sa->sa_family == AF_INET6 && d2d_sendto != NULL) {
        const sockaddr_in6 *s6 = (const sockaddr_in6 *)sa;
        ssize_t r = d2d_sendto(buf, len, s6);
        if (r > 0) {
            return r;
        }
    }

    ssize_t r = sendto(fd, buf, len, 0, sa, salen);
    if (r < 0 && errno != EHOSTUNREACH) {
        if (errno == ECONNREFUSED || errno == ECONNRESET ||
            errno == EHOSTUNREACH || errno == ENETUNREACH) {
            // ICMP
        } else {
            debug("sendto(%zu, %s) failed %d %s\n", len, sockaddr_str(sa), errno, strerror(errno));
        }
    }
    return r;
}

uint64 utp_callback_sendto(utp_callback_arguments *a)
{
    network *n = (network*)utp_context_get_userdata(a->context);
    return udp_sendto(n->fd, a->buf, a->len, a->address, a->address_len);
}

uint64 utp_callback_log(utp_callback_arguments *a)
{
    fprintf(stderr, "log: %s\n", a->buf);
    return 0;
}

void dht_schedule(network *n, time_t tosleep)
{
    timer_cancel(n->dht_timer);
    n->dht_timer = timer_start(n, tosleep * 1000, ^{
        n->dht_timer = NULL;
        dht_schedule(n, dht_tick(n->dht));
    });
}

void udp_read(evutil_socket_t fd, short events, void *arg);

bool network_make_socket(network *n)
{
    addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
        .ai_flags = AI_PASSIVE
    };

    addrinfo *res;
    char port_s[6];
    snprintf(port_s, sizeof(port_s), "%u", n->port);
    int error = getaddrinfo(n->address, port_s, &hints, &res);
    if (error) {
        log_error("%s getaddrinfo: %s\n", __func__, gai_strerror(error));
        return false;
    }

    n->fd = socket(res->ai_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (n->fd < 0) {
        log_errno("socket");
        return false;
    }

    int udp_sndbuf = 1048576;
    setsockopt(n->fd, SOL_SOCKET, SO_SNDBUF, (void *)&udp_sndbuf, sizeof(udp_sndbuf));

#ifdef __linux__
    int on = 1;
    if (setsockopt(n->fd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        log_errno("setsockopt");
        return false;
    }
#endif

#ifdef SO_RECV_ANYIF
    int optval = 1;
    setsockopt(n->fd, SOL_SOCKET, SO_RECV_ANYIF, &optval, sizeof(optval));
#endif

    port_t port = n->port;
    for (;;) {
        if (bind(n->fd, res->ai_addr, res->ai_addrlen) != 0) {
            if (port == 0) {
                log_errno("bind");
                return false;
            }
            debug("bind fail %d %s\n", errno, strerror(errno));
            freeaddrinfo(res);
            port = 0;
            snprintf(port_s, sizeof(port_s), "%u", port);
            error = getaddrinfo(n->address, port_s, &hints, &res);
            if (error) {
                log_error("%s getaddrinfo: %s\n", __func__, gai_strerror(error));
                return false;
            }
            continue;
        }
        freeaddrinfo(res);
        break;
    }

    evutil_make_socket_closeonexec(n->fd);
    evutil_make_socket_nonblocking(n->fd);

    event_assign(&n->udp_event, n->evbase, n->fd, EV_READ|EV_PERSIST, udp_read, n);
    if (event_add(&n->udp_event, NULL) < 0) {
        log_error("%s event_add udp_read failed\n", __func__);
        return false;
    }

    if (n->dht) {
        // the dht has to be re-created when the fd changes
        dht_destroy(n->dht);
        n->dht = NULL;
    }
    n->dht = dht_setup(n);
    network_async(n, ^{
        dht_restore(n->dht);
    });

    sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(n->fd, (sockaddr *)&ss, &ss_len) != 0) {
        log_errno("getsockname");
        return false;
    }
    n->port = sockaddr_get_port((const sockaddr *)&ss);
    printf("listening on UDP: %s\n", sockaddr_str((const sockaddr*)&ss));

    return true;
}

void network_recreate_sockets(network *n)
{
    debug("%s recreating sockets\n", __func__);
    event_del(&n->udp_event);
    evutil_closesocket(n->fd);
    network_make_socket(n);
    if (network_recreate_sockets_cb != NULL) {
        network_recreate_sockets_cb(n);
    }
}

bool udp_received(network *n, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen)
{
    ddebug("udp_received(%zu, %s)\n", len, sockaddr_str(sa));
    if (network_process_udp_cb != NULL) {
        if (network_process_udp_cb(buf, len, sa, salen)) {
            return true;
        }
    }
    if (utp_process_udp(n->utp, buf, len, sa, salen)) {
        return true;
    }
    // dht last because dht_process_udp doesn't really tell us if it was a valid dht packet
    time_t tosleep;
    bool r = dht_process_udp(n->dht, buf, len, sa, salen, &tosleep);
    dht_schedule(n, tosleep);
    return r;
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
        uint8_t buf[64 * 1024 + 1];
        ssize_t len = recvfrom(n->fd, buf, sizeof(buf), 0, (sockaddr *)&src_addr, &addrlen);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                utp_issue_deferred_acks(n->utp);
                break;
            }
            if (errno == ECONNREFUSED || errno == ECONNRESET ||
                errno == EHOSTUNREACH || errno == ENETUNREACH) {
#ifdef __linux__
                // ugg, libevent doesn't tell us about POLLERR
                // https://github.com/libevent/libevent/issues/495
                icmp_handler(n);
                break;
#endif
            }
            int err = errno;
            debug("%s recvfrom error fd:%d %d %s\n", __func__, n->fd, err, strerror(err));
            if (err == ENOTCONN) {
                // ENOTCONN indicates the socket has been reclaimed on iOS
                // https://developer.apple.com/library/archive/technotes/tn2277/_index.html#//apple_ref/doc/uid/DTS40010841-CH1-SUBSECTION9
                // we use this as a canary to indicate all sockets need to be recreated
                network_recreate_sockets(n);
            }
            break;
        }

        ddebug("recvfrom(%zu, %s)\n", len, sockaddr_str((const sockaddr *)&src_addr));

        const sockaddr *sa = (const sockaddr *)&src_addr;
        socklen_t salen = sockaddr_get_length(sa);

        sockaddr_in sin = {0};
        if (src_addr.ss_family == AF_INET6) {
            const sockaddr_in6 *sin6 = (const sockaddr_in6 *)&src_addr;
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                sin.sin_family = AF_INET;
                sin.sin_port = sin6->sin6_port;
#ifdef __APPLE__
                sin.sin_len = sizeof(sin);
#endif
                map6to4(&sin6->sin6_addr, &sin.sin_addr);
                sa = (const sockaddr *)&sin;
                salen = sizeof(sin);
            }
        }

        if (o_debug >= 3) {
            hexdump(buf, len);
        }

        udp_received(n, buf, len, sa, salen);
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

int evbuffer_copy(evbuffer *out, evbuffer *in)
{
    const uint8_t *i = evbuffer_pullup(in, evbuffer_get_length(in));
    return evbuffer_add(out, i, evbuffer_get_length(in));
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
    if (o_debug >= EVENT_LOG_ERR - severity) {
        debug("[libevent] %d %s\n", severity, msg);
    }
}

void evdns_log_cb(int severity, const char *msg)
{
    if (o_debug >= EVENT_LOG_ERR - severity) {
        debug("[evdns] %d %s\n", severity, msg);
    }
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

socklen_t sockaddr_get_length(const sockaddr* sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return sizeof(sockaddr_in);
    case AF_INET6:
        return sizeof(sockaddr_in6);
    case AF_LOCAL:
        return sizeof(sockaddr_un);
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
}

port_t sockaddr_get_port(const sockaddr* sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return ntohs(((sockaddr_in*)sa)->sin_port);
    case AF_INET6:
        return ntohs(((sockaddr_in6*)sa)->sin6_port);
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
}

void sockaddr_set_port(sockaddr* sa, port_t port)
{
    switch (sa->sa_family) {
    case AF_INET:
        ((sockaddr_in*)sa)->sin_port = htons(port);
        return;
    case AF_INET6:
        ((sockaddr_in6*)sa)->sin6_port = htons(port);
        return;
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
}

int sockaddr_cmp(const struct sockaddr * sa, const struct sockaddr * sb)
{
    if (sa->sa_family != sb->sa_family) {
        return sa->sa_family - sb->sa_family;
    }
    port_t pa = sockaddr_get_port(sa);
    port_t pb = sockaddr_get_port(sb);
    if (pa != pb) {
        return pa - pb;
    }
    switch (sa->sa_family) {
    case AF_INET: {
        const sockaddr_in *sina = (const sockaddr_in*)sa;
        const sockaddr_in *sinb = (const sockaddr_in*)sa;
        return sina->sin_addr.s_addr - sinb->sin_addr.s_addr;
    }
    case AF_INET6: {
        const sockaddr_in6 *sin6a = (const sockaddr_in6*)sa;
        const sockaddr_in6 *sin6b = (const sockaddr_in6*)sa;
        return memcmp(&sin6a->sin6_addr, &sin6b->sin6_addr, sizeof(sin6a->sin6_addr));
    }
    case AF_LOCAL: {
        const sockaddr_un *suna = (const sockaddr_un*)sa;
        const sockaddr_un *sunb = (const sockaddr_un*)sa;
        return strcmp(suna->sun_path, sunb->sun_path);
    }
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
}

bool sockaddr_eq(const struct sockaddr * sa, const struct sockaddr * sb)
{
    return sockaddr_cmp(sa, sb) == 0;
}

const char* sockaddr_str(const sockaddr *sa)
{
    if (sa->sa_family == AF_LOCAL) {
        const sockaddr_un *sun = (const sockaddr_un*)sa;
        return sun->sun_path;
    }
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    int r = getnameinfo(sa, sockaddr_get_length(sa), host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
    if (r) {
        debug("getnameinfo failed %d %s\n", r, gai_strerror(r));
        return "";
    }
    static char buf[1 + NI_MAXHOST + 2 + NI_MAXSERV + 1];
    switch (sa->sa_family) {
    case AF_INET:
        snprintf(buf, sizeof(buf), "%s:%s", host, serv);
        break;
    case AF_INET6:
        snprintf(buf, sizeof(buf), "[%s]:%s", host, serv);
        break;
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
    return buf;
}

const char* sockaddr_str_addronly(const sockaddr *sa)
{
    if (sa->sa_family == AF_LOCAL) {
        const sockaddr_un *sun = (const sockaddr_un*)sa;
        return sun->sun_path;
    }
    static char host[NI_MAXHOST] = {0};
    int r = getnameinfo(sa, sockaddr_get_length(sa), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
    if (r) {
        debug("getnameinfo failed %d %s\n", r, gai_strerror(r));
        return "";
    }
    return host;
}

bool sockaddr_is_localhost(const sockaddr *sa, socklen_t salen)
{
    switch(sa->sa_family) {
    case AF_INET: {
        const sockaddr_in *sin = (sockaddr_in *)sa;
        return IN_LOOPBACK(ntohl(sin->sin_addr.s_addr));
    }
    case AF_INET6: {
        const sockaddr_in6 *sin6 = (sockaddr_in6 *)sa;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }
    case AF_LOCAL: {
        return true;
    }
    default:
    case 0:
        debug("%s address family %d not supported\n", __func__, sa->sa_family);
        assert(false);
    }
    return false;
}

int bufferevent_getpeername(const bufferevent *bev, sockaddr *address, socklen_t *address_len)
{
    if (BEV_IS_UTP(bev)) {
        utp_socket *utp = bufferevent_get_utp(bev);
        return utp_getpeername(utp, address, address_len);
    }
    evutil_socket_t fd = bufferevent_getfd((bufferevent*)bev);
    int e = getpeername(fd, address, address_len);
    if (e) {
        log_errno("getpeername");
    }
    return e;
}

bool bufferevent_is_localhost(const bufferevent *bev)
{
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    int e = bufferevent_getpeername(bev, (sockaddr*)&ss, &len);
    if (e) {
        // we don't know anymore, but if it's TCP we assume it's localhost
        return !BEV_IS_UTP(bev);
    }
    return sockaddr_is_localhost((sockaddr*)&ss, len);
}

void set_max_nofile(void)
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

uint64_t us_clock()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

void network_set_log_level(int level)
{
    o_debug = level;
    if (o_debug) {
        event_enable_debug_logging(o_debug ? EVENT_DBG_ALL : EVENT_DBG_NONE);
    }
}

void network_set_sockaddr_callback(network *n, sockaddr_callback cb)
{
    Block_release(n->sockaddr_cb);
    n->sockaddr_cb = Block_copy(cb);
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

    n->request_discovery_permission = true;
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

    evdns_base_nameserver_ip_add(n->evdns, "1.1.1.1");
    evdns_base_nameserver_ip_add(n->evdns, "1.0.0.1");
    evdns_base_nameserver_ip_add(n->evdns, "8.8.8.8");
    evdns_base_nameserver_ip_add(n->evdns, "8.8.4.4");

    if (evthread_make_base_notifiable(n->evbase)) {
        fprintf(stderr, "evthread_make_base_notifiable failed\n");
        network_free(n);
        return NULL;
    }

    if (!network_make_socket(n)) {
        network_free(n);
        return NULL;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
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

void network_async(network *n, timer_callback cb)
{
    timer_start(n, 0, cb);
}

bool network_in_thread(network *n)
{
    EVBASE_ACQUIRE_LOCK(n->evbase, th_base_lock);
    bool in_thread = EVBASE_IN_THREAD(n->evbase);
    EVBASE_RELEASE_LOCK(n->evbase, th_base_lock);
    return in_thread;
}

void network_sync(network *n, timer_callback cb)
{
    assert(!network_in_thread(n));
    pthread_mutex_t *m = alloc(pthread_mutex_t);
    pthread_mutex_init(m, NULL);
    pthread_mutex_lock(m);
    network_async(n, ^{
        cb();
        pthread_mutex_unlock(m);
    });
    pthread_mutex_lock(m);
    pthread_mutex_destroy(m);
    free(m);
}

void network_locked(network *n, timer_callback cb)
{
    assert(!network_in_thread(n));
    pthread_mutex_t *outer = alloc(pthread_mutex_t);
    pthread_mutex_init(outer, NULL);
    pthread_mutex_lock(outer);
    pthread_mutex_t *inner = alloc(pthread_mutex_t);
    pthread_mutex_init(inner, NULL);
    pthread_mutex_lock(inner);
    network_async(n, ^{
        pthread_mutex_unlock(outer);
        pthread_mutex_lock(inner);
        pthread_mutex_destroy(inner);
        free(inner);
    });
    pthread_mutex_lock(outer);
    cb();
    pthread_mutex_unlock(inner);
    pthread_mutex_destroy(outer);
    free(outer);
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
