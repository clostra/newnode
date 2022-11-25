#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <sodium.h>

#include "utp.h"

#define TS(x) typedef struct x x
#define TE(x) typedef enum x x

TS(network);


#ifndef MIN
#define MIN(a, b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a, b) (((a)>(b))?(a):(b))
#endif
#define PACKED __attribute__((__packed__))
#define lenof(x) (sizeof(x)/sizeof(x[0]))
#define member_sizeof(type, member) sizeof(((type *)0)->member)
#define alloc(type) calloc(1, sizeof(type))
#define streq(a, b) (strcmp(a, b) == 0)
#define strcaseeq(a, b) (strcasecmp(a, b) == 0)
#define strneq(a, b, len) (strncmp(a, b, len) == 0)
#define strncaseeq(a, b, len) (strncasecmp(a, b, len) == 0)
#define memeq(a, b, len) (memcmp(a, b, len) == 0)
#define memdup(m, len) memcpy(malloc(len), m, len)

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func) \
    static inline void func##p(type *p) { if (*p) func(*p); }

static inline void freep(void *pp) { free(*(void **)pp); }
#define auto_free __attribute__((__cleanup__(freep)))

#ifndef IN_LINKLOCALNETNUM
#define IN_LINKLOCALNETNUM (u_int32_t)0xA9FE0000 /* 169.254.0.0 */
#endif
#ifndef IN_LINKLOCAL
#define IN_LINKLOCAL(i) (((u_int32_t)(i) & IN_CLASSB_NET) == IN_LINKLOCALNETNUM)
#endif
#ifndef IN_LOOPBACK
#define IN_LOOPBACK(a) ((((long int) (a)) & 0xff000000) == 0x7f000000)
#endif
#ifndef IN_ZERONET
#define IN_ZERONET(i) (((u_int32_t)(i) & 0xff000000) == 0)
#endif
#ifndef IN_PRIVATE
#define IN_PRIVATE(i) ((((u_int32_t)(i) & 0xff000000) == 0x0a000000) || \
                       (((u_int32_t)(i) & 0xfff00000) == 0xac100000) || \
                       (((u_int32_t)(i) & 0xffff0000) == 0xc0a80000))
#endif
#ifndef IN_LOCAL_GROUP
#define IN_LOCAL_GROUP(i) (((u_int32_t)(i) & 0xffffff00) == 0xe0000000)
#endif
#ifndef IN_ANY_LOCAL
#define IN_ANY_LOCAL(i) (IN_LINKLOCAL(i) || IN_LOCAL_GROUP(i))
#endif

#ifdef __APPLE__
#ifndef SO_RECV_ANYIF
#define SO_RECV_ANYIF 0x1104    /* unrestricted inbound processing */
#endif
#endif

#ifndef IN6_IS_ADDR_UNIQUE_LOCAL
/*
 * Unique Local IPv6 Unicast Addresses (per RFC 4193)
 */
#define IN6_IS_ADDR_UNIQUE_LOCAL(a) \
    (((a)->s6_addr[0] == 0xfc) || ((a)->s6_addr[0] == 0xfd))
#endif

TS(event_base);
TS(evdns_base);
TS(event);
TS(evhttp);
TS(evhttp_bound_socket);
TS(evwatch);
TS(evwatch_check_cb_info);
TS(evwatch_prepare_cb_info);
TS(evdns_getaddrinfo_request);
TS(evbuffer);
TS(evbuffer_ptr);
TS(evbuffer_iovec);
TS(evbuffer_cb_info);
TS(evbuffer_file_segment);
TS(evconnlistener);
TS(evutil_addrinfo);
TS(bufferevent);
TS(utp_iovec);
TS(timeval);
TS(timespec);
TS(tm);
TS(addrinfo);
TS(rlimit);
TS(in_addr);
TS(in6_addr);
TS(sockaddr);
TS(sockaddr_in);
TS(sockaddr_in6);
TS(sockaddr_un);
TS(sockaddr_storage);
TS(ip);
TE(bufferevent_flush_mode);
TE(bufferevent_filter_result);
typedef in_port_t port_t;


DEFINE_TRIVIAL_CLEANUP_FUNC(evbuffer*, evbuffer_free)
#define evbuffer_auto_free __attribute__((__cleanup__(evbuffer_freep)))


#include "dht.h"
#include "timer.h"


typedef void (^sockaddr_callback)(const sockaddr *addr, socklen_t addrlen);

struct network {
    event_base *evbase;
    evdns_base *evdns;
    char *address;
    port_t port;
    int fd;
    event udp_event;
    utp_context *utp;
    utp_socket *accepting_utp;
    dht *dht;
    timer *dht_timer;
    evhttp *http;
    sockaddr_callback sockaddr_cb;
    pthread_t thread;
    bool request_discovery_permission:1;
};

uint64_t us_clock(void);

int evbuffer_copy(evbuffer *out, evbuffer *in);
void evbuffer_clear(evbuffer *buf);
void evbuffer_hash_update(evbuffer *buf, crypto_generichash_state *content_state);
bool evbuffer_write_to_file(evbuffer *buf, int fd);
void bufferevent_free_checked(bufferevent *bev);
int bufferevent_get_error(bufferevent *bev);
const char* bev_events_to_str(short events);

socklen_t sockaddr_get_length(const sockaddr* sa);
port_t sockaddr_get_port(const sockaddr* sa);
void sockaddr_set_port(sockaddr* sa, port_t port);
int sockaddr_cmp(const sockaddr * sa, const sockaddr * sb);
bool sockaddr_eq(const sockaddr * sa, const sockaddr * sb);
const char* sockaddr_str(const sockaddr *ss);
const char* sockaddr_str_addronly(const sockaddr *ss);
bool sockaddr_is_localhost(const sockaddr *sa, socklen_t salen);
int bufferevent_getpeername(const bufferevent *bev, sockaddr *address, socklen_t *address_len);
bool bufferevent_is_localhost(const bufferevent *bev);

network* network_setup(char *address, port_t port);
void network_async(network *n, timer_callback cb);
void network_sync(network *n, timer_callback cb);
int network_loop(network *n);

void network_set_log_level(int level);
void network_set_sockaddr_callback(network *n, sockaddr_callback cb);
void network_free(network *n);
#define network_sendto(n, ...) udp_sendto(n->fd, __VA_ARGS__)
void network_recreate_sockets_cb(network *n) __attribute__((weak));
bool network_process_udp_cb(const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen) __attribute__((weak));
void network_ifchange(network *n) __attribute__((weak));

ssize_t udp_sendto(int fd, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen);
bool udp_received(network *n, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen);

#endif // __NETWORK_H__
