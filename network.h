#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <sodium.h>

#include "utp.h"

typedef struct network network;

#include "dht.h"


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

#ifndef IN_LOOPBACK
#define	IN_LOOPBACK(a) ((((long int) (a)) & 0xff000000) == 0x7f000000)
#endif

#ifdef __APPLE__
#ifndef SO_RECV_ANYIF
#define SO_RECV_ANYIF 0x1104    /* unrestricted inbound processing */
#endif
#endif

typedef struct event_base event_base;
typedef struct evdns_base evdns_base;
typedef struct event event;
typedef struct evhttp evhttp;
typedef struct evhttp_bound_socket evhttp_bound_socket;
typedef struct evbuffer evbuffer;
typedef struct evbuffer_ptr evbuffer_ptr;
typedef struct evbuffer_iovec evbuffer_iovec;
typedef struct evbuffer_cb_info evbuffer_cb_info;
typedef struct evbuffer_file_segment evbuffer_file_segment;
typedef struct evconnlistener evconnlistener;
typedef struct evutil_addrinfo evutil_addrinfo;
typedef struct bufferevent bufferevent;
typedef struct timeval timeval;
typedef struct timespec timespec;
typedef struct tm tm;
typedef struct addrinfo addrinfo;
typedef struct rlimit rlimit;
typedef struct in_addr in_addr;
typedef struct in6_addr in6_addr;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;
typedef struct sockaddr_storage sockaddr_storage;
typedef enum bufferevent_flush_mode bufferevent_flush_mode;
typedef enum bufferevent_filter_result bufferevent_filter_result;
typedef in_port_t port_t;

#include "timer.h"


struct network {
    event_base *evbase;
    evdns_base *evdns;
    char *address;
    port_t port;
    int fd;
    event udp_event;
    utp_context *utp;
    dht *dht;
    timer *dht_timer;
    evhttp *http;
};

void evbuffer_clear(evbuffer *buf);
void evbuffer_hash_update(evbuffer *buf, crypto_generichash_state *content_state);
bool evbuffer_write_to_file(evbuffer *buf, int fd);
void bufferevent_free_checked(bufferevent *bev);
int bufferevent_get_error(bufferevent *bev);
const char* bev_events_to_str(short events);

socklen_t sockaddr_get_length(const sockaddr* sa);
port_t sockaddr_get_port(const sockaddr* sa);
void sockaddr_set_port(sockaddr* sa, port_t port);
int sockaddr_cmp(const struct sockaddr * sa, const struct sockaddr * sb);
bool sockaddr_eq(const struct sockaddr * sa, const struct sockaddr * sb);
const char* sockaddr_str(const sockaddr *ss);

int udp_sendto(int fd, const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen);
bool udp_received(network *n, uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen);
network* network_setup(char *address, port_t port);
int network_loop(network *n);


#endif // __NETWORK_H__
