#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#include "utp.h"

typedef struct network network;

#include "dht.h"


#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
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


typedef struct event_base event_base;
typedef struct evdns_base evdns_base;
typedef struct event event;
typedef struct evhttp evhttp;
typedef struct evbuffer evbuffer;
typedef struct evbuffer_ptr evbuffer_ptr;
typedef struct evbuffer_iovec evbuffer_iovec;
typedef struct evbuffer_cb_info evbuffer_cb_info;
typedef struct evconnlistener evconnlistener;
typedef struct evutil_addrinfo evutil_addrinfo;
typedef struct bufferevent bufferevent;
typedef struct timeval timeval;
typedef struct timespec timespec;
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
    int fd;
    event udp_event;
    utp_context *utp;
    dht *dht;
    timer *dht_timer;
    evhttp *http;
};

void evbuffer_clear(evbuffer *buf);
void bufferevent_free_checked(bufferevent *bev);
int bufferevent_get_error(bufferevent *bev);
port_t sockaddr_get_port(const sockaddr* sa);
void sockaddr_set_port(sockaddr* sa, port_t port);

network* network_setup(char *address, port_t port);
int network_loop(network *n);


#endif // __NETWORK_H__
