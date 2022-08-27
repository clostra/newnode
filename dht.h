#ifndef __DHT_H__
#define __DHT_H__

#include <stdbool.h>

typedef struct dht dht;

#include "network.h"


typedef struct sockaddr sockaddr;
typedef void (^dht_event_callback)(int event,
                                   const unsigned char *info_hash,
                                   const void *data, size_t data_len);

dht* dht_setup(network *n);
void dht_set_event_cb(dht *d, dht_event_callback cb);
void dht_add_bootstrap(dht *d, const char *host, port_t port);
void dht_restore(dht *d);
time_t dht_tick(dht *d);
bool dht_process_udp(dht *d, const uint8_t *buffer, size_t len, const sockaddr *to, socklen_t tolen, time_t *tosleep);
bool dht_process_icmp_error(dht *d, const uint8_t *buffer, size_t len, const sockaddr *to, socklen_t tolen);
void dht_announce(dht *d, const uint8_t *info_hash);
void dht_get_peers(dht *d, const uint8_t *info_hash);
size_t dht_num_searches(void);
void dht_destroy(dht *d);

#endif // __DHT_H__
