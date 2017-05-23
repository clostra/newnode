#ifndef __DHT_API_H__
#define __DHT_API_H__

#include <Block.h>


typedef struct dht dht;
typedef struct sockaddr sockaddr;

typedef void (^add_nodes_callblock)(const byte *peers, uint num_peers);
typedef void (^put_complete_callblock)();

dht* dht_setup(int fd);
void dht_tick(dht *d);
bool dht_process_udp(dht *d, const byte *buffer, size_t len, const sockaddr *to, socklen_t tolen);
bool dht_process_icmp(dht *d, const byte *buffer, size_t len, const sockaddr *to, socklen_t tolen);
void dht_announce(dht *d, const byte *info_hash, add_nodes_callblock cb);
void dht_get_peers(dht *d, const byte *info_hash, add_nodes_callblock cb);
void dht_put(dht *d, const byte *pkey, const byte *skey, const char *v, int64 seq, put_complete_callblock cb);
void dht_destroy(dht *d);

#endif // __DHT_API_H__
