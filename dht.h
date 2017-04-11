#ifndef __DHT_API_H__
#define __DHT_API_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dht dht;
dht* dht_setup(int fd);
bool dht_process_udp(dht *d, const byte *buffer, size_t len, const struct sockaddr *to, socklen_t tolen);
bool dht_process_icmp(dht *d, const byte *buffer, size_t len, const struct sockaddr *to, socklen_t tolen);
void dht_destroy(dht *d);

#ifdef __cplusplus
}
#endif

#endif // __DHT_API_H__
