#ifndef __HTTP_H__
#define __HTTP_H__

#include <sodium.h>

#include "network.h"


//#define HASH_LOGGING

#ifdef HASH_LOGGING
int crypto_generichash_update_logged(crypto_generichash_state *state,
                                     const unsigned char *in,
                                     unsigned long long inlen);
#define crypto_generichash_update crypto_generichash_update_logged
#endif


typedef struct {
    uint8_t signature[crypto_sign_BYTES];
    char sign[sizeof("sign") - 1];
    char timestamp[sizeof("2011-10-08T07:07:09Z") - 1];
    uint8_t content_hash[crypto_generichash_BYTES];
} PACKED content_sig;

typedef struct evkeyval evkeyval;
typedef struct evkeyvalq evkeyvalq;
typedef struct evhttp_uri evhttp_uri;
typedef struct evbuffer_ptr evbuffer_ptr;
typedef struct evbuffer_iovec evbuffer_iovec;
typedef struct bufferevent bufferevent;
typedef struct evhttp_request evhttp_request;
typedef struct evhttp_connection evhttp_connection;

void join_url_swarm(network *n, const char *url);
void fetch_url_swarm(network *n, const char *url);

const char *evhttp_method(enum evhttp_cmd_type type);

int get_port_for_scheme(const char *scheme);

void overwrite_header(evhttp_request *to, const char *key, const char *value);
void copy_header(evhttp_request *from, evhttp_request *to, const char *key);
void copy_all_headers(evhttp_request *from, evhttp_request *to);
void hash_headers(evkeyvalq *in, crypto_generichash_state *content_state);

evhttp_connection *make_connection(network *n, const evhttp_uri *uri);
void return_connection(evhttp_connection *evcon);

uint64 utp_on_accept(utp_callback_arguments *a);

#endif // __HTTP_H__
