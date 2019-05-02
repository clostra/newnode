#ifndef __HTTP_H__
#define __HTTP_H__

#include <sodium.h>

#include "merkle_tree.h"
#include "network.h"


typedef struct {
    uint8_t signature[crypto_sign_BYTES];
    char sign[sizeof("sign") - 1];
    char timestamp[sizeof("2011-10-08T07:07:09Z") - 1];
    uint8_t content_hash[crypto_generichash_BYTES];
} PACKED content_sig;

typedef struct evkeyval evkeyval;
typedef struct evkeyvalq evkeyvalq;
typedef struct evhttp_uri evhttp_uri;
typedef struct evhttp_request evhttp_request;
typedef struct evhttp_connection evhttp_connection;
typedef enum evhttp_cmd_type evhttp_cmd_type;
typedef enum evhttp_request_error evhttp_request_error;

void join_url_swarm(network *n, const char *url);
void fetch_url_swarm(network *n, const char *url);

const char* evhttp_method(evhttp_cmd_type type);
const char* evhttp_request_error_str(evhttp_request_error error);

int get_port_for_scheme(const char *scheme);

void overwrite_kv_header(evkeyvalq *out, const char *key, const char *value);
void overwrite_header(evhttp_request *to, const char *key, const char *value);
void copy_header(evhttp_request *from, evhttp_request *to, const char *key);
void copy_all_headers(evhttp_request *from, evhttp_request *to);
void hash_headers(evkeyvalq *in, crypto_generichash_state *content_state);
void hash_request(evhttp_request *req, evkeyvalq *hdrs, crypto_generichash_state *content_state);
void merkle_tree_hash_request(merkle_tree *m, evhttp_request *req, evkeyvalq *hdrs);
evbuffer* build_request_buffer(int response_code, evkeyvalq *hdrs);

evhttp_connection *make_connection(network *n, const evhttp_uri *uri);
void return_connection(evhttp_connection *evcon);

uint64 utp_on_accept(utp_callback_arguments *a);

// defined by caller
void add_sockaddr(network *n, const sockaddr *addr, socklen_t addrlen);

#endif // __HTTP_H__
