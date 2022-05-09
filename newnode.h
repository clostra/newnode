#include <stdint.h>
#include <stdbool.h>
#include "g_https_cb.h"

typedef uint16_t port_t;
typedef struct network network;

typedef https_request_token (^https_callback)(const https_request *request, const char *url, https_complete_callback cb);

network* newnode_init(const char *app_name, const char *app_id, port_t *port, https_callback https_cb);
int newnode_run(network *n);
void newnode_thread(network *n);
port_t newnode_get_port(network *n);
