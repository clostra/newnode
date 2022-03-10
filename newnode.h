#include <stdint.h>
#include <stdbool.h>
#include "g_https_cb.h"

typedef uint16_t port_t;
typedef struct network network;

typedef void (^https_complete_callback)(bool success, https_result *result);
typedef int64_t (^https_callback)(const char *url, https_complete_callback cb, https_request *request);

network* newnode_init(const char *app_name, const char *app_id, port_t *port, https_callback https_cb);
int newnode_run(network *n);
void newnode_thread(network *n);
port_t newnode_get_port(network *n);
