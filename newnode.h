#include <stdint.h>
#include "network.h"
#include <stdbool.h>

typedef uint16_t port_t;

typedef void (^https_complete_callback)(bool success);
typedef void (^https_callback)(const char *url, https_complete_callback cb);

void newnode_init(const char *app_name, const char *app_id, port_t *http_port, port_t *socks_port, https_callback https_cb);
