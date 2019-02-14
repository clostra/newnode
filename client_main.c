#include <stdlib.h>

#include "network.h"
#include "log.h"


network* client_init(port_t *http_port, port_t *socks_port);
int client_run(network *n);

int main(int argc, char *argv[])
{
    char *port_s = "8006";

    for (;;) {
        int c = getopt(argc, argv, "p:v");
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'p':
            port_s = optarg;
            break;
        case 'v':
            o_debug++;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    port_t http_port = atoi(port_s);
    port_t socks_port = http_port + 1;
    network *n = client_init(&http_port, &socks_port);
    if (!n) {
        return 1;
    }
    return client_run(n);
}
