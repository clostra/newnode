#include <stdlib.h>

#include "network.h"
#include "log.h"


network* client_init(port_t port);
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

    network *n = client_init(atoi(port_s));
    return client_run(n);
}
