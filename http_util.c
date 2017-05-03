#include <event2/http.h>
#include "http_util.h"

void overwrite_header(struct evhttp_request *to, const char *key, const char *value)
{
    struct evkeyvalq *out = evhttp_request_get_output_headers(to);
    while (evhttp_find_header(out, key)) {
        evhttp_remove_header(out, key);
    }
    evhttp_add_header(out, key, value);
}

void copy_header(struct evhttp_request *from, struct evhttp_request *to, const char *key)
{
    struct evkeyvalq *in = evhttp_request_get_input_headers(from);
    const char *value = evhttp_find_header(in, key);
    if (value) {
        overwrite_header(to, key, value);
    }
}

