#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <sodium.h>

#include <event2/buffer.h>

#include "log.h"
#include "utp.h"
#include "timer.h"
#include "network.h"
#include "constants.h"


typedef struct {
    size_t total;
    size_t len;
    uint8_t buf[];
} buffer;

typedef struct evbuffer evbuffer;

typedef struct {
    buffer *read_buffer;
    evbuffer *write_buffer;
    // XXX: temp
    bool writing;
} socket_buffers;

socket_buffers* socket_buffers_alloc()
{
    socket_buffers *sb = alloc(socket_buffers);
    size_t total = 4096;
    sb->read_buffer = calloc(1, sizeof(buffer) + total);
    sb->read_buffer->total = total;
    sb->read_buffer->len = 0;
    // XXX: temp
    sb->writing = false;
    sb->write_buffer = evbuffer_new();
    return sb;
}

void socket_buffers_free(socket_buffers *sb)
{
    free(sb->read_buffer);
    if (sb->write_buffer) {
        evbuffer_free(sb->write_buffer);
    }
    free(sb);
}

void write_data(utp_socket *s)
{
    socket_buffers *sb = utp_get_userdata(s);
    while (evbuffer_get_length(sb->write_buffer)) {
        // the libutp interface for write is Very Broken
        ssize_t len = MIN(1500, evbuffer_get_length(sb->write_buffer));
        unsigned char *buf = evbuffer_pullup(sb->write_buffer, len);
        ssize_t r = utp_write(s, buf, len);
        assert(r == len);
        evbuffer_drain(sb->write_buffer, len);
    }
}

typedef bool (^http_stream_callback)(uint8_t *data, size_t length, size_t total_length);

void fetch_url(const char *url, http_stream_callback stream)
{
    if (!stream((uint8_t*)"TODO", 4, 8)) {
        return;
    }
    if (!stream((uint8_t*)"TODO", 4, 8)) {
        return;
    }
}

void dht_put_value(const uint8_t *key, const uint8_t *value)
{
    // TODO
    /*
    dht_put(n->dht, g_public_key, g_secret_key, value_str, 0, ^{
        printf("put complete\n");
    });
    */
}

void* memdup(const void *m, size_t length)
{
    void *r = malloc(length);
    memcpy(r, m, length);
    return r;
}

void process_line(socket_buffers *sb, char *line)
{
    printf("'%s'\n", line);
    char *url = line;

    // XXX: currently we don't handle a backlog of requests, so multiple responses will interleave
    assert(!sb->writing);
    sb->writing = true;

    __block struct {
        uint8_t url_hash[crypto_generichash_BYTES];
        crypto_generichash_state content_state;
    } hash_state;

    crypto_generichash(hash_state.url_hash, sizeof(hash_state.url_hash), (const uint8_t*)url, strlen(url), NULL, 0);
    crypto_generichash_init(&hash_state.content_state, NULL, 0, crypto_generichash_BYTES);

    __block size_t progress = 0;
    fetch_url(url, ^bool (uint8_t *data, size_t length, size_t total_length) {
        if (!progress) {
            uint32_t iprefix = (uint32_t)total_length;
            evbuffer_add(sb->write_buffer, &iprefix, sizeof(iprefix));
        }
        crypto_generichash_update(&hash_state.content_state, data, length);
        evbuffer_add(sb->write_buffer, data, length);
        progress += length;
        if (progress == total_length) {
            uint8_t content_hash[crypto_generichash_BYTES];
            crypto_generichash_final(&hash_state.content_state, content_hash, sizeof(content_hash));
            dht_put_value(hash_state.url_hash, content_hash);
            sb->writing = false;
        }
        return true;
    });
}

uint64 callback_on_read(utp_callback_arguments *a)
{
    socket_buffers *sb = utp_get_userdata(a->socket);
    buffer *b = sb->read_buffer;

    ssize_t left = a->len;
    while (left > 0) {
        ssize_t remaining = b->total - b->len;
        ssize_t copy = MIN(left, remaining);
        memcpy(b->buf + b->len, a->buf + (a->len - left), copy);

        b->len += copy;
        left -= copy;

        uint8_t *line_start = b->buf;
        while (line_start < b->buf + b->total) {
            uint8_t *line_end = (uint8_t*)memchr((void*)line_start, '\n', b->len - (line_start - b->buf));
            if (!line_end) {
                if (b->len == b->total) {
                    debug("Line length exceeded %llu\n", b->total);
                    utp_close(a->socket);
                    return 0;
                }
                break;
            }
            *line_end = 0;
            process_line(sb, (char*)line_start);
            line_start = line_end + 1;
        }
        b->len -= (line_start - b->buf);
        memmove(b->buf, line_start, b->len);
    }
    utp_read_drained(a->socket);
    return 0;
}

uint64 callback_on_accept(utp_callback_arguments *a)
{
    utp_set_userdata(a->socket, socket_buffers_alloc());
    debug("Accepted inbound socket %p\n", a->socket);
    return 0;
}

uint64 callback_on_state_change(utp_callback_arguments *a)
{
    debug("state %d: %s\n", a->state, utp_state_names[a->state]);

    switch (a->state) {
    case UTP_STATE_CONNECT:
    case UTP_STATE_WRITABLE:
        write_data(a->socket);
        break;

    case UTP_STATE_EOF:
        debug("Received EOF from socket; closing\n");
        utp_close(a->socket);
        break;

    case UTP_STATE_DESTROYING: {
        debug("UTP socket is being destroyed; exiting\n");

        socket_buffers_free(utp_get_userdata(a->socket));

        utp_socket_stats *stats = utp_get_stats(a->socket);
        if (stats) {
            debug("Socket Statistics:\n");
            debug("    Bytes sent:          %d\n", stats->nbytes_xmit);
            debug("    Bytes received:      %d\n", stats->nbytes_recv);
            debug("    Packets received:    %d\n", stats->nrecv);
            debug("    Packets sent:        %d\n", stats->nxmit);
            debug("    Duplicate receives:  %d\n", stats->nduprecv);
            debug("    Retransmits:         %d\n", stats->rexmit);
            debug("    Fast Retransmits:    %d\n", stats->fastrexmit);
            debug("    Best guess at MTU:   %d\n", stats->mtu_guess);
        } else {
            debug("No socket statistics available\n");
        }

        break;
    }
    }

    return 0;
}

void usage(char *name)
{
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr, "    %s [options] -p <listening-port>\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -h          Help\n");
    fprintf(stderr, "    -p <port>   Local port\n");
    fprintf(stderr, "    -s <IP>     Source IP\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *address = "0.0.0.0";
    char *port = NULL;

    for (;;) {
        int c = getopt(argc, argv, "hp:s:n");
        if (c == -1)
            break;
        switch (c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'p':
            port = optarg;
            break;
        case 's':
            address = optarg;
            break;
        default:
            die("Unhandled argument: %c\n", c);
        }
    }

    if (!port) {
        usage(argv[0]);
    }

    network *n = network_setup(address, port);

    utp_set_callback(n->utp, UTP_ON_ACCEPT, &callback_on_accept);
    utp_set_callback(n->utp, UTP_ON_STATE_CHANGE, &callback_on_state_change);
    utp_set_callback(n->utp, UTP_ON_READ, &callback_on_read);

    timer_repeating(n, 6 * 60 * 60 * 1000, ^{
        dht_announce(n->dht, injector_swarm, ^(const byte *peers, uint num_peers) {
            if (!peers) {
                printf("announce complete\n");
            }
        });
    });

    return network_loop(n);
}
