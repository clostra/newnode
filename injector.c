#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/queue.h>

#include "log.h"
#include "utp.h"
#include "network.h"


typedef struct {
    size_t total;
    size_t len;
    char buf[];
} buffer;

struct write_buffer {
    size_t len;
    char *buf;
    char *p;
    STAILQ_ENTRY(write_buffer) next;
};
typedef struct write_buffer write_buffer;
typedef STAILQ_HEAD(buffer_stailq, write_buffer) buffer_stailq;

typedef struct {
    buffer *read_buffer;
    buffer_stailq *write_buffers;
} socket_buffers;

write_buffer* write_buffer_alloc(char *data, size_t len)
{
    write_buffer *b = alloc(write_buffer);
    b->len = len;
    b->buf = data;
    b->p = b->buf;
    return b;
}

void write_buffer_free(write_buffer *wb)
{
    free(wb->buf);
    free(wb);
}

socket_buffers* socket_buffers_alloc()
{
    socket_buffers *sb = alloc(socket_buffers);
    size_t total = 4096;
    sb->read_buffer = calloc(1, sizeof(buffer) + total);
    sb->read_buffer->total = total;
    sb->read_buffer->len = 0;
    STAILQ_INIT(sb->write_buffers);
    return sb;
}

void socket_buffers_free(socket_buffers *sb)
{
    free(sb->read_buffer);
    write_buffer *n1 = STAILQ_FIRST(sb->write_buffers);
    while (n1) {
        write_buffer *n2 = STAILQ_NEXT(n1, next);
        write_buffer_free(n1);
        n1 = n2;
    }
    STAILQ_INIT(sb->write_buffers);
    free(sb);
}

void write_data(utp_socket *s)
{
    socket_buffers *sb = utp_get_userdata(s);
    // TODO: drain sb->write_buffers
    /*
    while (p < buf + buf_len) {
        size_t sent = utp_write(s, p, buf + buf_len - p);
        if (sent == 0) {
            debug("socket no longer writable\n");
            return;
        }

        p += sent;

        if (p == buf + buf_len) {
            debug("wrote %zd bytes; buffer now empty\n", sent);
            p = buf;
            buf_len = 0;
        } else {
            debug("wrote %zd bytes; %d bytes left in buffer\n", sent, buf + buf_len - p);
        }
    }

    if (buf_len == 0 && eof_flag) {
        debug("Buffer empty, and previously found EOF.  Closing socket\n");
        utp_close(s);
    }
    */
}

char* fetch_url(const char *url)
{
    return "TODO: wget url";
}

char* hash(const char *data)
{
    return "TODO: hash(data)";
}

void dht_put(const char *key, const char *value)
{
    // TODO
    //dht->Put(g_public_key, g_secret_key, key, value);
}

void process_line(socket_buffers *sb, char *line)
{
    printf("'%s'\n", line);
    char *url = line;
    char *data = fetch_url(url);
    dht_put(hash(url), hash(data));
    STAILQ_INSERT_TAIL(sb->write_buffers, write_buffer_alloc(data, strlen(data)), next); 
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

        char *line_start = b->buf;
        while (line_start < b->buf + b->total) {
            char *line_end = (char*)memchr((void*)line_start, '\n', b->len - (line_start - b->buf));
            if (!line_end) {
                if (b->len == b->total) {
                    debug("Line length exceeded %llu\n", b->total);
                    utp_close(a->socket);
                    return 0;
                }
                break;
            }
            *line_end = 0;
            process_line(sb, line_start);
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

uint64 callback_on_error(utp_callback_arguments *a)
{
    fprintf(stderr, "Error: %s\n", utp_error_code_names[a->error_code]);
    socket_buffers_free(utp_get_userdata(a->socket));
    utp_close(a->socket);
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
    char *port = NULL;
    char *address = "0.0.0.0";

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

    utp_context *ctx = network_setup(address, port);

    utp_set_callback(ctx, UTP_ON_ACCEPT, &callback_on_accept);
    utp_set_callback(ctx, UTP_ON_STATE_CHANGE, &callback_on_state_change);
    utp_set_callback(ctx, UTP_ON_READ, &callback_on_read);
    utp_set_callback(ctx, UTP_ON_ERROR, &callback_on_error);

    return network_loop(ctx);
}
