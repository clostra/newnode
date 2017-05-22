#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "utp.h"
#include "utp_bufferevent.h"
#include "log.h"


typedef struct bufferevent bufferevent;
typedef struct evbuffer evbuffer;


// utp_read > bev_output > other_fd_recv
// other_fd_send > bev_input > utp_write

typedef struct {
    utp_socket *utp;
    bufferevent *bev;
} utp_bufferevent;


void utp_clear_close(utp_socket *s)
{
    utp_set_userdata(s, NULL);
    utp_close(s);
}

void ubev_bev_close(utp_bufferevent *u)
{
    debug("ubev_bev_close %p\n", u);
    assert(!bufferevent_get_enabled(u->bev));
    assert(!evbuffer_get_length(bufferevent_get_input(u->bev)));
    assert(!evbuffer_get_length(bufferevent_get_output(u->bev)));
    bufferevent_free(u->bev);
    u->bev = NULL;
    if (u->utp) {
        return;
    }
    free(u);
}

void ubev_discard_input(utp_bufferevent *u)
{
    evbuffer *input = bufferevent_get_input(u->bev);
    evbuffer_drain(input, evbuffer_get_length(input));
    assert(evbuffer_get_length(input) == 0);
    bufferevent_disable(u->bev, EV_READ);

    if (!bufferevent_get_enabled(u->bev)) {
        ubev_bev_close(u);
    }
}

void ubev_bev_check_flush(utp_bufferevent *u)
{
    if (bufferevent_get_enabled(u->bev) || evbuffer_get_length(bufferevent_get_input(u->bev))) {
        return;
    }
    // utp has no way to tell if the write buffer is flushed. you just have to close and wait for UTP_STATE_DESTROYING
    utp_clear_close(u->utp);
    u->utp = NULL;
    ubev_bev_close(u);
}

void utp_bufferevent_utp_close(utp_bufferevent *u)
{
    utp_clear_close(u->utp);
    u->utp = NULL;
    if (u->bev) {
        if (bufferevent_get_enabled(u->bev) & EV_WRITE && !evbuffer_get_length(bufferevent_get_output(u->bev))) {
            bufferevent_disable(u->bev, EV_WRITE);
        }
        ubev_discard_input(u);
    } else {
        free(u);
    }
}

void utp_bufferevent_flush(utp_bufferevent *u)
{
    evbuffer *in = bufferevent_get_input(u->bev);
    while (evbuffer_get_length(in)) {
        // the libutp interface for write is Very Broken.
        ssize_t len = MIN(1500, evbuffer_get_length(in));
        unsigned char *buf = evbuffer_pullup(in, len);
        ssize_t r = utp_write(u->utp, buf, len);
        if (r < 0) {
            fprintf(stderr, "utp_write failed\n");
            utp_bufferevent_utp_close(u);
            return;
        }
        if (!r) {
            break;
        }
        evbuffer_drain(in, r);
    }
    ubev_bev_check_flush(u);
}

uint64 utp_on_error(utp_callback_arguments *a)
{
    fprintf(stderr, "Error: %s\n", utp_error_code_names[a->error_code]);
    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);
    if (u) {
        utp_bufferevent_utp_close(u);
    }
    return 0;
}

uint64 utp_on_read(utp_callback_arguments *a)
{
    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);
    if (u->bev && bufferevent_get_enabled(u->bev) & EV_WRITE) {
        debug("writing utp>bev %d bytes\n", a->len);
        bufferevent_write(u->bev, a->buf, a->len);
    }
    return 0;
}

uint64 utp_on_state_change(utp_callback_arguments *a)
{
    debug("state %d: %s\n", a->state, utp_state_names[a->state]);

    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);

    switch (a->state) {
    case UTP_STATE_CONNECT:
    case UTP_STATE_WRITABLE:
        if (u->bev) {
            utp_bufferevent_flush(u);
        }
        break;
    case UTP_STATE_EOF:
        // XXX: utp does not support half-close. if the other side sent a FIN, they will not read data either
        utp_bufferevent_utp_close(u);
        break;
    case UTP_STATE_DESTROYING: {
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

void ubev_read_cb(bufferevent *bev, void *ctx)
{
    debug("ubev_read_cb %p\n", ctx);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    assert(u->utp);
    utp_bufferevent_flush(u);
}

void ubev_write_cb(struct bufferevent *bev, void *ctx)
{
    debug("ubev_write_cb %p\n", ctx);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    // the output buffer is flushed
    assert(!evbuffer_get_length(bufferevent_get_output(u->bev)));
    if (!u->utp) {
        bufferevent_disable(u->bev, EV_WRITE);
        ubev_bev_close(u);
        return;
    }
    utp_read_drained(u->utp);
}

void ubev_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    debug("ubev_event_cb %p %x\n", ctx, events);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    if (events & BEV_EVENT_ERROR) {
        // data in the output buffer is lost
        evbuffer *output = bufferevent_get_output(u->bev);
        evbuffer_unfreeze(output, 1);
        evbuffer_drain(output, evbuffer_get_length(output));
        evbuffer_freeze(output, 1);
        assert(!evbuffer_get_length(output));
        bufferevent_disable(u->bev, EV_WRITE);
        bufferevent_disable(u->bev, EV_READ);
    }
    if (events & BEV_EVENT_EOF) {
        bufferevent_disable(u->bev, EV_READ);
    }
    ubev_bev_check_flush(u);
}

utp_bufferevent* utp_bufferevent_new(event_base *base, utp_socket *s, int fd)
{
    utp_bufferevent *u = alloc(utp_bufferevent);
    u->utp = s;
    utp_set_userdata(s, u);
    u->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!u->bev) {
        utp_clear_close(s);
        free(u);
        return NULL;
    }
    bufferevent_setcb(u->bev, ubev_read_cb, ubev_write_cb, ubev_event_cb, u);
    bufferevent_enable(u->bev, EV_READ);
    return u;
}

int utp_socket_create_fd(event_base *base, utp_socket *s)
{
    int fds[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);
    evutil_make_socket_closeonexec(fds[0]);
    evutil_make_socket_nonblocking(fds[0]);
    utp_bufferevent *u = utp_bufferevent_new(base, s, fds[0]);
    if (!u) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    return fds[1];
}

void utp_connect_tcp(event_base *base, utp_socket *s, const struct sockaddr *address, socklen_t address_len)
{
    utp_bufferevent *u = utp_bufferevent_new(base, s, -1);
    if (bufferevent_socket_connect(u->bev, address, address_len) < 0) {
        bufferevent_free(u->bev);
        utp_clear_close(s);
        free(u);
        fprintf(stderr, "bufferevent_socket_connect failed");
    }
}
