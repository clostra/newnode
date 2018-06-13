#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "utp.h"
#include "utp_bufferevent.h"
#include "obfoo.h"
#include "log.h"


// utp_read > decrypt > bev_output > other_fd_recv
// other_fd_send > bev_input > encrypt > utp_write


typedef struct {
    utp_socket *utp;
    evbuffer *utp_input;
    evbuffer *utp_output;
    obfoo *obfoo;
    bufferevent *bev;
    bufferevent *other_bev;
    bool utp_eof:1;
} utp_bufferevent;


void ubev_cleanup(utp_bufferevent *u)
{
    if (u->utp || u->bev) {
        return;
    }
    free(u);
}

void ubev_utp_close(utp_bufferevent *u)
{
    //debug("ubev_utp_close u:%p utp:%p\n", u, u->utp);
    utp_set_userdata(u->utp, NULL);
    utp_close(u->utp);
    u->utp = NULL;
    if (u->other_bev) {
        bufferevent_decref(u->other_bev);
        u->other_bev = NULL;
    }
}

void ubev_bev_close(utp_bufferevent *u)
{
    //debug("ubev_bev_close %p\n", u);
    obfoo_free(u->obfoo);
    u->obfoo = NULL;
    bufferevent_free_checked(u->bev);
    u->bev = NULL;
}

void ubev_bev_graceful_close(utp_bufferevent *u)
{
    if (u->bev) {
        evbuffer_clear(bufferevent_get_input(u->bev));
        bufferevent_disable(u->bev, EV_READ);
        if (!evbuffer_get_length(bufferevent_get_output(u->bev))) {
            bufferevent_disable(u->bev, EV_WRITE);
            ubev_bev_close(u);
        }
    }
    ubev_cleanup(u);
}

bool ubev_check_close(utp_bufferevent *u)
{
    if (bufferevent_get_enabled(u->bev) || evbuffer_get_length(bufferevent_get_input(u->bev))) {
        return false;
    }
    if (u->utp) {
        ubev_utp_close(u);
    }
    ubev_bev_close(u);
    ubev_cleanup(u);
    return true;
}

void ubev_read_cb(bufferevent *bev, void *ctx)
{
    //debug("%s %p\n", __func__, ctx);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    obfoo_output_filter(bufferevent_get_input(u->bev), u->utp_output, u->obfoo);
}

void utp_bufferevent_flush(utp_bufferevent *u)
{
    evbuffer *in = u->utp_output;
    while (evbuffer_get_length(in)) {
        // the libutp interface for write is Very Broken.
        ssize_t len = MIN(1500, evbuffer_get_length(in));
        unsigned char *buf = evbuffer_pullup(in, len);
        ssize_t r = utp_write(u->utp, buf, len);
        if (r < 0) {
            fprintf(stderr, "utp_write failed\n");
            ubev_utp_close(u);
            ubev_bev_graceful_close(u);
            return;
        }
        if (!r) {
            break;
        }
        evbuffer_drain(in, r);
    }
}

uint64 utp_on_error(utp_callback_arguments *a)
{
    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);
    //debug("utp error: %s %p\n", utp_error_code_names[a->error_code], u);
    if (u) {
        ubev_utp_close(u);
        ubev_bev_graceful_close(u);
    }
    return 0;
}

uint64 utp_on_read(utp_callback_arguments *a)
{
    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);
    if (u->bev) {
        //debug("writing utp>bev %d bytes\n", a->len);
        if (!u->utp_input) {
            u->utp_input = evbuffer_new();
        }
        evbuffer_add(u->utp_input, a->buf, a->len);
        of_state s = u->obfoo->state;
        if (obfoo_input_filter(u->utp_input, bufferevent_get_output(u->bev), u->obfoo) < 0) {
            ubev_utp_close(u);
            ubev_bev_graceful_close(u);
            return 0;
        }
        if (s < OF_STATE_DISCARD && u->obfoo->state >= OF_STATE_DISCARD) {
            // writing is now possible, flush
            ubev_read_cb(u->bev, u);
        }
    }
    return 0;
}

void ubev_bev_stop_writing(utp_bufferevent *u)
{
    assert(!evbuffer_get_length(bufferevent_get_output(u->bev)));
    bufferevent_disable(u->bev, EV_WRITE);
    if (ubev_check_close(u)) {
        return;
    }
    shutdown(bufferevent_getfd(u->bev), SHUT_WR);
}

uint64 utp_on_state_change(utp_callback_arguments *a)
{
    utp_bufferevent *u = (utp_bufferevent*)utp_get_userdata(a->socket);
    if (a->state != UTP_STATE_WRITABLE) {
        //debug("utp_on_state_change state:%d %s\n", a->state, utp_state_names[a->state]);
    }
    if (!u) {
        return 0;
    }

    switch (a->state) {
    case UTP_STATE_CONNECT:
        if (u->other_bev) {
            bufferevent_event_cb event_cb;
            void *d;
            bufferevent_getcb(u->other_bev, NULL, NULL, &event_cb, &d);
            if (event_cb) {
                event_cb(u->other_bev, BEV_EVENT_CONNECTED, d);
            }
            bufferevent_decref(u->other_bev);
            u->other_bev = NULL;
        }
    case UTP_STATE_WRITABLE:
        utp_bufferevent_flush(u);
        if (!(bufferevent_get_enabled(u->bev) & EV_READ ||
              evbuffer_get_length(bufferevent_get_input(u->bev)))) {
            if (ubev_check_close(u)) {
                return 0;
            }
            utp_shutdown(u->utp, SHUT_WR);
        }
        break;
    case UTP_STATE_EOF:
        u->utp_eof = true;
        if (!evbuffer_get_length(bufferevent_get_output(u->bev))) {
            ubev_bev_stop_writing(u);
        }
        break;
    case UTP_STATE_DESTROYING:
        break;
    }

    return 0;
}

void utp_outbuf_cb(evbuffer *buf, const evbuffer_cb_info *cbinfo, void *ctx)
{
    //debug("%s %p added:%zu deleted:%zu\n", __func__, ctx, cbinfo->n_added, cbinfo->n_deleted);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    if (cbinfo->n_added) {
        utp_bufferevent_flush(u);
    }
}

void ubev_write_cb(bufferevent *bev, void *ctx)
{
    //debug("%s %p\n", __func__, ctx);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    // the output buffer is flushed
    assert(!evbuffer_get_length(bufferevent_get_output(u->bev)));
    if (!u->utp) {
        bufferevent_disable(u->bev, EV_WRITE);
        ubev_bev_close(u);
        ubev_cleanup(u);
        return;
    }
    utp_read_drained(u->utp);
    if (u->utp_eof) {
        ubev_bev_stop_writing(u);
    }
}

void ubev_event_cb(bufferevent *bev, short events, void *ctx)
{
    //debug("%s %p %x\n", __func__, ctx, events);
    utp_bufferevent* u = (utp_bufferevent*)ctx;
    if (!(bufferevent_get_enabled(bev) & EV_READ)) {
        if (u->utp && !evbuffer_get_length(bufferevent_get_input(u->bev))) {
            utp_shutdown(u->utp, SHUT_WR);
        }
    }
    if (!(bufferevent_get_enabled(bev) & EV_WRITE)) {
        evbuffer_clear(bufferevent_get_output(u->bev));
        if (u->utp) {
            utp_shutdown(u->utp, SHUT_RD);
        }
    }
    ubev_check_close(u);
}

utp_bufferevent* utp_bufferevent_new(event_base *base, utp_socket *s, int fd)
{
    utp_bufferevent *u = alloc(utp_bufferevent);
    u->utp = s;
    utp_set_userdata(s, u);
    u->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!u->bev) {
        ubev_utp_close(u);
        ubev_cleanup(u);
        return NULL;
    }
    u->obfoo = obfoo_new();
    u->utp_output = evbuffer_new();
    evbuffer_add_cb(u->utp_output, utp_outbuf_cb, u);
    u->obfoo->output = u->utp_output;
    u->obfoo->incoming = true;
    bufferevent_setcb(u->bev, ubev_read_cb, ubev_write_cb, ubev_event_cb, u);
    bufferevent_enable(u->bev, EV_READ|EV_WRITE);
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

bufferevent* utp_socket_create_bev(event_base *base, utp_socket *s, bool encrypt)
{
    int fds[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);
    evutil_make_socket_closeonexec(fds[0]);
    evutil_make_socket_nonblocking(fds[0]);
    utp_bufferevent *u = utp_bufferevent_new(base, s, fds[0]);
    if (!u) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }
    evutil_make_socket_closeonexec(fds[1]);
    evutil_make_socket_nonblocking(fds[1]);
    u->other_bev = bufferevent_socket_new(base, fds[1], BEV_OPT_CLOSE_ON_FREE);
    bufferevent_incref(u->other_bev);
    if (encrypt) {
        u->obfoo->incoming = false;
        obfoo_write_intro(u->obfoo, u->obfoo->output);
    } else {
        u->obfoo->state = OF_STATE_DISABLED;
    }
    return u->other_bev;
}

void utp_connect_tcp(event_base *base, utp_socket *s, const sockaddr *address, socklen_t address_len)
{
    utp_bufferevent *u = utp_bufferevent_new(base, s, -1);
    if (bufferevent_socket_connect(u->bev, address, address_len) < 0) {
        bufferevent_free(u->bev);
        u->bev = NULL;
        ubev_utp_close(u);
        ubev_cleanup(u);
        fprintf(stderr, "bufferevent_socket_connect failed");
    }
}
