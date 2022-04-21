#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "bev_splice.h"
#include "assert.h"


#define READ_WATERMARK 64*1024

void bev_splice_shutdown_write(bufferevent *bev)
{
    if (!evbuffer_get_length(bufferevent_get_output(bev))) {
        bufferevent_disable(bev, EV_WRITE);
        // XXX: utp_shutdown()
        shutdown(bufferevent_getfd(bev), SHUT_WR);
    }
}

void bev_splice_read_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    if (!evbuffer_get_length(bufferevent_get_output(other))) {
        bufferevent_write_buffer(other, bufferevent_get_input(bev));
    }
}

void bev_splice_write_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    bev_splice_read_cb(other, bev);
    if (!(bufferevent_get_enabled(other) & EV_READ)) {
        bev_splice_shutdown_write(bev);
    }
}

void bev_splice_free_write_cb(bufferevent *bev, void *ctx)
{
    if (!evbuffer_get_length(bufferevent_get_output(bev))) {
        bufferevent_disable(bev, EV_WRITE);
        bufferevent_free_checked(bev);
    }
}

void bev_splice_free_event_cb(bufferevent *bev, short events, void *ctx)
{
    evbuffer_clear(bufferevent_get_output(bev));
    bufferevent_free_checked(bev);
}

void bev_splice_event_cb(bufferevent *bev, short events, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    //debug("bev_splice_event_cb events:0x%x bev:%p other:%p\n", events, bev, other);
    if (events & BEV_EVENT_CONNECTED) {
        bev_splice_write_cb(bev, other);
        return;
    }
    if (!(bufferevent_get_enabled(bev) & EV_READ)) {
        bufferevent_write_buffer(other, bufferevent_get_input(bev));
        bev_splice_shutdown_write(other);
    }
    if (!(bufferevent_get_enabled(bev) & EV_WRITE)) {
        evbuffer_clear(bufferevent_get_input(other));
        evbuffer_clear(bufferevent_get_output(bev));
        bufferevent_disable(other, EV_READ);
        // XXX: utp_shutdown()
        shutdown(bufferevent_getfd(other), SHUT_RD);
    }

    if (!bufferevent_get_enabled(bev)) {
        if (evbuffer_get_length(bufferevent_get_output(other))) {
            bufferevent_setcb(other, NULL, bev_splice_free_write_cb, bev_splice_free_event_cb, NULL);
        } else {
            bev_splice_free_write_cb(other, NULL);
        }
        bufferevent_free_checked(bev);
    }
}

void bev_splice(bufferevent *bev, bufferevent *other)
{
    //debug("bev_splice bev:%p other:%p\n", bev, other);
    bufferevent_setcb(bev, bev_splice_read_cb, bev_splice_write_cb, bev_splice_event_cb, other);
    bufferevent_setcb(other, bev_splice_read_cb, bev_splice_write_cb, bev_splice_event_cb, bev);
    bufferevent_setwatermark(bev, EV_READ, 0, READ_WATERMARK);
    bufferevent_setwatermark(other, EV_READ, 0, READ_WATERMARK);
}
