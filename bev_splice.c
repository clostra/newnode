#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "bev_splice.h"
#include "assert.h"


#define READ_WATERMARK 64*1024


void bev_splice_event_cb(bufferevent *bev, short events, void *ctx);

void bev_splice_read_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    //debug("bev_splice_read_cb bev:%p other:%p\n", bev, other);
    if (!evbuffer_get_length(bufferevent_get_output(other))) {
        bufferevent_write_buffer(other, bufferevent_get_input(bev));
    }
}

void bev_splice_free_cb(bufferevent *bev, void *ctx)
{
    //debug("bev_splice_free_cb bev:%p\n");
    bufferevent_free(bev);
}

void bev_splice_graceful_close(bufferevent *bev)
{
    if (evbuffer_get_length(bufferevent_get_output(bev))) {
        bufferevent_setcb(bev, NULL, bev_splice_free_cb, bev_splice_event_cb, NULL);
        return;
    }
    bufferevent_free(bev);
}

void bev_splice_stop_writing(bufferevent *bev, bufferevent *other)
{
    if (bufferevent_get_enabled(bev) & EV_READ) {
        bufferevent_disable(bev, EV_WRITE);
        shutdown(bufferevent_getfd(bev), SHUT_WR);
        return;
    }
    assert(!evbuffer_get_length(bufferevent_get_input(bev)));
    bev_splice_graceful_close(other);
    bufferevent_free(bev);
}

void bev_splice_write_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    //debug("bev_splice_write_cb bev:%p other:%p\n", bev, other);
    assert(!evbuffer_get_length(bufferevent_get_output(bev)));
    if (bufferevent_get_enabled(other) & EV_READ) {
        bufferevent_write_buffer(bev, bufferevent_get_input(other));
        return;
    }
    bev_splice_stop_writing(bev, other);
}

void bev_splice_stop_reading(bufferevent *bev)
{
    evbuffer_clear(bufferevent_get_input(bev));
    bufferevent_disable(bev, EV_READ);
    shutdown(bufferevent_getfd(bev), SHUT_RD);
}

void bev_splice_event_cb(bufferevent *bev, short events, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    debug("bev_splice_event_cb events:0x%x bev:%p other:%p\n", events, bev, other);
    if (events & BEV_EVENT_CONNECTED) {
        bev_splice_write_cb(bev, ctx);
    }
    if (other) {
        bufferevent_write_buffer(other, bufferevent_get_input(bev));
    }
    if (events & BEV_EVENT_ERROR) {
        if (other) {
            bev_splice_stop_reading(other);
            bev_splice_graceful_close(other);
        }
        bufferevent_free(bev);
    } else if (events & BEV_EVENT_EOF) {
        if (events & BEV_EVENT_WRITING) {
            if (other) {
                bev_splice_stop_reading(other);
            }
            if (!(bufferevent_get_enabled(bev) & EV_READ)) {
                if (other) {
                    bev_splice_graceful_close(other);
                }
                bufferevent_free(bev);
                return;
            }
            evbuffer_clear(bufferevent_get_output(bev));
        }
        if (events & BEV_EVENT_READING) {
            if (!evbuffer_get_length(bufferevent_get_output(other))) {
                bev_splice_stop_writing(other, bev);
            }
        }
    }
}

void bev_splice(bufferevent *bev, bufferevent *other)
{
    debug("bev_splice bev:%p other:%p\n", bev, other);
    bufferevent_setcb(bev, bev_splice_read_cb, bev_splice_write_cb, bev_splice_event_cb, other);
    bufferevent_setcb(other, bev_splice_read_cb, bev_splice_write_cb, bev_splice_event_cb, bev);
    bufferevent_setwatermark(bev, EV_READ, 0, READ_WATERMARK);
    bufferevent_setwatermark(other, EV_READ, 0, READ_WATERMARK);
}
