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

void bev_splice_write_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    //debug("bev_splice_write_cb bev:%p other:%p\n", bev, other);
    bufferevent_write_buffer(bev, bufferevent_get_input(other));
}

void bev_splice_free_cb(bufferevent *bev, void *ctx)
{
    debug("bev_splice_free_cb bev:%p\n");
    bufferevent_free(bev);
}

void bev_splice_free_after_write(bufferevent *bev)
{
    if (evbuffer_get_length(bufferevent_get_output(bev))) {
        bufferevent_setcb(bev, NULL, bev_splice_free_cb, bev_splice_event_cb, NULL);
        return;
    }
    bufferevent_free(bev);
}

void bev_splice_shutdown_write_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    debug("bev_splice_shutdown_write_cb bev:%p other:%p\n", bev, other);
    assert(!evbuffer_get_length(bufferevent_get_output(bev)));
    assert(!(bufferevent_get_enabled(other) & EV_READ));
    if (bufferevent_get_enabled(bev) & EV_READ) {
        bufferevent_disable(bev, EV_WRITE);
        shutdown(bufferevent_getfd(bev), SHUT_WR);
        return;
    }
    assert(!evbuffer_get_length(bufferevent_get_input(bev)));
    bev_splice_free_after_write(other);
    bufferevent_free(bev);
}

void evbuffer_clear(evbuffer *buf)
{
    evbuffer_unfreeze(buf, 1);
    evbuffer_drain(buf, evbuffer_get_length(buf));
    evbuffer_freeze(buf, 1);
    assert(!evbuffer_get_length(buf));
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
    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT)) {
        if (events & BEV_EVENT_READING) assert(!(bufferevent_get_enabled(bev) & EV_READ));
        if (events & BEV_EVENT_WRITING) assert(!(bufferevent_get_enabled(bev) & EV_WRITE));
    }
    if (events & BEV_EVENT_ERROR) {
        if (other) {
            bev_splice_stop_reading(other);
            bev_splice_free_after_write(other);
        }
        bufferevent_free(bev);
    } else if (events & BEV_EVENT_EOF) {
        if (other) {
            if (events & BEV_EVENT_WRITING) {
                evbuffer_clear(bufferevent_get_output(bev));
                bev_splice_stop_reading(other);
                if (!(bufferevent_get_enabled(bev) & EV_READ)) {
                    bev_splice_free_after_write(other);
                    bufferevent_free(bev);
                    return;
                }
            }
            if (events & BEV_EVENT_READING) {
                bufferevent_setcb(other, bev_splice_read_cb, bev_splice_shutdown_write_cb, bev_splice_event_cb, bev);
                if (!evbuffer_get_length(bufferevent_get_output(other))) {
                    bev_splice_shutdown_write_cb(other, bev);
                }
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
