#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log.h"
#include "bev_splice.h"
#include "assert.h"


#define WRITE_WATERMARK 64*1024
#define READ_WATERMARK 64*1024


void bev_splice_read_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    debug("bev_splice_read_cb bev:%p other:%p\n", bev, other);
    if (!evbuffer_get_length(bufferevent_get_output(other))) {
        bufferevent_write_buffer(other, bufferevent_get_input(bev));
    }
}

void bev_splice_write_cb(bufferevent *bev, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    debug("bev_splice_write_cb bev:%p other:%p\n", bev, other);

    if (other) {
        bufferevent_write_buffer(bev, bufferevent_get_input(other));
    } else {
        bufferevent_free(bev);
    }
}

void bev_splice_event_cb(bufferevent *bev, short events, void *ctx)
{
    bufferevent *other = (bufferevent *)ctx;
    debug("bev_splice_event_cb events:%x bev:%p other:%p\n", events, bev, other);

    if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (events & BEV_EVENT_ERROR) {
            bufferevent_disable(bev, EV_WRITE);
            bufferevent_disable(bev, EV_READ);
        }
        if (events & BEV_EVENT_EOF) {
            bufferevent_disable(bev, EV_READ);
        }
        if (other) {
            bufferevent_write_buffer(other, bufferevent_get_input(bev));
            if (evbuffer_get_length(bufferevent_get_output(other))) {
                bufferevent_setcb(other, NULL, bev_splice_write_cb, bev_splice_event_cb, NULL);
                // data in the input buffer is lost
                evbuffer *input = bufferevent_get_input(other);
                evbuffer_unfreeze(input, 1);
                evbuffer_drain(input, evbuffer_get_length(input));
                evbuffer_freeze(input, 1);
                assert(!evbuffer_get_length(input));
                bufferevent_disable(other, EV_READ);
            } else {
                bufferevent_free(other);
            }
        }
        bufferevent_free(bev);
    }
    if (events & BEV_EVENT_CONNECTED) {
        bev_splice_write_cb(bev, ctx);
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
