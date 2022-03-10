#include <stdlib.h>
#include <assert.h>

#include "timer.h"


void timer_free(timer *t)
{
    assert(!evtimer_pending(&t->event, NULL));
    Block_release(t->cb);
    free(t);
}

void evtimer_callback(evutil_socket_t fd, short events, void *arg)
{
    timer *t = (timer*)arg;
    t->cb();
    if (!(event_get_events(&t->event) & EV_PERSIST)) {
        timer_free(t);
    }
}

void timer_cancel(timer *t)
{
    if (!t) {
        return;
    }
    evtimer_del(&t->event);
    timer_free(t);
}

timer* timer_new(network *n, uint64_t timeout_ms, short events, timer_callback cb)
{
    timer *t = alloc(timer);
    t->cb = Block_copy(cb);
    if (event_assign(&t->event, n->evbase, -1, events, evtimer_callback, t)) {
        timer_free(t);
        return NULL;
    }
    if (timeout_ms) {
        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        evtimer_add(&t->event, &timeout);
    } else {
        event_active(&t->event, 0, 0);
    }
    return t;
}

timer* timer_start(network *n, uint64_t timeout_ms, timer_callback cb)
{
    return timer_new(n, timeout_ms, 0, cb);
}

timer* timer_repeating(network *n, uint64_t timeout_ms, timer_callback cb)
{
    return timer_new(n, timeout_ms, EV_PERSIST, cb);
}
