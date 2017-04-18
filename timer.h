#ifndef __TIMER_H__
#define __TIMER_H__

#include <event2/event_struct.h>

#include "network.h"


typedef struct event event;

typedef void (^callback)();

typedef struct {
    event event;
    callback cb;
} timer;

timer* timer_start(network *n, uint64_t timeout_ms, callback cb);
timer* timer_repeating(network *n, uint64_t timeout_ms, callback cb);
void timer_cancel(timer *t);

#endif // __TIMER_H__
