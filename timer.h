#ifndef __TIMER_H__
#define __TIMER_H__

#include <Block.h>

#include <event2/event_struct.h>

typedef struct timer timer;

#include "network.h"


typedef void (^timer_callback)(void);

struct timer {
    event event;
    timer_callback cb;
};

timer* timer_start(network *n, uint64_t timeout_ms, timer_callback cb);
timer* timer_repeating(network *n, uint64_t timeout_ms, timer_callback cb);
void timer_cancel(timer *t);

#endif // __TIMER_H__
