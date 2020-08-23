#include "stall_detector.h"
#include "network.h"
#include "log.h"
#include "thread.h"
#include "backtrace.h"

#include <pthread.h>
#include <event2/watch.h>


uint64_t stall_last_prepare;
uint64_t stall_last_check;
pthread_mutex_t stall_lock;

double ms_delta(uint64_t t)
{
    return (double)(us_clock() - t) / 1000.0;
}

static void check_cb(evwatch *watch, const evwatch_check_cb_info *info, void *arg)
{
    stall_last_check = us_clock();
    //debug("check:  %llu delta:%.2fms\n", stall_last_check, ms_delta(stall_last_prepare));
    pthread_mutex_unlock(&stall_lock);
}

static void prepare_cb(evwatch *watch, const evwatch_prepare_cb_info *info, void *arg)
{
    pthread_mutex_lock(&stall_lock);
    stall_last_prepare = us_clock();
    //debug("prepare:%llu delta:%.2fms\n", stall_last_prepare, ms_delta(stall_last_check));
}

void stall_detector(event_base *base)
{
    evwatch_prepare_new(base, prepare_cb, NULL);
    evwatch_check_new(base, check_cb, NULL);
    pthread_mutex_init(&stall_lock, NULL);
    pthread_t ev_thread = pthread_self();
    thread(^{
        for (;;) {
            pthread_mutex_lock(&stall_lock);
            if (stall_last_check > stall_last_prepare && ms_delta(stall_last_check) > 100) {
                uint64_t stall_prepare = stall_last_prepare;
                debug("event loop stalled! delta:%.2fms\n", ms_delta(stall_last_check));
                backtrace_thread(ev_thread);
                while (stall_prepare == stall_last_prepare) {
                    pthread_mutex_unlock(&stall_lock);
                    usleep(10 * 1000);
                    pthread_mutex_lock(&stall_lock);
                }
            }
            pthread_mutex_unlock(&stall_lock);
            usleep(10 * 1000);
        }
    });
}
