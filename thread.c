#include <stddef.h>
#include <pthread.h>

#include "thread.h"


void* thread_runner(void *userdata)
{
    thread_body tb = (thread_body)userdata;
    tb();
    Block_release(tb);
    return NULL;
}

void thread(thread_body tb)
{
    tb = Block_copy(tb);
    pthread_t t;
    if (pthread_create(&t, NULL, thread_runner, tb) == -1) {
        Block_release(tb);
        return;
    }
    pthread_detach(t);
}
