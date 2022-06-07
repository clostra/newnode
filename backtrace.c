#ifndef ANDROID
#include <execinfo.h>
#else
// TODO: libunwind-ndk
#endif
#include "log.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "backtrace.h"
#include "network.h"


volatile bool g_backtrace_occurred;
volatile pthread_t g_backtrace_thread;
void *backtrace_array[100];
size_t backtrace_array_size;

#ifndef ANDROID
void print_backtrace_array(void *array, size_t size)
{
    char **strings = backtrace_symbols(array, size);
    for (size_t i = 0; i < size; i++) {
        log_error("%s\n", strings[i]);
    }
    free(strings);
}
void print_trace_skip(int skip)
{
    void *array[100];
    size_t size = backtrace(array, lenof(array));
    print_backtrace_array(&array[skip], size - skip);
}
#else
void print_trace_skip(int skip)
{
    // TODO: libunwind-ndk
}

int backtrace(void **buffer, int size)
{
    return 0;
}

#endif

void print_trace()
{
    print_trace_skip(0);
}

#ifdef ANDROID
void backtrace_thread(pthread_t thread)
{
    debug("(alas, backtrace isn't implemented yet for Android.)\n");
}
#else
static void backtrace_signal_handler(int signum, siginfo_t *info, void *context)
{
    if (!pthread_equal(g_backtrace_thread, pthread_self())) {
        return;
    }
    backtrace_array_size = backtrace(backtrace_array, lenof(backtrace_array));
    g_backtrace_occurred = true;
}

void backtrace_thread(pthread_t thread)
{
    // pre-call this to make sure dlopen is not called in the signal handler
    void *dummy_trace_array[1];
    backtrace(dummy_trace_array, lenof(dummy_trace_array));

    g_backtrace_occurred = false;
    g_backtrace_thread = thread;

    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = backtrace_signal_handler;
    sigaction(SIGXCPU, &sa, NULL);
    pthread_kill(g_backtrace_thread, SIGXCPU);

    while (!g_backtrace_occurred) {
        usleep(10 * 1000);
    }

    // backtrace_signal_handler, _sigtramp
    int skip = MIN(backtrace_array_size, 2);
    print_backtrace_array(&backtrace_array[skip], backtrace_array_size - skip);
}
#endif
