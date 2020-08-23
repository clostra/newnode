#ifndef ANDROID
#include <execinfo.h>
#else
// TODO: libunwind-ndk
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "backtrace.h"


volatile bool g_backtrace_occurred;
volatile pthread_t g_backtrace_thread;


#ifndef ANDROID
void print_trace_skip(int skip)
{
    void *array[100];
    size_t size = backtrace(array, sizeof(array) / sizeof(array[0]));
    char **strings = backtrace_symbols(array, size);
    for (size_t i = 1 + skip; i < size; i++) {
        printf("%s\n", strings[i]);
    }
    free(strings);
}
#else
void print_trace_skip(int skip)
{
    // TODO: libunwind-ndk
}
#endif

void print_trace()
{
    print_trace_skip(0);
}

static void backtrace_signal_handler(int signum, siginfo_t *info, void *context)
{
    if (!pthread_equal(g_backtrace_thread, pthread_self())) {
        return;
    }
    // backtrace_signal_handler, _sigtramp
    print_trace_skip(2);
    g_backtrace_occurred = true;
}

void backtrace_thread(pthread_t thread)
{
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
}
