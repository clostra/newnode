#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifndef ANDROID
#include <execinfo.h>
#endif

int o_debug = 0;

void die(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

void debug(const char *fmt, ...)
{
    va_list ap;
    if (o_debug) {
        fflush(stdout);
        //fprintf(stderr, "debug: ");
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fflush(stderr);
    }
}

void pdie(const char *err)
{
    debug("%s: (%d) %s\n", err, errno, strerror(errno));
    assert(0);
}

void hexdump(const void *p, size_t len)
{
    int count = 1;

    while (len--) {
        if (count == 1) {
            fprintf(stderr, "    %p: ", p);
        }

        fprintf(stderr, " %02x", *(unsigned char *)p++ & 0xff);

        if (count++ == 16) {
            fprintf(stderr, "\n");
            count = 1;
        }
    }

    if (count != 1) {
        fprintf(stderr, "\n");
    }
}

#ifndef ANDROID
void print_trace()
{
    void *array[100];
    size_t size = backtrace(array, sizeof(array) / sizeof(array[0]));
    char **strings = backtrace_symbols(array, size);
    for (size_t i = 0; i < size; i++) {
        printf("%s\n", strings[i]);
    }
    free(strings);
}
#endif
