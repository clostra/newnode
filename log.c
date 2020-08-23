#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#ifndef ANDROID
#include <execinfo.h>
#endif

#include "log.h"


int o_debug = 0;


#ifdef ANDROID
void bugsnag_log(const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    void bugsnag_leave_breadcrumb_log(const char *buf);
    bugsnag_leave_breadcrumb_log(buf);
}
#endif

void die(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    assert(0);
}

void pdie(const char *err)
{
    debug("%s: (%d) %s\n", err, errno, strerror(errno));
    assert(0);
}

void hexdump(const void *addr, size_t len)
{
    unsigned char buff[33];
    unsigned char *pc = (unsigned char*)addr;

    if (!len) {
        return;
    }

    size_t i = 0;
    for (i = 0; i < len; i++) {
        if ((i % 32) == 0) {
            if (i != 0) {
                fprintf(stderr, "  %s\n", buff);
            }
            fprintf(stderr, "  %04zx ", i);
        }
        fprintf(stderr, " %02x", pc[i]);

        buff[i % 32] = isprint(pc[i]) ? pc[i] : '.';
        buff[(i % 32) + 1] = '\0';
    }

    while ((i % 32) != 0) {
        fprintf(stderr, "   ");
        i++;
    }

    fprintf(stderr, "  %s\n", buff);
}
