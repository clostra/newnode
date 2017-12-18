#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>


extern int o_debug;

void die(const char *fmt, ...);
void debug(const char *fmt, ...);
#define ddebug if (o_debug >= 2) debug
void pdie(const char *err);
void hexdump(const void *p, size_t len);
void print_trace();

#endif // __LOG_H__
