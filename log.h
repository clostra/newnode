#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>


extern int o_debug;

void die(const char *fmt, ...);
void debug(const char *fmt, ...);
void pdie(const char *err);
void hexdump(const void *p, size_t len);

#endif // __LOG_H__
