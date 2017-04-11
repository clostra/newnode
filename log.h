#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>


extern int o_debug;

void die(char *fmt, ...);
void debug(char *fmt, ...);
void pdie(char *err);
void hexdump(const void *p, size_t len);

#endif // __LOG_H__
