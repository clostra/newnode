#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>

#ifdef ANDROID
#include <android/log.h>
#endif

extern int o_debug;

#ifdef ANDROID
#define debug(...) if (o_debug) { __android_log_print(ANDROID_LOG_VERBOSE, "dcdn", __VA_ARGS__); }
#else
void debug(const char *fmt, ...);
#endif

#define ddebug if (o_debug >= 2) debug

void die(const char *fmt, ...);
void pdie(const char *err);
void hexdump(const void *p, size_t len);
void print_trace();

#endif // __LOG_H__
