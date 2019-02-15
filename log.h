#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>

#ifdef ANDROID
#include <android/log.h>
#endif

extern int o_debug;

#ifdef ANDROID
void bugsnag_log(const char *fmt, ...);
#define debug(...) if (o_debug) { __android_log_print(ANDROID_LOG_VERBOSE, "newnode", __VA_ARGS__); } \
    bugsnag_log(__VA_ARGS__);

#undef assert
#define assert(e) if (!(e)) { \
    bugsnag_log("%s:%d: %s: assertion \"%s\" failed", __FILE__, __LINE__, __PRETTY_FUNCTION__, #e); \
    __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, #e); \
}

#else
#define debug(...) if (o_debug) { fflush(stdout); fprintf(stderr, __VA_ARGS__); fflush(stderr); }
#endif

#define ddebug(...) if (o_debug >= 2) { debug(__VA_ARGS__); }

void die(const char *fmt, ...);
void pdie(const char *err);
void hexdump(const void *p, size_t len);
void print_trace(void);

#endif // __LOG_H__
