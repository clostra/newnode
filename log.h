#ifndef __LOG_H__
#define __LOG_H__

#include <sys/types.h>

extern int o_debug;

#ifdef __ANDROID__
#include <android/log.h>
void bugsnag_log(const char *fmt, ...);
#define log_error(...) __android_log_print(ANDROID_LOG_ERROR, "newnode", __VA_ARGS__); bugsnag_log(__VA_ARGS__);
#define debug(...) if (o_debug) { __android_log_print(ANDROID_LOG_VERBOSE, "newnode", __VA_ARGS__); } bugsnag_log(__VA_ARGS__);
#define critical(...) 

#undef assert
#define assert(e) if (!(e)) { \
    bugsnag_log("%s:%d: %s: assertion \"%s\" failed", __FILE__, __LINE__, __PRETTY_FUNCTION__, #e); \
    __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, #e); \
}
#elif defined __APPLE__
#include <os/log.h>
#define log_error(...) fflush(stdout); fprintf(stderr, __VA_ARGS__); fflush(stderr); os_log_error(OS_LOG_DEFAULT, __VA_ARGS__); 
#define debug(...) if (o_debug) { fflush(stdout); fprintf(stderr, __VA_ARGS__); fflush(stderr); os_log(OS_LOG_DEFAULT, __VA_ARGS__); }
#else
#define log_error(...) fflush(stdout); fprintf(stderr, __VA_ARGS__); fflush(stderr);
#define debug(...) if (o_debug) { fflush(stdout); fprintf(stderr, __VA_ARGS__); fflush(stderr); }
#endif

#define log_errno(err) log_error("%s %s: (%d) %s\n", __func__, err, errno, strerror(errno));

#define ddebug(...) if (o_debug >= 2) { debug(__VA_ARGS__); }

void hexdump(const void *p, size_t len);

#endif // __LOG_H__
