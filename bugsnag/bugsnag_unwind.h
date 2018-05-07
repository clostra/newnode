#ifndef NDKTEST_UNWIND_H
#define NDKTEST_UNWIND_H

#include <jni.h>
#include <android/log.h>
#include "bugsnag_ndk.h"
#include <signal.h>
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include <unwind.h>

#include "deps/bugsnag/bugsnag.h"
#include "deps/bugsnag/report.h"

/* The number of works to look through to find the next program counter */
#define WORDS_TO_SCAN 40

/* Structure to store unwound frame */
typedef struct unwind_struct_frame {
    void *frame_pointer;
    char method[1024];
} unwind_struct_frame;

/* Structure to store unwound frames */
typedef struct unwind_struct {
    unwind_struct_frame frames[BUGSNAG_FRAMES_MAX];
} unwind_struct;

typedef struct {
    uintptr_t absolute_pc;
    uintptr_t stack_top;
    size_t stack_size;
} backtrace_frame_t;

typedef struct {
    uintptr_t relative_pc;
    uintptr_t relative_symbol_addr;
    char* map_name;
    char* symbol_name;
    char* demangled_name;
} backtrace_symbol_t;

/* Extracted from Android's include/corkscrew/backtrace.h */
typedef struct map_info_t map_info_t;

extern int bugsnag_unwind_stack(unwind_struct* unwind, int max_depth, struct siginfo* si, void* sc);

extern int is_system_method(const char *method);

extern int is_system_file(const char *file);

extern size_t unwind_current_context(void** buffer, size_t max);

#endif //NDKTEST_UNWIND_H
