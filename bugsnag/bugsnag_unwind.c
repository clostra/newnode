#include <string.h>

#define HAVE_CONFIG_H
#include <libunwind.h>
#include <mempool.h>

#define _GNU_SOURCE
#include <unwind.h>

#include "bugsnag_unwind.h"


/**
 * Checks to see if the given string starts with the given prefix
 */
static int starts_with(const char *pre, const char *str)
{
    if (str == NULL) {
        return 0; // false
    }

    size_t lenpre = strlen(pre);
    size_t lenstr = strlen(str);

    if (lenstr < lenpre) {
        return 0; // false
    } else {
        return strncmp(pre, str, lenpre) == 0;
    }
}


/**
 * structure used when using <unwind.h> to get the trace for the current context
 */
struct BacktraceState
{
    void** current;
    void** end;
};

/**
 * callback used when using <unwind.h> to get the trace for the current context
 */
static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* context, void* arg)
{
    struct BacktraceState* state = (struct BacktraceState*)arg;
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = (void*)pc;
        }
    }
    return _URC_NO_REASON;
}

/**
 * uses built in <unwind.h> to get the trace for the current context
 */
size_t unwind_current_context(void** buffer, size_t max) {
    struct BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(unwind_callback, &state);

    return state.current - buffer;
}

/**
 * Checks if the given string is considered a "system" method or not
 * NOTE: some methods seem to get added to binaries automatically to catch arithmetic errors
 */
int is_system_method(const char *method) {
    if (starts_with("__aeabi_", method)
        || starts_with("oatexec", method)) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Checks if the given string should be considered a "system" file or not
 */
int is_system_file(const char *library_file_name) {
    return strstr(library_file_name, "/system/") ||
           strstr(library_file_name, "libc.so") ||
           strstr(library_file_name, "libart.so") ||
           strstr(library_file_name, "libdvm.so") ||
           strstr(library_file_name, "libcutils.so") ||
           strstr(library_file_name, "libandroid_runtime.so") ||
           strstr(library_file_name, "libbcc.so") ||
           strstr(library_file_name, "base.odex") ||
           strstr(library_file_name, "[vdso]") ||
           strstr(library_file_name, "[heap]");
}

static void ndcrash_libunwind_get_context(struct ucontext *context, unw_context_t *unw_ctx) {
#if defined(__arm__)
    struct sigcontext *sig_ctx = &context->uc_mcontext;
    memcpy(unw_ctx->regs, &sig_ctx->arm_r0, sizeof(unw_ctx->regs));
#elif defined(__i386__) || defined(__x86_64__) || defined(__aarch64__)
    *unw_ctx = *context;
#else
#error Architecture is not supported.
#endif
}

int unwind_libunwind(unwind_struct* unwind, int max_depth, struct ucontext *context)
{
    int size = 0;

    // Parsing local /proc/pid/maps
    unw_map_local_create();

    // Cursor - the main structure used for unwinding with a huge size. Allocating on stack is undesirable
    // due to limited alternate signal stack size. malloc isn't signal safe. Using libunwind memory pools.
    struct mempool cursor_pool;
    mempool_init(&cursor_pool, sizeof(unw_cursor_t), 0);
    unw_cursor_t * const unw_cursor = mempool_alloc(&cursor_pool);

    // Buffer for function name.
    char unw_function_name[64];

    // Initializing context instance (processor state).
    unw_context_t unw_ctx;
    ndcrash_libunwind_get_context(context, &unw_ctx);

    // Initializing cursor for unwinding from passed processor context.
    if (!unw_init_local(unw_cursor, &unw_ctx)) {

        for (int i = 0; i < max_depth; ++i) {
            // Getting program counter value for the a current stack frame.
            unw_word_t regip;
            unw_get_reg(unw_cursor, UNW_REG_IP, &regip);

            // Looking for a function name.
            unw_word_t func_offset;
            const bool func_name_found = unw_get_proc_name(
                    unw_cursor, unw_function_name, sizeof(unw_function_name), &func_offset) > 0;

            // Looking for a object (shared library) where a function is located.
            unw_map_cursor_t proc_map_cursor;
            unw_map_local_cursor_get(&proc_map_cursor);
            bool maps_found = false;
            unw_map_t proc_map_item;
            while (unw_map_cursor_get_next(&proc_map_cursor, &proc_map_item) > 0) {
                if (regip >= proc_map_item.start && regip < proc_map_item.end) {
                    maps_found = true;
                    regip -= proc_map_item.start; // Making relative.
                    break;
                }
            }

            unwind_struct_frame *frame = &unwind->frames[size];

            snprintf(frame->file, sizeof(frame->file), "%s", maps_found ? proc_map_item.path : NULL);
            snprintf(frame->method, sizeof(frame->method), "%s", func_name_found ? unw_function_name : NULL);
            frame->frame_pointer = (void*)regip;

            size++;

            // Trying to switch to a previous stack frame.
            if (unw_step(unw_cursor) <= 0) break;
        }
    }

    // Freeing a memory for cursor.
    mempool_free(&cursor_pool, unw_cursor);

    // Destroying local /proc/pid/maps
    unw_map_local_destroy();

    return size;
}

/**
 * Finds a way to unwind the stack trace
 * falls back to simply returning the top frame information
 */
int bugsnag_unwind_stack(unwind_struct* unwind, int max_depth, struct siginfo* si, void* sc) {
    return unwind_libunwind(unwind, max_depth, sc);
}
