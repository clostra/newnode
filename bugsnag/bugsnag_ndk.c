#include <signal.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

#include <jni.h>

#include "bugsnag_ndk.h"
#include "bugsnag_ndk_report.h"
#include "bugsnag_unwind.h"


/* Signals to be caught. */
#define BSG_SIG_CATCH_COUNT 6

/* Maximum value of a caught signal. */
#define BSG_SIG_NUMBER_MAX 32

// Globals
/* signals to be handled */
static const int native_sig_catch[BSG_SIG_CATCH_COUNT + 1]
        = { SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV };

/* the Bugsnag signal handler */
struct sigaction *g_sigaction;

/* the old signal handler array */
struct sigaction *g_sigaction_old;

/* the pre-populated Bugsnag error */
struct bugsnag_ndk_report *g_bugsnag_report;

/* structure for storing the unwound stack trace */
unwind_struct *g_native_code;

pthread_mutex_t bsg_lock;

JNIEnv *bugsnagGlobalEnv;

void populate_meta_object(JNIEnv *env, jobject jmeta, JSON_Object * meta_data);
void populate_meta_array(JNIEnv *env, jarray jmeta, JSON_Array * meta_data);

/**
 * Removes any path from the filename to make it consistent across API versions
 */
/*
static char* strip_path_from_file(const char* file) {

    char* pos = (char *) file;
    char* newpos = strchr(pos, '/');

    while (newpos) {
        pos = newpos + 1;
        newpos = strchr(pos, '/');
    }

    return pos;
}
*/

/**
 * Creates a java Double object using the given double
 */
jobject create_double(JNIEnv *env, double dbl) {
    jclass double_class = (*env)->FindClass(env, "java/lang/Double");
    jmethodID double_constructor = (*env)->GetMethodID(env, double_class, "<init>", "(D)V");
    return (*env)->NewObject(env, double_class, double_constructor, (jdouble)dbl);
}

/**
 * Creates a java Boolean object using the given bool value
 */
jobject create_boolean(JNIEnv *env, int bool) {
    jclass boolean_class = (*env)->FindClass(env, "java/lang/Boolean");
    jmethodID boolean_constructor = (*env)->GetMethodID(env, boolean_class, "<init>", "(Z)V");
    return (*env)->NewObject(env, boolean_class, boolean_constructor, (jboolean)bool);
}

/**
 * Populates the given java array with values from the JSON array
 */
void populate_meta_array(JNIEnv *env, jarray jmeta, JSON_Array * meta_data) {

    size_t count = json_array_get_count(meta_data);

    for (size_t i = 0; i < count; i++) {

        JSON_Value *value = json_array_get_value(meta_data, i);
        JSON_Value_Type type = json_value_get_type(value);
        jobject jvalue = NULL;

        if (type == JSONString) {
            jvalue = (*env)->NewStringUTF(env, json_array_get_string(meta_data, i));
        } else if (type == JSONNumber) {
            jvalue = create_double(env, json_array_get_number(meta_data, i));
        } else if (type == JSONBoolean) {
            jvalue = create_boolean(env, json_array_get_boolean(meta_data, i));
        } else if (type == JSONObject) {
            jclass hashmap_class = (*env)->FindClass(env, "java/util/HashMap");
            jmethodID hashmap_constructor = (*env)->GetMethodID(env, hashmap_class, "<init>", "()V");
            jobject jsubmeta = (*env)->NewObject(env, hashmap_class, hashmap_constructor);

            populate_meta_object(env, jsubmeta, json_array_get_object(meta_data, i));

            jvalue = jsubmeta;
        } else if (type == JSONArray) {
            JSON_Array * array = json_array_get_array(meta_data, i);
            size_t array_size = json_array_get_count(array);

            jobject jsubmeta = (*env)->NewObjectArray(env,
                                                      array_size,
                                                      (*env)->FindClass(env, "java/lang/Object"),
                                                      NULL);
            populate_meta_array(env, jsubmeta, array);

            jvalue = jsubmeta;
        }

        if (jvalue != NULL) {
            (*env)->SetObjectArrayElement(env, jmeta, i, jvalue);
        }
    }
}

/**
 * Populates the given java hash map with values from the JSON object
 */
void populate_meta_object(JNIEnv *env, jobject jmeta, JSON_Object * meta_data) {

    jclass hashmap_class = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID put_method = (*env)->GetMethodID(env, hashmap_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    size_t count = json_object_get_count(meta_data);

    for (size_t i = 0; i < count; i++) {

        const char *name = json_object_get_name(meta_data, i);
        jstring jname = (*env)->NewStringUTF(env, name);

        JSON_Value *value = json_object_get_value(meta_data, name);
        JSON_Value_Type type = json_value_get_type(value);
        jobject jvalue = NULL;

        if (type == JSONString) {
            jvalue = (*env)->NewStringUTF(env, json_object_get_string(meta_data, name));
        } else if (type == JSONNumber) {
            jvalue = create_double(env, json_object_get_number(meta_data, name));
        } else if (type == JSONBoolean) {
            jvalue = create_boolean(env, json_object_get_boolean(meta_data, name));
        } else if (type == JSONObject) {
            jmethodID hashmap_constructor = (*env)->GetMethodID(env, hashmap_class, "<init>", "()V");
            jobject jsubmeta = (*env)->NewObject(env, hashmap_class, hashmap_constructor);

            populate_meta_object(env, jsubmeta, json_object_get_object(meta_data, name));

            jvalue = jsubmeta;
        } else if (type == JSONArray) {
            JSON_Array * array = json_object_get_array(meta_data, name);
            size_t array_size = json_array_get_count(array);

            jobject jsubmeta = (*env)->NewObjectArray(env,
                                                      array_size,
                                                      (*env)->FindClass(env, "java/lang/Object"),
                                                      NULL);
            populate_meta_array(env, jsubmeta, array);

            jvalue = jsubmeta;
        }

        if (jvalue != NULL) {
            (*env)->CallObjectMethod(env, jmeta, put_method, jname, jvalue);
        }
    }
}

void bugsnag_init(JNIEnv *env) {
    bugsnagGlobalEnv = env;
}

/**
 * Sends an error report to Bugsnag, optionally attaching a JSON object as metadata. Metadata is
 * formatted as a mapping of named sections of key/value pairs.
 * For example, to attach the value `{"account": {"name": "Acme Co."}}`, construct the JSON value
 * and include it in the invocation of `bugsnag_notify_meta`.
 *
 * ```
 * JSON_Value *metadata_value = json_value_init_object();
 * JSON_Object *metadata = json_value_get_object(metadata_value);
 * JSON_Value *section_value = json_value_init_object();
 * JSON_Object *section = json_value_get_object(tab_value);
 * json_object_set_string(tab, "name", "Acme Co.");
 * json_object_set_value(meta_data, "account", tab_value);
 * bugsnag_notify_meta(env, "Corrupt Store", "Account registry invalidated", metadata);
 * ```
 */
/*
void bugsnag_notify_meta(JNIEnv *env, char* name, char* message, bsg_severity_t severity, JSON_Object * meta_data) {
    void* frames[BUGSNAG_FRAMES_MAX];
    size_t frames_size = unwind_current_context(frames, BUGSNAG_FRAMES_MAX);

    jclass trace_class = (*env)->FindClass(env, "java/lang/StackTraceElement");
    jmethodID trace_constructor = (*env)->GetMethodID(env, trace_class, "<init>",
                                                      "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");
    jobjectArray trace = (*env)->NewObjectArray(env,
                                                0,
                                                (*env)->FindClass(env, "java/lang/StackTraceElement"),
                                                NULL);

    // Ignore the first 3 frames that are in this notify code
    int frames_to_process = frames_size - 3;

    if (frames_to_process > 0) {
        // Create stack trace array
        trace = (*env)->NewObjectArray(env,
                                       frames_to_process,
                                       (*env)->FindClass(env, "java/lang/StackTraceElement"),
                                       NULL);

        // populate stack frame element array
        int i;
        for (i = 0; i < frames_to_process; i++) {

            void *frame = frames[i + (frames_size - frames_to_process)];

            Dl_info info;
            if (dladdr(frame, &info) != 0) {

                jstring class = (*env)->NewStringUTF(env, "");

                jstring filename;
                if (info.dli_fname != NULL) {
                    filename = (*env)->NewStringUTF(env, strip_path_from_file(info.dli_fname));
                } else {
                    filename = (*env)->NewStringUTF(env, "");
                }

                // use the method from unwind if there is one
                jstring methodName;
                if (info.dli_sname != NULL) {
                    methodName = (*env)->NewStringUTF(env, info.dli_sname);
                } else {
                    methodName = (*env)->NewStringUTF(env, "(null)");
                }

                uintptr_t file_offset = (uintptr_t) frame - (uintptr_t) info.dli_fbase;
                jint lineNumber = (int) file_offset;


                // Build up a stack frame
                jobject jframe = (*env)->NewObject(env,
                                                   trace_class,
                                                   trace_constructor,
                                                   class,
                                                   methodName,
                                                   filename,
                                                   lineNumber);

                (*env)->SetObjectArrayElement(env, trace, i, jframe);
            }
        }
    }

    // Create a severity Error
    jclass severity_class = (*env)->FindClass(env, "com/bugsnag/android/Severity");
    jfieldID error_field;
    if (severity == BSG_SEVERITY_ERR) {
        error_field = (*env)->GetStaticFieldID(env, severity_class , "ERROR", "Lcom/bugsnag/android/Severity;");
    } else if (severity == BSG_SEVERITY_WARN) {
        error_field = (*env)->GetStaticFieldID(env, severity_class , "WARNING", "Lcom/bugsnag/android/Severity;");
    } else {
        error_field = (*env)->GetStaticFieldID(env, severity_class , "INFO", "Lcom/bugsnag/android/Severity;");
    }
    jobject jseverity = (*env)->GetStaticObjectField(env, severity_class, error_field);

    jstring jname = (*env)->NewStringUTF(env, name);
    jstring jmessage = (*env)->NewStringUTF(env, message);


    // Build a hashmap of meta data
    jclass hashmap_class = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID hashmap_constructor = (*env)->GetMethodID(env, hashmap_class, "<init>", "()V");
    jobject jmeta = (*env)->NewObject(env, hashmap_class, hashmap_constructor);
    if (meta_data != NULL) {
        populate_meta_object(env, jmeta, meta_data);
    }

    jclass interface_class = (*env)->FindClass(env, "com/bugsnag/android/NativeInterface");
    jmethodID notify_method = (*env)->GetStaticMethodID(env, interface_class, "notify", "(Ljava/lang/String;Ljava/lang/String;Lcom/bugsnag/android/Severity;[Ljava/lang/StackTraceElement;Ljava/util/Map;)V");
    (*env)->CallStaticVoidMethod(env, interface_class, notify_method, jname, jmessage, jseverity, trace, jmeta);

    (*env)->DeleteLocalRef(env, hashmap_class);
    (*env)->DeleteLocalRef(env, jmeta);
    (*env)->DeleteLocalRef(env, trace_class);
    (*env)->DeleteLocalRef(env, trace);
    (*env)->DeleteLocalRef(env, severity_class);
    (*env)->DeleteLocalRef(env, jseverity);
    (*env)->DeleteLocalRef(env, interface_class);
}
*/

/**
 * Manually notify to Bugsnag
 * uses the java notifier to send basic information
 */
/*
void bugsnag_notify_env(JNIEnv *env, char* name, char* message, bsg_severity_t severity) {
    bugsnag_notify_meta(env, name, message, severity, NULL);
}

void bugsnag_notify(char* name, char* message, bsg_severity_t severity) {
    assert(bugsnagGlobalEnv != NULL);
    bugsnag_notify_meta(bugsnagGlobalEnv, name, message, severity, NULL);
}
*/

/**
 * Checks to see if Bugsnag should be notified for this release stage
 */
int should_notify_for_release_stage(const char* release_stage) {

    struct bugsnag_ndk_string_array stages = g_bugsnag_report->notify_release_stages;

    if (stages.size > 0) {
        for (int i = 0; i <stages.size; i++) {
            if (strcmp(stages.values[i], release_stage) == 0) {
                return 1;
            }
        }

        return 0;
    } else {
        return 1;
    }
}

/**
 * Handles signals when errors occur and writes a file to the Bugsnag error cache
 */
static void bugsnag_signal_handler(int code, struct siginfo *si, void *sc) {
    // check to see if this error should be notified
    const char* release_stage = bugsnag_event_get_string(g_bugsnag_report->event, BSG_APP, "releaseStage");
    if (should_notify_for_release_stage(release_stage)) {

        int frames_size = bugsnag_unwind_stack(g_native_code, BUGSNAG_FRAMES_MAX, si, sc);

        // Create an exception message and class
        bsg_exception *exception = g_bugsnag_report->exception;
        sprintf(exception->message, "Fatal signal from native code: %d (%s)", si->si_signo,
                strsignal(si->si_signo));
        sprintf(exception->name, "%s", strsignal(si->si_signo));

        if (frames_size > 0) {

            // populate stack frame element array
            int i;
            for (i = 0; i < frames_size; i++) {

                unwind_struct_frame *unwind_frame = &g_native_code->frames[i];

                bsg_stackframe frame = {
                    .method = unwind_frame->method,
                    .file = unwind_frame->file,
                    .line_number = (int) unwind_frame->frame_pointer,
                    .frame_address = (uintptr_t) unwind_frame->frame_pointer
                };

                if (strlen(unwind_frame->file) == 0) {
                    Dl_info info;
                    if (dladdr(unwind_frame->frame_pointer, &info) != 0) {
                        if (info.dli_fname != NULL) {
                            frame.file = info.dli_fname;
                        }

                        frame.method = info.dli_sname;

                        // Attempt to calculate the line numbers TODO: this gets the position in the file in bytes
                        frame.load_address = (uintptr_t) info.dli_fbase;
                        frame.symbol_address = (uintptr_t) info.dli_saddr;

                        uintptr_t file_offset =
                                (uintptr_t) unwind_frame->frame_pointer - (uintptr_t) info.dli_fbase;
                        frame.line_number = (int) file_offset;
                    }
                }

                // Check if this is a system file, or handler function
                if (is_system_file(frame.file)
                    || is_system_method(frame.method)) {
                    frame.in_project = 0;
                } else {
                    frame.in_project = 1;
                }

                bugsnag_exception_add_frame(exception, frame);
            }
        }

        // Create a filename for the error
        time_t now = time(NULL);
        char filename[strlen(g_bugsnag_report->error_store_path) + 20];
        sprintf(filename, "%s%ld.json", g_bugsnag_report->error_store_path, now);
        FILE *file = fopen(filename, "w+");

        if (file != NULL) {
            pthread_mutex_lock(&bsg_lock);
            char *payload = bugsnag_serialize_event(g_bugsnag_report->event);
            pthread_mutex_unlock(&bsg_lock);
            fputs(payload, file);

            fflush(file);
            fclose(file);
        }
    }

    /* Call previous handler. */
    if (si->si_signo >= 0 && si->si_signo < BSG_SIG_NUMBER_MAX) {
        if (g_sigaction_old[si->si_signo].sa_sigaction != NULL) {
            g_sigaction_old[si->si_signo].sa_sigaction(code, si, sc);
        }
    }
}

/**
 * Adds the Bugsnag signal handler
 */
int setupBugsnag(JNIEnv *env) {
    g_native_code = calloc(sizeof(unwind_struct), 1);
    memset(g_native_code, 0, sizeof(struct unwind_struct));

    bugsnag_report *report = bugsnag_report_init("");
    bsg_event *event = bugsnag_event_init();
    bsg_exception *exception = bugsnag_exception_init("","");
    char *error_store_path = bsg_load_error_store_path(env);
    bugsnag_report_add_event(report, event);
    bugsnag_event_add_exception(event, exception);

    pthread_mutex_init(&bsg_lock, NULL);

    g_bugsnag_report = malloc(sizeof(struct bugsnag_ndk_report));
    memset(g_bugsnag_report, 0, sizeof(struct bugsnag_ndk_report));
    g_bugsnag_report->error_store_path = error_store_path;
    g_bugsnag_report->report = report;
    g_bugsnag_report->event = event;
    g_bugsnag_report->exception = exception;

    bsg_populate_event_details(env, g_bugsnag_report);

    // create a signal handler
    g_sigaction = calloc(sizeof(struct sigaction), 1);
    memset(g_sigaction, 0, sizeof(struct sigaction));
    sigemptyset(&g_sigaction->sa_mask);
    g_sigaction->sa_sigaction = bugsnag_signal_handler;
    g_sigaction->sa_flags = SA_SIGINFO;

    g_sigaction_old = calloc(sizeof(struct sigaction), BSG_SIG_NUMBER_MAX);
    memset(g_sigaction_old, 0, sizeof(struct sigaction) * BSG_SIG_NUMBER_MAX);
    int i;
    for (i = 0; i < BSG_SIG_CATCH_COUNT; i++) {
        const int sig = native_sig_catch[i];
        sigaction(sig, g_sigaction, &g_sigaction_old[sig]);
    }

    return 0;
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_setupBugsnag(JNIEnv *env, jclass type) {
    setupBugsnag(env);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateErrorDetails(JNIEnv *env, jclass type) {
    bsg_populate_event_details(env, g_bugsnag_report);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateUserDetails(JNIEnv *env, jclass type) {
    bsg_populate_user_details(env, g_bugsnag_report->event);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateAppDetails(JNIEnv *env, jclass type) {
    bsg_populate_app_data(env, g_bugsnag_report->event);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateDeviceDetails(JNIEnv *env, jclass type) {
    bsg_populate_device_data(env, g_bugsnag_report->event);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateContextDetails(JNIEnv *env, jclass type) {
    bsg_populate_context(env, g_bugsnag_report->event);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateBreadcumbDetails(JNIEnv *env, jclass type) {
    pthread_mutex_lock(&bsg_lock);
    bsg_populate_breadcrumbs(env, g_bugsnag_report->event);
    pthread_mutex_unlock(&bsg_lock);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateMetaDataDetails(JNIEnv *env, jclass type) {
    bsg_populate_meta_data(env, g_bugsnag_report->event, &g_bugsnag_report->filters);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateReleaseStagesDetails(JNIEnv *env,
                                                                          jclass type) {
    bsg_load_release_stages(env, g_bugsnag_report);
}

JNIEXPORT void JNICALL
Java_com_bugsnag_android_ndk_BugsnagObserver_populateFilterDetails(JNIEnv *env, jclass type) {
    bsg_load_filters(env, g_bugsnag_report);
}

void bugsnag_set_user_env(JNIEnv *env, char* id, char* email, char* name) {
    bugsnag_event_set_string(g_bugsnag_report->event, BSG_USER, "id", id);
    bugsnag_event_set_string(g_bugsnag_report->event, BSG_USER, "email", email);
    bugsnag_event_set_string(g_bugsnag_report->event, BSG_USER, "name", name);

    bsg_set_user(env, id, email, name);
}

void bugsnag_set_user(char *id, char *email, char *name) {
    assert(bugsnagGlobalEnv != NULL);
    bugsnag_set_user_env(bugsnagGlobalEnv, id, email, name);
}

void bugsnag_add_breadcrumb(bsg_breadcrumb* crumb)
{
    pthread_mutex_lock(&bsg_lock);
    bugsnag_event_add_breadcrumb(g_bugsnag_report->event, crumb);
    pthread_mutex_unlock(&bsg_lock);
}

void bugsnag_leave_breadcrumb_env(JNIEnv *env, char *name, bsg_breadcrumb_t type) {

    time_t rawtime;
    time ( &rawtime );

    bsg_breadcrumb* crumb = malloc(sizeof(struct bsg_breadcrumb));
    crumb->name = name;
    crumb->timestamp = rawtime;
    crumb->type = type;
    crumb->metadata = NULL;

    pthread_mutex_lock(&bsg_lock);
    bugsnag_event_add_breadcrumb(g_bugsnag_report->event, crumb);
    pthread_mutex_unlock(&bsg_lock);

    bsg_leave_breadcrumb(env, name, type);
}

void bugsnag_leave_breadcrumb(char *name, bsg_breadcrumb_t type) {
    assert(bugsnagGlobalEnv != NULL);
    bugsnag_leave_breadcrumb_env(bugsnagGlobalEnv, name, type);
}

void bugsnag_add_string_to_tab(JNIEnv *env, char *tab, char *key, char *value) {
    bugsnag_event_set_metadata_string(g_bugsnag_report->event, tab, key, value);

    bsg_add_string_to_tab(env, tab, key, value);
}

void bugsnag_add_number_to_tab(JNIEnv *env, char *tab, char *key, double value) {
    bugsnag_event_set_metadata_number(g_bugsnag_report->event, tab, key, value);

    bsg_add_number_to_tab(env, tab, key, value);
}

void bugsnag_add_bool_to_tab(JNIEnv *env, char *tab, char *key, int value) {
    bugsnag_event_set_metadata_bool(g_bugsnag_report->event, tab, key, value);

    bsg_add_boolean_to_tab(env, tab, key, value);
}

/**
 * Removes the Bugsnag signal handler
 */
void tearDownBugsnag() {
    // replace signal handler with old one again
    int i;
    for(i = 0; i < BSG_SIG_CATCH_COUNT; i++) {
        int sig = native_sig_catch[i];
        sigaction(sig, &g_sigaction_old[sig], NULL);
    }

    free(g_sigaction);
    free(g_native_code);
    bugsnag_report_free(g_bugsnag_report->report);

    if (g_bugsnag_report->filters.values) {
        free(g_bugsnag_report->filters.values);
    }
    if (g_bugsnag_report->notify_release_stages.values) {
        free(g_bugsnag_report->notify_release_stages.values);
    }

    free(g_bugsnag_report);
}

