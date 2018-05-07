//
// Created by Dave Perryman on 04/10/2016.
//

#ifndef BUGSNAGNDK_REPORT_H
#define BUGSNAGNDK_REPORT_H

#include "bugsnag_ndk.h"
#include "deps/bugsnag/bugsnag.h"

struct bugsnag_ndk_string_array {
    const char **values;
    int size;
};

struct bugsnag_ndk_report {
    char *error_store_path;
    struct bugsnag_ndk_string_array notify_release_stages;
    struct bugsnag_ndk_string_array filters;
    bugsnag_report *report;
    bsg_event *event;
    bsg_exception *exception;
};

char *bsg_load_error_store_path(JNIEnv *env);
void bsg_load_release_stages(JNIEnv *env, struct bugsnag_ndk_report *report);
void bsg_load_filters(JNIEnv *env, struct bugsnag_ndk_report *report);

void bsg_populate_event_details(JNIEnv *env, struct bugsnag_ndk_report *report);
void bsg_populate_user_details(JNIEnv *env, bsg_event *event);
void bsg_populate_app_data(JNIEnv *env,bsg_event *event);
void bsg_populate_device_data(JNIEnv *env, bsg_event *event);
void bsg_populate_context(JNIEnv *env, bsg_event *event);
void bsg_populate_breadcrumbs(JNIEnv *env, bsg_event *event);
void bsg_populate_meta_data(JNIEnv *env, bsg_event *event, struct bugsnag_ndk_string_array *filters);

void bsg_set_user(JNIEnv *env, char* id, char* email, char* name);
void bsg_leave_breadcrumb(JNIEnv *env, char *name, bsg_breadcrumb_t type);
void bsg_add_string_to_tab(JNIEnv *env, char *tab, char *key, char* value);
void bsg_add_number_to_tab(JNIEnv *env, char *tab, char *key, double value);
void bsg_add_boolean_to_tab(JNIEnv *env, char *tab, char *key, int value);

#endif //BUGSNAGNDK_REPORT_H
