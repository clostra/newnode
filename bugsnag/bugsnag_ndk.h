/**
 * Bugsnag header file, for including in C code to report exceptions to Bugsnag
 */

#ifndef BUGSNAG_NDK_H
#define BUGSNAG_NDK_H

#include <stdlib.h>
#include <jni.h>
#include <android/log.h>

#define BUGSNAG_LOG(fmt, ...) __android_log_print(ANDROID_LOG_WARN, "BugsnagNDK", fmt, ##__VA_ARGS__)
#include "deps/bugsnag/bugsnag.h"
#include "deps/bugsnag/report.h"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_setupBugsnag (JNIEnv *env, jobject instance);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateErrorDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateUserDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateAppDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateDeviceDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateContextDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateReleaseStagesDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateFilterDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateBreadcumbDetails(JNIEnv *env, jclass type);
JNIEXPORT void JNICALL Java_com_bugsnag_android_ndk_BugsnagObserver_populateMetaDataDetails(JNIEnv *env, jclass type);

/**
 * Adds the Bugsnag signal handler
 */
extern int setupBugsnag(JNIEnv *);

/**
 * Removes the Bugsnag signal handler
 */
extern void tearDownBugsnag();
/**
 * Configure the Bugsnag interface, optionally including the JNI environment.
 * @param env  The JNI environment to use when using convenience methods
 */
void bugsnag_init(JNIEnv *env);
/**
 * Sends an error report to Bugsnag
 * @param name     The name of the error
 * @param message  The error message
 * @param severity The severity of the error
 */
void bugsnag_notify(char* name, char* message, bsg_severity_t severity);
void bugsnag_notify_env(JNIEnv *env, char* name, char* message, bsg_severity_t severity);
/**
 * Set the current user
 * @param id    The identifier of the user
 * @param email The user's email
 * @param name  The user's name
 */
void bugsnag_set_user(char* id, char* email, char* name);
void bugsnag_set_user_env(JNIEnv *env, char* id, char* email, char* name);
/**
 * Leave a breadcrumb, indicating an event of significance which will be logged in subsequent
 * error reports
 */
void bugsnag_leave_breadcrumb(char *name, bsg_breadcrumb_t type);
void bugsnag_leave_breadcrumb_env(JNIEnv *env, char *name, bsg_breadcrumb_t type);

#ifdef __cplusplus
}
#endif

#endif
