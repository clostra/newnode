#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "network.h"
#include "constants.h"
#include "log.h"


network* client_init(port_t port);
int client_run(network *n);

int pfd[2];

void* stdio_thread(void *useradata)
{
    ssize_t readSize;
    char buf[1024];

    while ((readSize = read(pfd[0], buf, sizeof buf - 1)) > 0) {
        if (buf[readSize - 1] == '\n') {
            --readSize;
        }
        buf[readSize] = 0;
        __android_log_write(ANDROID_LOG_VERBOSE, "newnode", buf);
    }
    return NULL;
}

void start_stdio_thread()
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    pipe(pfd);
    dup2(pfd[1], 1);
    dup2(pfd[1], 2);
    pthread_t t;
    if (pthread_create(&t, NULL, stdio_thread, NULL) == -1) {
        return;
    }
    pthread_detach(t);
}

void* android_main(void *userdata)
{
    client_run((network*)userdata);
    return NULL;
}

void set_version_name(JNIEnv* env)
{
    jclass cBugsnag = (*env)->FindClass(env, "com/bugsnag/android/Bugsnag");
    if (!cBugsnag) {
        (*env)->ExceptionClear(env);
        return;
    }
    jmethodID msetAppVersion = (*env)->GetStaticMethodID(env, cBugsnag, "setAppVersion", "(Ljava/lang/String;)V");
    if (!msetAppVersion) {
        (*env)->ExceptionClear(env);
        return;
    }
    jstring version = (*env)->NewStringUTF(env, VERSION);
    (*env)->CallStaticVoidMethod(env, cBugsnag, msetAppVersion, version);
    debug("version set: %s\n", VERSION);
}

void backwards_compat_set_version(JNIEnv* env)
{
    jclass cBuildConfig = (*env)->FindClass(env, "com/clostra/newnode/BuildConfig");
    if (!cBuildConfig) {
        (*env)->ExceptionClear(env);
        set_version_name(env);
    } else {
        jfieldID fVersionName = (*env)->GetStaticFieldID(env, cBuildConfig, "VERSION_NAME", "Ljava/lang/String;");
        jstring jVersionName = (*env)->GetStaticObjectField(env, cBuildConfig, fVersionName);
        if (!jVersionName) {
            (*env)->ExceptionClear(env);
            set_version_name(env);
        } else {
            const char *cVersionName = (*env)->GetStringUTFChars(env, jVersionName, NULL);
            if (strcmp(cVersionName, "1.3.7") < 0) {
                set_version_name(env);
            }
            (*env)->ReleaseStringUTFChars(env, jVersionName, cVersionName);
        }
    }
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);

    backwards_compat_set_version(env);

    network *n = client_init(8006);
    pthread_t t;
    pthread_create(&t, NULL, android_main, n);
    (*env)->ReleaseStringUTFChars(env, cacheDir, cCacheDir);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_dcdn_Dcdn_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    Java_com_clostra_newnode_NewNode_setCacheDir(env, thiz, cacheDir);
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    return JNI_VERSION_1_6;
}
