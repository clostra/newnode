#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "network.h"

network* client_init();
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
        __android_log_write(ANDROID_LOG_VERBOSE, "dcdn", buf);
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

JNIEXPORT void JNICALL Java_com_clostra_dcdn_Dcdn_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);
    (*env)->ReleaseStringUTFChars(env, cacheDir, cCacheDir);
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    network *n = client_init(8006);
    pthread_t t;
    pthread_create(&t, NULL, android_main, n);
    return JNI_VERSION_1_6;
}
