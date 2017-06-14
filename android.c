#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>


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
    setvbuf(stdout, 0, _IOLBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    pipe(pfd);
    dup2(pfd[1], 1);
    dup2(pfd[1], 2);
    pthread_t t;
    if (pthread_create(&t, 0, stdio_thread, 0) == -1) {
        return;
    }
    pthread_detach(t);
}

void* android_main(void *userdata)
{
    int run_client();
    run_client();
    return NULL;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    pthread_t t;
    pthread_create(&t, NULL, android_main, NULL);
    return  JNI_VERSION_1_6;
}
