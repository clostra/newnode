#include <jni.h>
#include <pthread.h>


int run_client();

void* android_main(void *userdata)
{
    run_client();
    return NULL;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    pthread_t t;
    pthread_create(&t, NULL, android_main, NULL);
    return  JNI_VERSION_1_6;
}
