#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "bugsnag/bugsnag_ndk.h"

#include "network.h"
#include "thread.h"
#include "constants.h"
#include "log.h"
#include "newnode.h"


int pfd[2];
static JavaVM *g_jvm;
static jobject bugsnagClient;
port_t http_port;
port_t socks_port;
bool use_ephemeral_port;

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

#define BUGSNAG_API_KEY "141ea25aa72c276c49d3a154b82f2b1f"

#define STR(A) #A

#define JSTR(s) (*env)->NewStringUTF(env, s)

#define IMPORT(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "/" STR(class));
#define IMPORT_INNER(pkg, class) jclass c ## class = (*env)->FindClass(env, STR(pkg) "$" STR(class));

#define CALL_VOID(class, obj, meth, sig, ...) \
 jmethodID m ## meth = (*env)->GetMethodID(env, class, #meth, "(" STR(sig) ")V"); \
 if (m ## meth) (*env)->CallVoidMethod(env, obj, m ## meth, __VA_ARGS__);

#define CALL_VOID_BOOL(class, obj, meth, arg) CALL_VOID(class, obj, meth, Z, arg)

#define CATCH(code) if ((*env)->ExceptionOccurred(env)) { (*env)->ExceptionDescribe(env); code; }

enum notify_type {
    ALL = 1,
    USER = 2,
    APP = 3,
    DEVICE = 4,
    CONTEXT = 5,
    RELEASE_STAGES = 6,
    FILTERS = 7,
    BREADCRUMB = 8,
    META = 9
};

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    static bool bugsnag_setup = false;
    if (!bugsnag_setup) {
        bugsnag_setup = true;
        setupBugsnag(env);
    }
    switch ((enum notify_type)notifyType) {
    case USER: Java_com_bugsnag_android_ndk_BugsnagObserver_populateUserDetails(env, NULL); break;
    case APP: Java_com_bugsnag_android_ndk_BugsnagObserver_populateAppDetails(env, NULL); break;
    case DEVICE: Java_com_bugsnag_android_ndk_BugsnagObserver_populateDeviceDetails(env, NULL); break;
    case CONTEXT: Java_com_bugsnag_android_ndk_BugsnagObserver_populateContextDetails(env, NULL); break;
    case RELEASE_STAGES: Java_com_bugsnag_android_ndk_BugsnagObserver_populateReleaseStagesDetails(env, NULL); break;
    case FILTERS: Java_com_bugsnag_android_ndk_BugsnagObserver_populateFilterDetails(env, NULL); break;
    case BREADCRUMB: Java_com_bugsnag_android_ndk_BugsnagObserver_populateBreadcumbDetails(env, NULL); break;
    case META: Java_com_bugsnag_android_ndk_BugsnagObserver_populateMetaDataDetails(env, NULL); break;
    case ALL:
    default:
        Java_com_bugsnag_android_ndk_BugsnagObserver_populateErrorDetails(env, NULL); break;
    }
}

jobject app(JNIEnv* env)
{
    IMPORT(com/clostra/newnode, NewNode);
    CATCH(return NULL);
    jmethodID mapp = (*env)->GetStaticMethodID(env, cNewNode, "app", "()Landroid/app/Application;");
    CATCH(return NULL);
    return (*env)->CallStaticObjectMethod(env, cNewNode, mapp);
}

void bugsnag_client_setup(JNIEnv* env)
{
    // Configuration config = new Configuration(BuildConfig.BUGSNAG_API_KEY);
    IMPORT(com/bugsnag/android, Configuration);
    CATCH(return);
    jmethodID mConfInit = (*env)->GetMethodID(env, cConfiguration, "<init>", "(Ljava/lang/String;)V");
    CATCH(return);
    jobject config = (*env)->NewObject(env, cConfiguration, mConfInit, JSTR(BUGSNAG_API_KEY));
    CATCH(return);

    // config.setAppVersion(VERSION);
    CALL_VOID(cConfiguration, config, setAppVersion, Ljava/lang/String;, JSTR(VERSION));
    CATCH(return);

    // config.setBuildUUID(data.getString(MF_BUILD_UUID));
    CALL_VOID(cConfiguration, config, setBuildUUID, Ljava/lang/String;, JSTR(VERSION));
    CATCH(return);

    //config.setReleaseStage(data.getString(MF_RELEASE_STAGE));

    // config.setSendThreads(true);
    CALL_VOID_BOOL(cConfiguration, config, setSendThreads, true);
    CATCH(return);

    // config.setPersistUserBetweenSessions(false);
    CALL_VOID_BOOL(cConfiguration, config, setPersistUserBetweenSessions, true);
    CATCH(return);

    // config.setAutoCaptureSessions(false);
    CALL_VOID_BOOL(cConfiguration, config, setAutoCaptureSessions, true);
    CATCH(return);

    // config.setEnableExceptionHandler(true);
    CALL_VOID_BOOL(cConfiguration, config, setEnableExceptionHandler, true);
    CATCH(return);

    // client = new Client(app(), config);
    IMPORT(com/bugsnag/android, Client);
    CATCH(return);
    jmethodID mClientInit = (*env)->GetMethodID(env, cClient, "<init>", "(Landroid/content/Context;Lcom/bugsnag/android/Configuration;)V");
    CATCH(return);
    jobject oapp = app(env);
    CATCH(return);
    jobject client = (*env)->NewObject(env, cClient, mClientInit, oapp, config);
    CATCH(return);
    bugsnagClient = (*env)->NewGlobalRef(env, client);
    CATCH(return);

    // client.setProjectPackages("com.clostra.newnode");
    jobjectArray packages = (*env)->NewObjectArray(env, 1, (*env)->FindClass(env, "java/lang/String"), JSTR("com.clostra.newnode"));
    CALL_VOID(cClient, client, setProjectPackages, [Ljava/lang/String;, packages);
    CATCH(return);

    // client.setLoggingEnabled(true);
    /*
    CALL_VOID_BOOL(cClient, client, setLoggingEnabled, true);
    CATCH(return);
    */

    // NativeInterface.client = client;
    IMPORT(com/bugsnag/android, NativeInterface);
    CATCH(return);
    jfieldID fclient = (*env)->GetStaticFieldID(env, cNativeInterface, "client", "Lcom/bugsnag/android/Client;");
    CATCH(return);
    (*env)->SetStaticObjectField(env, cNativeInterface, fclient, client);

    // client.addObserver(new BugsnagObserver());
    // XXX: temp try old class name
    {
        IMPORT_INNER(com/clostra/newnode/NewNode, BugsnagObserver);
        if (!cBugsnagObserver) {
            (*env)->ExceptionClear(env);
        } else {
            jmethodID mObvInit = (*env)->GetMethodID(env, cBugsnagObserver, "<init>", "()V");
            CATCH(return);
            jobject observer = (*env)->NewObject(env, cBugsnagObserver, mObvInit);
            CATCH(return);
            CALL_VOID(cClient, client, addObserver, Ljava/util/Observer;, observer);
            CATCH(return);
        }
    }
    {
        IMPORT_INNER(com/clostra/newnode/internal/NewNode, BugsnagObserver);
        if (!cBugsnagObserver) {
            (*env)->ExceptionClear(env);
        } else {
            jmethodID mObvInit = (*env)->GetMethodID(env, cBugsnagObserver, "<init>", "()V");
            CATCH(return);
            jobject observer = (*env)->NewObject(env, cBugsnagObserver, mObvInit);
            CATCH(return);
            CALL_VOID(cClient, client, addObserver, Ljava/util/Observer;, observer);
            CATCH(return);
        }
    }

    // client.notifyBugsnagObservers(NotifyType.ALL);
    Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(env, NULL, ALL);

    debug("bugsnag started\n");
}

void bugsnag_leave_breadcrumb_log(const char *buf)
{
    bsg_breadcrumb *crumb = bugsnag_breadcrumb_init("newnode", BSG_CRUMB_LOG);
    bugsnag_breadcrumb_add_metadata(crumb, "stdout", (char*)buf);
    bugsnag_add_breadcrumb(crumb);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_useEphemeralPort(JNIEnv* env, jobject thiz)
{
    use_ephemeral_port = true;
}

bool android_https(const char* url)
{
    JNIEnv *env;
    int stat = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (stat == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            fprintf(stderr, "%s Failed to get JNI environment\n", __func__);
            return false;
        }
    }

    // URL jUrl = new URL(url)
    jstring jUrlStr = JSTR(url);

    jclass jUrlClass = (*env)->FindClass(env, "java/net/URL");
    jmethodID jUrlConstructorID = (*env)->GetMethodID(env, jUrlClass, "<init>", "(Ljava/lang/String;)V");
    jobject jUrl = (*env)->NewObject(env, jUrlClass, jUrlConstructorID, jUrlStr);
    CATCH(return false);
    (*env)->DeleteLocalRef(env, jUrlStr);

    // HttpURLConnection connection = (HttpURLConnection) jUrl.openConnection();
    jmethodID jUrlOpenConnectionID = (*env)->GetMethodID(env, jUrlClass, "openConnection", "()Ljava/net/URLConnection;");
    jobject jConnection = (*env)->CallObjectMethod(env, jUrl, jUrlOpenConnectionID);
    CATCH(return false);

    // connection.setRequestMethod("GET");
    jstring jMethod = JSTR("GET");
    jclass jConnectionClass = (*env)->FindClass(env, "java/net/HttpURLConnection");
    jmethodID jConnectionSetMethodID = (*env)->GetMethodID(env, jConnectionClass, "setRequestMethod", "(Ljava/lang/String;)V");
    (*env)->CallVoidMethod(env, jConnection, jConnectionSetMethodID, jMethod);
    CATCH(return false);
    (*env)->DeleteLocalRef(env, jMethod);

    // connection.connect();
    jmethodID jConnectionConnectID = (*env)->GetMethodID(env, jConnectionClass, "connect", "()V");
    (*env)->CallVoidMethod(env, jConnection, jConnectionConnectID);
    CATCH(return false);

    // result.responseStatus = connection.getResponseCode();
    jmethodID jConnectionGetResponseCodeID = (*env)->GetMethodID(env, jConnectionClass, "getResponseCode", "()I");
    jint responseStatus = (*env)->CallIntMethod(env, jConnection, jConnectionGetResponseCodeID);
    CATCH(return false);

    if (stat == JNI_EDETACHED) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }

    return responseStatus == 200;
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);

    bugsnag_client_setup(env);

    o_debug = 1;

    char app_id[64] = {0};
    FILE *cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(app_id, sizeof(app_id), 1, cmdline);
        __android_log_print(ANDROID_LOG_DEBUG, "newnode", "application id %s\n", app_id);
        fclose(cmdline);
    }
    if (!use_ephemeral_port) {
        http_port = 8006;
        socks_port = 8007;
    }
    // XXX: TODO: use real app name
    const char *app_name = app_id;
    newnode_init(app_name, app_id, &http_port, &socks_port, ^void (const char *url, https_complete_callback cb) {
        debug("https stuff: %s\n", url);
        char *url2 = strdup(url);
        cb = Block_copy(cb);
        thread(^{
            debug("https stuff2: %s\n", url2);
            bool s = android_https(url2);
            cb(s);
            free(url2);
            Block_release(cb);
        });
    });

    (*env)->ReleaseStringUTFChars(env, cacheDir, cCacheDir);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_registerProxy(JNIEnv* env, jobject thiz)
{
    if (!http_port || !socks_port) {
        return;
    }

    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mSetProp = (*env)->GetStaticMethodID(env, cSystem, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);

    char port[6];
    snprintf(port, sizeof(port), "%u", socks_port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("socksProxyPort"), JSTR(port));

    snprintf(port, sizeof(port), "%u", http_port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("proxyPort"), JSTR(port));
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_unregisterProxy(JNIEnv* env, jobject thiz)
{
    IMPORT(java/lang, System);
    CATCH(return);
    jmethodID mClearProp = (*env)->GetStaticMethodID(env, cSystem, "clearProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    CATCH(return);
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("socksProxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("proxyPort"));
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    o_debug = level;
}


// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(env, thiz, notifyType);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_useEphemeralPort(JNIEnv* env, jobject thiz)
{
    Java_com_clostra_newnode_internal_NewNode_useEphemeralPort(env, thiz);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    Java_com_clostra_newnode_internal_NewNode_setCacheDir(env, thiz, cacheDir);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_registerProxy(JNIEnv* env, jobject thiz)
{
    Java_com_clostra_newnode_internal_NewNode_registerProxy(env, thiz);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_unregisterProxy(JNIEnv* env, jobject thiz)
{
    Java_com_clostra_newnode_internal_NewNode_unregisterProxy(env, thiz);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    Java_com_clostra_newnode_internal_NewNode_setLogLevel(env, thiz, level);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_dcdn_Dcdn_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    Java_com_clostra_newnode_internal_NewNode_setCacheDir(env, thiz, cacheDir);
}

void d2d_init(network *n)
{
    // TODO
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_jvm = vm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    start_stdio_thread();
    return JNI_VERSION_1_6;
}
