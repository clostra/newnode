#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include <jni.h>
#include <android/log.h>

#include "bugsnag/bugsnag_ndk.h"

#include "network.h"
#include "thread.h"
#include "constants.h"
#include "log.h"
#include "newnode.h"
#include "d2d.h"
#include "lsd.h"


static int pfd[2];
static JavaVM *g_jvm;
static jobject bugsnagClient;
static jobject newNode;
static port_t http_port;
static port_t socks_port;
static network *g_n;

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

#define CATCH(code) if ((*env)->ExceptionOccurred(env)) { \
  (*env)->ExceptionDescribe(env); \
  (*env)->ExceptionClear(env); \
  code; \
}

#define push_frame() (*env)->PushLocalFrame(env, 16)
#define pop_frame() (*env)->PopLocalFrame(env, NULL);

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

void bugsnag_leave_breadcrumb_log(const char *buf)
{
    bsg_breadcrumb *crumb = bugsnag_breadcrumb_init("newnode", BSG_CRUMB_LOG);
    bugsnag_breadcrumb_add_metadata(crumb, "stdout", (char*)buf);
    bugsnag_add_breadcrumb(crumb);
}

JNIEnv* get_env()
{
    JNIEnv *env;
    int stat = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    assert(stat == JNI_OK);
    return env;
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_callback(JNIEnv* env, jobject thiz, jlong callblock, jint value)
{
    timer_start(g_n, 0, ^{
        https_complete_callback cb = (https_complete_callback)callblock;
        cb(value == 200);
        Block_release(cb);
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeInit(JNIEnv* env, jobject thiz, jobject newNodeObj)
{
    newNode = (*env)->NewGlobalRef(env, newNodeObj);

    o_debug = 1;

    char app_id[64] = {0};
    FILE *cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(app_id, sizeof(app_id), 1, cmdline);
        __android_log_print(ANDROID_LOG_DEBUG, "newnode", "application id %s\n", app_id);
        fclose(cmdline);
    }
    // XXX: TODO: use real app name
    const char *app_name = app_id;
    g_n = newnode_init(app_name, app_id, &http_port, &socks_port, ^(const char* url, https_complete_callback cb) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        push_frame();
        ^() {
            if (!newNode) {
                cb(false);
                return;
            }
            jclass cNewNode = (*env)->GetObjectClass(env, newNode);
            CATCH(
                cb(false);
                return;
            );
            https_complete_callback cbc = Block_copy(cb);
            CALL_VOID(cNewNode, newNode, http, Ljava/lang/String;J, JSTR(url), (jlong)cbc);
            CATCH(
                cb(false);
                Block_release(cbc);
                return;
            );
        }();
        pop_frame();
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setCacheDir(JNIEnv* env, jobject thiz, jstring cacheDir)
{
    const char* cCacheDir = (*env)->GetStringUTFChars(env, cacheDir, NULL);
    chdir(cCacheDir);
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
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http.proxyPort"), JSTR(port));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyHost"), JSTR("127.0.0.1"));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https.proxyPort"), JSTR(port));

    char proxy[128];
    snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%s", port);
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("http_proxy"), JSTR(proxy));
    (*env)->CallStaticObjectMethod(env, cSystem, mSetProp, JSTR("https_proxy"), JSTR(proxy));
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
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyHost"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https.proxyPort"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("http_proxy"));
    (*env)->CallStaticObjectMethod(env, cSystem, mClearProp, JSTR("https_proxy"));
}

bool vpn_protect(int socket)
{
    JNIEnv *env = get_env();
    push_frame();
    bool r = ^bool() {
        if (!newNode) {
            return false;
        }
        IMPORT(com/clostra/newnode/vpn, VpnService);
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
            return true;
        }
        jmethodID mVpnProtect = (*env)->GetStaticMethodID(env, cVpnService, "vpnProtect", "(I)Z");
        CATCH(return false);
        jboolean success = (*env)->CallStaticBooleanMethod(env, cVpnService, mVpnProtect, socket);
        CATCH(return false);
        return (bool)success;
    }();
    pop_frame();
    return r;
}

int __real_bind(int socket, const struct sockaddr *address, socklen_t length);
int __wrap_bind(int socket, const struct sockaddr *address, socklen_t length)
{
    //debug("bind %d %s\n", socket, sockaddr_str(address));
    if (!sockaddr_is_localhost(address, length) && !vpn_protect(socket)) {
        debug("bind failed to protect\n");
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return __real_bind(socket, address, length);
}

int __real_connect(int socket, const struct sockaddr *address, socklen_t length);
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t length)
{
    //debug("connect %d %s\n", socket, sockaddr_str(address));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("connect failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_connect(socket, address, length);
}

ssize_t __real_sendto(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
ssize_t __wrap_sendto(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
    //debug("sendto %d %s\n", socket, sockaddr_str(dest_addr));
    sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(socket, (sockaddr*)&ss, &slen) == -1 || slen == 0 || sockaddr_get_port((const sockaddr*)&ss) == 0) {
        if (!vpn_protect(socket)) {
            debug("sendto failed to protect\n");
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }
    return __real_sendto(socket, buffer, length, flags, dest_addr, dest_len);
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_addEndpoint(JNIEnv* env, jobject thiz, jstring endpoint)
{
    const char* cEndpoint = (*env)->GetStringUTFChars(env, endpoint, NULL);
    sockaddr_in6 sin6 = endpoint_to_addr((const uint8_t*)cEndpoint, strlen(cEndpoint));
    timer_start(g_n, 0, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        add_sockaddr(g_n, (const sockaddr *)&sin6, sizeof(sin6));
        (*env)->ReleaseStringUTFChars(env, endpoint, cEndpoint);
    });
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_packetReceived(JNIEnv* env, jobject thiz, jbyteArray array, jstring endpoint)
{
    jobject arrayref = (*env)->NewGlobalRef(env, array);
    const char* cEndpoint = (*env)->GetStringUTFChars(env, endpoint, NULL);
    sockaddr_in6 sin6 = endpoint_to_addr((const uint8_t*)cEndpoint, strlen(cEndpoint));
    timer_start(g_n, 0, ^{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
        JNIEnv *env = get_env();
#pragma clang diagnostic pop
        jbyte *buf = (*env)->GetByteArrayElements(env, arrayref, NULL);
        jsize len = (*env)->GetArrayLength(env, arrayref);
        udp_received(g_n, (const uint8_t*)buf, len, (const sockaddr *)&sin6, sizeof(sin6));
        (*env)->ReleaseByteArrayElements(env, arrayref, buf, JNI_ABORT);
        (*env)->ReleaseStringUTFChars(env, endpoint, cEndpoint);
        (*env)->DeleteGlobalRef(env, arrayref);

        // XXX: this should be called when the read buffer is drained
        utp_issue_deferred_acks(g_n->utp);
    });
}

ssize_t d2d_sendto(const uint8* buf, size_t len, const sockaddr_in6 *sin6)
{
    JNIEnv *env = get_env();
    push_frame();
    ssize_t r = ^ssize_t() {
        if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
            return -1;
        }
        if (!newNode) {
            return -1;
        }
        const uint8_t *a = addr_to_endpoint(sin6);
        const char astr[sizeof(in6_addr) + 1] = {0};
        // XXX: google nearby endpoint ids happen to be ascii
        memcpy((void*)astr, a, sizeof(in6_addr));
        jstring endpoint = JSTR(astr);
        CATCH(return -1);
        jbyteArray array = (*env)->NewByteArray(env, len);
        CATCH(return -1);
        (*env)->SetByteArrayRegion(env, array, 0, len, (const jbyte *)buf);
        CATCH(return -1);
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return -1);
        CALL_VOID(cNewNode, newNode, sendPacket, [BLjava/lang/String;, array, endpoint);
        CATCH(return -1);
        return len;
    }();
    pop_frame();
    return r;
}

void ui_display_stats(const char *type, uint64_t direct, uint64_t peers)
{
    JNIEnv *env = get_env();
    push_frame();
    ^() {
        jclass cNewNode = (*env)->GetObjectClass(env, newNode);
        CATCH(return);
        CALL_VOID(cNewNode, newNode, displayStats, Ljava/lang/String;JJ, JSTR(type), direct, peers);
        CATCH(return);
    }();
    pop_frame();
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_setLogLevel(JNIEnv* env, jobject thiz, jint level)
{
    o_debug = level;
}

JNIEXPORT void JNICALL Java_com_clostra_newnode_internal_NewNode_newnodeRun(JNIEnv* env, jobject thiz)
{
    newnode_run(g_n);
}


// XXX: compat. can be removed when we have a NewNode.aar loader here in JNI
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_updateBugsnagDetails(JNIEnv* env, jobject thiz, int notifyType)
{
    Java_com_clostra_newnode_internal_NewNode_updateBugsnagDetails(env, thiz, notifyType);
}

// XXX: compat
JNIEXPORT void JNICALL Java_com_clostra_newnode_NewNode_useEphemeralPort(JNIEnv* env, jobject thiz)
{
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
